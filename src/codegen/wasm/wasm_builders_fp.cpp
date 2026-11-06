/**
 * @file        codegen/wasm/wasm_builders_fp.cpp
 * @brief       wasm builders for the floating-point unit and FPSCR (guest ABI v1)
 *
 * The reference is ReXGlue's builders/floating_point.cpp, memory.cpp (lfs..stfiwx) and
 * system.cpp (mffs/mtfsf). FPRs are f64 at ctx.fN. Differences from the C++ backend, which
 * runs on the host FPU with the guest rounding mode in MXCSR:
 *  - wasm arithmetic always rounds to nearest; fctiw/fctid honour FPSCR[RN] explicitly.
 *  - fmadd and friends use f64x2.relaxed_madd: fused where the host has FMA (x86 FMA3,
 *    ARMv8), otherwise rounded twice.
 *  - The context `fpscr` word holds the guest FPSCR bits written by mtfsf/mtfsfi/mtfsb0/1
 *    (no exception status bits are ever set); mffs reads it back.
 *
 * @copyright   Copyright (c) 2026 MCLA-Reborn contributors
 * @license     Not yet licensed: MCLA-Reborn decides before any release (D-009)
 */

#include "wasm_builders_internal.h"

#if REXGLUE_TRANSLATOR_PPC
#include <translator_ppc/binutils_compat.h>  // MCLA-Reborn: our decoder (T-048)
#else
#include <dis-asm.h>
#include <ppc-inst.h>
#endif

namespace rex::codegen::wasm::detail {

namespace {

//=============================================================================
// Loads and stores (memory.cpp). Singles are converted on the way in and out; doublewords
// follow the integer path (ADR-0009 rotation, misaligned helper).
//=============================================================================

enum class FpForm { D, DU, X, XU };

/// Computes the ea into kI0 and returns whether alignment is proven.
bool fpEa(W& w, FpForm form) {
  const bool indexed = form == FpForm::X || form == FpForm::XU;
  const bool update = form == FpForm::DU || form == FpForm::XU;
  indexed ? pushEaX(w, update) : pushEaD(w, w.simm(), update);
  w.set(kI0);
  return provablyAligned(w, Width::W, indexed, update, indexed ? 0 : w.simm());
}

void fpUpdate(W& w, FpForm form) {
  if (form == FpForm::DU || form == FpForm::XU)
    w.get(kI0), w.setR32(w.rA());
}

template <FpForm Form>
void build_lfs(W& w) {
  const bool aligned = fpEa(w, Form);
  loadValue(w, Width::W, false, false, aligned);
  w.op(Op::I32WrapI64), w.op(Op::F32ReinterpretI32), w.op(Op::F64PromoteF32);
  w.setF(w.rD());
  fpUpdate(w, Form);
}

template <FpForm Form>
void build_lfd(W& w) {
  const bool aligned = fpEa(w, Form);
  loadValue(w, Width::D, false, false, aligned);
  w.setFBits(w.rD());
  fpUpdate(w, Form);
}

/// MMIO checks as memory.cpp: stfs/stfsx/stfsux/stfd/stfdx/stfiwx check, stfsu/stfdu/stfdux
/// don't.
template <FpForm Form, bool Mmio>
void build_stfs(W& w) {
  const bool aligned = fpEa(w, Form);
  w.pushF(w.rS()), w.op(Op::F32DemoteF64), w.op(Op::I32ReinterpretF32), w.set(kI4);
  const bool indexed = Form == FpForm::X || Form == FpForm::XU;
  const bool mmio = Mmio && (indexed ? w.mmioCheckXForm() : w.mmioCheckDForm());
  storeValue(w, Width::W, kI4, mmio, aligned);
  fpUpdate(w, Form);
}

template <FpForm Form, bool Mmio>
void build_stfd(W& w) {
  const bool aligned = fpEa(w, Form);
  w.pushFBits(w.rS()), w.set(kL4);
  const bool indexed = Form == FpForm::X || Form == FpForm::XU;
  const bool mmio = Mmio && (indexed ? w.mmioCheckXForm() : w.mmioCheckDForm());
  storeValue(w, Width::D, kL4, mmio, aligned);
  fpUpdate(w, Form);
}

void build_stfiwx(W& w) {
  const bool aligned = fpEa(w, FpForm::X);
  w.pushFBits(w.rS()), w.op(Op::I32WrapI64), w.set(kI4);
  storeValue(w, Width::W, kI4, w.mmioCheckXForm(), aligned);
}

//=============================================================================
// Moves and sign operations (on the bits, as the C++ u64 forms)
//=============================================================================

void build_fmr(W& w) {
  w.pushFBits(w.opnd(1)), w.setFBits(w.opnd(0));
}

template <int Kind>  // 0 abs, 1 nabs, 2 neg
void build_fsign(W& w) {
  w.pushFBits(w.opnd(1));
  if (Kind == 0)
    w.i64(INT64_MAX), w.op(Op::I64And);
  else if (Kind == 1)
    w.i64(INT64_MIN), w.op(Op::I64Or);
  else
    w.i64(INT64_MIN), w.op(Op::I64Xor);
  w.setFBits(w.opnd(0));
}

//=============================================================================
// Arithmetic
//=============================================================================

/// double(float(x)) for the single-precision forms.
void roundSingle(W& w) {
  w.op(Op::F32DemoteF64), w.op(Op::F64PromoteF32);
}

template <uint8_t Opcode, bool Single>
void build_fbinary(W& w) {
  w.pushF(w.opnd(1)), w.pushF(w.opnd(2)), w.op(Opcode);
  if (Single)
    roundSingle(w);
  w.setF(w.opnd(0));
}

/// fma(A, C, +-B) through f64x2.relaxed_madd on splatted lanes; result negated for fnm*.
template <bool NegateB, bool NegateResult, bool Single>
void build_fmadd(W& w) {
  w.pushF(w.opnd(1)), w.simd(Simd::F64x2Splat);
  w.pushF(w.opnd(2)), w.simd(Simd::F64x2Splat);
  w.pushF(w.opnd(3));
  if (NegateB)
    w.op(Op::F64Neg);
  w.simd(Simd::F64x2Splat);
  w.simd(Simd::F64x2RelaxedMadd);
  w.c.simdLane(Simd::F64x2ExtractLane, 0);
  if (NegateResult)
    w.op(Op::F64Neg);
  if (Single)
    roundSingle(w);
  w.setF(w.opnd(0));
}

void build_fsqrt(W& w) {
  w.pushF(w.opnd(1)), w.op(Op::F64Sqrt), w.setF(w.opnd(0));
}

void build_fsqrts(W& w) {
  w.pushF(w.opnd(1)), w.op(Op::F64Sqrt), roundSingle(w), w.setF(w.opnd(0));
}

/// fres: double(float(1.0 / x)).
void build_fres(W& w) {
  w.c.f64Const(1.0), w.pushF(w.opnd(1)), w.op(Op::F64Div), roundSingle(w), w.setF(w.opnd(0));
}

/// frsqrte: double(float(1.0 / sqrt(x))).
void build_frsqrte(W& w) {
  w.c.f64Const(1.0), w.pushF(w.opnd(1)), w.op(Op::F64Sqrt), w.op(Op::F64Div), roundSingle(w);
  w.setF(w.opnd(0));
}

void build_frsp(W& w) {
  w.pushF(w.opnd(1)), roundSingle(w), w.setF(w.opnd(0));
}

/// fsel: A >= 0.0 ? C : B.
void build_fsel(W& w) {
  w.pushF(w.opnd(2)), w.pushF(w.opnd(3));
  w.pushF(w.opnd(1)), w.c.f64Const(0.0), w.op(Op::F64Ge);
  w.op(Op::Select), w.setF(w.opnd(0));
}

//=============================================================================
// Conversions
//=============================================================================

void build_fcfid(W& w) {
  w.pushFBits(w.opnd(1)), w.op(Op::F64ConvertI64S), w.setF(w.opnd(0));
}

/// Pushes kF0 rounded to an integer in the FPSCR[RN] mode (cvtsd2si under MXCSR in C++).
void pushRoundedByRn(W& w) {
  w.pushU32(w.L().fpscr), w.i32(3), w.op(Op::I32And), w.set(kI0);
  // rn >= 2 ? (rn == 3 ? floor : ceil) : (rn == 1 ? trunc : nearest)
  w.get(kF0), w.op(Op::F64Floor), w.get(kF0), w.op(Op::F64Ceil);
  w.get(kI0), w.i32(3), w.op(Op::I32Eq), w.op(Op::Select);
  w.get(kF0), w.op(Op::F64Trunc), w.get(kF0), w.op(Op::F64Nearest);
  w.get(kI0), w.i32(1), w.op(Op::I32Eq), w.op(Op::Select);
  w.get(kI0), w.i32(2), w.op(Op::I32GeU), w.op(Op::Select);
}

/// fctiw/fctiwz: NaN -> 0x80000000 (zero-extended), x >= INT_MAX -> INT_MAX, else the
/// rounded value with x86's out-of-range INT_MIN, sign-extended.
template <bool Truncate>
void build_fctiw(W& w) {
  w.pushF(w.opnd(1)), w.set(kF0);
  w.i64(0x80000000ll);
  w.i64(INT32_MAX);
  if (Truncate)
    w.get(kF0);
  else
    pushRoundedByRn(w);
  w.c.misc(Misc::I32TruncSatF64S), w.op(Op::I64ExtendI32S);
  w.get(kF0), w.c.f64Const(2147483647.0), w.op(Op::F64Ge), w.op(Op::Select);
  w.get(kF0), w.get(kF0), w.op(Op::F64Ne), w.op(Op::Select);
  w.setFBits(w.opnd(0));
}

/// fctid/fctidz: NaN -> INT64_MIN, x > 2^63 -> INT64_MAX, x == 2^63 -> INT64_MIN (x86's
/// indefinite), else the rounded value saturated.
template <bool Truncate>
void build_fctid(W& w) {
  w.pushF(w.opnd(1)), w.set(kF0);
  w.i64(INT64_MIN);
  if (Truncate)
    w.get(kF0);
  else
    pushRoundedByRn(w);
  w.c.misc(Misc::I64TruncSatF64S);
  w.get(kF0), w.get(kF0), w.op(Op::F64Ne);
  w.get(kF0), w.c.f64Const(9223372036854775808.0), w.op(Op::F64Eq), w.op(Op::I32Or);
  w.op(Op::Select);
  w.setFBits(w.opnd(0));
}

//=============================================================================
// Compares (CRRegister::compare(double, double)): un, then lt/gt/eq only when ordered
//=============================================================================

void build_fcmp(W& w) {
  const uint32_t field = w.opnd(0) & 7;
  w.pushF(w.opnd(1)), w.set(kF0), w.pushF(w.opnd(2)), w.set(kF1);
  w.get(kLocalCtx);
  w.get(kF0), w.get(kF1), w.op(Op::F64Lt);
  w.get(kF0), w.get(kF1), w.op(Op::F64Gt), w.i32(8), w.op(Op::I32Shl), w.op(Op::I32Or);
  w.get(kF0), w.get(kF1), w.op(Op::F64Eq), w.i32(16), w.op(Op::I32Shl), w.op(Op::I32Or);
  w.get(kF0), w.get(kF0), w.op(Op::F64Ne), w.get(kF1), w.get(kF1), w.op(Op::F64Ne),
      w.op(Op::I32Or), w.i32(24), w.op(Op::I32Shl), w.op(Op::I32Or);
  w.c.mem(Op::I32Store, 0, w.L().cr[field].lt);
}

//=============================================================================
// FPSCR
//=============================================================================

void build_mffs(W& w) {
  w.pushU32(w.L().fpscr), w.op(Op::I64ExtendI32U), w.setFBits(w.rD());
}

/// fpscr = (fpscr & ~mask) | (value & mask).
void storeFpscrMasked(W& w, uint32_t mask) {
  w.pushU32(w.L().fpscr), w.i32(static_cast<int32_t>(~mask)), w.op(Op::I32And);
  w.op(Op::I32Or);
  w.setU32(w.L().fpscr);
}

/// mtfsf FM, frB: FM bit (7 - i) selects FPSCR field i, as the architecture defines it.
/// (ReXGlue's build_mtfsf maps FM bit (7 - j) to nibble j from the low end, so `mtfsf 1`
/// leaves RN alone there; with the full mask both agree.)
void build_mtfsf(W& w) {
  const uint32_t fm = (w.word >> 17) & 0xFF;
  uint32_t mask = 0;
  for (uint32_t i = 0; i < 8; ++i) {
    if (fm & (0x80u >> i))
      mask |= 0xFu << (28 - 4 * i);
  }
  w.pushFBits(w.rB()), w.op(Op::I32WrapI64), w.i32(static_cast<int32_t>(mask)), w.op(Op::I32And);
  storeFpscrMasked(w, mask);
}

/// mtfsfi crfD, IMM (not in ReXGlue): field crfD = IMM.
void build_mtfsfi(W& w) {
  const uint32_t field = (w.word >> 23) & 7;
  const uint32_t imm = (w.word >> 12) & 0xF;
  const uint32_t shift = 28 - 4 * field;
  w.i32(static_cast<int32_t>(imm << shift));
  storeFpscrMasked(w, 0xFu << shift);
}

/// mtfsb0 / mtfsb1 crbD (not in ReXGlue).
template <bool Set>
void build_mtfsb(W& w) {
  const uint32_t bit = 1u << (31 - ((w.word >> 21) & 31));
  w.i32(Set ? static_cast<int32_t>(bit) : 0);
  storeFpscrMasked(w, bit);
}

}  // namespace

void RegisterFloatBuilders(IdTable& t) {
  t[PPC_INST_LFS] = build_lfs<FpForm::D>;
  t[PPC_INST_LFSU] = build_lfs<FpForm::DU>;
  t[PPC_INST_LFSX] = build_lfs<FpForm::X>;
  t[PPC_INST_LFSUX] = build_lfs<FpForm::XU>;
  t[PPC_INST_LFD] = build_lfd<FpForm::D>;
  t[PPC_INST_LFDU] = build_lfd<FpForm::DU>;
  t[PPC_INST_LFDX] = build_lfd<FpForm::X>;
  t[PPC_INST_LFDUX] = build_lfd<FpForm::XU>;
  t[PPC_INST_STFS] = build_stfs<FpForm::D, true>;
  t[PPC_INST_STFSU] = build_stfs<FpForm::DU, false>;
  t[PPC_INST_STFSX] = build_stfs<FpForm::X, true>;
  t[PPC_INST_STFSUX] = build_stfs<FpForm::XU, true>;
  t[PPC_INST_STFD] = build_stfd<FpForm::D, true>;
  t[PPC_INST_STFDU] = build_stfd<FpForm::DU, false>;
  t[PPC_INST_STFDX] = build_stfd<FpForm::X, true>;
  t[PPC_INST_STFDUX] = build_stfd<FpForm::XU, false>;
  t[PPC_INST_STFIWX] = build_stfiwx;

  t[PPC_INST_FMR] = build_fmr;
  t[PPC_INST_FABS] = build_fsign<0>;
  t[PPC_INST_FNABS] = build_fsign<1>;
  t[PPC_INST_FNEG] = build_fsign<2>;

  t[PPC_INST_FADD] = build_fbinary<Op::F64Add, false>;
  t[PPC_INST_FADDS] = build_fbinary<Op::F64Add, true>;
  t[PPC_INST_FSUB] = build_fbinary<Op::F64Sub, false>;
  t[PPC_INST_FSUBS] = build_fbinary<Op::F64Sub, true>;
  t[PPC_INST_FMUL] = build_fbinary<Op::F64Mul, false>;
  t[PPC_INST_FMULS] = build_fbinary<Op::F64Mul, true>;
  t[PPC_INST_FDIV] = build_fbinary<Op::F64Div, false>;
  t[PPC_INST_FDIVS] = build_fbinary<Op::F64Div, true>;
  t[PPC_INST_FMADD] = build_fmadd<false, false, false>;
  t[PPC_INST_FMADDS] = build_fmadd<false, false, true>;
  t[PPC_INST_FMSUB] = build_fmadd<true, false, false>;
  t[PPC_INST_FMSUBS] = build_fmadd<true, false, true>;
  t[PPC_INST_FNMADD] = build_fmadd<false, true, false>;
  t[PPC_INST_FNMADDS] = build_fmadd<false, true, true>;
  t[PPC_INST_FNMSUB] = build_fmadd<true, true, false>;
  t[PPC_INST_FNMSUBS] = build_fmadd<true, true, true>;
  t[PPC_INST_FSQRT] = build_fsqrt;
  t[PPC_INST_FSQRTS] = build_fsqrts;
  t[PPC_INST_FRES] = build_fres;
  t[PPC_INST_FRSQRTE] = build_frsqrte;
  t[PPC_INST_FRSP] = build_frsp;
  t[PPC_INST_FSEL] = build_fsel;

  t[PPC_INST_FCFID] = build_fcfid;
  t[PPC_INST_FCTIW] = build_fctiw<false>;
  t[PPC_INST_FCTIWZ] = build_fctiw<true>;
  t[PPC_INST_FCTID] = build_fctid<false>;
  t[PPC_INST_FCTIDZ] = build_fctid<true>;

  t[PPC_INST_FCMPU] = build_fcmp;
  t[PPC_INST_FCMPO] = build_fcmp;

  t[PPC_INST_MFFS] = build_mffs;
  t[PPC_INST_MTFSF] = build_mtfsf;
  t[PPC_INST_MTFSFI] = build_mtfsfi;
  t[PPC_INST_MTFSB0] = build_mtfsb<false>;
  t[PPC_INST_MTFSB1] = build_mtfsb<true>;
}

}  // namespace rex::codegen::wasm::detail
