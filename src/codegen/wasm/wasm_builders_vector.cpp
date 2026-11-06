/**
 * @file        codegen/wasm/wasm_builders_vector.cpp
 * @brief       wasm builders for VMX and VMX128 on SIMD128 (guest ABI v1)
 *
 * The reference is ReXGlue's builders/vector.cpp, memory.cpp (vector loads and stores) and
 * include/rex/ppc/intrinsics.h. Vector registers keep ReXGlue's layout: the whole 16-byte
 * register is reversed, so guest byte k is host byte 15 - k and guest word i is host lane
 * 3 - i. Every SSE operation of the C++ backend therefore maps lane for lane onto a SIMD128
 * one. Guest memory holds words in host order (ADR-0009), so a 16-byte block loads with one
 * v128.load and a word-reversing shuffle.
 *
 * ReXGlue runs the VMX float ops with MXCSR FTZ+DAZ (REX_SET_FLUSH_MODE), as the Xenon's VMX
 * flushes denormals. wasm has no flush mode, so those ops flush their float inputs and
 * results explicitly (kFlushDenormals).
 *
 * @copyright   Copyright (c) 2026 MCLA-Reborn contributors
 * @license     Not yet licensed: MCLA-Reborn decides before any release (D-009)
 */

#include <bit>
#include <cmath>

#include <rex/logging.h>

#include "../codegen_logging.h"
#include "wasm_builders_internal.h"

#if REXGLUE_TRANSLATOR_PPC
#include <translator_ppc/binutils_compat.h>  // MCLA-Reborn: our decoder (T-048)
#else
#include <dis-asm.h>
#include <ppc-inst.h>
#endif

namespace rex::codegen::wasm::detail {

namespace {

/// Flush denormal inputs and results of the VMX float ops to zero (ReXGlue's VMX flush mode).
constexpr bool kFlushDenormals = true;

constexpr uint8_t kRevWords[16] = {12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3};
constexpr uint8_t kIota[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
constexpr uint32_t kSign = 0x80000000u;

uint32_t vD(const W& w) {
  return w.opnd(0);
}
uint32_t vA(const W& w) {
  return w.opnd(1);
}
uint32_t vB(const W& w) {
  return w.opnd(2);
}
uint32_t vC(const W& w) {
  return w.opnd(3);
}

/// Denormal lanes of the f32x4 on the stack -> signed zero.
void flush(W& w) {
  if (!kFlushDenormals)
    return;
  w.set(kV6);
  w.get(kV6);
  w.get(kV6), w.c.i32x4Splat(kSign), w.simd(Simd::V128And);
  w.get(kV6), w.c.i32x4Splat(0x7FFFFFFF), w.simd(Simd::V128And);
  w.c.i32x4Splat(0x007FFFFF), w.simd(Simd::I32x4GtS);
  w.simd(Simd::V128Bitselect);
}

/// Pushes vN as a float input (flushed).
void pushVf(W& w, uint32_t n) {
  w.pushV(n);
  flush(w);
}

/// CR6 from a compare result on the stack (CRRegister::setFromMask): lt = all lanes set,
/// eq = none, gt = so = 0. `bytes`: movemask_epi8 (16 lanes) instead of movemask_ps.
void setCr6(W& w, bool bytes) {
  w.simd(bytes ? Simd::I8x16Bitmask : Simd::I32x4Bitmask), w.set(kI0);
  w.get(kLocalCtx);
  w.get(kI0), w.i32(bytes ? 0xFFFF : 0xF), w.op(Op::I32Eq);
  w.get(kI0), w.op(Op::I32Eqz), w.i32(16), w.op(Op::I32Shl), w.op(Op::I32Or);
  w.c.mem(Op::I32Store, 0, w.L().cr[6].lt);
}

/// Stores the v128 on the stack in vD and, for record forms, sets CR6 from it.
void finishCompare(W& w, bool bytes) {
  if (w.recordName()) {
    w.tee(kV0);
    w.setV(vD(w));
    w.get(kV0);
    setCr6(w, bytes);
  } else {
    w.setV(vD(w));
  }
}

//=============================================================================
// Loads and stores (memory.cpp)
//=============================================================================

/// Pushes (rA|0) + rB from operands 1 and 2 (helpers.h emitVectorEA).
void pushVecEa(W& w) {
  if (w.opnd(1) != 0)
    w.pushR32(w.opnd(1)), w.pushR32(w.opnd(2)), w.op(Op::I32Add);
  else
    w.pushR32(w.opnd(2));
}

/// Folds the vector ea in kI0 onto the canonical physical range when needed (T-050).
void foldVecEa(W& w) {
  foldEaX(w, kI0, w.opnd(1), w.opnd(2), false);
}

/// lvx, lvxl, lvebx, lvehx, lvewx (+128): the aligned 16 bytes, words reversed.
void build_lvx(W& w) {
  pushVecEa(w), w.i32(~0xF), w.op(Op::I32And), w.set(kI0);
  foldVecEa(w);
  pushGuestLinear(w, kI0), w.c.simdMem(Simd::V128Load, 4, 0);
  w.get(kV0);  // placeholder operand for the shuffle (unused lanes)
  w.c.shuffle(kRevWords);
  w.setV(vD(w));
}

void build_stvx(W& w) {
  pushVecEa(w), w.i32(~0xF), w.op(Op::I32And), w.set(kI0);
  foldVecEa(w);
  pushGuestLinear(w, kI0);
  w.pushV(vD(w)), w.get(kV0), w.c.shuffle(kRevWords);
  w.c.simdMem(Simd::V128Store, 4, 0);
}

/// Pushes the aligned block at kI0 & ~15 swizzled by ((splat(base + s) - iota) ^ 3), where
/// s = kI0 & 15: the VectorMaskL/R rows of intrinsics.h, with ^3 for the stored word order.
/// Indices >= 16 give zero, as the 0xFF entries do in shuffle_epi8.
void pushMaskedLoad(W& w, int32_t base) {
  w.get(kI0), w.i32(~0xF), w.op(Op::I32And), w.set(kI1);
  pushGuestLinear(w, kI1), w.c.simdMem(Simd::V128Load, 4, 0);
  w.get(kI0), w.i32(0xF), w.op(Op::I32And), w.i32(base), w.op(Op::I32Add),
      w.simd(Simd::I8x16Splat);
  w.c.v128Const(kIota), w.simd(Simd::I8x16Sub);
  w.c.i8x16Splat(3), w.simd(Simd::V128Xor);
  w.simd(Simd::I8x16Swizzle);
}

/// lvlx: VectorMaskL row s = (15 + s - k) for k >= s.
void build_lvlx(W& w) {
  pushVecEa(w), w.set(kI0);
  foldVecEa(w);
  pushMaskedLoad(w, 15);
  w.setV(vD(w));
}

/// lvrx: VectorMaskR row s = (s - 1 - k) for k < s; zero when s = 0.
void build_lvrx(W& w) {
  pushVecEa(w), w.set(kI0);
  foldVecEa(w);
  pushMaskedLoad(w, -1);
  w.setV(vD(w));
}

/// lvsl / lvsr: VectorShiftTableL/R rows as values.
template <bool Right>
void build_lvs(W& w) {
  pushVecEa(w), w.i32(0xF), w.op(Op::I32And), w.set(kI0);
  if (Right)
    w.i32(31), w.get(kI0), w.op(Op::I32Sub);
  else
    w.get(kI0), w.i32(15), w.op(Op::I32Add);
  w.simd(Simd::I8x16Splat);
  w.c.v128Const(kIota), w.simd(Simd::I8x16Sub);
  w.setV(vD(w));
}

/// Pushes the i64 address ctx + (local) for dynamic byte access into the register context.
void pushCtxPlus(W& w, uint32_t local) {
  w.get(kLocalCtx), w.get(local), w.op(Op::I64ExtendI32U), w.op(Op::I64Add);
}

/// stvebx: guest byte ea & 15 of the register (host byte 15 - (ea & 15)).
void build_stvebx(W& w) {
  pushVecEa(w), w.set(kI0);
  foldVecEa(w);
  w.i32(15), w.get(kI0), w.i32(0xF), w.op(Op::I32And), w.op(Op::I32Sub), w.set(kI1);
  w.get(kI0), w.i32(3), w.op(Op::I32Xor), w.op(Op::I64ExtendI32U);
  pushCtxPlus(w, kI1), w.c.mem(Op::I32Load8U, 0, w.L().v[vD(w)]);
  w.c.mem(Op::I32Store8, 0, kGuestBase);
}

/// stvehx: u16[7 - ((ea & 15) >> 1)] at ea & ~1.
void build_stvehx(W& w) {
  pushVecEa(w), w.i32(~1), w.op(Op::I32And), w.set(kI0);
  foldVecEa(w);
  w.i32(14), w.get(kI0), w.i32(0xE), w.op(Op::I32And), w.op(Op::I32Sub), w.set(kI1);
  w.get(kI0), w.i32(2), w.op(Op::I32Xor), w.op(Op::I64ExtendI32U);
  pushCtxPlus(w, kI1), w.c.mem(Op::I32Load16U, 1, w.L().v[vD(w)]);
  w.c.mem(Op::I32Store16, 1, kGuestBase);
}

/// stvewx: u32[3 - ((ea & 15) >> 2)] at ea & ~3.
void build_stvewx(W& w) {
  pushVecEa(w), w.i32(~3), w.op(Op::I32And), w.set(kI0);
  foldVecEa(w);
  w.i32(12), w.get(kI0), w.i32(0xC), w.op(Op::I32And), w.op(Op::I32Sub), w.set(kI1);
  w.get(kI0), w.op(Op::I64ExtendI32U);
  pushCtxPlus(w, kI1), w.c.mem(Op::I32Load, 2, w.L().v[vD(w)]);
  w.c.mem(Op::I32Store, 2, kGuestBase);
}

/// Byte loop of stvlx/stvrx: for (i = 0; i < count(kI2); i++) store byte. `left`: stvlx
/// (guest ea + i <- host byte 15 - i), else stvrx (guest ea - i - 1 <- host byte i).
void storeBytesLoop(W& w, bool left) {
  w.i32(0), w.set(kI1);
  w.beginBlock();
  w.c.loop();
  ++w.st.depth;
  w.get(kI1), w.get(kI2), w.op(Op::I32GeU), w.c.brIf(1);
  // address
  if (left)
    w.get(kI0), w.get(kI1), w.op(Op::I32Add);
  else
    w.get(kI0), w.get(kI1), w.op(Op::I32Sub), w.i32(1), w.op(Op::I32Sub);
  w.i32(3), w.op(Op::I32Xor), w.op(Op::I64ExtendI32U);
  // value
  if (left) {
    w.i32(15), w.get(kI1), w.op(Op::I32Sub), w.set(kI3);
    pushCtxPlus(w, kI3);
  } else {
    pushCtxPlus(w, kI1);
  }
  w.c.mem(Op::I32Load8U, 0, w.L().v[vD(w)]);
  w.c.mem(Op::I32Store8, 0, kGuestBase);
  w.get(kI1), w.i32(1), w.op(Op::I32Add), w.set(kI1);
  w.c.br(0);
  w.end();  // loop
  w.end();  // block
}

void build_stvlx(W& w) {
  pushVecEa(w), w.set(kI0);
  foldVecEa(w);
  w.i32(16), w.get(kI0), w.i32(0xF), w.op(Op::I32And), w.op(Op::I32Sub), w.set(kI2);
  storeBytesLoop(w, true);
}

void build_stvrx(W& w) {
  pushVecEa(w), w.set(kI0);
  foldVecEa(w);
  w.get(kI0), w.i32(0xF), w.op(Op::I32And), w.set(kI2);
  storeBytesLoop(w, false);
}

//=============================================================================
// Float arithmetic (flush mode on)
//=============================================================================

template <uint32_t Opcode>
void build_vfp_binary(W& w) {
  pushVf(w, vA(w)), pushVf(w, vB(w)), w.simd(Opcode);
  flush(w);
  w.setV(vD(w));
}

/// vmaddfp: (A * B) + C, two roundings (simde mul then add); operands as the C++ builder.
void build_vmaddfp(W& w) {
  pushVf(w, vA(w)), pushVf(w, vB(w)), w.simd(Simd::F32x4Mul), flush(w);
  pushVf(w, vC(w)), w.simd(Simd::F32x4Add), flush(w);
  w.setV(vD(w));
}

/// vnmsubfp: -((A * B) - C), negated through the sign bit.
void build_vnmsubfp(W& w) {
  pushVf(w, vA(w)), pushVf(w, vB(w)), w.simd(Simd::F32x4Mul), flush(w);
  pushVf(w, vC(w)), w.simd(Simd::F32x4Sub), flush(w);
  w.c.i32x4Splat(kSign), w.simd(Simd::V128Xor);
  w.setV(vD(w));
}

/// vmaxfp / vminfp: SSE maxps(a, b) = a > b ? a : b = pmax(b, a); minps likewise pmin(b, a).
template <uint32_t Opcode>
void build_vminmax(W& w) {
  pushVf(w, vB(w)), pushVf(w, vA(w)), w.simd(Opcode);
  w.setV(vD(w));
}

void build_vrefp(W& w) {
  w.c.i32x4Splat(std::bit_cast<uint32_t>(1.0f)), pushVf(w, vA(w)), w.simd(Simd::F32x4Div);
  flush(w);
  w.setV(vD(w));
}

void build_vrsqrtefp(W& w) {
  w.c.i32x4Splat(std::bit_cast<uint32_t>(1.0f));
  pushVf(w, vA(w)), w.simd(Simd::F32x4Sqrt), w.simd(Simd::F32x4Div);
  flush(w);
  w.setV(vD(w));
}

template <uint32_t Opcode>
void build_vround(W& w) {
  pushVf(w, vA(w)), w.simd(Opcode), w.setV(vD(w));
}

/// SSE cvttps2dq: truncation, INT_MIN for NaN and out-of-range lanes.
void cvttps(W& w) {
  w.tee(kV5);
  w.simd(Simd::I32x4TruncSatF32x4S);
  w.c.i32x4Splat(kSign);
  w.get(kV5), w.c.i32x4Splat(std::bit_cast<uint32_t>(2147483648.0f)), w.simd(Simd::F32x4Lt);
  w.simd(Simd::V128Bitselect);
}

/// vexptefp: 2^floor(x) * poly(x - floor(x)), the C++ builder's minimax polynomial.
void build_vexptefp(W& w) {
  auto splat = [&](float f) { w.c.i32x4Splat(std::bit_cast<uint32_t>(f)); };
  pushVf(w, vA(w)), w.set(kV0);
  w.get(kV0), w.simd(Simd::F32x4Floor), w.set(kV1);
  w.get(kV0), w.get(kV1), w.simd(Simd::F32x4Sub), w.set(kV2);
  splat(1.8775767e-3f);
  const float coeffs[] = {8.9893397e-3f, 5.5826318e-2f, 2.4015361e-1f, 6.9315308e-1f, 1.0f};
  for (float k : coeffs) {
    w.get(kV2), w.simd(Simd::F32x4Mul), splat(k), w.simd(Simd::F32x4Add);
  }
  w.get(kV1), cvttps(w), w.c.i32x4Splat(127), w.simd(Simd::I32x4Add), w.i32(23),
      w.simd(Simd::I32x4Shl);
  w.simd(Simd::F32x4Mul);
  flush(w);
  w.setV(vD(w));
}

/// vlogefp: log2f per lane through the module's helper.
void build_vlogefp(W& w) {
  pushVf(w, vA(w)), w.set(kV0);
  for (uint8_t i = 0; i < 4; ++i) {
    w.get(kV0);
    w.get(kV0), w.c.simdLane(Simd::F32x4ExtractLane, i), w.c.call(w.env.fnLog2f);
    w.c.simdLane(Simd::F32x4ReplaceLane, i), w.set(kV0);
  }
  w.get(kV0), flush(w), w.setV(vD(w));
}

/// vmsum3fp128 / vmsum4fp128: SSE4.1 dpps with masks 0xEF / 0xFF, whose sum order is
/// (p0 + p1) + (p2 + p3) with masked-out products as +0.0; the sum goes to every lane.
template <bool Three>
void build_vmsum(W& w) {
  pushVf(w, vA(w)), pushVf(w, vB(w)), w.simd(Simd::F32x4Mul), flush(w);
  if (Three)
    w.c.f32Const(0.0f), w.c.simdLane(Simd::F32x4ReplaceLane, 0);
  w.tee(kV0);
  constexpr uint8_t kPairs[16] = {4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11};
  w.get(kV0), w.get(kV0), w.c.shuffle(kPairs), w.simd(Simd::F32x4Add), flush(w);
  w.tee(kV0);
  constexpr uint8_t kHalves[16] = {8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7};
  w.get(kV0), w.get(kV0), w.c.shuffle(kHalves), w.simd(Simd::F32x4Add), flush(w);
  w.tee(kV0);
  constexpr uint8_t kLane0[16] = {0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3};
  w.get(kV0), w.c.shuffle(kLane0);
  w.setV(vD(w));
}

//=============================================================================
// Integer arithmetic and logic
//=============================================================================

template <uint32_t Opcode>
void build_vint(W& w) {
  w.pushV(vA(w)), w.pushV(vB(w)), w.simd(Opcode), w.setV(vD(w));
}

/// op(vB, vA): the C++ emit_vec_int_binary_swapped forms.
template <uint32_t Opcode>
void build_vint_swapped(W& w) {
  w.pushV(vB(w)), w.pushV(vA(w)), w.simd(Opcode), w.setV(vD(w));
}

/// Signed word saturation from sum (V2) and overflow mask (on the stack, sign bit per lane).
void saturateWords(W& w) {
  w.set(kV3);
  w.get(kV0), w.i32(31), w.simd(Simd::I32x4ShrS), w.c.i32x4Splat(0x7FFFFFFF),
      w.simd(Simd::V128Xor);
  w.get(kV2);
  w.get(kV3), w.i32(31), w.simd(Simd::I32x4ShrS);
  w.simd(Simd::V128Bitselect);
}

void build_vaddsws(W& w) {
  w.pushV(vA(w)), w.set(kV0), w.pushV(vB(w)), w.set(kV1);
  w.get(kV0), w.get(kV1), w.simd(Simd::I32x4Add), w.set(kV2);
  w.get(kV0), w.get(kV2), w.simd(Simd::V128Xor), w.get(kV1), w.get(kV2), w.simd(Simd::V128Xor);
  w.simd(Simd::V128And);
  saturateWords(w);
  w.setV(vD(w));
}

void build_vsubsws(W& w) {
  w.pushV(vA(w)), w.set(kV0), w.pushV(vB(w)), w.set(kV1);
  w.get(kV0), w.get(kV1), w.simd(Simd::I32x4Sub), w.set(kV2);
  w.get(kV0), w.get(kV1), w.simd(Simd::V128Xor), w.get(kV0), w.get(kV2), w.simd(Simd::V128Xor);
  w.simd(Simd::V128And);
  saturateWords(w);
  w.setV(vD(w));
}

/// vadduws: a + min_u(~a, b).
void build_vadduws(W& w) {
  w.pushV(vA(w)), w.tee(kV0);
  w.get(kV0), w.simd(Simd::V128Not), w.pushV(vB(w)), w.simd(Simd::I32x4MinU);
  w.simd(Simd::I32x4Add), w.setV(vD(w));
}

/// vsubuws: a - min_u(a, b).
void build_vsubuws(W& w) {
  w.pushV(vA(w)), w.tee(kV0);
  w.get(kV0), w.pushV(vB(w)), w.simd(Simd::I32x4MinU);
  w.simd(Simd::I32x4Sub), w.setV(vD(w));
}

/// vavgsb / vavgsh: avgr_u on sign-flipped lanes (intrinsics.h simde_mm_avg_epi8/16).
template <bool Half>
void build_vavgs(W& w) {
  auto bias = [&] { Half ? w.c.i32x4Splat(0x80008000u) : w.c.i8x16Splat(0x80); };
  w.pushV(vA(w)), bias(), w.simd(Simd::V128Xor);
  w.pushV(vB(w)), bias(), w.simd(Simd::V128Xor);
  w.simd(Half ? Simd::I16x8AvgrU : Simd::I8x16AvgrU);
  bias(), w.simd(Simd::V128Xor);
  w.setV(vD(w));
}

/// vavgsw: (a >> 1) + (b >> 1) + ((a | b) & 1).
void build_vavgsw(W& w) {
  w.pushV(vA(w)), w.set(kV0), w.pushV(vB(w)), w.set(kV1);
  w.get(kV0), w.i32(1), w.simd(Simd::I32x4ShrS), w.get(kV1), w.i32(1), w.simd(Simd::I32x4ShrS);
  w.simd(Simd::I32x4Add);
  w.get(kV0), w.get(kV1), w.simd(Simd::V128Or), w.c.i32x4Splat(1), w.simd(Simd::V128And);
  w.simd(Simd::I32x4Add), w.setV(vD(w));
}

void build_vandc(W& w) {
  w.pushV(vA(w)), w.pushV(vB(w)), w.simd(Simd::V128AndNot), w.setV(vD(w));
}

void build_vor(W& w) {
  w.pushV(vA(w));
  if (vA(w) != vB(w))
    w.pushV(vB(w)), w.simd(Simd::V128Or);
  w.setV(vD(w));
}

void build_vxor(W& w) {
  if (vA(w) != vB(w))
    w.pushV(vA(w)), w.pushV(vB(w)), w.simd(Simd::V128Xor);
  else
    w.c.i32x4Splat(0);
  w.setV(vD(w));
}

void build_vnor(W& w) {
  w.pushV(vA(w)), w.pushV(vB(w)), w.simd(Simd::V128Or), w.simd(Simd::V128Not), w.setV(vD(w));
}

/// vsel: (~C & A) | (C & B).
void build_vsel(W& w) {
  w.pushV(vB(w)), w.pushV(vA(w)), w.pushV(vC(w)), w.simd(Simd::V128Bitselect), w.setV(vD(w));
}

//=============================================================================
// Compares (Rc forms set CR6)
//=============================================================================

template <uint32_t Opcode>
void build_vcmp_fp(W& w) {
  pushVf(w, vA(w)), pushVf(w, vB(w)), w.simd(Opcode);
  finishCompare(w, false);
}

template <uint32_t Opcode, bool Bytes>
void build_vcmp_int(W& w) {
  w.pushV(vA(w)), w.pushV(vB(w)), w.simd(Opcode);
  finishCompare(w, Bytes);
}

/// vcmpbfp: bit 31 = A > B, bit 30 = A < -B; CR6 sees either bit (D | D << 1).
void build_vcmpbfp(W& w) {
  pushVf(w, vA(w)), w.set(kV0), pushVf(w, vB(w)), w.set(kV1);
  w.get(kV0), w.get(kV1), w.simd(Simd::F32x4Gt), w.c.i32x4Splat(kSign), w.simd(Simd::V128And);
  w.get(kV0), w.get(kV1), w.c.i32x4Splat(kSign), w.simd(Simd::V128Xor), w.simd(Simd::F32x4Lt);
  w.c.i32x4Splat(0x40000000), w.simd(Simd::V128And);
  w.simd(Simd::V128Or);
  if (w.recordName()) {
    w.tee(kV0), w.setV(vD(w));
    w.get(kV0), w.get(kV0), w.i32(1), w.simd(Simd::I32x4Shl), w.simd(Simd::V128Or);
    setCr6(w, false);
  } else {
    w.setV(vD(w));
  }
}

//=============================================================================
// Conversions (intrinsics.h simde_mm_vctsxs / vctuxs / cvtepu32_ps_)
//=============================================================================

void pushScaled(W& w) {
  pushVf(w, vA(w));
  if (w.opnd(2) != 0) {
    w.c.i32x4Splat(std::bit_cast<uint32_t>(static_cast<float>(1u << w.opnd(2))));
    w.simd(Simd::F32x4Mul);
  }
}

/// vctsxs: NaN -> 0, saturating truncation (what simde_mm_vctsxs computes).
void build_vctsxs(W& w) {
  pushScaled(w), w.simd(Simd::I32x4TruncSatF32x4S), w.setV(vD(w));
}

/// vctuxs: NaN and negatives -> 0, >= 2^32 -> 0xFFFFFFFF (simde_mm_vctuxs).
void build_vctuxs(W& w) {
  pushScaled(w), w.simd(Simd::I32x4TruncSatF32x4U), w.setV(vD(w));
}

/// vcfsx / vcfux: int to float, then * 2^-uimm.
template <uint32_t Opcode>
void build_vcf(W& w) {
  w.pushV(vA(w)), w.simd(Opcode);
  if (w.opnd(2) != 0) {
    const float scale = std::ldexp(1.0f, -static_cast<int32_t>(w.opnd(2)));
    w.c.i32x4Splat(std::bit_cast<uint32_t>(scale)), w.simd(Simd::F32x4Mul);
  }
  flush(w);
  w.setV(vD(w));
}

//=============================================================================
// Merges, permutes, splats
//=============================================================================

/// unpackhi/lo_epi{8,16,32}(first, second) as an i8x16.shuffle of (first, second).
void unpackLanes(uint8_t (&out)[16], bool high, uint32_t laneBytes) {
  const uint32_t lanes = 8 / laneBytes;
  const uint32_t start = high ? 8 : 0;
  uint32_t k = 0;
  for (uint32_t i = 0; i < lanes; ++i) {
    for (uint32_t b = 0; b < laneBytes; ++b)
      out[k++] = static_cast<uint8_t>(start + i * laneBytes + b);
    for (uint32_t b = 0; b < laneBytes; ++b)
      out[k++] = static_cast<uint8_t>(16 + start + i * laneBytes + b);
  }
}

/// vmrgh*/vmrgl*: unpack(vB, vA) (emit_vec_int_binary_swapped).
template <bool High, uint32_t LaneBytes>
void build_vmrg(W& w) {
  uint8_t lanes[16];
  unpackLanes(lanes, High, LaneBytes);
  w.pushV(vB(w)), w.pushV(vA(w)), w.c.shuffle(lanes), w.setV(vD(w));
}

/// vperm: byte k = (C[k] & 0x10 ? B : A)[15 - (C[k] & 15)] (simde_mm_perm_epi8_), as two
/// swizzles whose out-of-range indices give zero.
void build_vperm(W& w) {
  w.pushV(vC(w)), w.c.i8x16Splat(0x0F), w.simd(Simd::V128Xor), w.c.i8x16Splat(0x1F),
      w.simd(Simd::V128And), w.set(kV0);
  w.pushV(vA(w)), w.get(kV0), w.simd(Simd::I8x16Swizzle);
  w.pushV(vB(w)), w.get(kV0), w.c.i8x16Splat(0x10), w.simd(Simd::V128Xor),
      w.simd(Simd::I8x16Swizzle);
  w.simd(Simd::V128Or);
  w.setV(vD(w));
}

/// Shuffle lanes picking 32-bit lane sel[i] (0-3 first operand, 4-7 second) for lane i.
void wordLanes(uint8_t (&out)[16], const uint32_t (&sel)[4]) {
  for (uint32_t i = 0; i < 4; ++i)
    for (uint32_t b = 0; b < 4; ++b)
      out[4 * i + b] = static_cast<uint8_t>(4 * sel[i] + b);
}

/// vpermwi128: shuffle_epi32 with the guest selectors reversed.
void build_vpermwi128(W& w) {
  const uint32_t imm = w.opnd(2);
  const uint32_t sel[4] = {3 - (imm & 3), 3 - ((imm >> 2) & 3), 3 - ((imm >> 4) & 3),
                           3 - ((imm >> 6) & 3)};
  uint8_t lanes[16];
  wordLanes(lanes, sel);
  w.pushV(vA(w)), w.get(kV0), w.c.shuffle(lanes), w.setV(vD(w));
}

/// vrlimi128: blend_ps(vD, permute_ps(vA, rotation), mask).
void build_vrlimi128(W& w) {
  constexpr uint32_t kShuffles[] = {0xE4, 0x93, 0x4E, 0x39};
  const uint32_t mask = w.opnd(2);
  const uint32_t perm = kShuffles[w.opnd(3) & 3];
  uint32_t sel[4];
  for (uint32_t i = 0; i < 4; ++i)
    sel[i] = (mask >> i) & 1 ? 4 + ((perm >> (2 * i)) & 3) : i;
  uint8_t lanes[16];
  wordLanes(lanes, sel);
  w.pushV(vD(w)), w.pushV(vA(w)), w.c.shuffle(lanes), w.setV(vD(w));
}

/// vsldoi: alignr_epi8(vA, vB, 16 - sh).
void build_vsldoi(W& w) {
  const uint32_t n = 16 - (w.opnd(3) & 15);
  uint8_t lanes[16];
  for (uint32_t k = 0; k < 16; ++k)
    lanes[k] = static_cast<uint8_t>(k + n);
  w.pushV(vB(w)), w.pushV(vA(w)), w.c.shuffle(lanes), w.setV(vD(w));
}

template <uint32_t LaneBytes>
void build_vsplt(W& w) {
  const uint32_t count = 16 / LaneBytes;
  const uint32_t lane = count - 1 - (w.opnd(2) & (count - 1));
  uint8_t lanes[16];
  for (uint32_t k = 0; k < 16; ++k)
    lanes[k] = static_cast<uint8_t>(lane * LaneBytes + k % LaneBytes);
  w.pushV(vA(w)), w.get(kV0), w.c.shuffle(lanes), w.setV(vD(w));
}

/// vspltisb/h/w: the sign-extended 5-bit immediate in every lane.
template <uint32_t LaneBytes>
void build_vspltis(W& w) {
  const int32_t imm = static_cast<int8_t>(static_cast<uint8_t>(w.opnd(1) << 3)) >> 3;
  if (LaneBytes == 1) {
    w.c.i8x16Splat(static_cast<uint8_t>(imm));
  } else if (LaneBytes == 2) {
    const uint32_t h = static_cast<uint16_t>(imm);
    w.c.i32x4Splat(h | (h << 16));
  } else {
    w.c.i32x4Splat(static_cast<uint32_t>(imm));
  }
  w.setV(vD(w));
}

//=============================================================================
// Shifts and rotates
//=============================================================================

enum class ShiftKind { Shl, ShrU, ShrS, Rotl };

/// Pushes a splat of `value` in lanes of `laneBits`.
void splatLanes(W& w, uint32_t laneBits, uint32_t value) {
  if (laneBits == 8)
    w.c.i8x16Splat(static_cast<uint8_t>(value));
  else if (laneBits == 16)
    w.c.i32x4Splat((value & 0xFFFF) | (value << 16));
  else
    w.c.i32x4Splat(value);
}

/// Per-lane variable shift (simde sllv/srlv/srav emulations): the count (vB & countMask) is
/// applied one bit at a time with constant lane shifts and selects.
template <uint32_t LaneBits, ShiftKind Kind>
void build_vshift(W& w) {
  const uint32_t shl = LaneBits == 8 ? Simd::I8x16Shl : LaneBits == 16 ? Simd::I16x8Shl
                                                                        : Simd::I32x4Shl;
  const uint32_t shrU = LaneBits == 8 ? Simd::I8x16ShrU : LaneBits == 16 ? Simd::I16x8ShrU
                                                                          : Simd::I32x4ShrU;
  const uint32_t shrS = LaneBits == 8 ? Simd::I8x16ShrS : LaneBits == 16 ? Simd::I16x8ShrS
                                                                          : Simd::I32x4ShrS;
  const uint32_t eq = LaneBits == 8 ? Simd::I8x16Eq : LaneBits == 16 ? Simd::I16x8Eq
                                                                      : Simd::I32x4Eq;
  w.pushV(vA(w)), w.set(kV0);
  w.pushV(vB(w)), splatLanes(w, LaneBits, LaneBits - 1), w.simd(Simd::V128And), w.set(kV1);
  for (uint32_t k = 1; k < LaneBits; k <<= 1) {
    // shifted
    w.get(kV0), w.i32(static_cast<int32_t>(k));
    switch (Kind) {
      case ShiftKind::Shl:
        w.simd(shl);
        break;
      case ShiftKind::ShrU:
        w.simd(shrU);
        break;
      case ShiftKind::ShrS:
        w.simd(shrS);
        break;
      case ShiftKind::Rotl:
        w.simd(shl);
        w.get(kV0), w.i32(static_cast<int32_t>(LaneBits - k)), w.simd(shrU);
        w.simd(Simd::V128Or);
        break;
    }
    w.get(kV0);
    w.get(kV1), splatLanes(w, LaneBits, k), w.simd(Simd::V128And), splatLanes(w, LaneBits, k),
        w.simd(eq);
    w.simd(Simd::V128Bitselect), w.set(kV0);
  }
  w.get(kV0), w.setV(vD(w));
}

/// vsl: 128-bit left shift by host byte 15 & 7 (simde_mm_vsl).
void build_vsl(W& w) {
  w.pushV(vB(w)), w.c.simdLane(Simd::I8x16ExtractLaneU, 15), w.i32(7), w.op(Op::I32And),
      w.set(kI0);
  w.pushV(vA(w)), w.set(kV0);
  w.get(kV0), w.get(kI0), w.simd(Simd::I64x2Shl);
  w.c.i32x4Splat(0);
  w.get(kV0), w.i32(1), w.simd(Simd::I64x2ShrU), w.i32(63), w.get(kI0), w.op(Op::I32Sub),
      w.simd(Simd::I64x2ShrU);
  constexpr uint8_t kUp[16] = {0, 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21, 22, 23};
  w.c.shuffle(kUp);
  w.simd(Simd::V128Or), w.setV(vD(w));
}

/// vsr: 128-bit right shift by host byte 0 & 7 (simde_mm_vsr).
void build_vsr(W& w) {
  w.pushV(vB(w)), w.c.simdLane(Simd::I8x16ExtractLaneU, 0), w.i32(7), w.op(Op::I32And),
      w.set(kI0);
  w.pushV(vA(w)), w.set(kV0);
  w.get(kV0), w.get(kI0), w.simd(Simd::I64x2ShrU);
  w.get(kV0), w.i32(1), w.simd(Simd::I64x2Shl), w.i32(63), w.get(kI0), w.op(Op::I32Sub),
      w.simd(Simd::I64x2Shl);
  w.c.i32x4Splat(0);
  constexpr uint8_t kDown[16] = {8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23};
  w.c.shuffle(kDown);
  w.simd(Simd::V128Or), w.setV(vD(w));
}

/// vslo / vsro: byte shift by (host byte 0 >> 3) & 15 (simde_mm_vslo / vsro).
template <bool Right>
void build_vso(W& w) {
  w.pushV(vA(w));
  w.c.v128Const(kIota);
  w.pushV(vB(w)), w.c.simdLane(Simd::I8x16ExtractLaneU, 0), w.i32(3), w.op(Op::I32ShrU),
      w.i32(0xF), w.op(Op::I32And), w.simd(Simd::I8x16Splat);
  w.simd(Right ? Simd::I8x16Add : Simd::I8x16Sub);
  w.simd(Simd::I8x16Swizzle);
  w.setV(vD(w));
}

//=============================================================================
// Packs and unpacks
//=============================================================================

/// narrow(op(vB), op(vA)): packs put vB in the low lanes (the C++ builders pass vB first).
void pack(W& w, uint32_t narrowOp, int pre, uint32_t preMask) {
  auto prep = [&](uint32_t reg) {
    w.pushV(reg);
    if (pre == 1)
      w.c.i32x4Splat(preMask), w.simd(Simd::V128And);
    else if (pre == 2)
      w.c.i32x4Splat(preMask), w.simd(narrowOp == Simd::I8x16NarrowI16x8U ? Simd::I16x8MinU
                                                                            : Simd::I32x4MinU);
  };
  prep(vB(w));
  prep(vA(w));
  w.simd(narrowOp);
  w.setV(vD(w));
}

void build_vpkshus(W& w) {
  pack(w, Simd::I8x16NarrowI16x8U, 0, 0);
}
void build_vpkuhum(W& w) {
  pack(w, Simd::I8x16NarrowI16x8U, 1, 0x00FF00FF);
}
/// vpkuhus: unsigned saturation (ReXGlue's scalar loop; here without its vD-aliasing
/// hazard, where writing vD before reading every element of vA/vB corrupts the result).
void build_vpkuhus(W& w) {
  pack(w, Simd::I8x16NarrowI16x8U, 2, 0x00FF00FF);
}
void build_vpkuwum(W& w) {
  pack(w, Simd::I16x8NarrowI32x4U, 1, 0x0000FFFF);
}
void build_vpkuwus(W& w) {
  pack(w, Simd::I16x8NarrowI32x4U, 2, 0x0000FFFF);
}
void build_vpkshss(W& w) {
  pack(w, Simd::I8x16NarrowI16x8S, 0, 0);
}
void build_vpkswss(W& w) {
  pack(w, Simd::I16x8NarrowI32x4S, 0, 0);
}
void build_vpkswus(W& w) {
  pack(w, Simd::I16x8NarrowI32x4U, 0, 0);
}

template <uint32_t Opcode>
void build_vupk(W& w) {
  w.pushV(vA(w)), w.simd(Opcode), w.setV(vD(w));
}

//=============================================================================
// vpkd3d128 / vupkd3d128: the C++ builders' scalar sequences, lane by lane on the context
// (same read/write order, so a vD that aliases vA behaves the same)
//=============================================================================

/// Context-relative scalar access to a lane of vN.
void loadLane(W& w, uint32_t reg, uint32_t byteOff, uint8_t opcode, uint32_t alignLog2) {
  w.get(kLocalCtx), w.c.mem(opcode, alignLog2, w.L().v[reg] + byteOff);
}

/// Stores the value in `local` to a lane of vN.
void storeLane(W& w, uint32_t reg, uint32_t byteOff, uint8_t opcode, uint32_t alignLog2,
               uint32_t local) {
  w.get(kLocalCtx), w.get(local), w.c.mem(opcode, alignLog2, w.L().v[reg] + byteOff);
}

/// i32 on the stack clamped to [-32767, 32767].
void clampShort(W& w) {
  w.set(kI2);
  w.i32(32767);
  w.i32(-32767), w.get(kI2), w.get(kI2), w.i32(-32767), w.op(Op::I32LtS), w.op(Op::Select);
  w.get(kI2), w.i32(32767), w.op(Op::I32GtS), w.op(Op::Select);
}

/// f32 in kS0 clamped as `x < lo ? lo : (x > hi ? hi : x)` (NaN passes through); pushes bits.
void clampFloatBits(W& w, uint32_t loBits, uint32_t hiBits) {
  const float lo = std::bit_cast<float>(loBits), hi = std::bit_cast<float>(hiBits);
  w.c.f32Const(lo);
  w.c.f32Const(hi), w.get(kS0), w.get(kS0), w.c.f32Const(hi), w.op(Op::F32Gt), w.op(Op::Select);
  w.get(kS0), w.c.f32Const(lo), w.op(Op::F32Lt), w.op(Op::Select);
  w.op(Op::I32ReinterpretF32);
}

/// float -> half as the FLOAT16 cases do, for source lane `src` and destination u16 `dst`.
void packHalf(W& w, uint32_t a, uint32_t d, uint32_t src, uint32_t dst) {
  const uint32_t srcOff = 4 * src, dstOff = 2 * dst;
  // t = A.u32[src] & 0x7FFFFFFF
  loadLane(w, a, srcOff, Op::I32Load, 2), w.i32(0x7FFFFFFF), w.op(Op::I32And), w.set(kI0);
  // e = isnan(t) || t > 65504 ? 0xFF : (A.u32[src] & 0x7F800000) >> 23
  w.i32(0xFF);
  loadLane(w, a, srcOff, Op::I32Load, 2), w.i32(0x7F800000), w.op(Op::I32And), w.i32(23),
      w.op(Op::I32ShrU);
  w.get(kI0), w.op(Op::F32ReinterpretI32), w.set(kS0);
  w.get(kS0), w.get(kS0), w.op(Op::F32Ne), w.get(kS0), w.c.f32Const(65504.0f), w.op(Op::F32Gt),
      w.op(Op::I32Or);
  w.op(Op::Select), w.set(kI1);
  // m = e != 0xFF ? (A.u32[src] & 0x7FE000) >> 13 : 0
  loadLane(w, a, srcOff, Op::I32Load, 2), w.i32(0x7FE000), w.op(Op::I32And), w.i32(13),
      w.op(Op::I32ShrU);
  w.i32(0), w.get(kI1), w.i32(0xFF), w.op(Op::I32Ne), w.op(Op::Select), w.set(kI2);
  // D.u16[dst] = e != 0xFF ? (e > 0x70 ? ((e - 0x70) << 10) + m
  //                                    : (0x71 - e > 31 ? 0 : (0x400 + m) >> (0x71 - e))) : 0x7FFF
  w.get(kI1), w.i32(0x70), w.op(Op::I32Sub), w.i32(10), w.op(Op::I32Shl), w.get(kI2),
      w.op(Op::I32Add);
  w.i32(0);
  w.i32(0x400), w.get(kI2), w.op(Op::I32Add), w.i32(0x71), w.get(kI1), w.op(Op::I32Sub),
      w.op(Op::I32ShrU);
  w.i32(0x71), w.get(kI1), w.op(Op::I32Sub), w.i32(31), w.op(Op::I32GtS), w.op(Op::Select);
  w.get(kI1), w.i32(0x70), w.op(Op::I32GtS), w.op(Op::Select);
  w.i32(0x7FFF), w.get(kI1), w.i32(0xFF), w.op(Op::I32Ne), w.op(Op::Select), w.set(kI3);
  storeLane(w, d, dstOff, Op::I32Store16, 1, kI3);
  // D.u16[dst] |= (A.u32[src] & 0x80000000) >> 16
  loadLane(w, d, dstOff, Op::I32Load16U, 1);
  loadLane(w, a, srcOff, Op::I32Load, 2), w.i32(static_cast<int32_t>(kSign)), w.op(Op::I32And),
      w.i32(16), w.op(Op::I32ShrU);
  w.op(Op::I32Or), w.set(kI3);
  storeLane(w, d, dstOff, Op::I32Store16, 1, kI3);
}

/// cvttss2si: truncation, INT_MIN for NaN and out-of-range (f32 in kS0).
void pushCvttss(W& w) {
  w.i32(INT32_MIN);
  w.get(kS0), w.c.misc(Misc::I32TruncSatF32S);
  w.get(kS0), w.c.f32Const(2147483648.0f), w.op(Op::F32Lt), w.op(Op::Select);
}

void build_vpkd3d128(W& w) {
  const uint32_t d = vD(w), a = vA(w);
  const uint32_t type = w.opnd(2), mask = w.opnd(3), shift = w.opnd(4);
  switch (type) {
    case 0: {  // D3DCOLOR
      constexpr uint32_t kIndices[] = {3, 0, 1, 2};
      const float bias = std::bit_cast<float>(0x404000FFu);
      w.i32(0), w.set(kI4);
      for (uint32_t i = 0; i < 4; ++i) {
        loadLane(w, a, 4 * i, Op::F32Load, 2), w.set(kS0);
        // !(x >= 3) ? 3 : (x > bias ? bias : x)
        w.c.f32Const(3.0f);
        w.c.f32Const(bias), w.get(kS0), w.get(kS0), w.c.f32Const(bias), w.op(Op::F32Gt),
            w.op(Op::Select);
        w.get(kS0), w.c.f32Const(3.0f), w.op(Op::F32Ge), w.op(Op::I32Eqz), w.op(Op::Select);
        w.op(Op::I32ReinterpretF32), w.i32(0xFF), w.op(Op::I32And);
        w.i32(static_cast<int32_t>(kIndices[i] * 8)), w.op(Op::I32Shl);
        w.get(kI4), w.op(Op::I32Or), w.set(kI4);
      }
      w.i32(0), w.set(kI5);
      if (mask == 3 && shift == 3) {
        storeLane(w, d, 0, Op::I32Store, 2, kI5);
      } else {
        storeLane(w, d, 4 * (shift & 3), Op::I32Store, 2, kI4);
        if (mask >= 2 && shift < 3)
          storeLane(w, d, 4 * (shift + 1), Op::I32Store, 2, kI5);
      }
      break;
    }
    case 1:  // NORMSHORT2
      loadLane(w, a, 12, Op::I32Load, 2), w.i32(0x40400000), w.op(Op::I32Sub), clampShort(w);
      w.i32(0xFFFF), w.op(Op::I32And), w.i32(16), w.op(Op::I32Shl);
      loadLane(w, a, 8, Op::I32Load, 2), w.i32(0x40400000), w.op(Op::I32Sub), clampShort(w);
      w.i32(0xFFFF), w.op(Op::I32And), w.op(Op::I32Or), w.set(kI4);
      storeLane(w, d, 4 * (shift & 3), Op::I32Store, 2, kI4);
      break;
    case 2: {  // NORMPACKED32 (2:10:10:10)
      const uint32_t lanes[] = {3, 2, 1, 0};
      const uint32_t shifts[] = {0, 10, 20, 30};
      w.i32(0), w.set(kI4);
      for (uint32_t i = 0; i < 4; ++i) {
        loadLane(w, a, 4 * lanes[i], Op::F32Load, 2), w.set(kS0);
        if (i < 3)
          clampFloatBits(w, 0x403FFE01u, 0x404001FFu), w.i32(0x3FF);
        else
          clampFloatBits(w, 0x40400000u, 0x40400003u), w.i32(0x3);
        w.op(Op::I32And), w.i32(static_cast<int32_t>(shifts[i])), w.op(Op::I32Shl);
        w.get(kI4), w.op(Op::I32Or), w.set(kI4);
      }
      storeLane(w, d, 4 * (shift & 3), Op::I32Store, 2, kI4);
      break;
    }
    case 3:  // FLOAT16_2
      for (uint32_t i = 0; i < 2; ++i)
        packHalf(w, a, d, 3 - i, (1 - i) + 2 * shift);
      break;
    case 4:  // NORMSHORT4
      for (uint32_t i = 0; i < 4; ++i) {
        loadLane(w, a, 4 * (3 - i), Op::I32Load, 2), w.i32(0x40400000), w.op(Op::I32Sub),
            clampShort(w), w.set(kI4);
        storeLane(w, d, 2 * ((3 - i) + 2 * shift), Op::I32Store16, 1, kI4);
      }
      break;
    case 5:  // FLOAT16_4
      if (mask != 2 || shift > 2)
        REXCODEGEN_WARN("Unexpected float16_4 pack instruction at {:X} (mask {}, shift {})",
                        w.base, mask, shift);
      for (uint32_t i = 0; i < 4; ++i)
        packHalf(w, a, d, 3 - i, (3 - i) + 2 * shift);
      break;
    case 6: {  // NORMPACKED64 (4:20:20:20), lanes in host order as the C++ builder reads them
      w.i64(0), w.set(kL4);
      const uint32_t shifts[] = {0, 20, 40, 60};
      for (uint32_t i = 0; i < 4; ++i) {
        loadLane(w, a, 4 * i, Op::F32Load, 2), w.set(kS0);
        pushCvttss(w);
        w.i32(i < 3 ? 0xFFFFF : 0xF), w.op(Op::I32And), w.op(Op::I64ExtendI32U);
        w.i64(shifts[i]), w.op(Op::I64Shl), w.get(kL4), w.op(Op::I64Or), w.set(kL4);
      }
      storeLane(w, d, 8 * ((shift >> 1) & 1), Op::I64Store, 3, kL4);
      break;
    }
    default:
      w.unimplemented("vpkd3d128 (unknown type)");
      break;
  }
}

void build_vupkd3d128(W& w) {
  const uint32_t d = vD(w), a = vA(w);
  // Builds the result in kV0 lane by lane (every case writes all four lanes, after reading
  // all of vA, so aliasing is not a concern), then stores it.
  auto lane = [&](uint8_t i) { w.c.simdLane(Simd::I32x4ReplaceLane, i), w.set(kV0); };
  auto half = [&](uint32_t u16Index) {
    // ((t & 0x8000) << 16) | (((t & 0x7C00) + 0x1C000) << 13) | ((t & 0x3FF) << 13), or the
    // signed zero when the exponent is zero
    loadLane(w, a, 2 * u16Index, Op::I32Load16U, 1), w.set(kI0);
    w.get(kI0), w.i32(0x8000), w.op(Op::I32And), w.i32(16), w.op(Op::I32Shl);
    w.get(kI0), w.i32(0x7C00), w.op(Op::I32And), w.i32(0x1C000), w.op(Op::I32Add), w.i32(13),
        w.op(Op::I32Shl), w.op(Op::I32Or);
    w.get(kI0), w.i32(0x3FF), w.op(Op::I32And), w.i32(13), w.op(Op::I32Shl), w.op(Op::I32Or);
    w.get(kI0), w.i32(0x8000), w.op(Op::I32And), w.i32(16), w.op(Op::I32Shl);
    w.get(kI0), w.i32(0x7C00), w.op(Op::I32And), w.op(Op::Select);
  };
  w.c.i32x4Splat(0), w.set(kV0);
  switch (w.opnd(2) >> 2) {
    case 0: {  // D3DCOLOR
      constexpr uint32_t kIndices[] = {3, 0, 1, 2};
      for (uint8_t i = 0; i < 4; ++i) {
        w.get(kV0);
        loadLane(w, a, kIndices[i], Op::I32Load8U, 0), w.i32(0x3F800000), w.op(Op::I32Or);
        lane(i);
      }
      break;
    }
    case 1:  // NORMSHORT2: 3.0f bits + s16, then 0.0, 1.0
      for (uint8_t i = 0; i < 2; ++i) {
        w.get(kV0);
        w.i32(0x40400000), loadLane(w, a, 2 * (1 - i), Op::I32Load16S, 1), w.op(Op::I32Add);
        lane(3 - i);
      }
      w.get(kV0), w.i32(0x3F800000), lane(0);
      break;
    case 2:  // NORMPACKED32
      loadLane(w, a, 0, Op::I32Load, 2), w.set(kI1);
      // x: -512 -> 0x7FC00000, else 3.0f bits + x
      w.get(kV0);
      w.i32(0x7FC00000);
      w.get(kI1), w.i32(22), w.op(Op::I32Shl), w.i32(22), w.op(Op::I32ShrS), w.tee(kI2),
          w.i32(0x40400000), w.op(Op::I32Add);
      w.get(kI2), w.i32(-512), w.op(Op::I32Eq), w.op(Op::Select);
      lane(3);
      w.get(kV0), w.get(kI1), w.i32(12), w.op(Op::I32Shl), w.i32(22), w.op(Op::I32ShrS),
          w.i32(0x40400000), w.op(Op::I32Add), lane(2);
      w.get(kV0), w.get(kI1), w.i32(2), w.op(Op::I32Shl), w.i32(22), w.op(Op::I32ShrS),
          w.i32(0x40400000), w.op(Op::I32Add), lane(1);
      w.get(kV0), w.get(kI1), w.i32(30), w.op(Op::I32ShrU), w.i32(0x3F800000), w.op(Op::I32Or),
          lane(0);
      break;
    case 3:  // FLOAT16_2
      for (uint8_t i = 0; i < 2; ++i) {
        w.get(kV0), half(1 - i), lane(3 - i);
      }
      w.get(kV0), w.i32(0x3F800000), lane(0);
      break;
    case 4:  // NORMSHORT4
      for (uint8_t i = 0; i < 4; ++i) {
        w.get(kV0);
        w.i32(0x40400000), loadLane(w, a, 2 * (3 - i), Op::I32Load16S, 1), w.op(Op::I32Add);
        lane(3 - i);
      }
      break;
    case 5:  // FLOAT16_4
      for (uint8_t i = 0; i < 4; ++i) {
        w.get(kV0), half(3 - i), lane(3 - i);
      }
      break;
    case 6: {  // NORMPACKED64: 20-bit signed x, y, z and 4-bit w from u64[1]. The C++ builder
               // narrows to int32 before its arithmetic shifts (truncating the fields, and
               // shifting by 44 is undefined); this takes the sign-extended fields it means.
      loadLane(w, a, 8, Op::I64Load, 3), w.set(kL4);
      const int64_t shifts[] = {44, 24, 4};
      for (uint8_t i = 0; i < 3; ++i) {
        w.get(kV0);
        w.get(kL4), w.i64(shifts[i]), w.op(Op::I64Shl), w.i64(44), w.op(Op::I64ShrS);
        w.op(Op::I32WrapI64), w.op(Op::F32ConvertI32S), w.op(Op::I32ReinterpretF32);
        lane(i);
      }
      w.get(kV0), w.get(kL4), w.i64(60), w.op(Op::I64ShrU), w.op(Op::I32WrapI64),
          w.op(Op::F32ConvertI32U), w.op(Op::I32ReinterpretF32), lane(3);
      break;
    }
    default:
      w.unimplemented("vupkd3d128 (unknown type)");
      return;
  }
  w.get(kV0), w.setV(d);
}

}  // namespace

void RegisterVectorBuilders(IdTable& t) {
  // Loads and stores
  for (int id : {PPC_INST_LVX, PPC_INST_LVX128, PPC_INST_LVXL, PPC_INST_LVXL128, PPC_INST_LVEBX,
                 PPC_INST_LVEHX, PPC_INST_LVEWX, PPC_INST_LVEWX128})
    t[id] = build_lvx;
  t[PPC_INST_LVLX] = build_lvlx;
  t[PPC_INST_LVLX128] = build_lvlx;
  t[PPC_INST_LVRX] = build_lvrx;
  t[PPC_INST_LVRX128] = build_lvrx;
  t[PPC_INST_LVSL] = build_lvs<false>;
  t[PPC_INST_LVSR] = build_lvs<true>;
  t[PPC_INST_STVEBX] = build_stvebx;
  t[PPC_INST_STVEHX] = build_stvehx;
  t[PPC_INST_STVEWX] = build_stvewx;
  t[PPC_INST_STVEWX128] = build_stvewx;
  t[PPC_INST_STVLX] = build_stvlx;
  t[PPC_INST_STVLX128] = build_stvlx;
  t[PPC_INST_STVLXL128] = build_stvlx;
  t[PPC_INST_STVRX] = build_stvrx;
  t[PPC_INST_STVRX128] = build_stvrx;
  t[PPC_INST_STVX] = build_stvx;
  t[PPC_INST_STVX128] = build_stvx;
  t[PPC_INST_STVXL] = build_stvx;

  // Float arithmetic
  t[PPC_INST_VADDFP] = build_vfp_binary<Simd::F32x4Add>;
  t[PPC_INST_VADDFP128] = build_vfp_binary<Simd::F32x4Add>;
  t[PPC_INST_VSUBFP] = build_vfp_binary<Simd::F32x4Sub>;
  t[PPC_INST_VSUBFP128] = build_vfp_binary<Simd::F32x4Sub>;
  t[PPC_INST_VMULFP128] = build_vfp_binary<Simd::F32x4Mul>;
  t[PPC_INST_VMADDFP] = build_vmaddfp;
  t[PPC_INST_VMADDFP128] = build_vmaddfp;
  t[PPC_INST_VMADDCFP128] = build_vmaddfp;
  t[PPC_INST_VNMSUBFP] = build_vnmsubfp;
  t[PPC_INST_VNMSUBFP128] = build_vnmsubfp;
  t[PPC_INST_VMAXFP] = build_vminmax<Simd::F32x4Pmax>;
  t[PPC_INST_VMAXFP128] = build_vminmax<Simd::F32x4Pmax>;
  t[PPC_INST_VMINFP] = build_vminmax<Simd::F32x4Pmin>;
  t[PPC_INST_VMINFP128] = build_vminmax<Simd::F32x4Pmin>;
  t[PPC_INST_VREFP] = build_vrefp;
  t[PPC_INST_VREFP128] = build_vrefp;
  t[PPC_INST_VRSQRTEFP] = build_vrsqrtefp;
  t[PPC_INST_VRSQRTEFP128] = build_vrsqrtefp;
  t[PPC_INST_VEXPTEFP] = build_vexptefp;
  t[PPC_INST_VEXPTEFP128] = build_vexptefp;
  t[PPC_INST_VLOGEFP] = build_vlogefp;
  t[PPC_INST_VLOGEFP128] = build_vlogefp;
  t[PPC_INST_VMSUM3FP128] = build_vmsum<true>;
  t[PPC_INST_VMSUM4FP128] = build_vmsum<false>;
  t[PPC_INST_VRFIM] = build_vround<Simd::F32x4Floor>;
  t[PPC_INST_VRFIM128] = build_vround<Simd::F32x4Floor>;
  t[PPC_INST_VRFIN] = build_vround<Simd::F32x4Nearest>;
  t[PPC_INST_VRFIN128] = build_vround<Simd::F32x4Nearest>;
  t[PPC_INST_VRFIP] = build_vround<Simd::F32x4Ceil>;
  t[PPC_INST_VRFIP128] = build_vround<Simd::F32x4Ceil>;
  t[PPC_INST_VRFIZ] = build_vround<Simd::F32x4Trunc>;
  t[PPC_INST_VRFIZ128] = build_vround<Simd::F32x4Trunc>;

  // Integer arithmetic
  t[PPC_INST_VADDSBS] = build_vint<Simd::I8x16AddSatS>;
  t[PPC_INST_VADDSHS] = build_vint<Simd::I16x8AddSatS>;
  t[PPC_INST_VADDSWS] = build_vaddsws;
  t[PPC_INST_VADDUBM] = build_vint<Simd::I8x16Add>;
  t[PPC_INST_VADDUBS] = build_vint<Simd::I8x16AddSatU>;
  t[PPC_INST_VADDUHM] = build_vint<Simd::I16x8Add>;
  t[PPC_INST_VADDUWM] = build_vint<Simd::I32x4Add>;
  t[PPC_INST_VADDUWS] = build_vadduws;
  t[PPC_INST_VADDUHS] = build_vint<Simd::I16x8AddSatU>;
  t[PPC_INST_VSUBSBS] = build_vint<Simd::I8x16SubSatS>;
  t[PPC_INST_VSUBSWS] = build_vsubsws;
  t[PPC_INST_VSUBUBM] = build_vint<Simd::I8x16Sub>;
  t[PPC_INST_VSUBUBS] = build_vint<Simd::I8x16SubSatU>;
  t[PPC_INST_VSUBUHS] = build_vint<Simd::I16x8SubSatU>;
  t[PPC_INST_VSUBUWS] = build_vsubuws;
  t[PPC_INST_VSUBUHM] = build_vint<Simd::I16x8Sub>;
  t[PPC_INST_VSUBUWM] = build_vint<Simd::I32x4Sub>;
  t[PPC_INST_VSUBSHS] = build_vint<Simd::I16x8SubSatS>;
  t[PPC_INST_VMAXSW] = build_vint<Simd::I32x4MaxS>;
  t[PPC_INST_VMAXSH] = build_vint<Simd::I16x8MaxS>;
  t[PPC_INST_VMAXSB] = build_vint<Simd::I8x16MaxS>;
  t[PPC_INST_VMINSH] = build_vint<Simd::I16x8MinS>;
  t[PPC_INST_VMINSB] = build_vint<Simd::I8x16MinS>;
  t[PPC_INST_VMINSW] = build_vint<Simd::I32x4MinS>;
  t[PPC_INST_VMAXUH] = build_vint<Simd::I16x8MaxU>;
  t[PPC_INST_VMINUH] = build_vint<Simd::I16x8MinU>;
  t[PPC_INST_VMAXUB] = build_vint<Simd::I8x16MaxU>;
  t[PPC_INST_VMINUB] = build_vint<Simd::I8x16MinU>;
  t[PPC_INST_VMINUW] = build_vint<Simd::I32x4MinU>;
  t[PPC_INST_VAVGSB] = build_vavgs<false>;
  t[PPC_INST_VAVGSH] = build_vavgs<true>;
  t[PPC_INST_VAVGSW] = build_vavgsw;
  t[PPC_INST_VAVGUB] = build_vint<Simd::I8x16AvgrU>;
  t[PPC_INST_VAVGUH] = build_vint<Simd::I16x8AvgrU>;

  // Logical
  t[PPC_INST_VAND] = build_vint<Simd::V128And>;
  t[PPC_INST_VAND128] = build_vint<Simd::V128And>;
  t[PPC_INST_VANDC] = build_vandc;
  t[PPC_INST_VANDC128] = build_vandc;
  t[PPC_INST_VOR] = build_vor;
  t[PPC_INST_VOR128] = build_vor;
  t[PPC_INST_VXOR] = build_vxor;
  t[PPC_INST_VXOR128] = build_vxor;
  t[PPC_INST_VNOR] = build_vnor;
  t[PPC_INST_VNOR128] = build_vnor;
  t[PPC_INST_VSEL] = build_vsel;
  t[PPC_INST_VSEL128] = build_vsel;

  // Compares
  t[PPC_INST_VCMPBFP] = build_vcmpbfp;
  t[PPC_INST_VCMPBFP128] = build_vcmpbfp;
  t[PPC_INST_VCMPEQFP] = build_vcmp_fp<Simd::F32x4Eq>;
  t[PPC_INST_VCMPEQFP128] = build_vcmp_fp<Simd::F32x4Eq>;
  t[PPC_INST_VCMPGEFP] = build_vcmp_fp<Simd::F32x4Ge>;
  t[PPC_INST_VCMPGEFP128] = build_vcmp_fp<Simd::F32x4Ge>;
  t[PPC_INST_VCMPGTFP] = build_vcmp_fp<Simd::F32x4Gt>;
  t[PPC_INST_VCMPGTFP128] = build_vcmp_fp<Simd::F32x4Gt>;
  t[PPC_INST_VCMPEQUB] = build_vcmp_int<Simd::I8x16Eq, true>;
  t[PPC_INST_VCMPEQUH] = build_vcmp_int<Simd::I16x8Eq, true>;
  t[PPC_INST_VCMPEQUW] = build_vcmp_int<Simd::I32x4Eq, false>;
  t[PPC_INST_VCMPEQUW128] = build_vcmp_int<Simd::I32x4Eq, false>;
  t[PPC_INST_VCMPGTUB] = build_vcmp_int<Simd::I8x16GtU, true>;
  t[PPC_INST_VCMPGTUH] = build_vcmp_int<Simd::I16x8GtU, true>;
  t[PPC_INST_VCMPGTUW] = build_vcmp_int<Simd::I32x4GtU, false>;
  t[PPC_INST_VCMPGTSB] = build_vcmp_int<Simd::I8x16GtS, true>;
  t[PPC_INST_VCMPGTSH] = build_vcmp_int<Simd::I16x8GtS, true>;
  t[PPC_INST_VCMPGTSW] = build_vcmp_int<Simd::I32x4GtS, false>;

  // Conversions
  t[PPC_INST_VCTSXS] = build_vctsxs;
  t[PPC_INST_VCFPSXWS128] = build_vctsxs;
  t[PPC_INST_VCTUXS] = build_vctuxs;
  t[PPC_INST_VCFPUXWS128] = build_vctuxs;
  t[PPC_INST_VCFSX] = build_vcf<Simd::F32x4ConvertI32x4S>;
  t[PPC_INST_VCSXWFP128] = build_vcf<Simd::F32x4ConvertI32x4S>;
  t[PPC_INST_VCFUX] = build_vcf<Simd::F32x4ConvertI32x4U>;
  t[PPC_INST_VCUXWFP128] = build_vcf<Simd::F32x4ConvertI32x4U>;

  // Merges, permutes, splats
  t[PPC_INST_VMRGHB] = build_vmrg<true, 1>;
  t[PPC_INST_VMRGHH] = build_vmrg<true, 2>;
  t[PPC_INST_VMRGHW] = build_vmrg<true, 4>;
  t[PPC_INST_VMRGHW128] = build_vmrg<true, 4>;
  t[PPC_INST_VMRGLB] = build_vmrg<false, 1>;
  t[PPC_INST_VMRGLH] = build_vmrg<false, 2>;
  t[PPC_INST_VMRGLW] = build_vmrg<false, 4>;
  t[PPC_INST_VMRGLW128] = build_vmrg<false, 4>;
  t[PPC_INST_VPERM] = build_vperm;
  t[PPC_INST_VPERM128] = build_vperm;
  t[PPC_INST_VPERMWI128] = build_vpermwi128;
  t[PPC_INST_VRLIMI128] = build_vrlimi128;
  t[PPC_INST_VSLDOI] = build_vsldoi;
  t[PPC_INST_VSLDOI128] = build_vsldoi;
  t[PPC_INST_VSPLTB] = build_vsplt<1>;
  t[PPC_INST_VSPLTH] = build_vsplt<2>;
  t[PPC_INST_VSPLTW] = build_vsplt<4>;
  t[PPC_INST_VSPLTW128] = build_vsplt<4>;
  t[PPC_INST_VSPLTISB] = build_vspltis<1>;
  t[PPC_INST_VSPLTISH] = build_vspltis<2>;
  t[PPC_INST_VSPLTISW] = build_vspltis<4>;
  t[PPC_INST_VSPLTISW128] = build_vspltis<4>;

  // Shifts and rotates
  t[PPC_INST_VSLB] = build_vshift<8, ShiftKind::Shl>;
  t[PPC_INST_VSLH] = build_vshift<16, ShiftKind::Shl>;
  t[PPC_INST_VSLW] = build_vshift<32, ShiftKind::Shl>;
  t[PPC_INST_VSLW128] = build_vshift<32, ShiftKind::Shl>;
  t[PPC_INST_VSRB] = build_vshift<8, ShiftKind::ShrU>;
  t[PPC_INST_VSRH] = build_vshift<16, ShiftKind::ShrU>;
  t[PPC_INST_VSRW] = build_vshift<32, ShiftKind::ShrU>;
  t[PPC_INST_VSRW128] = build_vshift<32, ShiftKind::ShrU>;
  t[PPC_INST_VSRAB] = build_vshift<8, ShiftKind::ShrS>;
  t[PPC_INST_VSRAH] = build_vshift<16, ShiftKind::ShrS>;
  t[PPC_INST_VSRAW] = build_vshift<32, ShiftKind::ShrS>;
  t[PPC_INST_VSRAW128] = build_vshift<32, ShiftKind::ShrS>;
  t[PPC_INST_VRLH] = build_vshift<16, ShiftKind::Rotl>;
  t[PPC_INST_VRLW] = build_vshift<32, ShiftKind::Rotl>;
  t[PPC_INST_VRLW128] = build_vshift<32, ShiftKind::Rotl>;
  t[PPC_INST_VSL] = build_vsl;
  t[PPC_INST_VSR] = build_vsr;
  t[PPC_INST_VSLO] = build_vso<false>;
  t[PPC_INST_VSLO128] = build_vso<false>;
  t[PPC_INST_VSRO] = build_vso<true>;
  t[PPC_INST_VSRO128] = build_vso<true>;

  // Packs and unpacks
  t[PPC_INST_VPKUHUM] = build_vpkuhum;
  t[PPC_INST_VPKUHUM128] = build_vpkuhum;
  t[PPC_INST_VPKUHUS] = build_vpkuhus;
  t[PPC_INST_VPKUHUS128] = build_vpkuhus;
  t[PPC_INST_VPKUWUM] = build_vpkuwum;
  t[PPC_INST_VPKUWUM128] = build_vpkuwum;
  t[PPC_INST_VPKUWUS] = build_vpkuwus;
  t[PPC_INST_VPKUWUS128] = build_vpkuwus;
  t[PPC_INST_VPKSHSS] = build_vpkshss;
  t[PPC_INST_VPKSHSS128] = build_vpkshss;
  t[PPC_INST_VPKSHUS] = build_vpkshus;
  t[PPC_INST_VPKSHUS128] = build_vpkshus;
  t[PPC_INST_VPKSWSS] = build_vpkswss;
  t[PPC_INST_VPKSWSS128] = build_vpkswss;
  t[PPC_INST_VPKSWUS] = build_vpkswus;
  t[PPC_INST_VPKSWUS128] = build_vpkswus;
  t[PPC_INST_VPKD3D128] = build_vpkd3d128;
  t[PPC_INST_VUPKD3D128] = build_vupkd3d128;
  t[PPC_INST_VUPKHSB] = build_vupk<Simd::I16x8ExtendHighI8x16S>;
  t[PPC_INST_VUPKHSB128] = build_vupk<Simd::I16x8ExtendHighI8x16S>;
  t[PPC_INST_VUPKHSH] = build_vupk<Simd::I32x4ExtendHighI16x8S>;
  t[PPC_INST_VUPKHSH128] = build_vupk<Simd::I32x4ExtendHighI16x8S>;
  t[PPC_INST_VUPKLSB] = build_vupk<Simd::I16x8ExtendLowI8x16S>;
  t[PPC_INST_VUPKLSB128] = build_vupk<Simd::I16x8ExtendLowI8x16S>;
  t[PPC_INST_VUPKLSH] = build_vupk<Simd::I32x4ExtendLowI16x8S>;
  t[PPC_INST_VUPKLSH128] = build_vupk<Simd::I32x4ExtendLowI16x8S>;
}

}  // namespace rex::codegen::wasm::detail
