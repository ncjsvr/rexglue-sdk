/**
 * @file        codegen/wasm/wasm_builders.cpp
 * @brief       PowerPC to WebAssembly instruction builders: integer set, loads and stores,
 *              branches, dispatch (guest ABI v1)
 *
 * Semantics follow ReXGlue's C++ builders in src/codegen/builders (the reference), including
 * their 32-bit XER[CA] and CR0 conventions. Operands of the integer set are decoded from the
 * instruction word, so simplified mnemonics (li, mr, slwi, clrldi, beq, bdnz, ...) reach the
 * generic builder; the floating-point, vector and system builders (wasm_builders_fp.cpp,
 * _vector.cpp, _system.cpp) are keyed by PPC_INST_* id like instruction_dispatch.cpp.
 *
 * @copyright   Copyright (c) 2026 MCLA-Reborn contributors
 * @license     Not yet licensed: MCLA-Reborn decides before any release (D-009)
 */

#include "wasm_builders.h"

#include <cstring>
#include <set>
#include <unordered_map>

#include <rex/codegen/config.h>
#include <rex/codegen/function_node.h>
#include <rex/logging.h>
#include <rex/memory/utils.h>

#include "../codegen_logging.h"
#include "wasm_builders_internal.h"

#if REXGLUE_TRANSLATOR_PPC
#include <translator_ppc/binutils_compat.h>  // MCLA-Reborn: our decoder (T-048)
#else
#include <dis-asm.h>
#include <ppc-inst.h>
#endif

namespace rex::codegen::wasm {

using rex::memory::load_and_swap;

namespace {

constexpr uint32_t kEieio = 0x7C0006AC;
constexpr uint8_t kI64Block = static_cast<uint8_t>(ValType::I64);

/// 64-bit PowerPC rotate mask with bits mstart..mstop set (big-endian bit numbering).
uint64_t ppcMask(uint32_t mstart, uint32_t mstop) {
  mstart &= 63;
  mstop &= 63;
  uint64_t value = (~0ull >> mstart) ^ (mstop >= 63 ? 0 : ~0ull >> (mstop + 1));
  return mstart <= mstop ? value : ~value;
}

int64_t asI64(uint64_t v) {
  return static_cast<int64_t>(v);
}

bool isMmioUpperBits(uint32_t imm) {
  return (imm >= 0x7FC8 && imm <= 0x7FCF) || imm == 0x7FEA;
}

void setMmio(FunctionState& st, uint32_t reg, bool on) {
  if (on)
    st.mmioBaseRegs |= (1u << reg);
  else
    st.mmioBaseRegs &= ~(1u << reg);
}

bool isMmio(const FunctionState& st, uint32_t reg) {
  return (st.mmioBaseRegs & (1u << reg)) != 0;
}

const CallTarget* findCallTarget(const FunctionNode& fn, uint32_t site) {
  for (const auto& edge : fn.calls()) {
    if (edge.site == site)
      return &edge.target;
  }
  for (const auto& edge : fn.tailCalls()) {
    if (edge.site == site)
      return &edge.target;
  }
  return nullptr;
}

}  // namespace

//=============================================================================
// WasmBuilderContext helpers
//=============================================================================

const RecompilerConfig& WasmBuilderContext::config() const {
  return emitCtx.config;
}

const FunctionGraph& WasmBuilderContext::graph() const {
  return emitCtx.graph;
}

const char* WasmBuilderContext::mnemonic() const {
  return insn.opcode ? insn.opcode->name : "unknown";
}

void WasmBuilderContext::pushR(uint32_t n) {
  get(kLocalCtx);
  c.mem(Op::I64Load, 3, L().r[n]);
}

void WasmBuilderContext::pushR32(uint32_t n) {
  get(kLocalCtx);
  c.mem(Op::I32Load, 2, L().r[n]);
}

void WasmBuilderContext::setR(uint32_t n) {
  set(kL3);
  get(kLocalCtx);
  get(kL3);
  c.mem(Op::I64Store, 3, L().r[n]);
}

void WasmBuilderContext::setR32(uint32_t n) {
  set(kI3);
  get(kLocalCtx);
  get(kI3);
  c.mem(Op::I32Store, 2, L().r[n]);
}

void WasmBuilderContext::pushU8(uint32_t off) {
  get(kLocalCtx);
  c.mem(Op::I32Load8U, 0, off);
}

void WasmBuilderContext::setU8(uint32_t off) {
  set(kI3);
  get(kLocalCtx);
  get(kI3);
  c.mem(Op::I32Store8, 0, off);
}

void WasmBuilderContext::pushU32(uint32_t off) {
  get(kLocalCtx);
  c.mem(Op::I32Load, 2, off);
}

void WasmBuilderContext::setU32(uint32_t off) {
  set(kI3);
  get(kLocalCtx);
  get(kI3);
  c.mem(Op::I32Store, 2, off);
}

void WasmBuilderContext::pushU64(uint32_t off) {
  get(kLocalCtx);
  c.mem(Op::I64Load, 3, off);
}

void WasmBuilderContext::setU64(uint32_t off) {
  set(kL3);
  get(kLocalCtx);
  get(kL3);
  c.mem(Op::I64Store, 3, off);
}

uint32_t WasmBuilderContext::opnd(size_t i) const {
  return insn.operands[i];
}

bool WasmBuilderContext::recordName() const {
  return insn.opcode && std::strchr(insn.opcode->name, '.') != nullptr;
}

void WasmBuilderContext::pushF(uint32_t n) {
  get(kLocalCtx);
  c.mem(Op::F64Load, 3, L().f[n]);
}

void WasmBuilderContext::setF(uint32_t n) {
  set(kF3);
  get(kLocalCtx);
  get(kF3);
  c.mem(Op::F64Store, 3, L().f[n]);
}

void WasmBuilderContext::pushFBits(uint32_t n) {
  get(kLocalCtx);
  c.mem(Op::I64Load, 3, L().f[n]);
}

void WasmBuilderContext::setFBits(uint32_t n) {
  set(kL3);
  get(kLocalCtx);
  get(kL3);
  c.mem(Op::I64Store, 3, L().f[n]);
}

void WasmBuilderContext::pushV(uint32_t n) {
  get(kLocalCtx);
  c.simdMem(Simd::V128Load, 4, L().v[n]);
}

void WasmBuilderContext::setV(uint32_t n) {
  set(kV7);
  get(kLocalCtx);
  get(kV7);
  c.simdMem(Simd::V128Store, 4, L().v[n]);
}

void WasmBuilderContext::compare(uint32_t field, Cmp kind, uint32_t a, uint32_t b) {
  uint8_t lt, gt, eq;
  switch (kind) {
    case Cmp::S32:
      lt = Op::I32LtS, gt = Op::I32GtS, eq = Op::I32Eq;
      break;
    case Cmp::U32:
      lt = Op::I32LtU, gt = Op::I32GtU, eq = Op::I32Eq;
      break;
    case Cmp::S64:
      lt = Op::I64LtS, gt = Op::I64GtS, eq = Op::I64Eq;
      break;
    default:
      lt = Op::I64LtU, gt = Op::I64GtU, eq = Op::I64Eq;
      break;
  }
  // One i32 store writes lt, gt, eq, so (four consecutive bytes, checked in the layout).
  get(kLocalCtx);
  get(a), get(b), op(lt);
  get(a), get(b), op(gt), i32(8), op(Op::I32Shl), op(Op::I32Or);
  get(a), get(b), op(eq), i32(16), op(Op::I32Shl), op(Op::I32Or);
  pushU8(L().xerSo), i32(24), op(Op::I32Shl), op(Op::I32Or);
  c.mem(Op::I32Store, 0, L().cr[field & 7].lt);
}

void WasmBuilderContext::recordForm(uint32_t n) {
  pushR32(n);
  set(kI0);
  i32(0);
  set(kI1);
  compare(0, Cmp::S32, kI0, kI1);
}

void WasmBuilderContext::setOverflow() {
  set(kI2);
  get(kLocalCtx), get(kI2), c.mem(Op::I32Store8, 0, L().xerOv);
  get(kLocalCtx), pushU8(L().xerSo), get(kI2), op(Op::I32Or), c.mem(Op::I32Store8, 0, L().xerSo);
}

void WasmBuilderContext::beginIf(uint8_t blockType) {
  c.if_(blockType);
  ++st.depth;
}

void WasmBuilderContext::beginBlock() {
  c.block();
  ++st.depth;
}

void WasmBuilderContext::end() {
  c.end();
  --st.depth;
}

void WasmBuilderContext::branchTo(uint32_t target) {
  i32(static_cast<int32_t>(st.segments.at(target)));
  set(kLocalLabel);
  c.br(st.depth);
}

void WasmBuilderContext::branchIfTo(uint32_t target) {
  // The label local is read only by the dispatch, so setting it on the untaken path is harmless.
  i32(static_cast<int32_t>(st.segments.at(target)));
  set(kLocalLabel);
  c.brIf(st.depth);
}

void WasmBuilderContext::trap(TrapCode code, uint32_t addr) {
  get(kLocalCtx);
  i32(static_cast<int32_t>(addr));
  i32(code);
  c.call(env.fnTrap);
  if (code != kGuestTrap)
    op(Op::Unreachable);
}

void WasmBuilderContext::unimplemented(std::string_view what) {
  REXCODEGEN_WARN("wasm: unimplemented {} at 0x{:08X}", what, base);
  if (st.unimplemented)
    st.unimplemented->emplace(what);
  trap(kUnimplemented, base);
}

void WasmBuilderContext::setLr(uint32_t value) {
  if (config().skipLr)
    return;
  get(kLocalCtx);
  i64(static_cast<int64_t>(value));
  c.mem(Op::I64Store, 3, L().lr);
}

namespace {

/// A call to an import thunk (an IMPORT function node, which is how the analysis records every
/// call to a kernel/XAM export): env.kernel(ctx, import_id).
void callImportNode(WasmBuilderContext& w, const FunctionNode& node) {
  const uint32_t id =
      w.env.imports ? w.env.imports->idForThunk(node.base(), node.name(), w.emitCtx) : 0;
  w.get(kLocalCtx);
  w.i32(static_cast<int32_t>(id));
  w.c.call(w.env.fnKernel);
}

void callFunctionNode(WasmBuilderContext& w, const FunctionNode& node) {
  if (node.authority() == FunctionAuthority::IMPORT) {
    callImportNode(w, node);
    return;
  }
  if (auto it = w.env.localFunctions.find(node.base()); it != w.env.localFunctions.end()) {
    w.get(kLocalCtx);
    w.c.call(it->second);
    return;
  }
  if (w.env.slots) {
    if (auto it = w.env.slots->find(node.base()); it != w.env.slots->end()) {
      w.get(kLocalCtx);
      w.i32(static_cast<int32_t>(it->second));
      w.c.callIndirect(w.env.guestFnType, 0);
      return;
    }
  }
  REXCODEGEN_ERROR("wasm: no slot for function 0x{:08X} called from 0x{:08X}", node.base(),
                   w.base);
  w.trap(kUnresolvedCall, w.base);
}

}  // namespace

void WasmBuilderContext::callGuest(uint32_t target) {
  const auto& cfg = config();
  if (target != 0 && target == cfg.setJmpAddress) {
    // builders/context.cpp emit_function_call: env = ctx; r3 = ppc_setjmp(r3); on a longjmp
    // ctx = env and r3 = the value. The snapshot lives in v128 locals; the longjmp arrives as
    // an env.longjmp exception caught around the body (wasm_function.cpp).
    auto site = st.setjmpSites.find(base);
    if (site == st.setjmpSites.end() || env.longjmpTag == ModuleEnv::kNone ||
        !hasSegment(site->second)) {
      unimplemented("setjmp (not a bl)");
      return;
    }
    for (uint32_t i = 0; i < st.snapshotCount; ++i) {
      get(kLocalCtx), c.simdMem(Simd::V128Load, 4, 16 * i), set(st.localSnapshot + i);
    }
    pushR32(3), set(st.localJmpBuf);
    i32(static_cast<int32_t>(st.segments.at(site->second) + 1)), set(st.localJmpResume);
    i64(0), setR(3);
    return;
  }
  if (target != 0 && target == cfg.longJmpAddress) {
    // ppc_longjmp(r3.u32, r4.s32): unwinds to the frame that ran setjmp on that buffer.
    if (env.longjmpTag == ModuleEnv::kNone) {
      unimplemented("longjmp");
      return;
    }
    pushR32(3), pushR32(4), c.throw_(env.longjmpTag);
    return;
  }

  const FunctionNode* node = nullptr;
  if (const auto* ct = findCallTarget(fn, base)) {
    if (ct->isFunction()) {
      node = ct->asFunction();
    } else if (ct->isImport()) {
      const auto& imp = std::get<CallTarget::ToImport>(ct->value);
      uint32_t id = env.imports ? env.imports->idFor(imp.name, emitCtx) : 0;
      get(kLocalCtx);
      i32(static_cast<int32_t>(id));
      c.call(env.fnKernel);
      return;
    }
  } else {
    node = graph().getFunction(target);
  }

  if (!node) {
    REXCODEGEN_ERROR("wasm: unresolved call from 0x{:08X} to 0x{:08X}", base, target);
    trap(kUnresolvedCall, base);
    return;
  }
  callFunctionNode(*this, *node);
}

void WasmBuilderContext::callIndirect() {
  set(kI2);
  get(kLocalCtx), get(kI2), c.mem(Op::I32Store, 2, L().lastIndirectTarget);
  get(kI2), c.call(env.fnLookup), tee(kI1);
  i32(-1), op(Op::I32Eq);
  beginIf();
  get(kLocalCtx), get(kI2), i32(kUnknownTarget), c.call(env.fnTrap), op(Op::Unreachable);
  end();
  get(kLocalCtx), get(kI1), c.callIndirect(env.guestFnType, 0);
}

bool WasmBuilderContext::mmioCheckDForm() const {
  if (base + 4 < fn.end() && load_and_swap<uint32_t>(data + 1) == kEieio)
    return true;
  return isMmio(st, rA());
}

bool WasmBuilderContext::mmioCheckXForm() const {
  if (base + 4 < fn.end() && load_and_swap<uint32_t>(data + 1) == kEieio)
    return true;
  return isMmio(st, rA()) || isMmio(st, rB());
}

namespace {

using namespace detail;

//=============================================================================
// Shared pieces
//=============================================================================

/// L0 = rA, L1 = rB, I0 = rA.u32, I1 = rB.u32.
void loadAB(W& w) {
  w.pushR(w.rA()), w.tee(kL0), w.op(Op::I32WrapI64), w.set(kI0);
  w.pushR(w.rB()), w.tee(kL1), w.op(Op::I32WrapI64), w.set(kI1);
}

/// L0 = rA, I0 = rA.u32.
void loadA(W& w) {
  w.pushR(w.rA()), w.tee(kL0), w.op(Op::I32WrapI64), w.set(kI0);
}

void pushNot32(W& w, uint32_t local) {
  w.get(local), w.i32(-1), w.op(Op::I32Xor);
}

/// Signed 32-bit overflow of x + y (+ carry) = r: ((x ^ r) & (y ^ r)) >> 31.
template <class X, class Y>
void addOverflow32(W& w, X pushX, Y pushY, uint32_t resultLocal64) {
  pushX(), w.get(resultLocal64), w.op(Op::I32WrapI64), w.op(Op::I32Xor);
  pushY(), w.get(resultLocal64), w.op(Op::I32WrapI64), w.op(Op::I32Xor);
  w.op(Op::I32And), w.i32(31), w.op(Op::I32ShrU);
}

/// rD = L2, then optional XER[OV]/[SO] and CR0.
template <class X, class Y>
void finishAdd(W& w, X pushX, Y pushY) {
  w.get(kL2), w.setR(w.rD());
  if (w.oe()) {
    addOverflow32(w, pushX, pushY, kL2);
    w.setOverflow();
  }
  if (w.rc())
    w.recordForm(w.rD());
}

/// Two-part carry of x + y + ca (adde form): (x + y < x) | (x + y + ca < ca), left in I2.
template <class X, class Y>
void carryXYCa(W& w, X pushX, Y pushY) {
  const uint32_t ca = w.L().xerCa;
  pushX(), pushY(), w.op(Op::I32Add), pushX(), w.op(Op::I32LtU);
  pushX(), pushY(), w.op(Op::I32Add), w.pushU8(ca), w.op(Op::I32Add), w.pushU8(ca),
      w.op(Op::I32LtU);
  w.op(Op::I32Or), w.set(kI2);
}

//=============================================================================
// Arithmetic (builders/arithmetic.cpp)
//=============================================================================

void build_add(W& w) {
  loadAB(w);
  w.get(kL0), w.get(kL1), w.op(Op::I64Add), w.set(kL2);
  finishAdd(w, [&] { w.get(kI0); }, [&] { w.get(kI1); });
}

void build_addc(W& w) {
  loadAB(w);
  w.get(kI0), w.get(kI1), w.op(Op::I32Add), w.get(kI0), w.op(Op::I32LtU), w.setU8(w.L().xerCa);
  w.get(kL0), w.get(kL1), w.op(Op::I64Add), w.set(kL2);
  finishAdd(w, [&] { w.get(kI0); }, [&] { w.get(kI1); });
}

void build_adde(W& w) {
  loadAB(w);
  carryXYCa(w, [&] { w.get(kI0); }, [&] { w.get(kI1); });
  w.get(kL0), w.get(kL1), w.op(Op::I64Add), w.pushU8(w.L().xerCa), w.op(Op::I64ExtendI32U),
      w.op(Op::I64Add), w.set(kL2);
  w.get(kI2), w.setU8(w.L().xerCa);
  finishAdd(w, [&] { w.get(kI0); }, [&] { w.get(kI1); });
}

void build_addme(W& w) {
  loadA(w);
  carryXYCa(w, [&] { w.get(kI0); }, [&] { w.i32(-1); });
  w.get(kL0), w.pushU8(w.L().xerCa), w.op(Op::I64ExtendI32U), w.op(Op::I64Add), w.i64(-1),
      w.op(Op::I64Add), w.set(kL2);
  w.get(kI2), w.setU8(w.L().xerCa);
  finishAdd(w, [&] { w.get(kI0); }, [&] { w.i32(-1); });
}

void build_addze(W& w) {
  loadA(w);
  w.get(kL0), w.pushU8(w.L().xerCa), w.op(Op::I64ExtendI32U), w.op(Op::I64Add), w.set(kL2);
  w.get(kL2), w.op(Op::I32WrapI64), w.get(kI0), w.op(Op::I32LtU), w.setU8(w.L().xerCa);
  finishAdd(w, [&] { w.get(kI0); }, [&] { w.i32(0); });
}

void build_subf(W& w) {
  loadAB(w);
  w.get(kL1), w.get(kL0), w.op(Op::I64Sub), w.set(kL2);
  finishAdd(w, [&] { pushNot32(w, kI0); }, [&] { w.get(kI1); });
}

void build_subfc(W& w) {
  loadAB(w);
  w.get(kI1), w.get(kI0), w.op(Op::I32GeU), w.setU8(w.L().xerCa);
  w.get(kL1), w.get(kL0), w.op(Op::I64Sub), w.set(kL2);
  finishAdd(w, [&] { pushNot32(w, kI0); }, [&] { w.get(kI1); });
}

void build_subfe(W& w) {
  loadAB(w);
  carryXYCa(w, [&] { pushNot32(w, kI0); }, [&] { w.get(kI1); });
  w.get(kL0), w.i64(-1), w.op(Op::I64Xor), w.get(kL1), w.op(Op::I64Add), w.pushU8(w.L().xerCa),
      w.op(Op::I64ExtendI32U), w.op(Op::I64Add), w.set(kL2);
  w.get(kI2), w.setU8(w.L().xerCa);
  finishAdd(w, [&] { pushNot32(w, kI0); }, [&] { w.get(kI1); });
}

void build_subfme(W& w) {
  loadA(w);
  carryXYCa(w, [&] { pushNot32(w, kI0); }, [&] { w.i32(-1); });
  w.get(kL0), w.i64(-1), w.op(Op::I64Xor), w.pushU8(w.L().xerCa), w.op(Op::I64ExtendI32U),
      w.op(Op::I64Add), w.i64(-1), w.op(Op::I64Add), w.set(kL2);
  w.get(kI2), w.setU8(w.L().xerCa);
  finishAdd(w, [&] { pushNot32(w, kI0); }, [&] { w.i32(-1); });
}

void build_subfze(W& w) {
  loadA(w);
  // temp = ~a.u32 + ca < ~a.u32
  pushNot32(w, kI0), w.pushU8(w.L().xerCa), w.op(Op::I32Add), pushNot32(w, kI0),
      w.op(Op::I32LtU), w.set(kI2);
  w.get(kL0), w.i64(-1), w.op(Op::I64Xor), w.pushU8(w.L().xerCa), w.op(Op::I64ExtendI32U),
      w.op(Op::I64Add), w.set(kL2);
  w.get(kI2), w.setU8(w.L().xerCa);
  finishAdd(w, [&] { pushNot32(w, kI0); }, [&] { w.i32(0); });
}

void build_neg(W& w) {
  loadA(w);
  w.i64(0), w.get(kL0), w.op(Op::I64Sub), w.set(kL2);
  finishAdd(w, [&] { pushNot32(w, kI0); }, [&] { w.i32(0); });
}

void build_mullw(W& w) {
  loadAB(w);
  w.get(kI0), w.op(Op::I64ExtendI32S), w.get(kI1), w.op(Op::I64ExtendI32S), w.op(Op::I64Mul),
      w.set(kL2);
  w.get(kL2), w.setR(w.rD());
  if (w.oe()) {
    w.get(kL2), w.get(kL2), w.op(Op::I32WrapI64), w.op(Op::I64ExtendI32S), w.op(Op::I64Ne);
    w.setOverflow();
  }
  if (w.rc())
    w.recordForm(w.rD());
}

void build_mulhw(W& w) {
  loadAB(w);
  w.get(kI0), w.op(Op::I64ExtendI32S), w.get(kI1), w.op(Op::I64ExtendI32S), w.op(Op::I64Mul),
      w.i64(32), w.op(Op::I64ShrS), w.setR(w.rD());
  if (w.rc())
    w.recordForm(w.rD());
}

void build_mulhwu(W& w) {
  loadAB(w);
  w.get(kI0), w.op(Op::I64ExtendI32U), w.get(kI1), w.op(Op::I64ExtendI32U), w.op(Op::I64Mul),
      w.i64(32), w.op(Op::I64ShrU), w.setR(w.rD());
  if (w.rc())
    w.recordForm(w.rD());
}

void build_mulld(W& w) {
  if (w.oe()) {
    w.unimplemented("mulldo");
    return;
  }
  loadAB(w);
  w.get(kL0), w.get(kL1), w.op(Op::I64Mul), w.setR(w.rD());
  if (w.rc())
    w.recordForm(w.rD());
}

/// Safe division as ReXGlue emits it: 0 on division by zero or MIN / -1. I2 = bad flag.
void build_divw(W& w) {
  loadAB(w);
  w.get(kI1), w.op(Op::I32Eqz);
  w.get(kI0), w.i32(INT32_MIN), w.op(Op::I32Eq), w.get(kI1), w.i32(-1), w.op(Op::I32Eq),
      w.op(Op::I32And);
  w.op(Op::I32Or), w.set(kI2);
  w.i32(0);
  w.get(kI0), w.i32(1), w.get(kI1), w.get(kI2), w.op(Op::Select), w.op(Op::I32DivS);
  w.get(kI2), w.op(Op::Select), w.op(Op::I64ExtendI32U), w.setR(w.rD());
  if (w.oe())
    w.get(kI2), w.setOverflow();
  if (w.rc())
    w.recordForm(w.rD());
}

void build_divwu(W& w) {
  loadAB(w);
  w.get(kI1), w.op(Op::I32Eqz), w.set(kI2);
  w.i32(0);
  w.get(kI0), w.i32(1), w.get(kI1), w.get(kI2), w.op(Op::Select), w.op(Op::I32DivU);
  w.get(kI2), w.op(Op::Select), w.op(Op::I64ExtendI32U), w.setR(w.rD());
  if (w.oe())
    w.get(kI2), w.setOverflow();
  if (w.rc())
    w.recordForm(w.rD());
}

void build_divd(W& w) {
  loadAB(w);
  w.get(kL1), w.op(Op::I64Eqz);
  w.get(kL0), w.i64(INT64_MIN), w.op(Op::I64Eq), w.get(kL1), w.i64(-1), w.op(Op::I64Eq),
      w.op(Op::I32And);
  w.op(Op::I32Or), w.set(kI2);
  w.i64(0);
  w.get(kL0), w.i64(1), w.get(kL1), w.get(kI2), w.op(Op::Select), w.op(Op::I64DivS);
  w.get(kI2), w.op(Op::Select), w.setR(w.rD());
  if (w.oe())
    w.get(kI2), w.setOverflow();
  if (w.rc())
    w.recordForm(w.rD());
}

void build_divdu(W& w) {
  loadAB(w);
  w.get(kL1), w.op(Op::I64Eqz), w.set(kI2);
  w.i64(0);
  w.get(kL0), w.i64(1), w.get(kL1), w.get(kI2), w.op(Op::Select), w.op(Op::I64DivU);
  w.get(kI2), w.op(Op::Select), w.setR(w.rD());
  if (w.oe())
    w.get(kI2), w.setOverflow();
  if (w.rc())
    w.recordForm(w.rD());
}

void build_addi(W& w) {
  if (w.rA() != 0)
    w.pushR(w.rA()), w.i64(w.simm()), w.op(Op::I64Add);
  else
    w.i64(w.simm());
  w.setR(w.rD());
}

void build_addis(W& w) {
  const int32_t imm = static_cast<int32_t>(w.uimm() << 16);
  if (w.rA() != 0) {
    w.pushR(w.rA()), w.i64(imm), w.op(Op::I64Add);
  } else {
    w.i64(imm);
  }
  w.setR(w.rD());
  // lis tracks MMIO bases (builders/memory.cpp build_lis)
  if (w.rA() == 0)
    setMmio(w.st, w.rD(), isMmioUpperBits(w.uimm()));
}

void build_addic(W& w) {
  const uint32_t simmU = static_cast<uint32_t>(w.simm());
  w.pushR32(w.rA()), w.i32(static_cast<int32_t>(~simmU)), w.op(Op::I32GtU),
      w.setU8(w.L().xerCa);
  w.pushR(w.rA()), w.i64(w.simm()), w.op(Op::I64Add), w.setR(w.rD());
  if ((w.word >> 26) == 13)  // addic.
    w.recordForm(w.rD());
}

void build_subfic(W& w) {
  const uint32_t simmU = static_cast<uint32_t>(w.simm());
  w.pushR32(w.rA()), w.i32(static_cast<int32_t>(simmU)), w.op(Op::I32LeU), w.setU8(w.L().xerCa);
  w.i64(w.simm()), w.pushR(w.rA()), w.op(Op::I64Sub), w.setR(w.rD());
}

void build_mulli(W& w) {
  w.pushR(w.rA()), w.i64(w.simm()), w.op(Op::I64Mul), w.setR(w.rD());
}

//=============================================================================
// Logical, shifts and rotates (builders/logical.cpp)
//=============================================================================

template <uint8_t Opcode, bool InvertB, bool InvertResult>
void build_logical(W& w) {
  w.pushR(w.rS());
  w.pushR(w.rB());
  if (InvertB)
    w.i64(-1), w.op(Op::I64Xor);
  w.op(Opcode);
  if (InvertResult)
    w.i64(-1), w.op(Op::I64Xor);
  w.setR(w.rA());
  if (w.rc())
    w.recordForm(w.rA());
}

void build_or(W& w) {
  build_logical<Op::I64Or, false, false>(w);
  setMmio(w.st, w.rA(), isMmio(w.st, w.rS()) || isMmio(w.st, w.rB()));
}

void build_andi(W& w) {
  w.pushR(w.rS()), w.i64(w.uimm()), w.op(Op::I64And), w.setR(w.rA());
  w.recordForm(w.rA());
}

void build_andis(W& w) {
  w.pushR(w.rS()), w.i64(static_cast<int64_t>(w.uimm()) << 16), w.op(Op::I64And), w.setR(w.rA());
  w.recordForm(w.rA());
}

void build_ori(W& w) {
  w.pushR(w.rS()), w.i64(w.uimm()), w.op(Op::I64Or), w.setR(w.rA());
  setMmio(w.st, w.rA(), isMmio(w.st, w.rS()));
}

void build_oris(W& w) {
  w.pushR(w.rS()), w.i64(static_cast<int64_t>(w.uimm()) << 16), w.op(Op::I64Or), w.setR(w.rA());
  if (isMmioUpperBits(w.uimm()))
    setMmio(w.st, w.rA(), true);
}

void build_xori(W& w) {
  w.pushR(w.rS()), w.i64(w.uimm()), w.op(Op::I64Xor), w.setR(w.rA());
}

void build_xoris(W& w) {
  w.pushR(w.rS()), w.i64(static_cast<int64_t>(w.uimm()) << 16), w.op(Op::I64Xor), w.setR(w.rA());
}

template <uint8_t ExtendOp>
void build_exts(W& w) {
  w.pushR(w.rS()), w.op(ExtendOp), w.setR(w.rA());
  if (w.rc())
    w.recordForm(w.rA());
}

void build_cntlzw(W& w) {
  w.pushR32(w.rS()), w.op(Op::I32Clz), w.op(Op::I64ExtendI32U), w.setR(w.rA());
  if (w.rc())
    w.recordForm(w.rA());
}

void build_cntlzd(W& w) {
  w.pushR(w.rS()), w.op(Op::I64Clz), w.setR(w.rA());
  if (w.rc())
    w.recordForm(w.rA());
}

/// slw/srw: rB.u8 & 0x20 ? 0 : (rS.u32 shift (rB.u8 & 0x3F)), zero-extended.
template <uint8_t ShiftOp>
void build_shift_word(W& w) {
  w.i32(0);
  w.pushR32(w.rS()), w.pushR32(w.rB()), w.i32(0x3F), w.op(Op::I32And), w.op(ShiftOp);
  w.pushR32(w.rB()), w.i32(0x20), w.op(Op::I32And);
  w.op(Op::Select), w.op(Op::I64ExtendI32U), w.setR(w.rA());
  if (w.rc())
    w.recordForm(w.rA());
}

/// sld/srd: rB.u8 & 0x40 ? 0 : (rS.u64 shift (rB.u8 & 0x7F)).
template <uint8_t ShiftOp>
void build_shift_dword(W& w) {
  w.i64(0);
  w.pushR(w.rS()), w.pushR(w.rB()), w.i64(0x7F), w.op(Op::I64And), w.op(ShiftOp);
  w.pushR32(w.rB()), w.i32(0x40), w.op(Op::I32And);
  w.op(Op::Select), w.setR(w.rA());
  if (w.rc())
    w.recordForm(w.rA());
}

void build_sraw(W& w) {
  const uint32_t ca = w.L().xerCa;
  w.pushR32(w.rS()), w.set(kI1);
  w.pushR32(w.rB()), w.i32(0x3F), w.op(Op::I32And), w.set(kI0);
  w.i32(0x1F), w.get(kI0), w.get(kI0), w.i32(0x1F), w.op(Op::I32GtU), w.op(Op::Select), w.set(kI0);
  w.get(kI1), w.i32(0), w.op(Op::I32LtS);
  w.get(kI1), w.get(kI0), w.op(Op::I32ShrS), w.get(kI0), w.op(Op::I32Shl), w.get(kI1),
      w.op(Op::I32Ne);
  w.op(Op::I32And), w.setU8(ca);
  w.get(kI1), w.get(kI0), w.op(Op::I32ShrS), w.op(Op::I64ExtendI32S), w.setR(w.rA());
  if (w.rc())
    w.recordForm(w.rA());
}

void build_srawi(W& w) {
  const uint32_t sh = w.rB();
  const uint32_t ca = w.L().xerCa;
  if (sh != 0) {
    w.pushR32(w.rS()), w.i32(0), w.op(Op::I32LtS);
    w.pushR32(w.rS()), w.i32(static_cast<int32_t>((1u << sh) - 1)), w.op(Op::I32And), w.i32(0),
        w.op(Op::I32Ne);
    w.op(Op::I32And), w.setU8(ca);
    w.pushR32(w.rS()), w.i32(static_cast<int32_t>(sh)), w.op(Op::I32ShrS),
        w.op(Op::I64ExtendI32S), w.setR(w.rA());
  } else {
    w.i32(0), w.setU8(ca);
    w.pushR32(w.rS()), w.op(Op::I64ExtendI32S), w.setR(w.rA());
  }
  if (w.rc())
    w.recordForm(w.rA());
}

void build_srad(W& w) {
  const uint32_t ca = w.L().xerCa;
  w.pushR(w.rS()), w.set(kL1);
  w.pushR(w.rB()), w.i64(0x7F), w.op(Op::I64And), w.set(kL0);
  w.i64(0x3F), w.get(kL0), w.get(kL0), w.i64(0x3F), w.op(Op::I64GtU), w.op(Op::Select), w.set(kL0);
  w.get(kL1), w.i64(0), w.op(Op::I64LtS);
  w.get(kL1), w.get(kL0), w.op(Op::I64ShrS), w.get(kL0), w.op(Op::I64Shl), w.get(kL1),
      w.op(Op::I64Ne);
  w.op(Op::I32And), w.setU8(ca);
  w.get(kL1), w.get(kL0), w.op(Op::I64ShrS), w.setR(w.rA());
  if (w.rc())
    w.recordForm(w.rA());
}

void build_sradi(W& w) {
  const uint32_t sh = ((w.word >> 11) & 31) | (((w.word >> 1) & 1) << 5);
  const uint32_t ca = w.L().xerCa;
  if (sh != 0) {
    w.pushR(w.rS()), w.i64(0), w.op(Op::I64LtS);
    w.pushR(w.rS()), w.i64(asI64(ppcMask(64 - sh, 63))), w.op(Op::I64And), w.i64(0),
        w.op(Op::I64Ne);
    w.op(Op::I32And), w.setU8(ca);
    w.pushR(w.rS()), w.i64(sh), w.op(Op::I64ShrS), w.setR(w.rA());
  } else {
    w.i32(0), w.setU8(ca);
    w.pushR(w.rS()), w.setR(w.rA());
  }
  if (w.rc())
    w.recordForm(w.rA());
}

/// rS.u32 | (rS.u64 << 32): the low word duplicated, as the rlw* builders rotate it.
void pushDupWord(W& w) {
  w.pushR(w.rS()), w.tee(kL0), w.i64(0xFFFFFFFF), w.op(Op::I64And);
  w.get(kL0), w.i64(32), w.op(Op::I64Shl), w.op(Op::I64Or);
}

/// M-form rlwinm/rlwnm/rlwimi (opcodes 21, 23, 20).
void build_rlw(W& w) {
  const uint32_t opcd = w.word >> 26;
  const uint32_t mb = (w.word >> 6) & 31;
  const uint32_t me = (w.word >> 1) & 31;
  const uint64_t mask = ppcMask(mb + 32, me + 32);
  pushDupWord(w);
  if (opcd == 23)
    w.pushR(w.rB()), w.i64(0x1F), w.op(Op::I64And);
  else
    w.i64(w.rB());
  w.op(Op::I64Rotl), w.i64(asI64(mask)), w.op(Op::I64And);
  if (opcd == 20)
    w.pushR(w.rA()), w.i64(asI64(~mask)), w.op(Op::I64And), w.op(Op::I64Or);
  w.setR(w.rA());
  if (w.rc())
    w.recordForm(w.rA());
}

/// MD/MDS-form rldicl, rldicr, rldic, rldimi, rldcl, rldcr (opcode 30).
void build_rld(W& w) {
  const uint32_t sh = ((w.word >> 11) & 31) | (((w.word >> 1) & 1) << 5);
  const uint32_t mbe = ((w.word >> 6) & 31) | (((w.word >> 5) & 1) << 5);
  const uint32_t xo3 = (w.word >> 2) & 7;
  const uint32_t xo4 = (w.word >> 1) & 15;
  uint64_t mask;
  bool byRegister = false;
  bool insert = false;
  if (xo3 == 0) {
    mask = ppcMask(mbe, 63);  // rldicl
  } else if (xo3 == 1) {
    mask = ppcMask(0, mbe);  // rldicr
  } else if (xo3 == 2) {
    mask = ppcMask(mbe, 63 - sh);  // rldic
  } else if (xo3 == 3) {
    mask = ppcMask(mbe, ~sh);  // rldimi
    insert = true;
  } else if (xo4 == 8) {
    mask = ppcMask(mbe, 63);  // rldcl
    byRegister = true;
  } else if (xo4 == 9) {
    mask = ppcMask(0, mbe);  // rldcr
    byRegister = true;
  } else {
    w.unimplemented(w.mnemonic());
    return;
  }
  w.pushR(w.rS());
  if (byRegister)
    w.pushR(w.rB()), w.i64(0x3F), w.op(Op::I64And);
  else
    w.i64(sh);
  w.op(Op::I64Rotl), w.i64(asI64(mask)), w.op(Op::I64And);
  if (insert)
    w.pushR(w.rA()), w.i64(asI64(~mask)), w.op(Op::I64And), w.op(Op::I64Or);
  w.setR(w.rA());
  if (w.rc())
    w.recordForm(w.rA());
}

//=============================================================================
// Comparison (builders/comparison.cpp)
//=============================================================================

void compareRegs(W& w, bool isSigned) {
  const uint32_t bf = (w.word >> 23) & 7;
  const bool l64 = ((w.word >> 21) & 1) != 0;
  if (l64) {
    w.pushR(w.rA()), w.set(kL0), w.pushR(w.rB()), w.set(kL1);
    w.compare(bf, isSigned ? W::Cmp::S64 : W::Cmp::U64, kL0, kL1);
  } else {
    w.pushR32(w.rA()), w.set(kI0), w.pushR32(w.rB()), w.set(kI1);
    w.compare(bf, isSigned ? W::Cmp::S32 : W::Cmp::U32, kI0, kI1);
  }
}

void build_cmp(W& w) {
  compareRegs(w, true);
}

void build_cmpl(W& w) {
  compareRegs(w, false);
}

void compareImm(W& w, bool isSigned) {
  const uint32_t bf = (w.word >> 23) & 7;
  const bool l64 = ((w.word >> 21) & 1) != 0;
  const int64_t imm = isSigned ? static_cast<int64_t>(w.simm()) : static_cast<int64_t>(w.uimm());
  if (l64) {
    w.pushR(w.rA()), w.set(kL0), w.i64(imm), w.set(kL1);
    w.compare(bf, isSigned ? W::Cmp::S64 : W::Cmp::U64, kL0, kL1);
  } else {
    w.pushR32(w.rA()), w.set(kI0), w.i32(static_cast<int32_t>(imm)), w.set(kI1);
    w.compare(bf, isSigned ? W::Cmp::S32 : W::Cmp::U32, kI0, kI1);
  }
}

void build_cmpi(W& w) {
  compareImm(w, true);
}

void build_cmpli(W& w) {
  compareImm(w, false);
}

//=============================================================================
// Condition register (builders/logical.cpp cr*, builders/system.cpp mfcr/mtcrf/mcrf)
//=============================================================================

void build_crlogical(W& w) {
  const uint32_t xo = (w.word >> 1) & 0x3FF;
  const auto& l = w.L();
  const uint32_t dst = l.crBit(w.rD());
  auto pushA = [&] { w.pushU8(l.crBit(w.rA())); };
  auto pushB = [&] { w.pushU8(l.crBit(w.rB())); };
  w.get(kLocalCtx);
  switch (xo) {
    case 257:  // crand
      pushA(), pushB(), w.op(Op::I32And);
      break;
    case 129:  // crandc
      pushA(), pushB(), w.op(Op::I32Eqz), w.op(Op::I32And);
      break;
    case 289:  // creqv
      pushA(), pushB(), w.op(Op::I32Xor), w.op(Op::I32Eqz);
      break;
    case 225:  // crnand
      pushA(), pushB(), w.op(Op::I32And), w.op(Op::I32Eqz);
      break;
    case 33:  // crnor
      pushA(), pushB(), w.op(Op::I32Or), w.op(Op::I32Eqz);
      break;
    case 449:  // cror
      pushA(), pushB(), w.op(Op::I32Or);
      break;
    case 417:  // crorc
      pushA(), pushB(), w.op(Op::I32Eqz), w.op(Op::I32Or);
      break;
    default:  // 193 crxor
      pushA(), pushB(), w.op(Op::I32Xor);
      break;
  }
  w.c.mem(Op::I32Store8, 0, dst);
}

void build_mcrf(W& w) {
  const uint32_t bf = (w.word >> 23) & 7;
  const uint32_t bfa = (w.word >> 18) & 7;
  w.get(kLocalCtx);
  w.get(kLocalCtx), w.c.mem(Op::I32Load, 0, w.L().cr[bfa].lt);
  w.c.mem(Op::I32Store, 0, w.L().cr[bf].lt);
}

void build_mfcr(W& w) {
  const auto& l = w.L();
  if (w.word & 0x00100000) {
    // mfocrf: one field, (lt << b+3) | (gt << b+2) | (eq << b+1) | (so << b) as an int.
    const uint32_t fxm = (w.word >> 12) & 0xFF;
    uint32_t field = 0;
    for (uint32_t i = 0; i < 8; ++i) {
      if (fxm & (0x80u >> i)) {
        field = i;
        break;
      }
    }
    const int32_t b = static_cast<int32_t>(28 - 4 * field);
    w.pushU8(l.cr[field].lt), w.i32(b + 3), w.op(Op::I32Shl);
    w.pushU8(l.cr[field].gt), w.i32(b + 2), w.op(Op::I32Shl), w.op(Op::I32Or);
    w.pushU8(l.cr[field].eq), w.i32(b + 1), w.op(Op::I32Shl), w.op(Op::I32Or);
    w.pushU8(l.cr[field].so), w.i32(b), w.op(Op::I32Shl), w.op(Op::I32Or);
    w.op(Op::I64ExtendI32S), w.setR(w.rD());
    return;
  }
  // mfcr: bit (31 - i) set when CR bit i is non-zero.
  for (uint32_t i = 0; i < 32; ++i) {
    w.pushU8(l.crBit(i)), w.i32(0), w.op(Op::I32Ne), w.i32(static_cast<int32_t>(31 - i)),
        w.op(Op::I32Shl);
    if (i != 0)
      w.op(Op::I32Or);
  }
  w.op(Op::I64ExtendI32U), w.setR(w.rD());
}

void build_mtcrf(W& w) {
  const uint32_t fxm = (w.word >> 12) & 0xFF;
  const auto& l = w.L();
  for (uint32_t field = 0; field < 8; ++field) {
    if (!(fxm & (0x80u >> field)))
      continue;
    const uint32_t baseBit = 28 - 4 * field;
    const uint32_t offs[4] = {l.cr[field].lt, l.cr[field].gt, l.cr[field].eq, l.cr[field].so};
    for (uint32_t b = 0; b < 4; ++b) {
      w.get(kLocalCtx);
      w.pushR32(w.rS()), w.i32(static_cast<int32_t>(1u << (baseBit + 3 - b))), w.op(Op::I32And),
          w.i32(0), w.op(Op::I32Ne);
      w.c.mem(Op::I32Store8, 0, offs[b]);
    }
  }
}

//=============================================================================
// Special-purpose registers (builders/system.cpp)
//=============================================================================

uint32_t sprNumber(uint32_t word) {
  return ((word >> 16) & 31) | (((word >> 11) & 31) << 5);
}

void build_mfspr(W& w) {
  const auto& l = w.L();
  switch (sprNumber(w.word)) {
    case 8:  // lr
      if (!w.config().skipLr)
        w.pushU64(l.lr), w.setR(w.rD());
      break;
    case 9:  // ctr
      w.pushU64(l.ctr), w.setR(w.rD());
      break;
    case 268:  // tbl (mftb through mfspr)
      w.c.call(w.env.fnTimebase), w.setR(w.rD());
      break;
    case 269:  // tbu
      w.c.call(w.env.fnTimebase), w.i64(32), w.op(Op::I64ShrU), w.setR(w.rD());
      break;
    case 1:  // xer: (so << 31) | (ov << 30) | (ca << 29) as an int
      w.pushU8(l.xerSo), w.i32(31), w.op(Op::I32Shl);
      w.pushU8(l.xerOv), w.i32(30), w.op(Op::I32Shl), w.op(Op::I32Or);
      w.pushU8(l.xerCa), w.i32(29), w.op(Op::I32Shl), w.op(Op::I32Or);
      w.op(Op::I64ExtendI32S), w.setR(w.rD());
      break;
    default:
      w.unimplemented(w.mnemonic());
      break;
  }
}

void build_mtspr(W& w) {
  const auto& l = w.L();
  switch (sprNumber(w.word)) {
    case 8:  // lr
      if (!w.config().skipLr)
        w.pushR(w.rS()), w.setU64(l.lr);
      break;
    case 9:  // ctr
      w.pushR(w.rS()), w.setU64(l.ctr);
      break;
    case 1: {  // xer
      const uint32_t offs[3] = {l.xerSo, l.xerOv, l.xerCa};
      for (int i = 0; i < 3; ++i) {
        w.get(kLocalCtx);
        w.pushR32(w.rS()), w.i32(static_cast<int32_t>(0x80000000u >> i)), w.op(Op::I32And),
            w.i32(0), w.op(Op::I32Ne);
        w.c.mem(Op::I32Store8, 0, offs[i]);
      }
      break;
    }
    default:
      w.unimplemented(w.mnemonic());
      break;
  }
}

//=============================================================================
// Loads and stores (builders/memory.cpp). Guest address ea lives at GUEST_BASE + ea:
// words plain, bytes at ea ^ 3, halfwords at ea ^ 2, doublewords rotated by 32 (ADR-0009).
//=============================================================================

/// Pushes i32 (ea in I0 is in the MMIO range 0x7F000000..0x7FFFFFFF).
void pushIsMmioAddr(W& w) {
  w.get(kI0), w.i32(0x7F000000), w.op(Op::I32Sub), w.i32(0x01000000), w.op(Op::I32LtU);
}

void mmioLoad(W& w, Width width) {
  w.get(kLocalCtx), w.get(kI0), w.c.call(w.env.fnMmioLoad32);
  if (width == Width::B)
    w.i32(0xFF), w.op(Op::I32And);
  else if (width == Width::H)
    w.i32(0xFFFF), w.op(Op::I32And);
  w.op(Op::I64ExtendI32U);
  if (width == Width::D) {
    w.i64(32), w.op(Op::I64Shl);
    w.get(kLocalCtx), w.get(kI0), w.i32(4), w.op(Op::I32Add), w.c.call(w.env.fnMmioLoad32);
    w.op(Op::I64ExtendI32U), w.op(Op::I64Or);
  }
}

void mmioStore(W& w, Width width, uint32_t value) {
  if (width == Width::D) {
    w.get(kLocalCtx), w.get(kI0), w.get(value), w.i64(32), w.op(Op::I64ShrU),
        w.op(Op::I32WrapI64), w.c.call(w.env.fnMmioStore32);
    w.get(kLocalCtx), w.get(kI0), w.i32(4), w.op(Op::I32Add), w.get(value),
        w.op(Op::I32WrapI64), w.c.call(w.env.fnMmioStore32);
    return;
  }
  w.get(kLocalCtx), w.get(kI0), w.get(value);
  if (width == Width::B)
    w.i32(0xFF), w.op(Op::I32And);
  else if (width == Width::H)
    w.i32(0xFFFF), w.op(Op::I32And);
  w.c.call(w.env.fnMmioStore32);
}

/// Pushes the linear address for an aligned access of `width` at the ea in I0.
void pushLinear(W& w, Width width) {
  w.get(kI0);
  if (width == Width::B)
    w.i32(3), w.op(Op::I32Xor);
  else if (width == Width::H)
    w.i32(2), w.op(Op::I32Xor);
  w.op(Op::I64ExtendI32U);
}

void plainLoad(W& w, Width width, bool sign) {
  pushLinear(w, width);
  switch (width) {
    case Width::B:
      w.c.mem(Op::I64Load8U, 0, kGuestBase);
      break;
    case Width::H:
      w.c.mem(sign ? Op::I64Load16S : Op::I64Load16U, 1, kGuestBase);
      break;
    case Width::W:
      w.c.mem(sign ? Op::I64Load32S : Op::I64Load32U, 2, kGuestBase);
      break;
    case Width::D:
      w.c.mem(Op::I64Load, 3, kGuestBase);
      w.i64(32), w.op(Op::I64Rotl);
      break;
  }
}

/// Byte-wise load through the module's helpers (misaligned halfword, word or doubleword).
void slowLoad(W& w, Width width, bool sign) {
  w.get(kI0);
  switch (width) {
    case Width::H:
      w.c.call(w.env.fnLoad16);
      if (sign)
        w.op(Op::I32Extend16S), w.op(Op::I64ExtendI32S);
      else
        w.op(Op::I64ExtendI32U);
      break;
    case Width::W:
      w.c.call(w.env.fnLoad32);
      w.op(sign ? Op::I64ExtendI32S : Op::I64ExtendI32U);
      break;
    default:
      w.c.call(w.env.fnLoad64);
      break;
  }
}

void plainStore(W& w, Width width, uint32_t value) {
  pushLinear(w, width);
  w.get(value);
  switch (width) {
    case Width::B:
      w.c.mem(Op::I32Store8, 0, kGuestBase);
      break;
    case Width::H:
      w.c.mem(Op::I32Store16, 1, kGuestBase);
      break;
    case Width::W:
      w.c.mem(Op::I32Store, 2, kGuestBase);
      break;
    case Width::D:
      w.i64(32), w.op(Op::I64Rotl), w.c.mem(Op::I64Store, 3, kGuestBase);
      break;
  }
}

void slowStore(W& w, Width width, uint32_t value) {
  w.get(kI0), w.get(value);
  w.c.call(width == Width::H ? w.env.fnStore16
                             : (width == Width::W ? w.env.fnStore32 : w.env.fnStore64));
}

/// i32 mask of the address bits that must be clear for the fast path.
int32_t alignMask(Width width) {
  return width == Width::H ? 1 : 3;
}

void plainOrSlowLoad(W& w, Width width, bool sign, bool aligned) {
  if (aligned || width == Width::B) {
    plainLoad(w, width, sign);
    return;
  }
  w.get(kI0), w.i32(alignMask(width)), w.op(Op::I32And), w.op(Op::I32Eqz);
  w.beginIf(kI64Block);
  plainLoad(w, width, sign);
  w.beginElse();
  slowLoad(w, width, sign);
  w.end();
}

void plainOrSlowStore(W& w, Width width, uint32_t value, bool aligned) {
  if (aligned || width == Width::B) {
    plainStore(w, width, value);
    return;
  }
  w.get(kI0), w.i32(alignMask(width)), w.op(Op::I32And), w.op(Op::I32Eqz);
  w.beginIf();
  plainStore(w, width, value);
  w.beginElse();
  slowStore(w, width, value);
  w.end();
}

struct Access {
  Width width;
  bool sign = false;
  bool indexed = false;  // X-form
  bool update = false;
  bool checkMmio = false;
  int32_t disp = 0;  // D/DS-form displacement
};

bool foldAccess(W& w, const Access& a) {
  return a.indexed ? foldEaX(w, kI0, w.rA(), w.rB(), a.update)
                   : foldEaD(w, kI0, w.rA(), a.disp, a.update);
}

void emitLoad(W& w, const Access& a) {
  a.indexed ? pushEaX(w, a.update) : pushEaD(w, a.disp, a.update);
  w.set(kI0);
  const bool folded = foldAccess(w, a);
  const bool mmio = a.checkMmio && (a.indexed ? w.mmioCheckXForm() : w.mmioCheckDForm());
  loadValue(w, a.width, a.sign, mmio, provablyAligned(w, a.width, a.indexed, a.update, a.disp));
  w.setR(w.rD());
  if (a.update)
    w.get(unfoldedEa(folded)), w.setR32(w.rA());
}

void emitStore(W& w, const Access& a) {
  a.indexed ? pushEaX(w, a.update) : pushEaD(w, a.disp, a.update);
  w.set(kI0);
  const bool folded = foldAccess(w, a);
  const bool mmio = a.checkMmio && (a.indexed ? w.mmioCheckXForm() : w.mmioCheckDForm());
  uint32_t value;
  if (a.width == Width::D) {
    w.pushR(w.rS()), w.set(kL4);
    value = kL4;
  } else {
    w.pushR32(w.rS()), w.set(kI4);
    value = kI4;
  }
  storeValue(w, a.width, value, mmio, provablyAligned(w, a.width, a.indexed, a.update, a.disp));
  if (a.update)
    w.get(unfoldedEa(folded)), w.setR32(w.rA());
}

// MMIO checks follow builders/memory.cpp: plain D/X forms check, update loads and
// algebraic loads don't, update stores check only in the X form.
template <Width Wd, bool Update>
void build_load_d(W& w) {
  emitLoad(w, {.width = Wd, .update = Update, .checkMmio = !Update, .disp = w.simm()});
}
template <Width Wd, bool Update>
void build_load_x(W& w) {
  emitLoad(w, {.width = Wd, .indexed = true, .update = Update, .checkMmio = !Update});
}
template <bool Update>
void build_lha(W& w) {
  emitLoad(w, {.width = Width::H, .sign = true, .update = Update, .disp = w.simm()});
}
template <bool Update>
void build_lhax(W& w) {
  emitLoad(w, {.width = Width::H, .sign = true, .indexed = true, .update = Update});
}
template <bool Update>
void build_lwax(W& w) {
  emitLoad(w, {.width = Width::W, .sign = true, .indexed = true, .update = Update});
}
template <Width Wd, bool Update>
void build_store_d(W& w) {
  emitStore(w, {.width = Wd, .update = Update, .checkMmio = !Update, .disp = w.simm()});
}
template <Width Wd, bool Update>
void build_store_x(W& w) {
  emitStore(w, {.width = Wd, .indexed = true, .update = Update, .checkMmio = true});
}

/// DS-form opcode 58: ld, ldu, lwa.
void build_ds_load(W& w) {
  const int32_t disp = static_cast<int16_t>(w.word & 0xFFFC);
  switch (w.word & 3) {
    case 0:
      emitLoad(w, {.width = Width::D, .checkMmio = true, .disp = disp});
      break;
    case 1:
      emitLoad(w, {.width = Width::D, .update = true, .disp = disp});
      break;
    case 2:
      emitLoad(w, {.width = Width::W, .sign = true, .disp = disp});
      break;
    default:
      w.unimplemented(w.mnemonic());
      break;
  }
}

/// DS-form opcode 62: std, stdu.
void build_ds_store(W& w) {
  const int32_t disp = static_cast<int16_t>(w.word & 0xFFFC);
  switch (w.word & 3) {
    case 0:
      emitStore(w, {.width = Width::D, .checkMmio = true, .disp = disp});
      break;
    case 1:
      emitStore(w, {.width = Width::D, .update = true, .disp = disp});
      break;
    default:
      w.unimplemented(w.mnemonic());
      break;
  }
}

//=============================================================================
// Branches (builders/control_flow.cpp), decoded from BO/BI so every form is covered
//=============================================================================

/// Pushes the BO/BI condition as i32 0/1, decrementing ctr first when BO asks for it.
/// Returns false (nothing pushed) for "branch always".
bool pushBranchCondition(W& w, uint32_t bo, uint32_t bi, bool allowCtr) {
  const auto& l = w.L();
  const bool decrement = allowCtr && !(bo & 0x04);
  const bool testCr = !(bo & 0x10);
  if (decrement) {
    w.pushU64(l.ctr), w.i64(1), w.op(Op::I64Sub), w.setU64(l.ctr);
    w.pushU32(l.ctr);
    if (bo & 0x02)
      w.op(Op::I32Eqz);
    else
      w.i32(0), w.op(Op::I32Ne);
  }
  if (testCr) {
    w.pushU8(l.crBit(bi));
    if (bo & 0x08)
      w.i32(0), w.op(Op::I32Ne);
    else
      w.op(Op::I32Eqz);
    if (decrement)
      w.op(Op::I32And);
  }
  return decrement || testCr;
}

bool isInternal(W& w, uint32_t target, TargetKind kind) {
  if (kind == TargetKind::InternalLabel)
    return w.hasSegment(target);
  if (kind == TargetKind::Unknown)
    return target >= w.fn.base() && target < w.fn.end() && w.hasSegment(target);
  return false;
}

/// bc / bcl (opcode 16).
void build_bc(W& w) {
  const uint32_t bo = (w.word >> 21) & 31;
  const uint32_t bi = (w.word >> 16) & 31;
  const int32_t bd = static_cast<int16_t>(w.word & 0xFFFC);
  const bool absolute = (w.word & 2) != 0;
  const bool link = (w.word & 1) != 0;
  const uint32_t target = absolute ? static_cast<uint32_t>(bd) : w.base + bd;

  if (link)
    w.setLr(w.base + 4);
  const bool cond = pushBranchCondition(w, bo, bi, true);
  const TargetKind kind = w.graph().classifyTarget(target, w.base, link);

  if (isInternal(w, target, kind)) {
    cond ? w.branchIfTo(target) : w.branchTo(target);
    return;
  }
  if (cond)
    w.beginIf();
  if (kind == TargetKind::Function || kind == TargetKind::Import) {
    w.callGuest(target);
    if (!link)
      w.ret();
  } else {
    REXCODEGEN_ERROR("wasm: unresolved conditional branch 0x{:08X} -> 0x{:08X}", w.base, target);
    w.trap(kUnresolvedCall, w.base);
  }
  if (cond)
    w.end();
}

/// b / bl / ba / bla (opcode 18).
void build_b(W& w) {
  const int32_t li = static_cast<int32_t>(((w.word & 0x03FFFFFC) ^ 0x02000000) - 0x02000000);
  const bool absolute = (w.word & 2) != 0;
  const bool link = (w.word & 1) != 0;
  const uint32_t target = absolute ? static_cast<uint32_t>(li) : w.base + li;

  if (!link) {
    const TargetKind kind = w.graph().classifyTarget(target, w.base, false);
    if (isInternal(w, target, kind)) {
      w.branchTo(target);
      return;
    }
    w.callGuest(target);  // tail call
    w.ret();
    return;
  }

  w.setLr(w.base + 4);
  const TargetKind kind = w.graph().classifyTarget(target, w.base, true);
  if (isInternal(w, target, kind)) {
    w.branchTo(target);  // PIC pattern: bl to get the PC into lr
  } else if (kind == TargetKind::Function || kind == TargetKind::Import) {
    w.callGuest(target);
  } else {
    REXCODEGEN_ERROR("wasm: unresolved bl 0x{:08X} -> 0x{:08X}", w.base, target);
    w.trap(kUnresolvedCall, w.base);
  }
}

/// bclr / bclrl (opcode 19, xo 16): blr returns with wasm `return`.
void build_bclr(W& w) {
  const uint32_t bo = (w.word >> 21) & 31;
  const uint32_t bi = (w.word >> 16) & 31;
  const bool link = (w.word & 1) != 0;
  if (link) {
    w.pushU64(w.L().lr), w.set(kL0);
    w.setLr(w.base + 4);
  }
  const bool cond = pushBranchCondition(w, bo, bi, true);
  if (cond)
    w.beginIf();
  if (link) {
    w.get(kL0), w.op(Op::I32WrapI64), w.callIndirect();
  } else {
    w.ret();
  }
  if (cond)
    w.end();
}

/// Jumps to one jump-table target (an internal label, or a tail call to a function).
void gotoJumpTarget(W& w, uint32_t target) {
  if (target == 0) {
    w.trap(kBadJumpTable, w.base);
    return;
  }
  const TargetKind kind = w.graph().classifyTarget(target, w.base, false);
  if (isInternal(w, target, kind)) {
    w.branchTo(target);
  } else if (kind == TargetKind::Function || kind == TargetKind::Import) {
    if (const FunctionNode* node = w.graph().getFunction(target)) {
      callFunctionNode(w, *node);
      w.ret();
    } else {
      w.trap(kUnresolvedCall, w.base);
    }
  } else {
    REXCODEGEN_ERROR("wasm: jump target 0x{:08X} unresolved at bctr 0x{:08X}", target, w.base);
    w.trap(kUnresolvedCall, w.base);
  }
}

/// br_table on the index register, one block per case. With `checkCtr`, each case first
/// confirms that ctr holds its target and otherwise leaves the outer block.
void emitIndexSwitch(W& w, const JumpTable& jt, bool checkCtr) {
  const uint32_t m = static_cast<uint32_t>(jt.targets.size());
  w.beginBlock();  // index out of range (or ctr mismatch) lands after this block
  const uint32_t outerDepth = w.st.depth;
  for (uint32_t i = 0; i < m; ++i)
    w.beginBlock();
  w.pushR32(jt.indexRegister);
  std::vector<uint32_t> depths(m);
  for (uint32_t i = 0; i < m; ++i)
    depths[i] = i;
  w.c.brTable(depths, m);
  for (uint32_t i = 0; i < m; ++i) {
    w.end();  // case i starts here
    const uint32_t target = jt.targets[i];
    if (checkCtr && target != 0) {
      w.pushU32(w.L().ctr), w.i32(static_cast<int32_t>(target)), w.op(Op::I32Ne);
      w.c.brIf(w.st.depth - outerDepth);
    }
    gotoJumpTarget(w, target);
  }
  w.end();
}

/// Jump table at a bctr. ctr holds the address loaded from the table, which is the target
/// for every table type, so the dispatch keys on ctr and doesn't depend on the index
/// register surviving until the bctr (code may reuse it for the scaled offset, e.g.
/// `slwi r12,r12,2; lwzx r12,r11,r12; mtctr r12; bctr`). Fast path: br_table on the index
/// register, confirmed against ctr. Otherwise ctr is matched against each distinct target,
/// then the plain index switch (ReXGlue's C++ behaviour) is the last resort.
void emitJumpTable(W& w, const JumpTable& jt) {
  emitIndexSwitch(w, jt, true);
  std::set<uint32_t> seen;
  for (uint32_t target : jt.targets) {
    if (target == 0 || !seen.insert(target).second)
      continue;
    w.pushU32(w.L().ctr), w.i32(static_cast<int32_t>(target)), w.op(Op::I32Eq);
    w.beginIf();
    gotoJumpTarget(w, target);
    w.end();
  }
  emitIndexSwitch(w, jt, false);
  w.trap(kBadJumpTable, w.base);
}

/// bcctr / bcctrl (opcode 19, xo 528): jump tables become br_table, otherwise lookup.
void build_bcctr(W& w) {
  const uint32_t bo = (w.word >> 21) & 31;
  const uint32_t bi = (w.word >> 16) & 31;
  const bool link = (w.word & 1) != 0;
  if (link)
    w.setLr(w.base + 4);
  const bool cond = pushBranchCondition(w, bo, bi, false);

  if (!link && !cond) {
    const JumpTable* jt = w.activeJumpTable;
    if (!jt) {
      for (const auto& candidate : w.fn.jumpTables()) {
        if (candidate.bctrAddress == w.base) {
          jt = &candidate;
          break;
        }
      }
    }
    if (jt) {
      emitJumpTable(w, *jt);
      return;
    }
  }

  if (cond)
    w.beginIf();
  w.pushU32(w.L().ctr), w.callIndirect();
  if (!link)
    w.ret();
  if (cond)
    w.end();
}

//=============================================================================
// Dispatch table (twin of instruction_dispatch.cpp, keyed by opcode / extended opcode)
//=============================================================================

using Builder = void (*)(W&);

constexpr uint32_t Key(uint32_t opcd, uint32_t xo = 0) {
  return (opcd << 16) | xo;
}

const std::unordered_map<uint32_t, Builder>& Table() {
  static const std::unordered_map<uint32_t, Builder> table = [] {
    std::unordered_map<uint32_t, Builder> t = {
        // D-form arithmetic, logical, compare
        {Key(7), build_mulli},
        {Key(8), build_subfic},
        {Key(10), build_cmpli},
        {Key(11), build_cmpi},
        {Key(12), build_addic},
        {Key(13), build_addic},
        {Key(14), build_addi},
        {Key(15), build_addis},
        {Key(24), build_ori},
        {Key(25), build_oris},
        {Key(26), build_xori},
        {Key(27), build_xoris},
        {Key(28), build_andi},
        {Key(29), build_andis},
        // Rotates
        {Key(20), build_rlw},
        {Key(21), build_rlw},
        {Key(23), build_rlw},
        {Key(30), build_rld},
        // Branches
        {Key(16), build_bc},
        {Key(18), build_b},
        {Key(19, 16), build_bclr},
        {Key(19, 528), build_bcctr},
        // CR logical
        {Key(19, 0), build_mcrf},
        {Key(19, 257), build_crlogical},
        {Key(19, 129), build_crlogical},
        {Key(19, 289), build_crlogical},
        {Key(19, 225), build_crlogical},
        {Key(19, 33), build_crlogical},
        {Key(19, 449), build_crlogical},
        {Key(19, 417), build_crlogical},
        {Key(19, 193), build_crlogical},
        // D-form loads and stores
        {Key(32), build_load_d<Width::W, false>},
        {Key(33), build_load_d<Width::W, true>},
        {Key(34), build_load_d<Width::B, false>},
        {Key(35), build_load_d<Width::B, true>},
        {Key(40), build_load_d<Width::H, false>},
        {Key(41), build_load_d<Width::H, true>},
        {Key(42), build_lha<false>},
        {Key(43), build_lha<true>},
        {Key(36), build_store_d<Width::W, false>},
        {Key(37), build_store_d<Width::W, true>},
        {Key(38), build_store_d<Width::B, false>},
        {Key(39), build_store_d<Width::B, true>},
        {Key(44), build_store_d<Width::H, false>},
        {Key(45), build_store_d<Width::H, true>},
        {Key(58), build_ds_load},
        {Key(62), build_ds_store},
        // X-form (opcode 31)
        {Key(31, 0), build_cmp},
        {Key(31, 32), build_cmpl},
        {Key(31, 28), build_logical<Op::I64And, false, false>},
        {Key(31, 60), build_logical<Op::I64And, true, false>},
        {Key(31, 444), build_or},
        {Key(31, 412), build_logical<Op::I64Or, true, false>},
        {Key(31, 316), build_logical<Op::I64Xor, false, false>},
        {Key(31, 476), build_logical<Op::I64And, false, true>},
        {Key(31, 124), build_logical<Op::I64Or, false, true>},
        {Key(31, 284), build_logical<Op::I64Xor, false, true>},
        {Key(31, 954), build_exts<Op::I64Extend8S>},
        {Key(31, 922), build_exts<Op::I64Extend16S>},
        {Key(31, 986), build_exts<Op::I64Extend32S>},
        {Key(31, 26), build_cntlzw},
        {Key(31, 58), build_cntlzd},
        {Key(31, 24), build_shift_word<Op::I32Shl>},
        {Key(31, 536), build_shift_word<Op::I32ShrU>},
        {Key(31, 27), build_shift_dword<Op::I64Shl>},
        {Key(31, 539), build_shift_dword<Op::I64ShrU>},
        {Key(31, 792), build_sraw},
        {Key(31, 824), build_srawi},
        {Key(31, 794), build_srad},
        {Key(31, 826), build_sradi},
        {Key(31, 827), build_sradi},
        {Key(31, 339), build_mfspr},
        {Key(31, 467), build_mtspr},
        {Key(31, 19), build_mfcr},
        {Key(31, 144), build_mtcrf},
        // X-form loads and stores
        {Key(31, 23), build_load_x<Width::W, false>},
        {Key(31, 55), build_load_x<Width::W, true>},
        {Key(31, 87), build_load_x<Width::B, false>},
        {Key(31, 119), build_load_x<Width::B, true>},
        {Key(31, 279), build_load_x<Width::H, false>},
        {Key(31, 311), build_load_x<Width::H, true>},
        {Key(31, 343), build_lhax<false>},
        {Key(31, 375), build_lhax<true>},
        {Key(31, 341), build_lwax<false>},
        {Key(31, 373), build_lwax<true>},
        {Key(31, 21), build_load_x<Width::D, false>},
        {Key(31, 53), build_load_x<Width::D, true>},
        {Key(31, 151), build_store_x<Width::W, false>},
        {Key(31, 183), build_store_x<Width::W, true>},
        {Key(31, 215), build_store_x<Width::B, false>},
        {Key(31, 247), build_store_x<Width::B, true>},
        {Key(31, 407), build_store_x<Width::H, false>},
        {Key(31, 439), build_store_x<Width::H, true>},
        {Key(31, 149), build_store_x<Width::D, false>},
        {Key(31, 181), build_store_x<Width::D, true>},
    };
    // XO-form arithmetic: 9-bit extended opcode, registered with OE = 0 and OE = 1.
    const std::pair<uint32_t, Builder> xoForms[] = {
        {266, build_add},    {10, build_addc},    {138, build_adde},  {234, build_addme},
        {202, build_addze},  {40, build_subf},    {8, build_subfc},   {136, build_subfe},
        {232, build_subfme}, {200, build_subfze}, {104, build_neg},   {235, build_mullw},
        {75, build_mulhw},   {11, build_mulhwu},  {233, build_mulld}, {491, build_divw},
        {459, build_divwu},  {489, build_divd},   {457, build_divdu},
    };
    for (const auto& [xo, builder] : xoForms) {
      t[Key(31, xo)] = builder;
      if (xo != 75 && xo != 11)  // mulhw/mulhwu have no OE form
        t[Key(31, xo | 0x200)] = builder;
    }
    return t;
  }();
  return table;
}

const IdTable& Ids() {
  static const IdTable table = [] {
    IdTable t;
    RegisterFloatBuilders(t);
    RegisterVectorBuilders(t);
    RegisterSystemBuilders(t);
    return t;
  }();
  return table;
}

}  // namespace

AliasFoldStats& GetAliasFoldStats() {
  static AliasFoldStats stats;
  return stats;
}

namespace detail {

void pushEaD(W& w, int32_t disp, bool update) {
  if (w.rA() != 0 || update)
    w.pushR32(w.rA()), w.i32(disp), w.op(Op::I32Add);
  else
    w.i32(disp);
}

void pushEaX(W& w, bool update) {
  if (w.rA() != 0 || update)
    w.pushR32(w.rA()), w.pushR32(w.rB()), w.op(Op::I32Add);
  else
    w.pushR32(w.rB());
}

bool provablyAligned(const W& w, Width width, bool indexed, bool update, int32_t disp) {
  if (width == Width::B)
    return true;
  if (indexed || (disp & alignMask(width)) != 0)
    return false;
  if (w.rA() == 0 && !update)
    return true;  // absolute address
  return w.rA() == 1;
}

void loadValue(W& w, Width width, bool sign, bool mmio, bool aligned) {
  if (!mmio) {
    plainOrSlowLoad(w, width, sign, aligned);
    return;
  }
  pushIsMmioAddr(w);
  w.beginIf(kI64Block);
  mmioLoad(w, width);
  w.beginElse();
  plainOrSlowLoad(w, width, sign, aligned);
  w.end();
}

void storeValue(W& w, Width width, uint32_t valueLocal, bool mmio, bool aligned) {
  if (!mmio) {
    plainOrSlowStore(w, width, valueLocal, aligned);
    return;
  }
  pushIsMmioAddr(w);
  w.beginIf();
  mmioStore(w, width, valueLocal);
  w.beginElse();
  plainOrSlowStore(w, width, valueLocal, aligned);
  w.end();
}

//=============================================================================
// Physical alias fold (D-080, T-050; see CanonicalGuestAddress in wasm_backend.h)
//=============================================================================

namespace {

using K = RegKnowledge;

/// Knowledge of a base register: r1 and r13 count as stack-like (outside the physical views).
K baseKnowledge(const W& w, uint32_t r) {
  if (r == 1 || r == 13)
    return {K::kStack, 0};
  return w.st.regs[r];
}

/// Pushes the canonical address of the guest address in `local` (valid at or above 0xC0000000).
void pushCanonical(W& w, uint32_t local) {
  w.get(local), w.i32(0x1FFFFFFF), w.op(Op::I32And);
  w.i32(static_cast<int32_t>(kCanonicalPhysicalBase)), w.op(Op::I32Or);
  w.get(local), w.i32(17), w.op(Op::I32ShrU), w.i32(0x1000), w.op(Op::I32And);
  w.op(Op::I32Add);
}

bool foldOff(const W& w) {
  return w.config().wasmAliasFold == "none";
}

bool plain() {
  GetAliasFoldStats().plain++;
  return false;
}

}  // namespace

void emitAliasFold(W& w, uint32_t local) {
  if (w.config().wasmAliasFold == "select") {
    pushCanonical(w, local);
    w.get(local);
    w.get(local), w.i32(static_cast<int32_t>(kAliasFoldStart)), w.op(Op::I32GeU);
    w.op(Op::Select);
    w.set(local);
    return;
  }
  w.get(local), w.i32(static_cast<int32_t>(kAliasFoldStart)), w.op(Op::I32GeU);
  w.beginIf();
  pushCanonical(w, local);
  w.set(local);
  w.end();
}

bool foldEaD(W& w, uint32_t local, uint32_t ra, int32_t disp, bool update) {
  if (foldOff(w))
    return false;
  if (ra == 0 && !update) {
    const uint32_t ea = static_cast<uint32_t>(disp);
    if (ea < kAliasFoldStart)
      return plain();
    GetAliasFoldStats().constant++;
    w.i32(static_cast<int32_t>(CanonicalGuestAddress(ea))), w.set(local);
    return true;
  }
  const K k = baseKnowledge(w, ra);
  if (k.kind == K::kStack)
    return plain();
  if (k.kind == K::kConst && k.value + static_cast<uint32_t>(disp) < kAliasFoldStart)
    return plain();
  GetAliasFoldStats().checked++;
  if (update)
    w.get(local), w.set(kI6);
  emitAliasFold(w, local);
  return true;
}

bool foldEaX(W& w, uint32_t local, uint32_t ra, uint32_t rb, bool update) {
  if (foldOff(w))
    return false;
  const K a = ra == 0 && !update ? K{K::kConst, 0} : baseKnowledge(w, ra);
  const K b = baseKnowledge(w, rb);
  if (a.kind == K::kConst && b.kind == K::kConst && a.value + b.value < kAliasFoldStart)
    return plain();
  // A stack address plus a small known offset stays on the stack.
  auto small = [](const K& k) { return k.kind == K::kConst && k.value + 0x8000u < 0x10000u; };
  if ((a.kind == K::kStack && small(b)) || (b.kind == K::kStack && small(a)))
    return plain();
  GetAliasFoldStats().checked++;
  if (update)
    w.get(local), w.set(kI6);
  emitAliasFold(w, local);
  return true;
}

void ResetRegisterKnowledge(FunctionState& st) {
  st.regs.fill({});
}

void TrackRegisterWrites(FunctionState& st, uint32_t word) {
  auto& r = st.regs;
  const uint32_t opcd = word >> 26;
  const uint32_t rd = (word >> 21) & 31, ra = (word >> 16) & 31, rb = (word >> 11) & 31;
  const uint32_t simm = static_cast<uint32_t>(static_cast<int32_t>(static_cast<int16_t>(word)));
  const uint32_t uimm = word & 0xFFFF;
  const auto isStack = [&](uint32_t n) { return n == 1 || r[n].kind == K::kStack; };
  switch (opcd) {
    case 14: {  // addi (li)
      K k;
      if (ra == 0)
        k = {K::kConst, simm};
      else if (isStack(ra))
        k = {K::kStack, 0};
      else if (r[ra].kind == K::kConst)
        k = {K::kConst, r[ra].value + simm};
      r[rd] = k;
      return;
    }
    case 15: {  // addis (lis)
      K k;
      if (ra == 0)
        k = {K::kConst, uimm << 16};
      else if (r[ra].kind == K::kConst && ra != 1)
        k = {K::kConst, r[ra].value + (uimm << 16)};
      r[rd] = k;
      return;
    }
    case 24:    // ori rA, rS, uimm
    case 25: {  // oris
      K k;
      if (r[rd].kind == K::kConst && rd != 1)
        k = {K::kConst, r[rd].value | (opcd == 24 ? uimm : uimm << 16)};
      else if (isStack(rd) && uimm == 0)
        k = {K::kStack, 0};
      r[ra] = k;
      return;
    }
    case 32: case 34: case 40: case 42:  // lwz lbz lhz lha
      r[rd] = {};
      return;
    case 33: case 35: case 41: case 43:  // update loads
      r[rd] = {}, r[ra] = {};
      return;
    case 36: case 38: case 44: case 47:  // stw stb sth stmw
    case 48: case 50: case 52: case 54:  // lfs lfd stfs stfd
      return;
    case 37: case 39: case 45:           // update stores
    case 49: case 51: case 53: case 55:  // FP update forms
      r[ra] = {};
      return;
    case 46:  // lmw
      for (uint32_t n = rd; n < 32; ++n)
        r[n] = {};
      return;
    case 62:  // std / stdu
      if ((word & 3) == 1)
        r[ra] = {};
      return;
    case 16: case 18: case 19:  // branches: a linking one is a call and may change anything
      if (word & 1)
        r.fill({});
      return;
    case 17:  // sc
      r.fill({});
      return;
    case 31: {
      const uint32_t xo = (word >> 1) & 0x3FF;
      if (xo == 444 && rd == rb) {  // mr rA, rS
        r[ra] = rd == 1 ? K{K::kStack, 0} : r[rd];
        return;
      }
      if (xo == 533 || xo == 597) {  // lswx, lswi
        r.fill({});
        return;
      }
      break;
    }
    default:
      break;
  }
  // Everything else writes at most the registers in the rD/rS and rA fields.
  r[rd] = {}, r[ra] = {};
}

void pushGuestLinear(W& w, uint32_t local) {
  w.get(local), w.op(Op::I64ExtendI32U), w.i64(static_cast<int64_t>(kGuestBase)),
      w.op(Op::I64Add);
}

}  // namespace detail

bool DispatchWasmInstruction(WasmBuilderContext& ctx) {
  const uint32_t opcd = ctx.word >> 26;
  uint32_t key = Key(opcd);
  if (opcd == 19 || opcd == 31)
    key = Key(opcd, (ctx.word >> 1) & 0x3FF);
  const auto& table = Table();
  if (auto it = table.find(key); it != table.end()) {
    it->second(ctx);
    return true;
  }
  if (!ctx.insn.opcode)
    return false;
  int id = ctx.insn.opcode->id;
  // VUPKHSB128/VUPKLSB128 misidentification fixup (instruction_dispatch.cpp).
  if (id == PPC_INST_VUPKHSB128 && ctx.insn.operands[2] == 0x60)
    id = PPC_INST_VUPKHSH128;
  else if (id == PPC_INST_VUPKLSB128 && ctx.insn.operands[2] == 0x60)
    id = PPC_INST_VUPKLSH128;
  const auto& ids = Ids();
  auto it = ids.find(id);
  if (it == ids.end())
    return false;
  it->second(ctx);
  return true;
}

}  // namespace rex::codegen::wasm
