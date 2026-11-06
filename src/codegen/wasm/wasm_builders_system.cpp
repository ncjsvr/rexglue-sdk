/**
 * @file        codegen/wasm/wasm_builders_system.cpp
 * @brief       wasm builders for atomics, barriers, cache ops, traps, MSR, timebase, 128-bit
 *              multiplies and the remaining integer loads and stores (guest ABI v1)
 *
 * The reference is ReXGlue's builders/system.cpp, memory.cpp and helpers.h. Guest memory
 * is byte-swapped storage (ADR-0009): the reservation of lwarx/ldarx holds the raw stored
 * value, as ReXGlue's emitAtomicLoadReserve holds the raw big-endian one.
 *
 * @copyright   Copyright (c) 2026 MCLA-Reborn contributors
 * @license     Not yet licensed: MCLA-Reborn decides before any release (D-009)
 */

#include <rex/codegen/config.h>

#include "wasm_builders_internal.h"

#if REXGLUE_TRANSLATOR_PPC
#include <translator_ppc/binutils_compat.h>  // MCLA-Reborn: our decoder (T-048)
#else
#include <dis-asm.h>
#include <ppc-inst.h>
#endif

namespace rex::codegen::wasm::detail {

namespace {


void build_nothing(W&) {}

//=============================================================================
// Atomics (helpers.h emitAtomicLoadReserve / emitAtomicStoreConditional)
//=============================================================================

/// lwarx / ldarx: reserved = raw value at ea; rD = guest value.
template <bool Double>
void build_load_reserve(W& w) {
  pushEaX(w, false), w.set(kI0);
  pushGuestLinear(w, kI0);
  if (Double) {
    w.c.atomicMem(Atomic::I64Load, 3, 0), w.set(kL1);
    w.get(kLocalCtx), w.get(kL1), w.c.mem(Op::I64Store, 3, w.L().reserved);
    w.get(kL1), w.i64(32), w.op(Op::I64Rotl), w.setR(w.rD());
  } else {
    w.c.atomicMem(Atomic::I32Load, 2, 0), w.set(kI1);
    w.get(kLocalCtx), w.get(kI1), w.c.mem(Op::I32Store, 2, w.L().reserved);
    w.get(kI1), w.op(Op::I64ExtendI32U), w.setR(w.rD());
  }
}

/// stwcx. / stdcx.: cr0 = {0, 0, CAS(ea, reserved, rS), xer.so}.
template <bool Double>
void build_store_conditional(W& w) {
  pushEaX(w, false), w.set(kI0);
  pushGuestLinear(w, kI0);
  if (Double) {
    w.pushU64(w.L().reserved);
    w.pushR(w.rS()), w.i64(32), w.op(Op::I64Rotl);
    w.c.atomicMem(Atomic::I64RmwCmpxchg, 3, 0);
    w.pushU64(w.L().reserved), w.op(Op::I64Eq), w.set(kI1);
  } else {
    w.pushU32(w.L().reserved);
    w.pushR32(w.rS());
    w.c.atomicMem(Atomic::I32RmwCmpxchg, 2, 0);
    w.pushU32(w.L().reserved), w.op(Op::I32Eq), w.set(kI1);
  }
  w.get(kLocalCtx);
  w.get(kI1), w.i32(16), w.op(Op::I32Shl);
  w.pushU8(w.L().xerSo), w.i32(24), w.op(Op::I32Shl), w.op(Op::I32Or);
  w.c.mem(Op::I32Store, 0, w.L().cr[0].lt);
}

//=============================================================================
// Barriers and cache operations (system.cpp: all no-ops on x86)
//=============================================================================

/// sync / lwsync: ReXGlue relies on x86 ordering; wasm needs a fence to order plain
/// accesses on weakly ordered hosts, so these become atomic.fence.
void build_fence(W& w) {
  w.c.atomicFence();
}

/// dcbz (32 bytes) / dcbzl (dcbz128, 128 bytes): zero the aligned cache line.
template <uint32_t Line>
void build_dcbz(W& w) {
  if (w.rA() != 0)
    w.pushR32(w.rA()), w.pushR32(w.rB()), w.op(Op::I32Add);
  else
    w.pushR32(w.rB());
  w.i32(static_cast<int32_t>(~(Line - 1))), w.op(Op::I32And), w.set(kI0);
  pushGuestLinear(w, kI0);
  w.i32(0);
  w.i64(Line);
  w.c.memoryFill();
}

//=============================================================================
// Traps (system.cpp build_tw/twi/td/tdi, helpers.h emitTrap)
//=============================================================================

void guestTrap(W& w, uint32_t type) {
  w.get(kLocalCtx);
  w.i32(static_cast<int32_t>(w.base));
  w.i32(static_cast<int32_t>(kGuestTrap | (type << kTrapTypeShift)));
  w.c.call(w.env.fnTrap);
}

/// Traps when any TO condition holds for (a, b) in locals A, B (i32 or i64).
void emitTrap(W& w, uint32_t to, bool is64, uint32_t a, uint32_t b) {
  if (to == 0)
    return;
  if (to == 0x1F) {
    guestTrap(w, 0);
    return;
  }
  bool first = true;
  auto cond = [&](uint8_t op32, uint8_t op64) {
    w.get(a), w.get(b), w.op(is64 ? op64 : op32);
    if (!first)
      w.op(Op::I32Or);
    first = false;
  };
  if (to & 0x10)
    cond(Op::I32LtS, Op::I64LtS);
  if (to & 0x08)
    cond(Op::I32GtS, Op::I64GtS);
  if (to & 0x04)
    cond(Op::I32Eq, Op::I64Eq);
  if (to & 0x02)
    cond(Op::I32LtU, Op::I64LtU);
  if (to & 0x01)
    cond(Op::I32GtU, Op::I64GtU);
  w.beginIf();
  guestTrap(w, 0);
  w.end();
}

uint32_t trapTo(const W& w) {
  return (w.word >> 21) & 0x1F;
}

void build_tw(W& w) {
  w.pushR32(w.rA()), w.set(kI0), w.pushR32(w.rB()), w.set(kI1);
  emitTrap(w, trapTo(w), false, kI0, kI1);
}

void build_td(W& w) {
  w.pushR(w.rA()), w.set(kL0), w.pushR(w.rB()), w.set(kL1);
  emitTrap(w, trapTo(w), true, kL0, kL1);
}

void build_twi(W& w) {
  // twi 31, r0, imm is an unconditional service trap with its type in the immediate.
  if (trapTo(w) == 0x1F && w.rA() == 0) {
    guestTrap(w, w.uimm());
    return;
  }
  w.pushR32(w.rA()), w.set(kI0), w.i32(w.simm()), w.set(kI1);
  emitTrap(w, trapTo(w), false, kI0, kI1);
}

void build_tdi(W& w) {
  w.pushR(w.rA()), w.set(kL0), w.i64(w.simm()), w.set(kL1);
  emitTrap(w, trapTo(w), true, kL0, kL1);
}

/// sc: ReXGlue has no builder (REX_UNIMPLEMENTED throws); a system-call trap that never
/// returns, so the host can report it.
void build_sc(W& w) {
  w.trap(kSystemCall, w.base);
}

//=============================================================================
// MSR and timebase (system.cpp build_mfmsr / build_mtmsrd / build_mftb)
//=============================================================================

enum GlobalLockOp : int32_t { kLockCheck = 0, kLockEnter = 1, kLockLeave = 2 };

void build_mfmsr(W& w) {
  if (w.config().skipMsr)
    return;
  if (w.env.fnGlobalLock == ModuleEnv::kNone) {
    w.unimplemented("mfmsr");
    return;
  }
  w.c.atomicFence();
  // REX_CHECK_GLOBAL_LOCK(): 0x8000 when no thread holds the global lock, else 0.
  w.get(kLocalCtx), w.i32(kLockCheck), w.c.call(w.env.fnGlobalLock);
  w.op(Op::I64ExtendI32U), w.setR(w.rD());
}

/// mtmsrd (and mtmsr): EE/RI bits into ctx.msr; r13 enters the global lock, any other
/// register leaves it (the kernel's interrupt-disable idiom).
void build_mtmsrd(W& w) {
  if (w.config().skipMsr)
    return;
  if (w.env.fnGlobalLock == ModuleEnv::kNone) {
    w.unimplemented("mtmsrd");
    return;
  }
  w.c.atomicFence();
  w.pushR32(w.rS()), w.i32(0x8020), w.op(Op::I32And);
  w.pushU32(w.L().msr), w.i32(~0x8020), w.op(Op::I32And), w.op(Op::I32Or);
  w.setU32(w.L().msr);
  w.get(kLocalCtx), w.i32(w.rS() == 13 ? kLockEnter : kLockLeave), w.c.call(w.env.fnGlobalLock);
  w.op(Op::Drop);
}

/// mftb rD, tbr: TBR 269 reads the upper half. The disassembler reports `mftb rD, 269` as
/// mftb, so the TBR is decoded from the word (ReXGlue's build_mftb ignores it).
void build_mftb(W& w) {
  const uint32_t tbr = ((w.word >> 16) & 31) | (((w.word >> 11) & 31) << 5);
  w.c.call(w.env.fnTimebase);
  if (tbr == 269)
    w.i64(32), w.op(Op::I64ShrU);
  w.setR(w.rD());
}

void build_mftbu(W& w) {
  w.c.call(w.env.fnTimebase), w.i64(32), w.op(Op::I64ShrU), w.setR(w.rD());
}

//=============================================================================
// mulhd / mulhdu (arithmetic.cpp): the high 64 bits of a 128-bit product, from 32-bit halves
//=============================================================================

/// Pushes the unsigned high half of L0 * L1 (uses L2, L4, L5).
void pushMulHighU(W& w) {
  constexpr int64_t kLow = 0xFFFFFFFF;
  auto lo = [&](uint32_t l) { w.get(l), w.i64(kLow), w.op(Op::I64And); };
  auto hi = [&](uint32_t l) { w.get(l), w.i64(32), w.op(Op::I64ShrU); };
  lo(kL0), lo(kL1), w.op(Op::I64Mul), w.set(kL2);  // ll
  lo(kL0), hi(kL1), w.op(Op::I64Mul), w.set(kL4);  // lh
  hi(kL0), lo(kL1), w.op(Op::I64Mul), w.set(kL5);  // hl
  // mid = (ll >> 32) + (lh & 0xFFFFFFFF) + (hl & 0xFFFFFFFF)
  hi(kL2), lo(kL4), w.op(Op::I64Add), lo(kL5), w.op(Op::I64Add), w.set(kL2);
  // hh + (lh >> 32) + (hl >> 32) + (mid >> 32)
  hi(kL0), hi(kL1), w.op(Op::I64Mul);
  hi(kL4), w.op(Op::I64Add), hi(kL5), w.op(Op::I64Add), hi(kL2), w.op(Op::I64Add);
}

void build_mulhdu(W& w) {
  w.pushR(w.rA()), w.set(kL0), w.pushR(w.rB()), w.set(kL1);
  pushMulHighU(w);
  w.setR(w.rD());
  if (w.rc())
    w.recordForm(w.rD());
}

void build_mulhd(W& w) {
  w.pushR(w.rA()), w.set(kL0), w.pushR(w.rB()), w.set(kL1);
  pushMulHighU(w);
  // signed = unsigned - (a < 0 ? b : 0) - (b < 0 ? a : 0)
  w.get(kL1), w.i64(0), w.get(kL0), w.i64(0), w.op(Op::I64LtS), w.op(Op::Select), w.op(Op::I64Sub);
  w.get(kL0), w.i64(0), w.get(kL1), w.i64(0), w.op(Op::I64LtS), w.op(Op::Select), w.op(Op::I64Sub);
  w.setR(w.rD());
  if (w.rc())
    w.recordForm(w.rD());
}

//=============================================================================
// Byte-reversed and multiple-word loads and stores (memory.cpp)
//=============================================================================

/// i32 on the stack -> its bytes reversed.
void bswap32(W& w) {
  w.tee(kI2);
  w.i32(8), w.op(Op::I32Rotr), w.i32(static_cast<int32_t>(0xFF00FF00)), w.op(Op::I32And);
  w.get(kI2), w.i32(8), w.op(Op::I32Rotl), w.i32(0x00FF00FF), w.op(Op::I32And);
  w.op(Op::I32Or);
}

/// Low 16 bits of the i32 on the stack -> swapped, zero-extended.
void bswap16(W& w) {
  w.tee(kI2);
  w.i32(0xFF), w.op(Op::I32And), w.i32(8), w.op(Op::I32Shl);
  w.get(kI2), w.i32(8), w.op(Op::I32ShrU), w.i32(0xFF), w.op(Op::I32And);
  w.op(Op::I32Or);
}

template <Width Wd>
void build_load_brx(W& w) {
  pushEaX(w, false), w.set(kI0);
  loadValue(w, Wd, false, w.mmioCheckXForm(), false);
  w.op(Op::I32WrapI64);
  Wd == Width::W ? bswap32(w) : bswap16(w);
  w.op(Op::I64ExtendI32U), w.setR(w.rD());
}

template <Width Wd>
void build_store_brx(W& w) {
  pushEaX(w, false), w.set(kI0);
  w.pushR32(w.rS());
  Wd == Width::W ? bswap32(w) : bswap16(w);
  w.set(kI4);
  storeValue(w, Wd, kI4, w.mmioCheckXForm(), false);
}

/// stmw / lmw: words rS..r31 at (rA|0) + d, ascending.
template <bool Store>
void build_multiple(W& w) {
  pushEaD(w, w.simm(), false), w.set(kI5);
  const bool aligned = provablyAligned(w, Width::W, false, false, w.simm());
  for (uint32_t r = w.rD(); r <= 31; ++r) {
    w.get(kI5), w.i32(static_cast<int32_t>(4 * (r - w.rD()))), w.op(Op::I32Add), w.set(kI0);
    if (Store) {
      w.pushR32(r), w.set(kI4);
      storeValue(w, Width::W, kI4, false, aligned);
    } else {
      loadValue(w, Width::W, false, false, aligned);
      w.setR(r);
    }
  }
}

}  // namespace

void RegisterSystemBuilders(IdTable& t) {
  t[PPC_INST_LWARX] = build_load_reserve<false>;
  t[PPC_INST_LDARX] = build_load_reserve<true>;
  t[PPC_INST_STWCX] = build_store_conditional<false>;
  t[PPC_INST_STDCX] = build_store_conditional<true>;

  t[PPC_INST_SYNC] = build_fence;
  t[PPC_INST_LWSYNC] = build_fence;
  for (int id : {PPC_INST_EIEIO, PPC_INST_ISYNC, PPC_INST_NOP, PPC_INST_ATTN, PPC_INST_DB16CYC,
                 PPC_INST_CCTPL, PPC_INST_CCTPM, PPC_INST_CCTPH, PPC_INST_DCBF, PPC_INST_DCBT,
                 PPC_INST_DCBTST, PPC_INST_DCBST, PPC_INST_ICBI})
    t[id] = build_nothing;
  t[PPC_INST_DCBZ] = build_dcbz<32>;
  t[PPC_INST_DCBZL] = build_dcbz<128>;

  t[PPC_INST_TW] = build_tw;
  t[PPC_INST_TD] = build_td;
  t[PPC_INST_TWI] = build_twi;
  t[PPC_INST_TDI] = build_tdi;
  for (int id : {PPC_INST_TWGE, PPC_INST_TWGT, PPC_INST_TWLE, PPC_INST_TWLT, PPC_INST_TWEQ,
                 PPC_INST_TWNE, PPC_INST_TWLGE, PPC_INST_TWLGT, PPC_INST_TWLLE, PPC_INST_TWLLT,
                 // not in ReXGlue's table; the builder decodes TO from the word
                 PPC_INST_TRAP, PPC_INST_TWLNG, PPC_INST_TWLNL, PPC_INST_TWNG, PPC_INST_TWNL})
    t[id] = build_tw;
  for (int id : {PPC_INST_TDGE, PPC_INST_TDGT, PPC_INST_TDLE, PPC_INST_TDLT, PPC_INST_TDEQ,
                 PPC_INST_TDNE, PPC_INST_TDLGE, PPC_INST_TDLGT, PPC_INST_TDLLE, PPC_INST_TDLLT,
                 PPC_INST_TDLNG, PPC_INST_TDLNL, PPC_INST_TDNG, PPC_INST_TDNL})
    t[id] = build_td;
  for (int id : {PPC_INST_TWLGTI, PPC_INST_TWLLTI, PPC_INST_TWEQI, PPC_INST_TWLGEI,
                 PPC_INST_TWLNLI, PPC_INST_TWLLEI, PPC_INST_TWLNGI, PPC_INST_TWGTI, PPC_INST_TWGEI,
                 PPC_INST_TWNLI, PPC_INST_TWLTI, PPC_INST_TWLEI, PPC_INST_TWNGI, PPC_INST_TWNEI})
    t[id] = build_twi;
  for (int id : {PPC_INST_TDLGTI, PPC_INST_TDLLTI, PPC_INST_TDEQI, PPC_INST_TDLGEI,
                 PPC_INST_TDLNLI, PPC_INST_TDLLEI, PPC_INST_TDLNGI, PPC_INST_TDGTI, PPC_INST_TDGEI,
                 PPC_INST_TDNLI, PPC_INST_TDLTI, PPC_INST_TDLEI, PPC_INST_TDNGI, PPC_INST_TDNEI})
    t[id] = build_tdi;
  t[PPC_INST_SC] = build_sc;

  t[PPC_INST_MFMSR] = build_mfmsr;
  t[PPC_INST_MTMSRD] = build_mtmsrd;
  t[PPC_INST_MTMSR] = build_mtmsrd;
  t[PPC_INST_MFTB] = build_mftb;
  t[PPC_INST_MFTBU] = build_mftbu;

  t[PPC_INST_MULHD] = build_mulhd;
  t[PPC_INST_MULHDU] = build_mulhdu;

  t[PPC_INST_LWBRX] = build_load_brx<Width::W>;
  t[PPC_INST_LHBRX] = build_load_brx<Width::H>;
  t[PPC_INST_STWBRX] = build_store_brx<Width::W>;
  t[PPC_INST_STHBRX] = build_store_brx<Width::H>;
  t[PPC_INST_STMW] = build_multiple<true>;
  t[PPC_INST_LMW] = build_multiple<false>;
}

}  // namespace rex::codegen::wasm::detail
