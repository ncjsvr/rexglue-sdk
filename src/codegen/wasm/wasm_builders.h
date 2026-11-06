/**
 * @file        codegen/wasm/wasm_builders.h
 * @brief       Context for the wasm instruction builders (twin of builders/builder_context.h)
 *
 * @copyright   Copyright (c) 2026 MCLA-Reborn contributors
 * @license     Not yet licensed: MCLA-Reborn decides before any release (D-009)
 */

#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>

#include <rex/codegen/function_graph.h>

#include "wasm_backend.h"

#if REXGLUE_TRANSLATOR_PPC
#include <translator_ppc/binutils_compat.h>  // ppc_insn is translator_ppc's (T-048)
#else
struct ppc_insn;
#endif

namespace rex::codegen::wasm {

/// State that lives for one function's translation.
struct FunctionState {
  /// Open blocks between the current position and the dispatch loop.
  uint32_t depth = 0;
  /// Start address of each basic-block case -> its index in the dispatch br_table.
  std::map<uint32_t, uint32_t> segments;
  /// Registers holding an MMIO base (mirrors RecompilerLocalVariables::mmio_base_regs).
  uint32_t mmioBaseRegs = 0;
  /// Jump tables found at emission time (mtctr..bctr pattern), keyed by bctr address.
  std::unordered_map<uint32_t, JumpTable> lateJumpTables;
  std::set<std::string>* unimplemented = nullptr;
  /// setjmp call sites (bl to the configured setjmp_address) -> return address; empty when the
  /// function has none. With sites, the body is wrapped in a try_table (wasm_function.cpp).
  std::map<uint32_t, uint32_t> setjmpSites;
  uint32_t localJmpBuf = 0;     ///< i32: guest jmp_buf address of the last setjmp
  uint32_t localJmpResume = 0;  ///< i32: 1 + case index to resume at, 0 when no setjmp ran
  uint32_t localSnapshot = 0;   ///< first of the v128 locals holding the context snapshot
  uint32_t snapshotCount = 0;
};

/**
 * Context passed to each wasm builder. Builders decode operands from the raw instruction
 * word and emit wasm into `c`. Registers live in the PPCContext in linear memory at $ctx;
 * guest memory is at GUEST_BASE + ea with byte-swapped storage (ADR-0009).
 */
struct WasmBuilderContext {
  Code& c;
  const EmitContext& emitCtx;
  const ModuleEnv& env;
  const FunctionNode& fn;
  const ppc_insn& insn;
  uint32_t base;          ///< Guest address of the instruction
  uint32_t word;          ///< Instruction word (host order)
  const uint32_t* data;   ///< Raw (big-endian) instruction data at `base`
  FunctionState& st;
  const JumpTable* activeJumpTable = nullptr;

  const ContextLayout& L() const { return env.layout; }
  const RecompilerConfig& config() const;
  const FunctionGraph& graph() const;
  const char* mnemonic() const;

  // --- Instruction fields ---
  uint32_t rD() const { return (word >> 21) & 31; }
  uint32_t rS() const { return rD(); }
  uint32_t rA() const { return (word >> 16) & 31; }
  uint32_t rB() const { return (word >> 11) & 31; }
  int32_t simm() const { return static_cast<int16_t>(word & 0xFFFF); }
  uint32_t uimm() const { return word & 0xFFFF; }
  bool rc() const { return (word & 1) != 0; }
  bool oe() const { return ((word >> 10) & 1) != 0; }
  /// Decoded operand i, as ReXGlue's C++ builders read it (insn.operands[i]).
  uint32_t opnd(size_t i) const;
  /// Record form by mnemonic ('.' suffix), as helpers.h isRecordForm.
  bool recordName() const;

  // --- Stack helpers ---
  void get(uint32_t local) { c.localGet(local); }
  void set(uint32_t local) { c.localSet(local); }
  void tee(uint32_t local) { c.localTee(local); }
  void i32(int32_t v) { c.i32Const(v); }
  void i64(int64_t v) { c.i64Const(v); }
  void op(uint8_t o) { c.op(o); }

  // --- Register context access (every use goes through the context in v1) ---
  void pushR(uint32_t n);         ///< i64 rN
  void pushR32(uint32_t n);       ///< i32 low word of rN
  void setR(uint32_t n);          ///< pops i64 into rN
  void setR32(uint32_t n);        ///< pops i32 into the low word of rN (upper word kept)
  void pushU8(uint32_t off);      ///< i32 zero-extended byte at ctx+off
  void setU8(uint32_t off);       ///< pops i32 and stores its low byte
  void pushU32(uint32_t off);
  void setU32(uint32_t off);
  void pushU64(uint32_t off);
  void setU64(uint32_t off);
  void pushF(uint32_t n);      ///< f64 fN
  void setF(uint32_t n);       ///< pops f64 into fN
  void pushFBits(uint32_t n);  ///< i64 fN.u64
  void setFBits(uint32_t n);   ///< pops i64 into fN.u64
  void pushV(uint32_t n);      ///< v128 vN (host order, guest element 0 in the high lanes)
  void setV(uint32_t n);       ///< pops v128 into vN
  void simd(uint32_t o) { c.simd(o); }

  /// crN = compare(a, b) with so copied from XER, as CRRegister::compare does.
  enum class Cmp { S32, U32, S64, U64 };
  void compare(uint32_t field, Cmp kind, uint32_t localA, uint32_t localB);
  /// Record form: cr0 = compare<int32_t>(rN.s32, 0).
  void recordForm(uint32_t n);
  /// Pops an i32 overflow flag (0/1): XER[OV] = flag, XER[SO] |= flag.
  void setOverflow();

  // --- Control flow ---
  void beginIf(uint8_t blockType = kBlockEmpty);
  void beginElse() { c.else_(); }
  void beginBlock();
  void end();
  /// Branch to the case starting at `target`; false if it is not a case of this function.
  bool hasSegment(uint32_t target) const { return st.segments.count(target) != 0; }
  void branchTo(uint32_t target);
  /// Pops an i32 condition and branches to `target` when it is non-zero.
  void branchIfTo(uint32_t target);
  void ret() { op(Op::Return); }
  /// Calls env.trap(ctx, addr, code); non-guest codes never return.
  void trap(TrapCode code, uint32_t addr);
  /// Emits an unimplemented trap and records the mnemonic.
  void unimplemented(std::string_view what);

  // --- Calls ---
  /// Direct call to the function (or import) at `target`, as BuilderContext::emit_function_call.
  void callGuest(uint32_t target);
  /// Pops an i32 guest address and calls it through env.lookup and the table.
  void callIndirect();
  void setLr(uint32_t value);

  // --- Memory ---
  bool mmioCheckDForm() const;
  bool mmioCheckXForm() const;
};

/// Dispatches one instruction to its wasm builder. False when no builder exists.
bool DispatchWasmInstruction(WasmBuilderContext& ctx);

}  // namespace rex::codegen::wasm
