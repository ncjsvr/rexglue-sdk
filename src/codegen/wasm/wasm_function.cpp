/**
 * @file        codegen/wasm/wasm_function.cpp
 * @brief       FunctionNode::emitWasm, the wasm twin of FunctionNode::emitCpp
 *
 * Body lowering (guest ABI v1): a `loop` around a `br_table` on a label local. Every basic
 * block start (branch target, jump-table target, block base) is one case; falling off a case
 * runs into the next, a branch sets the label and continues the loop, blr returns.
 *
 * Functions that call the configured setjmp_address wrap that loop in a try_table catching
 * env.longjmp (ReXGlue's ppc_setjmp/ppc_longjmp): the catch restores the context snapshot
 * taken at the setjmp, sets r3 to the longjmp value and re-enters the loop at the case after
 * the setjmp call.
 *
 * @copyright   Copyright (c) 2026 MCLA-Reborn contributors
 * @license     Not yet licensed: MCLA-Reborn decides before any release (D-009)
 */

#include <cassert>
#include <set>

#include <fmt/format.h>

#include <rex/codegen/binary_view.h>
#include <rex/codegen/config.h>
#include <rex/codegen/function_graph.h>
#include <rex/codegen/function_scanner.h>
#include <rex/logging.h>
#include <rex/memory/utils.h>
#include <rex/system/export_resolver.h>

#include "../codegen_logging.h"
#include "../ppc/disasm.h"
#include "wasm_builders.h"

#include <dis-asm.h>

namespace rex::codegen {

using rex::memory::load_and_swap;

namespace wasm {

nlohmann::json TrapCodesJson() {
  return {{"guest_trap", kGuestTrap},
          {"unknown_target", kUnknownTarget},
          {"unimplemented", kUnimplemented},
          {"unresolved_call", kUnresolvedCall},
          {"bad_jump_table", kBadJumpTable},
          {"system_call", kSystemCall}};
}

uint32_t ImportRegistry::idFor(const std::string& importName, const EmitContext& ctx) {
  if (auto it = byName_.find(importName); it != byName_.end())
    return it->second;
  Entry e{static_cast<uint32_t>(entries_.size()), "", 0, importName};
  // "library@ordinal" names carry the ordinal; resolve it to the export name when possible.
  if (auto at = importName.find('@'); at != std::string::npos) {
    e.library = importName.substr(0, at);
    e.ordinal = static_cast<uint32_t>(std::stoul(importName.substr(at + 1)));
    e.name.clear();
    if (ctx.resolver) {
      auto* exp = ctx.resolver->GetExportByOrdinal(e.library + ".xex", static_cast<uint16_t>(e.ordinal));
      if (!exp)
        exp = ctx.resolver->GetExportByOrdinal(e.library, static_cast<uint16_t>(e.ordinal));
      if (exp)
        e.name = exp->name;
    }
  }
  byName_.emplace(importName, e.id);
  entries_.push_back(e);
  return e.id;
}

nlohmann::json ImportRegistry::toJson() const {
  nlohmann::json arr = nlohmann::json::array();
  for (const auto& e : entries_) {
    arr.push_back({{"id", e.id}, {"library", e.library}, {"ordinal", e.ordinal}, {"name", e.name}});
  }
  return arr;
}

namespace {

constexpr uint32_t kBctr = 0x4E800420;
constexpr uint32_t kMtctrMask = 0xFC1FFFFF;
// mtspr ctr, rS. emitCpp compares against 0x7C0003A6 (spr 0), which never matches mtctr, so its
// late detection does not fire; the wasm backend uses the real encoding (spr 9).
constexpr uint32_t kMtctr = 0x7C0903A6;
constexpr uint32_t kNop = 0x60000000;

uint32_t branchTarget(uint32_t addr, uint32_t word) {
  const uint32_t opcd = word >> 26;
  int32_t disp;
  if (opcd == 18)
    disp = static_cast<int32_t>(((word & 0x03FFFFFC) ^ 0x02000000) - 0x02000000);
  else
    disp = static_cast<int16_t>(word & 0xFFFC);
  return (word & 2) ? static_cast<uint32_t>(disp) : addr + disp;
}

/// The mtctr .. bctr pattern emitCpp looks for before late jump-table detection.
bool looksLikeSwitch(const uint32_t* data, uint32_t addr, uint32_t fnBase) {
  for (uint32_t i = 1; i <= 3; ++i) {
    if (addr < fnBase + 4 * i)
      return false;
    const uint32_t prev = load_and_swap<uint32_t>(data - i);
    if ((prev & kMtctrMask) == kMtctr) {
      for (uint32_t j = 1; j < i; ++j) {
        if (load_and_swap<uint32_t>(data - j) != kNop)
          return false;
      }
      return true;
    }
    if (prev != kNop)
      return false;
  }
  return false;
}

}  // namespace
}  // namespace wasm

namespace wasm {

ChunkFeatures ScanFeatures(const EmitContext& ctx, const FunctionNode& fn) {
  ChunkFeatures f;
  const auto& cfg = ctx.config;
  for (const auto& block : fn.blocks()) {
    const auto* data = reinterpret_cast<const uint32_t*>(ctx.binary.translate(block.base));
    if (!data)
      continue;
    for (uint32_t addr = block.base; addr < block.end(); addr += 4, ++data) {
      const uint32_t word = load_and_swap<uint32_t>(data);
      const uint32_t opcd = word >> 26;
      if (opcd == 31 && !cfg.skipMsr) {
        const uint32_t xo = (word >> 1) & 0x3FF;
        if (xo == 83 || xo == 146 || xo == 178)  // mfmsr, mtmsr, mtmsrd
          f.globalLock = true;
      }
      if (opcd == 16 || opcd == 18) {
        const uint32_t target = branchTarget(addr, word);
        if (target != 0 && (target == cfg.setJmpAddress || target == cfg.longJmpAddress))
          f.longjmp = true;
      }
    }
  }
  return f;
}

}  // namespace wasm

bool FunctionNode::emitWasm(const EmitContext& ctx, const wasm::ModuleEnv& env,
                            wasm::FunctionOutput& out) const {
  using namespace wasm;
  out.locals = FixedLocals();
  if (authority() == FunctionAuthority::IMPORT)
    return false;
  if (blocks().empty()) {
    REXCODEGEN_WARN("Function 0x{:08X} has no blocks - generating stub", base());
    return true;
  }

  wasm::FunctionState st;
  st.unimplemented = &out.unimplemented;

  // --- Pass 1: the instruction addresses and the block starts (cases) ---
  std::set<uint32_t> labels{base()};
  std::set<uint32_t> visited;
  for (const auto& block : blocks()) {
    const auto* data = reinterpret_cast<const uint32_t*>(ctx.binary.translate(block.base));
    if (!data)
      continue;
    labels.insert(block.base);
    for (uint32_t addr = block.base; addr < block.end(); addr += 4, ++data) {
      visited.insert(addr);
      const uint32_t word = load_and_swap<uint32_t>(data);
      const uint32_t opcd = word >> 26;
      if (opcd == 16 || opcd == 18) {
        // Linking branches inside the function are the PIC pattern (bl $+4; mflr).
        const uint32_t target = branchTarget(addr, word);
        if (!(word & 1) || (target >= base() && target < end()))
          labels.insert(target);
        // bl setjmp: the next instruction is where a longjmp resumes.
        if (opcd == 18 && (word & 1) && target != 0 && target == ctx.config.setJmpAddress &&
            env.longjmpTag != ModuleEnv::kNone) {
          st.setjmpSites.emplace(addr, addr + 4);
          labels.insert(addr + 4);
        }
      }
      if (auto st_it = ctx.config.switchTables.find(addr); st_it != ctx.config.switchTables.end()) {
        labels.insert(st_it->second.targets.begin(), st_it->second.targets.end());
      } else if (word == kBctr && looksLikeSwitch(data, addr, base())) {
        FunctionScanner scanner(ctx.binary);
        if (auto jt = scanner.detect_jump_table(addr)) {
          labels.insert(jt->targets.begin(), jt->targets.end());
          st.lateJumpTables.emplace(addr, std::move(*jt));
        }
      }
    }
  }
  for (const auto& jt : jumpTables())
    labels.insert(jt.targets.begin(), jt.targets.end());

  uint32_t index = 0;
  for (uint32_t addr : visited) {
    if (labels.count(addr))
      st.segments.emplace(addr, index++);
  }
  const uint32_t caseCount = index;
  if (caseCount == 0)
    return true;

  // --- setjmp state: buffer, resume case, caught buffer and value, context snapshot ---
  const bool hasSetjmp = !st.setjmpSites.empty();
  uint32_t localCaughtBuf = 0, localCaughtValue = 0;
  if (hasSetjmp) {
    st.localJmpBuf = kFirstExtraLocal;
    st.localJmpResume = kFirstExtraLocal + 1;
    localCaughtBuf = kFirstExtraLocal + 2;
    localCaughtValue = kFirstExtraLocal + 3;
    st.localSnapshot = kFirstExtraLocal + 4;
    st.snapshotCount = (env.layout.size + 15) / 16;
    out.locals.push_back({4, ValType::I32});
    out.locals.push_back({st.snapshotCount, ValType::V128});
  }

  // --- Dispatch prologue ---
  Code& c = out.body;
  if (auto it = st.segments.find(base()); it != st.segments.end() && it->second != 0) {
    c.i32Const(static_cast<int32_t>(it->second));
    c.localSet(kLocalLabel);
  }
  if (hasSetjmp) {
    c.loop();                         // restart after a caught longjmp
    c.blockTyped(env.catchType);      // [] -> [i32 buf, i32 value]
    c.tryTableCatch(env.longjmpTag, 0);
  }
  c.loop();
  for (uint32_t i = 0; i < caseCount; ++i)
    c.block();
  c.block();
  c.localGet(kLocalLabel);
  std::vector<uint32_t> depths(caseCount);
  for (uint32_t i = 0; i < caseCount; ++i)
    depths[i] = i + 1;
  c.brTable(depths, 0);
  c.end();
  c.localGet(kLocalCtx);
  c.i32Const(static_cast<int32_t>(base()));
  c.i32Const(kBadJumpTable);
  c.call(env.fnTrap);
  c.op(Op::Unreachable);
  st.depth = caseCount;

  // --- Pass 2: instructions ---
  ppc_insn insn;
  for (const auto& block : blocks()) {
    const auto* data = reinterpret_cast<const uint32_t*>(ctx.binary.translate(block.base));
    if (!data) {
      REXCODEGEN_WARN("Block 0x{:08X} in function 0x{:08X} has no mapped data - skipping",
                      block.base, base());
      continue;
    }
    for (uint32_t addr = block.base; addr < block.end(); addr += 4, ++data) {
      if (st.segments.count(addr)) {
        c.end();  // the next case starts here
        --st.depth;
      }

      const JumpTable* activeJt = nullptr;
      if (auto it = ctx.config.switchTables.find(addr); it != ctx.config.switchTables.end())
        activeJt = &it->second;
      else if (auto late = st.lateJumpTables.find(addr); late != st.lateJumpTables.end())
        activeJt = &late->second;

      ppc::Disassemble(data, 4, addr, insn);
      if (insn.opcode == nullptr)
        continue;  // emitCpp emits only a comment for undecodable words

      const uint32_t word = load_and_swap<uint32_t>(data);
      WasmBuilderContext w{c, ctx, env, *this, insn, addr, word, data, st, activeJt};
      if (ctx.config.midAsmHooks.count(addr))
        w.unimplemented("mid-asm hook");
      if (!DispatchWasmInstruction(w))
        w.unimplemented(insn.opcode->name);
    }
  }

  assert(st.depth == 0 && "unbalanced case blocks");
  c.end();  // loop: falling off the last case returns

  if (hasSetjmp) {
    c.end();  // try_table
    c.op(Op::Return);
    c.end();  // catch block: stack = buf, value
    c.localSet(localCaughtValue);
    c.localSet(localCaughtBuf);
    // A setjmp in this frame ran on this buffer: ctx = env; r3 = value ? value : 1.
    c.localGet(st.localJmpResume);
    c.i32Const(0);
    c.op(Op::I32Ne);
    c.localGet(localCaughtBuf);
    c.localGet(st.localJmpBuf);
    c.op(Op::I32Eq);
    c.op(Op::I32And);
    c.if_();
    for (uint32_t i = 0; i < st.snapshotCount; ++i) {
      c.localGet(kLocalCtx);
      c.localGet(st.localSnapshot + i);
      c.simdMem(Simd::V128Store, 4, 16 * i);
    }
    c.localGet(kLocalCtx);
    c.localGet(localCaughtValue);
    c.i32Const(1);
    c.localGet(localCaughtValue);
    c.op(Op::Select);
    c.op(Op::I64ExtendI32S);
    c.mem(Op::I64Store, 3, env.layout.r[3]);
    c.localGet(st.localJmpResume);
    c.i32Const(1);
    c.op(Op::I32Sub);
    c.localSet(kLocalLabel);
    c.br(1);  // restart loop
    c.end();
    // Not ours: keep unwinding.
    c.localGet(localCaughtBuf);
    c.localGet(localCaughtValue);
    c.throw_(env.longjmpTag);
    c.end();  // restart loop
  }
  return true;
}

}  // namespace rex::codegen
