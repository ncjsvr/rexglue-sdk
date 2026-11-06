/**
 * @file        codegen/wasm/wasm_backend.h
 * @brief       Shared types of the wasm backend (guest ABI v1)
 *
 * @copyright   Copyright (c) 2026 MCLA-Reborn contributors
 * @license     Not yet licensed: MCLA-Reborn decides before any release (D-009)
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

#include "wasm_context_layout.h"
#include "wasm_encoder.h"

namespace rex::codegen {
struct EmitContext;
class FunctionNode;
}

namespace rex::codegen::wasm {

constexpr uint32_t kAbiVersion = 1;
constexpr uint64_t kGuestBase = 0x10000000ull;
constexpr uint64_t kPageSize = 0x10000ull;
/// The memory must cover GUEST_BASE + 4 GiB (guest-abi.md).
constexpr uint64_t kMinMemoryPages = (kGuestBase + 0x100000000ull) / kPageSize;
/// Upper bound declared on the imported memory (16 GiB, V8's memory64 limit).
constexpr uint64_t kMaxMemoryPages = 0x400000000ull / kPageSize;

/// Physical alias views (MCLA-Reborn D-080, T-050). The Xbox 360 maps its 512 MiB of physical
/// memory three times: 0xA0000000-0xBFFFFFFF (64 KiB pages), 0xC0000000-0xDFFFFFFF (16 MiB
/// pages) and 0xE0000000-0xFFFFFFFF (4 KiB pages, where guest 0xE0000000 is physical 0x1000, as
/// ReXGlue's PhysicalHeap defines it). A linear memory can't map a page twice, so the bytes of
/// physical address p live once, at guest address 0xA0000000 + p (the canonical range), and
/// accesses through the other two views are folded onto it. Below 0xC0000000 nothing changes.
constexpr uint32_t kAliasFoldStart = 0xC0000000u;
constexpr uint32_t kCanonicalPhysicalBase = 0xA0000000u;
/// The canonical guest address of `ga`: itself below 0xC0000000, else the 0xA0000000-view
/// address of the same physical byte (bit 29 tells the 0xE view, +0x1000, from the 0xC view).
constexpr uint32_t CanonicalGuestAddress(uint32_t ga) {
  return ga < kAliasFoldStart ? ga
                              : ((ga & 0x1FFFFFFFu) | kCanonicalPhysicalBase) + ((ga >> 17) & 0x1000u);
}
static_assert(CanonicalGuestAddress(0xC0001234u) == 0xA0001234u);
static_assert(CanonicalGuestAddress(0xE0000000u) == 0xA0001000u);
static_assert(CanonicalGuestAddress(0xE870F000u) == 0xA8710000u);
static_assert(CanonicalGuestAddress(0xBFFFFFFFu) == 0xBFFFFFFFu);

/// Counts of guest memory accesses by how the alias fold treated them, over every translation
/// in this process (for the translation summary; not part of the output).
struct AliasFoldStats {
  std::atomic<uint64_t> plain{0};     ///< provably below 0xC0000000: base + ga
  std::atomic<uint64_t> checked{0};   ///< folded at run time when at or above 0xC0000000
  std::atomic<uint64_t> constant{0};  ///< constant address folded at translation time
};
AliasFoldStats& GetAliasFoldStats();

/// Titles whose code may only ever go through the wasm backend (MCLA-Reborn D-006: no C++
/// recompile of the game may exist). `titleId` is 8 upper-case hex digits.
inline bool IsWasmOnlyTitle(const std::string& titleId) {
  return titleId == "545407F8";  // Midnight Club: Los Angeles Complete Edition
}

/// Codes passed to env.trap. Only kGuestTrap may return to the caller.
enum TrapCode : int32_t {
  kGuestTrap = 0,
  kUnknownTarget = 1,
  kUnimplemented = 2,
  kUnresolvedCall = 3,
  kBadJumpTable = 4,
  kSystemCall = 5,
};
/// Guest traps (code 0) carry the guest trap type in the high 16 bits of the code argument:
/// 0 for conditional tw/td/twi/tdi, the immediate of `twi 31, r0, imm` (ReXGlue's ppc_trap).
constexpr int32_t kTrapTypeShift = 16;
nlohmann::json TrapCodesJson();

/// Kernel/XAM imports referenced by the translated code; ids index the manifest list.
class ImportRegistry {
 public:
  struct Entry {
    uint32_t id;
    std::string library;
    uint32_t ordinal;
    std::string name;
    uint32_t thunk = 0;  ///< Guest address of the import's thunk, when known
  };
  uint32_t idFor(const std::string& importName, const EmitContext& ctx);
  /// Id of the import whose thunk starts at `thunkAddress` (an IMPORT function node), by
  /// its "library@ordinal" symbol; `fallbackName` when the binary has no such symbol.
  uint32_t idForThunk(uint32_t thunkAddress, const std::string& fallbackName,
                      const EmitContext& ctx);
  const std::vector<Entry>& entries() const { return entries_; }
  nlohmann::json toJson() const;

 private:
  std::unordered_map<std::string, uint32_t> byName_;
  std::unordered_map<uint32_t, std::string> symbolByThunk_;
  bool symbolsLoaded_ = false;
  std::vector<Entry> entries_;
};

/// Mid-asm hooks (MCLA-Reborn patches, TRANS-003) emitted by the translation; ids index the
/// manifest's `hooks` list and are what env.hook receives. Assigned in emission order (address
/// order within a translation), so native and Emscripten builds agree.
class HookRegistry {
 public:
  struct Entry {
    uint32_t id;
    uint32_t address;
    std::string name;
    std::vector<std::string> registers;
    bool afterInstruction = false;
    bool returnsBool = false;
  };
  uint32_t idFor(uint32_t address, const std::string& name,
                 const std::vector<std::string>& registers, bool afterInstruction,
                 bool returnsBool);
  const std::vector<Entry>& entries() const { return entries_; }
  nlohmann::json toJson() const;

 private:
  std::unordered_map<uint32_t, uint32_t> byAddress_;
  std::vector<Entry> entries_;
};

/// Per-chunk information the function emitter needs.
struct ModuleEnv {
  const ContextLayout& layout = ContextLayout::Get();
  uint32_t guestFnType = 0;
  uint32_t fnLookup = 0, fnKernel = 0, fnTrap = 0, fnMmioLoad32 = 0, fnMmioStore32 = 0,
           fnTimebase = 0;
  /// Optional imports, present only in chunks that need them (guest-abi.md, v1 additions).
  static constexpr uint32_t kNone = UINT32_MAX;
  uint32_t fnGlobalLock = kNone;  ///< env.global_lock(ctx, op) -> i32 (mfmsr/mtmsrd)
  uint32_t longjmpTag = kNone;    ///< env.longjmp tag (i32 buf, i32 value)
  uint32_t catchType = 0;         ///< type index of [] -> [i32 i32] (the catch block)
  uint32_t fnHook = kNone;        ///< env.hook(ctx, hook_id) -> i32 (mid-asm hooks, T-019)
  /// Module-internal helpers (not in the table, not exported).
  uint32_t fnLoad16 = 0, fnLoad32 = 0, fnLoad64 = 0, fnStore16 = 0, fnStore32 = 0, fnStore64 = 0,
           fnLog2f = 0;
  /// Guest address -> function index, for functions defined in this chunk.
  std::unordered_map<uint32_t, uint32_t> localFunctions;
  /// Guest address -> table slot, for every translated function of the binary.
  const std::unordered_map<uint32_t, uint32_t>* slots = nullptr;
  ImportRegistry* imports = nullptr;
  HookRegistry* hooks = nullptr;
};

/// Optional imports a function needs (pre-scan, so that imports precede the functions).
struct ChunkFeatures {
  bool globalLock = false;  ///< mfmsr / mtmsr / mtmsrd (unless skip_msr)
  bool longjmp = false;     ///< calls to setjmp_address / longjmp_address
  bool hook = false;        ///< a configured mid-asm hook inside the function
};
ChunkFeatures ScanFeatures(const EmitContext& ctx, const FunctionNode& fn);

/// Result of translating one guest function.
struct FunctionOutput {
  Code body;
  std::vector<LocalDecl> locals;
  /// Mnemonics this function traps on as unimplemented (empty when fully translated).
  std::set<std::string> unimplemented;
};

/// Module-internal helpers (wasm_helpers.cpp): their count, index assignment (from the first
/// index after the guest functions) and bodies, added in index order.
constexpr uint32_t kHelperCount = 7;
void AssignHelperIndices(ModuleEnv& env, uint32_t firstIndex);
void AddHelperFunctions(ModuleBuilder& mb, const ModuleEnv& env);

// Local slots of every translated function: (param $ctx i64), then these.
constexpr uint32_t kLocalCtx = 0;
constexpr uint32_t kLocalLabel = 1;
constexpr uint32_t kI0 = 2, kI1 = 3, kI2 = 4, kI3 = 5;  // i32 temporaries (kI3: store scratch)
constexpr uint32_t kL0 = 6, kL1 = 7, kL2 = 8, kL3 = 9;  // i64 temporaries (kL3: store scratch)
constexpr uint32_t kI4 = 10, kI5 = 11, kI6 = 12, kI7 = 13;  // i32 (kI7: v128/f64 store scratch)
constexpr uint32_t kL4 = 14, kL5 = 15;                      // i64
constexpr uint32_t kF0 = 16, kF1 = 17, kF2 = 18, kF3 = 19;  // f64 (kF3: store scratch)
constexpr uint32_t kS0 = 20, kS1 = 21;                      // f32
constexpr uint32_t kV0 = 22, kV1 = 23, kV2 = 24, kV3 = 25,  // v128 (kV7: store scratch)
    kV4 = 26, kV5 = 27, kV6 = 28, kV7 = 29;
/// First local after the fixed set; setjmp state and the context snapshot follow it.
constexpr uint32_t kFirstExtraLocal = 30;
/// Declarations matching the slots above.
inline std::vector<LocalDecl> FixedLocals() {
  return {{5, ValType::I32}, {4, ValType::I64}, {4, ValType::I32}, {2, ValType::I64},
          {4, ValType::F64}, {2, ValType::F32}, {8, ValType::V128}};
}

}  // namespace rex::codegen::wasm
