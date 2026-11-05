/**
 * @file        codegen/wasm/wasm_backend.h
 * @brief       Shared types of the wasm backend (guest ABI v1)
 *
 * @copyright   Copyright (c) 2026 MCLA-Reborn contributors
 * @license     Not yet licensed: MCLA-Reborn decides before any release (D-009)
 */

#pragma once

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
}

namespace rex::codegen::wasm {

constexpr uint32_t kAbiVersion = 1;
constexpr uint64_t kGuestBase = 0x10000000ull;
constexpr uint64_t kPageSize = 0x10000ull;
/// The memory must cover GUEST_BASE + 4 GiB (guest-abi.md).
constexpr uint64_t kMinMemoryPages = (kGuestBase + 0x100000000ull) / kPageSize;
/// Upper bound declared on the imported memory (16 GiB, V8's memory64 limit).
constexpr uint64_t kMaxMemoryPages = 0x400000000ull / kPageSize;

/// Codes passed to env.trap. Only kGuestTrap may return to the caller.
enum TrapCode : int32_t {
  kGuestTrap = 0,
  kUnknownTarget = 1,
  kUnimplemented = 2,
  kUnresolvedCall = 3,
  kBadJumpTable = 4,
};
nlohmann::json TrapCodesJson();

/// Kernel/XAM imports referenced by the translated code; ids index the manifest list.
class ImportRegistry {
 public:
  struct Entry {
    uint32_t id;
    std::string library;
    uint32_t ordinal;
    std::string name;
  };
  uint32_t idFor(const std::string& importName, const EmitContext& ctx);
  const std::vector<Entry>& entries() const { return entries_; }
  nlohmann::json toJson() const;

 private:
  std::unordered_map<std::string, uint32_t> byName_;
  std::vector<Entry> entries_;
};

/// Per-chunk information the function emitter needs.
struct ModuleEnv {
  const ContextLayout& layout = ContextLayout::Get();
  uint32_t guestFnType = 0;
  uint32_t fnLookup = 0, fnKernel = 0, fnTrap = 0, fnMmioLoad32 = 0, fnMmioStore32 = 0,
           fnTimebase = 0;
  /// Guest address -> function index, for functions defined in this chunk.
  std::unordered_map<uint32_t, uint32_t> localFunctions;
  /// Guest address -> table slot, for every translated function of the binary.
  const std::unordered_map<uint32_t, uint32_t>* slots = nullptr;
  ImportRegistry* imports = nullptr;
};

/// Result of translating one guest function.
struct FunctionOutput {
  Code body;
  std::vector<LocalDecl> locals;
  /// Mnemonics this function traps on as unimplemented (empty when fully translated).
  std::set<std::string> unimplemented;
};

// Local slots of every translated function: (param $ctx i64), then these.
constexpr uint32_t kLocalCtx = 0;
constexpr uint32_t kLocalLabel = 1;
constexpr uint32_t kI0 = 2, kI1 = 3, kI2 = 4, kI3 = 5;  // i32 temporaries (kI3: store scratch)
constexpr uint32_t kL0 = 6, kL1 = 7, kL2 = 8, kL3 = 9;  // i64 temporaries (kL3: store scratch)

}  // namespace rex::codegen::wasm
