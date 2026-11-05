/**
 * @file        codegen/wasm/wasm_writer.h
 * @brief       Chunk modules and manifest.json for the wasm backend (guest ABI v1)
 *
 * @copyright   Copyright (c) 2026 MCLA-Reborn contributors
 * @license     Not yet licensed: MCLA-Reborn decides before any release (D-009)
 */

#pragma once

#include <cstdint>
#include <set>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "wasm_backend.h"

namespace rex {
class Runtime;
}

namespace rex::codegen {
class CodegenContext;
class FunctionNode;
}  // namespace rex::codegen

namespace rex::codegen::wasm {

constexpr const char* kTranslatorVersion = "0.1.0";

struct TranslateOptions {
  /// Export every function by name (test builds, guest-abi.md "Test builds").
  bool exportFunctions = false;
  /// Guest address range per chunk in bytes; 0 puts every function in one chunk.
  uint32_t chunkRange = 0;
  /// Chunk file names: `<prefix>NNN.wasm`, or exactly `singleFile` when non-empty and
  /// everything fits in one chunk.
  std::string filePrefix = "chunk-";
  std::string singleFile;
};

struct ChunkModule {
  std::string file;
  std::vector<uint8_t> bytes;
  nlohmann::json functions = nlohmann::json::array();
  std::set<std::string> unimplemented;
};

struct Translation {
  std::vector<ChunkModule> chunks;
  uint32_t endSlot = 0;  ///< One past the last slot assigned
};

/// Display/export name of a function: xstart for the entry point, its name, or sub_XXXXXXXX.
std::string FunctionName(const FunctionNode& fn, const EmitContext& ctx);

/// Translates functions (sorted by address, no imports) into chunk modules. Table slots are
/// assigned in address order starting at `firstSlot`.
Translation TranslateFunctions(const EmitContext& ctx,
                               const std::vector<const FunctionNode*>& functions,
                               uint32_t firstSlot, ImportRegistry& imports,
                               const TranslateOptions& options);

/// manifest.json fields shared by every translation (without chunks and imports).
nlohmann::json ManifestBase(uint32_t slots);

/// The wasm backend's replacement for CodegenWriter: writes chunk-NNN.wasm and manifest.json.
class WasmWriter {
 public:
  WasmWriter(CodegenContext& ctx, Runtime* runtime = nullptr);
  bool write(bool force);

  const std::vector<std::string>& deletedFiles() const { return deletedFiles_; }
  const std::vector<std::string>& writtenFiles() const { return writtenFiles_; }
  const std::vector<std::string>& unchangedFiles() const { return unchangedFiles_; }

 private:
  CodegenContext& ctx_;
  Runtime* runtime_;
  std::vector<std::string> deletedFiles_;
  std::vector<std::string> writtenFiles_;
  std::vector<std::string> unchangedFiles_;
};

}  // namespace rex::codegen::wasm
