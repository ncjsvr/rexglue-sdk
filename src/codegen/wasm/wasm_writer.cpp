/**
 * @file        codegen/wasm/wasm_writer.cpp
 * @brief       Chunk modules and manifest.json for the wasm backend (guest ABI v1)
 *
 * @copyright   Copyright (c) 2026 MCLA-Reborn contributors
 * @license     Not yet licensed: MCLA-Reborn decides before any release (D-009)
 */

#include "wasm_writer.h"

#include <algorithm>
#include <filesystem>
#include <string_view>
#include <unordered_map>

#include <fmt/format.h>

#include <rex/codegen/codegen_context.h>
#include <rex/codegen/function_graph.h>
#include <rex/logging.h>
#include <rex/runtime.h>

#include "../codegen_logging.h"
#include "../file_io.h"

namespace rex::codegen::wasm {

std::string FunctionName(const FunctionNode& fn, const EmitContext& ctx) {
  if (fn.base() == ctx.entryPoint)
    return "xstart";
  if (!fn.name().empty())
    return fn.name();
  return fmt::format("sub_{:08X}", fn.base());
}

nlohmann::json ManifestBase(uint32_t slots) {
  return {{"abi_version", kAbiVersion},
          {"translator_version", kTranslatorVersion},
          {"title_id", ""},
          {"xex_version", ""},
          {"guest_base", kGuestBase},
          {"slots", slots},
          {"memory_pages_min", kMinMemoryPages},
          {"memory_pages_max", kMaxMemoryPages},
          {"context", ContextLayout::Get().toJson()},
          {"trap_codes", TrapCodesJson()}};
}

namespace {

ChunkModule BuildChunk(const EmitContext& ctx, const std::vector<const FunctionNode*>& functions,
                       const std::unordered_map<uint32_t, uint32_t>& slots, uint32_t firstSlot,
                       ImportRegistry& imports, const TranslateOptions& options,
                       HookRegistry* hooks) {
  ModuleBuilder mb;
  ModuleEnv env;
  env.slots = &slots;
  env.imports = &imports;
  env.hooks = hooks;

  using V = ValType;
  env.guestFnType = mb.addType({{V::I64}, {}});
  const uint32_t tLookup = mb.addType({{V::I32}, {V::I32}});
  const uint32_t tKernel = mb.addType({{V::I64, V::I32}, {}});
  const uint32_t tTrap = mb.addType({{V::I64, V::I32, V::I32}, {}});
  const uint32_t tMmioLoad = mb.addType({{V::I64, V::I32}, {V::I32}});
  const uint32_t tTimebase = mb.addType({{}, {V::I64}});

  mb.importMemory("env", "memory", kMinMemoryPages, kMaxMemoryPages, /*shared=*/true,
                  /*memory64=*/true);
  mb.importTable("env", "table", firstSlot + static_cast<uint32_t>(functions.size()));
  env.fnLookup = mb.importFunction("env", "lookup", tLookup);
  env.fnKernel = mb.importFunction("env", "kernel", tKernel);
  env.fnTrap = mb.importFunction("env", "trap", tTrap);
  env.fnMmioLoad32 = mb.importFunction("env", "mmio_load32", tMmioLoad);
  env.fnMmioStore32 = mb.importFunction("env", "mmio_store32", tTrap);
  env.fnTimebase = mb.importFunction("env", "timebase", tTimebase);

  // Optional imports (guest-abi.md, v1 additions): only chunks that need them import them.
  ChunkFeatures features;
  for (const auto* fn : functions) {
    const ChunkFeatures f = ScanFeatures(ctx, *fn);
    features.globalLock |= f.globalLock;
    features.longjmp |= f.longjmp;
    features.hook |= f.hook;
  }
  if (features.globalLock)
    env.fnGlobalLock =
        mb.importFunction("env", "global_lock", mb.addType({{V::I64, V::I32}, {V::I32}}));
  if (features.longjmp) {
    const uint32_t tTag = mb.addType({{V::I32, V::I32}, {}});
    env.catchType = mb.addType({{}, {V::I32, V::I32}});
    env.longjmpTag = mb.importTag("env", "longjmp", tTag);
  }
  if (features.hook)
    env.fnHook = mb.importFunction("env", "hook", tMmioLoad);  // (i64 ctx, i32 id) -> i32

  const uint32_t firstIndex = mb.importedFunctionCount();
  for (size_t i = 0; i < functions.size(); ++i)
    env.localFunctions.emplace(functions[i]->base(), firstIndex + static_cast<uint32_t>(i));
  AssignHelperIndices(env, firstIndex + static_cast<uint32_t>(functions.size()));

  ChunkModule chunk;
  std::vector<uint32_t> elements;
  for (size_t i = 0; i < functions.size(); ++i) {
    const FunctionNode& fn = *functions[i];
    FunctionOutput out;
    fn.emitWasm(ctx, env, out);
    const std::string name = FunctionName(fn, ctx);
    const uint32_t index = mb.addFunction(env.guestFnType, std::move(out.locals),
                                          std::move(out.body), name);
    if (options.exportFunctions)
      mb.exportFunction(name, index);
    elements.push_back(index);

    nlohmann::json entry = {{"guest_addr", fn.base()}, {"slot", slots.at(fn.base())},
                            {"name", name}};
    if (!out.unimplemented.empty()) {
      entry["unimplemented"] =
          std::vector<std::string>(out.unimplemented.begin(), out.unimplemented.end());
      chunk.unimplemented.insert(out.unimplemented.begin(), out.unimplemented.end());
    }
    chunk.functions.push_back(std::move(entry));
  }
  AddHelperFunctions(mb, env);
  if (!functions.empty())
    mb.addElementSegment(slots.at(functions.front()->base()), std::move(elements));
  chunk.bytes = mb.finish();
  return chunk;
}

}  // namespace

Translation TranslateFunctions(const EmitContext& ctx,
                               const std::vector<const FunctionNode*>& functions,
                               uint32_t firstSlot, ImportRegistry& imports,
                               const TranslateOptions& options, HookRegistry* hooks) {
  std::unordered_map<uint32_t, uint32_t> slots;
  uint32_t slot = firstSlot;
  for (const auto* fn : functions)
    slots.emplace(fn->base(), slot++);

  // Split by guest address range (ADR-0010); one chunk when chunkRange is 0.
  std::vector<std::vector<const FunctionNode*>> groups;
  uint32_t chunkStart = 0;
  for (const auto* fn : functions) {
    if (groups.empty() ||
        (options.chunkRange != 0 && fn->base() - chunkStart >= options.chunkRange)) {
      groups.emplace_back();
      chunkStart = fn->base();
    }
    groups.back().push_back(fn);
  }

  Translation result;
  result.endSlot = slot;
  for (size_t i = 0; i < groups.size(); ++i) {
    ChunkModule chunk = BuildChunk(ctx, groups[i], slots, firstSlot, imports, options, hooks);
    chunk.file = (groups.size() == 1 && !options.singleFile.empty())
                     ? options.singleFile
                     : fmt::format("{}{:03}.wasm", options.filePrefix, i);
    result.chunks.push_back(std::move(chunk));
  }
  return result;
}

WasmWriter::WasmWriter(CodegenContext& ctx, Runtime* runtime) : ctx_(ctx), runtime_(runtime) {}

bool WasmWriter::write(bool force) {
  deletedFiles_.clear();
  writtenFiles_.clear();
  unchangedFiles_.clear();

  if (ctx_.errors.HasErrors() && !force) {
    REXCODEGEN_ERROR("Code generation blocked: {} validation errors. Use --force to override.",
                     ctx_.errors.Count());
    return false;
  }

  const auto& config = ctx_.Config();
  const std::filesystem::path outputPath = ctx_.configDir() / config.outDirectoryPath;
  std::filesystem::create_directories(outputPath);

  std::vector<const FunctionNode*> functions;
  for (const auto& [addr, node] : ctx_.graph.functions()) {
    if (node->authority() != FunctionAuthority::IMPORT)
      functions.push_back(node.get());
  }
  std::sort(functions.begin(), functions.end(),
            [](const auto* a, const auto* b) { return a->base() < b->base(); });

  EmitContext emitCtx{ctx_.binary(), config, ctx_.graph,
                      static_cast<uint32_t>(ctx_.analysisState().entryPoint), nullptr};
  emitCtx.resolver = runtime_ ? runtime_->export_resolver() : ctx_.resolver();

  // MCLA-Reborn patches (TRANS-003): hooks are addresses in one exact build of one title.
  if (!config.midAsmHooks.empty()) {
    if (config.patchTitleId.empty() || config.patchXexVersion.empty()) {
      REXCODEGEN_ERROR("[[midasm_hook]] entries need [patches] title_id and xex_version");
      return false;
    }
    if (!titleId_.empty() &&
        (titleId_ != config.patchTitleId || xexVersion_ != config.patchXexVersion)) {
      REXCODEGEN_ERROR("The config's patches are for title {} version {}, but the XEX is title {} "
                       "version {}: refusing to apply them",
                       config.patchTitleId, config.patchXexVersion, titleId_, xexVersion_);
      return false;
    }
  }

  ImportRegistry imports;
  HookRegistry hooks;
  TranslateOptions options;
  options.chunkRange = config.wasmChunkRange;
  auto translation = TranslateFunctions(emitCtx, functions, 0, imports, options, &hooks);

  nlohmann::json manifest = ManifestBase(translation.endSlot);
  manifest["title_id"] = titleId_;
  manifest["xex_version"] = xexVersion_;
  manifest["chunks"] = nlohmann::json::array();
  std::set<std::string> produced;
  size_t unimplementedFunctions = 0;
  for (const auto& chunk : translation.chunks) {
    for (const auto& fn : chunk.functions)
      unimplementedFunctions += fn.contains("unimplemented") ? 1 : 0;
    manifest["chunks"].push_back({{"file", chunk.file}, {"functions", chunk.functions}});
    produced.insert(chunk.file);
  }
  manifest["imports"] = imports.toJson();
  if (!hooks.entries().empty()) {
    manifest["patches"] = {{"title_id", config.patchTitleId},
                           {"xex_version", config.patchXexVersion}};
    manifest["hooks"] = hooks.toJson();
  }

  auto record = [&](const std::string& name, std::string_view content) {
    switch (WriteIfChanged(outputPath / name, content)) {
      case WriteOutcome::Written:
        writtenFiles_.push_back(name);
        return true;
      case WriteOutcome::Unchanged:
        unchangedFiles_.push_back(name);
        return true;
      default:
        REXCODEGEN_ERROR("Failed to write {}", (outputPath / name).string());
        return false;
    }
  };

  for (const auto& chunk : translation.chunks) {
    std::string_view bytes(reinterpret_cast<const char*>(chunk.bytes.data()), chunk.bytes.size());
    if (!record(chunk.file, bytes))
      return false;
  }
  if (!record("manifest.json", manifest.dump(2) + "\n"))
    return false;

  // Sweep chunk files left over from a previous, larger translation.
  std::error_code ec;
  for (const auto& entry : std::filesystem::directory_iterator(outputPath, ec)) {
    const std::string name = entry.path().filename().string();
    if (name.starts_with(options.filePrefix) && name.ends_with(".wasm") && !produced.count(name)) {
      std::filesystem::remove(entry.path(), ec);
      deletedFiles_.push_back(name);
    }
  }

  REXLOG_INFO("wasm backend: {} functions in {} chunk(s), {} with unimplemented instructions",
              functions.size(), translation.chunks.size(), unimplementedFunctions);
  if (!config.midAsmHooks.empty())
    REXLOG_INFO("wasm backend: {} of {} mid-asm hooks emitted (patches for {} v{})",
                hooks.entries().size(), config.midAsmHooks.size(), config.patchTitleId,
                config.patchXexVersion);
  const auto& folds = GetAliasFoldStats();
  REXLOG_INFO("wasm backend: alias fold ({}): {} accesses checked at run time, {} constant "
              "addresses folded, {} provably below 0xC0000000",
              config.wasmAliasFold, folds.checked.load(), folds.constant.load(),
              folds.plain.load());
  return true;
}

}  // namespace rex::codegen::wasm
