/**
 * @file        translator/main.cpp
 * @brief       rexglue-translate: XEX (or disc image) to wasm chunk modules
 *
 * @copyright   Copyright (c) 2026 MCLA-Reborn contributors
 * @license     Not yet licensed: MCLA-Reborn decides before any release (D-009)
 *
 * The translator as one small program, built with Emscripten for Node and (later) the browser:
 * reads default.xex from a disc image or an XEX file, loads it as ReXGlue does (XexModule into
 * guest memory, export names from the kernel tables), runs the codegen analysis and writes
 * chunk modules plus manifest.json with the wasm backend. It has no C++ backend.
 *
 *   rexglue-translate --config <manifest.toml> (--iso <image> | --xex <file>) [--out <dir>]
 *                     [--force] [--log-level <level>] [--progress]
 *                     [--patch-file <path> --patch <name> ... --patch-xex-sha256 <hex>]
 *   rexglue-translate --tests <bin-dir> --asm <asm-dir> --out <dir>
 *
 * The second form translates the assembled PowerPC fixture corpus exactly as
 * `rexglue recompile-tests --backend wasm` does, so the two builds can be compared.
 *
 * The TOML is a ReXGlue manifest ([project], [entrypoint] with backend = "wasm" and the
 * analysis entries); its file_path is used only when neither --iso nor --xex is given, and
 * --out overrides out_directory_path.
 *
 * --progress prints one line per step, "MCLA-TRANSLATE {"step":"<name>","t":<seconds>}", with
 * the steps read, load, the analysis phases (Register, Scan, Discover, GapFill, Merge,
 * Validate), write and done. The browser worker (T-023) shows them as progress.
 */

#include <algorithm>
#include <chrono>
#include <exception>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <fmt/format.h>
#include <toml++/toml.hpp>
#include <crypto/sha256.h>

#include <rex/codegen/analyze.h>
#include <rex/codegen/binary_view.h>
#include <rex/codegen/codegen_context.h>
#include <rex/codegen/manifest.h>
#include <rex/codegen/progress_reporter.h>
#include <rex/logging.h>
#include <rex/memory.h>
#include <rex/system/export_resolver.h>
#include <rex/system/function_dispatcher.h>
#include <rex/system/xex_module.h>
#include <rex/version.h>

#include "../codegen/wasm/wasm_writer.h"
#include "../rexglue/commands/test_recompiler.h"
#include "../rexglue/ui/ui.h"
#include "kernel_exports.h"
#include "xdvdfs.h"

namespace fs = std::filesystem;

namespace {

using Clock = std::chrono::steady_clock;

double Seconds(Clock::time_point from, Clock::time_point to) {
  return std::chrono::duration<double>(to - from).count();
}

void Usage() {
  std::fprintf(stderr,
               "usage: rexglue-translate --config <manifest.toml> (--iso <image> | --xex <file>)\n"
               "                         [--out <dir>] [--force] [--log-level <level>] [--progress]\n"
               "                         [--patch-file <path> --patch <name> ... --patch-xex-sha256 <hex>]\n"
               "       rexglue-translate --tests <bin-dir> --asm <asm-dir> --out <dir>\n");
}

// Under Emscripten with NODERAWFS, host paths go to Node's fs unchanged, so a Windows path
// ("C:/...") is absolute to Node but not to std::filesystem; never prefix such a path.
bool IsHostAbsolute(const std::string& p) {
  return fs::path(p).is_absolute() || (p.size() >= 2 && p[1] == ':') ||
         (!p.empty() && (p[0] == '/' || p[0] == '\\'));
}

fs::path Resolve(const fs::path& base, const std::string& p) {
  return IsHostAbsolute(p) || base.empty() ? fs::path(p) : base / p;
}

bool ReadFile(const fs::path& path, std::vector<uint8_t>& out) {
  std::ifstream in(path, std::ios::binary);
  if (!in)
    return false;
  in.seekg(0, std::ios::end);
  out.resize(static_cast<size_t>(in.tellg()));
  in.seekg(0);
  return static_cast<bool>(in.read(reinterpret_cast<char*>(out.data()), out.size()));
}

bool ApplyCanaryPatches(const std::string& file, const std::vector<std::string>& selected,
                        std::string_view title_id, const rex::runtime::XexModule& module,
                        rex::memory::Memory& memory) {
  auto document = toml::parse_file(file);
  if (title_id.empty() || document["title_id"].value_or(std::string_view{}) != title_id) {
    REXLOG_ERROR("Patch file does not match title {}", title_id);
    return false;
  }
  const auto* patches = document["patch"].as_array();
  if (!patches) {
    REXLOG_ERROR("Patch file has no patch entries");
    return false;
  }

  // Validate every requested byte before modifying the in-memory image.
  std::map<uint32_t, uint8_t> bytes;
  for (const auto& name : selected) {
    const toml::table* match = nullptr;
    for (const auto& node : *patches) {
      const auto* entry = node.as_table();
      if (!entry || (*entry)["name"].value_or(std::string_view{}) != name) continue;
      if (match) {
        REXLOG_ERROR("Ambiguous patch name: {}", name);
        return false;
      }
      match = entry;
    }
    if (!match) {
      REXLOG_ERROR("Patch not found: {}", name);
      return false;
    }
    bool has_writes = false;
    for (const auto& [key, node] : *match) {
      const auto type = key.str();
      if (type == "name" || type == "author" || type == "desc" || type == "is_enabled") continue;
      const uint32_t width = type == "be8" ? 1 : type == "be16" ? 2 : type == "be32" ? 4 : 0;
      const auto* writes = node.as_array();
      if (!width || !writes) {
        REXLOG_ERROR("Unsupported write type {} in patch {}", type, name);
        return false;
      }
      for (const auto& write : *writes) {
        const auto* entry = write.as_table();
        if (!entry) {
          REXLOG_ERROR("Invalid {} write in patch {}", type, name);
          return false;
        }
        const auto address = (*entry)["address"].value<uint32_t>();
        const auto value = (*entry)["value"].value<uint32_t>();
        if (!address || !value || *address % width || uint64_t(*address) + width > (uint64_t(1) << 32) ||
            uint64_t(*value) >= (uint64_t(1) << (width * 8))) {
          REXLOG_ERROR("Invalid {} write in patch {}", type, name);
          return false;
        }
        const auto& sections = module.binary_sections();
        const bool inside_code = std::any_of(sections.begin(), sections.end(), [&](const auto& s) {
          return s.executable && s.host_data && *address >= s.virtual_address &&
                 uint64_t(*address) + width <= uint64_t(s.virtual_address) + s.virtual_size;
        });
        if (!inside_code) {
          REXLOG_ERROR("Patch {} writes outside executable sections at {:08X}", name, *address);
          return false;
        }
        for (uint32_t i = 0; i < width; ++i) {
          if (!bytes.emplace(*address + i, uint8_t(*value >> ((width - 1 - i) * 8))).second) {
            REXLOG_ERROR("Overlapping patch writes at {:08X}", *address + i);
            return false;
          }
        }
        has_writes = true;
      }
    }
    if (!has_writes) {
      REXLOG_ERROR("Patch {} contains no executable writes", name);
      return false;
    }
  }
  for (const auto& [address, byte] : bytes) *memory.TranslateVirtual(address) = byte;
  REXLOG_INFO("Applied {} local patches ({} bytes) to the verified XEX", selected.size(),
              bytes.size());
  return true;
}

// --progress: one machine-readable line per step, flushed so a host sees it at once.
class StepPrinter : public rex::codegen::ProgressReporter {
 public:
  explicit StepPrinter(Clock::time_point start) : start_(start) {}
  void step(std::string_view name) const {
    std::printf("MCLA-TRANSLATE {\"step\":\"%.*s\",\"t\":%.3f}\n", int(name.size()),
                name.data(), Seconds(start_, Clock::now()));
    std::fflush(stdout);
  }
  void moduleStarted(std::string_view, std::size_t, std::size_t) override {}
  void phaseChanged(std::string_view name) override { step(name); }
  void moduleFinished(std::chrono::milliseconds) override {}
  void projectPhaseStarted(std::string_view) override {}
  void projectPhaseFinished() override {}

 private:
  Clock::time_point start_;
};

}  // namespace

int Run(int argc, char** argv) {
  const auto tStart = Clock::now();
  std::string configArg, isoArg, xexArg, outArg, testsArg, asmArg, logLevel = "info";
  std::string patchFile, patchXexSha256;
  std::vector<std::string> patches;
  bool force = false, progress = false;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    auto value = [&](std::string& dst) {
      if (i + 1 >= argc)
        return false;
      dst = argv[++i];
      return true;
    };
    bool ok = true;
    if (a == "--config")
      ok = value(configArg);
    else if (a == "--iso")
      ok = value(isoArg);
    else if (a == "--xex")
      ok = value(xexArg);
    else if (a == "--out")
      ok = value(outArg);
    else if (a == "--patch-file")
      ok = value(patchFile);
    else if (a == "--patch-xex-sha256")
      ok = value(patchXexSha256);
    else if (a == "--patch")
      ok = value(patches.emplace_back());
    else if (a == "--tests")
      ok = value(testsArg);
    else if (a == "--asm")
      ok = value(asmArg);
    else if (a == "--log-level")
      ok = value(logLevel);
    else if (a == "--force")
      force = true;
    else if (a == "--progress")
      progress = true;
    else if (a == "--version") {
      std::printf("rexglue-translate %s (ReXGlue %s, translator %s)\n", REXGLUE_VERSION_STRING,
                  REXGLUE_VERSION_STRING, rex::codegen::wasm::kTranslatorVersion);
      return 0;
    } else
      ok = false;
    if (!ok) {
      Usage();
      return 2;
    }
  }
  const bool testsMode = !testsArg.empty();
  if (testsMode ? (asmArg.empty() || outArg.empty())
                : (configArg.empty() || (!isoArg.empty() && !xexArg.empty()))) {
    Usage();
    return 2;
  }
  const bool patchMode = !patches.empty();
  if (patchMode != !patchFile.empty() || patchMode != !patchXexSha256.empty() ||
      (patchMode && (testsMode || outArg.empty() || patchXexSha256.size() != 64))) {
    Usage();
    return 2;
  }

  auto logConfig = rex::BuildLogConfig(nullptr, logLevel, {});
  logConfig.log_to_console = true;
  rex::InitLogging(logConfig);

  if (testsMode) {
    rexglue::ui::Init({.tty = false, .color = false});
    const bool ok = rexglue::cli::TranslateTestsWasm(testsArg, asmArg, outArg);
    rexglue::ui::Shutdown();
    std::printf("rexglue-translate: fixtures %s in %.2f s\n", ok ? "translated" : "FAILED",
                Seconds(tStart, Clock::now()));
    rex::ShutdownLogging();
    return ok ? 0 : 1;
  }

  // Configuration: a ReXGlue manifest; only the entrypoint is translated.
  const fs::path configPath = configArg;
  auto manifest = rex::codegen::ManifestConfig::Load(configPath);
  if (!manifest) {
    REXLOG_ERROR("Cannot load {}", configPath.string());
    return 1;
  }
  if (!manifest->modules.empty())
    REXLOG_WARN("[[modules]] are ignored: only the entrypoint is translated");
  rex::codegen::RecompilerConfig config = std::move(manifest->entrypoint.recompiler);
  if (!config.backend.empty() && config.backend != "wasm") {
    // This program has only the wasm backend; a config asking for another is a mistake.
    REXLOG_ERROR("backend = \"{}\" in {}: rexglue-translate writes wasm only", config.backend,
                 configPath.string());
    return 1;
  }
  config.backend = "wasm";
  // Paths in the TOML are relative to it; --out is used as given.
  const fs::path configDir = manifest->manifestDir;
  config.outDirectoryPath =
      outArg.empty() ? Resolve(configDir, config.outDirectoryPath).string() : outArg;

  StepPrinter steps(tStart);
  auto step = [&](std::string_view name) {
    if (progress)
      steps.step(name);
  };

  // Input bytes.
  step("read");
  std::vector<uint8_t> xexBytes;
  std::string source;
  if (!isoArg.empty()) {
    rex::translator::DiscFile file;
    std::string error;
    if (!rex::translator::ReadDiscFile(isoArg, "default.xex", file, error)) {
      REXLOG_ERROR("{}", error);
      return 1;
    }
    xexBytes = std::move(file.bytes);
    source = fmt::format("{} (default.xex, partition at {:#x})", isoArg, file.partitionBase);
  } else {
    const fs::path xexPath = xexArg.empty() ? Resolve(configDir, config.filePath) : fs::path(xexArg);
    if (!ReadFile(xexPath, xexBytes)) {
      REXLOG_ERROR("Cannot read {}", xexPath.string());
      return 1;
    }
    source = xexPath.string();
  }
  if (patchMode && sha256::SHA256{}(xexBytes.data(), xexBytes.size()) != patchXexSha256) {
    REXLOG_ERROR("XEX SHA-256 does not match the required patch target");
    return 1;
  }
  const auto tRead = Clock::now();
  REXLOG_INFO("Read {} bytes from {}", xexBytes.size(), source);

  // Load as ReXGlue does: guest memory, export names, XexModule.
  step("load");
  rex::memory::Memory memory;
  if (!memory.Initialize()) {
    REXLOG_ERROR("Guest memory initialisation failed");
    return 1;
  }
  rex::runtime::ExportResolver resolver;
  rex::translator::RegisterKernelExports(resolver);
  rex::runtime::FunctionDispatcher dispatcher(&memory, &resolver);
  rex::runtime::XexModule xex(&dispatcher, nullptr);
  if (!xex.Load("default.xex", "game:\\default.xex", xexBytes.data(), xexBytes.size()) ||
      !xex.LoadContinue()) {
    REXLOG_ERROR("Cannot load the XEX");
    return 1;
  }
  xexBytes.clear();
  xexBytes.shrink_to_fit();

  std::string titleId, xexVersion;
  if (auto* exec = xex.opt_execution_info()) {
    titleId = fmt::format("{:08X}", static_cast<uint32_t>(exec->title_id));
    auto v = exec->version();
    xexVersion = fmt::format("{}.{}.{}.{}", uint32_t(v.major), uint32_t(v.minor),
                             uint32_t(v.build), uint32_t(v.qfe));
  }
  REXLOG_INFO("Title {} version {}, image {:#x} bytes at {:#010x}", titleId, xexVersion,
              xex.image_size(), xex.base_address());
  if (patchMode && !ApplyCanaryPatches(patchFile, patches, titleId, xex, memory)) {
    return 1;
  }
  const auto tLoad = Clock::now();

  auto ctx = rex::codegen::CodegenContext::Create(rex::codegen::BinaryView::fromModule(xex),
                                                  std::move(config));
  ctx.setResolver(&resolver);
  ctx.setConfigDir(fs::path());  // outDirectoryPath is already resolved
  ctx.analysisState().format = "xex";
  ctx.analysisState().loadAddress = ctx.binary().baseAddress();
  ctx.analysisState().entryPoint = ctx.binary().entryPoint();
  ctx.analysisState().imageSize = ctx.binary().imageSize();
  if (ctx.Config().isDll.has_value())
    ctx.setDllModule(*ctx.Config().isDll);

  auto analysis = rex::codegen::Analyze(ctx, progress ? &steps : nullptr);
  if (!analysis) {
    if (!(force && analysis.error().category == rex::ErrorCategory::Validation)) {
      REXLOG_ERROR("Analysis failed: {}", analysis.error().message);
      return 1;
    }
    REXLOG_WARN("Analysis errors (continuing due to --force): {}", analysis.error().message);
  }
  const auto tAnalyze = Clock::now();

  step("write");
  rex::codegen::wasm::WasmWriter writer(ctx);
  writer.setTitle(titleId, xexVersion);
  if (!writer.write(force)) {
    REXLOG_ERROR("Writing modules failed");
    return 1;
  }
  const auto tWrite = Clock::now();

  REXLOG_INFO("Output: {} ({} written, {} unchanged, {} removed)",
              fs::path(ctx.Config().outDirectoryPath).lexically_normal().string(),
              writer.writtenFiles().size(), writer.unchangedFiles().size(),
              writer.deletedFiles().size());
  std::printf(
      "rexglue-translate: read %.2f s, load %.2f s, analyse %.2f s, write %.2f s, total %.2f s\n",
      Seconds(tStart, tRead), Seconds(tRead, tLoad), Seconds(tLoad, tAnalyze),
      Seconds(tAnalyze, tWrite), Seconds(tStart, tWrite));
  step("done");
  rex::ShutdownLogging();
  return 0;
}

int main(int argc, char** argv) {
  try {
    return Run(argc, argv);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "rexglue-translate: %s\n", e.what());
  } catch (...) {
    std::fprintf(stderr, "rexglue-translate: unknown exception\n");
  }
  return 1;
}
