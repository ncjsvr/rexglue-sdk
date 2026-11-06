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
 *                     [--force] [--log-level <level>]
 *   rexglue-translate --tests <bin-dir> --asm <asm-dir> --out <dir>
 *
 * The second form translates the assembled PowerPC fixture corpus exactly as
 * `rexglue recompile-tests --backend wasm` does, so the two builds can be compared.
 *
 * The TOML is a ReXGlue manifest ([project], [entrypoint] with backend = "wasm" and the
 * analysis entries); its file_path is used only when neither --iso nor --xex is given, and
 * --out overrides out_directory_path.
 */

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

#include <rex/codegen/analyze.h>
#include <rex/codegen/binary_view.h>
#include <rex/codegen/codegen_context.h>
#include <rex/codegen/manifest.h>
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
               "                         [--out <dir>] [--force] [--log-level <level>]\n"
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

}  // namespace

int Run(int argc, char** argv) {
  const auto tStart = Clock::now();
  std::string configArg, isoArg, xexArg, outArg, testsArg, asmArg, logLevel = "info";
  bool force = false;
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
    else if (a == "--tests")
      ok = value(testsArg);
    else if (a == "--asm")
      ok = value(asmArg);
    else if (a == "--log-level")
      ok = value(logLevel);
    else if (a == "--force")
      force = true;
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

  // Input bytes.
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
  const auto tRead = Clock::now();
  REXLOG_INFO("Read {} bytes from {}", xexBytes.size(), source);

  // Load as ReXGlue does: guest memory, export names, XexModule.
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

  auto analysis = rex::codegen::Analyze(ctx);
  if (!analysis) {
    if (!(force && analysis.error().category == rex::ErrorCategory::Validation)) {
      REXLOG_ERROR("Analysis failed: {}", analysis.error().message);
      return 1;
    }
    REXLOG_WARN("Analysis errors (continuing due to --force): {}", analysis.error().message);
  }
  const auto tAnalyze = Clock::now();

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
