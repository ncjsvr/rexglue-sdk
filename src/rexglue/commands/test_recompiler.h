/**
 * @file        rexglue/commands/test_recompiler.h
 * @brief       Recompiler test command interface
 *
 * @copyright   Copyright (c) 2026 Tom Clay
 * @license     BSD 3-Clause License
 */

#pragma once

#include <string_view>

#include "../cli_utils.h"

namespace CLI {
class App;
}

namespace rexglue::cli {

void RegisterRecompileTests(CLI::App& parent, const CliContext& ctx, DeferredAction& pending);

/// `recompile-tests --backend wasm`: one module per fixture binary plus manifest.json and
/// tests.json in outDir. Also used by rexglue-translate --tests (MCLA-Reborn).
bool TranslateTestsWasm(std::string_view binDir, std::string_view asmDir, std::string_view outDir);

}  // namespace rexglue::cli
