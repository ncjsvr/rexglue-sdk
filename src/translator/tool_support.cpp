/**
 * @file        translator/tool_support.cpp
 * @brief       Runtime pieces the translator tool links without the runtime
 *
 * @copyright   Copyright (c) 2026 MCLA-Reborn contributors
 * @license     Not yet licensed: MCLA-Reborn decides before any release (D-009)
 */

#include <rex/system/function_dispatcher.h>

// FunctionDispatcher holds the guest memory and export resolver an XexModule reads through
// Module::memory() and function_dispatcher(); the tool never dispatches or registers guest
// functions, so only these members are defined (function_dispatcher.cpp pulls in the Runtime).
namespace rex::runtime {

FunctionDispatcher::FunctionDispatcher(rex::memory::Memory* memory,
                                       ExportResolver* export_resolver)
    : memory_(memory), export_resolver_(export_resolver) {}

FunctionDispatcher::~FunctionDispatcher() = default;

bool FunctionDispatcher::SetFunction(uint32_t guest_address, ::PPCFunc* func) {
  (void)guest_address;
  (void)func;
  return false;
}

}  // namespace rex::runtime
