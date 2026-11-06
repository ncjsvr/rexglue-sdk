/**
 * @file        translator/kernel_exports.h
 * @brief       Kernel and XAM export tables for the translator tool
 *
 * @copyright   Copyright (c) 2026 MCLA-Reborn contributors
 * @license     Not yet licensed: MCLA-Reborn decides before any release (D-009)
 */

#pragma once

namespace rex::runtime {
class ExportResolver;
}

namespace rex::translator {

/// Registers xboxkrnl.exe, xam.xex and xbdm.xex export names, as the runtime's kernel
/// modules do, without their implementations.
void RegisterKernelExports(rex::runtime::ExportResolver& resolver);

}  // namespace rex::translator
