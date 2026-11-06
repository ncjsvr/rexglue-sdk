/**
 * @file        translator/kernel_exports.cpp
 * @brief       Kernel and XAM export tables (ordinal, name, kind) for the translator tool
 *
 * @copyright   Copyright (c) 2026 MCLA-Reborn contributors
 * @license     Not yet licensed: MCLA-Reborn decides before any release (D-009)
 *
 * The codegen names imports through an ExportResolver. The runtime fills it when it loads its
 * HLE kernel modules (XboxkrnlModule, XamModule, XbdmModule::RegisterExportTable); the
 * translator only needs the names, so it registers the same three tables from ReXGlue's
 * export_table.inc files without the kernel implementations.
 */

#include "kernel_exports.h"

#include <vector>

#include <rex/system/export_resolver.h>

namespace rex::translator {

namespace {

constexpr size_t kOrdinals = 4096;  // as the kernel modules size their tables

// export_table_pre.inc builds rex::runtime::Export entries from XE_EXPORT lines.
#include "../kernel/export_table_pre.inc"
rex::runtime::Export xboxkrnl_table[] = {
#include "../kernel/xboxkrnl/export_table.inc"
};
rex::runtime::Export xam_table[] = {
#include "../kernel/xam/export_table.inc"
};
rex::runtime::Export xbdm_table[] = {
#include "../kernel/xbdm/export_table.inc"
};
#include "../kernel/export_table_post.inc"

template <size_t N>
std::vector<rex::runtime::Export*>* ByOrdinal(rex::runtime::Export (&table)[N]) {
  auto* v = new std::vector<rex::runtime::Export*>(kOrdinals, nullptr);
  for (auto& e : table) {
    if (e.ordinal < v->size() && !(*v)[e.ordinal])
      (*v)[e.ordinal] = &e;
  }
  return v;
}

}  // namespace

void RegisterKernelExports(rex::runtime::ExportResolver& resolver) {
  // Same names and order as the runtime's kernel_init (xboxkrnl, xam, xbdm).
  static auto* xboxkrnl = ByOrdinal(xboxkrnl_table);
  static auto* xam = ByOrdinal(xam_table);
  static auto* xbdm = ByOrdinal(xbdm_table);
  resolver.RegisterTable("xboxkrnl.exe", xboxkrnl);
  resolver.RegisterTable("xam.xex", xam);
  resolver.RegisterTable("xbdm.xex", xbdm);
}

}  // namespace rex::translator
