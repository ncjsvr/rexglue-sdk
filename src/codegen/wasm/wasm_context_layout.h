/**
 * @file        codegen/wasm/wasm_context_layout.h
 * @brief       PPCContext field offsets for the wasm backend (guest ABI v1)
 *
 * @copyright   Copyright (c) 2026 MCLA-Reborn contributors
 * @license     Not yet licensed: MCLA-Reborn decides before any release (D-009)
 */

#pragma once

#include <cstdint>

#include <nlohmann/json.hpp>

namespace rex::codegen::wasm {

/// Offsets of PPCContext fields, taken from offsetof so that the emitter, the runtime and
/// the harness agree with include/rex/ppc/context.h by construction.
struct ContextLayout {
  struct CrField {
    uint32_t lt, gt, eq, so;
  };
  uint32_t size;
  uint32_t align;
  uint32_t r[32];
  uint32_t lr, ctr, reserved, msr, fpscr, vscrSat, lastIndirectTarget;
  uint32_t xerSo, xerOv, xerCa;
  CrField cr[8];
  uint32_t f[32];
  uint32_t v[128];

  static const ContextLayout& Get();

  /// Byte offset of CR bit `bit` (0-31, big-endian CR numbering).
  uint32_t crBit(uint32_t bit) const {
    const CrField& f = cr[(bit >> 2) & 7];
    switch (bit & 3) {
      case 0:
        return f.lt;
      case 1:
        return f.gt;
      case 2:
        return f.eq;
      default:
        return f.so;
    }
  }

  nlohmann::json toJson() const;
};

}  // namespace rex::codegen::wasm
