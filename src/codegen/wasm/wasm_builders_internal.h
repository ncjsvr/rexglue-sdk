/**
 * @file        codegen/wasm/wasm_builders_internal.h
 * @brief       Pieces shared by the wasm instruction builder files
 *
 * @copyright   Copyright (c) 2026 MCLA-Reborn contributors
 * @license     Not yet licensed: MCLA-Reborn decides before any release (D-009)
 */

#pragma once

#include <cstdint>
#include <unordered_map>

#include "wasm_builders.h"

namespace rex::codegen::wasm::detail {

using W = WasmBuilderContext;
using Builder = void (*)(W&);
/// Builders keyed by the disassembler's PPC_INST_* id (the C++ backend's dispatch key).
using IdTable = std::unordered_map<int, Builder>;

enum class Width { B, H, W, D };

/// Pushes the effective address (i32). D-form: (rA|0) + d; update forms always use rA.
void pushEaD(W& w, int32_t disp, bool update);
/// X-form: (rA|0) + rB; update forms always use rA.
void pushEaX(W& w, bool update);

/// True when an access of `width` is known to be aligned (a halfword on 2 bytes, a word or
/// doubleword on 4: what byte-swapped storage needs, ADR-0009). Absolute addresses are
/// checked; r1-relative accesses with an aligned displacement count as aligned because the
/// ABI keeps the stack pointer 8-byte aligned. Everything else is checked at run time.
bool provablyAligned(const W& w, Width width, bool indexed, bool update, int32_t disp);

/// Pushes the value (i64, zero- or sign-extended; doublewords as the guest value) loaded from
/// the guest address in kI0. `mmio`: test the MMIO range first. `aligned`: skip the
/// alignment test (otherwise misaligned halfwords, words and doublewords take the byte-wise
/// helpers).
void loadValue(W& w, Width width, bool sign, bool mmio, bool aligned);

/// Stores the value in `valueLocal` (i32 for B/H/W, i64 for D) at the guest address in kI0.
void storeValue(W& w, Width width, uint32_t valueLocal, bool mmio, bool aligned);

/// Pushes the i64 linear address GUEST_BASE + local (i32 guest address).
void pushGuestLinear(W& w, uint32_t local);

void RegisterFloatBuilders(IdTable& t);
void RegisterVectorBuilders(IdTable& t);
void RegisterSystemBuilders(IdTable& t);

}  // namespace rex::codegen::wasm::detail
