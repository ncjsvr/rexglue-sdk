/**
 * @file        codegen/wasm/wasm_context_layout.cpp
 * @brief       PPCContext field offsets for the wasm backend (guest ABI v1)
 *
 * @copyright   Copyright (c) 2026 MCLA-Reborn contributors
 * @license     Not yet licensed: MCLA-Reborn decides before any release (D-009)
 */

#include "wasm_context_layout.h"

#include <cstddef>
#include <string>

#include <rex/ppc/context.h>

namespace rex::codegen::wasm {

namespace {

// The emitter writes a whole CR field with one i32 store and XER bits as bytes.
static_assert(offsetof(PPCCRRegister, lt) == 0 && offsetof(PPCCRRegister, gt) == 1 &&
                  offsetof(PPCCRRegister, eq) == 2 && offsetof(PPCCRRegister, so) == 3 &&
                  sizeof(PPCCRRegister) == 4,
              "CR field must be four consecutive bytes lt, gt, eq, so");
static_assert(sizeof(PPCRegister) == 8, "GPRs are 8 bytes");

#define REX_CTX_OFF(field) static_cast<uint32_t>(offsetof(PPCContext, field))

ContextLayout Build() {
  ContextLayout l{};
  l.size = static_cast<uint32_t>(sizeof(PPCContext));
  l.align = static_cast<uint32_t>(alignof(PPCContext));
#define REX_R(n) l.r[n] = REX_CTX_OFF(r##n);
  REX_R(0) REX_R(1) REX_R(2) REX_R(3) REX_R(4) REX_R(5) REX_R(6) REX_R(7) REX_R(8) REX_R(9)
  REX_R(10) REX_R(11) REX_R(12) REX_R(13) REX_R(14) REX_R(15) REX_R(16) REX_R(17) REX_R(18)
  REX_R(19) REX_R(20) REX_R(21) REX_R(22) REX_R(23) REX_R(24) REX_R(25) REX_R(26) REX_R(27)
  REX_R(28) REX_R(29) REX_R(30) REX_R(31)
#undef REX_R
#define REX_F(n) l.f[n] = REX_CTX_OFF(f##n);
  REX_F(0) REX_F(1) REX_F(2) REX_F(3) REX_F(4) REX_F(5) REX_F(6) REX_F(7) REX_F(8) REX_F(9)
  REX_F(10) REX_F(11) REX_F(12) REX_F(13) REX_F(14) REX_F(15) REX_F(16) REX_F(17) REX_F(18)
  REX_F(19) REX_F(20) REX_F(21) REX_F(22) REX_F(23) REX_F(24) REX_F(25) REX_F(26) REX_F(27)
  REX_F(28) REX_F(29) REX_F(30) REX_F(31)
#undef REX_F
  l.lr = REX_CTX_OFF(lr);
  l.ctr = REX_CTX_OFF(ctr);
  l.reserved = REX_CTX_OFF(reserved);
  l.msr = REX_CTX_OFF(msr);
  l.fpscr = REX_CTX_OFF(fpscr);
  l.vscrSat = REX_CTX_OFF(vscr_sat);
  l.lastIndirectTarget = REX_CTX_OFF(last_indirect_target);
  l.xerSo = REX_CTX_OFF(xer) + static_cast<uint32_t>(offsetof(PPCXERRegister, so));
  l.xerOv = REX_CTX_OFF(xer) + static_cast<uint32_t>(offsetof(PPCXERRegister, ov));
  l.xerCa = REX_CTX_OFF(xer) + static_cast<uint32_t>(offsetof(PPCXERRegister, ca));
  const uint32_t crBase[8] = {REX_CTX_OFF(cr0), REX_CTX_OFF(cr1), REX_CTX_OFF(cr2),
                              REX_CTX_OFF(cr3), REX_CTX_OFF(cr4), REX_CTX_OFF(cr5),
                              REX_CTX_OFF(cr6), REX_CTX_OFF(cr7)};
  for (int i = 0; i < 8; ++i) {
    l.cr[i] = {crBase[i] + static_cast<uint32_t>(offsetof(PPCCRRegister, lt)),
               crBase[i] + static_cast<uint32_t>(offsetof(PPCCRRegister, gt)),
               crBase[i] + static_cast<uint32_t>(offsetof(PPCCRRegister, eq)),
               crBase[i] + static_cast<uint32_t>(offsetof(PPCCRRegister, so))};
  }
  // v0..v127 are consecutive members of one type; take v0 and the stride from offsetof.
  const uint32_t v0 = REX_CTX_OFF(v0);
  const uint32_t stride = REX_CTX_OFF(v1) - v0;
  static_assert(offsetof(PPCContext, v127) - offsetof(PPCContext, v0) == 127 * sizeof(PPCVRegister),
                "vector registers must be contiguous");
  for (uint32_t i = 0; i < 128; ++i)
    l.v[i] = v0 + i * stride;
  return l;
}

#undef REX_CTX_OFF

}  // namespace

const ContextLayout& ContextLayout::Get() {
  static const ContextLayout layout = Build();
  return layout;
}

nlohmann::json ContextLayout::toJson() const {
  nlohmann::json fields = nlohmann::json::object();
  for (int i = 0; i < 32; ++i)
    fields["r" + std::to_string(i)] = r[i];
  fields["lr"] = lr;
  fields["ctr"] = ctr;
  fields["xer"] = {{"so", xerSo}, {"ov", xerOv}, {"ca", xerCa}};
  fields["reserved"] = reserved;
  fields["msr"] = msr;
  for (int i = 0; i < 8; ++i) {
    fields["cr" + std::to_string(i)] = {
        {"lt", cr[i].lt}, {"gt", cr[i].gt}, {"eq", cr[i].eq}, {"so", cr[i].so}};
  }
  fields["fpscr"] = fpscr;
  fields["vscr_sat"] = vscrSat;
  fields["last_indirect_target"] = lastIndirectTarget;
  for (int i = 0; i < 32; ++i)
    fields["f" + std::to_string(i)] = f[i];
  for (int i = 0; i < 128; ++i)
    fields["v" + std::to_string(i)] = v[i];
  return {{"size", size}, {"align", align}, {"fields", fields}};
}

}  // namespace rex::codegen::wasm
