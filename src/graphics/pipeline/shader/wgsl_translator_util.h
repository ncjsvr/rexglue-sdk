#pragma once
/**
 * WGSL shader translator (MCLA-Reborn, T-028): shared WGSL snippets and literal formatting.
 * Semantics follow Xenia's SpirvShaderTranslator (Copyright 2022 Ben Vanik, BSD-3-Clause; see
 * LICENSE in the SDK root). MCLA-Reborn's additions: Not yet licensed (D-009).
 */

#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

#include <fmt/format.h>

namespace rex::graphics::wgsl {

// WgslShaderTranslator::SystemConstants in WGSL (the offsets match the C++ struct).
inline constexpr const char* kWgslSystemConstantsStruct =
    "struct XeSystemConstants {\n"
    "  flags: u32,\n"
    "  vertex_index_endian: u32,\n"
    "  vertex_base_index: i32,\n"
    "  vertex_index_min: u32,\n"
    "  vertex_index_max: u32,\n"
    "  alpha_test_reference: f32,\n"
    "  padding_0: vec2<u32>,\n"
    "  ndc_scale: vec3<f32>,\n"
    "  point_vertex_diameter_min: f32,\n"
    "  ndc_offset: vec3<f32>,\n"
    "  point_vertex_diameter_max: f32,\n"
    "  color_exp_bias: vec4<f32>,\n"
    "  texture_swizzled_signs: array<vec4<u32>, 2>,\n"
    "  texture_swizzles: array<vec4<u32>, 4>,\n"
    "  user_clip_planes: array<vec4<f32>, 6>,\n"
    "}\n";

// Helpers every shader gets. Infinity and NaN are built from bits at run time: WGSL rejects
// constant expressions that evaluate to them.
inline constexpr const char* kWgslHelpers =
    // Shader Model 3 multiplication: +-0 * anything (even Infinity or NaN) = +0.
    "fn xe_mul(a: vec4<f32>, b: vec4<f32>) -> vec4<f32> {\n"
    "  return select(a * b, vec4<f32>(0.0), (a == vec4<f32>(0.0)) | (b == vec4<f32>(0.0)));\n"
    "}\n"
    "fn xe_mul_s(a: f32, b: f32) -> f32 {\n"
    "  return select(a * b, 0.0, (a == 0.0) || (b == 0.0));\n"
    "}\n"
    // Saturation that flushes NaN to 0 (GLSL.std.450 NClamp).
    "fn xe_sat(v: vec4<f32>) -> vec4<f32> {\n"
    "  return select(clamp(v, vec4<f32>(0.0), vec4<f32>(1.0)), vec4<f32>(0.0), v != v);\n"
    "}\n"
    "fn xe_sat_s(v: f32) -> f32 {\n"
    "  return select(clamp(v, 0.0, 1.0), 0.0, v != v);\n"
    "}\n"
    "fn xe_inf() -> f32 {\n"
    "  var bits: u32 = 0x7F800000u;\n"
    "  return bitcast<f32>(bits);\n"
    "}\n"
    "fn xe_nan() -> f32 {\n"
    "  var bits: u32 = 0x7FC00000u;\n"
    "  return bitcast<f32>(bits);\n"
    "}\n"
    "fn xe_is_inf(v: f32) -> bool {\n"
    "  return (bitcast<u32>(v) & 0x7FFFFFFFu) == 0x7F800000u;\n"
    "}\n"
    "fn xe_sign_bit(v: f32) -> bool {\n"
    "  return (bitcast<u32>(v) & 0x80000000u) != 0u;\n"
    "}\n"
    // Endian swap of a 32-bit value: xenos::Endian kNone 0, k8in16 1, k8in32 2, k16in32 3.
    "fn xe_endian_swap(v: u32, endian: u32) -> u32 {\n"
    "  var r: u32 = v;\n"
    "  if (endian == 1u || endian == 2u) {\n"
    "    r = ((r & 0x00FF00FFu) << 8u) | ((r >> 8u) & 0x00FF00FFu);\n"
    "  }\n"
    "  if (endian == 2u || endian == 3u) {\n"
    "    r = (r << 16u) | (r >> 16u);\n"
    "  }\n"
    "  return r;\n"
    "}\n"
    // Xenos piecewise-linear gamma (SpirvShaderTranslator::PWLGammaToLinear / LinearToPWLGamma).
    "fn xe_pwl_gamma_to_linear(gamma_in: vec3<f32>) -> vec3<f32> {\n"
    "  let gamma: vec3<f32> = xe_sat(vec4<f32>(gamma_in, 0.0)).xyz;\n"
    "  let p3: vec3<bool> = gamma >= vec3<f32>(192.0 / 255.0);\n"
    "  let p2: vec3<bool> = gamma >= vec3<f32>(96.0 / 255.0);\n"
    "  let p1: vec3<bool> = gamma >= vec3<f32>(64.0 / 255.0);\n"
    "  let scale: vec3<f32> = select(select(vec3<f32>(1.0 / 1024.0), vec3<f32>(2.0 / 1024.0), p1),\n"
    "                                select(vec3<f32>(4.0 / 1024.0), vec3<f32>(8.0 / 1024.0), p3), p2);\n"
    "  let offset: vec3<f32> = select(select(vec3<f32>(0.0), vec3<f32>(-64.0), p1),\n"
    "                                 select(vec3<f32>(-256.0), vec3<f32>(-1024.0), p3), p2);\n"
    "  var linear: vec3<f32> = gamma * (255.0 * 1024.0) * scale + offset;\n"
    "  linear = linear + trunc(linear * scale);\n"
    "  return linear * (1.0 / 1023.0);\n"
    "}\n"
    "fn xe_linear_to_pwl_gamma(linear_in: vec3<f32>) -> vec3<f32> {\n"
    "  let linear: vec3<f32> = xe_sat(vec4<f32>(linear_in, 0.0)).xyz;\n"
    "  let p3: vec3<bool> = linear >= vec3<f32>(512.0 / 1023.0);\n"
    "  let p2: vec3<bool> = linear >= vec3<f32>(128.0 / 1023.0);\n"
    "  let p1: vec3<bool> = linear >= vec3<f32>(64.0 / 1023.0);\n"
    "  let scale: vec3<f32> = select(select(vec3<f32>(1023.0), vec3<f32>(1023.0 / 2.0), p1),\n"
    "                                select(vec3<f32>(1023.0 / 4.0), vec3<f32>(1023.0 / 8.0), p3), p2);\n"
    "  let offset: vec3<f32> = select(select(vec3<f32>(0.0), vec3<f32>(32.0 / 255.0), p1),\n"
    "                                 select(vec3<f32>(64.0 / 255.0), vec3<f32>(128.0 / 255.0), p3), p2);\n"
    "  return trunc(linear * scale) * (1.0 / 255.0) + offset;\n"
    "}\n";

inline constexpr const char* kWgslSharedMemoryHelpers =
    // A dword of guest physical memory (zero out of bounds).
    "fn xe_load_shared(address_dwords: i32) -> u32 {\n"
    "  let a: u32 = bitcast<u32>(address_dwords);\n"
    "  if (a >= arrayLength(&xe_shared_memory)) {\n"
    "    return 0u;\n"
    "  }\n"
    "  return xe_shared_memory[a];\n"
    "}\n";

inline constexpr const char* kWgslTextureHelpers =
    // Applies the combined guest/host swizzle (3 bits per component: 0-3 RGBA, 4 = 0, 5 = 1).
    "fn xe_texture_swizzle(v: vec4<f32>, swizzle: u32) -> vec4<f32> {\n"
    "  var r: vec4<f32>;\n"
    "  for (var i: u32 = 0u; i < 4u; i = i + 1u) {\n"
    "    let s: u32 = (swizzle >> (3u * i)) & 7u;\n"
    "    var c: f32 = 0.0;\n"
    "    if (s < 4u) { c = v[s]; } else if (s == 5u) { c = 1.0; }\n"
    "    r[i] = c;\n"
    "  }\n"
    "  return r;\n"
    "}\n"
    // Post-swizzle signedness, 2 bits per component: unsigned 0, signed 1 (needs a signed
    // view; passed through), unsigned biased 2 (2x - 1), gamma 3 (PWL to linear).
    "fn xe_texture_signs(v: vec4<f32>, signs: u32) -> vec4<f32> {\n"
    "  let linear: vec3<f32> = xe_pwl_gamma_to_linear(v.xyz);\n"
    "  var r: vec4<f32> = v;\n"
    "  for (var i: u32 = 0u; i < 4u; i = i + 1u) {\n"
    "    let s: u32 = (signs >> (2u * i)) & 3u;\n"
    "    if (s == 2u) {\n"
    "      r[i] = v[i] * 2.0 - 1.0;\n"
    "    } else if (s == 3u && i < 3u) {\n"
    "      r[i] = linear[i];\n"
    "    }\n"
    "  }\n"
    "  return r;\n"
    "}\n"
    // Cube face coordinates from the cube ALU instruction (SC, TC in 1...2, face ID) to a
    // direction, the opposite of the cube instruction.
    "fn xe_cube_direction(sc_in: f32, tc_in: f32, face_in: f32) -> vec3<f32> {\n"
    "  let sc: f32 = sc_in * 2.0 - 3.0;\n"
    "  let tc: f32 = tc_in * 2.0 - 3.0;\n"
    "  let face: u32 = u32(select(clamp(face_in, 0.0, 5.0), 0.0, face_in != face_in));\n"
    "  let negative: bool = (face & 1u) != 0u;\n"
    "  let face_sign: f32 = select(1.0, -1.0, negative);\n"
    "  switch (face >> 1u) {\n"
    "    case 0u: { return vec3<f32>(face_sign, -tc, select(-sc, sc, negative)); }\n"
    "    case 1u: { return vec3<f32>(sc, face_sign, select(tc, -tc, negative)); }\n"
    "    default: { return vec3<f32>(select(sc, -sc, negative), -tc, face_sign); }\n"
    "  }\n"
    "}\n";

// A WGSL f32 literal that round-trips exactly (decimal when short and exact, else hex float).
inline std::string FloatLiteral(float value) {
  if (std::isnan(value) || std::isinf(value)) {
    uint32_t bits;
    std::memcpy(&bits, &value, sizeof(bits));
    return fmt::format("bitcast<f32>({:#010x}u)", bits);
  }
  if (value == std::trunc(value) && std::fabs(value) < 16777216.0f) {
    return fmt::format("{:.1f}", value);
  }
  std::string decimal = fmt::format("{:.9g}", value);
  if (std::strtof(decimal.c_str(), nullptr) == value && decimal.find_first_of(".e") != std::string::npos &&
      std::fabs(value) < 1.0e30f && std::fabs(value) > 1.0e-30f) {
    return decimal;
  }
  return fmt::format("{:a}f", value);
}

}  // namespace rex::graphics::wgsl
