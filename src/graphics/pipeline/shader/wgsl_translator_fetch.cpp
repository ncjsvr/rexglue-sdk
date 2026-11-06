/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2022 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 *
 * WGSL shader translator (MCLA-Reborn, T-028): vertex and texture fetches, after
 * spirv_translator_fetch.cpp. Vertex data comes from the shared memory storage buffer with
 * endian swapping and format unpacking in the shader; textures are sampled through WebGPU
 * views and samplers chosen per fetch constant and filter overrides.
 * MCLA-Reborn's additions: Not yet licensed (D-009).
 */

#include <rex/graphics/pipeline/shader/wgsl_translator.h>

#include <cmath>

#include <fmt/format.h>

#include <rex/assert.h>
#include <rex/math.h>

#include "wgsl_translator_util.h"

namespace rex::graphics {

using namespace wgsl;

std::string WgslShaderTranslator::FetchConstantWord(uint32_t word_index) const {
  return fmt::format("xe_fetch[{}][{}]", word_index >> 2, word_index & 3);
}

std::string WgslShaderTranslator::TextureName(size_t binding_index) const {
  return fmt::format("xe_texture_{}", binding_index);
}

std::string WgslShaderTranslator::SamplerName(size_t binding_index) const {
  return fmt::format("xe_sampler_{}", binding_index);
}

size_t WgslShaderTranslator::FindOrAddTextureBinding(uint32_t fetch_constant,
                                                     xenos::FetchOpDimension fetch_dimension,
                                                     TextureViewDimension view_dimension) {
  for (size_t i = 0; i < texture_bindings_.size(); ++i) {
    const TextureBinding& binding = texture_bindings_[i];
    if (binding.fetch_constant == fetch_constant && binding.view_dimension == view_dimension) {
      return i;
    }
  }
  TextureBinding binding = {};
  binding.fetch_constant = fetch_constant;
  binding.fetch_dimension = fetch_dimension;
  binding.view_dimension = view_dimension;
  texture_bindings_.push_back(binding);
  return texture_bindings_.size() - 1;
}

size_t WgslShaderTranslator::FindOrAddSamplerBinding(uint32_t fetch_constant,
                                                     xenos::TextureFilter mag_filter,
                                                     xenos::TextureFilter min_filter,
                                                     xenos::TextureFilter mip_filter,
                                                     xenos::AnisoFilter aniso_filter) {
  if (aniso_filter != xenos::AnisoFilter::kUseFetchConst) {
    // An explicit anisotropy overrides the other filters (as in the SPIR-V path).
    if (aniso_filter == xenos::AnisoFilter::kDisabled) {
      // Keep the filters.
    } else {
      mag_filter = xenos::TextureFilter::kLinear;
      min_filter = xenos::TextureFilter::kLinear;
      mip_filter = xenos::TextureFilter::kLinear;
    }
  }
  for (size_t i = 0; i < sampler_bindings_.size(); ++i) {
    const SamplerBinding& binding = sampler_bindings_[i];
    if (binding.fetch_constant == fetch_constant && binding.mag_filter == mag_filter &&
        binding.min_filter == min_filter && binding.mip_filter == mip_filter &&
        binding.aniso_filter == aniso_filter) {
      return i;
    }
  }
  SamplerBinding binding = {};
  binding.fetch_constant = fetch_constant;
  binding.mag_filter = mag_filter;
  binding.min_filter = min_filter;
  binding.mip_filter = mip_filter;
  binding.aniso_filter = aniso_filter;
  sampler_bindings_.push_back(binding);
  return sampler_bindings_.size() - 1;
}

// ---------------------------------------------------------------------------------------------
// Vertex fetch.

void WgslShaderTranslator::ProcessVertexFetchInstruction(
    const ParsedVertexFetchInstruction& instr) {
  UpdateInstructionPredication(instr.is_predicated, instr.predicate_condition);

  uint32_t used_result_components = instr.result.GetUsedResultComponents();
  uint32_t needed_words =
      xenos::GetVertexFormatNeededWords(instr.attributes.data_format, used_result_components);
  if (!needed_words && instr.is_mini_fetch) {
    StoreResult(instr.result, std::string(), false);
    return;
  }
  uses_fetch_constants_ = true;
  uint32_t fetch_constant_word_0_index = instr.operands[1].storage_index << 1;

  std::string address;
  if (instr.is_mini_fetch) {
    address = Temp("i32", "xe_vfetch_address");
  } else {
    // Base address in dwords from bits 2:31 of the first fetch constant word.
    std::string base = fmt::format("i32({} >> 2u)", FetchConstantWord(fetch_constant_word_0_index));
    if (instr.attributes.stride) {
      std::string index = OperandScalar(LoadOperandStorage(instr.operands[0]), instr.operands[0], 0);
      if (instr.attributes.is_index_rounded) {
        index = fmt::format("({} + 0.5)", index);
      }
      base = fmt::format("{} + i32(floor({})) * {}", base, index, instr.attributes.stride);
    }
    address = Temp("i32", base);
    Line(fmt::format("xe_vfetch_address = {};", address));
  }
  if (!needed_words) {
    StoreResult(instr.result, std::string(), false);
    return;
  }
  uses_shared_memory_ = true;

  // Load the words of the element the result needs, endian-swapped by bits 0:1 of the second
  // fetch constant word.
  std::string endian =
      Temp("u32", fmt::format("{} & 3u", FetchConstantWord(fetch_constant_word_0_index + 1)));
  std::string words[4];
  for (uint32_t i = 0; i < 4; ++i) {
    if (!(needed_words & (1u << i))) {
      words[i] = "0u";
      continue;
    }
    int32_t word_offset = instr.attributes.offset + int32_t(i);
    words[i] = Temp("u32", fmt::format("xe_endian_swap(xe_load_shared({} + {}), {})", address,
                                       word_offset, endian));
  }

  bool is_signed = instr.attributes.is_signed;
  bool normalize = !instr.attributes.is_integer;
  bool no_zero =
      instr.attributes.signed_rf_mode == xenos::SignedRepeatingFractionMode::kNoZero;
  // An extracted packed component as f32, normalized if needed.
  auto packed = [&](const std::string& word, uint32_t offset, uint32_t width) -> std::string {
    std::string value =
        is_signed ? fmt::format("f32(extractBits(bitcast<i32>({}), {}u, {}u))", word, offset, width)
                  : fmt::format("f32(extractBits({}, {}u, {}u))", word, offset, width);
    if (!normalize) {
      return value;
    }
    if (is_signed) {
      float scale = 1.0f / (float((uint32_t(1) << (width - 1)) - 1) + (no_zero ? 0.5f : 0.0f));
      if (no_zero) {
        return fmt::format("({} * {} + {})", value, FloatLiteral(scale),
                           FloatLiteral(0.5f * scale));
      }
      // Both -(2^(n-1)) and -(2^(n-1)-1) are -1.
      return fmt::format("max({} * {}, -1.0)", value, FloatLiteral(scale));
    }
    return fmt::format("({} * {})", value,
                       FloatLiteral(1.0f / float((uint64_t(1) << width) - 1)));
  };
  auto whole = [&](const std::string& word) -> std::string {
    std::string value =
        is_signed ? fmt::format("f32(bitcast<i32>({}))", word) : fmt::format("f32({})", word);
    if (!normalize) {
      return value;
    }
    if (is_signed) {
      if (no_zero) {
        return fmt::format("({} * {} + {})", value, FloatLiteral(1.0f / 2147483647.5f),
                           FloatLiteral(0.5f / 2147483647.5f));
      }
      return fmt::format("({} * {})", value, FloatLiteral(1.0f / 2147483647.0f));
    }
    return fmt::format("({} * {})", value, FloatLiteral(1.0f / 4294967295.0f));
  };

  std::string c[4] = {"0.0", "0.0", "0.0", "0.0"};
  switch (instr.attributes.data_format) {
    case xenos::VertexFormat::k_8_8_8_8:
      for (uint32_t i = 0; i < 4; ++i) {
        c[i] = packed(words[0], i * 8, 8);
      }
      break;
    case xenos::VertexFormat::k_2_10_10_10:
      c[0] = packed(words[0], 0, 10);
      c[1] = packed(words[0], 10, 10);
      c[2] = packed(words[0], 20, 10);
      c[3] = packed(words[0], 30, 2);
      break;
    case xenos::VertexFormat::k_10_11_11:
      c[0] = packed(words[0], 0, 11);
      c[1] = packed(words[0], 11, 11);
      c[2] = packed(words[0], 22, 10);
      break;
    case xenos::VertexFormat::k_11_11_10:
      c[0] = packed(words[0], 0, 10);
      c[1] = packed(words[0], 10, 11);
      c[2] = packed(words[0], 21, 11);
      break;
    case xenos::VertexFormat::k_16_16:
      c[0] = packed(words[0], 0, 16);
      c[1] = packed(words[0], 16, 16);
      break;
    case xenos::VertexFormat::k_16_16_16_16:
      c[0] = packed(words[0], 0, 16);
      c[1] = packed(words[0], 16, 16);
      c[2] = packed(words[1], 0, 16);
      c[3] = packed(words[1], 16, 16);
      break;
    case xenos::VertexFormat::k_16_16_FLOAT:
    case xenos::VertexFormat::k_16_16_16_16_FLOAT: {
      // GLSL-style float16 (Xbox 360 float16 has an extended range instead of Infinity and
      // NaN; the SPIR-V path makes the same simplification).
      std::string xy = Temp("vec2<f32>", fmt::format("unpack2x16float({})", words[0]));
      c[0] = xy + ".x";
      c[1] = xy + ".y";
      if (instr.attributes.data_format == xenos::VertexFormat::k_16_16_16_16_FLOAT) {
        std::string zw = Temp("vec2<f32>", fmt::format("unpack2x16float({})", words[1]));
        c[2] = zw + ".x";
        c[3] = zw + ".y";
      }
    } break;
    case xenos::VertexFormat::k_32:
    case xenos::VertexFormat::k_32_32:
    case xenos::VertexFormat::k_32_32_32_32: {
      uint32_t count = xenos::GetVertexFormatComponentCount(instr.attributes.data_format);
      for (uint32_t i = 0; i < count; ++i) {
        c[i] = whole(words[i]);
      }
    } break;
    case xenos::VertexFormat::k_32_FLOAT:
    case xenos::VertexFormat::k_32_32_FLOAT:
    case xenos::VertexFormat::k_32_32_32_FLOAT:
    case xenos::VertexFormat::k_32_32_32_32_FLOAT: {
      uint32_t count = xenos::GetVertexFormatComponentCount(instr.attributes.data_format);
      for (uint32_t i = 0; i < count; ++i) {
        c[i] = fmt::format("bitcast<f32>({})", words[i]);
      }
    } break;
    default:
      EmitTranslationError("WGSL: unsupported vertex format");
      StoreResult(instr.result, std::string(), false);
      return;
  }
  // Components the format doesn't have, or the result doesn't use, stay 0.
  for (uint32_t i = 0; i < 4; ++i) {
    if (!(used_result_components & (1u << i))) {
      c[i] = "0.0";
    }
  }
  std::string result =
      fmt::format("vec4<f32>({}, {}, {}, {})", c[0], c[1], c[2], c[3]);
  if (instr.attributes.exp_adjust) {
    result = fmt::format("{} * {}", result,
                         FloatLiteral(std::ldexp(1.0f, instr.attributes.exp_adjust)));
  }
  StoreResult(instr.result, Temp("vec4<f32>", result), false);
}

// ---------------------------------------------------------------------------------------------
// Texture fetch.

void WgslShaderTranslator::ProcessTextureFetchInstruction(
    const ParsedTextureFetchInstruction& instr) {
  UpdateInstructionPredication(instr.is_predicated, instr.predicate_condition);

  switch (instr.opcode) {
    case ucode::FetchOpcode::kSetTextureLod:
      Line(fmt::format("xe_tfetch_lod = {};",
                       OperandScalar(LoadOperandStorage(instr.operands[0]), instr.operands[0], 0)));
      return;
    case ucode::FetchOpcode::kSetTextureGradientsHorz:
    case ucode::FetchOpcode::kSetTextureGradientsVert: {
      std::string v = OperandVector(LoadOperandStorage(instr.operands[0]), instr.operands[0]);
      Line(fmt::format("{} = ({}).xyz;",
                       instr.opcode == ucode::FetchOpcode::kSetTextureGradientsHorz
                           ? "xe_tfetch_grad_h"
                           : "xe_tfetch_grad_v",
                       v));
      return;
    }
    default:
      break;
  }

  uint32_t used_result_components = instr.result.GetUsedResultComponents();
  uint32_t used_nonzero_components = instr.GetNonZeroResultComponents();
  switch (instr.opcode) {
    case ucode::FetchOpcode::kTextureFetch:
    case ucode::FetchOpcode::kGetTextureComputedLod:
    case ucode::FetchOpcode::kGetTextureGradients:
      break;
    case ucode::FetchOpcode::kGetTextureWeights:
      // The mip lerp factor is not calculated (as in the SPIR-V path).
      used_nonzero_components &= ~uint32_t(0b1000);
      break;
    case ucode::FetchOpcode::kGetTextureBorderColorFrac:
      AddWarning("WGSL: getBCF is not implemented (returns 0)");
      used_nonzero_components = 0;
      break;
    default:
      EmitTranslationError("WGSL: unknown texture fetch operation");
      used_nonzero_components = 0;
      break;
  }
  if (!used_nonzero_components) {
    if (used_result_components) {
      StoreResult(instr.result, "vec4<f32>(0.0)", false);
    }
    return;
  }

  bool derivatives_available = is_pixel_shader();
  std::string coordinates_storage = LoadOperandStorage(instr.operands[0]);
  std::string coordinates =
      Temp("vec4<f32>", OperandVector(coordinates_storage, instr.operands[0]));

  if (instr.opcode == ucode::FetchOpcode::kGetTextureGradients) {
    if (!derivatives_available) {
      AddWarning("WGSL: getGradients in a vertex shader returns 0");
      StoreResult(instr.result, "vec4<f32>(0.0)", false);
      return;
    }
    uses_derivatives_ = true;
    // XZ = ddx(source.xy), YW = ddy(source.xy), coarse.
    StoreResult(instr.result,
                Temp("vec4<f32>",
                     fmt::format("vec4<f32>(dpdxCoarse({0}.x), dpdyCoarse({0}.x), "
                                 "dpdxCoarse({0}.y), dpdyCoarse({0}.y))",
                                 coordinates)),
                false);
    return;
  }

  uses_fetch_constants_ = true;
  uint32_t fetch_constant = instr.operands[1].storage_index;
  uint32_t fetch_word_0 = 6 * fetch_constant;
  bool use_computed_lod = instr.attributes.use_computed_lod &&
                          (is_pixel_shader() || instr.attributes.use_register_gradients);
  if (instr.opcode == ucode::FetchOpcode::kGetTextureComputedLod &&
      (!use_computed_lod || instr.attributes.use_register_gradients || !derivatives_available)) {
    AddWarning("WGSL: getCompTexLOD with explicit LOD, gradients or in a vertex shader returns 0");
    StoreResult(instr.result, "vec4<f32>(0.0)", false);
    return;
  }

  // Bindings. Stacked 2D and 3D textures are separate views chosen at run time by the fetch
  // constant's dimension (bits 9:10 of word 5).
  xenos::FetchOpDimension dimension = instr.dimension;
  TextureViewDimension primary_view = TextureViewDimension::k2DArray;
  if (dimension == xenos::FetchOpDimension::kCube) {
    primary_view = TextureViewDimension::kCube;
  }
  size_t texture_primary = FindOrAddTextureBinding(fetch_constant, dimension, primary_view);
  size_t texture_3d = SIZE_MAX;
  if (dimension == xenos::FetchOpDimension::k3DOrStacked) {
    texture_3d = FindOrAddTextureBinding(fetch_constant, dimension, TextureViewDimension::k3D);
  }
  size_t sampler = SIZE_MAX;
  if (instr.opcode != ucode::FetchOpcode::kGetTextureWeights) {
    sampler = FindOrAddSamplerBinding(
        fetch_constant, instr.attributes.mag_filter, instr.attributes.min_filter,
        instr.opcode == ucode::FetchOpcode::kGetTextureComputedLod ? xenos::TextureFilter::kLinear
                                                                   : instr.attributes.mip_filter,
        use_computed_lod ? instr.attributes.aniso_filter : xenos::AnisoFilter::kDisabled);
  }
  std::string tex = TextureName(texture_primary);
  std::string tex3d = texture_3d != SIZE_MAX ? TextureName(texture_3d) : std::string();
  std::string smp = sampler != SIZE_MAX ? SamplerName(sampler) : std::string();

  std::string is_3d;
  if (dimension == xenos::FetchOpDimension::k3DOrStacked) {
    is_3d = Temp("bool",
                 fmt::format("(({} >> 9u) & 3u) == 2u", FetchConstantWord(fetch_word_0 + 5)));
  }

  // Sizes for normalization, offsets and weights.
  std::string size;  // vec3<f32>: width, height, depth or layer count
  if (dimension == xenos::FetchOpDimension::kCube) {
    size = Temp("vec3<f32>", fmt::format("vec3<f32>(vec2<f32>(textureDimensions({})), 1.0)", tex));
  } else if (dimension == xenos::FetchOpDimension::k3DOrStacked) {
    size = Temp("vec3<f32>",
                fmt::format("select(vec3<f32>(vec2<f32>(textureDimensions({0})), "
                            "f32(textureNumLayers({0}))), vec3<f32>(textureDimensions({1})), {2})",
                            tex, tex3d, is_3d));
  } else {
    size = Temp("vec3<f32>", fmt::format("vec3<f32>(vec2<f32>(textureDimensions({})), 1.0)", tex));
  }

  // Coordinates: normalized, with the instruction's texel offsets applied.
  uint32_t coordinate_count = dimension == xenos::FetchOpDimension::k1D   ? 1
                              : dimension == xenos::FetchOpDimension::k2D ? 2
                                                                          : 3;
  float offsets[3] = {instr.attributes.offset_x, instr.attributes.offset_y,
                      instr.attributes.offset_z};
  std::string unnormalized_factor;  // multiply to get texel units
  std::string uvw = Temp("vec3<f32>", fmt::format("{}.xyz", coordinates));
  if (dimension != xenos::FetchOpDimension::kCube) {
    std::string normalized;
    if (instr.attributes.unnormalized_coordinates) {
      normalized = fmt::format("{} / {}", uvw, size);
    } else {
      normalized = uvw;
    }
    std::string offset_vector = fmt::format(
        "vec3<f32>({}, {}, {})", FloatLiteral(offsets[0]),
        coordinate_count >= 2 ? FloatLiteral(offsets[1]) : "0.0",
        dimension == xenos::FetchOpDimension::k3DOrStacked ? FloatLiteral(offsets[2]) : "0.0");
    if (offsets[0] != 0.0f || offsets[1] != 0.0f || offsets[2] != 0.0f) {
      normalized = fmt::format("({}) + {} / {}", normalized, offset_vector, size);
    }
    uvw = Temp("vec3<f32>", normalized);
    if (coordinate_count == 1) {
      // 1D textures are 2D arrays of height 1.
      Line(fmt::format("let {0}_1d: vec3<f32> = vec3<f32>({0}.x, 0.5, 0.0);", uvw));
      uvw = uvw + "_1d";
    }
  }

  // getWeights: bilinear lerp factors.
  if (instr.opcode == ucode::FetchOpcode::kGetTextureWeights) {
    std::string w = Temp("vec3<f32>", fmt::format("fract({} * {} - 0.5)", uvw, size));
    StoreResult(instr.result,
                Temp("vec4<f32>", fmt::format("vec4<f32>({0}.x, {1}, {2}, 0.0)", w,
                                              coordinate_count >= 2 ? w + ".y" : "0.0",
                                              coordinate_count >= 3 ? w + ".z" : "0.0")),
                false);
    return;
  }

  // LOD bias: the instruction's plus the fetch constant's (word 4 bits 12:21, 1/32 units).
  std::string bias = Temp(
      "f32", fmt::format("{} + f32(extractBits(bitcast<i32>({}), 12u, 10u)) * (1.0 / 32.0)",
                         FloatLiteral(instr.attributes.lod_bias),
                         FetchConstantWord(fetch_word_0 + 4)));

  // Direction for cube maps.
  std::string cube_direction;
  if (dimension == xenos::FetchOpDimension::kCube) {
    cube_direction = Temp(
        "vec3<f32>", fmt::format("xe_cube_direction({0}.x, {0}.y, {0}.z + {1})", uvw,
                                 FloatLiteral(offsets[2])));
  }

  if (instr.opcode == ucode::FetchOpcode::kGetTextureComputedLod) {
    // WGSL has no textureQueryLod: the LOD from the derivatives of the texel coordinates.
    uses_derivatives_ = true;
    std::string texels = Temp(
        "vec3<f32>", dimension == xenos::FetchOpDimension::kCube
                         ? fmt::format("{} * {}.x", cube_direction, size)
                         : fmt::format("{} * {}", uvw, size));
    std::string mask = dimension == xenos::FetchOpDimension::k1D   ? "vec3<f32>(1.0, 0.0, 0.0)"
                       : dimension == xenos::FetchOpDimension::k2D ? "vec3<f32>(1.0, 1.0, 0.0)"
                                                                   : "vec3<f32>(1.0)";
    std::string lod = Temp(
        "f32", fmt::format("log2(max(length(dpdx({0}) * {1}), length(dpdy({0}) * {1})))",
                           texels, mask));
    StoreResult(instr.result, Temp("vec4<f32>", fmt::format("vec4<f32>({}, 0.0, 0.0, 0.0)", lod)),
                false);
    return;
  }

  // kTextureFetch.
  std::string grad_scale_h, grad_scale_v;
  if (use_computed_lod && instr.attributes.use_register_gradients) {
    // Gradient exponent adjustments (word 4 bits 22:26 and 27:31), and the bias as a scale
    // (WGSL can't combine explicit gradients with a bias).
    std::string word_4 = FetchConstantWord(fetch_word_0 + 4);
    grad_scale_h = Temp("f32", fmt::format("exp2({} + f32(extractBits(bitcast<i32>({}), 22u, 5u)))",
                                           bias, word_4));
    grad_scale_v = Temp("f32", fmt::format("exp2({} + f32(extractBits(bitcast<i32>({}), 27u, 5u)))",
                                           bias, word_4));
  }
  std::string level;
  if (!use_computed_lod) {
    level = Temp("f32", instr.attributes.use_register_lod
                            ? fmt::format("xe_tfetch_lod + {}", bias)
                            : bias);
  } else if (!instr.attributes.use_register_gradients) {
    std::string total = instr.attributes.use_register_lod
                            ? fmt::format("xe_tfetch_lod + {}", bias)
                            : bias;
    bias = Temp("f32", fmt::format("clamp({}, -16.0, 15.99)", total));
  }

  // Builds the sample call for a view: coords (already a WGSL expression) and the extra
  // array index argument for 2D arrays.
  auto sample = [&](const std::string& texture, const std::string& coords,
                    const std::string& array_index, uint32_t gradient_components) {
    std::string array_arg = array_index.empty() ? std::string() : ", " + array_index;
    if (!use_computed_lod) {
      return fmt::format("textureSampleLevel({}, {}, {}{}, {})", texture, smp, coords, array_arg,
                         level);
    }
    if (instr.attributes.use_register_gradients) {
      const char* swizzle = gradient_components == 2 ? "xy" : "xyz";
      return fmt::format("textureSampleGrad({}, {}, {}{}, xe_tfetch_grad_h.{} * {}, "
                         "xe_tfetch_grad_v.{} * {})",
                         texture, smp, coords, array_arg, swizzle, grad_scale_h, swizzle,
                         grad_scale_v);
    }
    return fmt::format("textureSampleBias({}, {}, {}{}, {})", texture, smp, coords, array_arg,
                       bias);
  };

  std::string raw;
  if (dimension == xenos::FetchOpDimension::kCube) {
    raw = Temp("vec4<f32>", sample(tex, cube_direction, std::string(), 3));
  } else if (dimension == xenos::FetchOpDimension::k3DOrStacked) {
    // Stacked: the layer is z * depth (+ offset, already included above), nearest layer.
    Line(fmt::format("var {}_sample: vec4<f32>;", uvw));
    OpenScope(fmt::format("if ({}) {{", is_3d));
    Line(fmt::format("{}_sample = {};", uvw, sample(tex3d, uvw, std::string(), 3)));
    CloseScope();
    OpenScope("else {");
    Line(fmt::format(
        "{}_sample = {};", uvw,
        sample(tex, uvw + ".xy",
               fmt::format("i32(clamp(floor({0}.z * {1}.z), 0.0, {1}.z - 1.0))", uvw, size), 2)));
    CloseScope();
    raw = uvw + "_sample";
  } else {
    raw = Temp("vec4<f32>", sample(tex, uvw + ".xy", "0", 2));
  }

  // Swizzle, signedness and the result exponent bias (word 3 bits 13:18).
  std::string swizzle = fmt::format("(xe_system.texture_swizzles[{}][{}] >> {}u)",
                                    fetch_constant >> 3, (fetch_constant >> 1) & 3,
                                    (fetch_constant & 1) * 12);
  std::string signs = fmt::format("((xe_system.texture_swizzled_signs[{}][{}] >> {}u) & 0xFFu)",
                                  fetch_constant >> 4, (fetch_constant >> 2) & 3,
                                  (fetch_constant & 3) * 8);
  std::string result = Temp(
      "vec4<f32>",
      fmt::format("xe_texture_signs(xe_texture_swizzle({}, {}), {}) * "
                  "exp2(f32(extractBits(bitcast<i32>({}), 13u, 6u)))",
                  raw, swizzle, signs, FetchConstantWord(fetch_word_0 + 3)));
  StoreResult(instr.result, result, false);
}

}  // namespace rex::graphics
