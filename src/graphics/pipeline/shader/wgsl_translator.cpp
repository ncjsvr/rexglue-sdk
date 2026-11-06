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
 * WGSL shader translator (MCLA-Reborn, T-028): control flow, interface, operands and results.
 * Follows SpirvShaderTranslator (spirv_translator.cpp) callback for callback; see
 * wgsl_translator.h. MCLA-Reborn's additions: Not yet licensed (D-009).
 */

#include <rex/graphics/pipeline/shader/wgsl_translator.h>

#include <algorithm>
#include <cstring>

#include <fmt/format.h>

#include <rex/assert.h>
#include <rex/math.h>

#include "wgsl_translator_util.h"

namespace rex::graphics {

using namespace wgsl;

uint64_t WgslShaderTranslator::GetDefaultVertexShaderModification(
    uint32_t dynamic_addressable_register_count,
    Shader::HostVertexShaderType host_vertex_shader_type) const {
  Modification modification;
  modification.vertex.dynamic_addressable_register_count = dynamic_addressable_register_count;
  modification.vertex.host_vertex_shader_type = host_vertex_shader_type;
  return modification.value;
}

uint64_t WgslShaderTranslator::GetDefaultPixelShaderModification(
    uint32_t dynamic_addressable_register_count) const {
  Modification modification;
  modification.pixel.dynamic_addressable_register_count = dynamic_addressable_register_count;
  return modification.value;
}

void WgslShaderTranslator::Reset() {
  ShaderTranslator::Reset();
  body_.clear();
  indent_ = 1;
  dead_ = false;
  scope_dead_stack_.clear();
  temp_counter_ = 0;
  has_labels_ = false;
  uses_shared_memory_ = false;
  uses_fetch_constants_ = false;
  uses_bool_loop_constants_ = false;
  uses_front_facing_ = false;
  uses_frag_coord_ = false;
  uses_derivatives_ = false;
  float_constant_array_size_ = 0;
  texture_bindings_.clear();
  sampler_bindings_.clear();
  warnings_.clear();
  exec_conditional_open_ = false;
  instruction_predicate_open_ = false;
  cf_exec_bool_constant_or_predicate_ = 0;
  cf_exec_condition_ = false;
  cf_instruction_predicate_condition_ = false;
  cf_exec_predicate_written_ = false;
}

uint32_t WgslShaderTranslator::GetModificationRegisterCount() const {
  Modification modification = GetWgslModification();
  return is_vertex_shader() ? modification.vertex.dynamic_addressable_register_count
                            : modification.pixel.dynamic_addressable_register_count;
}

uint32_t WgslShaderTranslator::GetModificationInterpolatorMask() const {
  Modification modification = GetWgslModification();
  return is_vertex_shader() ? modification.vertex.interpolator_mask
                            : modification.pixel.interpolator_mask;
}

uint32_t WgslShaderTranslator::GetPsParamGenInterpolator() const {
  Modification modification = GetWgslModification();
  return (modification.pixel.param_gen_enable &&
          modification.pixel.param_gen_interpolator < register_count())
             ? modification.pixel.param_gen_interpolator
             : UINT32_MAX;
}

void WgslShaderTranslator::AddWarning(const char* message) {
  if (std::find(warnings_.begin(), warnings_.end(), message) != warnings_.end()) {
    return;
  }
  warnings_.emplace_back(message);
  EmitTranslationError(message, false);
}

// ---------------------------------------------------------------------------------------------
// Text emission.

void WgslShaderTranslator::Line(const std::string& text) {
  if (dead_) {
    return;
  }
  body_.append(size_t(indent_) * 2, ' ');
  body_ += text;
  body_ += '\n';
}

void WgslShaderTranslator::OpenScope(const std::string& header) {
  Line(header);
  scope_dead_stack_.push_back(dead_);
  ++indent_;
}

void WgslShaderTranslator::CloseScope() {
  assert_false(scope_dead_stack_.empty());
  --indent_;
  dead_ = scope_dead_stack_.back();
  scope_dead_stack_.pop_back();
  Line("}");
}

void WgslShaderTranslator::Terminate(const std::string& statement) {
  Line(statement);
  dead_ = true;
}

std::string WgslShaderTranslator::Temp(const std::string& type, const std::string& expression) {
  std::string name = fmt::format("t{}", temp_counter_++);
  Line(fmt::format("let {}: {} = {};", name, type, expression));
  return name;
}

// ---------------------------------------------------------------------------------------------
// Translation start and end.

void WgslShaderTranslator::StartTranslation() {
  const Shader& shader = current_shader();
  has_labels_ = !shader.label_addresses().empty();

  const Shader::ConstantRegisterMap& constant_map = shader.constant_register_map();
  if (constant_map.float_dynamic_addressing) {
    float_constant_array_size_ = 256;
  } else {
    float_constant_array_size_ = constant_map.float_count;
  }

  // Registers and the rest of the guest state, initialised for safety like the SPIR-V path.
  if (register_count()) {
    Line(fmt::format("var xe_r: array<vec4<f32>, {}>;", register_count()));
  }
  Line("var xe_p0: bool = false;");
  Line("var xe_a0: i32 = 0;");
  Line("var xe_aL: vec4<i32> = vec4<i32>(0);");
  Line("var xe_loop_count: vec4<u32> = vec4<u32>(0u);");
  Line("var xe_ps: f32 = 0.0;");
  Line("var xe_vfetch_address: i32 = 0;");
  Line("var xe_tfetch_lod: f32 = 0.0;");
  Line("var xe_tfetch_grad_h: vec3<f32> = vec3<f32>(0.0);");
  Line("var xe_tfetch_grad_v: vec3<f32> = vec3<f32>(0.0);");

  if (is_vertex_shader()) {
    EmitVertexPrologue();
  } else {
    EmitPixelPrologue();
  }

  // The main loop: guest jumps and loops set xe_pc and continue; exece breaks.
  if (has_labels_) {
    Line("var xe_pc: i32 = 0;");
    OpenScope("loop {");
    OpenScope("if (xe_pc == 0) {");
  } else {
    OpenScope("loop {");
  }
}

std::vector<uint8_t> WgslShaderTranslator::CompleteTranslation() {
  CloseExecConditionals();
  if (has_labels_) {
    CloseScope();  // the last label's block
  }
  Terminate("break;");
  CloseScope();  // loop

  if (is_vertex_shader()) {
    EmitVertexEpilogue();
  } else {
    EmitPixelEpilogue();
  }

  // Binding numbers: textures first, then samplers, in the stage's texture bind group.
  for (size_t i = 0; i < texture_bindings_.size(); ++i) {
    texture_bindings_[i].binding = uint32_t(i);
  }
  for (size_t i = 0; i < sampler_bindings_.size(); ++i) {
    sampler_bindings_[i].binding = uint32_t(texture_bindings_.size() + i);
  }

  std::string text = BuildHeader();
  text += BuildEntryPoint(body_);
  return std::vector<uint8_t>(text.begin(), text.end());
}

std::string WgslShaderTranslator::BuildHeader() const {
  const Shader& shader = current_shader();
  std::string h;
  h += fmt::format(
      "// Translated from Xenos {} shader microcode {:016X} by WgslShaderTranslator v{}\n"
      "// (MCLA-Reborn), modification {:016X}.\n",
      is_vertex_shader() ? "vertex" : "pixel", shader.ucode_data_hash(), kVersion,
      current_translation().modification());
  if (is_pixel_shader()) {
    // Xenos computes derivatives for every quad regardless of control flow, as the SPIR-V
    // and DXBC paths assume; WGSL's uniformity analysis would reject guest control flow.
    h += "diagnostic(off, derivative_uniformity);\n";
  }
  h += "\n";
  h += kWgslSystemConstantsStruct;
  h += fmt::format("@group({}) @binding({}) var<uniform> xe_system: XeSystemConstants;\n",
                   kBindGroupConstants, uint32_t(kConstantBindingSystem));
  if (float_constant_array_size_) {
    h += fmt::format("@group({}) @binding({}) var<uniform> xe_float_constants: array<vec4<f32>, {}>;\n",
                     kBindGroupConstants,
                     uint32_t(is_pixel_shader() ? kConstantBindingFloatPixel
                                                : kConstantBindingFloatVertex),
                     float_constant_array_size_);
  }
  if (uses_bool_loop_constants_) {
    h += "struct XeBoolLoopConstants {\n"
         "  bool_constants: array<vec4<u32>, 2>,\n"
         "  loop_constants: array<vec4<u32>, 8>,\n"
         "}\n";
    h += fmt::format("@group({}) @binding({}) var<uniform> xe_bool_loop: XeBoolLoopConstants;\n",
                     kBindGroupConstants, uint32_t(kConstantBindingBoolLoop));
  }
  if (uses_fetch_constants_) {
    h += fmt::format("@group({}) @binding({}) var<uniform> xe_fetch: array<vec4<u32>, 48>;\n",
                     kBindGroupConstants, uint32_t(kConstantBindingFetch));
  }
  if (uses_shared_memory_) {
    h += fmt::format(
        "@group({}) @binding(0) var<storage, read> xe_shared_memory: array<u32>;\n",
        kBindGroupSharedMemory);
  }
  uint32_t texture_group = is_pixel_shader() ? kBindGroupTexturesPixel : kBindGroupTexturesVertex;
  for (size_t i = 0; i < texture_bindings_.size(); ++i) {
    const TextureBinding& binding = texture_bindings_[i];
    const char* type = "texture_2d_array<f32>";
    if (binding.view_dimension == TextureViewDimension::k3D) {
      type = "texture_3d<f32>";
    } else if (binding.view_dimension == TextureViewDimension::kCube) {
      type = "texture_cube<f32>";
    }
    h += fmt::format("@group({}) @binding({}) var {}: {};  // tf{}\n", texture_group,
                     binding.binding, TextureName(i), type, binding.fetch_constant);
  }
  for (size_t i = 0; i < sampler_bindings_.size(); ++i) {
    const SamplerBinding& binding = sampler_bindings_[i];
    h += fmt::format("@group({}) @binding({}) var {}: sampler;  // tf{}\n", texture_group,
                     binding.binding, SamplerName(i), binding.fetch_constant);
  }
  h += "\n";
  h += kWgslHelpers;
  if (uses_shared_memory_) {
    h += kWgslSharedMemoryHelpers;
  }
  if (!texture_bindings_.empty()) {
    h += kWgslTextureHelpers;
  }
  h += "\n";
  return h;
}

std::string WgslShaderTranslator::BuildEntryPoint(const std::string& main_body) const {
  const Shader& shader = current_shader();
  uint32_t interpolator_mask = GetModificationInterpolatorMask();
  std::string s;
  if (is_vertex_shader()) {
    s += "struct XeVertexOutput {\n";
    s += "  @builtin(position) @invariant position: vec4<f32>,\n";
    for (uint32_t i = 0; i < xenos::kMaxInterpolators; ++i) {
      if (interpolator_mask & (1u << i)) {
        s += fmt::format("  @location({}) interpolator_{}: vec4<f32>,\n", i, i);
      }
    }
    s += "}\n\n";
    s += "@vertex\n";
    s += "fn main(@builtin(vertex_index) xe_vertex_index: u32) -> XeVertexOutput {\n";
    s += main_body;
    s += "  var xe_output: XeVertexOutput;\n";
    s += "  xe_output.position = xe_position_out;\n";
    for (uint32_t i = 0; i < xenos::kMaxInterpolators; ++i) {
      if (interpolator_mask & (1u << i)) {
        s += fmt::format("  xe_output.interpolator_{} = xe_o{};\n", i, i);
      }
    }
    s += "  return xe_output;\n";
    s += "}\n";
    return s;
  }

  Modification modification = GetWgslModification();
  s += "struct XeFragmentInput {\n";
  s += "  @builtin(position) frag_coord: vec4<f32>,\n";
  if (uses_front_facing_) {
    s += "  @builtin(front_facing) front_facing: bool,\n";
  }
  for (uint32_t i = 0; i < xenos::kMaxInterpolators; ++i) {
    if (interpolator_mask & (1u << i)) {
      bool centroid = (modification.pixel.interpolators_centroid >> i) & 1;
      s += fmt::format("  @location({}){} interpolator_{}: vec4<f32>,\n", i,
                       centroid ? " @interpolate(perspective, centroid)" : "", i);
    }
  }
  s += "}\n\n";
  uint32_t colors = shader.writes_color_targets();
  bool has_outputs = colors || shader.writes_depth();
  if (has_outputs) {
    s += "struct XeFragmentOutput {\n";
    for (uint32_t i = 0; i < xenos::kMaxColorRenderTargets; ++i) {
      if (colors & (1u << i)) {
        s += fmt::format("  @location({}) color_{}: vec4<f32>,\n", i, i);
      }
    }
    if (shader.writes_depth()) {
      s += "  @builtin(frag_depth) depth: f32,\n";
    }
    s += "}\n\n";
  }
  s += "@fragment\n";
  s += fmt::format("fn main(xe_input: XeFragmentInput){} {{\n",
                   has_outputs ? " -> XeFragmentOutput" : "");
  s += main_body;
  if (has_outputs) {
    s += "  var xe_output: XeFragmentOutput;\n";
    for (uint32_t i = 0; i < xenos::kMaxColorRenderTargets; ++i) {
      if (colors & (1u << i)) {
        s += fmt::format("  xe_output.color_{} = xe_color_{};\n", i, i);
      }
    }
    if (shader.writes_depth()) {
      s += "  xe_output.depth = xe_depth;\n";
    }
    s += "  return xe_output;\n";
  }
  s += "}\n";
  return s;
}

// ---------------------------------------------------------------------------------------------
// Vertex shader interface.

void WgslShaderTranslator::EmitVertexPrologue() {
  Modification modification = GetWgslModification();
  if (modification.vertex.host_vertex_shader_type != Shader::HostVertexShaderType::kVertex) {
    // Domain (tessellation), memexport compute and point / rectangle expansion are not
    // implemented yet (docs/research/shader-translation.md, gaps).
    EmitTranslationError("WGSL: only HostVertexShaderType::kVertex is implemented");
  }
  if (modification.vertex.user_clip_plane_count) {
    AddWarning("WGSL: user clip planes are not implemented (needs clip_distances)");
  }
  Line("var xe_position: vec4<f32> = vec4<f32>(0.0);");
  // The edge flag is ignored; point size defaults to negative ("use the default").
  Line("var xe_point_size_edge_flag_kill_vertex: vec3<f32> = vec3<f32>(-1.0, 0.0, 0.0);");
  uint32_t interpolator_mask = GetModificationInterpolatorMask();
  for (uint32_t i = 0; i < xenos::kMaxInterpolators; ++i) {
    if (interpolator_mask & (1u << i)) {
      Line(fmt::format("var xe_o{}: vec4<f32> = vec4<f32>(0.0);", i));
    }
  }
  if (register_count()) {
    // The guest vertex index: endian-swapped (indices come from guest memory), with the base
    // index added, masked to 24 bits and clamped to the draw's range, as in the SPIR-V path.
    Line("var xe_index: u32 = xe_endian_swap(xe_vertex_index, xe_system.vertex_index_endian);");
    Line("xe_index = (xe_index + bitcast<u32>(xe_system.vertex_base_index)) & 0xFFFFFFu;");
    Line("xe_index = clamp(xe_index, xe_system.vertex_index_min, xe_system.vertex_index_max);");
    Line("xe_r[0] = vec4<f32>(f32(xe_index), 0.0, 0.0, 0.0);");
  }
}

void WgslShaderTranslator::EmitVertexEpilogue() {
  const Shader& shader = current_shader();
  Line("var xe_w: f32 = xe_position.w;");
  Line(fmt::format("if ((xe_system.flags & {}u) == 0u) {{ xe_w = 1.0 / xe_w; }}",
                   uint32_t(kSysFlag_WNotReciprocal)));
  Line("var xe_xyz: vec3<f32> = xe_position.xyz;");
  Line(fmt::format("if ((xe_system.flags & {}u) != 0u) {{ xe_xyz.x = xe_xyz.x * xe_w; "
                   "xe_xyz.y = xe_xyz.y * xe_w; }}",
                   uint32_t(kSysFlag_XYDividedByW)));
  Line(fmt::format("if ((xe_system.flags & {}u) != 0u) {{ xe_xyz.z = xe_xyz.z * xe_w; }}",
                   uint32_t(kSysFlag_ZDividedByW)));
  Line("xe_xyz = xe_xyz * xe_system.ndc_scale + xe_system.ndc_offset * xe_w;");
  if (shader.writes_point_size_edge_flag_kill_vertex() & 0b100) {
    // Killed vertices make the primitive's position NaN (no cull distances in WGSL, so the
    // AND mode kills like the OR mode).
    Line("if ((bitcast<u32>(xe_point_size_edge_flag_kill_vertex.z) & 0x7FFFFFFFu) != 0u) {"
         " xe_w = xe_nan(); }");
  }
  if (shader.writes_point_size_edge_flag_kill_vertex() & 0b001) {
    AddWarning("WGSL: vertex point size is ignored (point sprites are not expanded yet)");
  }
  Line("let xe_position_out: vec4<f32> = vec4<f32>(xe_xyz, xe_w);");
}

// ---------------------------------------------------------------------------------------------
// Pixel shader interface.

void WgslShaderTranslator::EmitPixelPrologue() {
  const Shader& shader = current_shader();
  Modification modification = GetWgslModification();
  if (modification.pixel.depth_stencil_mode > 1) {
    AddWarning("WGSL: float24 depth conversion is not implemented");
  }
  uint32_t param_gen_interpolator = GetPsParamGenInterpolator();
  uint32_t interpolator_mask = GetModificationInterpolatorMask();
  for (uint32_t i = 0; i < register_count(); ++i) {
    if (i == param_gen_interpolator) {
      continue;
    }
    if (i < xenos::kMaxInterpolators && (interpolator_mask & (1u << i))) {
      Line(fmt::format("xe_r[{}] = xe_input.interpolator_{};", i, i));
    } else {
      Line(fmt::format("xe_r[{}] = vec4<f32>(0.0);", i));
    }
  }
  if (param_gen_interpolator != UINT32_MAX) {
    // PsParamGen: |pixel position| with the sign bits telling the primitive type and facing.
    uses_frag_coord_ = true;
    Line("var xe_param_gen: vec4<f32> = vec4<f32>(abs(floor(xe_input.frag_coord.xy)), 0.0, 0.0);");
    if (!modification.pixel.param_gen_point) {
      uses_front_facing_ = true;
      Line(fmt::format(
          "if ((xe_system.flags & {}u) != 0u && !xe_input.front_facing) {{ xe_param_gen.x = "
          "-xe_param_gen.x; }}",
          uint32_t(kSysFlag_PrimitivePolygonal)));
      Line(fmt::format(
          "if ((xe_system.flags & {}u) != 0u) {{ xe_param_gen.z = bitcast<f32>(0x80000000u); }}",
          uint32_t(kSysFlag_PrimitiveLine)));
    } else {
      // Point sprite coordinates need point expansion, which is not implemented.
      AddWarning("WGSL: PsParamGen point coordinates are not implemented");
      Line("xe_param_gen.y = -xe_param_gen.y;");
    }
    Line(fmt::format("xe_r[{}] = xe_param_gen;", param_gen_interpolator));
  }
  for (uint32_t i = 0; i < xenos::kMaxColorRenderTargets; ++i) {
    if (shader.writes_color_target(i)) {
      Line(fmt::format("var xe_color_{}: vec4<f32> = vec4<f32>(0.0);", i));
    }
  }
  if (shader.writes_depth()) {
    Line("var xe_depth: f32 = 0.0;");
  }
}

void WgslShaderTranslator::EmitPixelEpilogue() {
  const Shader& shader = current_shader();
  Modification modification = GetWgslModification();
  bool early_hint =
      modification.pixel.depth_stencil_mode == 1 && shader.implicit_early_z_write_allowed();
  if (shader.writes_color_target(0) && !early_hint) {
    // Alpha test (SpirvShaderTranslator::CompleteFragmentShaderInMain, host render targets).
    Line(fmt::format("let xe_alpha_test: u32 = (xe_system.flags >> {}u) & 7u;",
                     uint32_t(kSysFlag_AlphaPassIfLess_Shift)));
    OpenScope("if (xe_alpha_test != 7u) {");
    Line("let xe_alpha: f32 = xe_color_0.w;");
    Line("let xe_alpha_ref: f32 = xe_system.alpha_test_reference;");
    Line("var xe_alpha_pass: bool = xe_alpha != xe_alpha_ref;");
    OpenScope("if (xe_alpha_test != 5u) {");
    Line("xe_alpha_pass = ((xe_alpha_test & 1u) != 0u && xe_alpha < xe_alpha_ref) ||"
         " ((xe_alpha_test & 2u) != 0u && xe_alpha == xe_alpha_ref) ||"
         " ((xe_alpha_test & 4u) != 0u && xe_alpha > xe_alpha_ref);");
    CloseScope();
    Line("if (!xe_alpha_pass) { discard; }");
    CloseScope();
  }
  for (uint32_t i = 0; i < xenos::kMaxColorRenderTargets; ++i) {
    if (!shader.writes_color_target(i)) {
      continue;
    }
    // Exponent bias after the alpha test, then PWL gamma for gamma render targets.
    Line(fmt::format("xe_color_{0} = xe_color_{0} * xe_system.color_exp_bias[{0}];", i));
    Line(fmt::format(
        "if ((xe_system.flags & {1}u) != 0u) {{ xe_color_{0} = "
        "vec4<f32>(xe_linear_to_pwl_gamma(xe_color_{0}.xyz), xe_color_{0}.w); }}",
        i, uint32_t(kSysFlag_ConvertColor0ToGamma) << i));
  }
}

// ---------------------------------------------------------------------------------------------
// Control flow.

void WgslShaderTranslator::ProcessLabel(uint32_t cf_index) {
  if (cf_index == 0) {
    return;
  }
  CloseExecConditionals();
  // Fall through into the next label's block.
  Line(fmt::format("xe_pc = {};", cf_index));
  CloseScope();
  OpenScope(fmt::format("if (xe_pc == {}) {{", cf_index));
}

void WgslShaderTranslator::ProcessExecInstructionBegin(const ParsedExecInstruction& instr) {
  UpdateExecConditionals(instr.type, instr.bool_constant_index, instr.condition);
}

void WgslShaderTranslator::ProcessExecInstructionEnd(const ParsedExecInstruction& instr) {
  if (instr.is_end) {
    CloseInstructionPredication();
    Terminate("break;");
  }
  UpdateExecConditionals(instr.type, instr.bool_constant_index, instr.condition);
}

std::string WgslShaderTranslator::BoolConstantExpression(uint32_t bool_constant_index) const {
  return fmt::format("((xe_bool_loop.bool_constants[{}][{}] & {:#x}u) != 0u)",
                     bool_constant_index >> 7, (bool_constant_index >> 5) & 3,
                     uint32_t(1) << (bool_constant_index & 31));
}

std::string WgslShaderTranslator::LoopConstantExpression(uint32_t loop_constant_index) const {
  return fmt::format("xe_bool_loop.loop_constants[{}][{}]", loop_constant_index >> 2,
                     loop_constant_index & 3);
}

void WgslShaderTranslator::ProcessLoopStartInstruction(const ParsedLoopStartInstruction& instr) {
  CloseExecConditionals();
  uses_bool_loop_constants_ = true;
  if (!has_labels_) {
    EmitTranslationError("WGSL: loop without labels");
    return;
  }
  std::string loop_constant = Temp("u32", LoopConstantExpression(instr.loop_constant_index));
  // Push the count (bits 0:7) and aL (bits 8:15, or the current aL if repeating).
  Line(fmt::format("xe_loop_count = vec4<u32>({} & 0xFFu, xe_loop_count.xyz);", loop_constant));
  if (instr.is_repeat) {
    Line("xe_aL = vec4<i32>(xe_aL.x, xe_aL.xyz);");
  } else {
    Line(fmt::format("xe_aL = vec4<i32>(i32(({} >> 8u) & 0xFFu), xe_aL.xyz);", loop_constant));
  }
  // The count is checked at the end - skip the loop if it's 0.
  OpenScope("if (xe_loop_count.x == 0u) {");
  Line(fmt::format("xe_pc = {};", instr.loop_skip_address));
  Terminate("continue;");
  CloseScope();
}

void WgslShaderTranslator::ProcessLoopEndInstruction(const ParsedLoopEndInstruction& instr) {
  CloseExecConditionals();
  uses_bool_loop_constants_ = true;
  if (!has_labels_) {
    EmitTranslationError("WGSL: loop without labels");
    return;
  }
  std::string count = Temp("u32", "xe_loop_count.x - 1u");
  // Predicated break works like break if (count == 0 || [!]p0).
  std::string continue_condition;
  if (instr.is_predicated_break) {
    continue_condition = instr.predicate_condition
                             ? fmt::format("({} != 0u) && !xe_p0", count)
                             : fmt::format("({} != 0u) && xe_p0", count);
  } else {
    continue_condition = fmt::format("{} != 0u", count);
  }
  OpenScope(fmt::format("if ({}) {{", continue_condition));
  Line(fmt::format("xe_loop_count.x = {};", count));
  Line(fmt::format("xe_aL.x = xe_aL.x + extractBits(bitcast<i32>({}), 16u, 8u);",
                   LoopConstantExpression(instr.loop_constant_index)));
  Line(fmt::format("xe_pc = {};", instr.loop_body_address));
  Terminate("continue;");
  CloseScope();
  // Break: pop the loop counter and aL stacks.
  Line("xe_loop_count = vec4<u32>(xe_loop_count.yzw, 0u);");
  Line("xe_aL = vec4<i32>(xe_aL.yzw, 0);");
}

void WgslShaderTranslator::ProcessCallInstruction(const ParsedCallInstruction& instr) {
  // Not implemented in the SPIR-V translator either (rare; ignored there too).
  AddWarning("WGSL: call/return are not implemented (ignored, as in the SPIR-V path)");
}

void WgslShaderTranslator::ProcessReturnInstruction(const ParsedReturnInstruction& instr) {
  AddWarning("WGSL: call/return are not implemented (ignored, as in the SPIR-V path)");
}

void WgslShaderTranslator::ProcessJumpInstruction(const ParsedJumpInstruction& instr) {
  ParsedExecInstruction::Type type;
  if (instr.type == ParsedJumpInstruction::Type::kConditional) {
    type = ParsedExecInstruction::Type::kConditional;
  } else if (instr.type == ParsedJumpInstruction::Type::kPredicated) {
    type = ParsedExecInstruction::Type::kPredicated;
  } else {
    type = ParsedExecInstruction::Type::kUnconditional;
  }
  UpdateExecConditionals(type, instr.bool_constant_index, instr.condition);
  CloseInstructionPredication();
  if (!has_labels_) {
    EmitTranslationError("WGSL: jump without labels");
    return;
  }
  Line(fmt::format("xe_pc = {};", instr.target_address));
  Terminate("continue;");
}

void WgslShaderTranslator::ProcessAllocInstruction(const ParsedAllocInstruction& instr,
                                                   uint8_t export_eM) {
  if (export_eM || (instr.type == ucode::AllocType::kMemory &&
                    current_shader().memexport_eM_written())) {
    AddWarning("WGSL: memory export is not implemented (writes are dropped)");
  }
}

void WgslShaderTranslator::UpdateExecConditionals(ParsedExecInstruction::Type type,
                                                  uint32_t bool_constant_index, bool condition) {
  // Merge with the previous exec if the condition is the same (see the SPIR-V translator).
  if (type == ParsedExecInstruction::Type::kConditional) {
    if (exec_conditional_open_ && cf_exec_bool_constant_or_predicate_ == bool_constant_index &&
        cf_exec_condition_ == condition) {
      return;
    }
  } else if (type == ParsedExecInstruction::Type::kPredicated) {
    if (!cf_exec_predicate_written_ && exec_conditional_open_ &&
        cf_exec_bool_constant_or_predicate_ == kCfExecBoolConstantPredicate &&
        cf_exec_condition_ == condition) {
      return;
    }
  } else {
    if (!exec_conditional_open_) {
      return;
    }
  }

  CloseExecConditionals();

  if (type == ParsedExecInstruction::Type::kUnconditional) {
    return;
  }
  std::string condition_expression;
  if (type == ParsedExecInstruction::Type::kConditional) {
    uses_bool_loop_constants_ = true;
    condition_expression = BoolConstantExpression(bool_constant_index);
    cf_exec_bool_constant_or_predicate_ = bool_constant_index;
  } else {
    condition_expression = "xe_p0";
    cf_exec_bool_constant_or_predicate_ = kCfExecBoolConstantPredicate;
  }
  cf_exec_condition_ = condition;
  OpenScope(fmt::format("if ({}{}) {{", condition ? "" : "!", condition_expression));
  exec_conditional_open_ = true;
}

void WgslShaderTranslator::UpdateInstructionPredication(bool predicated, bool condition) {
  if (!predicated) {
    CloseInstructionPredication();
    return;
  }
  if (instruction_predicate_open_) {
    if (cf_instruction_predicate_condition_ == condition) {
      return;
    }
    CloseInstructionPredication();
  }
  // The exec already checks the same predicate value, unless a setp changed it since.
  if (!cf_exec_predicate_written_ && exec_conditional_open_ &&
      cf_exec_bool_constant_or_predicate_ == kCfExecBoolConstantPredicate &&
      cf_exec_condition_ == condition) {
    return;
  }
  cf_instruction_predicate_condition_ = condition;
  OpenScope(fmt::format("if ({}xe_p0) {{", condition ? "" : "!"));
  instruction_predicate_open_ = true;
}

void WgslShaderTranslator::CloseInstructionPredication() {
  if (!instruction_predicate_open_) {
    return;
  }
  CloseScope();
  instruction_predicate_open_ = false;
}

void WgslShaderTranslator::CloseExecConditionals() {
  CloseInstructionPredication();
  if (exec_conditional_open_) {
    CloseScope();
    exec_conditional_open_ = false;
  }
  cf_exec_predicate_written_ = false;
}

// ---------------------------------------------------------------------------------------------
// Operands and results.

std::string WgslShaderTranslator::StorageIndex(InstructionStorageAddressingMode mode,
                                               uint32_t index, bool is_float_constant) {
  switch (mode) {
    case InstructionStorageAddressingMode::kAbsolute: {
      uint32_t static_index = index;
      if (is_float_constant) {
        static_index =
            current_shader().constant_register_map().GetPackedFloatConstantIndex(index);
        if (static_index == UINT32_MAX) {
          static_index = 0;
        }
      }
      return fmt::format("{}", static_index);
    }
    case InstructionStorageAddressingMode::kAddressRegisterRelative:
      return index ? fmt::format("(xe_a0 + {})", index) : std::string("xe_a0");
    case InstructionStorageAddressingMode::kLoopRelative:
      return index ? fmt::format("(xe_aL.x + {})", index) : std::string("xe_aL.x");
  }
  return "0";
}

std::string WgslShaderTranslator::LoadOperandStorage(const InstructionOperand& operand) {
  switch (operand.storage_source) {
    case InstructionStorageSource::kRegister:
      if (!register_count()) {
        return "vec4<f32>(0.0)";
      }
      return Temp("vec4<f32>",
                  fmt::format("xe_r[{}]", StorageIndex(operand.storage_addressing_mode,
                                                       operand.storage_index, false)));
    case InstructionStorageSource::kConstantFloat:
      if (!float_constant_array_size_) {
        return "vec4<f32>(0.0)";
      }
      return Temp("vec4<f32>",
                  fmt::format("xe_float_constants[{}]",
                              StorageIndex(operand.storage_addressing_mode,
                                           operand.storage_index, true)));
    default:
      EmitTranslationError("WGSL: unexpected operand storage source");
      return "vec4<f32>(0.0)";
  }
}

std::string WgslShaderTranslator::ApplyModifiers(const std::string& value,
                                                 const InstructionOperand& operand) {
  std::string result = value;
  if (operand.is_absolute_value) {
    result = fmt::format("abs({})", result);
  }
  if (operand.is_negated) {
    result = fmt::format("(-{})", result);
  }
  return result;
}

std::string WgslShaderTranslator::OperandVector(const std::string& storage,
                                                const InstructionOperand& operand) {
  std::string swizzle;
  for (uint32_t i = 0; i < 4; ++i) {
    SwizzleSource component = operand.GetComponent(i);
    swizzle += GetCharForSwizzle(component <= SwizzleSource::kW ? component : SwizzleSource::kX);
  }
  std::string value = swizzle == "xyzw" ? storage : fmt::format("{}.{}", storage, swizzle);
  return ApplyModifiers(value, operand);
}

std::string WgslShaderTranslator::OperandScalar(const std::string& storage,
                                                const InstructionOperand& operand,
                                                uint32_t component) {
  SwizzleSource source = operand.GetComponent(component);
  if (source > SwizzleSource::kW) {
    source = SwizzleSource::kX;
  }
  return ApplyModifiers(fmt::format("{}.{}", storage, GetCharForSwizzle(source)), operand);
}

void WgslShaderTranslator::StoreResult(const InstructionResult& result, const std::string& value,
                                       bool is_scalar) {
  uint32_t used_write_mask = result.GetUsedWriteMask();
  if (!used_write_mask) {
    return;
  }
  const Shader& shader = current_shader();
  bool is_clamped = result.is_clamped;
  std::string target;
  uint32_t target_component_count = 4;
  switch (result.storage_target) {
    case InstructionStorageTarget::kNone:
      return;
    case InstructionStorageTarget::kRegister:
      if (!register_count()) {
        return;
      }
      target = fmt::format("xe_r[{}]",
                           StorageIndex(result.storage_addressing_mode, result.storage_index,
                                        false));
      break;
    case InstructionStorageTarget::kInterpolator:
      if (!is_vertex_shader() ||
          !(GetModificationInterpolatorMask() & (1u << result.storage_index))) {
        return;
      }
      target = fmt::format("xe_o{}", result.storage_index);
      break;
    case InstructionStorageTarget::kPosition:
      target = "xe_position";
      break;
    case InstructionStorageTarget::kPointSizeEdgeFlagKillVertex:
      target = "xe_point_size_edge_flag_kill_vertex";
      target_component_count = 3;
      break;
    case InstructionStorageTarget::kColor:
      if (!shader.writes_color_target(result.storage_index)) {
        return;
      }
      target = fmt::format("xe_color_{}", result.storage_index);
      break;
    case InstructionStorageTarget::kDepth:
      if (!shader.writes_depth()) {
        return;
      }
      target = "xe_depth";
      target_component_count = 1;
      // Guest depth output is expected to be [0, 1].
      is_clamped = true;
      break;
    case InstructionStorageTarget::kExportAddress:
    case InstructionStorageTarget::kExportData:
      AddWarning("WGSL: memory export is not implemented (writes are dropped)");
      return;
  }

  uint32_t constant_values;
  uint32_t constant_components = result.GetUsedConstantComponents(constant_values);
  if (value.empty()) {
    constant_components = used_write_mask;
  }
  uint32_t non_constant_components = used_write_mask & ~constant_components;
  std::string source = value;
  if (non_constant_components && is_clamped) {
    source = Temp(is_scalar ? "f32" : "vec4<f32>",
                  fmt::format("{}({})", is_scalar ? "xe_sat_s" : "xe_sat", source));
  }
  if (!is_scalar && target_component_count == 4 && non_constant_components == 0b1111 &&
      result.IsStandardSwizzle()) {
    Line(fmt::format("{} = {};", target, source));
    return;
  }
  std::string components[4];
  for (uint32_t i = 0; i < target_component_count; ++i) {
    uint32_t bit = 1u << i;
    if (!(used_write_mask & bit)) {
      components[i] = target_component_count > 1
                          ? fmt::format("{}.{}", target, GetCharForComponentIndex(i))
                          : target;
    } else if (constant_components & bit) {
      components[i] = (constant_values & bit) ? "1.0" : "0.0";
    } else if (is_scalar) {
      components[i] = source;
    } else {
      SwizzleSource swizzle = result.components[i];
      components[i] = fmt::format("{}.{}", source, GetCharForSwizzle(swizzle));
    }
  }
  if (target_component_count == 1) {
    Line(fmt::format("{} = {};", target, components[0]));
  } else {
    std::string list;
    for (uint32_t i = 0; i < target_component_count; ++i) {
      if (i) {
        list += ", ";
      }
      list += components[i];
    }
    Line(fmt::format("{} = vec{}<f32>({});", target, target_component_count, list));
  }
}

}  // namespace rex::graphics
