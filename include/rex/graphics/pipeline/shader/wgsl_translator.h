#pragma once
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
 * WGSL shader translator, written for MCLA-Reborn (T-028) after the semantics of Xenia's
 * SpirvShaderTranslator as adapted by ReXGlue (spirv_translator*.cpp, BSD-3-Clause, notices
 * above). It walks the same ShaderTranslator callbacks over the same ucode analysis and emits
 * WGSL text for a WebGPU backend instead of SPIR-V.
 * MCLA-Reborn's additions: Not yet licensed, MCLA-Reborn decides before any release (D-009).
 *
 * Built only by MCLA-Reborn's gpu-webgpu project, or by the SDK with REXGLUE_WGSL_TRANSLATOR=ON
 * (off by default, so the Vulkan and D3D12 builds are unaffected).
 */

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include <rex/graphics/pipeline/shader/translator.h>
#include <rex/graphics/xenos.h>

namespace rex::graphics {

class WgslShaderTranslator : public ShaderTranslator {
 public:
  // Bump when the generated WGSL, the binding layout, the system constants or the Modification
  // layout change: it is part of every shader cache key.
  static constexpr uint32_t kVersion = 1;

  // Translation-time state, the WGSL counterpart of SpirvShaderTranslator::Modification.
  union Modification {
    struct {
      // Interpolators written by the vertex shader and needed by the pixel shader.
      uint32_t interpolator_mask : xenos::kMaxInterpolators;
      // Dynamically indexable register count from SQ_PROGRAM_CNTL.
      uint32_t dynamic_addressable_register_count : 8;
      // PA_CL_CLIP_CNTL vertex kill AND mode (killed through a NaN position either way, as
      // WGSL has no cull distances).
      uint32_t vertex_kill_and : 1;
      uint32_t user_clip_plane_count : 3;
      uint32_t : 4;
      // Only kVertex is implemented (see docs/research/shader-translation.md).
      Shader::HostVertexShaderType host_vertex_shader_type : Shader::kHostVertexShaderTypeBitCount;
    } vertex;
    struct {
      uint32_t interpolator_mask : xenos::kMaxInterpolators;
      uint32_t interpolators_centroid : xenos::kMaxInterpolators;
      uint32_t dynamic_addressable_register_count : 8;
      uint32_t param_gen_enable : 1;
      uint32_t param_gen_interpolator : 4;
      uint32_t param_gen_point : 1;
      // Early fragment tests hint (1) is the only mode besides 0; float24 depth conversion is
      // not implemented.
      uint32_t depth_stencil_mode : 3;
    } pixel;
    uint64_t value = 0;

    explicit Modification(uint64_t modification_value = 0) : value(modification_value) {}
  };
  static_assert(sizeof(Modification) == sizeof(uint64_t));

  // System constant flags (bit positions in SystemConstants::flags).
  enum : uint32_t {
    kSysFlag_XYDividedByW = 1u << 0,
    kSysFlag_ZDividedByW = 1u << 1,
    kSysFlag_WNotReciprocal = 1u << 2,
    kSysFlag_PrimitivePolygonal = 1u << 3,
    kSysFlag_PrimitiveLine = 1u << 4,
    // Three bits: pass if less (bit 5), equal (6), greater (7), like xenos::CompareFunction.
    kSysFlag_AlphaPassIfLess_Shift = 5,
    kSysFlag_AlphaPassIfLess = 1u << 5,
    kSysFlag_AlphaPassIfEqual = 1u << 6,
    kSysFlag_AlphaPassIfGreater = 1u << 7,
    kSysFlag_ConvertColor0ToGamma_Shift = 8,
    kSysFlag_ConvertColor0ToGamma = 1u << 8,
  };

  // Uniform buffer at @group(1) @binding(0), WGSL uniform layout (vec3 aligned to 16 bytes).
  struct SystemConstants {
    uint32_t flags;                     // 0
    uint32_t vertex_index_endian;       // 4, xenos::Endian
    int32_t vertex_base_index;          // 8
    uint32_t vertex_index_min;          // 12
    uint32_t vertex_index_max;          // 16
    float alpha_test_reference;         // 20
    uint32_t padding_0[2];              // 24
    float ndc_scale[3];                 // 32
    float point_vertex_diameter_min;    // 44
    float ndc_offset[3];                // 48
    float point_vertex_diameter_max;    // 60
    float color_exp_bias[4];            // 64
    // Byte per fetch constant: post-swizzle xenos::TextureSign, 2 bits per component.
    uint32_t texture_swizzled_signs[8];  // 80
    // 12 bits per fetch constant (two per word, bits 0:11 and 12:23): 3 bits per result
    // component, 0-3 = source RGBA, 4 = 0, 5 = 1, guest and host swizzles combined.
    uint32_t texture_swizzles[16];  // 112
    float user_clip_planes[6][4];   // 176 (reserved: WGSL clip_distances is not used yet)
  };
  static_assert(sizeof(SystemConstants) == 272);

  // Binding layout (bind groups mirror SpirvShaderTranslator's descriptor sets; WebGPU's
  // maxBindGroups is 4):
  //   @group(0) @binding(0)  shared memory, array<u32>, read-only storage (512 MiB mirror)
  //   @group(1) @binding(0)  system constants          @binding(1) float constants (vertex)
  //             @binding(2)  float constants (pixel)   @binding(3) bool and loop constants
  //             @binding(4)  fetch constants
  //   @group(2)  vertex shader textures, then samplers  (TextureBinding/SamplerBinding::binding)
  //   @group(3)  pixel shader textures, then samplers
  static constexpr uint32_t kBindGroupSharedMemory = 0;
  static constexpr uint32_t kBindGroupConstants = 1;
  static constexpr uint32_t kBindGroupTexturesVertex = 2;
  static constexpr uint32_t kBindGroupTexturesPixel = 3;
  enum ConstantBinding : uint32_t {
    kConstantBindingSystem,
    kConstantBindingFloatVertex,
    kConstantBindingFloatPixel,
    kConstantBindingBoolLoop,
    kConstantBindingFetch,
  };

  enum class TextureViewDimension : uint32_t { k2DArray, k3D, kCube };

  struct TextureBinding {
    uint32_t binding;
    uint32_t fetch_constant;
    // What the instruction asked for (stacked and 3D are separate bindings).
    xenos::FetchOpDimension fetch_dimension;
    TextureViewDimension view_dimension;
  };
  struct SamplerBinding {
    uint32_t binding;
    uint32_t fetch_constant;
    xenos::TextureFilter mag_filter;
    xenos::TextureFilter min_filter;
    xenos::TextureFilter mip_filter;
    xenos::AnisoFilter aniso_filter;
  };

  WgslShaderTranslator() = default;

  uint64_t GetDefaultVertexShaderModification(
      uint32_t dynamic_addressable_register_count,
      Shader::HostVertexShaderType host_vertex_shader_type =
          Shader::HostVertexShaderType::kVertex) const override;
  uint64_t GetDefaultPixelShaderModification(
      uint32_t dynamic_addressable_register_count) const override;

  // Valid after TranslateAnalyzedShader until the next translation.
  const std::vector<TextureBinding>& texture_bindings() const { return texture_bindings_; }
  const std::vector<SamplerBinding>& sampler_bindings() const { return sampler_bindings_; }
  bool uses_shared_memory() const { return uses_shared_memory_; }
  // Number of vec4 float constants the shader declares (0 if none).
  uint32_t float_constant_array_size() const { return float_constant_array_size_; }

 protected:
  void Reset() override;
  uint32_t GetModificationRegisterCount() const override;
  void StartTranslation() override;
  std::vector<uint8_t> CompleteTranslation() override;

  void ProcessLabel(uint32_t cf_index) override;
  void ProcessExecInstructionBegin(const ParsedExecInstruction& instr) override;
  void ProcessExecInstructionEnd(const ParsedExecInstruction& instr) override;
  void ProcessLoopStartInstruction(const ParsedLoopStartInstruction& instr) override;
  void ProcessLoopEndInstruction(const ParsedLoopEndInstruction& instr) override;
  void ProcessCallInstruction(const ParsedCallInstruction& instr) override;
  void ProcessReturnInstruction(const ParsedReturnInstruction& instr) override;
  void ProcessJumpInstruction(const ParsedJumpInstruction& instr) override;
  void ProcessAllocInstruction(const ParsedAllocInstruction& instr, uint8_t export_eM) override;
  void ProcessVertexFetchInstruction(const ParsedVertexFetchInstruction& instr) override;
  void ProcessTextureFetchInstruction(const ParsedTextureFetchInstruction& instr) override;
  void ProcessAluInstruction(const ParsedAluInstruction& instr,
                             uint8_t memexport_eM_potentially_written_before) override;

 private:
  // Text emission. Code after a break/continue in the same scope is unreachable and dropped.
  void Line(const std::string& text);
  void OpenScope(const std::string& header);
  void CloseScope();
  void Terminate(const std::string& statement);
  bool IsDead() const { return dead_; }
  std::string Temp(const std::string& type, const std::string& expression);

  Modification GetWgslModification() const {
    return Modification(current_translation().modification());
  }
  uint32_t GetModificationInterpolatorMask() const;
  uint32_t GetPsParamGenInterpolator() const;

  void EmitVertexPrologue();
  void EmitVertexEpilogue();
  void EmitPixelPrologue();
  void EmitPixelEpilogue();
  std::string BuildHeader() const;
  std::string BuildEntryPoint(const std::string& main_body) const;

  // Control flow (same merging rules as SpirvShaderTranslator).
  void UpdateExecConditionals(ParsedExecInstruction::Type type, uint32_t bool_constant_index,
                              bool condition);
  void UpdateInstructionPredication(bool predicated, bool condition);
  void CloseInstructionPredication();
  void CloseExecConditionals();
  std::string BoolConstantExpression(uint32_t bool_constant_index) const;
  std::string LoopConstantExpression(uint32_t loop_constant_index) const;

  // Operands and results. Values are WGSL expressions: vec4<f32> for vectors, f32 for scalars.
  std::string StorageIndex(InstructionStorageAddressingMode mode, uint32_t index,
                           bool is_float_constant);
  // The operand's storage (unswizzled, unmodified), as a vec4<f32> temporary.
  std::string LoadOperandStorage(const InstructionOperand& operand);
  std::string ApplyModifiers(const std::string& value, const InstructionOperand& operand);
  // All four components with the operand's swizzle and modifiers applied (vec4<f32>).
  std::string OperandVector(const std::string& storage, const InstructionOperand& operand);
  // One component (swizzled index `component`) with modifiers applied (f32).
  std::string OperandScalar(const std::string& storage, const InstructionOperand& operand,
                            uint32_t component);
  // value: vec4 with result component i at index i, or an f32 to replicate, or "" for none.
  void StoreResult(const InstructionResult& result, const std::string& value, bool is_scalar);

  std::string ProcessVectorAluOperation(const ParsedAluInstruction& instr, bool& is_scalar,
                                        bool& predicate_written);
  std::string ProcessScalarAluOperation(const ParsedAluInstruction& instr,
                                        bool& predicate_written);
  void KillPixel(const std::string& condition);

  std::string FetchConstantWord(uint32_t word_index) const;
  size_t FindOrAddTextureBinding(uint32_t fetch_constant, xenos::FetchOpDimension fetch_dimension,
                                 TextureViewDimension view_dimension);
  size_t FindOrAddSamplerBinding(uint32_t fetch_constant, xenos::TextureFilter mag_filter,
                                 xenos::TextureFilter min_filter, xenos::TextureFilter mip_filter,
                                 xenos::AnisoFilter aniso_filter);
  std::string TextureName(size_t binding_index) const;
  std::string SamplerName(size_t binding_index) const;

  void AddWarning(const char* message);

  // Output.
  std::string body_;
  uint32_t indent_ = 1;
  bool dead_ = false;
  std::vector<bool> scope_dead_stack_;
  uint32_t temp_counter_ = 0;

  // Analysis-derived per-translation facts.
  bool has_labels_ = false;
  bool uses_shared_memory_ = false;
  bool uses_fetch_constants_ = false;
  bool uses_bool_loop_constants_ = false;
  bool uses_front_facing_ = false;
  bool uses_frag_coord_ = false;
  bool uses_derivatives_ = false;
  uint32_t float_constant_array_size_ = 0;
  std::vector<TextureBinding> texture_bindings_;
  std::vector<SamplerBinding> sampler_bindings_;
  std::vector<std::string> warnings_;

  // Control flow state.
  bool exec_conditional_open_ = false;
  bool instruction_predicate_open_ = false;
  uint32_t cf_exec_bool_constant_or_predicate_ = 0;
  static constexpr uint32_t kCfExecBoolConstantPredicate = UINT32_MAX;
  bool cf_exec_condition_ = false;
  bool cf_instruction_predicate_condition_ = false;
  bool cf_exec_predicate_written_ = false;
};

}  // namespace rex::graphics
