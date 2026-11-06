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
 * WGSL shader translator (MCLA-Reborn, T-028): ALU instructions, with the semantics of
 * spirv_translator_alu.cpp (Shader Model 3 multiplication and min/max NaN rules, the
 * clamping reciprocal variants, predicate and kill instructions). Values are computed on all
 * four components and masked on store. MCLA-Reborn's additions: Not yet licensed (D-009).
 */

#include <rex/graphics/pipeline/shader/wgsl_translator.h>

#include <cfloat>

#include <fmt/format.h>

#include <rex/assert.h>

#include "wgsl_translator_util.h"

namespace rex::graphics {

using namespace wgsl;

namespace {

// Comparison operators: Ord for ==, >, >=, <; != is unordered in WGSL like FUnordNotEqual.
const char* kCompareEq = "==";
const char* kCompareNe = "!=";
const char* kCompareGt = ">";
const char* kCompareGe = ">=";

}  // namespace

void WgslShaderTranslator::KillPixel(const std::string& condition) {
  // WGSL discard demotes the invocation to a helper (derivatives keep working), like
  // OpDemoteToHelperInvocation in the SPIR-V path.
  if (!is_pixel_shader()) {
    return;
  }
  Line(fmt::format("if ({}) {{ discard; }}", condition));
}

void WgslShaderTranslator::ProcessAluInstruction(const ParsedAluInstruction& instr,
                                                 uint8_t memexport_eM_potentially_written_before) {
  if (instr.IsNop()) {
    return;
  }
  UpdateInstructionPredication(instr.is_predicated, instr.predicate_condition);

  // Both operations read their operands before either result is stored.
  bool vector_is_scalar = false;
  bool predicate_written_vector = false;
  std::string vector_result =
      ProcessVectorAluOperation(instr, vector_is_scalar, predicate_written_vector);
  bool predicate_written_scalar = false;
  std::string scalar_result = ProcessScalarAluOperation(instr, predicate_written_scalar);
  if (!scalar_result.empty()) {
    Line(fmt::format("xe_ps = {};", scalar_result));
  } else if (instr.scalar_result.GetUsedWriteMask()) {
    // retain_prev.
    scalar_result = Temp("f32", "xe_ps");
  }

  StoreResult(instr.vector_and_constant_result, vector_result, vector_is_scalar);
  StoreResult(instr.scalar_result, scalar_result, true);

  if (predicate_written_vector || predicate_written_scalar) {
    cf_exec_predicate_written_ = true;
    CloseInstructionPredication();
  }
}

std::string WgslShaderTranslator::ProcessVectorAluOperation(const ParsedAluInstruction& instr,
                                                            bool& is_scalar,
                                                            bool& predicate_written) {
  is_scalar = false;
  predicate_written = false;
  uint32_t used_result_components = instr.vector_and_constant_result.GetUsedResultComponents();
  if (!used_result_components &&
      !ucode::GetAluVectorOpcodeInfo(instr.vector_opcode).changed_state) {
    return std::string();
  }

  uint32_t operand_count =
      instr.vector_opcode == ucode::AluVectorOpcode::kCube ? 1 : instr.vector_operand_count;
  std::string storage[3];
  for (uint32_t i = 0; i < operand_count; ++i) {
    // The same register or constant read twice (mov as max a, a): load it once.
    if (i && instr.vector_operands[i].storage_source == instr.vector_operands[0].storage_source &&
        instr.vector_operands[i].storage_index == instr.vector_operands[0].storage_index &&
        instr.vector_operands[i].storage_addressing_mode ==
            instr.vector_operands[0].storage_addressing_mode) {
      storage[i] = storage[0];
      continue;
    }
    storage[i] = LoadOperandStorage(instr.vector_operands[i]);
  }
  auto operand = [&](uint32_t i) { return OperandVector(storage[i], instr.vector_operands[i]); };
  auto operand_scalar = [&](uint32_t i, uint32_t component) {
    return OperandScalar(storage[i], instr.vector_operands[i], component);
  };
  const char* v4 = "vec4<f32>";

  switch (instr.vector_opcode) {
    case ucode::AluVectorOpcode::kAdd:
      return Temp(v4, fmt::format("{} + {}", operand(0), operand(1)));
    case ucode::AluVectorOpcode::kMul:
      return Temp(v4, fmt::format("xe_mul({}, {})", operand(0), operand(1)));
    case ucode::AluVectorOpcode::kMad:
      // Not fused, and not `0 + c` -> `c` (+0 + -0 must be +0).
      return Temp(v4, fmt::format("xe_mul({}, {}) + {}", operand(0), operand(1), operand(2)));

    case ucode::AluVectorOpcode::kMax:
    case ucode::AluVectorOpcode::kMin:
    case ucode::AluVectorOpcode::kMaxA: {
      std::string a = Temp(v4, operand(0));
      if (instr.vector_opcode == ucode::AluVectorOpcode::kMaxA) {
        // a0 = (int)clamp(floor(src0.w + 0.5), -256.0, 255.0)
        Line(fmt::format("xe_a0 = i32(clamp(floor({}.w + 0.5), -256.0, 255.0));", a));
        if (!used_result_components) {
          return std::string();
        }
      }
      if (instr.vector_operands[0].GetIdenticalComponents(instr.vector_operands[1]) == 0b1111) {
        // max/min of an operand with itself: the common encoding of mov.
        return a;
      }
      std::string b = Temp(v4, operand(1));
      // Shader Model 3 NaN behavior: a op b ? a : b.
      const char* op = instr.vector_opcode == ucode::AluVectorOpcode::kMin ? "<" : ">=";
      return Temp(v4, fmt::format("select({1}, {0}, {0} {2} {1})", a, b, op));
    }

    case ucode::AluVectorOpcode::kSeq:
    case ucode::AluVectorOpcode::kSgt:
    case ucode::AluVectorOpcode::kSge:
    case ucode::AluVectorOpcode::kSne: {
      const char* op = kCompareEq;
      if (instr.vector_opcode == ucode::AluVectorOpcode::kSgt) {
        op = kCompareGt;
      } else if (instr.vector_opcode == ucode::AluVectorOpcode::kSge) {
        op = kCompareGe;
      } else if (instr.vector_opcode == ucode::AluVectorOpcode::kSne) {
        op = kCompareNe;
      }
      return Temp(v4, fmt::format("select(vec4<f32>(0.0), vec4<f32>(1.0), {} {} {})", operand(0),
                                  op, operand(1)));
    }

    case ucode::AluVectorOpcode::kFrc:
      return Temp(v4, fmt::format("fract({})", operand(0)));
    case ucode::AluVectorOpcode::kTrunc:
      return Temp(v4, fmt::format("trunc({})", operand(0)));
    case ucode::AluVectorOpcode::kFloor:
      return Temp(v4, fmt::format("floor({})", operand(0)));

    case ucode::AluVectorOpcode::kCndEq:
    case ucode::AluVectorOpcode::kCndGe:
    case ucode::AluVectorOpcode::kCndGt: {
      const char* op = kCompareEq;
      if (instr.vector_opcode == ucode::AluVectorOpcode::kCndGe) {
        op = kCompareGe;
      } else if (instr.vector_opcode == ucode::AluVectorOpcode::kCndGt) {
        op = kCompareGt;
      }
      return Temp(v4, fmt::format("select({}, {}, {} {} vec4<f32>(0.0))", operand(2), operand(1),
                                  operand(0), op));
    }

    case ucode::AluVectorOpcode::kDp4:
    case ucode::AluVectorOpcode::kDp3:
    case ucode::AluVectorOpcode::kDp2Add: {
      // Not dot(): a predictable addition order, with the SM3 multiplication rule.
      uint32_t component_count = 4;
      if (instr.vector_opcode == ucode::AluVectorOpcode::kDp3) {
        component_count = 3;
      } else if (instr.vector_opcode == ucode::AluVectorOpcode::kDp2Add) {
        component_count = 2;
      }
      std::string products = Temp(v4, fmt::format("xe_mul({}, {})", operand(0), operand(1)));
      std::string sum = fmt::format("{}.x", products);
      for (uint32_t i = 1; i < component_count; ++i) {
        sum = fmt::format("({} + {}.{})", sum, products, GetCharForComponentIndex(i));
      }
      if (instr.vector_opcode == ucode::AluVectorOpcode::kDp2Add) {
        sum = fmt::format("({} + {})", sum, operand_scalar(2, 0));
      }
      is_scalar = true;
      return Temp("f32", sum);
    }

    case ucode::AluVectorOpcode::kCube: {
      // The operand is .z_xy: x = component 2, y = component 3, z = component 0.
      // Result: T coordinate, S coordinate, 2 * major axis, face ID.
      std::string x = Temp("f32", operand_scalar(0, 2));
      std::string y = Temp("f32", operand_scalar(0, 3));
      std::string z = Temp("f32", operand_scalar(0, 0));
      std::string ma_z = Temp(
          "bool", fmt::format("abs({2}) >= abs({0}) && abs({2}) >= abs({1})", x, y, z));
      std::string ma_y = Temp("bool", fmt::format("abs({1}) >= abs({0})", x, y));
      std::string tc = Temp(
          "f32", fmt::format("select(select(-{1}, select({2}, -{2}, {1} < 0.0), {4}), -{1}, {3})",
                             x, y, z, ma_z, ma_y));
      std::string sc = Temp(
          "f32",
          fmt::format("select(select(select(-{2}, {2}, {0} < 0.0), {0}, {4}), "
                      "select({0}, -{0}, {2} < 0.0), {3})",
                      x, y, z, ma_z, ma_y));
      std::string ma = Temp("f32", fmt::format("select(select({0}, {1}, {4}), {2}, {3})", x, y, z,
                                               ma_z, ma_y));
      std::string id = Temp(
          "f32", fmt::format("select(select(select(0.0, 1.0, {0} < 0.0), select(2.0, 3.0, {1} < "
                             "0.0), {4}), select(4.0, 5.0, {2} < 0.0), {3})",
                             x, y, z, ma_z, ma_y));
      return Temp(v4, fmt::format("vec4<f32>({}, {}, 2.0 * {}, {})", tc, sc, ma, id));
    }

    case ucode::AluVectorOpcode::kMax4: {
      std::string v = Temp(v4, operand(0));
      is_scalar = true;
      return Temp("f32", fmt::format("max(max({0}.x, {0}.y), max({0}.z, {0}.w))", v));
    }

    case ucode::AluVectorOpcode::kSetpEqPush:
    case ucode::AluVectorOpcode::kSetpNePush:
    case ucode::AluVectorOpcode::kSetpGtPush:
    case ucode::AluVectorOpcode::kSetpGePush: {
      const char* op = kCompareEq;
      if (instr.vector_opcode == ucode::AluVectorOpcode::kSetpNePush) {
        op = kCompareNe;
      } else if (instr.vector_opcode == ucode::AluVectorOpcode::kSetpGtPush) {
        op = kCompareGt;
      } else if (instr.vector_opcode == ucode::AluVectorOpcode::kSetpGePush) {
        op = kCompareGe;
      }
      std::string a = Temp(v4, operand(0));
      std::string b = Temp(v4, operand(1));
      // p0 = src0.w == 0.0 && src1.w op 0.0
      Line(fmt::format("xe_p0 = {}.w == 0.0 && {}.w {} 0.0;", a, b, op));
      predicate_written = true;
      if (!used_result_components) {
        return std::string();
      }
      // result = ((src0.x == 0.0 && src1.x op 0.0) ? -1.0 : src0.x) + 1.0
      is_scalar = true;
      return Temp("f32", fmt::format("select({0}.x, -1.0, {0}.x == 0.0 && {1}.x {2} 0.0) + 1.0",
                                     a, b, op));
    }

    case ucode::AluVectorOpcode::kKillEq:
    case ucode::AluVectorOpcode::kKillGt:
    case ucode::AluVectorOpcode::kKillGe:
    case ucode::AluVectorOpcode::kKillNe: {
      const char* op = kCompareEq;
      if (instr.vector_opcode == ucode::AluVectorOpcode::kKillGt) {
        op = kCompareGt;
      } else if (instr.vector_opcode == ucode::AluVectorOpcode::kKillGe) {
        op = kCompareGe;
      } else if (instr.vector_opcode == ucode::AluVectorOpcode::kKillNe) {
        op = kCompareNe;
      }
      KillPixel(fmt::format("any({} {} {})", operand(0), op, operand(1)));
      is_scalar = true;
      return "0.0";
    }

    case ucode::AluVectorOpcode::kDst: {
      std::string a = Temp(v4, operand(0));
      std::string b = Temp(v4, operand(1));
      // (1, src0.y * src1.y, src0.z, src1.w)
      return Temp(v4, fmt::format("vec4<f32>(1.0, xe_mul_s({0}.y, {1}.y), {0}.z, {1}.w)", a, b));
    }
  }

  EmitTranslationError("WGSL: unknown ALU vector operation");
  return std::string();
}

std::string WgslShaderTranslator::ProcessScalarAluOperation(const ParsedAluInstruction& instr,
                                                            bool& predicate_written) {
  predicate_written = false;
  std::string storage[2];
  for (uint32_t i = 0; i < instr.scalar_operand_count; ++i) {
    storage[i] = LoadOperandStorage(instr.scalar_operands[i]);
  }
  // `a` is component 0 of the (first) operand, `b` component 1.
  auto a = [&]() { return OperandScalar(storage[0], instr.scalar_operands[0], 0); };
  auto b = [&]() { return OperandScalar(storage[0], instr.scalar_operands[0], 1); };
  auto second = [&]() { return OperandScalar(storage[1], instr.scalar_operands[1], 0); };
  const std::string flt_max = FloatLiteral(FLT_MAX);

  switch (instr.scalar_opcode) {
    case ucode::AluScalarOpcode::kAdds:
      return Temp("f32", fmt::format("{} + {}", a(), b()));
    case ucode::AluScalarOpcode::kSubs:
      return Temp("f32", fmt::format("{} - {}", a(), b()));
    case ucode::AluScalarOpcode::kAddsPrev:
      return Temp("f32", fmt::format("{} + xe_ps", a()));
    case ucode::AluScalarOpcode::kSubsPrev:
      return Temp("f32", fmt::format("{} - xe_ps", a()));
    case ucode::AluScalarOpcode::kMuls:
      return Temp("f32", fmt::format("xe_mul_s({}, {})", a(), b()));
    case ucode::AluScalarOpcode::kMulsPrev:
      return Temp("f32", fmt::format("xe_mul_s({}, xe_ps)", a()));
    case ucode::AluScalarOpcode::kMulsPrev2: {
      // ps == -FLT_MAX || !isfinite(ps) || !isfinite(src0.b) || src0.b <= 0
      //     ? -FLT_MAX : src0.a * ps
      std::string sb = Temp("f32", b());
      std::string condition = fmt::format(
          "xe_ps != -{0} && !xe_is_inf(xe_ps) && xe_ps == xe_ps && !xe_is_inf({1}) && {1} > 0.0",
          flt_max, sb);
      return Temp("f32", fmt::format("select(-{}, xe_mul_s({}, xe_ps), {})", flt_max, a(),
                                     condition));
    }

    case ucode::AluScalarOpcode::kMaxs:
    case ucode::AluScalarOpcode::kMins:
    case ucode::AluScalarOpcode::kMaxAs:
    case ucode::AluScalarOpcode::kMaxAsf: {
      std::string sa = Temp("f32", a());
      std::string sb = Temp("f32", b());
      if (instr.scalar_opcode == ucode::AluScalarOpcode::kMaxAs) {
        Line(fmt::format("xe_a0 = i32(clamp(floor({} + 0.5), -256.0, 255.0));", sa));
      } else if (instr.scalar_opcode == ucode::AluScalarOpcode::kMaxAsf) {
        Line(fmt::format("xe_a0 = i32(clamp(floor({}), -256.0, 255.0));", sa));
      }
      const char* op = instr.scalar_opcode == ucode::AluScalarOpcode::kMins ? "<" : ">=";
      return Temp("f32", fmt::format("select({1}, {0}, {0} {2} {1})", sa, sb, op));
    }

    case ucode::AluScalarOpcode::kSeqs:
    case ucode::AluScalarOpcode::kSgts:
    case ucode::AluScalarOpcode::kSges:
    case ucode::AluScalarOpcode::kSnes: {
      const char* op = kCompareEq;
      if (instr.scalar_opcode == ucode::AluScalarOpcode::kSgts) {
        op = kCompareGt;
      } else if (instr.scalar_opcode == ucode::AluScalarOpcode::kSges) {
        op = kCompareGe;
      } else if (instr.scalar_opcode == ucode::AluScalarOpcode::kSnes) {
        op = kCompareNe;
      }
      return Temp("f32", fmt::format("select(0.0, 1.0, {} {} 0.0)", a(), op));
    }

    case ucode::AluScalarOpcode::kFrcs:
      return Temp("f32", fmt::format("fract({})", a()));
    case ucode::AluScalarOpcode::kTruncs:
      return Temp("f32", fmt::format("trunc({})", a()));
    case ucode::AluScalarOpcode::kFloors:
      return Temp("f32", fmt::format("floor({})", a()));
    case ucode::AluScalarOpcode::kExp:
      return Temp("f32", fmt::format("exp2({})", a()));
    case ucode::AluScalarOpcode::kLog:
    case ucode::AluScalarOpcode::kLogc: {
      // log2(0) is -Infinity on Xenos (WGSL leaves it undefined); logc clamps it to -FLT_MAX.
      std::string sa = Temp("f32", a());
      std::string minus_infinity = instr.scalar_opcode == ucode::AluScalarOpcode::kLogc
                                       ? "-" + flt_max
                                       : std::string("-xe_inf()");
      return Temp("f32", fmt::format("select(log2({0}), {1}, {0} == 0.0)", sa, minus_infinity));
    }
    case ucode::AluScalarOpcode::kSqrt:
      return Temp("f32", fmt::format("sqrt({})", a()));
    case ucode::AluScalarOpcode::kSin:
      return Temp("f32", fmt::format("sin({})", a()));
    case ucode::AluScalarOpcode::kCos:
      return Temp("f32", fmt::format("cos({})", a()));

    case ucode::AluScalarOpcode::kRcp:
    case ucode::AluScalarOpcode::kRcpc:
    case ucode::AluScalarOpcode::kRcpf:
    case ucode::AluScalarOpcode::kRsq:
    case ucode::AluScalarOpcode::kRsqc:
    case ucode::AluScalarOpcode::kRsqf: {
      bool is_rsq = instr.scalar_opcode == ucode::AluScalarOpcode::kRsq ||
                    instr.scalar_opcode == ucode::AluScalarOpcode::kRsqc ||
                    instr.scalar_opcode == ucode::AluScalarOpcode::kRsqf;
      std::string sa = Temp("f32", a());
      // Division by zero is made explicit: +-0 -> +-Infinity (rsq(-0) = -Infinity).
      std::string r = Temp(
          "f32", fmt::format("select({1}, select(xe_inf(), -xe_inf(), xe_sign_bit({0})), {0} == 0.0)",
                             sa, is_rsq ? fmt::format("inverseSqrt({})", sa)
                                        : fmt::format("1.0 / {}", sa)));
      if (instr.scalar_opcode == ucode::AluScalarOpcode::kRcpc ||
          instr.scalar_opcode == ucode::AluScalarOpcode::kRsqc) {
        // +-Infinity -> +-FLT_MAX.
        return Temp("f32", fmt::format("select({0}, select({1}, -{1}, xe_sign_bit({0})), "
                                       "xe_is_inf({0}))",
                                       r, flt_max));
      }
      if (instr.scalar_opcode == ucode::AluScalarOpcode::kRcpf ||
          instr.scalar_opcode == ucode::AluScalarOpcode::kRsqf) {
        // +Infinity -> +0, -Infinity -> -0.
        return Temp("f32", fmt::format("select({0}, select(0.0, -0.0, xe_sign_bit({0})), "
                                       "xe_is_inf({0}))",
                                       r));
      }
      return r;
    }

    case ucode::AluScalarOpcode::kSetpEq:
    case ucode::AluScalarOpcode::kSetpNe:
    case ucode::AluScalarOpcode::kSetpGt:
    case ucode::AluScalarOpcode::kSetpGe: {
      const char* op = kCompareEq;
      if (instr.scalar_opcode == ucode::AluScalarOpcode::kSetpNe) {
        op = kCompareNe;
      } else if (instr.scalar_opcode == ucode::AluScalarOpcode::kSetpGt) {
        op = kCompareGt;
      } else if (instr.scalar_opcode == ucode::AluScalarOpcode::kSetpGe) {
        op = kCompareGe;
      }
      Line(fmt::format("xe_p0 = {} {} 0.0;", a(), op));
      predicate_written = true;
      return Temp("f32", "select(1.0, 0.0, xe_p0)");
    }
    case ucode::AluScalarOpcode::kSetpInv: {
      std::string sa = Temp("f32", a());
      Line(fmt::format("xe_p0 = {} == 1.0;", sa));
      predicate_written = true;
      return Temp("f32", fmt::format("select(select({0}, 1.0, {0} == 0.0), 0.0, xe_p0)", sa));
    }
    case ucode::AluScalarOpcode::kSetpPop: {
      std::string m = Temp("f32", fmt::format("{} - 1.0", a()));
      Line(fmt::format("xe_p0 = {} <= 0.0;", m));
      predicate_written = true;
      return Temp("f32", fmt::format("select({}, 0.0, xe_p0)", m));
    }
    case ucode::AluScalarOpcode::kSetpClr:
      Line("xe_p0 = false;");
      // (The SPIR-V path doesn't flag this as a predicate write either.)
      return Temp("f32", flt_max);
    case ucode::AluScalarOpcode::kSetpRstr: {
      std::string sa = Temp("f32", a());
      Line(fmt::format("xe_p0 = {} == 0.0;", sa));
      predicate_written = true;
      return Temp("f32", fmt::format("select({}, 0.0, xe_p0)", sa));
    }

    case ucode::AluScalarOpcode::kKillsEq:
    case ucode::AluScalarOpcode::kKillsGt:
    case ucode::AluScalarOpcode::kKillsGe:
    case ucode::AluScalarOpcode::kKillsNe:
    case ucode::AluScalarOpcode::kKillsOne: {
      const char* op = kCompareEq;
      if (instr.scalar_opcode == ucode::AluScalarOpcode::kKillsGt) {
        op = kCompareGt;
      } else if (instr.scalar_opcode == ucode::AluScalarOpcode::kKillsGe) {
        op = kCompareGe;
      } else if (instr.scalar_opcode == ucode::AluScalarOpcode::kKillsNe) {
        op = kCompareNe;
      }
      KillPixel(fmt::format("{} {} {}", a(), op,
                            instr.scalar_opcode == ucode::AluScalarOpcode::kKillsOne ? "1.0"
                                                                                     : "0.0"));
      return Temp("f32", "0.0");
    }

    case ucode::AluScalarOpcode::kMulsc0:
    case ucode::AluScalarOpcode::kMulsc1:
      return Temp("f32", fmt::format("xe_mul_s({}, {})", a(), second()));
    case ucode::AluScalarOpcode::kAddsc0:
    case ucode::AluScalarOpcode::kAddsc1:
      return Temp("f32", fmt::format("{} + {}", a(), second()));
    case ucode::AluScalarOpcode::kSubsc0:
    case ucode::AluScalarOpcode::kSubsc1:
      return Temp("f32", fmt::format("{} - {}", a(), second()));

    case ucode::AluScalarOpcode::kRetainPrev:
      return std::string();
  }

  EmitTranslationError("WGSL: unknown ALU scalar operation");
  return std::string();
}

}  // namespace rex::graphics
