/**
 * @file        codegen/wasm/wasm_helpers.cpp
 * @brief       Module-internal helper functions of the wasm backend: byte-wise accesses for
 *              misaligned halfwords, words and doublewords under byte-swapped storage
 *              (ADR-0009), and log2f for vlogefp
 *
 * Every chunk defines these after its guest functions. They are not in the table and not
 * exported, so they are not part of the guest ABI.
 *
 * @copyright   Copyright (c) 2026 MCLA-Reborn contributors
 * @license     Not yet licensed: MCLA-Reborn decides before any release (D-009)
 */

#include <bit>
#include <cmath>
#include <limits>

#include "wasm_backend.h"

namespace rex::codegen::wasm {

namespace {

enum Helper : uint32_t { kLoad16, kLoad32, kLoad64, kStore16, kStore32, kStore64, kLog2f };

/// Pushes the linear address of guest byte (ea + i) (ea in local 0): GUEST_BASE folds into
/// the memarg offset, the byte's position in its word is (ea + i) ^ 3.
void pushByteAddr(Code& c, uint32_t i) {
  c.localGet(0);
  if (i != 0) {
    c.i32Const(static_cast<int32_t>(i));
    c.op(Op::I32Add);
  }
  c.i32Const(3);
  c.op(Op::I32Xor);
  c.op(Op::I64ExtendI32U);
}

/// Guest bytes ea .. ea + n - 1 as a big-endian i32.
Code loadBytes(uint32_t n) {
  Code c;
  for (uint32_t i = 0; i < n; ++i) {
    pushByteAddr(c, i);
    c.mem(Op::I32Load8U, 0, kGuestBase);
    if (i + 1 < n) {
      c.i32Const(static_cast<int32_t>(8 * (n - 1 - i)));
      c.op(Op::I32Shl);
    }
    if (i != 0)
      c.op(Op::I32Or);
  }
  return c;
}

/// Stores the low n bytes of the i32 in local 1, big-endian, at guest ea.
Code storeBytes(uint32_t n) {
  Code c;
  for (uint32_t i = 0; i < n; ++i) {
    pushByteAddr(c, i);
    c.localGet(1);
    if (i + 1 < n) {
      c.i32Const(static_cast<int32_t>(8 * (n - 1 - i)));
      c.op(Op::I32ShrU);
    }
    c.mem(Op::I32Store8, 0, kGuestBase);
  }
  return c;
}

Code load64(const ModuleEnv& env) {
  Code c;
  c.localGet(0);
  c.call(env.fnLoad32);
  c.op(Op::I64ExtendI32U);
  c.i64Const(32);
  c.op(Op::I64Shl);
  c.localGet(0);
  c.i32Const(4);
  c.op(Op::I32Add);
  c.call(env.fnLoad32);
  c.op(Op::I64ExtendI32U);
  c.op(Op::I64Or);
  return c;
}

Code store64(const ModuleEnv& env) {
  Code c;
  c.localGet(0);
  c.localGet(1);
  c.i64Const(32);
  c.op(Op::I64ShrU);
  c.op(Op::I32WrapI64);
  c.call(env.fnStore32);
  c.localGet(0);
  c.i32Const(4);
  c.op(Op::I32Add);
  c.localGet(1);
  c.op(Op::I32WrapI64);
  c.call(env.fnStore32);
  return c;
}

/// log2f(x): x = m * 2^e with m in [sqrt(1/2), sqrt(2)), ln(m) = 2 atanh((m-1)/(m+1)) as an
/// odd series in f64 (error below 1e-10), rounded once to f32. Locals: 1 bits (i32), 2 e
/// (i32), 3 m, 4 s, 5 s2 (f64).
Code log2f() {
  Code c;
  // NaN -> quiet NaN; 0 -> -inf; negative -> NaN; +inf -> +inf.
  c.localGet(0), c.localGet(0), c.op(Op::F32Ne);
  c.if_();
  c.localGet(0), c.localGet(0), c.op(Op::F32Add), c.op(Op::Return);
  c.end();
  c.localGet(0), c.f32Const(0.0f), c.op(Op::F32Eq);
  c.if_();
  c.f32Const(-std::numeric_limits<float>::infinity()), c.op(Op::Return);
  c.end();
  c.localGet(0), c.f32Const(0.0f), c.op(Op::F32Lt);
  c.if_();
  c.localGet(0), c.localGet(0), c.op(Op::F32Sub), c.localGet(0), c.localGet(0), c.op(Op::F32Sub),
      c.op(Op::F32Div), c.op(Op::Return);
  c.end();
  c.localGet(0), c.f32Const(std::numeric_limits<float>::infinity()), c.op(Op::F32Eq);
  c.if_();
  c.localGet(0), c.op(Op::Return);
  c.end();
  // Denormals: scale by 2^24 first.
  c.i32Const(0), c.localSet(2);
  c.localGet(0), c.op(Op::I32ReinterpretF32), c.i32Const(0x00800000), c.op(Op::I32LtU);
  c.if_();
  c.localGet(0), c.f32Const(16777216.0f), c.op(Op::F32Mul), c.localSet(0);
  c.i32Const(-24), c.localSet(2);
  c.end();
  c.localGet(0), c.op(Op::I32ReinterpretF32), c.localSet(1);
  // e += exponent - 127; mantissa bits with a zero exponent
  c.localGet(2), c.localGet(1), c.i32Const(23), c.op(Op::I32ShrU), c.i32Const(127),
      c.op(Op::I32Sub), c.op(Op::I32Add), c.localSet(2);
  c.localGet(1), c.i32Const(0x7FFFFF), c.op(Op::I32And), c.i32Const(0x3F800000), c.op(Op::I32Or),
      c.localSet(1);
  c.localGet(1), c.i32Const(0x3FB504F3), c.op(Op::I32GtU);
  c.if_();
  c.localGet(1), c.i32Const(0x00800000), c.op(Op::I32Sub), c.localSet(1);
  c.localGet(2), c.i32Const(1), c.op(Op::I32Add), c.localSet(2);
  c.end();
  c.localGet(1), c.op(Op::F32ReinterpretI32), c.op(Op::F64PromoteF32), c.localSet(3);
  // s = (m - 1) / (m + 1)
  c.localGet(3), c.f64Const(1.0), c.op(Op::F64Sub), c.localGet(3), c.f64Const(1.0),
      c.op(Op::F64Add), c.op(Op::F64Div), c.localSet(4);
  c.localGet(4), c.localGet(4), c.op(Op::F64Mul), c.localSet(5);
  // p = 1 + s2/3 + s2^2/5 + ... + s2^6/13 (Horner)
  c.f64Const(1.0 / 13.0);
  for (double k : {11.0, 9.0, 7.0, 5.0, 3.0, 1.0}) {
    c.localGet(5), c.op(Op::F64Mul), c.f64Const(1.0 / k), c.op(Op::F64Add);
  }
  // log2 = e + 2 s p / ln 2
  c.localGet(4), c.op(Op::F64Mul), c.f64Const(2.0 / std::log(2.0)), c.op(Op::F64Mul);
  c.localGet(2), c.op(Op::F64ConvertI32S), c.op(Op::F64Add);
  c.op(Op::F32DemoteF64);
  return c;
}

}  // namespace

void AssignHelperIndices(ModuleEnv& env, uint32_t firstIndex) {
  env.fnLoad16 = firstIndex + kLoad16;
  env.fnLoad32 = firstIndex + kLoad32;
  env.fnLoad64 = firstIndex + kLoad64;
  env.fnStore16 = firstIndex + kStore16;
  env.fnStore32 = firstIndex + kStore32;
  env.fnStore64 = firstIndex + kStore64;
  env.fnLog2f = firstIndex + kLog2f;
}

void AddHelperFunctions(ModuleBuilder& mb, const ModuleEnv& env) {
  using V = ValType;
  const uint32_t tLoad32 = mb.addType({{V::I32}, {V::I32}});
  const uint32_t tLoad64 = mb.addType({{V::I32}, {V::I64}});
  const uint32_t tStore32 = mb.addType({{V::I32, V::I32}, {}});
  const uint32_t tStore64 = mb.addType({{V::I32, V::I64}, {}});
  const uint32_t tLog2f = mb.addType({{V::F32}, {V::F32}});
  mb.addFunction(tLoad32, {}, loadBytes(2), "__load16_misaligned");
  mb.addFunction(tLoad32, {}, loadBytes(4), "__load32_misaligned");
  mb.addFunction(tLoad64, {}, load64(env), "__load64_misaligned");
  mb.addFunction(tStore32, {}, storeBytes(2), "__store16_misaligned");
  mb.addFunction(tStore32, {}, storeBytes(4), "__store32_misaligned");
  mb.addFunction(tStore64, {}, store64(env), "__store64_misaligned");
  mb.addFunction(tLog2f, {{2, V::I32}, {3, V::F64}}, log2f(), "__log2f");
}

}  // namespace rex::codegen::wasm
