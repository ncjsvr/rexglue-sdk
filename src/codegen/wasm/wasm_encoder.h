/**
 * @file        codegen/wasm/wasm_encoder.h
 * @brief       Minimal WebAssembly binary encoder for the wasm backend
 *
 * @copyright   Copyright (c) 2026 MCLA-Reborn contributors
 * @license     Not yet licensed: MCLA-Reborn decides before any release (D-009)
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rex::codegen::wasm {

enum class ValType : uint8_t { I32 = 0x7F, I64 = 0x7E, F32 = 0x7D, F64 = 0x7C, V128 = 0x7B };

constexpr uint8_t kBlockEmpty = 0x40;
constexpr uint8_t kFuncRef = 0x70;

/// Opcodes used by the backend (single-byte MVP, sign-extension and exception-handling ops).
namespace Op {
constexpr uint8_t Unreachable = 0x00, Nop = 0x01, Block = 0x02, Loop = 0x03, If = 0x04,
                  Else = 0x05, Throw = 0x08, End = 0x0B, TryTable = 0x1F, Br = 0x0C, BrIf = 0x0D, BrTable = 0x0E,
                  Return = 0x0F, Call = 0x10, CallIndirect = 0x11, Drop = 0x1A, Select = 0x1B;
constexpr uint8_t LocalGet = 0x20, LocalSet = 0x21, LocalTee = 0x22;
constexpr uint8_t I32Load = 0x28, I64Load = 0x29, I32Load8S = 0x2C, I32Load8U = 0x2D,
                  I32Load16S = 0x2E, I32Load16U = 0x2F, I64Load8S = 0x30, I64Load8U = 0x31,
                  I64Load16S = 0x32, I64Load16U = 0x33, I64Load32S = 0x34, I64Load32U = 0x35,
                  I32Store = 0x36, I64Store = 0x37, I32Store8 = 0x3A, I32Store16 = 0x3B,
                  I64Store8 = 0x3C, I64Store16 = 0x3D, I64Store32 = 0x3E;
constexpr uint8_t F32Load = 0x2A, F64Load = 0x2B, F32Store = 0x38, F64Store = 0x39;
constexpr uint8_t I32Const = 0x41, I64Const = 0x42, F32Const = 0x43, F64Const = 0x44;
constexpr uint8_t I32Eqz = 0x45, I32Eq = 0x46, I32Ne = 0x47, I32LtS = 0x48, I32LtU = 0x49,
                  I32GtS = 0x4A, I32GtU = 0x4B, I32LeS = 0x4C, I32LeU = 0x4D, I32GeS = 0x4E,
                  I32GeU = 0x4F;
constexpr uint8_t I64Eqz = 0x50, I64Eq = 0x51, I64Ne = 0x52, I64LtS = 0x53, I64LtU = 0x54,
                  I64GtS = 0x55, I64GtU = 0x56, I64LeS = 0x57, I64LeU = 0x58, I64GeS = 0x59,
                  I64GeU = 0x5A;
constexpr uint8_t F32Eq = 0x5B, F32Ne = 0x5C, F32Lt = 0x5D, F32Gt = 0x5E, F32Le = 0x5F,
                  F32Ge = 0x60, F64Eq = 0x61, F64Ne = 0x62, F64Lt = 0x63, F64Gt = 0x64,
                  F64Le = 0x65, F64Ge = 0x66;
constexpr uint8_t I32Clz = 0x67, I32Add = 0x6A, I32Sub = 0x6B, I32Mul = 0x6C, I32DivS = 0x6D,
                  I32DivU = 0x6E, I32And = 0x71, I32Or = 0x72, I32Xor = 0x73, I32Shl = 0x74,
                  I32ShrS = 0x75, I32ShrU = 0x76, I32Rotl = 0x77, I32Rotr = 0x78;
constexpr uint8_t I64Clz = 0x79, I64Add = 0x7C, I64Sub = 0x7D, I64Mul = 0x7E, I64DivS = 0x7F,
                  I64DivU = 0x80, I64And = 0x83, I64Or = 0x84, I64Xor = 0x85, I64Shl = 0x86,
                  I64ShrS = 0x87, I64ShrU = 0x88, I64Rotl = 0x89, I64Rotr = 0x8A;
constexpr uint8_t F32Abs = 0x8B, F32Neg = 0x8C, F32Ceil = 0x8D, F32Floor = 0x8E, F32Trunc = 0x8F,
                  F32Nearest = 0x90, F32Sqrt = 0x91, F32Add = 0x92, F32Sub = 0x93, F32Mul = 0x94,
                  F32Div = 0x95, F32Min = 0x96, F32Max = 0x97;
constexpr uint8_t F64Abs = 0x99, F64Neg = 0x9A, F64Ceil = 0x9B, F64Floor = 0x9C, F64Trunc = 0x9D,
                  F64Nearest = 0x9E, F64Sqrt = 0x9F, F64Add = 0xA0, F64Sub = 0xA1, F64Mul = 0xA2,
                  F64Div = 0xA3, F64Min = 0xA4, F64Max = 0xA5;
constexpr uint8_t I32WrapI64 = 0xA7, I64ExtendI32S = 0xAC, I64ExtendI32U = 0xAD;
constexpr uint8_t F32ConvertI32S = 0xB2, F32ConvertI32U = 0xB3, F32DemoteF64 = 0xB6,
                  F64ConvertI32S = 0xB7, F64ConvertI32U = 0xB8, F64ConvertI64S = 0xB9,
                  F64ConvertI64U = 0xBA, F64PromoteF32 = 0xBB, I32ReinterpretF32 = 0xBC,
                  I64ReinterpretF64 = 0xBD, F32ReinterpretI32 = 0xBE, F64ReinterpretI64 = 0xBF;
constexpr uint8_t PrefixMisc = 0xFC, PrefixSimd = 0xFD, PrefixAtomic = 0xFE;
constexpr uint8_t I32Extend8S = 0xC0, I32Extend16S = 0xC1, I64Extend8S = 0xC2,
                  I64Extend16S = 0xC3, I64Extend32S = 0xC4;
}  // namespace Op

/// 0xFC-prefixed opcodes (saturating truncation, bulk memory).
namespace Misc {
constexpr uint32_t I32TruncSatF32S = 0, I32TruncSatF32U = 1, I32TruncSatF64S = 2,
                   I32TruncSatF64U = 3, I64TruncSatF32S = 4, I64TruncSatF32U = 5,
                   I64TruncSatF64S = 6, I64TruncSatF64U = 7, MemoryFill = 11;
}  // namespace Misc

/// 0xFE-prefixed opcodes (threads proposal).
namespace Atomic {
constexpr uint32_t Fence = 0x03, I32Load = 0x10, I64Load = 0x11, I32RmwCmpxchg = 0x48,
                   I64RmwCmpxchg = 0x49;
}  // namespace Atomic

/// 0xFD-prefixed opcodes (SIMD128 and relaxed SIMD).
namespace Simd {
constexpr uint32_t V128Load = 0x00, V128Store = 0x0B, V128Const = 0x0C, I8x16Shuffle = 0x0D,
                   I8x16Swizzle = 0x0E, I8x16Splat = 0x0F, I16x8Splat = 0x10, I32x4Splat = 0x11,
                   I64x2Splat = 0x12, F32x4Splat = 0x13, F64x2Splat = 0x14;
constexpr uint32_t I8x16ExtractLaneS = 0x15, I8x16ExtractLaneU = 0x16, I8x16ReplaceLane = 0x17,
                   I16x8ExtractLaneS = 0x18, I16x8ExtractLaneU = 0x19, I16x8ReplaceLane = 0x1A,
                   I32x4ExtractLane = 0x1B, I32x4ReplaceLane = 0x1C, I64x2ExtractLane = 0x1D,
                   I64x2ReplaceLane = 0x1E, F32x4ExtractLane = 0x1F, F32x4ReplaceLane = 0x20,
                   F64x2ExtractLane = 0x21, F64x2ReplaceLane = 0x22;
constexpr uint32_t I8x16Eq = 0x23, I8x16GtS = 0x27, I8x16GtU = 0x28, I16x8Eq = 0x2D,
                   I16x8GtS = 0x31, I16x8GtU = 0x32, I32x4Eq = 0x37, I32x4LtS = 0x39,
                   I32x4GtS = 0x3B, I32x4GtU = 0x3C;
constexpr uint32_t F32x4Eq = 0x41, F32x4Ne = 0x42, F32x4Lt = 0x43, F32x4Gt = 0x44, F32x4Le = 0x45,
                   F32x4Ge = 0x46;
constexpr uint32_t V128Not = 0x4D, V128And = 0x4E, V128AndNot = 0x4F, V128Or = 0x50,
                   V128Xor = 0x51, V128Bitselect = 0x52, V128AnyTrue = 0x53;
constexpr uint32_t I8x16Bitmask = 0x64, I8x16NarrowI16x8S = 0x65, I8x16NarrowI16x8U = 0x66,
                   F32x4Ceil = 0x67, F32x4Floor = 0x68, F32x4Trunc = 0x69, F32x4Nearest = 0x6A,
                   I8x16Shl = 0x6B, I8x16ShrS = 0x6C, I8x16ShrU = 0x6D, I8x16Add = 0x6E,
                   I8x16AddSatS = 0x6F, I8x16AddSatU = 0x70, I8x16Sub = 0x71,
                   I8x16SubSatS = 0x72, I8x16SubSatU = 0x73, I8x16MinS = 0x76, I8x16MinU = 0x77,
                   I8x16MaxS = 0x78, I8x16MaxU = 0x79, I8x16AvgrU = 0x7B;
constexpr uint32_t I16x8Bitmask = 0x84, I16x8NarrowI32x4S = 0x85, I16x8NarrowI32x4U = 0x86,
                   I16x8ExtendLowI8x16S = 0x87, I16x8ExtendHighI8x16S = 0x88, I16x8Shl = 0x8B,
                   I16x8ShrS = 0x8C, I16x8ShrU = 0x8D, I16x8Add = 0x8E, I16x8AddSatS = 0x8F,
                   I16x8AddSatU = 0x90, I16x8Sub = 0x91, I16x8SubSatS = 0x92,
                   I16x8SubSatU = 0x93, I16x8MinS = 0x96, I16x8MinU = 0x97, I16x8MaxS = 0x98,
                   I16x8MaxU = 0x99, I16x8AvgrU = 0x9B;
constexpr uint32_t I32x4Bitmask = 0xA4, I32x4ExtendLowI16x8S = 0xA7, I32x4ExtendHighI16x8S = 0xA8,
                   I32x4Shl = 0xAB, I32x4ShrS = 0xAC, I32x4ShrU = 0xAD, I32x4Add = 0xAE,
                   I32x4Sub = 0xB1, I32x4MinS = 0xB6, I32x4MinU = 0xB7, I32x4MaxS = 0xB8,
                   I32x4MaxU = 0xB9;
constexpr uint32_t I64x2Shl = 0xCB, I64x2ShrU = 0xCD;
constexpr uint32_t F32x4Abs = 0xE0, F32x4Neg = 0xE1, F32x4Sqrt = 0xE3, F32x4Add = 0xE4,
                   F32x4Sub = 0xE5, F32x4Mul = 0xE6, F32x4Div = 0xE7, F32x4Min = 0xE8,
                   F32x4Max = 0xE9, F32x4Pmin = 0xEA, F32x4Pmax = 0xEB;
constexpr uint32_t I32x4TruncSatF32x4S = 0xF8, I32x4TruncSatF32x4U = 0xF9,
                   F32x4ConvertI32x4S = 0xFA, F32x4ConvertI32x4U = 0xFB;
constexpr uint32_t F64x2RelaxedMadd = 0x107;
}  // namespace Simd

/// Growable byte buffer with LEB128 helpers.
class Bytes {
 public:
  void u8(uint8_t v) { data_.push_back(v); }
  void u32le(uint32_t v);
  void uleb(uint64_t v);
  void sleb(int64_t v);
  void name(std::string_view s);
  void append(const std::vector<uint8_t>& other);
  void append(const Bytes& other) { append(other.data_); }
  /// Appends `other` prefixed with its size as uleb.
  void appendSized(const Bytes& other);

  const std::vector<uint8_t>& data() const { return data_; }
  size_t size() const { return data_.size(); }
  bool empty() const { return data_.empty(); }

 protected:
  std::vector<uint8_t> data_;
};

/// Instruction stream for one function body (without the trailing `end`).
class Code : public Bytes {
 public:
  void op(uint8_t opcode) { u8(opcode); }
  void i32Const(int32_t v) {
    u8(Op::I32Const);
    sleb(v);
  }
  void i64Const(int64_t v) {
    u8(Op::I64Const);
    sleb(v);
  }
  void localGet(uint32_t i) {
    u8(Op::LocalGet);
    uleb(i);
  }
  void localSet(uint32_t i) {
    u8(Op::LocalSet);
    uleb(i);
  }
  void localTee(uint32_t i) {
    u8(Op::LocalTee);
    uleb(i);
  }
  void block(uint8_t blockType = kBlockEmpty) {
    u8(Op::Block);
    u8(blockType);
  }
  void loop(uint8_t blockType = kBlockEmpty) {
    u8(Op::Loop);
    u8(blockType);
  }
  void if_(uint8_t blockType = kBlockEmpty) {
    u8(Op::If);
    u8(blockType);
  }
  void else_() { u8(Op::Else); }
  void end() { u8(Op::End); }
  void br(uint32_t depth) {
    u8(Op::Br);
    uleb(depth);
  }
  void brIf(uint32_t depth) {
    u8(Op::BrIf);
    uleb(depth);
  }
  void brTable(const std::vector<uint32_t>& depths, uint32_t defaultDepth);
  void call(uint32_t funcIndex) {
    u8(Op::Call);
    uleb(funcIndex);
  }
  void callIndirect(uint32_t typeIndex, uint32_t tableIndex = 0) {
    u8(Op::CallIndirect);
    uleb(typeIndex);
    uleb(tableIndex);
  }
  /// Memory access with a memory64 memarg (alignment exponent, 64-bit offset).
  void mem(uint8_t opcode, uint32_t alignLog2, uint64_t offset) {
    u8(opcode);
    uleb(alignLog2);
    uleb(offset);
  }
  void f32Const(float v);
  void f64Const(double v);
  /// Block whose type is a function type index (multi-value results).
  void blockTyped(uint32_t typeIndex) {
    u8(Op::Block);
    sleb(typeIndex);
  }
  /// try_table with one `catch tag label` clause (exception handling, exnref form).
  void tryTableCatch(uint32_t tagIndex, uint32_t labelDepth) {
    u8(Op::TryTable);
    u8(kBlockEmpty);
    uleb(1);
    u8(0x00);
    uleb(tagIndex);
    uleb(labelDepth);
  }
  void throw_(uint32_t tagIndex) {
    u8(Op::Throw);
    uleb(tagIndex);
  }
  void misc(uint32_t opcode) {
    u8(Op::PrefixMisc);
    uleb(opcode);
  }
  void memoryFill() {
    misc(Misc::MemoryFill);
    u8(0x00);
  }
  void atomicFence() {
    u8(Op::PrefixAtomic);
    uleb(Atomic::Fence);
    u8(0x00);
  }
  void atomicMem(uint32_t opcode, uint32_t alignLog2, uint64_t offset) {
    u8(Op::PrefixAtomic);
    uleb(opcode);
    uleb(alignLog2);
    uleb(offset);
  }
  void simd(uint32_t opcode) {
    u8(Op::PrefixSimd);
    uleb(opcode);
  }
  void simdMem(uint32_t opcode, uint32_t alignLog2, uint64_t offset) {
    simd(opcode);
    uleb(alignLog2);
    uleb(offset);
  }
  void simdLane(uint32_t opcode, uint8_t lane) {
    simd(opcode);
    u8(lane);
  }
  void v128Const(const uint8_t (&bytes)[16]);
  void i32x4Const(uint32_t a, uint32_t b, uint32_t c, uint32_t d);
  void i32x4Splat(uint32_t v) { i32x4Const(v, v, v, v); }
  void i8x16Splat(uint8_t v);
  void shuffle(const uint8_t (&lanes)[16]);
};

struct FuncType {
  std::vector<ValType> params;
  std::vector<ValType> results;
  bool operator==(const FuncType&) const = default;
};

struct LocalDecl {
  uint32_t count;
  ValType type;
};

/// Builds one module: types, imports, functions, element segments, exports and a name section.
class ModuleBuilder {
 public:
  uint32_t addType(const FuncType& type);
  uint32_t importFunction(std::string_view module, std::string_view field, uint32_t typeIndex);
  void importMemory(std::string_view module, std::string_view field, uint64_t minPages,
                    std::optional<uint64_t> maxPages, bool shared, bool memory64);
  void importTable(std::string_view module, std::string_view field, uint32_t minSize);
  /// Imports an exception tag whose parameters are the params of `typeIndex`.
  uint32_t importTag(std::string_view module, std::string_view field, uint32_t typeIndex);

  /// Declares a defined function; returns its function index (after all imports).
  /// All imports must be added before the first function.
  uint32_t addFunction(uint32_t typeIndex, std::vector<LocalDecl> locals, Code body,
                       std::string name);
  void exportFunction(std::string_view name, uint32_t funcIndex);
  /// Active element segment for table 0 at a constant i32 offset.
  void addElementSegment(uint32_t offset, std::vector<uint32_t> funcIndices);
  void setModuleName(std::string name) { moduleName_ = std::move(name); }

  uint32_t importedFunctionCount() const { return importedFuncs_; }
  std::vector<uint8_t> finish() const;

 private:
  struct Function {
    uint32_t type;
    std::vector<LocalDecl> locals;
    Code body;
  };
  struct Export {
    std::string name;
    uint8_t kind;
    uint32_t index;
  };
  struct Element {
    uint32_t offset;
    std::vector<uint32_t> funcs;
  };

  std::vector<FuncType> types_;
  Bytes imports_;
  uint32_t importCount_ = 0;
  uint32_t importedFuncs_ = 0;
  uint32_t importedTags_ = 0;
  std::vector<Function> functions_;
  std::vector<std::pair<uint32_t, std::string>> funcNames_;
  std::vector<Export> exports_;
  std::vector<Element> elements_;
  std::string moduleName_;
};

}  // namespace rex::codegen::wasm
