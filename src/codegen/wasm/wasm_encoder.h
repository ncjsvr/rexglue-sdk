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

enum class ValType : uint8_t { I32 = 0x7F, I64 = 0x7E, F32 = 0x7D, F64 = 0x7C };

constexpr uint8_t kBlockEmpty = 0x40;
constexpr uint8_t kFuncRef = 0x70;

/// Opcodes used by the backend (single-byte MVP plus sign-extension ops).
namespace Op {
constexpr uint8_t Unreachable = 0x00, Nop = 0x01, Block = 0x02, Loop = 0x03, If = 0x04,
                  Else = 0x05, End = 0x0B, Br = 0x0C, BrIf = 0x0D, BrTable = 0x0E,
                  Return = 0x0F, Call = 0x10, CallIndirect = 0x11, Drop = 0x1A, Select = 0x1B;
constexpr uint8_t LocalGet = 0x20, LocalSet = 0x21, LocalTee = 0x22;
constexpr uint8_t I32Load = 0x28, I64Load = 0x29, I32Load8S = 0x2C, I32Load8U = 0x2D,
                  I32Load16S = 0x2E, I32Load16U = 0x2F, I64Load8S = 0x30, I64Load8U = 0x31,
                  I64Load16S = 0x32, I64Load16U = 0x33, I64Load32S = 0x34, I64Load32U = 0x35,
                  I32Store = 0x36, I64Store = 0x37, I32Store8 = 0x3A, I32Store16 = 0x3B,
                  I64Store8 = 0x3C, I64Store16 = 0x3D, I64Store32 = 0x3E;
constexpr uint8_t I32Const = 0x41, I64Const = 0x42;
constexpr uint8_t I32Eqz = 0x45, I32Eq = 0x46, I32Ne = 0x47, I32LtS = 0x48, I32LtU = 0x49,
                  I32GtS = 0x4A, I32GtU = 0x4B, I32LeS = 0x4C, I32LeU = 0x4D, I32GeS = 0x4E,
                  I32GeU = 0x4F;
constexpr uint8_t I64Eqz = 0x50, I64Eq = 0x51, I64Ne = 0x52, I64LtS = 0x53, I64LtU = 0x54,
                  I64GtS = 0x55, I64GtU = 0x56, I64LeS = 0x57, I64LeU = 0x58, I64GeS = 0x59,
                  I64GeU = 0x5A;
constexpr uint8_t I32Clz = 0x67, I32Add = 0x6A, I32Sub = 0x6B, I32Mul = 0x6C, I32DivS = 0x6D,
                  I32DivU = 0x6E, I32And = 0x71, I32Or = 0x72, I32Xor = 0x73, I32Shl = 0x74,
                  I32ShrS = 0x75, I32ShrU = 0x76, I32Rotl = 0x77;
constexpr uint8_t I64Clz = 0x79, I64Add = 0x7C, I64Sub = 0x7D, I64Mul = 0x7E, I64DivS = 0x7F,
                  I64DivU = 0x80, I64And = 0x83, I64Or = 0x84, I64Xor = 0x85, I64Shl = 0x86,
                  I64ShrS = 0x87, I64ShrU = 0x88, I64Rotl = 0x89;
constexpr uint8_t I32WrapI64 = 0xA7, I64ExtendI32S = 0xAC, I64ExtendI32U = 0xAD;
constexpr uint8_t I32Extend8S = 0xC0, I32Extend16S = 0xC1, I64Extend8S = 0xC2,
                  I64Extend16S = 0xC3, I64Extend32S = 0xC4;
}  // namespace Op

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
  std::vector<Function> functions_;
  std::vector<std::pair<uint32_t, std::string>> funcNames_;
  std::vector<Export> exports_;
  std::vector<Element> elements_;
  std::string moduleName_;
};

}  // namespace rex::codegen::wasm
