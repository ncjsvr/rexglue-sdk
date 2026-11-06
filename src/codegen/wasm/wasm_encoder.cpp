/**
 * @file        codegen/wasm/wasm_encoder.cpp
 * @brief       Minimal WebAssembly binary encoder for the wasm backend
 *
 * @copyright   Copyright (c) 2026 MCLA-Reborn contributors
 * @license     Not yet licensed: MCLA-Reborn decides before any release (D-009)
 */

#include "wasm_encoder.h"

#include <algorithm>
#include <bit>

namespace rex::codegen::wasm {

namespace {

constexpr uint8_t kSectionCustom = 0, kSectionType = 1, kSectionImport = 2, kSectionFunction = 3,
                  kSectionExport = 7, kSectionElement = 9, kSectionCode = 10;
constexpr uint8_t kExternFunc = 0x00, kExternTable = 0x01, kExternMemory = 0x02, kExternTag = 0x04;

void writeSection(Bytes& out, uint8_t id, const Bytes& content) {
  out.u8(id);
  out.appendSized(content);
}

}  // namespace

void Bytes::u32le(uint32_t v) {
  for (int i = 0; i < 4; ++i)
    data_.push_back(static_cast<uint8_t>(v >> (8 * i)));
}

void Bytes::uleb(uint64_t v) {
  do {
    uint8_t byte = v & 0x7F;
    v >>= 7;
    if (v != 0)
      byte |= 0x80;
    data_.push_back(byte);
  } while (v != 0);
}

void Bytes::sleb(int64_t v) {
  bool more = true;
  while (more) {
    uint8_t byte = v & 0x7F;
    v >>= 7;  // arithmetic shift
    bool signBit = (byte & 0x40) != 0;
    if ((v == 0 && !signBit) || (v == -1 && signBit)) {
      more = false;
    } else {
      byte |= 0x80;
    }
    data_.push_back(byte);
  }
}

void Bytes::name(std::string_view s) {
  uleb(s.size());
  data_.insert(data_.end(), s.begin(), s.end());
}

void Bytes::append(const std::vector<uint8_t>& other) {
  data_.insert(data_.end(), other.begin(), other.end());
}

void Bytes::appendSized(const Bytes& other) {
  uleb(other.size());
  append(other);
}

void Code::f32Const(float v) {
  u8(Op::F32Const);
  u32le(std::bit_cast<uint32_t>(v));
}

void Code::f64Const(double v) {
  u8(Op::F64Const);
  const uint64_t bits = std::bit_cast<uint64_t>(v);
  u32le(static_cast<uint32_t>(bits));
  u32le(static_cast<uint32_t>(bits >> 32));
}

void Code::v128Const(const uint8_t (&bytes)[16]) {
  simd(Simd::V128Const);
  for (uint8_t b : bytes)
    u8(b);
}

void Code::i32x4Const(uint32_t a, uint32_t b, uint32_t c, uint32_t d) {
  simd(Simd::V128Const);
  u32le(a);
  u32le(b);
  u32le(c);
  u32le(d);
}

void Code::i8x16Splat(uint8_t v) {
  simd(Simd::V128Const);
  for (int i = 0; i < 16; ++i)
    u8(v);
}

void Code::shuffle(const uint8_t (&lanes)[16]) {
  simd(Simd::I8x16Shuffle);
  for (uint8_t b : lanes)
    u8(b);
}

void Code::brTable(const std::vector<uint32_t>& depths, uint32_t defaultDepth) {
  u8(Op::BrTable);
  uleb(depths.size());
  for (uint32_t d : depths)
    uleb(d);
  uleb(defaultDepth);
}

uint32_t ModuleBuilder::addType(const FuncType& type) {
  auto it = std::find(types_.begin(), types_.end(), type);
  if (it != types_.end())
    return static_cast<uint32_t>(it - types_.begin());
  types_.push_back(type);
  return static_cast<uint32_t>(types_.size() - 1);
}

uint32_t ModuleBuilder::importFunction(std::string_view module, std::string_view field,
                                       uint32_t typeIndex) {
  imports_.name(module);
  imports_.name(field);
  imports_.u8(kExternFunc);
  imports_.uleb(typeIndex);
  ++importCount_;
  funcNames_.emplace_back(importedFuncs_, std::string(field));
  return importedFuncs_++;
}

void ModuleBuilder::importMemory(std::string_view module, std::string_view field,
                                 uint64_t minPages, std::optional<uint64_t> maxPages, bool shared,
                                 bool memory64) {
  imports_.name(module);
  imports_.name(field);
  imports_.u8(kExternMemory);
  uint8_t flags = (maxPages ? 0x01 : 0) | (shared ? 0x02 : 0) | (memory64 ? 0x04 : 0);
  imports_.u8(flags);
  imports_.uleb(minPages);
  if (maxPages)
    imports_.uleb(*maxPages);
  ++importCount_;
}

void ModuleBuilder::importTable(std::string_view module, std::string_view field,
                                uint32_t minSize) {
  imports_.name(module);
  imports_.name(field);
  imports_.u8(kExternTable);
  imports_.u8(kFuncRef);
  imports_.u8(0x00);  // limits: min only, i32 index
  imports_.uleb(minSize);
  ++importCount_;
}

uint32_t ModuleBuilder::importTag(std::string_view module, std::string_view field,
                                  uint32_t typeIndex) {
  imports_.name(module);
  imports_.name(field);
  imports_.u8(kExternTag);
  imports_.u8(0x00);  // attribute: exception
  imports_.uleb(typeIndex);
  ++importCount_;
  return importedTags_++;
}

uint32_t ModuleBuilder::addFunction(uint32_t typeIndex, std::vector<LocalDecl> locals, Code body,
                                    std::string name) {
  uint32_t index = importedFuncs_ + static_cast<uint32_t>(functions_.size());
  functions_.push_back({typeIndex, std::move(locals), std::move(body)});
  funcNames_.emplace_back(index, std::move(name));
  return index;
}

void ModuleBuilder::exportFunction(std::string_view name, uint32_t funcIndex) {
  exports_.push_back({std::string(name), kExternFunc, funcIndex});
}

void ModuleBuilder::addElementSegment(uint32_t offset, std::vector<uint32_t> funcIndices) {
  elements_.push_back({offset, std::move(funcIndices)});
}

std::vector<uint8_t> ModuleBuilder::finish() const {
  Bytes out;
  out.u32le(0x6D736100);  // "\0asm"
  out.u32le(1);           // version

  {
    Bytes s;
    s.uleb(types_.size());
    for (const auto& t : types_) {
      s.u8(0x60);
      s.uleb(t.params.size());
      for (auto v : t.params)
        s.u8(static_cast<uint8_t>(v));
      s.uleb(t.results.size());
      for (auto v : t.results)
        s.u8(static_cast<uint8_t>(v));
    }
    writeSection(out, kSectionType, s);
  }

  if (importCount_ != 0) {
    Bytes s;
    s.uleb(importCount_);
    s.append(imports_);
    writeSection(out, kSectionImport, s);
  }

  {
    Bytes s;
    s.uleb(functions_.size());
    for (const auto& f : functions_)
      s.uleb(f.type);
    writeSection(out, kSectionFunction, s);
  }

  if (!exports_.empty()) {
    Bytes s;
    s.uleb(exports_.size());
    for (const auto& e : exports_) {
      s.name(e.name);
      s.u8(e.kind);
      s.uleb(e.index);
    }
    writeSection(out, kSectionExport, s);
  }

  if (!elements_.empty()) {
    Bytes s;
    s.uleb(elements_.size());
    for (const auto& e : elements_) {
      s.u8(0x00);  // active, table 0, funcref, offset expression
      s.u8(Op::I32Const);
      s.sleb(static_cast<int32_t>(e.offset));
      s.u8(Op::End);
      s.uleb(e.funcs.size());
      for (uint32_t f : e.funcs)
        s.uleb(f);
    }
    writeSection(out, kSectionElement, s);
  }

  {
    Bytes s;
    s.uleb(functions_.size());
    for (const auto& f : functions_) {
      Bytes body;
      body.uleb(f.locals.size());
      for (const auto& l : f.locals) {
        body.uleb(l.count);
        body.u8(static_cast<uint8_t>(l.type));
      }
      body.append(f.body);
      body.u8(Op::End);
      s.appendSized(body);
    }
    writeSection(out, kSectionCode, s);
  }

  {
    Bytes s;
    s.name("name");
    if (!moduleName_.empty()) {
      Bytes sub;
      sub.name(moduleName_);
      s.u8(0);
      s.appendSized(sub);
    }
    Bytes sub;
    sub.uleb(funcNames_.size());
    for (const auto& [index, name] : funcNames_) {
      sub.uleb(index);
      sub.name(name);
    }
    s.u8(1);
    s.appendSized(sub);
    writeSection(out, kSectionCustom, s);
  }

  return out.data();
}

}  // namespace rex::codegen::wasm
