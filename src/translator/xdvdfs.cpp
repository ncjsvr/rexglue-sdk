/**
 * @file        translator/xdvdfs.cpp
 * @brief       Reads one file from an Xbox 360 disc image (XDVDFS / "XISO")
 *
 * @copyright   Copyright (c) 2026 MCLA-Reborn contributors
 * @license     Not yet licensed: MCLA-Reborn decides before any release (D-009)
 */

#include "xdvdfs.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>

namespace rex::translator {

namespace {

constexpr uint64_t kSectorSize = 2048;
constexpr uint64_t kVolumeDescriptorSector = 32;
constexpr char kVolumeMagic[] = "MICROSOFT*XBOX*MEDIA";  // 20 bytes
// Plain XISO, XGD1, XGD2, XGD3 (crates/xiso PARTITION_BASES).
constexpr uint64_t kPartitionBases[] = {0, 0x18300000, 0x0FD90000, 0x02080000};
constexpr uint32_t kMaxDirectorySize = 16 * 1024 * 1024;
constexpr uint8_t kAttrDirectory = 0x10;
constexpr size_t kEntryHeader = 14;

struct FileCloser {
  void operator()(std::FILE* f) const { std::fclose(f); }
};
using File = std::unique_ptr<std::FILE, FileCloser>;

struct Entry {
  std::string name;
  uint32_t sector = 0;
  uint32_t size = 0;
  bool isDir = false;
};

uint32_t U32Le(const uint8_t* p) {
  return uint32_t(p[0]) | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24;
}

bool ReadAt(std::FILE* f, uint64_t offset, void* dst, size_t len) {
  if (fseeko(f, static_cast<off_t>(offset), SEEK_SET) != 0)
    return false;
  return std::fread(dst, 1, len, f) == len;
}

bool EqualsIgnoreCase(const std::string& a, const std::string& b) {
  if (a.size() != b.size())
    return false;
  for (size_t i = 0; i < a.size(); ++i) {
    auto lower = [](char c) { return (c >= 'A' && c <= 'Z') ? char(c - 'A' + 'a') : c; };
    if (lower(a[i]) != lower(b[i]))
      return false;
  }
  return true;
}

/// Walks one directory table's binary tree looking for `name`. Bounds- and cycle-checked.
bool FindInTable(const std::vector<uint8_t>& table, const std::string& name, Entry& out,
                 std::string& error) {
  if (table.empty() || (table.size() >= 4 && table[0] == 0xFF && table[1] == 0xFF &&
                        table[2] == 0xFF && table[3] == 0xFF))
    return false;
  std::vector<bool> visited(table.size() / 4 + 1, false);
  std::vector<size_t> stack{0};
  while (!stack.empty()) {
    const size_t offset = stack.back();
    stack.pop_back();
    if (offset + kEntryHeader > table.size()) {
      error = "directory entry out of bounds";
      return false;
    }
    if (visited[offset / 4]) {
      error = "directory cycle";
      return false;
    }
    visited[offset / 4] = true;
    const uint8_t* h = table.data() + offset;
    const uint16_t left = uint16_t(h[0] | h[1] << 8), right = uint16_t(h[2] | h[3] << 8);
    const size_t nameLen = h[13];
    if ((left == 0xFFFF && right == 0xFFFF) || nameLen == 0 ||
        offset + kEntryHeader + nameLen > table.size()) {
      error = "invalid directory entry";
      return false;
    }
    Entry e;
    e.name.assign(reinterpret_cast<const char*>(h + kEntryHeader), nameLen);
    e.sector = U32Le(h + 4);
    e.size = U32Le(h + 8);
    e.isDir = (h[12] & kAttrDirectory) != 0;
    if (EqualsIgnoreCase(e.name, name)) {
      out = std::move(e);
      return true;
    }
    if (left)
      stack.push_back(size_t(left) * 4);
    if (right)
      stack.push_back(size_t(right) * 4);
  }
  return false;
}

}  // namespace

bool ReadDiscFile(const std::filesystem::path& image, const std::string& path, DiscFile& out,
                  std::string& error) {
  File f(std::fopen(image.string().c_str(), "rb"));
  if (!f) {
    error = "cannot open " + image.string();
    return false;
  }
  if (fseeko(f.get(), 0, SEEK_END) != 0) {
    error = "cannot seek " + image.string();
    return false;
  }
  const uint64_t length = static_cast<uint64_t>(ftello(f.get()));

  bool found = false;
  Entry current;
  for (uint64_t base : kPartitionBases) {
    const uint64_t at = base + kVolumeDescriptorSector * kSectorSize;
    uint8_t header[28];
    if (at + sizeof(header) > length || !ReadAt(f.get(), at, header, sizeof(header)))
      continue;
    if (std::memcmp(header, kVolumeMagic, 20) != 0)
      continue;
    out.partitionBase = base;
    current = {"", U32Le(header + 20), U32Le(header + 24), true};
    found = true;
    break;
  }
  if (!found) {
    error = "no XDVDFS volume descriptor in " + image.string();
    return false;
  }
  auto extentEnd = [&](const Entry& e) {
    return out.partitionBase + uint64_t(e.sector) * kSectorSize + e.size;
  };

  size_t start = 0;
  while (start <= path.size()) {
    size_t end = path.find_first_of("/\\", start);
    if (end == std::string::npos)
      end = path.size();
    const std::string component = path.substr(start, end - start);
    start = end + 1;
    if (component.empty())
      continue;
    if (!current.isDir) {
      error = path + ": not found";
      return false;
    }
    if (current.size > kMaxDirectorySize || extentEnd(current) > length) {
      error = "directory table out of bounds";
      return false;
    }
    std::vector<uint8_t> table(current.size);
    if (!table.empty() &&
        !ReadAt(f.get(), out.partitionBase + uint64_t(current.sector) * kSectorSize, table.data(),
                table.size())) {
      error = "cannot read a directory table";
      return false;
    }
    Entry next;
    if (!FindInTable(table, component, next, error)) {
      if (error.empty())
        error = path + ": not found";
      return false;
    }
    current = std::move(next);
  }
  if (current.isDir) {
    error = path + ": is a directory";
    return false;
  }
  if (extentEnd(current) > length) {
    error = path + ": extent out of bounds";
    return false;
  }
  out.bytes.resize(current.size);
  // Bounded reads, 4 MiB at a time.
  const uint64_t fileStart = out.partitionBase + uint64_t(current.sector) * kSectorSize;
  for (size_t done = 0; done < out.bytes.size();) {
    const size_t n = std::min<size_t>(out.bytes.size() - done, 4u << 20);
    if (!ReadAt(f.get(), fileStart + done, out.bytes.data() + done, n)) {
      error = "cannot read " + path;
      return false;
    }
    done += n;
  }
  return true;
}

}  // namespace rex::translator
