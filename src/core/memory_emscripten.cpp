/**
 * @file        core/memory_emscripten.cpp
 * @brief       Host memory primitives for the Emscripten translator tool
 *
 * @copyright   Copyright (c) 2026 MCLA-Reborn contributors
 * @license     Not yet licensed: MCLA-Reborn decides before any release (D-009)
 *
 * The translator tool (rexglue-translate) only loads an XEX image into guest memory and reads
 * it back; nothing runs there. WebAssembly linear memory can't reserve, protect or alias
 * pages, so the guest address space is one plain allocation (see Memory::Initialize): the
 * "file mapping" is that allocation, a view is a pointer into it, committing is a no-op,
 * decommitting zeroes, and protection is not enforced. The allocation isn't zeroed up front
 * (that would touch all 4.5 GiB): the XEX loader zeroes the image range before filling it, and
 * a first large allocation comes from fresh, zeroed linear memory anyway.
 *
 * The browser runtime (T-022) instead sets an external arena: the guest range reserved inside
 * the module's own linear memory (the shared memory the translated chunks import). Inside it
 * every page already exists: reserving and committing return the address, releasing does
 * nothing, decommitting zeroes, and protection is not enforced.
 */

#include <cstdlib>
#include <cstring>

#include <rex/memory/utils.h>
#include <rex/platform.h>

#if !REX_PLATFORM_EMSCRIPTEN
#error memory_emscripten.cpp is for Emscripten builds only
#endif

namespace rex::memory {

namespace {

struct Mapping {
  uint8_t* base = nullptr;
  size_t length = 0;
};
Mapping g_mapping;
uintptr_t g_arena_base = 0;
size_t g_arena_size = 0;

bool InMapping(const void* address, size_t length) {
  auto* p = static_cast<const uint8_t*>(address);
  if (g_arena_size) {
    auto a = reinterpret_cast<uintptr_t>(address);
    return a >= g_arena_base && length <= g_arena_size && a - g_arena_base <= g_arena_size - length;
  }
  return g_mapping.base && p >= g_mapping.base && length <= g_mapping.length &&
         static_cast<size_t>(p - g_mapping.base) <= g_mapping.length - length;
}

}  // namespace

void SetExternalArena(void* base, size_t size) {
  g_arena_base = reinterpret_cast<uintptr_t>(base);
  g_arena_size = size;
}

bool IsInExternalArena(const void* address) {
  return reinterpret_cast<uintptr_t>(address) - g_arena_base < g_arena_size;
}

size_t page_size() {
  return 4096;
}

size_t allocation_granularity() {
  return 64 * 1024;
}

bool IsWritableExecutableMemorySupported() {
  return false;
}

void* AllocFixed(void* base_address, size_t length, AllocationType allocation_type,
                 PageAccess access) {
  (void)allocation_type;
  (void)access;
  if (base_address) {
    // Inside the guest allocation: the pages already exist.
    return InMapping(base_address, length) ? base_address : nullptr;
  }
  void* p = std::aligned_alloc(allocation_granularity(),
                               (length + allocation_granularity() - 1) &
                                   ~(allocation_granularity() - 1));
  if (p)
    std::memset(p, 0, length);
  return p;
}

bool DeallocFixed(void* base_address, size_t length, DeallocationType deallocation_type) {
  if (InMapping(base_address, length)) {
    if (deallocation_type == DeallocationType::kDecommit && length)
      std::memset(base_address, 0, length);
    return true;
  }
  if (deallocation_type == DeallocationType::kRelease)
    std::free(base_address);
  return true;
}

bool Protect(void* base_address, size_t length, PageAccess access, PageAccess* out_old_access) {
  (void)base_address;
  (void)length;
  (void)access;
  if (out_old_access)
    *out_old_access = PageAccess::kReadWrite;
  return true;
}

bool QueryProtect(void* base_address, size_t& length, PageAccess& access_out) {
  (void)base_address;
  (void)length;
  access_out = PageAccess::kReadWrite;
  return true;
}

FileMappingHandle CreateFileMappingHandle(const std::filesystem::path& path, size_t length,
                                          PageAccess access, bool commit) {
  (void)path;
  (void)access;
  (void)commit;
  if (g_mapping.base)
    return kFileMappingHandleInvalid;  // one guest address space per process
  // Not zeroed on purpose (see the file comment): untouched pages cost the host nothing.
  void* p = std::aligned_alloc(allocation_granularity(), length);
  if (!p)
    return kFileMappingHandleInvalid;
  g_mapping = {static_cast<uint8_t*>(p), length};
  return reinterpret_cast<FileMappingHandle>(p);
}

void CloseFileMappingHandle(FileMappingHandle handle, const std::filesystem::path& path) {
  (void)path;
  if (handle != kFileMappingHandleInvalid &&
      reinterpret_cast<uint8_t*>(handle) == g_mapping.base) {
    std::free(g_mapping.base);
    g_mapping = {};
  }
}

void* MapFileView(FileMappingHandle handle, void* base_address, size_t length, PageAccess access,
                  size_t file_offset) {
  (void)handle;
  (void)access;
  (void)file_offset;
  // Views are laid out back to back inside the one allocation; aliases are not supported.
  return InMapping(base_address, length) ? base_address : nullptr;
}

bool UnmapFileView(FileMappingHandle handle, void* base_address, size_t length) {
  (void)handle;
  (void)base_address;
  (void)length;
  return true;
}

}  // namespace rex::memory
