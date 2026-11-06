/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2020 Ben Vanik. All rights reserved.                             *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 */

#pragma once

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
#include <type_traits>

#include <rex/assert.h>
#include <rex/platform.h>
#include <rex/types.h>

namespace rex {
namespace memory {

// For variable declarations (not return values or `this` pointer).
// Not propagated.
#define REX_RESTRICT_VAR __restrict

// Aliasing-safe bit reinterpretation.
// For more complex cases such as non-trivially-copyable types, write copying
// code respecting the requirements for them externally instead of using these
// functions.

template <typename Dst, typename Src>
void Reinterpret(Dst& REX_RESTRICT_VAR dst, const Src& REX_RESTRICT_VAR src) {
  static_assert(sizeof(Dst) == sizeof(Src));
  static_assert(std::is_trivially_copyable_v<Dst>);
  static_assert(std::is_trivially_copyable_v<Src>);
  std::memcpy(&dst, &src, sizeof(Dst));
}

template <typename Dst, typename Src>
Dst Reinterpret(const Src& REX_RESTRICT_VAR src) {
  Dst dst;
  Reinterpret(dst, src);
  return dst;
}

#if REX_PLATFORM_ANDROID
void AndroidInitialize();
void AndroidShutdown();
#endif

// Returns the native page size of the system, in bytes.
// This should be ~4KiB.
size_t page_size();

// Returns the allocation granularity of the system, in bytes.
// This is likely 64KiB.
size_t allocation_granularity();

enum class PageAccess {
  kNoAccess = 0,
  kReadOnly = 1 << 0,
  kReadWrite = kReadOnly | 1 << 1,
  kExecuteReadOnly = kReadOnly | 1 << 2,
  kExecuteReadWrite = kReadWrite | 1 << 2,
};

enum class AllocationType {
  kReserve = 1 << 0,
  kCommit = 1 << 1,
  kReserveCommit = kReserve | kCommit,
};

enum class DeallocationType {
  kRelease = 1 << 0,
  kDecommit = 1 << 1,
};

// Whether the host allows the pages to be allocated or mapped with
// PageAccess::kExecuteReadWrite - if not, separate mappings backed by the same
// memory-mapped file must be used to write to executable pages.
bool IsWritableExecutableMemorySupported();

// Whether PageAccess::kExecuteReadWrite is a supported and preferred way of
// writing executable memory, useful for simulating how Xenia would work without
// writable executable memory on a system with it.
bool IsWritableExecutableMemoryPreferred();

// Allocates a block of memory at the given page-aligned base address.
// Fails if the memory is not available.
// Specify nullptr for base_address to leave it up to the system.
void* AllocFixed(void* base_address, size_t length, AllocationType allocation_type,
                 PageAccess access);

// Deallocates and/or releases the given block of memory.
// When releasing memory length must be zero, as all pages in the region are
// released.
bool DeallocFixed(void* base_address, size_t length, DeallocationType deallocation_type);

// Sets the access rights for the given block of memory and returns the previous
// access rights. Both base_address and length will be adjusted to page_size().
bool Protect(void* base_address, size_t length, PageAccess access,
             PageAccess* out_old_access = nullptr);

// Queries a region of pages to get the access rights. This will modify the
// length parameter to the length of pages with the same consecutive access
// rights. The length will start from the first byte of the first page of
// the region.
bool QueryProtect(void* base_address, size_t& length, PageAccess& access_out);

// Allocates a block of memory for a type with the given alignment.
// The memory must be freed with AlignedFree.
template <typename T>
inline T* AlignedAlloc(size_t alignment) {
#if REX_PLATFORM_WIN32
  return reinterpret_cast<T*>(_aligned_malloc(sizeof(T), alignment));
#else
  void* ptr = nullptr;
  if (posix_memalign(&ptr, alignment, sizeof(T))) {
    return nullptr;
  }
  return reinterpret_cast<T*>(ptr);
#endif
}

// Frees memory previously allocated with AlignedAlloc.
template <typename T>
void AlignedFree(T* ptr) {
#if REX_PLATFORM_WIN32
  _aligned_free(ptr);
#else
  free(ptr);
#endif
}

// MCLA-Reborn (T-017): an externally owned, already reserved range of host memory (the native
// harness's wasmtime shared memory). Inside it AllocFixed with kReserve returns the address
// unchanged, kReserveCommit only commits, and DeallocFixed with kRelease does nothing; commit,
// decommit and protection work as usual. Not set by any other build.
void SetExternalArena(void* base, size_t size);
bool IsInExternalArena(const void* address);

// MCLA-Reborn (T-017): turns on swapped guest storage (rex/types.h) for the code in this
// module (the runtime DLL). The caller also calls guest_storage::EnableLocal for its own.
void EnableSwappedGuestStorage(void* guest_base, size_t size);

// Opaque file mapping handle.
// On Windows this holds a HANDLE (void*), on POSIX a file descriptor (int).
// We use intptr_t to hold either without platform guards.
using FileMappingHandle = intptr_t;
constexpr FileMappingHandle kFileMappingHandleInvalid = -1;

FileMappingHandle CreateFileMappingHandle(const std::filesystem::path& path, size_t length,
                                          PageAccess access, bool commit);
void CloseFileMappingHandle(FileMappingHandle handle, const std::filesystem::path& path);
void* MapFileView(FileMappingHandle handle, void* base_address, size_t length, PageAccess access,
                  size_t file_offset);
bool UnmapFileView(FileMappingHandle handle, void* base_address, size_t length);

inline size_t hash_combine(size_t seed) {
  return seed;
}

template <typename T, typename... Ts>
size_t hash_combine(size_t seed, const T& v, const Ts&... vs) {
  std::hash<T> hasher;
  seed ^= hasher(v) + 0x9E3779B9 + (seed << 6) + (seed >> 2);
  return hash_combine(seed, vs...);
}

inline void* low_address(void* address) {
  return reinterpret_cast<void*>(uint64_t(address) & 0xFFFFFFFF);
}

void copy_128_aligned(void* dest, const void* src, size_t count);

void copy_and_swap_16_aligned(void* dest, const void* src, size_t count);
void copy_and_swap_16_unaligned(void* dest, const void* src, size_t count);
void copy_and_swap_32_aligned(void* dest, const void* src, size_t count);
void copy_and_swap_32_unaligned(void* dest, const void* src, size_t count);
void copy_and_swap_64_aligned(void* dest, const void* src, size_t count);
void copy_and_swap_64_unaligned(void* dest, const void* src, size_t count);
void copy_and_swap_16_in_32_aligned(void* dest, const void* src, size_t count);
void copy_and_swap_16_in_32_unaligned(void* dest, const void* src, size_t count);

template <typename T>
void copy_and_swap(T* dest, const T* src, size_t count) {
  if (guest_storage::enabled() && sizeof(T) <= 8 &&
      (guest_storage::contains(src) || guest_storage::contains(dest))) [[unlikely]] {
    // Swapped guest storage (MCLA-Reborn harness): element by element in the guest layout.
    using U = guest_storage::uint_of<T>;
    for (size_t i = 0; i < count; ++i) {
      U v;
      if (guest_storage::contains(src + i)) {
        v = guest_storage::load<U>(src + i);
      } else {
        std::memcpy(&v, src + i, sizeof(U));  // host values going into guest memory
      }
      if (guest_storage::contains(dest + i)) {
        guest_storage::store<U>(dest + i, v);
      } else {
        std::memcpy(dest + i, &v, sizeof(U));
      }
    }
    return;
  }
  bool is_aligned =
      reinterpret_cast<uintptr_t>(dest) % 32 == 0 && reinterpret_cast<uintptr_t>(src) % 32 == 0;
  if (sizeof(T) == 1) {
    std::memcpy(dest, src, count);
  } else if (sizeof(T) == 2) {
    auto ps = reinterpret_cast<const uint16_t*>(src);
    auto pd = reinterpret_cast<uint16_t*>(dest);
    if (is_aligned) {
      copy_and_swap_16_aligned(pd, ps, count);
    } else {
      copy_and_swap_16_unaligned(pd, ps, count);
    }
  } else if (sizeof(T) == 4) {
    auto ps = reinterpret_cast<const uint32_t*>(src);
    auto pd = reinterpret_cast<uint32_t*>(dest);
    if (is_aligned) {
      copy_and_swap_32_aligned(pd, ps, count);
    } else {
      copy_and_swap_32_unaligned(pd, ps, count);
    }
  } else if (sizeof(T) == 8) {
    auto ps = reinterpret_cast<const uint64_t*>(src);
    auto pd = reinterpret_cast<uint64_t*>(dest);
    if (is_aligned) {
      copy_and_swap_64_aligned(pd, ps, count);
    } else {
      copy_and_swap_64_unaligned(pd, ps, count);
    }
  } else {
    assert_always("Invalid memory::copy_and_swap size");
  }
}

/// Load a value of type T from arbitrary memory (handles unaligned access).
template <typename T>
inline T load(const void* mem) {
  static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
  T result;
  if (guest_storage::contains(mem)) [[unlikely]] {
    // Swapped guest storage: the bytes as the guest sees them (what a native raw load gives).
    auto d = reinterpret_cast<uint8_t*>(&result);
    for (size_t i = 0; i < sizeof(T); ++i) {
      d[i] = guest_storage::load<uint8_t>(static_cast<const uint8_t*>(mem) + i);
    }
    return result;
  }
  std::memcpy(&result, mem, sizeof(T));
  return result;
}

/// Load a value of type T from memory and byte-swap it. Inside swapped guest storage
/// (MCLA-Reborn harness, rex/types.h) this reads the guest value in that layout instead.
template <typename T>
inline T load_and_swap(const void* mem) {
  if (guest_storage::contains(mem)) [[unlikely]] {
    return guest_storage::load<T>(mem);
  }
  return byte_swap(load<T>(mem));
}

// String specializations need custom logic
template <>
inline std::string load_and_swap<std::string>(const void* mem) {
  std::string value;
  for (int i = 0;; ++i) {
    auto c = load_and_swap<uint8_t>(reinterpret_cast<const uint8_t*>(mem) + i);
    if (!c) {
      break;
    }
    value.push_back(static_cast<char>(c));
  }
  return value;
}
template <>
inline std::u16string load_and_swap<std::u16string>(const void* mem) {
  std::u16string value;
  for (int i = 0;; ++i) {
    auto c = load_and_swap<uint16_t>(reinterpret_cast<const uint16_t*>(mem) + i);
    if (!c) {
      break;
    }
    value.push_back(static_cast<wchar_t>(c));
  }
  return value;
}

/// Store a value of type T to arbitrary memory (handles unaligned access).
template <typename T>
inline void store(void* mem, const T& value) {
  static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
  if (guest_storage::contains(mem)) [[unlikely]] {
    auto s = reinterpret_cast<const uint8_t*>(&value);
    for (size_t i = 0; i < sizeof(T); ++i) {
      guest_storage::store<uint8_t>(static_cast<uint8_t*>(mem) + i, s[i]);
    }
    return;
  }
  std::memcpy(mem, &value, sizeof(T));
}

/// Store a byte-swapped value of type T to memory (swapped guest storage aware, as above).
template <typename T>
inline void store_and_swap(void* mem, const T& value) {
  if (guest_storage::contains(mem)) [[unlikely]] {
    guest_storage::store<T>(mem, value);
    return;
  }
  store(mem, byte_swap(value));
}

//=============================================================================
// Raw byte transfers between host buffers and guest memory (MCLA-Reborn, T-017)
//=============================================================================
// Byte streams (file contents, strings, packets) copied into or out of guest memory must be
// converted at the boundary when guest memory uses swapped storage (ADR-0009). Outside it, or
// with swapped storage disabled, these are plain memcpy/memset.

/// Copies `size` bytes in guest byte order from `src` into guest memory at host address `dst`.
inline void copy_to_guest(void* dst, const void* src, size_t size) {
  if (!guest_storage::contains(dst)) {
    std::memcpy(dst, src, size);
    return;
  }
  const uintptr_t a = reinterpret_cast<uintptr_t>(dst);
  auto s = static_cast<const uint8_t*>(src);
  size_t i = 0;
  for (; i < size && ((a + i) & 3); ++i) {
    *reinterpret_cast<uint8_t*>((a + i) ^ 3) = s[i];
  }
  for (; i + 4 <= size; i += 4) {
    uint32_t w;
    std::memcpy(&w, s + i, 4);
    w = byte_swap(w);
    std::memcpy(reinterpret_cast<void*>(a + i), &w, 4);
  }
  for (; i < size; ++i) {
    *reinterpret_cast<uint8_t*>((a + i) ^ 3) = s[i];
  }
}

/// Copies `size` bytes in guest byte order out of guest memory at host address `src`.
inline void copy_from_guest(void* dst, const void* src, size_t size) {
  if (!guest_storage::contains(src)) {
    std::memcpy(dst, src, size);
    return;
  }
  const uintptr_t a = reinterpret_cast<uintptr_t>(src);
  auto d = static_cast<uint8_t*>(dst);
  size_t i = 0;
  for (; i < size && ((a + i) & 3); ++i) {
    d[i] = *reinterpret_cast<const uint8_t*>((a + i) ^ 3);
  }
  for (; i + 4 <= size; i += 4) {
    uint32_t w;
    std::memcpy(&w, reinterpret_cast<const void*>(a + i), 4);
    w = byte_swap(w);
    std::memcpy(d + i, &w, 4);
  }
  for (; i < size; ++i) {
    d[i] = *reinterpret_cast<const uint8_t*>((a + i) ^ 3);
  }
}

/// Converts a guest-memory range written as plain big-endian bytes (for example by a loader
/// that copied file data in) to swapped storage, in place. Word aligned ranges only.
inline void swap_guest_words_in_place(void* p, size_t size) {
  if (!guest_storage::contains(p)) {
    return;
  }
  auto w = static_cast<uint32_t*>(p);
  for (size_t i = 0; i < size / 4; ++i) {
    w[i] = byte_swap(w[i]);
  }
}

/// Reads a NUL-terminated (or `max`-limited) byte string from guest memory.
inline std::string read_guest_string(const void* src, size_t max = SIZE_MAX) {
  std::string s;
  auto p = static_cast<const uint8_t*>(src);
  for (size_t i = 0; i < max; ++i) {
    uint8_t c = guest_storage::contains(p + i) ? guest_storage::load<uint8_t>(p + i) : p[i];
    if (!c) {
      break;
    }
    s.push_back(static_cast<char>(c));
  }
  return s;
}

// String specializations need custom logic
template <>
inline void store_and_swap<std::string_view>(void* mem, const std::string_view& value) {
  for (size_t i = 0; i < value.size(); ++i) {
    store_and_swap<uint8_t>(reinterpret_cast<uint8_t*>(mem) + i, value[i]);
  }
}
template <>
inline void store_and_swap<std::string>(void* mem, const std::string& value) {
  return store_and_swap<std::string_view>(mem, value);
}
template <>
inline void store_and_swap<std::u16string_view>(void* mem, const std::u16string_view& value) {
  for (size_t i = 0; i < value.size(); ++i) {
    store_and_swap<uint16_t>(reinterpret_cast<uint16_t*>(mem) + i, value[i]);
  }
}
template <>
inline void store_and_swap<std::u16string>(void* mem, const std::u16string& value) {
  return store_and_swap<std::u16string_view>(mem, value);
}

using fourcc_t = uint32_t;

// Get FourCC in host byte order
// make_fourcc('a', 'b', 'c', 'd') == 0x61626364
constexpr inline fourcc_t make_fourcc(char a, char b, char c, char d) {
  return fourcc_t((static_cast<fourcc_t>(a) << 24) | (static_cast<fourcc_t>(b) << 16) |
                  (static_cast<fourcc_t>(c) << 8) | static_cast<fourcc_t>(d));
}

// Get FourCC in host byte order
// This overload requires fourcc.length() == 4
// make_fourcc("abcd") == 'abcd' == 0x61626364 for most compilers
constexpr inline fourcc_t make_fourcc(const std::string_view fourcc) {
  if (fourcc.length() != 4) {
    throw std::runtime_error("Invalid fourcc length");
  }
  return make_fourcc(fourcc[0], fourcc[1], fourcc[2], fourcc[3]);
}

}  // namespace memory
}  // namespace rex
