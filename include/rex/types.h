/**
 * @file        types.h
 * @brief       Core type definitions and aliases
 *
 * @copyright   Copyright (c) 2026 Tom Clay <tomc@tctechstuff.com>
 *              All rights reserved.
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 */

#pragma once

#include <bit>
#include <compare>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <type_traits>

#include <rex/assert.h>
#include <rex/platform.h>

// Check for mixed endian
static_assert((std::endian::native == std::endian::big) ||
              (std::endian::native == std::endian::little));

namespace rex {

/// Byte-swap a value of any trivially copyable type (1, 2, 4, or 8 bytes).
/// Uses std::bit_cast for safe type punning and std::byteswap for the swap.
template <class T>
constexpr T byte_swap(T value) noexcept {
  static_assert(sizeof(T) == 8 || sizeof(T) == 4 || sizeof(T) == 2 || sizeof(T) == 1,
                "byte_swap(T value): Type T has illegal size");
  if constexpr (sizeof(T) == 1) {
    return value;
  } else {
    // Convert to unsigned integer of same size, byteswap, convert back
    using uint_t = std::conditional_t<sizeof(T) == 8, uint64_t,
                                      std::conditional_t<sizeof(T) == 4, uint32_t, uint16_t>>;
    return std::bit_cast<T>(std::byteswap(std::bit_cast<uint_t>(value)));
  }
}

//=============================================================================
// Swapped guest storage (MCLA-Reborn, T-017, ADR-0009)
//=============================================================================
// The MCLA-Reborn native harness runs translated WebAssembly whose guest memory holds 32-bit
// words in host order: a byte at guest address a lives at a ^ 3, a halfword at a ^ 2, a
// doubleword is two words (high word first) and so reads as a 64-bit load rotated by 32.
// When the harness enables it, every big-endian access the runtime makes to a host address
// inside the guest range follows that layout, while big-endian data in host memory (file
// headers and the like) keeps its plain meaning. Disabled, which is the default and the only
// state any other build sees, nothing changes.
namespace guest_storage {

struct Range {
  uintptr_t base = 0;
  uintptr_t size = 0;
};

// One copy per module (a DLL and the executable each have their own); the harness sets both
// through Enable() in the runtime DLL and EnableLocal() in its own code.
inline Range g_range;

inline void EnableLocal(void* base, size_t size) noexcept {
  g_range.base = reinterpret_cast<uintptr_t>(base);
  g_range.size = size;
}
inline bool enabled() noexcept {
  return g_range.size != 0;
}
inline bool contains(const void* p) noexcept {
  return reinterpret_cast<uintptr_t>(p) - g_range.base < g_range.size;
}

template <class T>
using uint_of = std::conditional_t<
    sizeof(T) == 8, uint64_t,
    std::conditional_t<sizeof(T) == 4, uint32_t,
                       std::conditional_t<sizeof(T) == 2, uint16_t, uint8_t>>>;

// Loads the guest value of type T stored at host address p (inside the guest range).
template <class T>
inline T load(const void* p) noexcept {
  static_assert(sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8);
  using U = uint_of<T>;
  const uintptr_t a = reinterpret_cast<uintptr_t>(p);
  if constexpr (sizeof(T) == 1) {
    return std::bit_cast<T>(*reinterpret_cast<const volatile uint8_t*>(a ^ 3));
  } else if constexpr (sizeof(T) == 2) {
    if (!(a & 1)) {
      U v;
      std::memcpy(&v, reinterpret_cast<const void*>(a ^ 2), 2);
      return std::bit_cast<T>(v);
    }
  } else if constexpr (sizeof(T) == 4) {
    if (!(a & 3)) {
      U v;
      std::memcpy(&v, p, 4);
      return std::bit_cast<T>(v);
    }
  } else {
    if (!(a & 3)) {
      U v;
      std::memcpy(&v, p, 8);
      return std::bit_cast<T>(static_cast<U>((v << 32) | (v >> 32)));
    }
  }
  U v = 0;  // misaligned: assemble the big-endian value byte by byte
  for (size_t k = 0; k < sizeof(T); ++k) {
    v = static_cast<U>((uint64_t(v) << 8) | *reinterpret_cast<const uint8_t*>((a + k) ^ 3));
  }
  return std::bit_cast<T>(v);
}

// Stores the guest value of type T at host address p (inside the guest range).
template <class T>
inline void store(void* p, const T& value) noexcept {
  static_assert(sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8);
  using U = uint_of<T>;
  const uintptr_t a = reinterpret_cast<uintptr_t>(p);
  U v = std::bit_cast<U>(value);
  if constexpr (sizeof(T) == 1) {
    *reinterpret_cast<volatile uint8_t*>(a ^ 3) = v;
    return;
  } else if constexpr (sizeof(T) == 2) {
    if (!(a & 1)) {
      std::memcpy(reinterpret_cast<void*>(a ^ 2), &v, 2);
      return;
    }
  } else if constexpr (sizeof(T) == 4) {
    if (!(a & 3)) {
      std::memcpy(p, &v, 4);
      return;
    }
  } else {
    if (!(a & 3)) {
      U r = static_cast<U>((v << 32) | (v >> 32));
      std::memcpy(p, &r, 8);
      return;
    }
  }
  for (size_t k = sizeof(T); k-- > 0;) {  // misaligned: byte by byte
    *reinterpret_cast<uint8_t*>((a + k) ^ 3) = static_cast<uint8_t>(v);
    v = static_cast<U>(uint64_t(v) >> 8);
  }
}

// A guest NUL-terminated string at host address p (inside the guest range), copied out in guest
// byte order. The view stays valid until the same thread has made 16 more such copies.
template <class C>
inline std::basic_string_view<C> string_view_of(const C* p) noexcept {
  thread_local std::basic_string<C> ring[16];
  thread_local unsigned next = 0;
  auto& s = ring[next++ % 16];
  s.clear();
  for (const C* q = p;; ++q) {
    C c = load<C>(q);
    if (!c) break;
    if constexpr (sizeof(C) == 2) {
      c = static_cast<C>((uint16_t(c) >> 8) | (uint16_t(c) << 8));  // callers expect BE units
    }
    s.push_back(c);
  }
  return s;
}

}  // namespace guest_storage

template <typename T, std::endian E>
struct endian_store {
  using value_type = T;  // Type alias for value() in MappedPtr

  endian_store() = default;
  endian_store(const T& src) { set(src); }
  endian_store(const endian_store&) = default;
  endian_store& operator=(const endian_store&) = default;
  // Assigning a plain value goes through set() (rather than a temporary plus a raw copy), so
  // swapped guest storage gets the right layout.
  endian_store& operator=(const T& src) {
    set(src);
    return *this;
  }
  operator T() const { return get(); }

  void set(const T& src) {
    if constexpr (std::endian::native == E) {
      value = src;
    } else {
      if (guest_storage::contains(this)) [[unlikely]] {
        guest_storage::store<T>(this, src);
        return;
      }
      value = rex::byte_swap(src);
    }
  }
  T get() const {
    if constexpr (std::endian::native == E) {
      return value;
    } else {
      if (guest_storage::contains(this)) [[unlikely]] {
        return guest_storage::load<T>(this);
      }
      return rex::byte_swap(value);
    }
  }

  endian_store<T, E>& operator+=(int a) {
    *this = *this + a;
    return *this;
  }
  endian_store<T, E>& operator-=(int a) {
    *this = *this - a;
    return *this;
  }
  endian_store<T, E>& operator++() {
    *this += 1;
    return *this;
  }  // ++a
  endian_store<T, E> operator++(int) {
    *this += 1;
    return (*this - 1);
  }  // a++
  endian_store<T, E>& operator--() {
    *this -= 1;
    return *this;
  }  // --a
  endian_store<T, E> operator--(int) {
    *this -= 1;
    return (*this + 1);
  }  // a--

  T value;
};

template <typename T>
using be = endian_store<T, std::endian::big>;
template <typename T>
using le = endian_store<T, std::endian::little>;

//=============================================================================
// Big-Endian Type Detection
//=============================================================================

template <typename T>
struct is_be_type : std::false_type {};

template <typename T>
struct is_be_type<rex::be<T>> : std::true_type {};

template <typename T>
inline constexpr bool is_be_type_v = is_be_type<T>::value;

//=============================================================================
// Basic Integer Types
//=============================================================================

using u8 = uint8_t;
using u16 = uint16_t;
using u32 = uint32_t;
using u64 = uint64_t;

using i8 = int8_t;
using i16 = int16_t;
using i32 = int32_t;
using i64 = int64_t;

using f32 = float;
using f64 = double;

static_assert(sizeof(f32) == 4, "float must be 4 bytes");
static_assert(sizeof(f64) == 8, "double must be 8 bytes");

//=============================================================================
// Memory Address Types
//=============================================================================

using guest_addr_t = u32;       // Xbox 360 guest address (32-bit)
using host_addr_t = uintptr_t;  // Host native address (64-bit on x64)

//=============================================================================
// Big-Endian Type Aliases (using rex::be<T>)
//=============================================================================

using be_u8 = u8;  // No byte-swapping needed for single bytes
using be_u16 = be<u16>;
using be_u32 = be<u32>;
using be_u64 = be<u64>;

using be_i8 = i8;
using be_i16 = be<i16>;
using be_i32 = be<i32>;
using be_i64 = be<i64>;

using be_f32 = be<f32>;
using be_f64 = be<f64>;

//=============================================================================
// MappedPtr - Wraps host pointer with guest address tracking
//=============================================================================

template <typename T>
class MappedPtr {
  T* host_ptr_;
  u32 guest_addr_;

 public:
  MappedPtr() : host_ptr_(nullptr), guest_addr_(0) {}
  MappedPtr(T* host_ptr, u32 guest_addr) : host_ptr_(host_ptr), guest_addr_(guest_addr) {}
  MappedPtr(std::nullptr_t) : host_ptr_(nullptr), guest_addr_(0) {}

  static MappedPtr from_host(T* host_ptr) { return MappedPtr(host_ptr, 0); }

  u32 guest_address() const { return guest_addr_; }
  T* host_address() const { return host_ptr_; }

  operator T*() const { return host_ptr_; }

  T* operator->() const { return host_ptr_; }
  T& operator*() const { return *host_ptr_; }

  auto value() const {
    if constexpr (is_be_type_v<T>) {
      return static_cast<typename T::value_type>(*host_ptr_);
    } else {
      return *host_ptr_;
    }
  }

  explicit operator bool() const { return host_ptr_ != nullptr; }
  explicit operator u32() const { return guest_address(); }

  MappedPtr operator+(std::ptrdiff_t offset) const {
    return MappedPtr(host_ptr_ + offset, guest_addr_ + static_cast<u32>(offset * sizeof(T)));
  }
  MappedPtr operator-(std::ptrdiff_t offset) const {
    return MappedPtr(host_ptr_ - offset, guest_addr_ - static_cast<u32>(offset * sizeof(T)));
  }

  template <typename U>
  U as() const {
    return reinterpret_cast<U>(host_ptr_);
  }

  template <typename U>
  rex::be<U>* as_array() const {
    return reinterpret_cast<rex::be<U>*>(host_ptr_);
  }

  void Zero() const {
    if (host_ptr_) {
      std::memset(host_ptr_, 0, sizeof(T));
    }
  }

  void Zero(size_t size) const {
    if (host_ptr_) {
      std::memset(host_ptr_, 0, size);
    }
  }
};

//=============================================================================
// MappedPtr<void> Specialization
//=============================================================================

template <>
class MappedPtr<void> {
  void* host_ptr_;
  u32 guest_addr_;

 public:
  MappedPtr() : host_ptr_(nullptr), guest_addr_(0) {}
  MappedPtr(void* host_ptr, u32 guest_addr) : host_ptr_(host_ptr), guest_addr_(guest_addr) {}
  MappedPtr(std::nullptr_t) : host_ptr_(nullptr), guest_addr_(0) {}

  static MappedPtr from_host(void* host_ptr) { return MappedPtr(host_ptr, 0); }

  u32 guest_address() const { return guest_addr_; }
  u32 value() const { return guest_addr_; }
  void* host_address() const { return host_ptr_; }

  operator void*() const { return host_ptr_; }
  operator uint8_t*() const { return static_cast<uint8_t*>(host_ptr_); }
  explicit operator bool() const { return host_ptr_ != nullptr; }
  explicit operator u32() const { return guest_addr_; }

  template <std::integral IntType>
  MappedPtr operator+(IntType offset) const {
    return MappedPtr(static_cast<uint8_t*>(host_ptr_) + static_cast<std::ptrdiff_t>(offset),
                     guest_addr_ + static_cast<u32>(offset));
  }
  template <std::integral IntType>
  MappedPtr operator-(IntType offset) const {
    return MappedPtr(static_cast<uint8_t*>(host_ptr_) - static_cast<std::ptrdiff_t>(offset),
                     guest_addr_ - static_cast<u32>(offset));
  }

  template <typename U>
  U as() const {
    return reinterpret_cast<U>(host_ptr_);
  }

  template <typename U>
  rex::be<U>* as_array() const {
    return reinterpret_cast<rex::be<U>*>(host_ptr_);
  }

  void Zero(size_t size) const {
    if (host_ptr_) {
      std::memset(host_ptr_, 0, size);
    }
  }
};

//=============================================================================
// MappedPtr<char> Specialization (strings)
//=============================================================================

template <>
class MappedPtr<char> {
  char* host_ptr_;
  u32 guest_addr_;

 public:
  MappedPtr() : host_ptr_(nullptr), guest_addr_(0) {}
  MappedPtr(char* host_ptr, u32 guest_addr) : host_ptr_(host_ptr), guest_addr_(guest_addr) {}
  MappedPtr(std::nullptr_t) : host_ptr_(nullptr), guest_addr_(0) {}

  u32 guest_address() const { return guest_addr_; }
  char* host_address() const { return host_ptr_; }

  operator char*() const { return host_ptr_; }
  explicit operator bool() const { return host_ptr_ != nullptr; }

  std::string_view value() const {
    if (host_ptr_ && guest_storage::contains(host_ptr_)) [[unlikely]] {
      return guest_storage::string_view_of(host_ptr_);  // swapped guest storage (T-017)
    }
    return host_ptr_ ? std::string_view(host_ptr_) : std::string_view();
  }

  char* operator->() const { return host_ptr_; }
  char& operator*() const { return *host_ptr_; }

  MappedPtr operator+(std::ptrdiff_t offset) const {
    return MappedPtr(host_ptr_ + offset, guest_addr_ + static_cast<u32>(offset));
  }
  MappedPtr operator-(std::ptrdiff_t offset) const {
    return MappedPtr(host_ptr_ - offset, guest_addr_ - static_cast<u32>(offset));
  }

  char& operator[](size_t idx) const { return host_ptr_[idx]; }

  template <typename U>
  U as() const {
    return reinterpret_cast<U>(host_ptr_);
  }
};

//=============================================================================
// MappedPtr<char16_t> Specialization (wide strings)
//=============================================================================

template <>
class MappedPtr<char16_t> {
  char16_t* host_ptr_;
  u32 guest_addr_;

 public:
  MappedPtr() : host_ptr_(nullptr), guest_addr_(0) {}
  MappedPtr(char16_t* host_ptr, u32 guest_addr) : host_ptr_(host_ptr), guest_addr_(guest_addr) {}
  MappedPtr(std::nullptr_t) : host_ptr_(nullptr), guest_addr_(0) {}

  u32 guest_address() const { return guest_addr_; }
  char16_t* host_address() const { return host_ptr_; }

  operator char16_t*() const { return host_ptr_; }
  explicit operator bool() const { return host_ptr_ != nullptr; }

  std::u16string_view value() const {
    if (host_ptr_ && guest_storage::contains(host_ptr_)) [[unlikely]] {
      return guest_storage::string_view_of(host_ptr_);  // swapped guest storage (T-017)
    }
    return host_ptr_ ? std::u16string_view(host_ptr_) : std::u16string_view();
  }

  char16_t* operator->() const { return host_ptr_; }
  char16_t& operator*() const { return *host_ptr_; }

  MappedPtr operator+(std::ptrdiff_t offset) const {
    return MappedPtr(host_ptr_ + offset, guest_addr_ + static_cast<u32>(offset * sizeof(char16_t)));
  }
  MappedPtr operator-(std::ptrdiff_t offset) const {
    return MappedPtr(host_ptr_ - offset, guest_addr_ - static_cast<u32>(offset * sizeof(char16_t)));
  }

  char16_t& operator[](size_t idx) const { return host_ptr_[idx]; }

  template <typename U>
  U as() const {
    return reinterpret_cast<U>(host_ptr_);
  }
};

//=============================================================================
// MappedPtr Type Traits
//=============================================================================

template <typename T>
struct is_mapped_ptr : std::false_type {};
template <typename T>
struct is_mapped_ptr<MappedPtr<T>> : std::true_type {};
template <typename T>
inline constexpr bool is_mapped_ptr_v = is_mapped_ptr<T>::value;

template <typename T>
struct mapped_ptr_inner_type;
template <typename T>
struct mapped_ptr_inner_type<MappedPtr<T>> {
  using type = T;
};

}  // namespace rex

//=============================================================================
// Global Namespace Exports
//=============================================================================

using u8 = rex::u8;
using i8 = rex::i8;
using u16 = rex::u16;
using i16 = rex::i16;
using u32 = rex::u32;
using i32 = rex::i32;
using u64 = rex::u64;
using i64 = rex::i64;
using f32 = rex::f32;
using f64 = rex::f64;

using be_u16 = rex::be_u16;
using be_u32 = rex::be_u32;
using be_u64 = rex::be_u64;
using be_i16 = rex::be_i16;
using be_i32 = rex::be_i32;
using be_i64 = rex::be_i64;
using be_f32 = rex::be_f32;
using be_f64 = rex::be_f64;

using mapped_void = rex::MappedPtr<void>;
using mapped_u8 = rex::MappedPtr<uint8_t>;
using mapped_u16 = rex::MappedPtr<rex::be_u16>;
using mapped_u32 = rex::MappedPtr<rex::be_u32>;
using mapped_u64 = rex::MappedPtr<rex::be_u64>;
using mapped_f32 = rex::MappedPtr<rex::be_f32>;
using mapped_f64 = rex::MappedPtr<rex::be_f64>;
using mapped_string = rex::MappedPtr<char>;
using mapped_wstring = rex::MappedPtr<char16_t>;

// Legacy compat alias for ppc_ptr_t<T>
template <typename T>
using ppc_ptr_t = rex::MappedPtr<T>;
