/**
 * @file        kernel/xboxkrnl/xboxkrnl_strings.cpp
 * @brief       Xbox kernel string function exports
 *
 * @copyright   Copyright 2022 Ben Vanik. All rights reserved. (Xenia Project)
 *
 * @license     BSD 3-Clause License
 *              See LICENSE file in the project root for full license text.
 *
 * @modified    Tom Clay, 2026 - Adapted for ReXGlue runtime
 * @modified    MCLA-Reborn contributors, 2026 - storage-aware guest strings; the raw hooks are
 *              registered as exports, so the runtime's ordinal lookup finds them
 */

#pragma GCC diagnostic ignored "-Wunused-parameter"

#include <algorithm>
#include <cctype>
#include <cstring>

#include <rex/logging.h>
#include <rex/memory/utils.h>
#include <rex/hook.h>
#include <rex/system/flags.h>
#include <rex/system/format.h>

using namespace rex::system::format;
using rex::memory::GuestPtr;

namespace {
// Guest output (MCLA-Reborn): through swapped guest storage when the harness enables it, plain
// memory otherwise.
void put_guest_chars(uint8_t* dst, const char* src, size_t n) {
  rex::memory::copy_to_guest(dst, src, n);
}
void put_guest_char(uint8_t* p, uint8_t v) {
  if (rex::guest_storage::contains(p)) {
    rex::guest_storage::store<uint8_t>(p, v);
  } else {
    *p = v;
  }
}
void put_guest_wchar(uint16_t* p, uint16_t v) {  // v is the guest (big-endian) value
  if (rex::guest_storage::contains(p)) {
    rex::guest_storage::store<uint16_t>(p, v);
  } else {
    *p = rex::byte_swap(v);
  }
}
}  // namespace

// A raw hook (direct ctx/base access) that is also registered as a kernel export, as
// REX_EXPORT does for typed ones; without the registration the runtime's export lookup by
// ordinal never finds it.
#define REX_EXPORT_RAW(name)                                                \
  extern "C" REX_FUNC(name);                                                \
  static rex::ppc::detail::PPCFuncRegistrar _ppc_reg_##name(#name, &name); \
  extern "C" REX_FUNC(name)

//=============================================================================
// DbgPrint / XamDbgPrint
//=============================================================================

REX_EXPORT_RAW(__imp__DbgPrint) {
  uint32_t format_ptr = ctx.r3.u32;
  if (!format_ptr) {
    ctx.r3.u64 = 0;
    return;
  }
  auto format = GuestPtr<const u8*>(base, format_ptr);

  StackArgList args(ctx, base, 1);
  StringFormatData data(format);

  int32_t count = format_core(base, data, args, false);
  if (count > 0) {
    auto str = data.str();
    // Trim trailing whitespace
    while (!str.empty() && std::isspace(static_cast<unsigned char>(str.back()))) {
      str.pop_back();
    }
    REXKRNL_INFO("DbgPrint: {}", str);
  }

  ctx.r3.u64 = 0;  // NTSTATUS success
}

REX_EXPORT_RAW(__imp__XamDbgPrint) {
  uint32_t format_ptr = ctx.r3.u32;
  if (!format_ptr) {
    ctx.r3.u64 = 0;
    return;
  }
  auto format = GuestPtr<const u8*>(base, format_ptr);

  StackArgList args(ctx, base, 1);
  StringFormatData data(format);

  int32_t count = format_core(base, data, args, false);
  if (count > 0) {
    auto str = data.str();
    while (!str.empty() && std::isspace(static_cast<unsigned char>(str.back()))) {
      str.pop_back();
    }
    REXKRNL_INFO("XamDbgPrint: {}", str);
  }

  ctx.r3.u64 = 0;
}

//=============================================================================
// sprintf / _snprintf (narrow, stack varargs)
//=============================================================================

REX_EXPORT_RAW(__imp__sprintf) {
  uint32_t buffer_ptr = ctx.r3.u32;
  uint32_t format_ptr = ctx.r4.u32;

  if (buffer_ptr == 0 || format_ptr == 0) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }

  auto buffer = GuestPtr<u8*>(base, buffer_ptr);
  auto format = GuestPtr<const u8*>(base, format_ptr);

  StackArgList args(ctx, base, 2);
  StringFormatData data(format);

  int32_t count = format_core(base, data, args, false);
  if (count <= 0) {
    put_guest_char(&buffer[0], 0);
  } else {
    put_guest_chars(buffer, data.str().c_str(), count);
    put_guest_char(&buffer[count], 0);
  }
  ctx.r3.u64 = count;
}

REX_EXPORT_RAW(__imp___snprintf) {
  uint32_t buffer_ptr = ctx.r3.u32;
  int32_t buffer_count = static_cast<int32_t>(ctx.r4.u32);
  uint32_t format_ptr = ctx.r5.u32;

  if (buffer_ptr == 0 || buffer_count <= 0 || format_ptr == 0) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }

  auto buffer = GuestPtr<u8*>(base, buffer_ptr);
  auto format = GuestPtr<const u8*>(base, format_ptr);

  StackArgList args(ctx, base, 3);
  StringFormatData data(format);

  int32_t count = format_core(base, data, args, false);
  if (count < 0) {
    if (buffer_count > 0) {
      put_guest_char(&buffer[0], 0);
    }
  } else if (count <= buffer_count) {
    put_guest_chars(buffer, data.str().c_str(), count);
    if (count < buffer_count) {
      put_guest_char(&buffer[count], 0);
    }
  } else {
    put_guest_chars(buffer, data.str().c_str(), buffer_count);
    count = -1;
  }
  ctx.r3.u64 = count;
}

//=============================================================================
// swprintf / _snwprintf (wide, stack varargs)
//=============================================================================

REX_EXPORT_RAW(__imp__swprintf) {
  uint32_t buffer_ptr = ctx.r3.u32;
  uint32_t format_ptr = ctx.r4.u32;

  if (buffer_ptr == 0 || format_ptr == 0) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }

  auto buffer = GuestPtr<u16*>(base, buffer_ptr);
  auto format = GuestPtr<const u16*>(base, format_ptr);

  StackArgList args(ctx, base, 2);
  WideStringFormatData data(format);

  int32_t count = format_core(base, data, args, true);
  if (count <= 0) {
    put_guest_wchar(&buffer[0], 0);
  } else {
    rex::memory::copy_and_swap(buffer, reinterpret_cast<const uint16_t*>(data.wstr().c_str()),
                               count);
    put_guest_wchar(&buffer[count], 0);
  }
  ctx.r3.u64 = count;
}

REX_EXPORT_RAW(__imp___snwprintf) {
  uint32_t buffer_ptr = ctx.r3.u32;
  int32_t buffer_count = static_cast<int32_t>(ctx.r4.u32);
  uint32_t format_ptr = ctx.r5.u32;

  if (buffer_ptr == 0 || buffer_count <= 0 || format_ptr == 0) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }

  auto buffer = GuestPtr<u16*>(base, buffer_ptr);
  auto format = GuestPtr<const u16*>(base, format_ptr);

  StackArgList args(ctx, base, 3);
  WideStringFormatData data(format);

  int32_t count = format_core(base, data, args, true);
  if (count < 0) {
    if (buffer_count > 0) {
      put_guest_wchar(&buffer[0], 0);
    }
  } else if (count <= buffer_count) {
    rex::memory::copy_and_swap(buffer, reinterpret_cast<const uint16_t*>(data.wstr().c_str()),
                               count);
    if (count < buffer_count) {
      put_guest_wchar(&buffer[count], 0);
    }
  } else {
    rex::memory::copy_and_swap(buffer, reinterpret_cast<const uint16_t*>(data.wstr().c_str()),
                               buffer_count);
    count = -1;
  }
  ctx.r3.u64 = count;
}

//=============================================================================
// vsprintf / _vsnprintf (narrow, va_list from memory)
//=============================================================================

REX_EXPORT_RAW(__imp__vsprintf) {
  uint32_t buffer_ptr = ctx.r3.u32;
  uint32_t format_ptr = ctx.r4.u32;
  uint32_t arg_ptr = ctx.r5.u32;

  if (buffer_ptr == 0 || format_ptr == 0) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }

  auto buffer = GuestPtr<u8*>(base, buffer_ptr);
  auto format = GuestPtr<const u8*>(base, format_ptr);

  ArrayArgList args(base, arg_ptr);
  StringFormatData data(format);

  int32_t count = format_core(base, data, args, false);
  if (count <= 0) {
    put_guest_char(&buffer[0], 0);
  } else {
    put_guest_chars(buffer, data.str().c_str(), count);
    put_guest_char(&buffer[count], 0);
  }
  ctx.r3.u64 = count;
}

REX_EXPORT_RAW(__imp___vsnprintf) {
  uint32_t buffer_ptr = ctx.r3.u32;
  int32_t buffer_count = static_cast<int32_t>(ctx.r4.u32);
  uint32_t format_ptr = ctx.r5.u32;
  uint32_t arg_ptr = ctx.r6.u32;

  if (buffer_ptr == 0 || buffer_count <= 0 || format_ptr == 0) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }

  auto buffer = GuestPtr<u8*>(base, buffer_ptr);
  auto format = GuestPtr<const u8*>(base, format_ptr);

  ArrayArgList args(base, arg_ptr);
  StringFormatData data(format);

  int32_t count = format_core(base, data, args, false);
  if (count < 0) {
    if (buffer_count > 0) {
      put_guest_char(&buffer[0], 0);
    }
  } else if (count <= buffer_count) {
    put_guest_chars(buffer, data.str().c_str(), count);
    if (count < buffer_count) {
      put_guest_char(&buffer[count], 0);
    }
  } else {
    put_guest_chars(buffer, data.str().c_str(), buffer_count);
  }
  ctx.r3.u64 = count;
}

//=============================================================================
// vswprintf / _vsnwprintf / _vscwprintf (wide, va_list from memory)
//=============================================================================

REX_EXPORT_RAW(__imp__vswprintf) {
  uint32_t buffer_ptr = ctx.r3.u32;
  uint32_t format_ptr = ctx.r4.u32;
  uint32_t arg_ptr = ctx.r5.u32;

  if (buffer_ptr == 0 || format_ptr == 0) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }

  auto buffer = GuestPtr<u16*>(base, buffer_ptr);
  auto format = GuestPtr<const u16*>(base, format_ptr);

  ArrayArgList args(base, arg_ptr);
  WideStringFormatData data(format);

  int32_t count = format_core(base, data, args, true);
  if (count <= 0) {
    put_guest_wchar(&buffer[0], 0);
  } else {
    rex::memory::copy_and_swap(buffer, reinterpret_cast<const uint16_t*>(data.wstr().c_str()),
                               count);
    put_guest_wchar(&buffer[count], 0);
  }
  ctx.r3.u64 = count;
}

REX_EXPORT_RAW(__imp___vsnwprintf) {
  uint32_t buffer_ptr = ctx.r3.u32;
  int32_t buffer_count = static_cast<int32_t>(ctx.r4.u32);
  uint32_t format_ptr = ctx.r5.u32;
  uint32_t arg_ptr = ctx.r6.u32;

  if (buffer_ptr == 0 || buffer_count <= 0 || format_ptr == 0) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }

  auto buffer = GuestPtr<u16*>(base, buffer_ptr);
  auto format = GuestPtr<const u16*>(base, format_ptr);

  ArrayArgList args(base, arg_ptr);
  WideStringFormatData data(format);

  int32_t count = format_core(base, data, args, true);
  if (count < 0) {
    if (buffer_count > 0) {
      put_guest_wchar(&buffer[0], 0);
    }
  } else if (count <= buffer_count) {
    rex::memory::copy_and_swap(buffer, reinterpret_cast<const uint16_t*>(data.wstr().c_str()),
                               count);
    if (count < buffer_count) {
      put_guest_wchar(&buffer[count], 0);
    }
  } else {
    rex::memory::copy_and_swap(buffer, reinterpret_cast<const uint16_t*>(data.wstr().c_str()),
                               buffer_count);
  }
  ctx.r3.u64 = count;
}

REX_EXPORT_RAW(__imp___vscwprintf) {
  uint32_t format_ptr = ctx.r3.u32;
  uint32_t arg_ptr = ctx.r4.u32;

  if (format_ptr == 0) {
    ctx.r3.u64 = static_cast<uint64_t>(-1);
    return;
  }

  auto format = GuestPtr<const u16*>(base, format_ptr);

  ArrayArgList args(base, arg_ptr);
  WideCountFormatData data(format);

  int32_t count = format_core(base, data, args, true);
  assert_true(count < 0 || data.count() == count);
  ctx.r3.u64 = count;
}

//=============================================================================
// Export stubs
//=============================================================================

REX_EXPORT_STUB(__imp___scprintf);
REX_EXPORT_STUB(__imp___scwprintf);
REX_EXPORT_STUB(__imp___vscprintf);
