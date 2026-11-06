# MCLA-Reborn: ReXGlue's runtime (core, filesystem, kernel, XAM, system, the audio and GPU base
# classes) as one static library for the browser, built with Emscripten (wasm64, pthreads).
#
# Included from the top-level CMakeLists.txt when REXGLUE_WASM_RUNTIME is ON. Nothing else of
# the SDK is configured: no codegen, no C++ backend, no UI, no Vulkan/D3D12, no SDL. The host
# that links this library (MCLA-Reborn's runtime/browser) supplies the GPU (ReXGlue's command
# processor with draws discarded), a silent audio driver and the game-file device.
#   - XEX LZX by translator-lzx instead of libmspack (LGPL), as in the translator build (T-049);
#   - no libavcodec: xma_context.cpp decodes every XMA frame to silence (audio is silent).
# Required: REXGLUE_TRANSLATOR_LZX_DIR (MCLA-Reborn's translator-lzx folder).
# Outputs stay in the build tree: this file returns before the top-level CMakeLists.txt sets
# CMAKE_*_OUTPUT_DIRECTORY to out/${REX_PLATFORM}, so out/win-amd64 is never touched.
#
# @license Not yet licensed: MCLA-Reborn decides before any release (D-009)

if(NOT EMSCRIPTEN)
  message(FATAL_ERROR "REXGLUE_WASM_RUNTIME needs the Emscripten toolchain")
endif()
if(NOT REXGLUE_TRANSLATOR_LZX_DIR OR NOT EXISTS "${REXGLUE_TRANSLATOR_LZX_DIR}/include")
  message(FATAL_ERROR "Set REXGLUE_TRANSLATOR_LZX_DIR to MCLA-Reborn's translator-lzx folder")
endif()

set(REXGLUE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
set(REX_PLATFORM "wasm64-emscripten")
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Version header, as the native build makes it.
include(${REXGLUE_ROOT}/cmake/rex_version.cmake)
rex_resolve_version(REXGLUE_FULL_VERSION
    FLOOR_MAJOR ${PROJECT_VERSION_MAJOR}
    FLOOR_MINOR ${PROJECT_VERSION_MINOR})
string(REGEX REPLACE "-.*$" "" REXGLUE_NUMERIC_VERSION "${REXGLUE_FULL_VERSION}")
string(REGEX MATCH "^([0-9]+)\\.([0-9]+)(\\.([0-9]+))?(\\.([0-9]+))?" _ "${REXGLUE_NUMERIC_VERSION}")
set(REXGLUE_DERIVED_MAJOR "${CMAKE_MATCH_1}")
set(REXGLUE_DERIVED_MINOR "${CMAKE_MATCH_2}")
set(REXGLUE_DERIVED_PATCH "0")
set(REXGLUE_DERIVED_TWEAK "0")
if(CMAKE_MATCH_4)
  set(REXGLUE_DERIVED_PATCH "${CMAKE_MATCH_4}")
endif()
if(CMAKE_MATCH_6)
  set(REXGLUE_DERIVED_TWEAK "${CMAKE_MATCH_6}")
endif()
set(REXGLUE_FLOOR_VERSION
    "${REXGLUE_DERIVED_MAJOR}.${REXGLUE_DERIVED_MINOR}.${REXGLUE_DERIVED_PATCH}")
rex_version_channel(REXGLUE_VERSION_CHANNEL VERSION "${REXGLUE_FULL_VERSION}")
string(TIMESTAMP REXGLUE_BUILD_TIMESTAMP "%Y%m%d_%H%M")
configure_file(${REXGLUE_ROOT}/include/rex/version.h.in
               ${CMAKE_CURRENT_BINARY_DIR}/include/rex/version.h @ONLY)

# wasm64, pthreads (shared memory), wasm exceptions; the same strictness flags as native.
set(REXGLUE_WASM_RUNTIME_FLAGS -m64 -pthread -fwasm-exceptions)
add_compile_options(${REXGLUE_WASM_RUNTIME_FLAGS} -fno-strict-aliasing -ffp-model=strict
                    -fno-char8_t $<$<CONFIG:Release>:-O3> $<$<CONFIG:Release>:-DNDEBUG>)
add_compile_definitions(REXGLUE_BUILD_CONFIG="$<CONFIG>" REXGLUE_WASM_RUNTIME=1)

# Third-party pieces (all permissive: MIT/BSD/zlib-style).
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(FMT_DOC OFF CACHE BOOL "" FORCE)
set(FMT_TEST OFF CACHE BOOL "" FORCE)
set(FMT_INSTALL OFF CACHE BOOL "" FORCE)
add_subdirectory(thirdparty/fmt EXCLUDE_FROM_ALL)
target_compile_options(fmt PRIVATE -w)
set(SPDLOG_FMT_EXTERNAL ON CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_BENCH OFF CACHE BOOL "" FORCE)
set(SPDLOG_INSTALL OFF CACHE BOOL "" FORCE)
add_subdirectory(thirdparty/spdlog EXCLUDE_FROM_ALL)
target_compile_options(spdlog PRIVATE -w)
set(XXHASH_BUILD_XXHSUM OFF CACHE BOOL "" FORCE)
add_subdirectory(thirdparty/xxHash/cmake_unofficial EXCLUDE_FROM_ALL)
target_compile_options(xxhash PRIVATE -w)

add_library(translator_lzx STATIC ${REXGLUE_TRANSLATOR_LZX_DIR}/src/lzx.cpp)
target_include_directories(translator_lzx PUBLIC ${REXGLUE_TRANSLATOR_LZX_DIR}/include)
target_compile_features(translator_lzx PUBLIC cxx_std_20)

set(_tp ${REXGLUE_ROOT}/thirdparty)
set(_core ${REXGLUE_ROOT}/src/core)
set(_fs ${REXGLUE_ROOT}/src/filesystem)
set(_sys ${REXGLUE_ROOT}/src/system)
set(_k ${REXGLUE_ROOT}/src/kernel)
set(_audio ${REXGLUE_ROOT}/src/audio)
set(_gpu ${REXGLUE_ROOT}/src/graphics)

add_library(rexruntime_wasm STATIC
    # third-party C
    ${_tp}/aes_128/aes.c
    ${_tp}/o1heap/o1heap/o1heap.c
    # core (POSIX sources, with Emscripten branches inside)
    ${_core}/arena.cpp
    ${_core}/bit_map.cpp
    ${_core}/bit_stream.cpp
    ${_core}/byte_stream.cpp
    ${_core}/clock.cpp
    ${_core}/cvar.cpp
    ${_core}/exception_handler.cpp
    ${_core}/filesystem.cpp
    ${_core}/filesystem_wildcard.cpp
    ${_core}/hash.cpp
    ${_core}/logging.cpp
    ${_core}/memory.cpp
    ${_core}/mutex.cpp
    ${_core}/ring_buffer.cpp
    ${_core}/string_buffer.cpp
    ${_core}/threading.cpp
    ${_core}/timer_queue.cpp
    ${_core}/utf8.cpp
    ${_core}/vec128.cpp
    ${_core}/atomic_posix.cpp
    ${_core}/clock_posix.cpp
    ${_core}/dbg_posix.cpp
    ${_core}/dynlib_posix.cpp
    ${_core}/exception_handler_posix.cpp
    ${_core}/filesystem_posix.cpp
    ${_core}/fiber_posix.cpp
    ${_core}/mapped_memory_posix.cpp
    ${_core}/math_gcc.cpp
    ${_core}/memory_emscripten.cpp
    ${_core}/platform/console_posix.cpp
    ${_core}/platform/env_posix.cpp
    ${_core}/seh_posix.cpp
    ${_core}/socket_posix.cpp
    ${_core}/system_posix.cpp
    ${_core}/threading_posix.cpp
    ${_gpu}/xenos.cpp
    ${_gpu}/pipeline/texture/info.cpp
    ${_gpu}/pipeline/texture/info_formats.cpp
    ${_gpu}/pipeline/texture/extent.cpp
    ${_gpu}/pipeline/texture/util.cpp
    ${_gpu}/pipeline/texture/conversion.cpp
    # filesystem
    ${_fs}/device.cpp
    ${_fs}/entry.cpp
    ${_fs}/virtual_file_system.cpp
    ${_fs}/devices/disc_image_device.cpp
    ${_fs}/devices/disc_image_entry.cpp
    ${_fs}/devices/disc_image_file.cpp
    ${_fs}/devices/host_path_device.cpp
    ${_fs}/devices/host_path_entry.cpp
    ${_fs}/devices/host_path_file.cpp
    ${_fs}/devices/null_device.cpp
    ${_fs}/devices/null_entry.cpp
    ${_fs}/devices/null_file.cpp
    ${_fs}/devices/stfs_container_device.cpp
    ${_fs}/devices/stfs_container_entry.cpp
    ${_fs}/devices/stfs_container_file.cpp
    # system
    ${_sys}/runtime.cpp
    ${_sys}/embedded_metadata.cpp
    ${_sys}/achievement_manager.cpp
    ${_sys}/achievements.cpp
    ${_sys}/kernel_state.cpp
    ${_sys}/xmemory.cpp
    ${_sys}/kernel_module.cpp
    ${_sys}/user_module.cpp
    ${_sys}/xthread.cpp
    ${_sys}/xevent.cpp
    ${_sys}/xfile.cpp
    ${_sys}/xmutant.cpp
    ${_sys}/xsemaphore.cpp
    ${_sys}/xtimer.cpp
    ${_sys}/xiocompletion.cpp
    ${_sys}/xnotifylistener.cpp
    ${_sys}/xenumerator.cpp
    ${_sys}/xsocket.cpp
    ${_sys}/xsymboliclink.cpp
    ${_sys}/xobject.cpp
    ${_sys}/xmodule.cpp
    ${_sys}/guest_path.cpp
    ${_sys}/util/object_table.cpp
    ${_sys}/util/native_list.cpp
    ${_sys}/util/xdbf_utils.cpp
    ${_sys}/util/gameinfo_utils.cpp
    ${_sys}/xam/app_manager.cpp
    ${_sys}/xam/content_manager.cpp
    ${_sys}/xam/user_profile.cpp
    ${_sys}/ppc_types.cpp
    ${_sys}/elf_module.cpp
    ${_sys}/entry_table.cpp
    ${_sys}/export_resolver.cpp
    ${_sys}/lzx.cpp
    ${_sys}/mmio_handler.cpp
    ${_sys}/map_parser.cpp
    ${_sys}/module.cpp
    ${_sys}/function_dispatcher.cpp
    ${_sys}/thread.cpp
    ${_sys}/thread_state.cpp
    ${_sys}/xex_module.cpp
    # kernel and XAM exports
    ${_k}/kernel_init.cpp
    ${_k}/xam/xam_module.cpp
    ${_k}/xam/xam_avatar.cpp
    ${_k}/xam/xam_content.cpp
    ${_k}/xam/xam_content_aggregate.cpp
    ${_k}/xam/xam_content_device.cpp
    ${_k}/xam/xam_debug.cpp
    ${_k}/xam/xam_enum.cpp
    ${_k}/xam/xam_info.cpp
    ${_k}/xam/xam_input.cpp
    ${_k}/xam/xam_locale.cpp
    ${_k}/xam/xam_msg.cpp
    ${_k}/xam/xam_net.cpp
    ${_k}/xam/xam_notify.cpp
    ${_k}/xam/xam_nui.cpp
    ${_k}/xam/xam_party.cpp
    ${_k}/xam/xam_task.cpp
    ${_k}/xam/xam_ui.cpp
    ${_k}/xam/xam_user.cpp
    ${_k}/xam/xam_video.cpp
    ${_k}/xam/xam_voice.cpp
    ${_k}/xam/xam_misc.cpp
    ${_k}/xam/apps/xam_app.cpp
    ${_k}/xam/apps/xgi_app.cpp
    ${_k}/xam/apps/xlivebase_app.cpp
    ${_k}/xam/apps/xmp_app.cpp
    ${_k}/xbdm/xbdm_module.cpp
    ${_k}/xbdm/xbdm_misc.cpp
    ${_k}/xboxkrnl/xboxkrnl_crypt.cpp
    ${_k}/xboxkrnl/xboxkrnl_debug.cpp
    ${_k}/xboxkrnl/xboxkrnl_error.cpp
    ${_k}/xboxkrnl/xboxkrnl_hal.cpp
    ${_k}/xboxkrnl/xboxkrnl_hid.cpp
    ${_k}/xboxkrnl/xboxkrnl_io.cpp
    ${_k}/xboxkrnl/xboxkrnl_io_info.cpp
    ${_k}/xboxkrnl/xboxkrnl_memory.cpp
    ${_k}/xboxkrnl/xboxkrnl_misc.cpp
    ${_k}/xboxkrnl/xboxkrnl_module.cpp
    ${_k}/xboxkrnl/xboxkrnl_modules.cpp
    ${_k}/xboxkrnl/xboxkrnl_ob.cpp
    ${_k}/xboxkrnl/xboxkrnl_rtl.cpp
    ${_k}/xboxkrnl/xboxkrnl_strings.cpp
    ${_k}/xboxkrnl/xboxkrnl_threading.cpp
    ${_k}/xboxkrnl/xboxkrnl_video.cpp
    ${_k}/xboxkrnl/xboxkrnl_xconfig.cpp
    ${_k}/xboxkrnl/xboxkrnl_audio.cpp
    ${_k}/xboxkrnl/xboxkrnl_audio_xma.cpp
    ${_k}/crt/heap.cpp
    ${_k}/crt/file.cpp
    ${_k}/crt/memory.cpp
    ${_k}/crt/string.cpp
    ${_k}/crt/threading.cpp
    # audio: the system, client drivers and the XMA decoder (silent frames, no FFmpeg)
    ${_audio}/audio_driver.cpp
    ${_audio}/audio_system.cpp
    ${_audio}/downmix.cpp
    ${_audio}/xma_context.cpp
    ${_audio}/xma_decoder.cpp
    ${_audio}/xma_register_file.cpp
    # GPU base classes: MMIO registers, ring buffer, PM4 command processor, vblank
    ${_gpu}/graphics_system.cpp
    ${_gpu}/command_processor.cpp
    ${_gpu}/register_file.cpp
    ${_gpu}/registers.cpp
    ${_gpu}/flags.cpp
    # XAM's message-box and keyboard dialogs derive from ImGuiDialog; they are never shown
    # (no ImGui drawer), but the class must link.
    ${REXGLUE_ROOT}/src/ui/imgui_dialog.cpp
    # Input: the system and its no-controller driver (the host adds no other driver yet)
    ${REXGLUE_ROOT}/src/input/input_system.cpp
    ${REXGLUE_ROOT}/src/input/device_assignment.cpp
    ${REXGLUE_ROOT}/src/input/state_merge.cpp
    ${REXGLUE_ROOT}/src/input/nop/nop_input_driver.cpp
)
add_library(rex::runtime_wasm ALIAS rexruntime_wasm)

# MCLA-Reborn (T-029): what a WebGPU backend in the host needs on top of the GPU base classes:
# the microcode analysis (Shader), the shared ShaderTranslator with the WGSL translator, and the
# draw utilities (viewport, scissor, resolve info). Only for the browser runtime build.
option(REXGLUE_WASM_WEBGPU "Add shader translation, draw utilities and the render target cache" OFF)
if(REXGLUE_WASM_WEBGPU)
  target_sources(rexruntime_wasm PRIVATE
      ${_gpu}/format/ucode.cpp
      ${_gpu}/pipeline/render_target/cache.cpp
      ${_gpu}/pipeline/shader/interpreter.cpp
      ${_gpu}/pipeline/shader/shader.cpp
      ${_gpu}/pipeline/shader/translator.cpp
      ${_gpu}/pipeline/shader/translator_disasm.cpp
      ${_gpu}/pipeline/shader/wgsl_translator.cpp
      ${_gpu}/pipeline/shader/wgsl_translator_alu.cpp
      ${_gpu}/pipeline/shader/wgsl_translator_fetch.cpp
      ${_gpu}/util/draw.cpp
      ${_gpu}/util/draw_extent_estimator.cpp
      ${REXGLUE_ROOT}/src/ui/graphics_util.cpp)
  target_compile_definitions(rexruntime_wasm PUBLIC REXGLUE_WASM_WEBGPU=1)
endif()
# Consumers compile with the same target flags (wasm64 etc.) and see the same configuration.
target_compile_options(rexruntime_wasm INTERFACE ${REXGLUE_WASM_RUNTIME_FLAGS})
target_compile_definitions(rexruntime_wasm PUBLIC
    REXGLUE_WASM_RUNTIME=1
    REXGLUE_TRANSLATOR_LZX=1
    "O1HEAP_CONFIG_HEADER=\"${REXGLUE_ROOT}/include/rex/o1heap_config.h\"")
target_include_directories(rexruntime_wasm PUBLIC
    ${REXGLUE_ROOT}/include
    ${CMAKE_CURRENT_BINARY_DIR}/include
    ${_tp}
    ${_tp}/simde
    ${_tp}/tomlplusplus/include
    ${_tp}/disruptorplus/include
    ${_tp}/utfcpp/source
    ${_tp}/o1heap/o1heap
    ${_tp}/imgui
    ${_tp}/sdl3/include
    ${_tp}/cli11/include)
target_include_directories(rexruntime_wasm PRIVATE
    ${REXGLUE_ROOT}
    ${REXGLUE_ROOT}/src
    ${_fs}/devices)
target_compile_options(rexruntime_wasm PRIVATE -Wall -Wno-unused-parameter
                       -Wno-unused-variable -Wno-invalid-offsetof)
set_source_files_properties(${_tp}/aes_128/aes.c ${_tp}/o1heap/o1heap/o1heap.c
                            PROPERTIES COMPILE_OPTIONS "-w")
target_link_libraries(rexruntime_wasm PUBLIC translator_lzx fmt::fmt spdlog::spdlog
                      xxHash::xxhash)
