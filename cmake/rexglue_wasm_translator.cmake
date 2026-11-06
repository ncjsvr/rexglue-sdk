# MCLA-Reborn: the translator tool, rexglue-translate, built with Emscripten (wasm64).
#
# Included from the top-level CMakeLists.txt when REXGLUE_WASM_TRANSLATOR is ON; the rest of
# the SDK (runtime, kernel, graphics, the C++ backend, the rexglue CLI) is not configured.
# The tool loads an XEX the way ReXGlue does (XexModule over guest memory), runs the codegen
# analysis and writes wasm chunk modules with the wasm backend only:
#   - no C++ backend (REXGLUE_NO_CPP_BACKEND): it cannot write C++ from game code (D-006);
#   - PowerPC decoding by translator-ppc instead of thirdparty/disasm (GPL), T-048;
#   - LZX by translator-lzx instead of libmspack (LGPL), T-049.
# Required: REXGLUE_TRANSLATOR_PPC_DIR and REXGLUE_TRANSLATOR_LZX_DIR (MCLA-Reborn's
# translator-ppc and translator-lzx folders).
#
# @license Not yet licensed: MCLA-Reborn decides before any release (D-009)

if(NOT EMSCRIPTEN)
  message(FATAL_ERROR "REXGLUE_WASM_TRANSLATOR needs the Emscripten toolchain")
endif()
foreach(_dir REXGLUE_TRANSLATOR_PPC_DIR REXGLUE_TRANSLATOR_LZX_DIR)
  if(NOT ${_dir} OR NOT EXISTS "${${_dir}}/include")
    message(FATAL_ERROR "Set ${_dir} to MCLA-Reborn's translator-ppc / translator-lzx folder")
  endif()
endforeach()

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

# Same code-generation flags as the native build, so analysis and output match it.
add_compile_options(-m64 -fwasm-exceptions -fno-strict-aliasing -ffp-model=strict -fno-char8_t
                    $<$<CONFIG:Release>:-O3> $<$<CONFIG:Release>:-DNDEBUG>)
add_compile_definitions(REXGLUE_BUILD_CONFIG="$<CONFIG>")
add_link_options(-m64 -fwasm-exceptions)

# Third-party pieces the tool needs (all permissive: MIT/BSD/zlib-style).
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
add_library(aes128 STATIC thirdparty/aes_128/aes.c)
target_include_directories(aes128 PUBLIC ${REXGLUE_ROOT}/thirdparty)
target_compile_options(aes128 PRIVATE -w)

# Our decoders (MCLA-Reborn, T-048 and T-049).
add_library(translator_ppc STATIC ${REXGLUE_TRANSLATOR_PPC_DIR}/src/decode.cpp)
target_include_directories(translator_ppc PUBLIC ${REXGLUE_TRANSLATOR_PPC_DIR}/include)
target_compile_features(translator_ppc PUBLIC cxx_std_20)
add_library(translator_lzx STATIC ${REXGLUE_TRANSLATOR_LZX_DIR}/src/lzx.cpp)
target_include_directories(translator_lzx PUBLIC ${REXGLUE_TRANSLATOR_LZX_DIR}/include)
target_compile_features(translator_lzx PUBLIC cxx_std_20)

set(_core ${REXGLUE_ROOT}/src/core)
set(_sys ${REXGLUE_ROOT}/src/system)
set(_cg ${REXGLUE_ROOT}/src/codegen)
add_executable(rexglue-translate
    # CLI, ISO reader, kernel export tables (names only)
    ${REXGLUE_ROOT}/src/translator/main.cpp
    ${REXGLUE_ROOT}/src/translator/xdvdfs.cpp
    ${REXGLUE_ROOT}/src/translator/kernel_exports.cpp
    ${REXGLUE_ROOT}/src/translator/tool_support.cpp
    # --tests: the fixture corpus as `recompile-tests --backend wasm` translates it
    ${REXGLUE_ROOT}/src/rexglue/commands/test_recompiler.cpp
    ${REXGLUE_ROOT}/src/rexglue/ui/ui.cpp
    ${_cg}/test_support.cpp
    ${_core}/platform/console_posix.cpp
    # Core utilities
    ${_core}/logging.cpp
    ${_core}/cvar.cpp
    ${_core}/utf8.cpp
    ${_core}/memory.cpp
    ${_core}/memory_emscripten.cpp
    ${_core}/math_gcc.cpp
    ${_core}/mutex.cpp
    ${_core}/clock.cpp
    ${_core}/clock_posix.cpp
    ${_core}/platform/env_posix.cpp
    ${_core}/filesystem_posix.cpp
    # XEX loader and guest memory
    ${_sys}/xex_module.cpp
    ${_sys}/module.cpp
    ${_sys}/xmemory.cpp
    ${_sys}/export_resolver.cpp
    ${_sys}/lzx.cpp
    ${_sys}/guest_path.cpp
    ${_sys}/map_parser.cpp
    # Codegen analysis and the wasm backend
    ${_cg}/analyze.cpp
    ${_cg}/binary_view.cpp
    ${_cg}/code_emitter.cpp
    ${_cg}/codegen_context.cpp
    ${_cg}/codegen_flags.cpp
    ${_cg}/config.cpp
    ${_cg}/decoded_binary.cpp
    ${_cg}/function_graph.cpp
    ${_cg}/function_scanner.cpp
    ${_cg}/manifest.cpp
    ${_cg}/phase_register.cpp
    ${_cg}/phase_scan.cpp
    ${_cg}/phase_discover.cpp
    ${_cg}/phase_gapfill.cpp
    ${_cg}/phase_merge.cpp
    ${_cg}/phase_validate.cpp
    ${_cg}/sig_scanner.cpp
    ${_cg}/vtable_scanner.cpp
    ${_cg}/ppc/opcode.cpp
    ${_cg}/ppc/instruction.cpp
    ${_cg}/ppc/disasm.cpp
    ${_cg}/wasm/wasm_encoder.cpp
    ${_cg}/wasm/wasm_context_layout.cpp
    ${_cg}/wasm/wasm_builders.cpp
    ${_cg}/wasm/wasm_builders_fp.cpp
    ${_cg}/wasm/wasm_builders_system.cpp
    ${_cg}/wasm/wasm_builders_vector.cpp
    ${_cg}/wasm/wasm_helpers.cpp
    ${_cg}/wasm/wasm_function.cpp
    ${_cg}/wasm/wasm_writer.cpp
)
target_compile_definitions(rexglue-translate PRIVATE
    REXGLUE_TRANSLATOR_PPC=1
    REXGLUE_TRANSLATOR_LZX=1
    REXGLUE_NO_CPP_BACKEND=1
    REXGLUE_NO_RUNTIME=1)
target_include_directories(rexglue-translate PRIVATE
    ${REXGLUE_ROOT}/include
    ${CMAKE_CURRENT_BINARY_DIR}/include
    ${REXGLUE_ROOT}/thirdparty
    ${REXGLUE_ROOT}/thirdparty/tomlplusplus/include
    ${REXGLUE_ROOT}/thirdparty/simde
    ${REXGLUE_ROOT}/thirdparty/inja/third_party/include
    ${REXGLUE_ROOT}/thirdparty/utfcpp/source
    ${REXGLUE_ROOT}/thirdparty/cli11/include
    ${_cg}
    ${_cg}/builders
    ${REXGLUE_ROOT}/src)
target_compile_options(rexglue-translate PRIVATE -Wall -Wextra -Wno-unused-parameter)
target_link_libraries(rexglue-translate PRIVATE
    translator_ppc translator_lzx fmt::fmt spdlog::spdlog xxHash::xxhash aes128)
# Node: real filesystem access (NODERAWFS), a 64-bit address space with room for the 4.5 GiB
# guest address space plus the analysis (MAXIMUM_MEMORY), no threads (the codegen is
# single-threaded). EXIT_RUNTIME so the exit code reaches the shell.
target_link_options(rexglue-translate PRIVATE
    -sENVIRONMENT=node -sNODERAWFS=1 -sALLOW_MEMORY_GROWTH=1 -sMAXIMUM_MEMORY=16GB
    -sINITIAL_MEMORY=64MB -sSTACK_SIZE=8MB -sEXIT_RUNTIME=1
    "SHELL:--emit-symbol-map" -Wl,--error-limit=0)
set_target_properties(rexglue-translate PROPERTIES SUFFIX ".js")
