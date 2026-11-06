/**
 * @file        translator/xdvdfs.h
 * @brief       Reads one file from an Xbox 360 disc image (XDVDFS / "XISO")
 *
 * @copyright   Copyright (c) 2026 MCLA-Reborn contributors
 * @license     Not yet licensed: MCLA-Reborn decides before any release (D-009)
 *
 * The same lookup as MCLA-Reborn's `xiso` crate (crates/xiso): find the volume descriptor at
 * one of the known partition bases, walk directory tables (binary trees) to the file, and
 * read only that file's bytes. The whole image is never loaded.
 */

#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace rex::translator {

struct DiscFile {
  uint64_t partitionBase = 0;  ///< Byte offset of the XDVDFS partition in the image
  std::vector<uint8_t> bytes;
};

/// Reads `path` (components separated by / or \, matched case-insensitively) from the disc
/// image at `image`. On failure returns false and sets `error`.
bool ReadDiscFile(const std::filesystem::path& image, const std::string& path, DiscFile& out,
                  std::string& error);

}  // namespace rex::translator
