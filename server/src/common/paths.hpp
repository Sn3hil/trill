// SPDX-License-Identifier: MIT
#pragma once

#include "common/error.hpp"

#include <filesystem>

namespace ar {

struct Paths {
    std::filesystem::path config_dir;
    std::filesystem::path state_dir;
    std::filesystem::path runtime_dir;
    std::filesystem::path identity_dir;
    std::filesystem::path config_file;
    std::filesystem::path devices_file;
    std::filesystem::path prev_default_file;
    std::filesystem::path socket_path;
    std::filesystem::path log_file;
};

// Resolve XDG paths. Honours XDG_CONFIG_HOME, XDG_STATE_HOME and
// XDG_RUNTIME_DIR. Overridable for tests through the same environment
// variables.
[[nodiscard]] Result<Paths> resolve_paths();

// Create a directory (including parents). Enforces mode (e.g. 0700).
[[nodiscard]] Result<void> ensure_dir(const std::filesystem::path& dir, unsigned mode);

// Write a file atomically through a same-directory temp file + rename, with the
// given mode (e.g. 0600). fsyncs the file and the directory.
[[nodiscard]] Result<void> write_file_atomic(const std::filesystem::path& path,
                                             const std::string& content, unsigned mode = 0600);

[[nodiscard]] Result<std::string> read_file(const std::filesystem::path& path);

[[nodiscard]] Result<void> remove_file(const std::filesystem::path& path);

// Wall-clock timestamp in the protocol's ISO-8601 Z form.
[[nodiscard]] std::string utc_now_iso8601();

} // namespace ar
