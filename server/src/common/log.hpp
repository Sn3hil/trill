// SPDX-License-Identifier: MIT
#pragma once

#include <memory>
#include <spdlog/spdlog.h>
#include <string>
#include <string_view>

namespace ar {

// Initialise the process-wide logger. When log_file is non-empty, logs are
// written to that file (mode 0600) in addition to the console when
// also_console is true.
void init_logging(std::string_view level, const std::string& log_file = {},
                  bool also_console = true);

void shutdown_logging();

[[nodiscard]] std::shared_ptr<spdlog::logger> logger();

// Redaction helpers. Nothing in this codebase should ever log a pairing code,
// private key, SPKI private material or a shared secret. These helpers exist
// so call sites can be explicit and greppable.
[[nodiscard]] constexpr std::string_view redacted() {
    return "<redacted>";
}

// Returns the first 8 hex characters of an identifier, or "<empty>".
[[nodiscard]] std::string short_id(std::string_view hex_id);

} // namespace ar
