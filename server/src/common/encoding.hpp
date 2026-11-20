// SPDX-License-Identifier: MIT
#pragma once

#include "common/error.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ar {

[[nodiscard]] std::string hex_encode(std::span<const std::uint8_t> bytes);
[[nodiscard]] Result<std::vector<std::uint8_t>> hex_decode(std::string_view hex);

[[nodiscard]] std::string base64_encode(std::span<const std::uint8_t> bytes);
[[nodiscard]] Result<std::vector<std::uint8_t>> base64_decode(std::string_view text);

// Constant-time comparison for secrets and fingerprints.
[[nodiscard]] bool constant_time_equal(std::string_view a, std::string_view b);

} // namespace ar
