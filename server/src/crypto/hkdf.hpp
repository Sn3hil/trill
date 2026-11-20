// SPDX-License-Identifier: MIT
#pragma once

#include "common/error.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace ar {

using Sha256 = std::array<std::uint8_t, 32>;

[[nodiscard]] Sha256 sha256(std::span<const std::uint8_t> data);
[[nodiscard]] Sha256 sha256(std::string_view data);

// HKDF-SHA256 (RFC 5869). Empty salt/info are permitted.
[[nodiscard]] Result<std::vector<std::uint8_t>> hkdf_sha256(std::span<const std::uint8_t> ikm,
                                                            std::span<const std::uint8_t> salt,
                                                            std::span<const std::uint8_t> info,
                                                            std::size_t length);

[[nodiscard]] Result<std::vector<std::uint8_t>> hmac_sha256(std::span<const std::uint8_t> key,
                                                            std::span<const std::uint8_t> message);

} // namespace ar
