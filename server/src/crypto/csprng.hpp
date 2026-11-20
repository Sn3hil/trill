// SPDX-License-Identifier: MIT
#pragma once

#include "common/error.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace ar {

[[nodiscard]] Result<std::vector<std::uint8_t>> random_bytes(std::size_t count);

// Uniform decimal code in [0, 999999], zero-padded to six digits. Uses
// rejection sampling so every code is equally likely.
[[nodiscard]] Result<std::string> random_code6();

[[nodiscard]] Result<std::string> random_hex(std::size_t byte_count);

} // namespace ar
