// SPDX-License-Identifier: MIT
#pragma once

#include "common/error.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace ar {

inline constexpr std::size_t kMaxFrameSize = 65536;
inline constexpr std::size_t kFrameHeaderSize = 4;

// u32 big-endian length (1..65536), then UTF-8 JSON.
[[nodiscard]] Result<std::vector<std::uint8_t>> encode_frame(std::string_view payload);

// Sans-IO incremental decoder. Feed arbitrary chunks; complete frames are
// returned in order. Rejects zero-length and oversized frames without
// allocating attacker-controlled memory beyond the declared size.
class FrameDecoder {
  public:
    [[nodiscard]] Result<std::vector<std::string>> feed(std::span<const std::uint8_t> chunk);

    [[nodiscard]] std::size_t buffered() const {
        return buffer_.size();
    }
    void reset() {
        buffer_.clear();
    }

  private:
    std::vector<std::uint8_t> buffer_;
};

} // namespace ar
