// SPDX-License-Identifier: MIT
#include "net/framing.hpp"

#include <algorithm>
#include <cstring>

namespace ar {

Result<std::vector<std::uint8_t>> encode_frame(std::string_view payload) {
    if (payload.empty()) {
        return fail(ErrorCode::bad_request, "empty frame");
    }
    if (payload.size() > kMaxFrameSize) {
        return fail(ErrorCode::bad_request, "frame too large");
    }
    std::vector<std::uint8_t> out(kFrameHeaderSize + payload.size());
    const auto len = static_cast<std::uint32_t>(payload.size());
    out[0] = static_cast<std::uint8_t>((len >> 24) & 0xff);
    out[1] = static_cast<std::uint8_t>((len >> 16) & 0xff);
    out[2] = static_cast<std::uint8_t>((len >> 8) & 0xff);
    out[3] = static_cast<std::uint8_t>(len & 0xff);
    std::memcpy(out.data() + kFrameHeaderSize, payload.data(), payload.size());
    return out;
}

Result<std::vector<std::string>> FrameDecoder::feed(std::span<const std::uint8_t> chunk) {
    std::vector<std::string> frames;
    if (chunk.empty())
        return frames;

    // Header says at most 64 KiB; refuse to buffer more than one oversized
    // frame even if a peer keeps feeding without a valid length.
    if (buffer_.size() + chunk.size() > kMaxFrameSize + kFrameHeaderSize) {
        buffer_.clear();
        return fail(ErrorCode::protocol_error, "frame buffer overflow");
    }
    buffer_.insert(buffer_.end(), chunk.begin(), chunk.end());

    std::size_t offset = 0;
    while (buffer_.size() - offset >= kFrameHeaderSize) {
        const std::uint8_t* h = buffer_.data() + offset;
        const std::uint32_t len =
            (static_cast<std::uint32_t>(h[0]) << 24) | (static_cast<std::uint32_t>(h[1]) << 16) |
            (static_cast<std::uint32_t>(h[2]) << 8) | static_cast<std::uint32_t>(h[3]);
        if (len == 0) {
            buffer_.clear();
            return fail(ErrorCode::protocol_error, "zero-length frame");
        }
        if (len > kMaxFrameSize) {
            buffer_.clear();
            return fail(ErrorCode::protocol_error, "frame exceeds 64 KiB");
        }
        if (buffer_.size() - offset < kFrameHeaderSize + len)
            break;
        frames.emplace_back(
            reinterpret_cast<const char*>(buffer_.data() + offset + kFrameHeaderSize), len);
        offset += kFrameHeaderSize + len;
    }

    if (offset > 0) {
        buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(offset));
    }
    return frames;
}

} // namespace ar
