// SPDX-License-Identifier: MIT
#include "crypto/csprng.hpp"

#include "common/encoding.hpp"

#include <cstdio>
#include <openssl/rand.h>

namespace ar {

Result<std::vector<std::uint8_t>> random_bytes(std::size_t count) {
    std::vector<std::uint8_t> out(count);
    if (count == 0)
        return out;
    if (RAND_bytes(out.data(), static_cast<int>(count)) != 1) {
        return fail(ErrorCode::crypto_error, "RAND_bytes failed");
    }
    return out;
}

Result<std::string> random_code6() {
    // 1,000,000 is not a power of two. Reject values above the largest
    // multiple of the range to keep the distribution uniform.
    constexpr std::uint32_t kRange = 1'000'000;
    constexpr std::uint32_t kLimit = (UINT32_MAX / kRange) * kRange;

    for (int attempt = 0; attempt < 64; ++attempt) {
        std::uint32_t value = 0;
        if (RAND_bytes(reinterpret_cast<unsigned char*>(&value), sizeof(value)) != 1) {
            return fail(ErrorCode::crypto_error, "RAND_bytes failed");
        }
        if (value >= kLimit)
            continue;
        const std::uint32_t code = value % kRange;
        char buf[8]{};
        std::snprintf(buf, sizeof(buf), "%06u", code);
        return std::string(buf);
    }
    return fail(ErrorCode::crypto_error, "code rejection sampling failed");
}

Result<std::string> random_hex(std::size_t byte_count) {
    auto bytes = random_bytes(byte_count);
    if (!bytes)
        return std::unexpected(bytes.error());
    return hex_encode(*bytes);
}

} // namespace ar
