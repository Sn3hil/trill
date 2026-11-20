// SPDX-License-Identifier: MIT
#include "common/encoding.hpp"

#include <array>
#include <cctype>
#include <openssl/crypto.h>
#include <openssl/evp.h>

namespace ar {
namespace {

constexpr char kHex[] = "0123456789abcdef";

int hex_value(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

} // namespace

std::string hex_encode(std::span<const std::uint8_t> bytes) {
    std::string out;
    out.resize(bytes.size() * 2);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        out[2 * i] = kHex[bytes[i] >> 4];
        out[2 * i + 1] = kHex[bytes[i] & 0x0f];
    }
    return out;
}

Result<std::vector<std::uint8_t>> hex_decode(std::string_view hex) {
    if (hex.size() % 2 != 0) {
        return fail(ErrorCode::invalid_argument, "hex string has odd length");
    }
    std::vector<std::uint8_t> out(hex.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        const int hi = hex_value(hex[2 * i]);
        const int lo = hex_value(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return fail(ErrorCode::invalid_argument, "invalid hex character");
        }
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return out;
}

std::string base64_encode(std::span<const std::uint8_t> bytes) {
    if (bytes.empty())
        return {};
    const std::size_t out_len = 4 * ((bytes.size() + 2) / 3);
    std::string out(out_len, '\0');
    const int written = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()), bytes.data(),
                                        static_cast<int>(bytes.size()));
    if (written < 0)
        return {};
    out.resize(static_cast<std::size_t>(written));
    return out;
}

Result<std::vector<std::uint8_t>> base64_decode(std::string_view text) {
    if (text.empty())
        return std::vector<std::uint8_t>{};
    if (text.size() % 4 != 0) {
        return fail(ErrorCode::invalid_argument, "base64 length is not a multiple of 4");
    }
    std::vector<std::uint8_t> out(3 * (text.size() / 4));
    const int n = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(text.data()),
                                  static_cast<int>(text.size()));
    if (n < 0) {
        return fail(ErrorCode::invalid_argument, "invalid base64");
    }
    std::size_t len = static_cast<std::size_t>(n);
    if (!text.empty() && text.back() == '=')
        --len;
    if (text.size() >= 2 && text[text.size() - 2] == '=')
        --len;
    out.resize(len);
    return out;
}

bool constant_time_equal(std::string_view a, std::string_view b) {
    if (a.size() != b.size())
        return false;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

} // namespace ar
