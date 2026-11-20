// SPDX-License-Identifier: MIT
#include "common/encoding.hpp"

#include <gtest/gtest.h>

namespace ar {
namespace {

TEST(EncodingTest, HexEncodeAndDecode) {
    const std::vector<std::uint8_t> bytes = {0x00, 0x01, 0x0a, 0x10, 0x7f, 0x80, 0xff};
    const std::string hex = hex_encode(bytes);
    EXPECT_EQ(hex, "00010a107f80ff");

    auto decoded = hex_decode(hex);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, bytes);

    // Empty
    EXPECT_EQ(hex_encode({}), "");
    auto empty_decoded = hex_decode("");
    ASSERT_TRUE(empty_decoded.has_value());
    EXPECT_TRUE(empty_decoded->empty());

    // Odd length
    auto odd = hex_decode("abc");
    EXPECT_FALSE(odd.has_value());
    EXPECT_EQ(odd.error().code, ErrorCode::invalid_argument);

    // Invalid chars
    auto invalid = hex_decode("012g");
    EXPECT_FALSE(invalid.has_value());
    EXPECT_EQ(invalid.error().code, ErrorCode::invalid_argument);
}

TEST(EncodingTest, Base64EncodeAndDecode) {
    const std::string text = "Hello, Trill!";
    std::vector<std::uint8_t> bytes(text.begin(), text.end());

    const std::string b64 = base64_encode(bytes);
    EXPECT_FALSE(b64.empty());

    auto decoded = base64_decode(b64);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, bytes);

    // Empty
    EXPECT_EQ(base64_encode({}), "");
    auto empty_decoded = base64_decode("");
    ASSERT_TRUE(empty_decoded.has_value());
    EXPECT_TRUE(empty_decoded->empty());

    // Invalid base64
    auto bad = base64_decode("!@#$%^&*()");
    EXPECT_FALSE(bad.has_value());
}

TEST(EncodingTest, ConstantTimeEqual) {
    EXPECT_TRUE(constant_time_equal("secret_key_12345", "secret_key_12345"));
    EXPECT_FALSE(constant_time_equal("secret_key_12345", "secret_key_12346"));
    EXPECT_FALSE(constant_time_equal("short", "longer_secret"));
    EXPECT_TRUE(constant_time_equal("", ""));
}

} // namespace
} // namespace ar
