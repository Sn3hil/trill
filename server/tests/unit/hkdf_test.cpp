// SPDX-License-Identifier: MIT
#include "common/encoding.hpp"
#include "crypto/hkdf.hpp"

#include <gtest/gtest.h>

namespace ar {
namespace {

TEST(HkdfTest, Sha256Nist) {
    // NIST vector for "abc"
    // ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
    const auto hash1 = sha256("abc");
    EXPECT_EQ(hex_encode(hash1),
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // Empty string
    // e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855
    const auto hash2 = sha256("");
    EXPECT_EQ(hex_encode(hash2),
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(HkdfTest, HmacSha256Rfc4231Case1) {
    // RFC 4231 Test Case 1:
    // Key = 0x0b repeated 20 times
    // Data = "Hi There"
    // Digest = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
    std::vector<std::uint8_t> key(20, 0x0b);
    std::string data = "Hi There";
    std::vector<std::uint8_t> data_vec(data.begin(), data.end());

    auto mac = hmac_sha256(key, data_vec);
    ASSERT_TRUE(mac.has_value());
    EXPECT_EQ(hex_encode(*mac), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
}

TEST(HkdfTest, Rfc5869Case1) {
    // RFC 5869 Test Case 1:
    // IKM = 0x0b repeated 22 times
    // salt = 0x000102030405060708090a0b0c
    // info = 0xf0f1f2f3f4f5f6f7f8f9
    // L = 42
    // OKM = 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
    std::vector<std::uint8_t> ikm(22, 0x0b);
    auto salt = hex_decode("000102030405060708090a0b0c");
    auto info = hex_decode("f0f1f2f3f4f5f6f7f8f9");
    ASSERT_TRUE(salt.has_value() && info.has_value());

    auto okm = hkdf_sha256(ikm, *salt, *info, 42);
    ASSERT_TRUE(okm.has_value());
    EXPECT_EQ(
        hex_encode(*okm),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
}

TEST(HkdfTest, Rfc5869Case3EmptySaltAndInfo) {
    // RFC 5869 Test Case 3:
    // IKM = 0x0b repeated 22 times
    // salt = empty
    // info = empty
    // L = 42
    // OKM = 8da4e7759503a0ec0905c047464b13c46e61b7ce97166f041e277b55a1233aaf3fb9614f1e24a1690270
    std::vector<std::uint8_t> ikm(22, 0x0b);
    auto okm = hkdf_sha256(ikm, {}, {}, 42);
    ASSERT_TRUE(okm.has_value());
    EXPECT_EQ(
        hex_encode(*okm),
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
}

} // namespace
} // namespace ar
