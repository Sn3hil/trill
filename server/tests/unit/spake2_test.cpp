// SPDX-License-Identifier: MIT
#include "common/encoding.hpp"
#include "crypto/spake2.hpp"

#include <array>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <iostream>
#include <nlohmann/json.hpp>

namespace ar {
namespace {

std::array<std::uint8_t, 32> to_32_bytes(std::string_view hex) {
    auto dec = hex_decode(hex);
    EXPECT_TRUE(dec.has_value());
    std::array<std::uint8_t, 32> arr{};
    if (dec && dec->size() == 32) {
        std::copy(dec->begin(), dec->end(), arr.begin());
    }
    return arr;
}

std::filesystem::path find_vector(const std::string& filename) {
    const std::vector<std::filesystem::path> candidates = {
        filename,
        "protocol/testvectors/" + filename,
        "../protocol/testvectors/" + filename,
        "../../protocol/testvectors/" + filename,
        "../../../protocol/testvectors/" + filename,
    };
    for (const auto& p : candidates) {
        if (std::filesystem::exists(p))
            return p;
    }
    return filename;
}

TEST(Spake2Test, Rfc9382AppendixBCases) {
    auto path = find_vector("spake2_rfc9382_p256.json");
    std::ifstream f(path);
    ASSERT_TRUE(f.is_open()) << "Could not open " << path;

    auto json_data = nlohmann::json::parse(f);
    ASSERT_TRUE(json_data.contains("cases"));

    for (const auto& item : json_data["cases"]) {
        const std::string id_a = item["id_a"];
        const std::string id_b = item["id_b"];
        const std::string w_hex = item["w"];
        const std::string x_hex = item["x"];
        const std::string y_hex = item["y"];

        auto scalar_a = to_32_bytes(x_hex);
        auto scalar_b = to_32_bytes(y_hex);

        const std::string raw_w = "raw-w:" + w_hex;

        Spake2 party_a(SpakeRole::a, raw_w, id_a, id_b, scalar_a);
        Spake2 party_b(SpakeRole::b, raw_w, id_a, id_b, scalar_b);

        auto share_a = party_a.share();
        auto share_b = party_b.share();
        ASSERT_TRUE(share_a.has_value());
        ASSERT_TRUE(share_b.has_value());

        EXPECT_EQ(hex_encode(*share_a), item["pA"].get<std::string>());
        EXPECT_EQ(hex_encode(*share_b), item["pB"].get<std::string>());

        ASSERT_TRUE(party_a.process_peer_share(*share_b));
        ASSERT_TRUE(party_b.process_peer_share(*share_a));

        EXPECT_EQ(hex_encode(party_a.shared_point()), item["K"].get<std::string>());
        EXPECT_EQ(hex_encode(party_b.shared_point()), item["K"].get<std::string>());

        EXPECT_EQ(hex_encode(party_a.transcript()), item["TT"].get<std::string>());
        EXPECT_EQ(hex_encode(party_b.transcript()), item["TT"].get<std::string>());

        EXPECT_EQ(hex_encode(party_a.hash_tt()), item["hash_TT"].get<std::string>());
        EXPECT_EQ(hex_encode(party_b.hash_tt()), item["hash_TT"].get<std::string>());

        EXPECT_EQ(hex_encode(party_a.ke()), item["Ke"].get<std::string>());
        EXPECT_EQ(hex_encode(party_b.ke()), item["Ke"].get<std::string>());

        EXPECT_EQ(hex_encode(party_a.ka()), item["Ka"].get<std::string>());
        EXPECT_EQ(hex_encode(party_b.ka()), item["Ka"].get<std::string>());

        EXPECT_EQ(hex_encode(party_a.kca()), item["KcA"].get<std::string>());
        EXPECT_EQ(hex_encode(party_b.kca()), item["KcA"].get<std::string>());

        EXPECT_EQ(hex_encode(party_a.kcb()), item["KcB"].get<std::string>());
        EXPECT_EQ(hex_encode(party_b.kcb()), item["KcB"].get<std::string>());

        auto rfc_a = party_a.rfc_confirm_a();
        auto rfc_b = party_b.rfc_confirm_b();
        ASSERT_TRUE(rfc_a.has_value());
        ASSERT_TRUE(rfc_b.has_value());

        EXPECT_EQ(hex_encode(*rfc_a), item["rfc_confirm_a"].get<std::string>());
        EXPECT_EQ(hex_encode(*rfc_b), item["rfc_confirm_b"].get<std::string>());
    }
}

TEST(Spake2Test, PairV1Vector) {
    auto path = find_vector("pair_v1.json");
    std::ifstream f(path);
    ASSERT_TRUE(f.is_open()) << "Could not open " << path;

    auto v = nlohmann::json::parse(f);

    const std::string code = v["code"];
    const std::string id_a = v["id_a"];
    const std::string id_b = v["id_b"];

    auto scalar_a = to_32_bytes(v["scalar_a_hex"].get<std::string>());
    auto scalar_b = to_32_bytes(v["scalar_b_hex"].get<std::string>());

    // Test derive_w
    auto derived_w = Spake2::derive_w(code);
    ASSERT_TRUE(derived_w.has_value());
    EXPECT_EQ(*derived_w, v["w_hex"].get<std::string>());

    Spake2 phone(SpakeRole::a, code, id_a, id_b, scalar_a);
    Spake2 host(SpakeRole::b, code, id_a, id_b, scalar_b);

    auto pA = phone.share();
    auto pB = host.share();
    ASSERT_TRUE(pA.has_value());
    ASSERT_TRUE(pB.has_value());

    EXPECT_EQ(hex_encode(*pA), v["share_a_hex"].get<std::string>());
    EXPECT_EQ(base64_encode(*pA), v["share_a_b64"].get<std::string>());
    EXPECT_EQ(hex_encode(*pB), v["share_b_hex"].get<std::string>());
    EXPECT_EQ(base64_encode(*pB), v["share_b_b64"].get<std::string>());

    ASSERT_TRUE(phone.process_peer_share(*pB));
    ASSERT_TRUE(host.process_peer_share(*pA));

    EXPECT_EQ(hex_encode(phone.shared_point()), v["K_hex"].get<std::string>());
    EXPECT_EQ(hex_encode(host.shared_point()), v["K_hex"].get<std::string>());

    EXPECT_EQ(hex_encode(phone.transcript()), v["TT_hex"].get<std::string>());
    EXPECT_EQ(hex_encode(host.transcript()), v["TT_hex"].get<std::string>());

    EXPECT_EQ(hex_encode(phone.hash_tt()), v["hash_TT_hex"].get<std::string>());
    EXPECT_EQ(hex_encode(phone.ke()), v["Ke_hex"].get<std::string>());
    EXPECT_EQ(hex_encode(phone.ka()), v["Ka_hex"].get<std::string>());
    EXPECT_EQ(hex_encode(phone.kca()), v["KcA_hex"].get<std::string>());
    EXPECT_EQ(hex_encode(phone.kcb()), v["KcB_hex"].get<std::string>());

    // Wire confirms:
    // Host sends message 2: confirm_b = MAC(KcB, pA)
    auto host_confirm = host.own_confirm();
    ASSERT_TRUE(host_confirm.has_value());
    EXPECT_EQ(hex_encode(*host_confirm), v["confirm_b_hex"].get<std::string>());
    EXPECT_EQ(base64_encode(*host_confirm), v["confirm_b_b64"].get<std::string>());

    // Phone verifies host confirm
    auto phone_verifies_host = phone.verify_peer_confirm(*host_confirm);
    ASSERT_TRUE(phone_verifies_host.has_value());
    EXPECT_TRUE(*phone_verifies_host);

    // Phone sends message 3: confirm_a = MAC(KcA, pB)
    auto phone_confirm = phone.own_confirm();
    ASSERT_TRUE(phone_confirm.has_value());
    EXPECT_EQ(hex_encode(*phone_confirm), v["confirm_a_hex"].get<std::string>());
    EXPECT_EQ(base64_encode(*phone_confirm), v["confirm_a_b64"].get<std::string>());

    // Host verifies phone confirm
    auto host_verifies_phone = host.verify_peer_confirm(*phone_confirm);
    ASSERT_TRUE(host_verifies_phone.has_value());
    EXPECT_TRUE(*host_verifies_phone);
}

TEST(Spake2Test, MutualConfirmationLive) {
    const std::string code = "492015";
    const std::string id_phone =
        "tr-phone:0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const std::string id_host =
        "tr-host:201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201";

    // Random ephemeral scalars
    Spake2 phone(SpakeRole::a, code, id_phone, id_host);
    Spake2 host(SpakeRole::b, code, id_phone, id_host);

    auto pA = phone.share();
    auto pB = host.share();
    ASSERT_TRUE(pA.has_value());
    ASSERT_TRUE(pB.has_value());

    ASSERT_TRUE(phone.process_peer_share(*pB));
    ASSERT_TRUE(host.process_peer_share(*pA));

    auto cB = host.own_confirm_b64();
    ASSERT_TRUE(cB.has_value());
    auto phone_ok = phone.verify_peer_confirm_b64(*cB);
    ASSERT_TRUE(phone_ok.has_value());
    EXPECT_TRUE(*phone_ok);

    auto cA = phone.own_confirm_b64();
    ASSERT_TRUE(cA.has_value());
    auto host_ok = host.verify_peer_confirm_b64(*cA);
    ASSERT_TRUE(host_ok.has_value());
    EXPECT_TRUE(*host_ok);
}

TEST(Spake2Test, WrongCodeRejection) {
    const std::string id_phone =
        "tr-phone:1111111111111111111111111111111111111111111111111111111111111111";
    const std::string id_host =
        "tr-host:2222222222222222222222222222222222222222222222222222222222222222";

    Spake2 phone(SpakeRole::a, "123456", id_phone, id_host);
    Spake2 host(SpakeRole::b, "654321", id_phone, id_host);

    auto pA = phone.share();
    auto pB = host.share();
    ASSERT_TRUE(pA.has_value());
    ASSERT_TRUE(pB.has_value());

    ASSERT_TRUE(phone.process_peer_share(*pB));
    ASSERT_TRUE(host.process_peer_share(*pA));

    auto cB = host.own_confirm_b64();
    ASSERT_TRUE(cB.has_value());

    auto phone_ok = phone.verify_peer_confirm_b64(*cB);
    ASSERT_TRUE(phone_ok.has_value());
    EXPECT_FALSE(*phone_ok); // Must fail!
}

TEST(Spake2Test, RejectInvalidPeerShare) {
    Spake2 phone(SpakeRole::a, "123456", "tr-phone:11", "tr-host:22");
    std::vector<std::uint8_t> invalid_share = {0x04, 0x01, 0x02};
    auto res = phone.process_peer_share(invalid_share);
    EXPECT_FALSE(res.has_value());
}

} // namespace
} // namespace ar
