// SPDX-License-Identifier: MIT
#include "common/clock.hpp"
#include "common/encoding.hpp"
#include "crypto/spake2.hpp"
#include "pairing/pairing_manager.hpp"

#include <gtest/gtest.h>

namespace ar {
namespace {

TEST(PairingManagerTest, OpenWindowAndTimeout) {
    auto clock = std::make_shared<FakeClock>();
    PairingConfig config{.window_seconds = 30, .max_attempts = 3};
    const std::string host_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string host_name = "Desktop";

    PairingManager pm(config, host_id, host_name, clock);

    bool opened_called = false;
    std::string opened_code;
    std::string closed_reason;

    pm.set_callbacks(
        [&](const std::string& code, int /*seconds*/) {
            opened_called = true;
            opened_code = code;
        },
        [&](const std::string& reason) { closed_reason = reason; },
        [](const std::string&, const std::string&, const std::string&) {});

    EXPECT_FALSE(pm.is_open());
    auto res = pm.open_window(30);
    ASSERT_TRUE(res.has_value());
    EXPECT_TRUE(opened_called);
    EXPECT_EQ(res->first.size(), 6u);
    EXPECT_EQ(res->first, opened_code);
    EXPECT_EQ(res->second, 30);
    EXPECT_TRUE(pm.is_open());
    EXPECT_EQ(pm.seconds_remaining(), 30);

    // Opening again while open is busy
    auto res2 = pm.open_window(30);
    EXPECT_FALSE(res2.has_value());
    EXPECT_EQ(res2.error().code, ErrorCode::busy);

    // Advance 10s
    clock->advance(std::chrono::seconds(10));
    EXPECT_EQ(pm.seconds_remaining(), 20);
    EXPECT_FALSE(pm.tick().has_value());

    // Advance 21s -> expired
    clock->advance(std::chrono::seconds(21));
    auto reason = pm.tick();
    ASSERT_TRUE(reason.has_value());
    EXPECT_EQ(*reason, "timeout");
    EXPECT_FALSE(pm.is_open());
    EXPECT_EQ(closed_reason, "timeout");
}

TEST(PairingManagerTest, LockoutAfterMaxAttempts) {
    auto clock = std::make_shared<FakeClock>();
    PairingConfig config{.window_seconds = 30, .max_attempts = 3};
    const std::string host_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string host_name = "Desktop";

    PairingManager pm(config, host_id, host_name, clock);

    std::string closed_reason;
    pm.set_callbacks([](const std::string&, int) {},
                     [&](const std::string& reason) { closed_reason = reason; },
                     [](const std::string&, const std::string&, const std::string&) {});

    auto res = pm.open_window(30);
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(pm.attempts_remaining(), 3);

    const std::string phone_spki =
        "1111222233334444111122223333444411112222333344441111222233334444";
    const std::string id_phone = "tr-phone:" + phone_spki;
    const std::string id_host = "tr-host:" + host_id;

    // Simulate 3 failed attempts
    for (int i = 0; i < 3; ++i) {
        Spake2 phone(SpakeRole::a, "999999", id_phone, id_host); // wrong code
        auto share_a = phone.share();
        ASSERT_TRUE(share_a.has_value());

        protocol::PairStart req{
            .proto = 1,
            .name = "Phone",
            .method = "spake2",
            .suite = "P256-SHA256-HKDF-HMAC",
            .share_b64 = base64_encode(*share_a),
        };

        auto start_resp = pm.begin_pair(req, phone_spki);
        ASSERT_TRUE(start_resp.has_value());

        auto host_share_bytes = base64_decode(start_resp->share_b64);
        ASSERT_TRUE(host_share_bytes.has_value());
        ASSERT_TRUE(phone.process_peer_share(*host_share_bytes));
        auto wrong_confirm = phone.own_confirm_b64();
        ASSERT_TRUE(wrong_confirm.has_value());

        auto finish = pm.finish_pair(*wrong_confirm, "192.168.1.50");
        EXPECT_FALSE(finish.has_value());
        EXPECT_EQ(finish.error().code, ErrorCode::pair_failed);
    }

    EXPECT_TRUE(pm.locked());
    EXPECT_FALSE(pm.is_open());
    EXPECT_EQ(closed_reason, "locked");
}

TEST(PairingManagerTest, SuccessfulPairingFlow) {
    auto clock = std::make_shared<FakeClock>();
    PairingConfig config{.window_seconds = 30, .max_attempts = 3};
    const std::string host_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const std::string host_name = "Desktop";

    PairingManager pm(config, host_id, host_name, clock);

    bool paired_called = false;
    std::string paired_id;
    std::string paired_name;
    std::string closed_reason;

    pm.set_callbacks([](const std::string&, int) {},
                     [&](const std::string& reason) { closed_reason = reason; },
                     [&](const std::string& id, const std::string& name, const std::string&) {
                         paired_called = true;
                         paired_id = id;
                         paired_name = name;
                     });

    auto open_res = pm.open_window(30);
    ASSERT_TRUE(open_res.has_value());
    const std::string code = open_res->first;

    const std::string phone_spki =
        "1111222233334444111122223333444411112222333344441111222233334444";
    const std::string id_phone = "tr-phone:" + phone_spki;
    const std::string id_host = "tr-host:" + host_id;

    // Phone runs role A with same code and identities
    Spake2 phone(SpakeRole::a, code, id_phone, id_host);
    auto share_a = phone.share();
    ASSERT_TRUE(share_a.has_value());

    protocol::PairStart start_req{
        .proto = 1,
        .name = "Pixel 8",
        .method = "spake2",
        .suite = "P256-SHA256-HKDF-HMAC",
        .share_b64 = base64_encode(*share_a),
    };

    auto host_start_resp = pm.begin_pair(start_req, phone_spki);
    ASSERT_TRUE(host_start_resp.has_value());
    EXPECT_EQ(host_start_resp->host_name, host_name);

    // Phone processes host share
    auto host_share_bytes = base64_decode(host_start_resp->share_b64);
    ASSERT_TRUE(host_share_bytes.has_value());
    ASSERT_TRUE(phone.process_peer_share(*host_share_bytes));

    // Phone verifies host confirm
    auto verify_host = phone.verify_peer_confirm_b64(host_start_resp->confirm_b64);
    ASSERT_TRUE(verify_host.has_value());
    EXPECT_TRUE(*verify_host);

    // Phone generates own confirm
    auto phone_confirm_b64 = phone.own_confirm_b64();
    ASSERT_TRUE(phone_confirm_b64.has_value());

    // Host receives phone confirm
    auto finish_res = pm.finish_pair(*phone_confirm_b64, "192.168.1.100");
    ASSERT_TRUE(finish_res.has_value());

    EXPECT_TRUE(paired_called);
    EXPECT_EQ(paired_id, phone_spki);
    EXPECT_EQ(paired_name, "Pixel 8");
    EXPECT_FALSE(pm.is_open());
    EXPECT_EQ(closed_reason, "success");
}

} // namespace
} // namespace ar
