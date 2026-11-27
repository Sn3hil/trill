// SPDX-License-Identifier: MIT
#include "protocol/messages.hpp"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <string>

namespace ar {
namespace {

std::filesystem::path find_golden(const std::string& filename) {
    const std::vector<std::filesystem::path> candidates = {
        filename,
        "protocol/golden/" + filename,
        "../protocol/golden/" + filename,
        "../../protocol/golden/" + filename,
        "../../../protocol/golden/" + filename,
    };
    for (const auto& p : candidates) {
        if (std::filesystem::exists(p))
            return p;
    }
    return filename;
}

std::string read_file_string(const std::filesystem::path& path) {
    std::ifstream f(path);
    EXPECT_TRUE(f.is_open()) << "Could not open " << path;
    return std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}

TEST(MessagesTest, Envelopes) {
    auto req = protocol::parse_envelope(R"({"id":1,"type":"ping"})");
    ASSERT_TRUE(req.has_value());
    EXPECT_EQ(req->id, 1u);
    EXPECT_EQ(req->type, "ping");
    EXPECT_FALSE(req->is_event);
    EXPECT_FALSE(req->is_response);

    auto evt = protocol::parse_envelope(R"({"type":"event.stream.state","stream_id":1})");
    ASSERT_TRUE(evt.has_value());
    EXPECT_FALSE(evt->id.has_value());
    EXPECT_EQ(evt->type, "event.stream.state");
    EXPECT_TRUE(evt->is_event);

    auto resp = protocol::parse_envelope(R"({"re":1,"ok":true})");
    ASSERT_TRUE(resp.has_value());
    EXPECT_EQ(resp->id, 1u);
    EXPECT_TRUE(resp->is_response);
}

TEST(MessagesTest, GoldenPairStart) {
    auto valid_raw = read_file_string(find_golden("pair_start.valid.json"));
    auto env = protocol::parse_envelope(valid_raw);
    ASSERT_TRUE(env.has_value());
    auto msg = protocol::parse_pair_start(env->body);
    ASSERT_TRUE(msg.has_value());
    EXPECT_EQ(msg->proto, 1);
    EXPECT_EQ(msg->name, "Pixel 8");
    EXPECT_EQ(msg->method, "spake2");
    EXPECT_EQ(msg->suite, "P256-SHA256-HKDF-HMAC");
    EXPECT_FALSE(msg->share_b64.empty());

    auto invalid_raw = read_file_string(find_golden("pair_start.invalid.json"));
    auto inv_env = protocol::parse_envelope(invalid_raw);
    ASSERT_TRUE(inv_env.has_value());
    auto bad = protocol::parse_pair_start(inv_env->body);
    EXPECT_FALSE(bad.has_value());
}

TEST(MessagesTest, GoldenPairConfirm) {
    auto valid_raw = read_file_string(find_golden("pair_confirm.valid.json"));
    auto env = protocol::parse_envelope(valid_raw);
    ASSERT_TRUE(env.has_value());
    auto msg = protocol::parse_pair_confirm(env->body);
    ASSERT_TRUE(msg.has_value());
    EXPECT_FALSE(msg->confirm_b64.empty());

    auto invalid_raw = read_file_string(find_golden("pair_confirm.invalid.json"));
    auto inv_env = protocol::parse_envelope(invalid_raw);
    ASSERT_TRUE(inv_env.has_value());
    auto bad = protocol::parse_pair_confirm(inv_env->body);
    EXPECT_FALSE(bad.has_value());
}

TEST(MessagesTest, GoldenSessionHello) {
    auto valid_raw = read_file_string(find_golden("session_hello.valid.json"));
    auto env = protocol::parse_envelope(valid_raw);
    ASSERT_TRUE(env.has_value());
    auto msg = protocol::parse_session_hello(env->body);
    ASSERT_TRUE(msg.has_value());
    EXPECT_EQ(msg->proto_min, 1);
    EXPECT_EQ(msg->proto_max, 1);
    EXPECT_EQ(msg->name, "Pixel 8");
    EXPECT_EQ(msg->roc, "0.4.0");

    auto invalid_raw = read_file_string(find_golden("session_hello.invalid.json"));
    auto inv_env = protocol::parse_envelope(invalid_raw);
    ASSERT_TRUE(inv_env.has_value());
    auto bad = protocol::parse_session_hello(inv_env->body);
    EXPECT_FALSE(bad.has_value());
}

TEST(MessagesTest, GoldenStreamStart) {
    auto valid_raw = read_file_string(find_golden("stream_start.valid.json"));
    auto env = protocol::parse_envelope(valid_raw);
    ASSERT_TRUE(env.has_value());
    auto msg = protocol::parse_stream_start(env->body);
    ASSERT_TRUE(msg.has_value());
    EXPECT_EQ(msg->source_port, 41001);
    EXPECT_EQ(msg->repair_port, 41002);
    EXPECT_EQ(msg->wire_encoding, "avp_l16_stereo_44100");
    EXPECT_EQ(msg->fec, "rs8m");
    EXPECT_EQ(msg->target_latency_ms, 150);

    auto invalid_raw = read_file_string(find_golden("stream_start.invalid.json"));
    auto inv_env = protocol::parse_envelope(invalid_raw);
    ASSERT_TRUE(inv_env.has_value());
    auto bad = protocol::parse_stream_start(inv_env->body);
    EXPECT_FALSE(bad.has_value());
}

TEST(MessagesTest, GoldenStreamStop) {
    auto valid_raw = read_file_string(find_golden("stream_stop.valid.json"));
    auto env = protocol::parse_envelope(valid_raw);
    ASSERT_TRUE(env.has_value());
    auto msg = protocol::parse_stream_stop(env->body);
    ASSERT_TRUE(msg.has_value());
    EXPECT_EQ(msg->stream_id, 1u);

    auto invalid_raw = read_file_string(find_golden("stream_stop.invalid.json"));
    auto inv_env = protocol::parse_envelope(invalid_raw);
    ASSERT_TRUE(inv_env.has_value());
    auto bad = protocol::parse_stream_stop(inv_env->body);
    EXPECT_FALSE(bad.has_value());
}

TEST(MessagesTest, GoldenDeviceRename) {
    auto valid_raw = read_file_string(find_golden("device_rename.valid.json"));
    auto env = protocol::parse_envelope(valid_raw);
    ASSERT_TRUE(env.has_value());
    auto msg = protocol::parse_device_rename(env->body);
    ASSERT_TRUE(msg.has_value());
    EXPECT_EQ(msg->name, "Living Room Pixel");

    auto invalid_raw = read_file_string(find_golden("device_rename.invalid.json"));
    auto inv_env = protocol::parse_envelope(invalid_raw);
    ASSERT_TRUE(inv_env.has_value());
    auto bad = protocol::parse_device_rename(inv_env->body);
    EXPECT_FALSE(bad.has_value());
}

TEST(MessagesTest, Serializers) {
    auto ok_resp = protocol::make_ok_response(1, {{"status", "ready"}});
    auto env = protocol::parse_envelope(ok_resp);
    ASSERT_TRUE(env.has_value());
    EXPECT_TRUE(env->is_response);
    EXPECT_EQ(env->body["ok"], true);

    auto err_resp = protocol::make_error_response(2, {"busy", "Another stream active"});
    auto env_err = protocol::parse_envelope(err_resp);
    ASSERT_TRUE(env_err.has_value());
    EXPECT_TRUE(env_err->is_response);
    EXPECT_EQ(env_err->body["ok"], false);
    EXPECT_EQ(env_err->body["error"]["code"], "busy");

    auto evt = protocol::make_event("event.stream.state", {{"state", "running"}});
    auto env_evt = protocol::parse_envelope(evt);
    ASSERT_TRUE(env_evt.has_value());
    EXPECT_TRUE(env_evt->is_event);
    EXPECT_EQ(env_evt->type, "event.stream.state");
}

TEST(MessagesTest, MicMessages) {
    auto req_raw = R"({"id":10,"type":"mic.start","wire_encoding":"avp_l16_stereo_44100","fec":"rs8m"})";
    auto env = protocol::parse_envelope(req_raw);
    ASSERT_TRUE(env.has_value());
    auto mic_start = protocol::parse_mic_start(env->body);
    ASSERT_TRUE(mic_start.has_value());
    EXPECT_EQ(mic_start->wire_encoding, "avp_l16_stereo_44100");
    EXPECT_EQ(mic_start->fec, "rs8m");

    protocol::MicStartResponse resp{1, 49100, 49101, "starting"};
    auto resp_json = protocol::to_json(resp);
    EXPECT_EQ(resp_json["stream_id"], 1);
    EXPECT_EQ(resp_json["receiver"]["source_port"], 49100);
    EXPECT_EQ(resp_json["receiver"]["repair_port"], 49101);

    auto stop_raw = R"({"id":11,"type":"mic.stop","stream_id":1})";
    auto env_stop = protocol::parse_envelope(stop_raw);
    ASSERT_TRUE(env_stop.has_value());
    auto mic_stop = protocol::parse_mic_stop(env_stop->body);
    ASSERT_TRUE(mic_stop.has_value());
    EXPECT_EQ(mic_stop->stream_id, 1u);

    protocol::MicStateEvent evt{1, "running", ""};
    auto evt_json = protocol::to_json(evt);
    EXPECT_EQ(evt_json["stream_id"], 1);
    EXPECT_EQ(evt_json["state"], "running");
}

} // namespace
} // namespace ar
