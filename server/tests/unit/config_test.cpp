// SPDX-License-Identifier: MIT
#include "store/config.hpp"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>

namespace ar {
namespace {

class ConfigTest : public ::testing::Test {
  protected:
    void SetUp() override {
        test_dir_ = std::filesystem::temp_directory_path() / "ar_config_test";
        std::error_code ec;
        std::filesystem::remove_all(test_dir_, ec);
        std::filesystem::create_directories(test_dir_, ec);
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(test_dir_, ec);
    }

    std::filesystem::path test_dir_;
};

TEST_F(ConfigTest, DefaultsAreValid) {
    auto cfg = Config::defaults();
    EXPECT_TRUE(cfg.validate().has_value());
    EXPECT_EQ(cfg.daemon.control_port, 47800);
    EXPECT_EQ(cfg.pairing.window_seconds, 30);
    EXPECT_EQ(cfg.pairing.max_attempts, 3);
    EXPECT_EQ(cfg.audio.sink_name, "trill");
    EXPECT_EQ(cfg.audio.sink_lifetime, "session");
    EXPECT_TRUE(cfg.audio.auto_default_sink);
    EXPECT_EQ(cfg.stream.packet_ms, 5);
    EXPECT_EQ(cfg.stream.fec_block_source, 18);
    EXPECT_EQ(cfg.stream.fec_block_repair, 10);
}

TEST_F(ConfigTest, LoadMissingReturnsDefaults) {
    auto path = test_dir_ / "nonexistent.toml";
    auto cfg = Config::load(path);
    ASSERT_TRUE(cfg.has_value());
    EXPECT_EQ(cfg->daemon.control_port, 47800);
}

TEST_F(ConfigTest, LoadValidToml) {
    auto path = test_dir_ / "config.toml";
    {
        std::ofstream out(path);
        out << R"(
[daemon]
control_port = 50000

[pairing]
window_seconds = 60
max_attempts = 5

[audio]
sink_name = "my-sink"
sink_lifetime = "daemon"
auto_default_sink = false

[stream]
packet_ms = 10
silence_policy = "suspend"

[log]
level = "debug"
)";
    }

    auto cfg = Config::load(path);
    ASSERT_TRUE(cfg.has_value());
    EXPECT_EQ(cfg->daemon.control_port, 50000);
    EXPECT_EQ(cfg->pairing.window_seconds, 60);
    EXPECT_EQ(cfg->pairing.max_attempts, 5);
    EXPECT_EQ(cfg->audio.sink_name, "my-sink");
    EXPECT_EQ(cfg->audio.sink_lifetime, "daemon");
    EXPECT_FALSE(cfg->audio.auto_default_sink);
    EXPECT_EQ(cfg->stream.packet_ms, 10);
    EXPECT_EQ(cfg->stream.silence_policy, "suspend");
    EXPECT_EQ(cfg->log.level, "debug");
}

TEST_F(ConfigTest, RejectInvalidValues) {
    auto cfg = Config::defaults();

    cfg.daemon.control_port = 0;
    EXPECT_FALSE(cfg.validate().has_value());
    cfg = Config::defaults();

    cfg.pairing.window_seconds = 0;
    EXPECT_FALSE(cfg.validate().has_value());
    cfg = Config::defaults();

    cfg.pairing.max_attempts = 0;
    EXPECT_FALSE(cfg.validate().has_value());
    cfg = Config::defaults();

    cfg.audio.sink_lifetime = "invalid";
    EXPECT_FALSE(cfg.validate().has_value());
    cfg = Config::defaults();

    cfg.stream.silence_policy = "unknown";
    EXPECT_FALSE(cfg.validate().has_value());
}

} // namespace
} // namespace ar
