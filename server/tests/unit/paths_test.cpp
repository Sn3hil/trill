// SPDX-License-Identifier: MIT
#include "common/paths.hpp"

#include <cstdlib>
#include <filesystem>
#include <gtest/gtest.h>

namespace ar {
namespace {

class PathsTest : public ::testing::Test {
  protected:
    void SetUp() override {
        test_dir_ = std::filesystem::temp_directory_path() / "ar_paths_test";
        std::error_code ec;
        std::filesystem::remove_all(test_dir_, ec);
        std::filesystem::create_directories(test_dir_, ec);

        config_dir_ = test_dir_ / "config";
        state_dir_ = test_dir_ / "state";
        runtime_dir_ = test_dir_ / "runtime";

        ::setenv("XDG_CONFIG_HOME", config_dir_.c_str(), 1);
        ::setenv("XDG_STATE_HOME", state_dir_.c_str(), 1);
        ::setenv("XDG_RUNTIME_DIR", runtime_dir_.c_str(), 1);
    }

    void TearDown() override {
        ::unsetenv("XDG_CONFIG_HOME");
        ::unsetenv("XDG_STATE_HOME");
        ::unsetenv("XDG_RUNTIME_DIR");
        std::error_code ec;
        std::filesystem::remove_all(test_dir_, ec);
    }

    std::filesystem::path test_dir_;
    std::filesystem::path config_dir_;
    std::filesystem::path state_dir_;
    std::filesystem::path runtime_dir_;
};

TEST_F(PathsTest, ResolveXdgPaths) {
    auto paths = resolve_paths();
    ASSERT_TRUE(paths.has_value());
    EXPECT_EQ(paths->config_dir, config_dir_ / "trill");
    EXPECT_EQ(paths->state_dir, state_dir_ / "trill");
    EXPECT_EQ(paths->runtime_dir, runtime_dir_ / "trill");
    EXPECT_EQ(paths->socket_path, runtime_dir_ / "trill" / "ctl.sock");
    EXPECT_EQ(paths->config_file, config_dir_ / "trill" / "config.toml");
    EXPECT_EQ(paths->devices_file, config_dir_ / "trill" / "devices.json");
}

TEST_F(PathsTest, EnsureDirAndAtomicWrite) {
    auto sub = test_dir_ / "a" / "b" / "c";
    auto res_dir = ensure_dir(sub, 0700);
    ASSERT_TRUE(res_dir.has_value());
    EXPECT_TRUE(std::filesystem::is_directory(sub));

    auto target_file = sub / "test.txt";
    const std::string content = "Atomic test content 123";
    auto res_write = write_file_atomic(target_file, content, 0600);
    ASSERT_TRUE(res_write.has_value());

    auto read_back = read_file(target_file);
    ASSERT_TRUE(read_back.has_value());
    EXPECT_EQ(*read_back, content);

    auto res_del = remove_file(target_file);
    ASSERT_TRUE(res_del.has_value());
    EXPECT_FALSE(std::filesystem::exists(target_file));
}

TEST_F(PathsTest, UtcNowIso8601) {
    auto ts = utc_now_iso8601();
    EXPECT_FALSE(ts.empty());
    EXPECT_EQ(ts.back(), 'Z');
    EXPECT_NE(ts.find('T'), std::string::npos);
}

} // namespace
} // namespace ar
