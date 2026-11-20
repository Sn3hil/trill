// SPDX-License-Identifier: MIT
#include "cli/ipc_client.hpp"
#include "ipc/ipc_server.hpp"

#include <asio.hpp>
#include <filesystem>
#include <gtest/gtest.h>
#include <thread>

namespace ar {
namespace {

class IpcRoundtripTest : public ::testing::Test {
  protected:
    void SetUp() override {
        test_dir_ = std::filesystem::temp_directory_path() / "ar_ipc_test";
        std::error_code ec;
        std::filesystem::remove_all(test_dir_, ec);
        std::filesystem::create_directories(test_dir_, ec);
        socket_path_ = test_dir_ / "ipc.sock";

        server_ = std::make_unique<IpcServer>(io_, socket_path_);
        server_->set_handler([](const ipc::Request& req) -> Result<nlohmann::json> {
            if (req.cmd == "ping") {
                return nlohmann::json{{"reply", "pong"}};
            }
            if (req.cmd == "fail_me") {
                return fail(ErrorCode::bad_request, "intentional failure");
            }
            return fail(ErrorCode::not_found, "unknown command");
        });

        ASSERT_TRUE(server_->start().has_value());
        io_thread_ = std::thread([this] { io_.run(); });
    }

    void TearDown() override {
        server_->stop();
        io_.stop();
        if (io_thread_.joinable()) {
            io_thread_.join();
        }
        std::error_code ec;
        std::filesystem::remove_all(test_dir_, ec);
    }

    asio::io_context io_;
    std::filesystem::path test_dir_;
    std::filesystem::path socket_path_;
    std::unique_ptr<IpcServer> server_;
    std::thread io_thread_;
};

TEST_F(IpcRoundtripTest, CallSuccessAndFailure) {
    auto client = IpcClient::connect(socket_path_);
    ASSERT_TRUE(client.has_value());

    // Success call
    auto res_ping = (*client)->call("ping", {});
    ASSERT_TRUE(res_ping.has_value());
    EXPECT_EQ((*res_ping)["reply"], "pong");

    // Failure call
    auto res_fail = (*client)->call("fail_me", {});
    EXPECT_FALSE(res_fail.has_value());
    EXPECT_EQ(res_fail.error().code, ErrorCode::bad_request);
    EXPECT_EQ(res_fail.error().message, "intentional failure");
}

TEST_F(IpcRoundtripTest, BroadcastAndReadMessage) {
    auto client = IpcClient::connect(socket_path_);
    ASSERT_TRUE(client.has_value());

    for (int i = 0; i < 50 && server_->connection_count() == 0; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_GT(server_->connection_count(), 0u);

    // Broadcast an event from server
    server_->broadcast("test.notice", {{"hello", "world"}});

    auto msg = (*client)->read_message();
    ASSERT_TRUE(msg.has_value());
    EXPECT_EQ((*msg)["event"], "test.notice");
    EXPECT_EQ((*msg)["hello"], "world");
}

} // namespace
} // namespace ar
