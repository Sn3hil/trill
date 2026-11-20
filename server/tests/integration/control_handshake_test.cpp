// SPDX-License-Identifier: MIT
#include "net/control_server.hpp"
#include "net/framing.hpp"
#include "net/tls.hpp"
#include "store/identity.hpp"

#include <asio.hpp>
#include <filesystem>
#include <future>
#include <gtest/gtest.h>
#include <thread>

namespace ar {
namespace {

class ControlHandshakeTest : public ::testing::Test {
  protected:
    void SetUp() override {
        test_dir_ = std::filesystem::temp_directory_path() / "ar_control_test";
        std::error_code ec;
        std::filesystem::remove_all(test_dir_, ec);
        std::filesystem::create_directories(test_dir_, ec);

        auto host_id = HostIdentity::load_or_create(test_dir_ / "host_id", "TrillHost");
        ASSERT_TRUE(host_id.has_value());
        host_identity_ = std::make_unique<HostIdentity>(std::move(*host_id));

        auto client_id = HostIdentity::load_or_create(test_dir_ / "client_id", "TrillClient");
        ASSERT_TRUE(client_id.has_value());
        client_identity_ = std::make_unique<HostIdentity>(std::move(*client_id));

        auto s_cert = host_identity_->cert_pem();
        auto s_key = host_identity_->key_pem();
        ASSERT_TRUE(s_cert.has_value() && s_key.has_value());
        auto s_ctx = make_server_tls_context(*s_cert, *s_key);
        ASSERT_TRUE(s_ctx.has_value());
        server_ctx_ = *s_ctx;

        auto c_cert = client_identity_->cert_pem();
        auto c_key = client_identity_->key_pem();
        ASSERT_TRUE(c_cert.has_value() && c_key.has_value());
        auto c_ctx = make_client_tls_context(*c_cert, *c_key);
        ASSERT_TRUE(c_ctx.has_value());
        client_ctx_ = *c_ctx;
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(test_dir_, ec);
    }

    std::filesystem::path test_dir_;
    std::unique_ptr<HostIdentity> host_identity_;
    std::unique_ptr<HostIdentity> client_identity_;
    std::shared_ptr<asio::ssl::context> server_ctx_;
    std::shared_ptr<asio::ssl::context> client_ctx_;
};

TEST_F(ControlHandshakeTest, HandshakeAlpnAndSpki) {
    asio::io_context io;
    std::promise<TlsConnection::Ptr> server_conn_promise;
    auto server_conn_future = server_conn_promise.get_future();

    ControlServer server(io, server_ctx_, 0, [&](TlsConnection::Ptr conn) {
        server_conn_promise.set_value(std::move(conn));
    });
    ASSERT_TRUE(server.start().has_value());
    const std::uint16_t port = server.port();

    // Client connects
    Tcp::socket client_sock(io);
    client_sock.connect(Tcp::endpoint(asio::ip::make_address("127.0.0.1"), port));

    auto client_conn = std::make_shared<TlsConnection>(std::move(client_sock), client_ctx_,
                                                       /*is_server=*/false, "tr-ctrl/1");

    std::promise<Result<void>> client_hs_promise;
    auto client_hs_future = client_hs_promise.get_future();
    client_conn->async_handshake([&](Result<void> res) { client_hs_promise.set_value(res); });

    std::thread io_thread([&io] { io.run(); });

    ASSERT_EQ(client_hs_future.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    auto client_hs_res = client_hs_future.get();
    ASSERT_TRUE(client_hs_res.has_value()) << client_hs_res.error().message;

    ASSERT_EQ(server_conn_future.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    auto server_conn = server_conn_future.get();
    ASSERT_NE(server_conn, nullptr);

    // Verify ALPN
    EXPECT_EQ(client_conn->alpn(), "tr-ctrl/1");
    EXPECT_EQ(server_conn->alpn(), "tr-ctrl/1");

    // Verify SPKI pinning
    auto server_saw_spki = server_conn->peer_spki_hex();
    ASSERT_TRUE(server_saw_spki.has_value());
    EXPECT_EQ(*server_saw_spki, client_identity_->spki_hex());

    auto client_saw_spki = client_conn->peer_spki_hex();
    ASSERT_TRUE(client_saw_spki.has_value());
    EXPECT_EQ(*client_saw_spki, host_identity_->spki_hex());

    // Message exchange: client sends, server reads and echoes back
    std::promise<std::string> server_recv_promise;
    auto server_recv_future = server_recv_promise.get_future();
    server_conn->async_read_frame([&](Result<std::string> msg) {
        if (msg) {
            server_recv_promise.set_value(*msg);
            server_conn->async_write(R"({"type":"pong"})", {});
        }
    });

    client_conn->async_write(R"({"type":"ping"})", {});

    std::promise<std::string> client_recv_promise;
    auto client_recv_future = client_recv_promise.get_future();
    client_conn->async_read_frame([&](Result<std::string> msg) {
        if (msg) {
            client_recv_promise.set_value(*msg);
        }
    });

    ASSERT_EQ(server_recv_future.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    EXPECT_EQ(server_recv_future.get(), R"({"type":"ping"})");

    ASSERT_EQ(client_recv_future.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    EXPECT_EQ(client_recv_future.get(), R"({"type":"pong"})");

    client_conn->close();
    server_conn->close();
    server.stop();
    io.stop();
    io_thread.join();
}

} // namespace
} // namespace ar
