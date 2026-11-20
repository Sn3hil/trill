// SPDX-License-Identifier: MIT
#include "net/control_server.hpp"

#include "common/log.hpp"

namespace ar {

ControlServer::ControlServer(asio::io_context& io, std::shared_ptr<asio::ssl::context> context,
                             std::uint16_t port, Handler handler)
    : io_(io), context_(std::move(context)), acceptor_(io), port_(port),
      handler_(std::move(handler)) {}

ControlServer::~ControlServer() {
    stop();
}

Result<void> ControlServer::start() {
    std::error_code ec;
    // Attempt dual-stack IPv6 (listening on [::], which also accepts IPv4 if v6_only is false).
    acceptor_.open(Tcp::v6(), ec);
    if (!ec) {
        acceptor_.set_option(asio::ip::v6_only(false), ec);
        acceptor_.set_option(Tcp::acceptor::reuse_address(true), ec);
        acceptor_.bind(Tcp::endpoint(Tcp::v6(), port_), ec);
    }
    if (ec) {
        // Fall back to IPv4 if IPv6 is unavailable or failed to bind.
        ec.clear();
        acceptor_.close(ec);
        acceptor_.open(Tcp::v4(), ec);
        if (ec) {
            return fail(ErrorCode::io_error, "cannot open control socket: " + ec.message());
        }
        acceptor_.set_option(Tcp::acceptor::reuse_address(true), ec);
        acceptor_.bind(Tcp::endpoint(Tcp::v4(), port_), ec);
        if (ec) {
            return fail(ErrorCode::io_error,
                        "cannot bind control port " + std::to_string(port_) + ": " + ec.message());
        }
    }
    acceptor_.listen(asio::socket_base::max_listen_connections, ec);
    if (ec) {
        return fail(ErrorCode::io_error, "cannot listen: " + ec.message());
    }
    port_ = acceptor_.local_endpoint(ec).port();
    running_ = true;
    logger()->info("control server listening on port {}", port_);
    do_accept();
    return {};
}

void ControlServer::stop() {
    running_ = false;
    std::error_code ec;
    acceptor_.close(ec);
}

void ControlServer::do_accept() {
    if (!running_)
        return;
    acceptor_.async_accept([this](const std::error_code& ec, Tcp::socket socket) {
        if (!running_)
            return;
        if (ec) {
            if (ec != asio::error::operation_aborted) {
                logger()->warn("accept failed: {}", ec.message());
                do_accept();
            }
            return;
        }

        std::error_code opt_ec;
        socket.set_option(Tcp::no_delay(true), opt_ec);

        auto connection =
            std::make_shared<TlsConnection>(std::move(socket), context_, true, std::nullopt);
        connection->async_handshake([this, connection](Result<void> result) {
            if (!result) {
                logger()->warn("TLS handshake rejected: {}", result.error().message);
                connection->close();
                return;
            }
            // ALPN is mandatory. No ALPN means a non-conforming client.
            if (connection->alpn().empty()) {
                logger()->warn("connection without ALPN from {}", connection->peer_ip());
                connection->close();
                return;
            }
            handler_(connection);
        });
        do_accept();
    });
}

} // namespace ar
