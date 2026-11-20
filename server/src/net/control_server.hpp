// SPDX-License-Identifier: MIT
#pragma once

#include "common/error.hpp"
#include "net/tls.hpp"

#include <asio.hpp>
#include <cstdint>
#include <functional>
#include <memory>

namespace ar {

// Asynchronous TLS acceptor. Hands each successfully handshaken connection to
// the daemon, which dispatches on ALPN and pins the peer SPKI.
class ControlServer {
  public:
    using Handler = std::function<void(TlsConnection::Ptr)>;

    ControlServer(asio::io_context& io, std::shared_ptr<asio::ssl::context> context,
                  std::uint16_t port, Handler handler);
    ~ControlServer();

    ControlServer(const ControlServer&) = delete;
    ControlServer& operator=(const ControlServer&) = delete;

    [[nodiscard]] Result<void> start();
    void stop();

    [[nodiscard]] std::uint16_t port() const {
        return port_;
    }

  private:
    void do_accept();

    asio::io_context& io_;
    std::shared_ptr<asio::ssl::context> context_;
    Tcp::acceptor acceptor_;
    std::uint16_t port_;
    Handler handler_;
    bool running_{false};
};

} // namespace ar
