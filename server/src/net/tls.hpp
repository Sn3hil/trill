// SPDX-License-Identifier: MIT
#pragma once

#include "common/error.hpp"

#include <asio.hpp>
#include <asio/ssl.hpp>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ar {

using Tcp = asio::ip::tcp;

// TLS 1.3 only, mutual authentication, ALPN tr-pair/1 or tr-ctrl/1.
// Peer certificates are accepted unconditionally at the TLS layer and pinned
// later by SPKI hash; see PROTOCOL section 5/6/7.
[[nodiscard]] Result<std::shared_ptr<asio::ssl::context>>
make_server_tls_context(std::string_view cert_pem, std::string_view key_pem);
[[nodiscard]] Result<std::shared_ptr<asio::ssl::context>>
make_client_tls_context(std::string_view cert_pem, std::string_view key_pem);

class TlsConnection : public std::enable_shared_from_this<TlsConnection> {
  public:
    using Ptr = std::shared_ptr<TlsConnection>;
    using ReadHandler = std::function<void(Result<std::string>)>;
    using WriteHandler = std::function<void(Result<void>)>;
    using HandshakeHandler = std::function<void(Result<void>)>;

    TlsConnection(Tcp::socket socket, std::shared_ptr<asio::ssl::context> context,
                  bool is_server = true, std::optional<std::string> client_alpn = std::nullopt);

    void async_handshake(HandshakeHandler handler);
    void async_read_frame(ReadHandler handler);
    void async_write(std::string payload, WriteHandler handler = {});

    void close();
    [[nodiscard]] bool open() const;

    [[nodiscard]] std::string alpn();
    [[nodiscard]] std::string peer_ip();
    [[nodiscard]] Result<std::string> peer_spki_hex();
    [[nodiscard]] asio::ssl::stream<Tcp::socket>& stream() {
        return stream_;
    }

  private:
    void do_read_header();
    void do_read_body(std::uint32_t length);
    void deliver_read(Result<std::string> result);
    void complete_handshake(Result<void> result, HandshakeHandler& handler);
    void do_write();

    asio::ssl::stream<Tcp::socket> stream_;
    std::shared_ptr<asio::ssl::context> context_;
    asio::steady_timer handshake_timer_;
    bool is_server_{true};
    bool handshake_finished_{false};
    std::array<std::uint8_t, 4> header_{};
    std::vector<std::uint8_t> body_;
    std::vector<std::uint8_t> write_frame_;
    std::optional<std::string> client_alpn_;
    std::deque<std::pair<std::string, WriteHandler>> write_queue_;
    ReadHandler pending_read_;
    bool writing_{false};
    bool closed_{false};
    std::string peer_spki_;
    bool peer_spki_ready_{false};
};

} // namespace ar
