// SPDX-License-Identifier: MIT
#include "net/tls.hpp"

#include "common/log.hpp"
#include "crypto/spki.hpp"
#include "net/framing.hpp"

#include <algorithm>
#include <cstring>
#include <openssl/ssl.h>
#include <openssl/x509.h>

namespace ar {
namespace {

constexpr auto kHandshakeTimeout = std::chrono::seconds(5);

int alpn_select_cb(SSL* /*ssl*/, const unsigned char** out, unsigned char* outlen,
                   const unsigned char* in, unsigned int inlen, void* /*arg*/) {
    static constexpr std::string_view kSupported[] = {"tr-ctrl/1", "tr-pair/1"};
    for (const auto wanted : kSupported) {
        unsigned int offset = 0;
        while (offset + 1 <= inlen) {
            const unsigned int len = in[offset];
            if (offset + 1 + len > inlen)
                break;
            if (len == wanted.size() && std::memcmp(in + offset + 1, wanted.data(), len) == 0) {
                *out = in + offset + 1;
                *outlen = static_cast<unsigned char>(len);
                return SSL_TLSEXT_ERR_OK;
            }
            offset += 1 + len;
        }
    }
    std::string offered;
    unsigned int offset = 0;
    while (offset + 1 <= inlen) {
        const unsigned int len = in[offset];
        if (offset + 1 + len > inlen)
            break;
        if (!offered.empty())
            offered += ", ";
        offered += std::string_view(reinterpret_cast<const char*>(in + offset + 1), len);
        offset += 1 + len;
    }
    logger()->warn("TLS ALPN mismatch: client offered [{}] (expected tr-ctrl/1 or tr-pair/1)",
                   offered);
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

int verify_accept_all(int /*preverify_ok*/, X509_STORE_CTX* /*ctx*/) {
    // Pin by SPKI after the handshake. Never validate chains or expiry.
    return 1;
}

Result<std::shared_ptr<asio::ssl::context>> make_context(bool server, std::string_view cert_pem,
                                                         std::string_view key_pem) {
    auto ctx = std::make_shared<asio::ssl::context>(server ? asio::ssl::context::tls_server
                                                           : asio::ssl::context::tls_client);
    ctx->set_options(asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2 |
                     asio::ssl::context::no_sslv3 | asio::ssl::context::no_tlsv1 |
                     asio::ssl::context::no_tlsv1_1 | asio::ssl::context::no_tlsv1_2);

    if (SSL_CTX_set_min_proto_version(ctx->native_handle(), TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(ctx->native_handle(), TLS1_3_VERSION) != 1) {
        return fail(ErrorCode::crypto_error, "cannot restrict TLS to 1.3");
    }

    std::error_code ec;
    ctx->use_certificate_chain(asio::buffer(cert_pem.data(), cert_pem.size()), ec);
    if (ec)
        return fail(ErrorCode::crypto_error, "cannot load certificate: " + ec.message());
    ctx->use_private_key(asio::buffer(key_pem.data(), key_pem.size()), asio::ssl::context::pem, ec);
    if (ec)
        return fail(ErrorCode::crypto_error, "cannot load private key: " + ec.message());

    SSL_CTX_set_verify(ctx->native_handle(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       verify_accept_all);
    if (server) {
        SSL_CTX_set_alpn_select_cb(ctx->native_handle(), alpn_select_cb, nullptr);
    }
    return ctx;
}

} // namespace

Result<std::shared_ptr<asio::ssl::context>> make_server_tls_context(std::string_view cert_pem,
                                                                    std::string_view key_pem) {
    return make_context(true, cert_pem, key_pem);
}

Result<std::shared_ptr<asio::ssl::context>> make_client_tls_context(std::string_view cert_pem,
                                                                    std::string_view key_pem) {
    return make_context(false, cert_pem, key_pem);
}

TlsConnection::TlsConnection(Tcp::socket socket, std::shared_ptr<asio::ssl::context> context,
                             bool is_server, std::optional<std::string> client_alpn)
    : stream_(std::move(socket), *context), context_(std::move(context)),
      handshake_timer_(stream_.get_executor()), is_server_(is_server),
      client_alpn_(std::move(client_alpn)) {
    if (client_alpn_) {
        // SSL_set_alpn_protos expects a length-prefixed list.
        std::vector<unsigned char> wire;
        wire.push_back(static_cast<unsigned char>(client_alpn_->size()));
        wire.insert(wire.end(), client_alpn_->begin(), client_alpn_->end());
        SSL_set_alpn_protos(stream_.native_handle(), wire.data(),
                            static_cast<unsigned int>(wire.size()));
    }
}

void TlsConnection::async_handshake(HandshakeHandler handler) {
    auto self = shared_from_this();
    auto shared_handler = std::make_shared<HandshakeHandler>(std::move(handler));
    handshake_timer_.expires_after(kHandshakeTimeout);
    handshake_timer_.async_wait([self, shared_handler](const std::error_code& ec) {
        if (ec == asio::error::operation_aborted)
            return;
        if (!ec) {
            std::error_code ignored;
            self->stream_.lowest_layer().close(ignored);
            self->complete_handshake(fail(ErrorCode::timeout, "TLS handshake timed out"),
                                     *shared_handler);
        }
    });
    stream_.async_handshake(
        is_server_ ? asio::ssl::stream_base::server : asio::ssl::stream_base::client,
        [self, shared_handler](const std::error_code& ec) {
            if (ec) {
                std::string detail = ec.message();
                unsigned long err = ERR_get_error();
                if (err != 0) {
                    char err_buf[256]{};
                    ERR_error_string_n(err, err_buf, sizeof(err_buf));
                    detail += " (OpenSSL: " + std::string(err_buf) + ")";
                }
                self->complete_handshake(
                    fail(ErrorCode::protocol_error, "TLS handshake failed: " + detail),
                    *shared_handler);
                return;
            }
            self->complete_handshake({}, *shared_handler);
        });
}

void TlsConnection::complete_handshake(Result<void> result, HandshakeHandler& handler) {
    if (handshake_finished_)
        return;
    handshake_finished_ = true;
    handshake_timer_.cancel();
    handler(std::move(result));
}

void TlsConnection::async_read_frame(ReadHandler handler) {
    pending_read_ = std::move(handler);
    do_read_header();
}

void TlsConnection::do_read_header() {
    auto self = shared_from_this();
    asio::async_read(
        stream_, asio::buffer(header_), [self](const std::error_code& ec, std::size_t /*n*/) {
            if (ec) {
                self->deliver_read(fail(ErrorCode::io_error, "read header: " + ec.message()));
                return;
            }
            const std::uint32_t len = (static_cast<std::uint32_t>(self->header_[0]) << 24) |
                                      (static_cast<std::uint32_t>(self->header_[1]) << 16) |
                                      (static_cast<std::uint32_t>(self->header_[2]) << 8) |
                                      static_cast<std::uint32_t>(self->header_[3]);
            if (len == 0 || len > kMaxFrameSize) {
                self->deliver_read(fail(ErrorCode::protocol_error, "invalid frame length"));
                return;
            }
            self->do_read_body(len);
        });
}

void TlsConnection::do_read_body(std::uint32_t length) {
    body_.resize(length);
    auto self = shared_from_this();
    asio::async_read(
        stream_, asio::buffer(body_), [self](const std::error_code& ec, std::size_t /*n*/) {
            if (ec) {
                self->deliver_read(fail(ErrorCode::io_error, "read body: " + ec.message()));
                return;
            }
            self->deliver_read(
                std::string(reinterpret_cast<const char*>(self->body_.data()), self->body_.size()));
        });
}

void TlsConnection::deliver_read(Result<std::string> result) {
    if (!pending_read_)
        return;
    auto handler = std::move(pending_read_);
    pending_read_ = nullptr;
    if (!result)
        close();
    handler(std::move(result));
}

void TlsConnection::async_write(std::string payload, WriteHandler handler) {
    write_queue_.emplace_back(std::move(payload), std::move(handler));
    if (!writing_)
        do_write();
}

void TlsConnection::do_write() {
    if (write_queue_.empty() || closed_)
        return;
    writing_ = true;
    auto self = shared_from_this();
    auto frame = encode_frame(write_queue_.front().first);
    if (!frame) {
        auto item = std::move(write_queue_.front());
        write_queue_.pop_front();
        writing_ = false;
        if (item.second)
            item.second(fail(frame.error().code, frame.error().message));
        do_write();
        return;
    }
    write_frame_ = std::move(*frame);
    asio::async_write(stream_, asio::buffer(write_frame_),
                      [self](const std::error_code& ec, std::size_t /*n*/) {
                          if (self->write_queue_.empty()) {
                              self->writing_ = false;
                              return;
                          }
                          auto item = std::move(self->write_queue_.front());
                          self->write_queue_.pop_front();
                          self->writing_ = false;
                          if (item.second) {
                              if (ec) {
                                  item.second(fail(ErrorCode::io_error, "write: " + ec.message()));
                              } else {
                                  item.second({});
                              }
                          }
                          if (ec) {
                              self->close();
                              return;
                          }
                          self->do_write();
                      });
}

void TlsConnection::close() {
    if (closed_)
        return;
    closed_ = true;
    std::error_code ec;
    stream_.lowest_layer().close(ec);
}

bool TlsConnection::open() const {
    return !closed_ && stream_.lowest_layer().is_open();
}

std::string TlsConnection::alpn() {
    const unsigned char* proto = nullptr;
    unsigned int len = 0;
    SSL_get0_alpn_selected(stream_.native_handle(), &proto, &len);
    if (proto == nullptr || len == 0)
        return {};
    return std::string(reinterpret_cast<const char*>(proto), len);
}

std::string TlsConnection::peer_ip() {
    std::error_code ec;
    const auto endpoint = stream_.lowest_layer().remote_endpoint(ec);
    if (ec)
        return {};
    const auto addr = endpoint.address();
    if (addr.is_v6() && addr.to_v6().is_v4_mapped()) {
        return asio::ip::make_address_v4(asio::ip::v4_mapped, addr.to_v6()).to_string();
    }
    return addr.to_string();
}

Result<std::string> TlsConnection::peer_spki_hex() {
    if (peer_spki_ready_)
        return peer_spki_;
    SSL* ssl = const_cast<SSL*>(stream_.native_handle());
    X509* cert = SSL_get1_peer_certificate(ssl);
    if (cert == nullptr) {
        return fail(ErrorCode::not_paired, "peer presented no certificate");
    }
    auto spki = spki_sha256_hex(cert);
    X509_free(cert);
    if (!spki)
        return std::unexpected(spki.error());
    peer_spki_ = *spki;
    peer_spki_ready_ = true;
    return *spki;
}

} // namespace ar
