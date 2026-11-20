// SPDX-License-Identifier: MIT
#include "daemon/pairing_session.hpp"

#include "common/log.hpp"
#include "protocol/messages.hpp"

#include <utility>

namespace ar {

PairingSession::PairingSession(TlsConnection::Ptr connection, PairingManager& pairing,
                               std::string host_id, std::string peer_ip)
    : connection_(std::move(connection)), pairing_(pairing), host_id_(std::move(host_id)),
      peer_ip_(std::move(peer_ip)) {}

PairingSession::~PairingSession() = default;

void PairingSession::start() {
    if (connection_ == nullptr || !connection_->open())
        return;
    auto spki = connection_->peer_spki_hex();
    if (!spki) {
        logger()->warn("pairing connection from {} has no certificate", peer_ip_);
        connection_->close();
        return;
    }
    peer_spki_ = *spki;
    read_next();
}

void PairingSession::read_next() {
    if (closed_)
        return;
    auto self = shared_from_this();
    connection_->async_read_frame([self](Result<std::string> frame) {
        if (self->closed_)
            return;
        if (!frame) {
            self->closed_ = true;
            self->pairing_.cancel_pending();
            return;
        }
        self->handle_frame(*frame);
    });
}

void PairingSession::handle_frame(const std::string& payload) {
    auto envelope = protocol::parse_envelope(payload);
    if (!envelope) {
        fail(envelope.error());
        return;
    }
    if (envelope->is_event || envelope->is_response || !envelope->id) {
        fail(Error{ErrorCode::bad_request, "expected a pairing request"});
        return;
    }
    const std::uint64_t id = *envelope->id;
    const std::string type = envelope->body.value("type", std::string());

    if (type == "pair.start") {
        if (started_) {
            reply_error(id, Error{ErrorCode::bad_request, "duplicate pair.start"});
            return;
        }
        auto request = protocol::parse_pair_start(envelope->body);
        if (!request) {
            reply_error(id, request.error());
            return;
        }
        auto response = pairing_.begin_pair(*request, peer_spki_);
        if (!response) {
            logger()->warn("pairing start from {} rejected: {}", peer_ip_,
                           response.error().message);
            reply_error(id, response.error());
            return;
        }
        started_ = true;
        // Dev pairing completes in begin_pair; reply once and close.
        if (response->share_b64.empty() && response->confirm_b64.empty()) {
            confirmed_ = true;
            reply_ok(
                id, protocol::to_json(protocol::PairConfirmResponse{host_id_, response->host_name}),
                true);
            return;
        }
        reply_ok(id, protocol::to_json(*response), false);
        read_next();
        return;
    }

    if (type == "pair.confirm") {
        if (!started_ || confirmed_) {
            reply_error(id, Error{ErrorCode::bad_request, "unexpected pair.confirm"});
            return;
        }
        auto request = protocol::parse_pair_confirm(envelope->body);
        if (!request) {
            reply_error(id, request.error());
            return;
        }
        auto result = pairing_.finish_pair(request->confirm_b64, peer_ip_);
        if (!result) {
            logger()->warn("pairing confirmation from {} rejected: {}", peer_ip_,
                           result.error().message);
            reply_error(id, result.error());
            return;
        }
        confirmed_ = true;
        reply_ok(id,
                 protocol::to_json(protocol::PairConfirmResponse{host_id_, pairing_.host_name()}),
                 true);
        return;
    }

    reply_error(id, Error{ErrorCode::unsupported, "unsupported pairing request"});
}

void PairingSession::reply_ok(std::uint64_t id, nlohmann::json fields, bool close_after) {
    if (closed_)
        return;
    auto self = shared_from_this();
    connection_->async_write(protocol::make_ok_response(id, std::move(fields)),
                             [self, close_after](Result<void> result) {
                                 if (!result) {
                                     self->closed_ = true;
                                     return;
                                 }
                                 if (close_after)
                                     self->close();
                             });
}

void PairingSession::reply_error(std::uint64_t id, const Error& error) {
    if (closed_)
        return;
    pairing_.cancel_pending();
    logger()->info("pairing connection from {} closed: {}", peer_ip_, error.message);
    auto self = shared_from_this();
    connection_->async_write(
        protocol::make_error_response(
            id, protocol::ErrorInfo{std::string(protocol_code(error.code)), error.message}),
        [self](Result<void>) { self->close(); });
}

void PairingSession::fail(const Error& error) {
    if (closed_)
        return;
    pairing_.cancel_pending();
    // Every failure closes the connection; the caller may retry from scratch.
    logger()->info("pairing connection from {} closed: {}", peer_ip_, error.message);
    close();
}

void PairingSession::close() {
    if (closed_) {
        if (connection_)
            connection_->close();
        return;
    }
    closed_ = true;
    if (pairing_.has_pending())
        pairing_.cancel_pending();
    if (connection_)
        connection_->close();
}

} // namespace ar
