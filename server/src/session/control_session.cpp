// SPDX-License-Identifier: MIT
#include "session/control_session.hpp"

#include "audio/stream_pipeline.hpp"
#include "common/log.hpp"
#include "protocol/messages.hpp"
#include "session/session_manager.hpp"

#include <chrono>

namespace ar {

ControlSession::ControlSession(TlsConnection::Ptr connection, SessionManager& manager,
                               std::string device_id, std::string device_name, std::string peer_ip)
    : connection_(std::move(connection)), manager_(manager), device_id_(std::move(device_id)),
      device_name_(std::move(device_name)), peer_ip_(std::move(peer_ip)),
      ping_timer_(connection_->stream().get_executor()),
      last_rx_(std::chrono::steady_clock::now()) {}

ControlSession::~ControlSession() = default;

void ControlSession::start() {
    start_keepalive();
    read_next();
}

std::string ControlSession::state_name() const {
    switch (state_) {
    case State::connected:
        return "connected";
    case State::ready:
        return "ready";
    case State::streaming:
        return "streaming";
    case State::closed:
        return "closed";
    }
    return "closed";
}

void ControlSession::read_next() {
    if (closed_)
        return;
    auto self = shared_from_this();
    connection_->async_read_frame([self](Result<std::string> frame) {
        if (self->closed_)
            return;
        if (!frame) {
            self->close("control_lost");
            return;
        }
        self->last_rx_ = std::chrono::steady_clock::now();
        self->handle_frame(*frame);
    });
}

void ControlSession::handle_frame(const std::string& payload) {
    auto envelope = protocol::parse_envelope(payload);
    if (!envelope) {
        protocol_fail(envelope.error().message);
        return;
    }
    if (envelope->is_event || envelope->is_response) {
        protocol_fail("unexpected event or response from phone");
        return;
    }
    if (!envelope->id) {
        protocol_fail("request without id");
        return;
    }
    if (!handle_request(envelope->body, *envelope->id))
        return;
    read_next();
}

bool ControlSession::handle_request(const nlohmann::json& root, std::uint64_t id) {
    const std::string type = root.value("type", "");

    if (state_ == State::connected && type != "session.hello") {
        reply_error(id, ErrorCode::bad_request, "session.hello must be the first message");
        close("protocol_error");
        return false;
    }

    if (type == "session.hello") {
        if (state_ != State::connected) {
            reply_error(id, ErrorCode::bad_request, "duplicate session.hello");
            return true;
        }
        auto hello = protocol::parse_session_hello(root);
        if (!hello) {
            reply_error(id, hello.error().code, hello.error().message);
            close("protocol_error");
            return false;
        }
        device_name_ = hello->name;
        (void)manager_.rename_device(device_id_, hello->name);
        state_ = State::ready;
        reply_ok(id, protocol::to_json(manager_.make_hello_response()));
        logger()->info("control session ready for '{}' ({}) from {}", device_name_,
                       short_id(device_id_), peer_ip_);
        return true;
    }

    if (type == "ping") {
        reply_ok(id, nlohmann::json{{"type", "pong"}});
        return true;
    }

    if (type == "host.status") {
        reply_ok(id, protocol::to_json(manager_.host_status()));
        return true;
    }

    if (type == "device.rename") {
        auto rename = protocol::parse_device_rename(root);
        if (!rename) {
            reply_error(id, rename.error().code, rename.error().message);
            return true;
        }
        if (auto r = manager_.rename_device(device_id_, rename->name); !r) {
            reply_error(id, r.error().code, r.error().message);
            return true;
        }
        device_name_ = rename->name;
        reply_ok(id);
        return true;
    }

    if (type == "stream.start") {
        if (state_ != State::ready) {
            reply_error(id, ErrorCode::busy, "already streaming");
            return true;
        }
        auto start = protocol::parse_stream_start(root);
        if (!start) {
            reply_error(id, start.error().code, start.error().message);
            return true;
        }
        StreamParams params;
        params.peer_ip = peer_ip_;
        params.source_port = start->source_port;
        params.repair_port = start->repair_port;

        auto stream_id = manager_.begin_stream(this, params);
        if (!stream_id) {
            reply_error(id, stream_id.error().code, stream_id.error().message);
            return true;
        }
        state_ = State::streaming;
        reply_ok(id, nlohmann::json{{"stream_id", *stream_id}, {"state", "starting"}});
        send_event("event.stream.state",
                   nlohmann::json{{"stream_id", *stream_id}, {"state", "running"}});
        return true;
    }

    if (type == "stream.stop") {
        auto stop = protocol::parse_stream_stop(root);
        if (!stop) {
            reply_error(id, stop.error().code, stop.error().message);
            return true;
        }
        if (state_ != State::streaming) {
            reply_error(id, ErrorCode::bad_request, "no active stream");
            return true;
        }
        const std::uint32_t stream_id = manager_.active_stream_id();
        manager_.end_stream(this, "phone");
        state_ = State::ready;
        reply_ok(id);
        send_event(
            "event.stream.state",
            nlohmann::json{{"stream_id", stream_id}, {"state", "stopped"}, {"reason", "phone"}});
        return true;
    }

    reply_error(id, ErrorCode::unsupported, "unsupported request type");
    return true;
}

void ControlSession::reply_ok(std::uint64_t id, nlohmann::json fields) {
    if (closed_ || !connection_->open())
        return;
    connection_->async_write(protocol::make_ok_response(id, std::move(fields)));
}

void ControlSession::reply_error(std::uint64_t id, ErrorCode code, const std::string& message) {
    if (closed_ || !connection_->open())
        return;
    connection_->async_write(protocol::make_error_response(
        id, protocol::ErrorInfo{std::string(protocol_code(code)), message}));
}

void ControlSession::send_event(const std::string& type, nlohmann::json fields) {
    if (closed_ || !connection_->open())
        return;
    connection_->async_write(protocol::make_event(type, std::move(fields)));
}

void ControlSession::on_stream_started(std::uint32_t /*stream_id*/) {
    if (closed_)
        return;
    state_ = State::streaming;
}

void ControlSession::on_stream_stopped(std::uint32_t stream_id, const std::string& reason) {
    if (closed_)
        return;
    state_ = State::ready;
    send_event("event.stream.state",
               nlohmann::json{{"stream_id", stream_id}, {"state", "stopped"}, {"reason", reason}});
}

void ControlSession::request_host_started_stream() {
    if (closed_ || state_ != State::ready)
        return;
    send_event("event.stream.requested", nlohmann::json{{"host_name", manager_.host_name()}});
}

void ControlSession::start_keepalive() {
    ping_timer_.expires_after(std::chrono::seconds(2));
    auto self = shared_from_this();
    ping_timer_.async_wait([self](const std::error_code& ec) {
        if (ec == asio::error::operation_aborted || self->closed_)
            return;
        if (!ec)
            self->check_keepalive();
    });
}

void ControlSession::check_keepalive() {
    if (closed_)
        return;
    const auto idle = std::chrono::steady_clock::now() - last_rx_;
    if (idle > std::chrono::seconds(15)) {
        logger()->warn("control session for '{}' timed out", short_id(device_id_));
        close("control_lost");
        return;
    }
    start_keepalive();
}

void ControlSession::protocol_fail(const std::string& message) {
    logger()->warn("control protocol error from {}: {}", short_id(device_id_), message);
    close("protocol_error");
}

void ControlSession::close(const std::string& reason) {
    if (closed_)
        return;
    closed_ = true;
    state_ = State::closed;
    ping_timer_.cancel();
    connection_->close();
    manager_.unregister(this, reason);
}

void ControlSession::shutdown(const std::string& reason) {
    if (closed_)
        return;
    auto self = shared_from_this();
    connection_->async_write(
        protocol::make_event("event.host.shutdown", nlohmann::json{{"reason", reason}}),
        [self, reason](Result<void>) { self->close(reason); });
}

} // namespace ar
