// SPDX-License-Identifier: MIT
#pragma once

#include "common/clock.hpp"
#include "common/error.hpp"
#include "net/tls.hpp"
#include "store/config.hpp"

#include <memory>
#include <nlohmann/json.hpp>
#include <string>

namespace ar {

class SessionManager;

// One control connection (ALPN tr-ctrl/1): CONNECTED -> READY -> STREAMING.
// All callbacks run on the asio io_context thread.
class ControlSession : public std::enable_shared_from_this<ControlSession> {
  public:
    enum class State { connected, ready, streaming, closed };

    ControlSession(TlsConnection::Ptr connection, SessionManager& manager, std::string device_id,
                   std::string device_name, std::string peer_ip);
    ~ControlSession();

    ControlSession(const ControlSession&) = delete;
    ControlSession& operator=(const ControlSession&) = delete;

    void start();
    void close(const std::string& reason);
    void shutdown(const std::string& reason);

    [[nodiscard]] const std::string& device_id() const {
        return device_id_;
    }
    [[nodiscard]] const std::string& device_name() const {
        return device_name_;
    }
    [[nodiscard]] const std::string& peer_ip() const {
        return peer_ip_;
    }
    [[nodiscard]] State state() const {
        return state_;
    }
    [[nodiscard]] bool streaming() const {
        return state_ == State::streaming;
    }
    [[nodiscard]] bool mic_streaming() const {
        return mic_streaming_;
    }

    void set_device_name(std::string name) {
        device_name_ = std::move(name);
    }
    void on_stream_started(std::uint32_t stream_id);
    void on_stream_stopped(std::uint32_t stream_id, const std::string& reason);
    void on_mic_stopped(std::uint32_t stream_id, const std::string& reason);
    void request_host_started_stream();

    [[nodiscard]] std::string state_name() const;
    [[nodiscard]] bool open() const {
        return !closed_;
    }

  private:
    void read_next();
    void handle_frame(const std::string& payload);
    bool handle_request(const nlohmann::json& root, std::uint64_t id);
    void reply_ok(std::uint64_t id, nlohmann::json fields = {});
    void reply_error(std::uint64_t id, ErrorCode code, const std::string& message);
    void send_event(const std::string& type, nlohmann::json fields);
    void start_keepalive();
    void check_keepalive();
    void protocol_fail(const std::string& message);

    TlsConnection::Ptr connection_;
    SessionManager& manager_;
    std::string device_id_;
    std::string device_name_;
    std::string peer_ip_;
    State state_{State::connected};
    bool closed_{false};
    bool mic_streaming_{false};
    std::uint32_t active_mic_stream_id_{0};
    asio::steady_timer ping_timer_;
    TimePoint last_rx_;
};

} // namespace ar
