// SPDX-License-Identifier: MIT
#pragma once

#include "common/clock.hpp"
#include "common/error.hpp"
#include "protocol/messages.hpp"
#include "store/config.hpp"
#include "store/device_store.hpp"

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace ar {

class ControlSession;
class TlsConnection;
struct StreamParams;

struct SessionStatus {
    std::string device_id;
    std::string name;
    std::string peer_ip;
    std::string state;
    bool streaming{false};
    std::uint32_t stream_id{0};
};

// Owns active control sessions, enforces one stream per host, and drives the
// audio pipeline hooks supplied by the daemon.
class SessionManager {
  public:
    using EventCallback =
        std::function<void(const std::string& type, const nlohmann::json& fields)>;

    struct Hooks {
        std::function<Result<void>(const StreamParams&, const std::string& device_id)> start_stream;
        std::function<void(std::uint32_t, const std::string& reason)> stop_stream;
        std::function<bool()> sink_available;
    };

    SessionManager(DeviceStore& devices, Config config, std::string host_name,
                   std::string host_version, EventCallback event_callback);
    ~SessionManager();

    SessionManager(const SessionManager&) = delete;
    SessionManager& operator=(const SessionManager&) = delete;

    void set_hooks(Hooks hooks);

    // Attach a successfully handshaken TLS connection.
    [[nodiscard]] Result<std::shared_ptr<ControlSession>>
    attach(const std::shared_ptr<TlsConnection>& connection, const std::string& peer_spki,
           const std::string& peer_ip);

    // Called by a session when its transport is gone.
    void unregister(ControlSession* session, const std::string& reason);

    [[nodiscard]] Result<std::uint32_t> begin_stream(ControlSession* session,
                                                     const StreamParams& params);
    void end_stream(ControlSession* session, const std::string& reason);

    [[nodiscard]] protocol::SessionHelloResponse make_hello_response() const;
    [[nodiscard]] protocol::HostStatus host_status() const;
    [[nodiscard]] std::vector<SessionStatus> sessions() const;

    [[nodiscard]] bool streaming() const {
        return streaming_session_ != nullptr;
    }
    [[nodiscard]] std::uint32_t active_stream_id() const {
        return active_stream_id_;
    }
    [[nodiscard]] const std::string& host_name() const {
        return host_name_;
    }

    // Used by the CLI `start` command (M4). Returns phone_not_connected when the
    // device has no live session.
    [[nodiscard]] Result<void> request_start(const std::string& device_id);
    [[nodiscard]] Result<void> rename_device(const std::string& device_id, const std::string& name);
    [[nodiscard]] Result<void> stop_device(const std::string& device_id, const std::string& reason);
    // Ends any stream and closes the control session for an unpair.
    [[nodiscard]] Result<void> drop_device(const std::string& device_id, const std::string& reason);

    void stop_all(const std::string& reason);
    void send_shutdown_events();
    void close_all(const std::string& reason);

    [[nodiscard]] const Config& config() const {
        return config_;
    }

  private:
    DeviceStore& devices_;
    Config config_;
    std::string host_name_;
    std::string host_version_;
    EventCallback event_callback_;
    Hooks hooks_;

    std::map<std::string, std::shared_ptr<ControlSession>> sessions_;
    std::shared_ptr<ControlSession> streaming_session_;
    std::uint32_t active_stream_id_{0};
    std::uint32_t next_stream_id_{1};
};

} // namespace ar
