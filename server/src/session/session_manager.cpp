// SPDX-License-Identifier: MIT
#include "session/session_manager.hpp"

#include "audio/stream_pipeline.hpp"
#include "common/log.hpp"
#include "session/control_session.hpp"

#include <algorithm>

namespace ar {

SessionManager::SessionManager(DeviceStore& devices, Config config, std::string host_name,
                               std::string host_version, EventCallback event_callback)
    : devices_(devices), config_(std::move(config)), host_name_(std::move(host_name)),
      host_version_(std::move(host_version)), event_callback_(std::move(event_callback)) {}

SessionManager::~SessionManager() = default;

void SessionManager::set_hooks(Hooks hooks) {
    hooks_ = std::move(hooks);
}

Result<std::shared_ptr<ControlSession>>
SessionManager::attach(const std::shared_ptr<TlsConnection>& connection,
                       const std::string& peer_spki, const std::string& peer_ip) {
    if (peer_spki.size() != 64) {
        return fail(ErrorCode::not_paired, "invalid peer certificate");
    }
    const Device* device = devices_.find_by_id(peer_spki);
    if (device == nullptr) {
        return fail(ErrorCode::not_paired, "peer certificate is not paired");
    }

    if (const auto it = sessions_.find(peer_spki); it != sessions_.end()) {
        auto old = it->second;
        if (streaming_session_ && streaming_session_.get() == old.get()) {
            end_stream(old.get(), "control_lost");
        }
        if (mic_session_ && mic_session_.get() == old.get()) {
            end_mic(old.get(), "control_lost");
        }
        sessions_.erase(it);
        old->close("replaced");
        logger()->info("replaced control session for '{}'", short_id(peer_spki));
    }

    (void)devices_.touch(peer_spki, peer_ip);

    auto session =
        std::make_shared<ControlSession>(connection, *this, peer_spki, device->name, peer_ip);
    sessions_[peer_spki] = session;
    session->start();

    if (event_callback_) {
        event_callback_(
            "session.state",
            nlohmann::json{{"device_id", peer_spki}, {"name", device->name}, {"state", "online"}});
    }
    return session;
}

void SessionManager::unregister(ControlSession* session, const std::string& reason) {
    const auto it = sessions_.find(session->device_id());
    if (it == sessions_.end() || it->second.get() != session)
        return;

    if (streaming_session_ && streaming_session_.get() == session) {
        end_stream(session, "control_lost");
    }
    if (mic_session_ && mic_session_.get() == session) {
        end_mic(session, "control_lost");
    }
    sessions_.erase(it);
    if (event_callback_) {
        event_callback_("session.state", nlohmann::json{{"device_id", session->device_id()},
                                                        {"name", session->device_name()},
                                                        {"state", "offline"},
                                                        {"reason", reason}});
    }
}

Result<std::uint32_t> SessionManager::begin_stream(ControlSession* session,
                                                   const StreamParams& params) {
    if (streaming_session_) {
        return fail(ErrorCode::busy, "another phone is already streaming");
    }
    if (!hooks_.start_stream) {
        return fail(ErrorCode::stream_failed, "audio pipeline is unavailable");
    }
    const auto it = sessions_.find(session->device_id());
    if (it == sessions_.end() || it->second.get() != session) {
        return fail(ErrorCode::internal, "session is not registered");
    }

    if (auto r = hooks_.start_stream(params, session->device_id()); !r) {
        return std::unexpected(r.error());
    }

    const std::uint32_t stream_id = next_stream_id_++;
    active_stream_id_ = stream_id;
    streaming_session_ = it->second;
    if (event_callback_) {
        event_callback_("stream.state", nlohmann::json{{"stream_id", stream_id},
                                                       {"device_id", session->device_id()},
                                                       {"name", session->device_name()},
                                                       {"state", "running"}});
    }
    return stream_id;
}

void SessionManager::end_stream(ControlSession* session, const std::string& reason) {
    if (!streaming_session_ || (session != nullptr && streaming_session_.get() != session)) {
        return;
    }
    const std::uint32_t stream_id = active_stream_id_;
    const std::string device_id = streaming_session_->device_id();
    const std::string name = streaming_session_->device_name();

    active_stream_id_ = 0;
    streaming_session_.reset();

    if (hooks_.stop_stream) {
        try {
            hooks_.stop_stream(stream_id, reason);
        } catch (...) {
            logger()->error("audio stop hook threw");
        }
    }
    if (event_callback_) {
        event_callback_("stream.state", nlohmann::json{{"stream_id", stream_id},
                                                       {"device_id", device_id},
                                                       {"name", name},
                                                       {"state", "stopped"},
                                                       {"reason", reason}});
    }
}

Result<std::pair<std::uint32_t, MicStreamPorts>>
SessionManager::begin_mic(ControlSession* session, const MicStreamParams& params) {
    if (mic_session_) {
        return fail(ErrorCode::busy, "another phone is already streaming microphone");
    }
    if (!hooks_.start_mic) {
        return fail(ErrorCode::stream_failed, "mic pipeline is unavailable");
    }
    const auto it = sessions_.find(session->device_id());
    if (it == sessions_.end() || it->second.get() != session) {
        return fail(ErrorCode::internal, "session is not registered");
    }

    auto ports = hooks_.start_mic(params, session->device_id());
    if (!ports) {
        return std::unexpected(ports.error());
    }

    const std::uint32_t stream_id = next_mic_stream_id_++;
    active_mic_stream_id_ = stream_id;
    mic_session_ = it->second;
    if (event_callback_) {
        event_callback_("mic.state", nlohmann::json{{"stream_id", stream_id},
                                                    {"device_id", session->device_id()},
                                                    {"name", session->device_name()},
                                                    {"state", "running"}});
    }
    return std::make_pair(stream_id, *ports);
}

void SessionManager::end_mic(ControlSession* session, const std::string& reason) {
    if (!mic_session_ || (session != nullptr && mic_session_.get() != session)) {
        return;
    }
    const std::uint32_t stream_id = active_mic_stream_id_;
    const std::string device_id = mic_session_->device_id();
    const std::string name = mic_session_->device_name();

    active_mic_stream_id_ = 0;
    mic_session_.reset();

    if (hooks_.stop_mic) {
        try {
            hooks_.stop_mic(stream_id, reason);
        } catch (...) {
            logger()->error("mic stop hook threw");
        }
    }
    if (event_callback_) {
        event_callback_("mic.state", nlohmann::json{{"stream_id", stream_id},
                                                    {"device_id", device_id},
                                                    {"name", name},
                                                    {"state", "stopped"},
                                                    {"reason", reason}});
    }
}

Result<void> SessionManager::stop_device(const std::string& device_id, const std::string& reason) {
    if (device_id.empty()) {
        if (!streaming_session_)
            return {};
        auto* session = streaming_session_.get();
        const std::uint32_t stream_id = active_stream_id_;
        end_stream(session, reason);
        session->on_stream_stopped(stream_id, reason);
        return {};
    }
    if (streaming_session_ && streaming_session_->device_id() == device_id) {
        auto* session = streaming_session_.get();
        const std::uint32_t stream_id = active_stream_id_;
        end_stream(session, reason);
        session->on_stream_stopped(stream_id, reason);
    }
    return {};
}

Result<void> SessionManager::drop_device(const std::string& device_id, const std::string& reason) {
    const auto it = sessions_.find(device_id);
    if (it == sessions_.end())
        return {};
    auto session = it->second;
    if (streaming_session_ && streaming_session_.get() == session.get()) {
        end_stream(session.get(), reason);
    }
    sessions_.erase(it);
    session->close(reason);
    return {};
}

Result<void> SessionManager::request_start(const std::string& device_id) {
    const auto it = sessions_.find(device_id);
    if (it == sessions_.end()) {
        return fail(ErrorCode::phone_not_connected, "phone is not connected");
    }
    if (streaming_session_) {
        return fail(ErrorCode::busy, "a stream is already active");
    }
    it->second->request_host_started_stream();
    return {};
}

Result<void> SessionManager::rename_device(const std::string& device_id, const std::string& name) {
    if (auto r = devices_.rename(device_id, name); !r) {
        // A hello for a paired device should always resolve; log without secrets.
        return r;
    }
    if (const auto it = sessions_.find(device_id); it != sessions_.end()) {
        it->second->set_device_name(name);
    }
    return {};
}

protocol::SessionHelloResponse SessionManager::make_hello_response() const {
    protocol::SessionHelloResponse response;
    response.host_name = host_name_;
    response.host_version = host_version_;
    response.stream.packet_ms = config_.stream.packet_ms;
    response.stream.fec_block_ms = config_.stream.packet_ms * config_.stream.fec_block_source;
    response.stream.min_latency_ms =
        std::max(120, response.stream.fec_block_ms + config_.stream.packet_ms * 2);
    response.sink.name = config_.audio.sink_name;
    response.sink.available = hooks_.sink_available ? hooks_.sink_available() : false;
    response.streaming = streaming_session_ != nullptr;
    response.caps.multi = false;
    response.caps.host_request = true;
    return response;
}

protocol::HostStatus SessionManager::host_status() const {
    protocol::HostStatus status;
    status.sink_available = hooks_.sink_available ? hooks_.sink_available() : false;
    status.streaming = streaming_session_ != nullptr;
    status.other_sessions = static_cast<int>(sessions_.size());
    return status;
}

std::vector<SessionStatus> SessionManager::sessions() const {
    std::vector<SessionStatus> out;
    out.reserve(sessions_.size());
    for (const auto& [id, session] : sessions_) {
        SessionStatus status;
        status.device_id = id;
        status.name = session->device_name();
        status.peer_ip = session->peer_ip();
        status.state = session->state_name();
        status.streaming = session->streaming();
        if (status.streaming)
            status.stream_id = active_stream_id_;
        out.push_back(std::move(status));
    }
    return out;
}

void SessionManager::stop_all(const std::string& reason) {
    if (streaming_session_) {
        auto* session = streaming_session_.get();
        const std::uint32_t stream_id = active_stream_id_;
        end_stream(session, reason);
        session->on_stream_stopped(stream_id, reason);
    }
    if (mic_session_) {
        auto* session = mic_session_.get();
        const std::uint32_t stream_id = active_mic_stream_id_;
        end_mic(session, reason);
        session->on_mic_stopped(stream_id, reason);
    }
}

void SessionManager::send_shutdown_events() {
    std::vector<std::shared_ptr<ControlSession>> copy;
    copy.reserve(sessions_.size());
    for (const auto& [id, session] : sessions_)
        copy.push_back(session);
    for (const auto& session : copy)
        session->shutdown("host_shutdown");
}

void SessionManager::close_all(const std::string& reason) {
    std::vector<std::shared_ptr<ControlSession>> copy;
    copy.reserve(sessions_.size());
    for (const auto& [id, session] : sessions_)
        copy.push_back(session);
    for (const auto& session : copy)
        session->close(reason);
}

} // namespace ar
