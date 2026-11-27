// SPDX-License-Identifier: MIT
#include "daemon/daemon.hpp"

#include "audio/default_sink_guard.hpp"
#include "audio/mic_pipeline.hpp"
#include "audio/stream_pipeline.hpp"
#include "common/clock.hpp"
#include "common/log.hpp"
#include "common/paths.hpp"
#include "crypto/spki.hpp"
#include "daemon/pairing_session.hpp"
#include "ipc/commands.hpp"
#include "ipc/ipc_server.hpp"
#include "net/control_server.hpp"
#include "net/mdns.hpp"
#include "net/tls.hpp"
#include "pairing/pairing_manager.hpp"
#include "session/session_manager.hpp"
#include "store/device_store.hpp"
#include "store/identity.hpp"

#include <csignal>
#include <unistd.h>
#include <utility>

namespace ar {
namespace {

std::string local_host_name() {
    char buf[256]{};
    if (::gethostname(buf, sizeof(buf) - 1) != 0 || buf[0] == '\0') {
        return "trill";
    }
    return buf;
}

} // namespace

Daemon::Daemon(DaemonOptions options)
    : options_(std::move(options)), paths_([] {
          auto paths = resolve_paths();
          return paths ? *paths : Paths{};
      }()),
      pairing_timer_(io_), shutdown_timer_(io_), signals_(io_) {}

Daemon::~Daemon() {
    if (!stopped_)
        finish_shutdown();
}

Result<void> Daemon::load_config() {
    const auto path = options_.config_path.empty() ? paths_.config_file : options_.config_path;
    auto loaded = Config::load(path);
    if (!loaded)
        return std::unexpected(loaded.error());
    config_ = *loaded;
    if (options_.control_port)
        config_.daemon.control_port = *options_.control_port;
    if (options_.mic_source_port)
        config_.daemon.mic_source_port = *options_.mic_source_port;
    if (options_.mic_repair_port)
        config_.daemon.mic_repair_port = *options_.mic_repair_port;
    if (options_.log_level)
        config_.log.level = *options_.log_level;
    if (auto r = config_.validate(); !r)
        return r;
    return {};
}

Result<void> Daemon::start() {
    if (paths_.config_dir.empty()) {
        return fail(ErrorCode::io_error, "cannot resolve XDG paths");
    }
    if (auto r = ensure_dir(paths_.config_dir, 0700); !r)
        return r;
    if (auto r = ensure_dir(paths_.state_dir, 0700); !r)
        return r;
    if (auto r = ensure_dir(paths_.runtime_dir, 0700); !r)
        return r;

    if (auto r = load_config(); !r) {
        init_logging("info");
        return r;
    }
    init_logging(config_.log.level, paths_.log_file.string(), true);

    auto identity = HostIdentity::load_or_create(paths_.identity_dir, "trill-host");
    if (!identity)
        return std::unexpected(identity.error());
    identity_ = std::make_unique<HostIdentity>(std::move(*identity));

    auto devices = DeviceStore::load(paths_.devices_file);
    if (!devices)
        return std::unexpected(devices.error());
    devices_ = std::make_unique<DeviceStore>(std::move(*devices));

    auto cert = identity_->cert_pem();
    auto key = identity_->key_pem();
    if (!cert || !key) {
        return fail(ErrorCode::crypto_error, "cannot export the host identity");
    }
    auto tls = make_server_tls_context(*cert, *key);
    if (!tls)
        return std::unexpected(tls.error());
    tls_context_ = std::move(*tls);

    PipelineSettings settings;
    settings.sink.name = config_.audio.sink_name;
    settings.sink.description = config_.audio.sink_description;
    settings.packet_ms = config_.stream.packet_ms;
    settings.fec_block_source = config_.stream.fec_block_source;
    settings.fec_block_repair = config_.stream.fec_block_repair;
    settings.sink_per_session = config_.audio.sink_lifetime != "daemon";
    pipeline_ = std::make_unique<StreamPipeline>(settings);

    MicPipelineSettings mic_settings;
    mic_settings.source.name = "trill-mic";
    mic_settings.source.description = "Trill Microphone";
    mic_pipeline_ = std::make_unique<MicPipeline>(mic_settings);

    if (!settings.sink_per_session) {
        if (auto r = pipeline_->start_sink(); !r) {
            logger()->warn("cannot start the daemon-lifetime sink: {}", r.error().message);
        }
    }

    {
        // Always connect: the metadata object doubles as the PipeWire
        // availability probe used by status and session.hello.
        sink_guard_ = std::make_unique<DefaultSinkGuard>();
        if (auto r = sink_guard_->start(); !r) {
            logger()->warn("PipeWire default metadata unavailable: {}", r.error().message);
            sink_guard_.reset();
        } else {
            sink_guard_started_ = true;
            if (auto rec = recover_default_sink(); !rec) {
                logger()->warn("cannot recover the previous default sink: {}", rec.error().message);
            }
        }
    }

    auto clock = std::make_shared<SystemClock>();
    const std::string host_name = local_host_name();
    pairing_ =
        std::make_unique<PairingManager>(config_.pairing, identity_->spki_hex(), host_name, clock);
    pairing_->set_callbacks(
        [this](const std::string& code, int seconds) { on_pairing_opened(code, seconds); },
        [this](const std::string& reason) { on_pairing_closed(reason); },
        [this](const std::string& id, const std::string& name, const std::string& ip) {
            on_pairing_success(id, name, ip);
        });

    sessions_ = std::make_unique<SessionManager>(
        *devices_, config_, host_name, TRILL_VERSION,
        [this](const std::string& type, const nlohmann::json& fields) { broadcast(type, fields); });

    SessionManager::Hooks hooks;
    hooks.start_stream = [this](const StreamParams& params,
                                const std::string& /*device_id*/) -> Result<void> {
        if (auto r = pipeline_->start(params); !r)
            return r;
        switch_default_sink();
        return {};
    };
    hooks.stop_stream = [this](std::uint32_t /*stream_id*/, const std::string& reason) {
        logger()->info("stopping audio stream ({})", reason);
        pipeline_->stop();
        restore_default_sink();
    };
    hooks.start_mic = [this](const MicStreamParams& /*params*/,
                             const std::string& /*device_id*/) -> Result<MicStreamPorts> {
        if (!mic_pipeline_) {
            return fail(ErrorCode::internal, "mic pipeline not initialized");
        }
        auto bound = mic_pipeline_->start(config_.daemon.mic_source_port,
                                          config_.daemon.mic_repair_port);
        if (!bound) {
            logger()->warn("failed to bind configured mic ports ({}, {}); falling back to dynamic ports",
                           config_.daemon.mic_source_port, config_.daemon.mic_repair_port);
            bound = mic_pipeline_->start(0, 0);
            if (!bound) {
                return std::unexpected(bound.error());
            }
        }
        return MicStreamPorts{bound->source_port, bound->repair_port};
    };
    hooks.stop_mic = [this](std::uint32_t /*stream_id*/, const std::string& reason) {
        logger()->info("stopping mic stream ({})", reason);
        if (mic_pipeline_) {
            mic_pipeline_->stop();
        }
    };
    hooks.sink_available = [this] {
        if (pipeline_ != nullptr && pipeline_->sink_running())
            return true;
        return sink_guard_ != nullptr && sink_guard_->available();
    };
    sessions_->set_hooks(std::move(hooks));

    commands_ = std::make_unique<CommandHandler>(*devices_, *pairing_, *sessions_);
    commands_->set_status_provider([this] {
        const PipelineStats stats = pipeline_->stats();
        nlohmann::json out{
            {"host", nlohmann::json{{"name", sessions_->host_name()},
                                    {"version", TRILL_VERSION},
                                    {"id16", identity_->spki_hex().substr(0, 16)}}},
            {"sink", nlohmann::json{{"name", config_.audio.sink_name},
                                    {"available", sessions_->host_status().sink_available}}},
            {"stream", nlohmann::json{{"running", stats.streaming},
                                      {"capture_running", stats.capture_running},
                                      {"frames_sent", stats.frames_sent},
                                      {"ring_overrun_samples", stats.ring_overrun_samples},
                                      {"ring_underrun_frames", stats.ring_underrun_frames},
                                      {"write_errors", stats.write_errors},
                                      {"ring_available_samples", stats.ring_available_samples},
                                      {"ring_capacity_samples", stats.ring_capacity_samples}}},
            {"mdns", nlohmann::json{{"available", mdns_ != nullptr && mdns_->available()}}}};
        if (mic_pipeline_) {
            const auto mic_stats = mic_pipeline_->stats();
            out["mic"] = nlohmann::json{{"running", mic_stats.streaming},
                                        {"source_running", mic_stats.source_running},
                                        {"frames_received", mic_stats.frames_received},
                                        {"read_errors", mic_stats.read_errors},
                                        {"ring_available_samples", mic_stats.ring_available_samples},
                                        {"ring_capacity_samples", mic_stats.ring_capacity_samples}};
        }
        return out;
    });
    commands_->set_shutdown_request([this] { request_shutdown(); });

    ipc_ = std::make_unique<IpcServer>(io_, paths_.socket_path);
    ipc_->set_handler([this](const ipc::Request& request) { return commands_->handle(request); });
    if (auto r = ipc_->start(); !r)
        return r;

    control_ = std::make_unique<ControlServer>(
        io_, tls_context_, config_.daemon.control_port,
        [this](TlsConnection::Ptr connection) { on_control_connection(connection); });
    if (auto r = control_->start(); !r)
        return r;

    mdns_ = std::make_unique<MdnsPublisher>("", identity_->spki_hex().substr(0, 16),
                                            control_->port(), "0.4");
    if (auto r = mdns_->start(); !r) {
        logger()->warn("mDNS unavailable ({}); the phone can use manual host:port",
                       r.error().message);
        mdns_.reset();
    }

    pairing_timer_.expires_after(std::chrono::milliseconds(250));
    pairing_timer_.async_wait([this](const std::error_code& ec) {
        if (ec || stopping_)
            return;
        tick_pairing();
        schedule_pairing_tick();
    });

    signals_.add(SIGINT);
    signals_.add(SIGTERM);
    signals_.async_wait([this](const std::error_code& ec, int signal_number) {
        if (ec)
            return;
        logger()->info("received signal {}, shutting down", signal_number);
        begin_shutdown();
    });

    logger()->info("trilld {} ready: id {}, control port {}", TRILL_VERSION,
                   short_id(identity_->spki_hex()), control_->port());
    return {};
}

void Daemon::run() {
    io_.run();
    if (!stopped_)
        finish_shutdown();
}

void Daemon::request_shutdown() {
    asio::post(io_, [this] { begin_shutdown(); });
}

void Daemon::on_control_connection(const std::shared_ptr<TlsConnection>& connection) {
    auto spki = connection->peer_spki_hex();
    if (!spki) {
        logger()->warn("connection from {} presented no usable certificate", connection->peer_ip());
        connection->close();
        return;
    }
    const std::string alpn = connection->alpn();
    if (alpn == protocol::kAlpnPair) {
        if (!pairing_) {
            connection->close();
            return;
        }
        auto session = std::make_shared<PairingSession>(
            connection, *pairing_, identity_->spki_hex(), connection->peer_ip());
        session->start();
        return;
    }
    if (alpn == protocol::kAlpnCtrl) {
        auto result = sessions_->attach(connection, *spki, connection->peer_ip());
        if (!result) {
            logger()->warn("control connection from {} rejected: {}", connection->peer_ip(),
                           result.error().message);
            connection->close();
        }
        return;
    }
    logger()->warn("connection with unsupported ALPN '{}' from {}", alpn, connection->peer_ip());
    connection->close();
}

void Daemon::on_pairing_opened(const std::string& /*code*/, int seconds) {
    last_pairing_second_ = seconds;
    if (mdns_)
        mdns_->set_pairing(true);
    // The code itself only goes to the CLI that opened the window, in the
    // response to its `pair` request. Events never carry it.
    broadcast("pair.progress", nlohmann::json{{"state", "open"}, {"expires_in", seconds}});
}

void Daemon::on_pairing_closed(const std::string& reason) {
    last_pairing_second_ = -1;
    if (mdns_)
        mdns_->set_pairing(false);
    broadcast("pair.closed", nlohmann::json{{"reason", reason}});
}

void Daemon::on_pairing_success(const std::string& device_id, const std::string& name,
                                const std::string& peer_ip) {
    if (auto r = devices_->upsert(device_id, name, peer_ip); !r) {
        logger()->warn("cannot store the paired device: {}", r.error().message);
        return;
    }
    if (auto r = devices_->save(); !r) {
        logger()->warn("cannot save devices.json: {}", r.error().message);
    }
    broadcast("pair.paired", nlohmann::json{{"device_id", device_id}, {"name", name}});
}

void Daemon::broadcast(std::string_view event, nlohmann::json fields) {
    if (ipc_)
        ipc_->broadcast(event, std::move(fields));
}

void Daemon::tick_pairing() {
    if (!pairing_)
        return;
    (void)pairing_->tick();
    if (!pairing_->is_open()) {
        last_pairing_second_ = -1;
        return;
    }
    const int remaining = pairing_->seconds_remaining();
    if (remaining != last_pairing_second_) {
        last_pairing_second_ = remaining;
        broadcast("pair.progress",
                  nlohmann::json{{"state", "open"}, {"seconds_remaining", remaining}});
    }
}

void Daemon::schedule_pairing_tick() {
    if (stopping_ || stopped_)
        return;
    pairing_timer_.expires_after(std::chrono::milliseconds(250));
    pairing_timer_.async_wait([this](const std::error_code& ec) {
        if (ec || stopping_)
            return;
        tick_pairing();
        schedule_pairing_tick();
    });
}

Result<void> Daemon::recover_default_sink() {
    if (!sink_guard_started_ || sink_guard_ == nullptr)
        return {};
    std::error_code ec;
    if (!std::filesystem::exists(paths_.prev_default_file, ec))
        return {};
    auto content = read_file(paths_.prev_default_file);
    if (!content)
        return std::unexpected(content.error());
    auto snapshot = DefaultSinkGuard::parse(*content);
    if (!snapshot)
        return std::unexpected(snapshot.error());
    if (auto r = sink_guard_->restore(*snapshot); !r)
        return r;
    logger()->info("restored the default sink saved before the last exit");
    std::error_code remove_ec;
    std::filesystem::remove(paths_.prev_default_file, remove_ec);
    return {};
}

void Daemon::switch_default_sink() {
    if (!sink_guard_started_ || sink_guard_ == nullptr)
        return;
    if (!config_.audio.auto_default_sink || options_.no_default_switch)
        return;
    if (default_switched_)
        return;
    const auto snapshot = sink_guard_->snapshot();
    if (auto r = write_file_atomic(paths_.prev_default_file, DefaultSinkGuard::serialize(snapshot),
                                   0600);
        !r) {
        logger()->warn("cannot save the previous default sink: {}", r.error().message);
        return;
    }
    if (auto r = sink_guard_->set_default_sink(config_.audio.sink_name); !r) {
        logger()->warn("cannot switch the default sink: {}", r.error().message);
        return;
    }
    default_switched_ = true;
    logger()->info("default sink switched to '{}'", config_.audio.sink_name);
}

void Daemon::restore_default_sink() {
    if (!default_switched_ || !sink_guard_started_ || sink_guard_ == nullptr)
        return;
    default_switched_ = false;
    auto content = read_file(paths_.prev_default_file);
    if (!content) {
        logger()->warn("previous default sink file is missing: {}", content.error().message);
        return;
    }
    auto snapshot = DefaultSinkGuard::parse(*content);
    if (!snapshot) {
        logger()->warn("cannot parse the previous default sink: {}", snapshot.error().message);
        return;
    }
    if (auto r = sink_guard_->restore(*snapshot); !r) {
        logger()->warn("cannot restore the default sink: {}", r.error().message);
        return;
    }
    std::error_code ec;
    std::filesystem::remove(paths_.prev_default_file, ec);
    logger()->info("default sink restored");
}

void Daemon::begin_shutdown() {
    if (stopping_)
        return;
    stopping_ = true;
    pairing_timer_.cancel();
    if (control_)
        control_->stop();
    if (pairing_)
        pairing_->close("shutdown");
    if (sessions_) {
        sessions_->send_shutdown_events();
        sessions_->stop_all("host_shutdown");
    }
    // Give queued event.host.shutdown writes and the IPC response a moment to
    // flush before the sockets are torn down.
    shutdown_timer_.expires_after(std::chrono::milliseconds(150));
    shutdown_timer_.async_wait([this](const std::error_code& timer_ec) {
        if (timer_ec)
            return;
        finish_shutdown();
    });
}

void Daemon::finish_shutdown() {
    if (stopped_)
        return;
    stopped_ = true;
    shutdown_timer_.cancel();
    signals_.cancel();
    pairing_timer_.cancel();

    if (sessions_) {
        sessions_->close_all("host_shutdown");
        sessions_.reset();
    }
    if (pipeline_) {
        pipeline_->stop();
        pipeline_.reset();
    }
    if (mic_pipeline_) {
        mic_pipeline_->stop();
        mic_pipeline_.reset();
    }
    restore_default_sink();
    if (sink_guard_) {
        sink_guard_->stop();
        sink_guard_.reset();
    }
    if (mdns_) {
        mdns_->stop();
        mdns_.reset();
    }
    broadcast("daemon.shutdown", nlohmann::json::object());
    if (ipc_) {
        ipc_->stop();
        ipc_.reset();
    }
    commands_.reset();
    pairing_.reset();
    devices_.reset();
    identity_.reset();
    logger()->info("trilld stopped");
    io_.stop();
    shutdown_logging();
}

Result<void> Daemon::run_debug_send(const DaemonOptions& options) {
    auto paths = resolve_paths();
    if (!paths)
        return std::unexpected(paths.error());
    auto config =
        Config::load(options.config_path.empty() ? paths->config_file : options.config_path);
    if (!config)
        return std::unexpected(config.error());
    init_logging(options.log_level.value_or(config->log.level), {}, true);

    StreamParams params;
    params.peer_ip = options.debug_ip;
    params.source_port = options.debug_source_port;
    params.repair_port = options.debug_repair_port;

    PipelineSettings settings;
    settings.sink.name = config->audio.sink_name;
    settings.sink.description = config->audio.sink_description;
    settings.packet_ms = config->stream.packet_ms;
    settings.fec_block_source = config->stream.fec_block_source;
    settings.fec_block_repair = config->stream.fec_block_repair;
    settings.sink_per_session = false;

    StreamPipeline pipeline(settings);
    if (auto r = pipeline.start(params); !r)
        return r;

    asio::io_context io;
    asio::signal_set signals(io, SIGINT, SIGTERM);
    signals.async_wait([&io](const std::error_code&, int) { io.stop(); });
    logger()->info("debug-send active; press Ctrl-C to stop");
    io.run();
    pipeline.stop();
    shutdown_logging();
    return {};
}

} // namespace ar
