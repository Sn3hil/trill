// SPDX-License-Identifier: MIT
#pragma once

#include "common/error.hpp"
#include "common/paths.hpp"
#include "store/config.hpp"

#include <asio.hpp>
#include <asio/ssl.hpp>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>

namespace ar {

class DeviceStore;
class DefaultSinkGuard;
class HostIdentity;
class IpcServer;
class MdnsPublisher;
class PairingManager;
class SessionManager;
class StreamPipeline;
class ControlServer;
class CommandHandler;
class TlsConnection;

struct DaemonOptions {
    std::filesystem::path config_path;
    std::optional<std::uint16_t> control_port;
    std::optional<std::string> log_level;
    bool no_default_switch{false};
    bool insecure_dev_pairing{false};
    bool debug_send{false};
    std::string debug_ip;
    std::uint16_t debug_source_port{0};
    std::uint16_t debug_repair_port{0};
};

// Composition root: owns the config, identity, stores, control plane, audio
// pipeline, IPC server and timers. All asynchronous work runs on one
// io_context thread.
class Daemon {
  public:
    explicit Daemon(DaemonOptions options);
    ~Daemon();

    Daemon(const Daemon&) = delete;
    Daemon& operator=(const Daemon&) = delete;

    [[nodiscard]] Result<void> start();
    // Runs the io_context until SIGINT/SIGTERM or the IPC shutdown command.
    void run();
    void request_shutdown();

    [[nodiscard]] const Paths& paths() const {
        return paths_;
    }
    [[nodiscard]] const Config& config() const {
        return config_;
    }

    // Hidden S1/S3 debugging path: no control plane, no IPC. Blocks until a
    // signal arrives.
    [[nodiscard]] static Result<void> run_debug_send(const DaemonOptions& options);

  private:
    void on_control_connection(const std::shared_ptr<TlsConnection>& connection);
    void on_pairing_opened(const std::string& code, int seconds);
    void on_pairing_closed(const std::string& reason);
    void on_pairing_success(const std::string& device_id, const std::string& name,
                            const std::string& peer_ip);
    void broadcast(std::string_view event, nlohmann::json fields = {});

    [[nodiscard]] Result<void> load_config();
    [[nodiscard]] Result<void> recover_default_sink();
    void switch_default_sink();
    void restore_default_sink();
    void tick_pairing();
    void schedule_pairing_tick();
    void begin_shutdown();
    void finish_shutdown();

    DaemonOptions options_;
    Paths paths_;
    Config config_;

    std::unique_ptr<HostIdentity> identity_;
    std::unique_ptr<DeviceStore> devices_;
    std::unique_ptr<PairingManager> pairing_;
    std::unique_ptr<SessionManager> sessions_;
    std::unique_ptr<StreamPipeline> pipeline_;
    std::unique_ptr<DefaultSinkGuard> sink_guard_;
    std::unique_ptr<MdnsPublisher> mdns_;
    std::unique_ptr<CommandHandler> commands_;
    std::unique_ptr<IpcServer> ipc_;
    std::unique_ptr<ControlServer> control_;

    asio::io_context io_;
    std::shared_ptr<asio::ssl::context> tls_context_;
    asio::steady_timer pairing_timer_;
    asio::steady_timer shutdown_timer_;
    asio::signal_set signals_;

    bool sink_guard_started_{false};
    bool default_switched_{false};
    bool stopping_{false};
    bool stopped_{false};
    int last_pairing_second_{-1};
};

} // namespace ar
