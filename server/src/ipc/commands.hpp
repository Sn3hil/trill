// SPDX-License-Identifier: MIT
#pragma once

#include "common/error.hpp"
#include "ipc/ipc_protocol.hpp"
#include "pairing/pairing_manager.hpp"
#include "session/session_manager.hpp"
#include "store/device_store.hpp"

#include <functional>
#include <nlohmann/json.hpp>
#include <string>

namespace ar {

// Handles one IPC request from the CLI. Every command runs on the daemon's
// io_context thread; it never blocks.
class CommandHandler {
  public:
    using StatusProvider = std::function<nlohmann::json()>;
    using ShutdownRequest = std::function<void()>;

    CommandHandler(DeviceStore& devices, PairingManager& pairing, SessionManager& sessions);

    void set_status_provider(StatusProvider provider) {
        status_provider_ = std::move(provider);
    }
    void set_shutdown_request(ShutdownRequest request) {
        shutdown_request_ = std::move(request);
    }

    [[nodiscard]] Result<nlohmann::json> handle(const ipc::Request& request);

  private:
    [[nodiscard]] Result<nlohmann::json> cmd_pair(const nlohmann::json& args);
    [[nodiscard]] Result<nlohmann::json> cmd_list();
    [[nodiscard]] Result<nlohmann::json> cmd_status();
    [[nodiscard]] Result<nlohmann::json> cmd_start(const nlohmann::json& args);
    [[nodiscard]] Result<nlohmann::json> cmd_stop(const nlohmann::json& args);
    [[nodiscard]] Result<nlohmann::json> cmd_unpair(const nlohmann::json& args);
    [[nodiscard]] Result<nlohmann::json> cmd_rename(const nlohmann::json& args);
    [[nodiscard]] Result<nlohmann::json> cmd_shutdown();

    [[nodiscard]] Result<std::string> resolve_device(const nlohmann::json& args) const;
    [[nodiscard]] nlohmann::json sessions_json() const;

    DeviceStore& devices_;
    PairingManager& pairing_;
    SessionManager& sessions_;
    StatusProvider status_provider_;
    ShutdownRequest shutdown_request_;
};

} // namespace ar
