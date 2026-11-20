// SPDX-License-Identifier: MIT
#include "ipc/commands.hpp"

#include "common/log.hpp"

#include <algorithm>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace ar {
namespace {

Result<std::string> required_string(const nlohmann::json& args, const char* key) {
    const auto it = args.find(key);
    if (it == args.end() || !it->is_string()) {
        return fail(ErrorCode::invalid_argument,
                    std::string("missing string argument '") + key + "'");
    }
    std::string value = it->get<std::string>();
    if (value.empty()) {
        return fail(ErrorCode::invalid_argument,
                    std::string("argument '") + key + "' must not be empty");
    }
    return value;
}

std::string joined_names(const std::vector<Device>& devices) {
    std::string out;
    for (const auto& device : devices) {
        if (!out.empty())
            out += ", ";
        out += device.name;
    }
    return out;
}

} // namespace

CommandHandler::CommandHandler(DeviceStore& devices, PairingManager& pairing,
                               SessionManager& sessions)
    : devices_(devices), pairing_(pairing), sessions_(sessions) {}

Result<nlohmann::json> CommandHandler::handle(const ipc::Request& request) {
    if (request.cmd == "pair")
        return cmd_pair(request.args);
    if (request.cmd == "list")
        return cmd_list();
    if (request.cmd == "status")
        return cmd_status();
    if (request.cmd == "start")
        return cmd_start(request.args);
    if (request.cmd == "stop")
        return cmd_stop(request.args);
    if (request.cmd == "unpair")
        return cmd_unpair(request.args);
    if (request.cmd == "rename")
        return cmd_rename(request.args);
    if (request.cmd == "shutdown")
        return cmd_shutdown();
    return fail(ErrorCode::unsupported, "unknown command '" + request.cmd + "'");
}

Result<std::string> CommandHandler::resolve_device(const nlohmann::json& args) const {
    auto selector = required_string(args, "device");
    if (!selector)
        return std::unexpected(selector.error());
    auto index = devices_.resolve(*selector);
    if (!index) {
        if (index.error().code == ErrorCode::ambiguous) {
            auto matches = devices_.matches(*selector);
            return fail(ErrorCode::ambiguous,
                        "device '" + *selector + "' is ambiguous: " + joined_names(matches));
        }
        return fail(ErrorCode::not_found, "no paired device matches '" + *selector + "'");
    }
    return devices_.devices()[*index].id;
}

nlohmann::json CommandHandler::sessions_json() const {
    nlohmann::json out = nlohmann::json::array();
    for (const auto& session : sessions_.sessions()) {
        out.push_back(nlohmann::json{{"device_id", session.device_id},
                                     {"name", session.name},
                                     {"peer_ip", session.peer_ip},
                                     {"state", session.state},
                                     {"streaming", session.streaming},
                                     {"stream_id", session.stream_id}});
    }
    return out;
}

Result<nlohmann::json> CommandHandler::cmd_pair(const nlohmann::json& args) {
    int seconds = 0;
    if (const auto it = args.find("timeout"); it != args.end()) {
        if (!it->is_number_integer()) {
            return fail(ErrorCode::invalid_argument, "'timeout' must be an integer");
        }
        seconds = it->get<int>();
        if (seconds < 1 || seconds > 120) {
            return fail(ErrorCode::invalid_argument, "'timeout' must be between 1 and 120");
        }
    }

    auto window = pairing_.open_window(seconds);
    if (!window)
        return std::unexpected(window.error());
    return nlohmann::json{{"code", window->first}, {"expires_in", window->second}};
}

Result<nlohmann::json> CommandHandler::cmd_list() {
    std::vector<SessionStatus> live = sessions_.sessions();
    nlohmann::json devices = nlohmann::json::array();
    for (const auto& device : devices_.devices()) {
        const auto it =
            std::find_if(live.begin(), live.end(), [&device](const SessionStatus& session) {
                return session.device_id == device.id;
            });
        nlohmann::json entry{
            {"id", device.id},
            {"id8", device.id.substr(0, std::min<std::size_t>(8, device.id.size()))},
            {"name", device.name},
            {"paired_at", device.paired_at},
            {"last_seen", device.last_seen},
            {"last_ip", device.last_ip},
            {"connected", it != live.end()}};
        if (it != live.end()) {
            entry["state"] = it->state;
            entry["streaming"] = it->streaming;
        } else {
            entry["state"] = "offline";
            entry["streaming"] = false;
        }
        devices.push_back(std::move(entry));
    }
    return nlohmann::json{{"devices", std::move(devices)}};
}

Result<nlohmann::json> CommandHandler::cmd_status() {
    nlohmann::json out = status_provider_ ? status_provider_() : nlohmann::json::object();
    out["sink"] = nlohmann::json{{"name", sessions_.config().audio.sink_name},
                                 {"available", sessions_.host_status().sink_available}};
    out["streaming"] = sessions_.streaming();
    out["stream_id"] = sessions_.active_stream_id();
    out["sessions"] = sessions_json();
    out["pairing"] = nlohmann::json{{"open", pairing_.is_open()},
                                    {"locked", pairing_.locked()},
                                    {"seconds_remaining", pairing_.seconds_remaining()},
                                    {"attempts_remaining", pairing_.attempts_remaining()}};
    return out;
}

Result<nlohmann::json> CommandHandler::cmd_start(const nlohmann::json& args) {
    auto device_id = resolve_device(args);
    if (!device_id)
        return std::unexpected(device_id.error());
    if (auto r = sessions_.request_start(*device_id); !r) {
        return std::unexpected(r.error());
    }
    logger()->info("requested the phone to start streaming ({})", short_id(*device_id));
    return nlohmann::json{{"device_id", *device_id}};
}

Result<nlohmann::json> CommandHandler::cmd_stop(const nlohmann::json& args) {
    const auto it = args.find("device");
    if (it == args.end() || (it->is_string() && it->get<std::string>().empty())) {
        sessions_.stop_all("user");
        return nlohmann::json{{"stopped", "all"}};
    }
    auto device_id = resolve_device(args);
    if (!device_id)
        return std::unexpected(device_id.error());
    if (auto r = sessions_.stop_device(*device_id, "user"); !r) {
        return std::unexpected(r.error());
    }
    return nlohmann::json{{"device_id", *device_id}};
}

Result<nlohmann::json> CommandHandler::cmd_unpair(const nlohmann::json& args) {
    auto device_id = resolve_device(args);
    if (!device_id)
        return std::unexpected(device_id.error());

    (void)sessions_.drop_device(*device_id, "unpaired");
    if (auto r = devices_.remove(*device_id); !r)
        return std::unexpected(r.error());
    if (auto r = devices_.save(); !r)
        return std::unexpected(r.error());
    logger()->info("unpaired device {}", short_id(*device_id));
    return nlohmann::json{{"device_id", *device_id}};
}

Result<nlohmann::json> CommandHandler::cmd_rename(const nlohmann::json& args) {
    auto device_id = resolve_device(args);
    if (!device_id)
        return std::unexpected(device_id.error());
    auto name = required_string(args, "name");
    if (!name)
        return std::unexpected(name.error());
    if (name->size() > 63) {
        return fail(ErrorCode::invalid_argument, "name must be at most 63 bytes");
    }
    if (auto r = sessions_.rename_device(*device_id, *name); !r) {
        return std::unexpected(r.error());
    }
    if (auto r = devices_.save(); !r)
        return std::unexpected(r.error());
    return nlohmann::json{{"device_id", *device_id}, {"name", *name}};
}

Result<nlohmann::json> CommandHandler::cmd_shutdown() {
    if (shutdown_request_)
        shutdown_request_();
    return nlohmann::json{{"ok", true}};
}

} // namespace ar
