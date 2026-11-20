// SPDX-License-Identifier: MIT
#include "cli/ipc_client.hpp"
#include "cli/render.hpp"
#include "common/error.hpp"
#include "common/paths.hpp"

#include <CLI/CLI.hpp>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <unistd.h>

namespace {

using nlohmann::json;

struct Action {
    std::string command;
    nlohmann::json args = nlohmann::json::object();
    bool watch_pairing{false};
};

int finish(const ar::Error& error, bool as_json) {
    ar::render::print_error(error, as_json);
    return ar::cli_exit_code(error.code);
}

int watch_pairing(ar::IpcClient& client, bool as_json, const std::string& code, int expires) {
    bool tty = ::isatty(STDOUT_FILENO) != 0;
    int remaining = expires;
    while (true) {
        auto message = client.read_message();
        if (!message)
            return finish(message.error(), as_json);
        const std::string event = message->value("event", std::string());
        if (event.empty())
            continue;

        if (as_json) {
            ar::render::print_json(*message);
        }

        if (event == "pair.progress") {
            if (as_json || !tty)
                continue;
            if (message->value("state", std::string()) != "open")
                continue;
            const int seconds = message->value("seconds_remaining", remaining);
            if (seconds == remaining)
                continue;
            remaining = seconds;
            std::cout << "\rPairing code: " << ar::render::pairing_code(code) << " (expires in "
                      << remaining << "s)" << std::flush;
            continue;
        }
        if (event == "pair.paired") {
            const std::string name = message->value("name", std::string("phone"));
            const std::string id = message->value("device_id", std::string());
            if (!as_json) {
                if (tty)
                    std::cout << '\n';
                std::cout << "Paired with '" << name << "' (" << ar::render::short_device_id(id)
                          << ")\n";
            }
            return 0;
        }
        if (event == "pair.closed") {
            const std::string reason = message->value("reason", std::string("closed"));
            if (!as_json) {
                if (tty)
                    std::cout << '\n';
                if (reason == "timeout") {
                    std::cout << "Pairing window expired.\n";
                } else if (reason == "locked") {
                    std::cout << "Too many wrong pairing attempts. Window locked.\n";
                } else if (reason != "success") {
                    std::cout << "Pairing closed: " << reason << '\n';
                }
            }
            return reason == "success" ? 0 : 1;
        }
        if (event == "daemon.shutdown") {
            if (!as_json)
                std::cout << "The daemon is shutting down.\n";
            return 1;
        }
    }
}

int run(const Action& action, const std::filesystem::path& socket_path, bool as_json) {
    auto client = ar::IpcClient::connect(socket_path);
    if (!client)
        return finish(client.error(), as_json);
    auto& ipc = **client;

    if (action.watch_pairing) {
        auto result = ipc.call("pair", action.args);
        if (!result)
            return finish(result.error(), as_json);
        const std::string code = result->value("code", std::string());
        const int expires = result->value("expires_in", 30);
        if (as_json) {
            ar::render::print_json(*result);
        } else {
            bool tty = ::isatty(STDOUT_FILENO) != 0;
            std::cout << "Pairing code: " << ar::render::pairing_code(code) << " (expires in "
                      << expires << "s)";
            if (tty) {
                std::cout << std::flush;
            } else {
                std::cout << '\n';
            }
        }
        return watch_pairing(ipc, as_json, code, expires);
    }

    auto result = ipc.call(action.command, action.args);
    if (!result)
        return finish(result.error(), as_json);
    if (as_json) {
        ar::render::print_json(*result);
        return 0;
    }

    if (action.command == "list") {
        ar::render::print_device_list(*result);
    } else if (action.command == "status") {
        ar::render::print_status(*result);
    } else if (action.command == "start") {
        std::cout << "Asked the phone to start streaming. If nothing happens, enable "
                     "\"Allow PC to start streaming\" on the phone.\n";
    } else if (action.command == "stop") {
        if (result->contains("device_id")) {
            std::cout << "Stopped "
                      << ar::render::short_device_id(result->value("device_id", std::string()))
                      << ".\n";
        } else {
            std::cout << "Stopped all streams.\n";
        }
    } else if (action.command == "unpair") {
        std::cout << "Unpaired "
                  << ar::render::short_device_id(result->value("device_id", std::string()))
                  << ".\n";
    } else if (action.command == "rename") {
        std::cout << "Renamed "
                  << ar::render::short_device_id(result->value("device_id", std::string()))
                  << " to '" << result->value("name", std::string()) << "'.\n";
    } else if (action.command == "shutdown") {
        std::cout << "Daemon is shutting down.\n";
    }
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    CLI::App app{"Control the trill daemon", "trill"};
    app.set_version_flag("--version", TRILL_VERSION);

    bool as_json = false;
    std::string socket_path;
    app.fallthrough(true);
    app.add_flag("--json", as_json, "Print machine-readable JSON");
    app.add_option("--socket", socket_path, "Override the daemon IPC socket path");

    Action action;
    int pair_timeout = 0;

    auto* pair_cmd = app.add_subcommand("pair", "Open a pairing window and show the code");
    pair_cmd->add_option("--timeout", pair_timeout, "Window duration in seconds (1..120)");
    pair_cmd->callback([&] {
        action.command = "pair";
        action.watch_pairing = true;
        if (pair_timeout > 0)
            action.args["timeout"] = pair_timeout;
    });

    app.add_subcommand("list", "List paired phones")->callback([&] { action.command = "list"; });
    app.add_subcommand("status", "Show daemon, sink, sessions and stream status")->callback([&] {
        action.command = "status";
    });

    std::string start_device;
    auto* start_cmd = app.add_subcommand("start", "Ask a connected phone to start streaming");
    start_cmd->add_option("device", start_device, "Phone id prefix or name")->required();
    start_cmd->callback([&] {
        action.command = "start";
        action.args["device"] = start_device;
    });

    std::string stop_device;
    auto* stop_cmd = app.add_subcommand("stop", "Stop one stream, or all when no device is given");
    stop_cmd->add_option("device", stop_device, "Phone id prefix or name");
    stop_cmd->callback([&] {
        action.command = "stop";
        if (!stop_device.empty())
            action.args["device"] = stop_device;
    });

    std::string unpair_device;
    auto* unpair_cmd = app.add_subcommand("unpair", "Remove the pin and drop the session");
    unpair_cmd->add_option("device", unpair_device, "Phone id prefix or name")->required();
    unpair_cmd->callback([&] {
        action.command = "unpair";
        action.args["device"] = unpair_device;
    });

    std::string rename_device;
    std::string rename_name;
    auto* rename_cmd = app.add_subcommand("rename", "Change a phone's label");
    rename_cmd->add_option("device", rename_device, "Phone id prefix or name")->required();
    rename_cmd->add_option("name", rename_name, "New label")->required();
    rename_cmd->callback([&] {
        action.command = "rename";
        action.args["device"] = rename_device;
        action.args["name"] = rename_name;
    });

    app.add_subcommand("shutdown", "Stop the daemon")->callback([&] {
        action.command = "shutdown";
    });

    // Legacy flag aliases from the plan.
    bool legacy_pair = false;
    bool legacy_list = false;
    bool legacy_status = false;
    std::string legacy_start;
    std::string legacy_stop;
    app.add_flag("--pair", legacy_pair, "Alias for 'pair'")->group("");
    app.add_flag("--list", legacy_list, "Alias for 'list'")->group("");
    app.add_flag("--status", legacy_status, "Alias for 'status'")->group("");
    app.add_option("--start", legacy_start, "Alias for 'start <device>'")->group("");
    app.add_option("--stop", legacy_stop, "Alias for 'stop [device]'")->expected(0, 1)->group("");

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& error) {
        const int code = app.exit(error);
        return code == 0 ? 0 : 2;
    }

    if (action.command.empty()) {
        if (legacy_pair) {
            action.command = "pair";
            action.watch_pairing = true;
        } else if (legacy_list) {
            action.command = "list";
        } else if (legacy_status) {
            action.command = "status";
        } else if (!legacy_start.empty()) {
            action.command = "start";
            action.args["device"] = legacy_start;
        } else if (app.count("--stop") > 0) {
            action.command = "stop";
            if (!legacy_stop.empty())
                action.args["device"] = legacy_stop;
        }
    }

    if (action.command.empty()) {
        std::cerr << "trill: no command given\n\n" << app.help();
        return 2;
    }

    std::filesystem::path path;
    if (!socket_path.empty()) {
        path = socket_path;
    } else {
        auto paths = ar::resolve_paths();
        if (!paths)
            return finish(paths.error(), as_json);
        path = paths->socket_path;
    }
    return run(action, path, as_json);
}
