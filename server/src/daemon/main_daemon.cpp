// SPDX-License-Identifier: MIT
#include "daemon/daemon.hpp"

#include <CLI/CLI.hpp>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    CLI::App app{"trilld: PipeWire audio to a paired phone over Roc", "trilld"};
    app.set_version_flag("--version", TRILL_VERSION);

    ar::DaemonOptions options;
    std::string config_path;
    std::string log_level;
    int control_port = 0;
    int mic_source_port = 0;
    int mic_repair_port = 0;
    std::vector<std::string> debug_send;

    app.add_option("--config", config_path, "Path to config.toml");
    app.add_option("--control-port", control_port, "Override daemon.control_port");
    app.add_option("--mic-source-port", mic_source_port, "Override daemon.mic_source_port");
    app.add_option("--mic-repair-port", mic_repair_port, "Override daemon.mic_repair_port");
    app.add_option("--log-level", log_level, "Override log.level");
    app.add_flag("--no-default-switch", options.no_default_switch,
                 "Never change the PipeWire default sink");
    app.add_option("--debug-send", debug_send,
                   "Send the sink to <ip> <source_port> <repair_port> without a control plane")
        ->expected(3)
        ->group("");
#ifdef TRILL_ENABLE_DEV_PAIRING
    app.add_flag("--insecure-dev-pairing", options.insecure_dev_pairing,
                 "Accept method=dev-plain pairing (debug builds only)");
#endif

    CLI11_PARSE(app, argc, argv);

    if (!config_path.empty())
        options.config_path = config_path;
    if (!log_level.empty())
        options.log_level = log_level;
    if (control_port != 0) {
        if (control_port < 1 || control_port > 65535) {
            std::cerr << "trilld: --control-port must be 1..65535\n";
            return 2;
        }
        options.control_port = static_cast<std::uint16_t>(control_port);
    }
    if (mic_source_port != 0) {
        options.mic_source_port = static_cast<std::uint16_t>(mic_source_port);
    }
    if (mic_repair_port != 0) {
        options.mic_repair_port = static_cast<std::uint16_t>(mic_repair_port);
    }
    if (!debug_send.empty()) {
        options.debug_send = true;
        options.debug_ip = debug_send[0];
        try {
            options.debug_source_port = static_cast<std::uint16_t>(std::stoi(debug_send[1]));
            options.debug_repair_port = static_cast<std::uint16_t>(std::stoi(debug_send[2]));
        } catch (const std::exception&) {
            std::cerr << "trilld: --debug-send ports must be integers\n";
            return 2;
        }
        if (options.debug_source_port == 0 || options.debug_repair_port == 0) {
            std::cerr << "trilld: --debug-send ports must be 1..65535\n";
            return 2;
        }
        if (auto result = ar::Daemon::run_debug_send(options); !result) {
            std::cerr << "trilld: " << result.error().message << '\n';
            return 1;
        }
        return 0;
    }

    ar::Daemon daemon(std::move(options));
    if (auto result = daemon.start(); !result) {
        std::cerr << "trilld: " << result.error().message << '\n';
        return 1;
    }
    daemon.run();
    return 0;
}
