// SPDX-License-Identifier: MIT
#include "store/config.hpp"

#include "common/paths.hpp"

#include <algorithm>
#include <cctype>
#include <string_view>
#include <toml++/toml.hpp>

namespace ar {
namespace {

std::string lower(std::string_view value) {
    std::string out(value);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

} // namespace

Config Config::defaults() {
    return Config{};
}

Result<Config> Config::load(const std::filesystem::path& path) {
    Config cfg;
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        return cfg;
    }

    toml::table table;
    try {
        table = toml::parse_file(path.string());
    } catch (const toml::parse_error& err) {
        return fail(ErrorCode::invalid_argument,
                    "config parse error: " + std::string(err.description()));
    }

    auto get_int = [&](std::string_view section, std::string_view key,
                       auto& target) -> Result<void> {
        if (const auto* node = table[section][key].as_integer()) {
            target = static_cast<std::remove_reference_t<decltype(target)>>(node->get());
        } else if (table[section][key]) {
            return fail(ErrorCode::invalid_argument, "config " + std::string(section) + "." +
                                                         std::string(key) + " must be an integer");
        }
        return {};
    };
    auto get_bool = [&](std::string_view section, std::string_view key,
                        bool& target) -> Result<void> {
        if (const auto* node = table[section][key].as_boolean()) {
            target = node->get();
        } else if (table[section][key]) {
            return fail(ErrorCode::invalid_argument, "config " + std::string(section) + "." +
                                                         std::string(key) + " must be a boolean");
        }
        return {};
    };
    auto get_string = [&](std::string_view section, std::string_view key,
                          std::string& target) -> Result<void> {
        if (const auto* node = table[section][key].as_string()) {
            target = node->get();
        } else if (table[section][key]) {
            return fail(ErrorCode::invalid_argument, "config " + std::string(section) + "." +
                                                         std::string(key) + " must be a string");
        }
        return {};
    };

    int port = cfg.daemon.control_port;
    if (auto r = get_int("daemon", "control_port", port); !r)
        return std::unexpected(r.error());
    cfg.daemon.control_port = static_cast<std::uint16_t>(std::clamp(port, 1, 65535));

    if (auto r = get_int("pairing", "window_seconds", cfg.pairing.window_seconds); !r)
        return std::unexpected(r.error());
    if (auto r = get_int("pairing", "max_attempts", cfg.pairing.max_attempts); !r)
        return std::unexpected(r.error());

    if (auto r = get_string("audio", "sink_name", cfg.audio.sink_name); !r)
        return std::unexpected(r.error());
    if (auto r = get_string("audio", "sink_description", cfg.audio.sink_description); !r)
        return std::unexpected(r.error());
    if (auto r = get_string("audio", "sink_lifetime", cfg.audio.sink_lifetime); !r)
        return std::unexpected(r.error());
    if (auto r = get_bool("audio", "auto_default_sink", cfg.audio.auto_default_sink); !r)
        return std::unexpected(r.error());

    if (auto r = get_int("stream", "packet_ms", cfg.stream.packet_ms); !r)
        return std::unexpected(r.error());
    if (auto r = get_int("stream", "fec_block_source", cfg.stream.fec_block_source); !r)
        return std::unexpected(r.error());
    if (auto r = get_int("stream", "fec_block_repair", cfg.stream.fec_block_repair); !r)
        return std::unexpected(r.error());
    if (auto r = get_string("stream", "silence_policy", cfg.stream.silence_policy); !r)
        return std::unexpected(r.error());

    if (auto r = get_string("log", "level", cfg.log.level); !r)
        return std::unexpected(r.error());

    if (auto r = cfg.validate(); !r)
        return std::unexpected(r.error());
    return cfg;
}

Result<void> Config::validate() const {
    if (daemon.control_port == 0) {
        return fail(ErrorCode::invalid_argument, "daemon.control_port must be 1..65535");
    }
    if (pairing.window_seconds < 1 || pairing.window_seconds > 120) {
        return fail(ErrorCode::invalid_argument, "pairing.window_seconds must be 1..120");
    }
    if (pairing.max_attempts < 1 || pairing.max_attempts > 10) {
        return fail(ErrorCode::invalid_argument, "pairing.max_attempts must be 1..10");
    }
    if (audio.sink_name.empty()) {
        return fail(ErrorCode::invalid_argument, "audio.sink_name must not be empty");
    }
    const auto lifetime = lower(audio.sink_lifetime);
    if (lifetime != "session" && lifetime != "daemon") {
        return fail(ErrorCode::invalid_argument,
                    "audio.sink_lifetime must be \"session\" or \"daemon\"");
    }
    if (stream.packet_ms < 1 || stream.packet_ms > 50) {
        return fail(ErrorCode::invalid_argument, "stream.packet_ms must be 1..50");
    }
    if (stream.fec_block_source < 1 || stream.fec_block_source > 255 ||
        stream.fec_block_repair < 0 || stream.fec_block_repair > 255) {
        return fail(ErrorCode::invalid_argument, "stream FEC block sizes out of range");
    }
    const auto policy = lower(stream.silence_policy);
    if (policy != "continuous" && policy != "suspend") {
        return fail(ErrorCode::invalid_argument,
                    "stream.silence_policy must be \"continuous\" or \"suspend\"");
    }
    return {};
}

} // namespace ar
