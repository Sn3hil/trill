// SPDX-License-Identifier: MIT
#pragma once

#include "common/error.hpp"

#include <cstdint>
#include <filesystem>
#include <string>

namespace ar {

struct DaemonConfig {
    std::uint16_t control_port{47800};
    std::uint16_t mic_source_port{47810};
    std::uint16_t mic_repair_port{47811};
};

struct PairingConfig {
    int window_seconds{30};
    int max_attempts{3};
};

struct AudioConfig {
    std::string sink_name{"trill"};
    std::string sink_description{"Trill"};
    std::string sink_lifetime{"session"}; // "session" | "daemon"
    bool auto_default_sink{true};
};

struct StreamConfig {
    int packet_ms{5};
    int fec_block_source{18};
    int fec_block_repair{10};
    std::string silence_policy{"continuous"};
};

struct LogConfig {
    std::string level{"info"};
};

struct Config {
    DaemonConfig daemon;
    PairingConfig pairing;
    AudioConfig audio;
    StreamConfig stream;
    LogConfig log;

    [[nodiscard]] static Config defaults();
    [[nodiscard]] static Result<Config> load(const std::filesystem::path& path);

    // Validates ranges and enum-like values. Called by load() and by tests.
    [[nodiscard]] Result<void> validate() const;
};

} // namespace ar
