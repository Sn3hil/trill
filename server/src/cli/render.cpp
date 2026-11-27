// SPDX-License-Identifier: MIT
#include "cli/render.hpp"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

namespace ar::render {

std::string pairing_code(std::string_view code) {
    std::string out(code);
    if (out.size() == 6)
        out.insert(3, " ");
    return out;
}

std::string short_device_id(std::string_view id) {
    return std::string(id.substr(0, std::min<std::size_t>(8, id.size())));
}

void print_json(const nlohmann::json& value) {
    std::cout << value.dump(2) << '\n';
}

void print_error(const Error& error, bool json) {
    if (json) {
        print_json(nlohmann::json{{"ok", false},
                                  {"error", nlohmann::json{{"code", to_string(error.code)},
                                                           {"message", error.message}}}});
        return;
    }
    std::cerr << "trill: " << error.message << '\n';
}

void print_device_list(const nlohmann::json& result) {
    const auto devices = result.find("devices");
    if (devices == result.end() || !devices->is_array() || devices->empty()) {
        std::cout << "No paired phones. Run 'trill pair'.\n";
        return;
    }
    std::cout << std::left << std::setw(10) << "ID" << std::setw(24) << "NAME" << std::setw(22)
              << "LAST SEEN" << "STATE\n";
    for (const auto& device : *devices) {
        std::string state = device.value("state", std::string("offline"));
        if (device.value("streaming", false))
            state = "streaming";
        std::cout << std::left << std::setw(10) << device.value("id8", std::string())
                  << std::setw(24) << device.value("name", std::string()) << std::setw(22)
                  << device.value("last_seen", std::string("-")) << state << '\n';
    }
}

void print_status(const nlohmann::json& result) {
    const auto host = result.value("host", nlohmann::json::object());
    const auto sink = result.value("sink", nlohmann::json::object());
    const auto stream = result.value("stream", nlohmann::json::object());
    const auto pairing = result.value("pairing", nlohmann::json::object());
    const auto sessions = result.value("sessions", nlohmann::json::array());

    std::cout << "Host:      " << host.value("name", std::string("trill"));
    if (host.contains("version"))
        std::cout << " (trilld " << host.value("version", std::string()) << ")";
    if (host.contains("id16"))
        std::cout << " id " << host.value("id16", std::string());
    std::cout << '\n';

    std::cout << "Sink:      " << sink.value("name", std::string("trill"))
              << (sink.value("available", false) ? " (available)" : " (unavailable)") << '\n';

    const bool streaming = result.value("streaming", false);
    std::cout << "Streaming: " << (streaming ? "yes" : "no");
    if (streaming) {
        std::cout << " (stream " << result.value("stream_id", 0) << ")";
    }
    std::cout << '\n';

    if (pairing.value("open", false)) {
        std::cout << "Pairing:   open for " << pairing.value("seconds_remaining", 0) << "s ("
                  << pairing.value("attempts_remaining", 0) << " attempts left)\n";
    } else if (pairing.value("locked", false)) {
        std::cout << "Pairing:   locked\n";
    } else {
        std::cout << "Pairing:   closed\n";
    }

    if (!sessions.empty()) {
        std::cout << "\nSessions:\n";
        for (const auto& session : sessions) {
            std::cout << "  " << short_device_id(session.value("device_id", std::string())) << "  "
                      << std::left << std::setw(22) << session.value("name", std::string())
                      << std::right << std::setw(16) << session.value("peer_ip", std::string())
                      << "  " << session.value("state", std::string()) << '\n';
        }
    }

    std::cout << "\nAudio:     frames=" << stream.value("frames_sent", std::uint64_t{0})
              << " overruns=" << stream.value("ring_overrun_samples", std::uint64_t{0})
              << " underruns=" << stream.value("ring_underrun_frames", std::uint64_t{0})
              << " write_errors=" << stream.value("write_errors", std::uint64_t{0}) << '\n';

    if (result.contains("mic")) {
        const auto mic = result["mic"];
        std::cout << "Mic:       " << (mic.value("running", false) ? "active" : "idle")
                  << " frames=" << mic.value("frames_received", std::uint64_t{0})
                  << " errors=" << mic.value("read_errors", std::uint64_t{0}) << '\n';
    }
}

} // namespace ar::render
