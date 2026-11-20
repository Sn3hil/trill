// SPDX-License-Identifier: MIT
#include "common/log.hpp"

#include <spdlog/pattern_formatter.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <stdexcept>
#include <sys/stat.h>
#include <vector>

namespace ar {
namespace {

std::shared_ptr<spdlog::logger> g_logger;

spdlog::level::level_enum parse_level(std::string_view level) {
    if (level == "trace")
        return spdlog::level::trace;
    if (level == "debug")
        return spdlog::level::debug;
    if (level == "info")
        return spdlog::level::info;
    if (level == "warn" || level == "warning")
        return spdlog::level::warn;
    if (level == "error")
        return spdlog::level::err;
    if (level == "off")
        return spdlog::level::off;
    return spdlog::level::info;
}

} // namespace

void init_logging(std::string_view level, const std::string& log_file, bool also_console) {
    std::vector<spdlog::sink_ptr> sinks;
    if (!log_file.empty()) {
        ::chmod(log_file.c_str(), 0600);
        auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(log_file, false);
        ::chmod(log_file.c_str(), 0600);
        sinks.push_back(file_sink);
    }
    if (also_console || sinks.empty()) {
        sinks.push_back(std::make_shared<spdlog::sinks::stderr_color_sink_mt>());
    }

    g_logger = std::make_shared<spdlog::logger>("trill", sinks.begin(), sinks.end());
    g_logger->set_level(parse_level(level));
    g_logger->flush_on(spdlog::level::warn);
    spdlog::register_logger(g_logger);
    spdlog::set_default_logger(g_logger);
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");
    spdlog::flush_every(std::chrono::seconds(2));
}

void shutdown_logging() {
    if (g_logger) {
        g_logger->flush();
        spdlog::drop(g_logger->name());
        g_logger.reset();
    }
}

std::shared_ptr<spdlog::logger> logger() {
    if (!g_logger) {
        // Safe fallback for tests and early startup.
        g_logger = spdlog::stderr_color_mt("trill");
        spdlog::set_default_logger(g_logger);
    }
    return g_logger;
}

std::string short_id(std::string_view hex_id) {
    if (hex_id.empty())
        return "<empty>";
    return std::string(hex_id.substr(0, std::min<std::size_t>(8, hex_id.size())));
}

} // namespace ar
