// SPDX-License-Identifier: MIT
#include "common/paths.hpp"

#include <cerrno>
#include <chrono>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace ar {
namespace {

std::filesystem::path home_dir() {
    if (const char* home = ::getenv("HOME"); home != nullptr && *home != '\0') {
        return home;
    }
    return "/tmp";
}

std::filesystem::path xdg_dir(const char* env, const std::filesystem::path& fallback) {
    if (const char* value = ::getenv(env); value != nullptr && *value != '\0') {
        return value;
    }
    return fallback;
}

Result<void> chmod_path(const std::filesystem::path& path, unsigned mode) {
    if (::chmod(path.c_str(), static_cast<mode_t>(mode)) != 0) {
        return fail(ErrorCode::permission_denied,
                    "chmod " + path.string() + ": " + std::strerror(errno));
    }
    return {};
}

} // namespace

Result<Paths> resolve_paths() {
    Paths p;
    const auto home = home_dir();
    p.config_dir = xdg_dir("XDG_CONFIG_HOME", home / ".config") / "trill";
    p.state_dir = xdg_dir("XDG_STATE_HOME", home / ".local" / "state") / "trill";
    p.runtime_dir = xdg_dir("XDG_RUNTIME_DIR", std::filesystem::path("/tmp") /
                                                   ("user-" + std::to_string(::getuid()))) /
                    "trill";
    p.identity_dir = p.config_dir / "identity";
    p.config_file = p.config_dir / "config.toml";
    p.devices_file = p.config_dir / "devices.json";
    p.prev_default_file = p.state_dir / "prev_default.json";
    p.socket_path = p.runtime_dir / "ctl.sock";
    p.log_file = p.state_dir / "trilld.log";
    return p;
}

Result<void> ensure_dir(const std::filesystem::path& dir, unsigned mode) {
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) {
        return fail(ErrorCode::io_error, "create " + dir.string() + ": " + ec.message());
    }
    return chmod_path(dir, mode);
}

Result<void> write_file_atomic(const std::filesystem::path& path, const std::string& content,
                               unsigned mode) {
    std::error_code ec;
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path(), ec);
        if (ec) {
            return fail(ErrorCode::io_error,
                        "create " + path.parent_path().string() + ": " + ec.message());
        }
    }

    auto tmp = path;
    tmp += ".tmp." + std::to_string(::getpid());

    const int fd =
        ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, static_cast<mode_t>(mode));
    if (fd < 0) {
        return fail(ErrorCode::io_error, "open " + tmp.string() + ": " + std::strerror(errno));
    }

    std::size_t off = 0;
    while (off < content.size()) {
        const ssize_t n = ::write(fd, content.data() + off, content.size() - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            const std::string msg = std::strerror(errno);
            ::close(fd);
            ::unlink(tmp.c_str());
            return fail(ErrorCode::io_error, "write " + tmp.string() + ": " + msg);
        }
        off += static_cast<std::size_t>(n);
    }
    if (::fchmod(fd, static_cast<mode_t>(mode)) != 0 || ::fsync(fd) != 0) {
        const std::string msg = std::strerror(errno);
        ::close(fd);
        ::unlink(tmp.c_str());
        return fail(ErrorCode::io_error, "fsync " + tmp.string() + ": " + msg);
    }
    ::close(fd);

    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        const std::string msg = std::strerror(errno);
        ::unlink(tmp.c_str());
        return fail(ErrorCode::io_error, "rename " + path.string() + ": " + msg);
    }

    if (path.has_parent_path()) {
        const int dfd = ::open(path.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (dfd >= 0) {
            ::fsync(dfd);
            ::close(dfd);
        }
    }
    return {};
}

Result<std::string> read_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return fail(ErrorCode::not_found, "cannot read " + path.string());
    }
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (!in.good() && !in.eof()) {
        return fail(ErrorCode::io_error, "read " + path.string());
    }
    return content;
}

Result<void> remove_file(const std::filesystem::path& path) {
    std::error_code ec;
    std::filesystem::remove(path, ec);
    if (ec) {
        return fail(ErrorCode::io_error, "remove " + path.string() + ": " + ec.message());
    }
    return {};
}

std::string utc_now_iso8601() {
    const auto now = std::chrono::system_clock::now();
    const auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    ::gmtime_r(&time, &tm);
    char buf[32]{};
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

} // namespace ar
