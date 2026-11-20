// SPDX-License-Identifier: MIT
#pragma once

#include "common/error.hpp"

#include <asio.hpp>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>

namespace ar {

// Synchronous NDJSON client for the daemon's Unix socket. The CLI is a
// one-shot process, so a blocking implementation keeps the code simple.
class IpcClient {
  public:
    ~IpcClient();

    IpcClient(const IpcClient&) = delete;
    IpcClient& operator=(const IpcClient&) = delete;

    [[nodiscard]] static Result<std::unique_ptr<IpcClient>>
    connect(const std::filesystem::path& socket_path);

    using EventHandler = std::function<void(const nlohmann::json&)>;

    // Sends one request and waits for its response. Events received in the
    // meantime are passed to on_event.
    [[nodiscard]] Result<nlohmann::json> call(std::string_view command, nlohmann::json args = {},
                                              const EventHandler& on_event = {});

    // Reads one newline-delimited message (event or response).
    [[nodiscard]] Result<nlohmann::json> read_message();

    void close();

  private:
    IpcClient();

    asio::io_context io_;
    asio::local::stream_protocol::socket socket_;
    asio::streambuf buffer_{65536};
    std::uint64_t next_id_{1};
};

// Maps the daemon's IPC error codes back to local ErrorCode values.
[[nodiscard]] ErrorCode error_code_from_name(std::string_view name);

} // namespace ar
