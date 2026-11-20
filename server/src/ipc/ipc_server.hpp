// SPDX-License-Identifier: MIT
#pragma once

#include "common/error.hpp"
#include "ipc/ipc_protocol.hpp"

#include <asio.hpp>
#include <atomic>
#include <deque>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ar {

// Newline-delimited JSON over a Unix socket in XDG_RUNTIME_DIR.
class IpcServer {
  public:
    using Handler = std::function<Result<nlohmann::json>(const ipc::Request&)>;

    IpcServer(asio::io_context& io, std::filesystem::path socket_path);
    ~IpcServer();

    IpcServer(const IpcServer&) = delete;
    IpcServer& operator=(const IpcServer&) = delete;

    [[nodiscard]] Result<void> start();
    void stop();

    void set_handler(Handler handler) {
        handler_ = std::move(handler);
    }

    void broadcast(std::string_view event, nlohmann::json fields = {});
    [[nodiscard]] std::size_t connection_count() const {
        return connection_count_.load(std::memory_order_relaxed);
    }

  private:
    struct Connection : public std::enable_shared_from_this<Connection> {
        Connection(asio::local::stream_protocol::socket socket, IpcServer& server);
        void start();
        void read_next();
        void send(std::string line);
        void close();
        void do_write();

        asio::local::stream_protocol::socket socket;
        IpcServer& server;
        asio::streambuf buffer{65536};
        std::deque<std::string> write_queue;
        bool writing{false};
        bool closed{false};
    };

    void do_accept();
    void remove(const std::shared_ptr<Connection>& connection);

    asio::io_context& io_;
    std::filesystem::path socket_path_;
    asio::local::stream_protocol::acceptor acceptor_;
    Handler handler_;
    std::vector<std::shared_ptr<Connection>> connections_;
    std::atomic<std::size_t> connection_count_{0};
    bool running_{false};
};

} // namespace ar
