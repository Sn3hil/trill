// SPDX-License-Identifier: MIT
#include "ipc/ipc_server.hpp"

#include "common/log.hpp"
#include "common/paths.hpp"

#include <algorithm>
#include <sys/stat.h>
#include <unistd.h>

namespace ar {

using LocalSocket = asio::local::stream_protocol;

IpcServer::Connection::Connection(LocalSocket::socket socket_, IpcServer& server_)
    : socket(std::move(socket_)), server(server_) {}

void IpcServer::Connection::start() {
    read_next();
}

void IpcServer::Connection::read_next() {
    if (closed)
        return;
    auto self = shared_from_this();
    asio::async_read_until(
        socket, buffer, '\n', [self](const std::error_code& ec, std::size_t /*n*/) {
            if (ec) {
                self->server.remove(self);
                self->close();
                return;
            }
            std::istream stream(&self->buffer);
            std::string line;
            std::getline(stream, line);
            if (!line.empty() && line.back() == '\r')
                line.pop_back();

            auto request = ipc::parse_request(line);
            if (!request) {
                self->send(ipc::error(0, request.error()));
            } else {
                Result<nlohmann::json> result = fail(ErrorCode::unsupported, "unknown command");
                if (self->server.handler_) {
                    result = self->server.handler_(*request);
                }
                if (result) {
                    self->send(ipc::ok(request->id, std::move(*result)));
                } else {
                    self->send(ipc::error(request->id, result.error()));
                }
            }
            self->read_next();
        });
}

void IpcServer::Connection::send(std::string line) {
    auto self = shared_from_this();
    asio::post(socket.get_executor(), [self, line = std::move(line)]() mutable {
        if (self->closed)
            return;
        line.push_back('\n');
        self->write_queue.push_back(std::move(line));
        if (!self->writing)
            self->do_write();
    });
}

void IpcServer::Connection::do_write() {
    if (write_queue.empty() || closed)
        return;
    writing = true;
    auto self = shared_from_this();
    asio::async_write(socket, asio::buffer(write_queue.front()),
                      [self](const std::error_code& ec, std::size_t /*n*/) {
                          self->writing = false;
                          if (ec) {
                              self->server.remove(self);
                              self->close();
                              return;
                          }
                          if (!self->write_queue.empty()) {
                              self->write_queue.pop_front();
                          }
                          self->do_write();
                      });
}

void IpcServer::Connection::close() {
    if (closed)
        return;
    closed = true;
    std::error_code ec;
    socket.close(ec);
}

IpcServer::IpcServer(asio::io_context& io, std::filesystem::path socket_path)
    : io_(io), socket_path_(std::move(socket_path)), acceptor_(io) {}

IpcServer::~IpcServer() {
    stop();
}

Result<void> IpcServer::start() {
    auto parent = socket_path_.parent_path();
    if (auto r = ensure_dir(parent, 0700); !r)
        return r;

    std::error_code ec;
    std::filesystem::remove(socket_path_, ec);

    const std::string path = socket_path_.string();
    if (path.size() >= 100) {
        return fail(ErrorCode::invalid_argument, "IPC socket path is too long: " + path);
    }

    acceptor_.open(LocalSocket(), ec);
    if (ec)
        return fail(ErrorCode::io_error, "cannot open IPC socket: " + ec.message());
    acceptor_.bind(LocalSocket::endpoint(path), ec);
    if (ec) {
        return fail(ErrorCode::io_error, "cannot bind IPC socket: " + ec.message());
    }
    ::chmod(path.c_str(), 0600);
    acceptor_.listen(asio::socket_base::max_listen_connections, ec);
    if (ec)
        return fail(ErrorCode::io_error, "cannot listen on IPC socket: " + ec.message());

    running_ = true;
    logger()->debug("IPC listening on {}", path);
    do_accept();
    return {};
}

void IpcServer::stop() {
    running_ = false;
    connection_count_ = 0;
    std::error_code ec;
    acceptor_.close(ec);
    for (const auto& connection : connections_)
        connection->close();
    connections_.clear();
    std::filesystem::remove(socket_path_, ec);
}

void IpcServer::do_accept() {
    if (!running_)
        return;
    acceptor_.async_accept([this](const std::error_code& ec, LocalSocket::socket socket) {
        if (!running_)
            return;
        if (ec) {
            if (ec != asio::error::operation_aborted) {
                logger()->warn("IPC accept failed: {}", ec.message());
                do_accept();
            }
            return;
        }
        auto connection = std::make_shared<Connection>(std::move(socket), *this);
        connections_.push_back(connection);
        ++connection_count_;
        connection->start();
        do_accept();
    });
}

void IpcServer::remove(const std::shared_ptr<Connection>& connection) {
    auto it = std::find(connections_.begin(), connections_.end(), connection);
    if (it != connections_.end()) {
        connections_.erase(it);
        --connection_count_;
    }
}

void IpcServer::broadcast(std::string_view event, nlohmann::json fields) {
    std::string line = ipc::event(event, std::move(fields));
    asio::post(io_, [this, line = std::move(line)]() {
        for (const auto& connection : connections_)
            connection->send(line);
    });
}

} // namespace ar
