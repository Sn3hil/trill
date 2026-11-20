// SPDX-License-Identifier: MIT
#include "cli/ipc_client.hpp"

#include "ipc/ipc_protocol.hpp"

#include <istream>
#include <string>
#include <utility>

namespace ar {

ErrorCode error_code_from_name(std::string_view name) {
    const auto same = [name](std::string_view value) { return name == value; };
    if (same("ok"))
        return ErrorCode::ok;
    if (same("bad_request"))
        return ErrorCode::bad_request;
    if (same("unsupported"))
        return ErrorCode::unsupported;
    if (same("version_mismatch"))
        return ErrorCode::version_mismatch;
    if (same("pair_closed"))
        return ErrorCode::pair_closed;
    if (same("pair_failed"))
        return ErrorCode::pair_failed;
    if (same("pair_locked"))
        return ErrorCode::pair_locked;
    if (same("busy"))
        return ErrorCode::busy;
    if (same("not_paired"))
        return ErrorCode::not_paired;
    if (same("no_sink"))
        return ErrorCode::no_sink;
    if (same("stream_failed"))
        return ErrorCode::stream_failed;
    if (same("invalid_argument"))
        return ErrorCode::invalid_argument;
    if (same("io_error"))
        return ErrorCode::io_error;
    if (same("not_found"))
        return ErrorCode::not_found;
    if (same("ambiguous"))
        return ErrorCode::ambiguous;
    if (same("permission_denied"))
        return ErrorCode::permission_denied;
    if (same("crypto_error"))
        return ErrorCode::crypto_error;
    if (same("protocol_error"))
        return ErrorCode::protocol_error;
    if (same("timeout"))
        return ErrorCode::timeout;
    if (same("daemon_not_running"))
        return ErrorCode::daemon_not_running;
    if (same("phone_not_connected"))
        return ErrorCode::phone_not_connected;
    return ErrorCode::internal;
}

IpcClient::IpcClient() : socket_(io_) {}

IpcClient::~IpcClient() {
    close();
}

Result<std::unique_ptr<IpcClient>> IpcClient::connect(const std::filesystem::path& socket_path) {
    std::error_code ec;
    if (!std::filesystem::exists(socket_path, ec)) {
        return fail(ErrorCode::daemon_not_running,
                    "daemon is not running (no socket at " + socket_path.string() + ")");
    }
    auto client = std::unique_ptr<IpcClient>(new IpcClient());
    client->socket_.connect(asio::local::stream_protocol::endpoint(socket_path.string()), ec);
    if (ec) {
        return fail(ErrorCode::daemon_not_running, "cannot connect to the daemon: " + ec.message());
    }
    return client;
}

Result<nlohmann::json> IpcClient::read_message() {
    std::error_code ec;
    asio::read_until(socket_, buffer_, '\n', ec);
    if (ec) {
        return fail(ErrorCode::io_error, "daemon connection closed: " + ec.message());
    }
    std::istream input(&buffer_);
    std::string line;
    std::getline(input, line);
    if (!line.empty() && line.back() == '\r')
        line.pop_back();
    auto root = nlohmann::json::parse(line.begin(), line.end(), nullptr, false);
    if (root.is_discarded() || !root.is_object()) {
        return fail(ErrorCode::protocol_error, "daemon sent invalid JSON");
    }
    return root;
}

Result<nlohmann::json> IpcClient::call(std::string_view command, nlohmann::json args,
                                       const EventHandler& on_event) {
    const std::uint64_t id = next_id_++;
    nlohmann::json request{{"id", id}, {"cmd", command}};
    if (!args.is_null())
        request["args"] = std::move(args);

    std::string line = request.dump();
    line.push_back('\n');
    std::error_code ec;
    asio::write(socket_, asio::buffer(line), ec);
    if (ec) {
        return fail(ErrorCode::daemon_not_running, "cannot write to the daemon: " + ec.message());
    }

    while (true) {
        auto message = read_message();
        if (!message)
            return std::unexpected(message.error());
        if (const auto event = message->find("event"); event != message->end()) {
            if (on_event)
                on_event(*message);
            continue;
        }
        const auto re = message->find("re");
        if (re == message->end() || !re->is_number_integer()) {
            return fail(ErrorCode::protocol_error, "daemon sent a message without 're'");
        }
        if (re->get<std::uint64_t>() != id)
            continue;
        if (message->value("ok", false)) {
            const auto result = message->find("result");
            return result == message->end() ? nlohmann::json::object() : *result;
        }
        const auto error = message->find("error");
        if (error == message->end() || !error->is_object()) {
            return fail(ErrorCode::internal, "daemon reported an unknown error");
        }
        ErrorCode code = error_code_from_name(error->value("code", std::string()));
        std::string text = error->value("message", std::string("command failed"));
        return fail(code, std::move(text));
    }
}

void IpcClient::close() {
    std::error_code ec;
    socket_.close(ec);
}

} // namespace ar
