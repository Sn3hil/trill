// SPDX-License-Identifier: MIT
#include "ipc/ipc_protocol.hpp"

namespace ar::ipc {

Result<Request> parse_request(std::string_view line) {
    nlohmann::json root = nlohmann::json::parse(line.begin(), line.end(), nullptr, false);
    if (root.is_discarded() || !root.is_object()) {
        return fail(ErrorCode::bad_request, "IPC request is not a JSON object");
    }
    Request request;
    const auto id = root.find("id");
    if (id == root.end() || !id->is_number_integer()) {
        return fail(ErrorCode::bad_request, "IPC request has no integer id");
    }
    request.id = id->get<std::uint64_t>();
    const auto cmd = root.find("cmd");
    if (cmd == root.end() || !cmd->is_string()) {
        return fail(ErrorCode::bad_request, "IPC request has no cmd");
    }
    request.cmd = cmd->get<std::string>();
    if (const auto args = root.find("args"); args != root.end()) {
        if (!args->is_object()) {
            return fail(ErrorCode::bad_request, "IPC args must be an object");
        }
        request.args = *args;
    } else {
        request.args = nlohmann::json::object();
    }
    return request;
}

std::string ok(std::uint64_t id, nlohmann::json result) {
    if (result.is_null())
        result = nlohmann::json::object();
    return nlohmann::json{{"re", id}, {"ok", true}, {"result", std::move(result)}}.dump();
}

std::string error(std::uint64_t id, const Error& err, nlohmann::json extra) {
    // Local IPC keeps the full error taxonomy (not_found, ambiguous,
    // phone_not_connected, ...), which the CLI maps to exit codes.
    nlohmann::json body{{"code", std::string(to_string(err.code))}, {"message", err.message}};
    if (extra.is_object()) {
        for (auto it = extra.begin(); it != extra.end(); ++it)
            body[it.key()] = it.value();
    }
    return nlohmann::json{{"re", id}, {"ok", false}, {"error", std::move(body)}}.dump();
}

std::string event(std::string_view name, nlohmann::json fields) {
    nlohmann::json root = nlohmann::json::object();
    root["event"] = name;
    if (fields.is_object()) {
        for (auto it = fields.begin(); it != fields.end(); ++it)
            root[it.key()] = it.value();
    }
    return root.dump();
}

} // namespace ar::ipc
