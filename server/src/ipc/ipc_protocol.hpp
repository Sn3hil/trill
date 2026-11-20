// SPDX-License-Identifier: MIT
#pragma once

#include "common/error.hpp"

#include <cstdint>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>

namespace ar::ipc {

struct Request {
    std::uint64_t id{0};
    std::string cmd;
    nlohmann::json args;
};

[[nodiscard]] Result<Request> parse_request(std::string_view line);

[[nodiscard]] std::string ok(std::uint64_t id, nlohmann::json result = {});
[[nodiscard]] std::string error(std::uint64_t id, const Error& err, nlohmann::json extra = {});
[[nodiscard]] std::string event(std::string_view name, nlohmann::json fields = {});

} // namespace ar::ipc
