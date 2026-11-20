// SPDX-License-Identifier: MIT
#pragma once

#include "common/error.hpp"

#include <nlohmann/json.hpp>
#include <string>
#include <string_view>

namespace ar::render {

[[nodiscard]] std::string pairing_code(std::string_view code);
[[nodiscard]] std::string short_device_id(std::string_view id);

void print_json(const nlohmann::json& value);
void print_error(const Error& error, bool json);

void print_device_list(const nlohmann::json& result);
void print_status(const nlohmann::json& result);

} // namespace ar::render
