// SPDX-License-Identifier: MIT
#include "store/device_store.hpp"

#include "common/paths.hpp"

#include <algorithm>
#include <cctype>
#include <nlohmann/json.hpp>
#include <string_view>

namespace ar {
namespace {

nlohmann::json to_json(const Device& d) {
    return nlohmann::json{{"id", d.id},
                          {"name", d.name},
                          {"paired_at", d.paired_at},
                          {"last_seen", d.last_seen},
                          {"last_ip", d.last_ip}};
}

Device device_from_json(const nlohmann::json& j) {
    Device d;
    d.id = j.value("id", "");
    d.name = j.value("name", "");
    d.paired_at = j.value("paired_at", "");
    d.last_seen = j.value("last_seen", "");
    d.last_ip = j.value("last_ip", "");
    return d;
}

std::string lower(std::string_view value) {
    std::string out(value);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

bool is_hex(std::string_view value) {
    return std::all_of(value.begin(), value.end(),
                       [](unsigned char c) { return std::isxdigit(c) != 0; });
}

} // namespace

Result<DeviceStore> DeviceStore::load(const std::filesystem::path& path) {
    DeviceStore store(path);
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        return store;
    }
    auto content = read_file(path);
    if (!content)
        return std::unexpected(content.error());

    nlohmann::json root = nlohmann::json::parse(*content, nullptr, false);
    if (root.is_discarded() || !root.is_object()) {
        return fail(ErrorCode::invalid_argument, "devices.json is not a JSON object");
    }
    const int version = root.value("version", 0);
    if (version != 1) {
        return fail(ErrorCode::unsupported,
                    "unsupported devices.json version " + std::to_string(version));
    }
    const auto devices = root.find("devices");
    if (devices == root.end() || !devices->is_array()) {
        return fail(ErrorCode::invalid_argument, "devices.json has no devices array");
    }
    for (const auto& item : *devices) {
        if (!item.is_object()) {
            return fail(ErrorCode::invalid_argument, "devices.json entry is not an object");
        }
        Device d = device_from_json(item);
        if (d.id.size() != 64 || !is_hex(d.id)) {
            return fail(ErrorCode::invalid_argument, "devices.json id is not 64 hex chars");
        }
        if (d.name.empty())
            d.name = "Phone";
        store.devices_.push_back(std::move(d));
    }
    return store;
}

Result<void> DeviceStore::write() const {
    nlohmann::json devices = nlohmann::json::array();
    for (const auto& d : devices_)
        devices.push_back(to_json(d));
    nlohmann::json root{{"version", 1}, {"devices", std::move(devices)}};
    return write_file_atomic(path_, root.dump(2) + "\n", 0600);
}

Result<void> DeviceStore::save() {
    return write();
}

const Device* DeviceStore::find_by_id(const std::string& id) const {
    for (const auto& d : devices_) {
        if (d.id == id)
            return &d;
    }
    return nullptr;
}

std::vector<Device> DeviceStore::matches(const std::string& selector) const {
    std::vector<Device> out;
    if (selector.empty())
        return out;

    const std::string lowered = lower(selector);
    const bool hex_selector = is_hex(selector);

    if (hex_selector) {
        for (const auto& d : devices_) {
            if (d.id.starts_with(lowered))
                out.push_back(d);
        }
        if (!out.empty())
            return out;
    }

    for (const auto& d : devices_) {
        if (lower(d.name) == lowered)
            out.push_back(d);
    }
    return out;
}

Result<std::size_t> DeviceStore::resolve(const std::string& selector) const {
    if (selector.empty()) {
        return fail(ErrorCode::invalid_argument, "empty device selector");
    }
    const auto found = matches(selector);
    if (found.empty()) {
        return fail(ErrorCode::not_found, "no paired device matches '" + selector + "'");
    }
    if (found.size() > 1) {
        return fail(ErrorCode::ambiguous, "device selector '" + selector + "' matches " +
                                              std::to_string(found.size()) + " devices");
    }
    for (std::size_t i = 0; i < devices_.size(); ++i) {
        if (devices_[i].id == found.front().id)
            return i;
    }
    return fail(ErrorCode::not_found, "no paired device matches '" + selector + "'");
}

Result<std::size_t> DeviceStore::upsert(const std::string& id, const std::string& name,
                                        const std::string& ip) {
    if (id.size() != 64 || !is_hex(id)) {
        return fail(ErrorCode::invalid_argument, "device id must be 64 hex chars");
    }
    const std::string now = utc_now_iso8601();
    for (std::size_t i = 0; i < devices_.size(); ++i) {
        if (devices_[i].id == id) {
            if (!name.empty())
                devices_[i].name = name;
            devices_[i].last_seen = now;
            devices_[i].last_ip = ip;
            if (auto r = write(); !r)
                return std::unexpected(r.error());
            return i;
        }
    }
    Device d;
    d.id = id;
    d.name = name.empty() ? "Phone" : name;
    d.paired_at = now;
    d.last_seen = now;
    d.last_ip = ip;
    devices_.push_back(std::move(d));
    if (auto r = write(); !r)
        return std::unexpected(r.error());
    return devices_.size() - 1;
}

Result<void> DeviceStore::touch(const std::string& id, const std::string& ip) {
    for (auto& d : devices_) {
        if (d.id == id) {
            d.last_seen = utc_now_iso8601();
            if (!ip.empty())
                d.last_ip = ip;
            return write();
        }
    }
    return fail(ErrorCode::not_found, "device not found");
}

Result<void> DeviceStore::rename(const std::string& id, const std::string& name) {
    if (name.empty() || name.size() > 63) {
        return fail(ErrorCode::invalid_argument, "name must be 1..63 bytes");
    }
    for (auto& d : devices_) {
        if (d.id == id) {
            d.name = name;
            return write();
        }
    }
    return fail(ErrorCode::not_found, "device not found");
}

Result<void> DeviceStore::remove(const std::string& id) {
    const auto it =
        std::find_if(devices_.begin(), devices_.end(), [&](const Device& d) { return d.id == id; });
    if (it == devices_.end()) {
        return fail(ErrorCode::not_found, "device not found");
    }
    devices_.erase(it);
    return write();
}

} // namespace ar
