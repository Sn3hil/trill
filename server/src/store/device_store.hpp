// SPDX-License-Identifier: MIT
#pragma once

#include "common/error.hpp"

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace ar {

struct Device {
    std::string id;        // 64 lowercase hex chars (SPKI SHA-256)
    std::string name;      // editable label
    std::string paired_at; // ISO-8601 Z
    std::string last_seen; // ISO-8601 Z
    std::string last_ip;
};

// devices.json: public-key hashes only. Never contains secrets, but is still
// written with mode 0600.
class DeviceStore {
  public:
    static Result<DeviceStore> load(const std::filesystem::path& path);

    // Persist atomically. No-op when clean.
    Result<void> save();

    [[nodiscard]] const std::vector<Device>& devices() const {
        return devices_;
    }
    [[nodiscard]] bool empty() const {
        return devices_.empty();
    }
    [[nodiscard]] std::size_t size() const {
        return devices_.size();
    }

    [[nodiscard]] const Device* find_by_id(const std::string& id) const;

    // Resolve by full/prefix id first, then case-insensitive name.
    // Returns ErrorCode::not_found or ErrorCode::ambiguous.
    [[nodiscard]] Result<std::size_t> resolve(const std::string& selector) const;
    [[nodiscard]] std::vector<Device> matches(const std::string& selector) const;

    // Insert or update a paired device. Keeps paired_at on update.
    Result<std::size_t> upsert(const std::string& id, const std::string& name,
                               const std::string& ip);

    Result<void> touch(const std::string& id, const std::string& ip);
    Result<void> rename(const std::string& id, const std::string& name);
    Result<void> remove(const std::string& id);

  private:
    explicit DeviceStore(std::filesystem::path path) : path_(std::move(path)) {}
    Result<void> write() const;

    std::filesystem::path path_;
    std::vector<Device> devices_;
};

} // namespace ar
