// SPDX-License-Identifier: MIT
#pragma once

#include "common/error.hpp"

#include <map>
#include <mutex>
#include <pipewire/extensions/metadata.h>
#include <pipewire/pipewire.h>
#include <string>
#include <string_view>

namespace ar {

// Saves and restores the user's default sink through PipeWire's "default"
// metadata object (WirePlumber honours default.configured.audio.sink). The
// daemon writes a crash-recovery file before switching and restores it on the
// next start if it exists.
class DefaultSinkGuard {
  public:
    using Snapshot = std::map<std::string, std::string>;

    DefaultSinkGuard();
    ~DefaultSinkGuard();

    DefaultSinkGuard(const DefaultSinkGuard&) = delete;
    DefaultSinkGuard& operator=(const DefaultSinkGuard&) = delete;

    // Connect and capture the current metadata values.
    [[nodiscard]] Result<void> start();
    void stop();
    [[nodiscard]] bool available() const {
        return metadata_ != nullptr;
    }

    [[nodiscard]] Snapshot snapshot() const;

    [[nodiscard]] Result<void> set_default_sink(std::string_view sink_name);
    [[nodiscard]] Result<void> restore(const Snapshot& snapshot);

    [[nodiscard]] static std::string serialize(const Snapshot& snapshot);
    [[nodiscard]] static Result<Snapshot> parse(std::string_view json);

  private:
    static void on_global(void* data, std::uint32_t id, std::uint32_t permissions, const char* type,
                          std::uint32_t version, const spa_dict* props);
    static int on_property(void* data, std::uint32_t subject, const char* key, const char* type,
                           const char* value);

    void handle_global(std::uint32_t id, const char* type, const spa_dict* props);
    void handle_property(const char* key, const char* value);
    void teardown();

    mutable std::mutex mutex_;
    Snapshot values_;

    pw_thread_loop* loop_{nullptr};
    pw_context* context_{nullptr};
    pw_core* core_{nullptr};
    pw_registry* registry_{nullptr};
    pw_metadata* metadata_{nullptr};
    spa_hook registry_listener_{};
    spa_hook metadata_listener_{};
};

} // namespace ar
