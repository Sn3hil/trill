// SPDX-License-Identifier: MIT
#pragma once

#include "audio/capture_backend.hpp"
#include "common/error.hpp"

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <pipewire/pipewire.h>
#include <string>

namespace ar {

struct SourceOptions {
    std::string name{"trill-mic"};
    std::string description{"Trill Microphone"};
};

// PipeWire virtual source node (media.class=Audio/Source, direction=PW_DIRECTION_OUTPUT).
// Applications on PC see this node as a recording device (microphone).
class PwSource {
  public:
    using PullCallback = std::function<std::size_t(float* samples, std::size_t sample_count)>;

    explicit PwSource(SourceOptions options = {});
    ~PwSource();

    PwSource(const PwSource&) = delete;
    PwSource& operator=(const PwSource&) = delete;

    Result<void> start(CaptureFormat format, PullCallback on_pull);
    void stop();

    [[nodiscard]] bool running() const {
        return running_.load();
    }

    [[nodiscard]] std::uint64_t callback_count() const {
        return callback_count_.load();
    }

  private:
    static void on_process(void* userdata);
    static void on_state_changed(void* userdata, pw_stream_state old_state, pw_stream_state state,
                                 const char* error);
    Result<void> create_stream();

    SourceOptions options_;
    CaptureFormat format_{};
    PullCallback on_pull_;
    std::atomic<bool> running_{false};
    std::atomic<std::uint64_t> callback_count_{0};

    pw_thread_loop* loop_{nullptr};
    pw_context* context_{nullptr};
    pw_core* core_{nullptr};
    pw_stream* stream_{nullptr};
    spa_hook stream_listener_{};
};

} // namespace ar
