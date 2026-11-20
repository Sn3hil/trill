// SPDX-License-Identifier: MIT
#pragma once

#include "audio/capture_backend.hpp"
#include "common/error.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <pipewire/pipewire.h>
#include <string>

namespace ar {

struct SinkOptions {
    std::string name{"trill"};
    std::string description{"Trill"};
};

// A stream-owned PipeWire node with media.class=Audio/Sink. Because the
// stream owns the node, the sink disappears if the daemon dies: crash-safe by
// construction. The RT process callback only copies into the supplied callback.
class PwSink final : public CaptureBackend {
  public:
    explicit PwSink(SinkOptions options);
    ~PwSink() override;

    PwSink(const PwSink&) = delete;
    PwSink& operator=(const PwSink&) = delete;

    Result<void> start(CaptureFormat format, FrameCallback on_samples) override;
    void stop() override;
    [[nodiscard]] bool running() const override {
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

    SinkOptions options_;
    CaptureFormat format_{};
    FrameCallback on_samples_;
    std::atomic<bool> running_{false};
    std::atomic<std::uint64_t> callback_count_{0};

    pw_thread_loop* loop_{nullptr};
    pw_context* context_{nullptr};
    pw_core* core_{nullptr};
    pw_stream* stream_{nullptr};
    spa_hook stream_listener_{};
};

} // namespace ar
