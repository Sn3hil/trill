// SPDX-License-Identifier: MIT
#pragma once

#include "audio/pw_sink.hpp"
#include "audio/ring_buffer.hpp"
#include "audio/roc_sender.hpp"
#include "common/error.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

namespace ar {

struct PipelineSettings {
    SinkOptions sink;
    int packet_ms{5};
    int fec_block_source{18};
    int fec_block_repair{10};
    int rate_hz{48000};
    int channels{2};
    bool sink_per_session{true};
};

struct StreamParams {
    std::string peer_ip;
    std::uint16_t source_port{0};
    std::uint16_t repair_port{0};
};

struct PipelineStats {
    std::uint64_t frames_sent{0};
    std::uint64_t ring_overrun_samples{0};
    std::uint64_t ring_underrun_frames{0};
    std::uint64_t write_errors{0};
    std::size_t ring_available_samples{0};
    std::size_t ring_capacity_samples{0};
    bool capture_running{false};
    bool streaming{false};
};

// Capture -> lock-free ring -> sender thread -> one Roc sender per peer.
// The sender thread is the only consumer; the RT callback is the only producer.
class StreamPipeline {
  public:
    explicit StreamPipeline(PipelineSettings settings);
    ~StreamPipeline();

    StreamPipeline(const StreamPipeline&) = delete;
    StreamPipeline& operator=(const StreamPipeline&) = delete;

    // Start capture without a stream (used when sink_lifetime = "daemon").
    [[nodiscard]] Result<void> start_sink();

    [[nodiscard]] Result<void> start(const StreamParams& params);
    void stop();

    [[nodiscard]] bool running() const {
        return running_.load();
    }
    [[nodiscard]] bool sink_running() const {
        return sink_.running();
    }
    [[nodiscard]] PipelineStats stats() const;

    [[nodiscard]] int rate_hz() const {
        return settings_.rate_hz;
    }
    [[nodiscard]] int channels() const {
        return settings_.channels;
    }

  private:
    void on_capture(const float* samples, std::size_t count);
    void sender_loop();

    PipelineSettings settings_;
    FloatRingBuffer ring_;
    PwSink sink_;
    RocContext context_;
    std::vector<RocSender> senders_;
    std::thread sender_thread_;
    std::atomic<bool> running_{false};

    std::atomic<std::uint64_t> frames_sent_{0};
    std::atomic<std::uint64_t> overrun_samples_{0};
    std::atomic<std::uint64_t> underrun_frames_{0};
    std::atomic<std::uint64_t> write_errors_{0};
    std::atomic<std::uint64_t> callback_count_{0};
};

} // namespace ar
