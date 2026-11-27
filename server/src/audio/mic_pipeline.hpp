// SPDX-License-Identifier: MIT
#pragma once

#include "audio/pw_source.hpp"
#include "audio/ring_buffer.hpp"
#include "audio/roc_receiver.hpp"
#include "common/error.hpp"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>
#include <thread>

namespace ar {

struct MicPipelineSettings {
    SourceOptions source;
    int rate_hz{44100};
    int channels{2};
    int target_latency_ms{120};
};

struct MicBoundPorts {
    std::uint16_t source_port{0};
    std::uint16_t repair_port{0};
};

struct MicPipelineStats {
    std::uint64_t frames_received{0};
    std::uint64_t read_errors{0};
    std::size_t ring_available_samples{0};
    std::size_t ring_capacity_samples{0};
    bool source_running{false};
    bool streaming{false};
};

class MicPipeline {
  public:
    explicit MicPipeline(MicPipelineSettings settings = {});
    ~MicPipeline();

    MicPipeline(const MicPipeline&) = delete;
    MicPipeline& operator=(const MicPipeline&) = delete;

    [[nodiscard]] Result<MicBoundPorts> start(std::uint16_t source_port = 0,
                                             std::uint16_t repair_port = 0);
    void stop();

    [[nodiscard]] bool running() const {
        return running_.load();
    }
    [[nodiscard]] bool source_running() const {
        return source_.running();
    }
    [[nodiscard]] int rate_hz() const {
        return settings_.rate_hz;
    }
    [[nodiscard]] int channels() const {
        return settings_.channels;
    }
    [[nodiscard]] MicPipelineStats stats() const;

  private:
    void receiver_loop();
    std::size_t on_pull_samples(float* samples, std::size_t max_samples);

    MicPipelineSettings settings_;
    FloatRingBuffer ring_;
    PwSource source_;
    RocContext context_;
    RocReceiver receiver_;
    std::thread receiver_thread_;
    std::atomic<bool> running_{false};
    std::atomic<std::uint64_t> frames_received_{0};
    std::atomic<std::uint64_t> read_errors_{0};
};

} // namespace ar
