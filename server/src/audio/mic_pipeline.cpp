// SPDX-License-Identifier: MIT
#include "audio/mic_pipeline.hpp"

#include "common/log.hpp"

#include <algorithm>
#include <chrono>
#include <vector>

namespace ar {

MicPipeline::MicPipeline(MicPipelineSettings settings)
    : settings_(std::move(settings)),
      ring_(static_cast<std::size_t>(settings_.rate_hz) * 400 / 1000 *
            static_cast<std::size_t>(settings_.channels)),
      source_(settings_.source) {
    if (settings_.channels < 1)
        settings_.channels = 2;
    if (settings_.rate_hz < 8000)
        settings_.rate_hz = 44100;
}

MicPipeline::~MicPipeline() {
    stop();
}

Result<MicBoundPorts> MicPipeline::start(std::uint16_t source_port, std::uint16_t repair_port) {
    if (running_.load()) {
        return fail(ErrorCode::busy, "mic pipeline is already active");
    }

    auto context = RocContext::create();
    if (!context)
        return std::unexpected(context.error());
    context_ = std::move(*context);

    RocReceiverOptions recv_options;
    recv_options.rate_hz = settings_.rate_hz;
    recv_options.channels = settings_.channels;
    recv_options.target_latency_ms = settings_.target_latency_ms;

    auto receiver = RocReceiver::create(context_, recv_options);
    if (!receiver)
        return std::unexpected(receiver.error());

    auto bound = receiver->bind(source_port, repair_port);
    if (!bound)
        return std::unexpected(bound.error());

    receiver_ = std::move(*receiver);

    ring_.clear();
    auto src_res = source_.start(
        CaptureFormat{settings_.rate_hz, settings_.channels},
        [this](float* samples, std::size_t count) { return on_pull_samples(samples, count); });
    if (!src_res) {
        receiver_.close();
        context_ = RocContext{};
        return std::unexpected(src_res.error());
    }

    frames_received_ = 0;
    read_errors_ = 0;
    running_ = true;
    receiver_thread_ = std::thread([this] { receiver_loop(); });

    logger()->info("mic pipeline started: receiver ports source={} repair={} -> PipeWire '{}'",
                   bound->source_port, bound->repair_port, settings_.source.name);

    return MicBoundPorts{bound->source_port, bound->repair_port};
}

void MicPipeline::stop() {
    if (running_.exchange(false) && receiver_thread_.joinable()) {
        receiver_thread_.join();
    }
    receiver_.close();
    context_ = RocContext{};
    source_.stop();
    ring_.clear();
}

void MicPipeline::receiver_loop() {
    const std::size_t channels = static_cast<std::size_t>(settings_.channels);
    const std::size_t frame_frames = static_cast<std::size_t>(settings_.rate_hz) / 100; // 10 ms
    const std::size_t frame_samples = frame_frames * channels;
    std::vector<float> frame(frame_samples, 0.0F);

    auto next = std::chrono::steady_clock::now();
    while (running_.load(std::memory_order_relaxed)) {
        if (auto r = receiver_.read(frame.data(), frame.size()); r) {
            ring_.write(std::span<const float>(frame.data(), frame.size()));
            frames_received_.fetch_add(frame_frames, std::memory_order_relaxed);
        } else {
            read_errors_.fetch_add(1, std::memory_order_relaxed);
        }

        next += std::chrono::milliseconds(10);
        const auto now = std::chrono::steady_clock::now();
        if (now > next + std::chrono::milliseconds(100)) {
            next = now;
        }
        if (next > now) {
            std::this_thread::sleep_until(next);
        } else {
            std::this_thread::sleep_for(std::chrono::microseconds(500));
        }
    }
}

std::size_t MicPipeline::on_pull_samples(float* samples, std::size_t max_samples) {
    const std::size_t got = ring_.read(std::span<float>(samples, max_samples));
    if (got < max_samples) {
        std::fill(samples + got, samples + max_samples, 0.0F);
    }
    return max_samples;
}

MicPipelineStats MicPipeline::stats() const {
    MicPipelineStats out;
    out.frames_received = frames_received_.load(std::memory_order_relaxed);
    out.read_errors = read_errors_.load(std::memory_order_relaxed);
    out.ring_available_samples = ring_.available_samples();
    out.ring_capacity_samples = ring_.capacity_samples();
    out.source_running = source_.running();
    out.streaming = running_.load();
    return out;
}

} // namespace ar
