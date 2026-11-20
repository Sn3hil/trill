// SPDX-License-Identifier: MIT
#include "audio/stream_pipeline.hpp"

#include "common/log.hpp"

#include <algorithm>
#include <chrono>
#include <vector>

namespace ar {

StreamPipeline::StreamPipeline(PipelineSettings settings)
    : settings_(std::move(settings)), ring_(static_cast<std::size_t>(settings_.rate_hz) * 400 /
                                            1000 * static_cast<std::size_t>(settings_.channels)),
      sink_(settings_.sink) {
    if (settings_.channels < 1)
        settings_.channels = 2;
    if (settings_.rate_hz < 8000)
        settings_.rate_hz = 48000;
}

StreamPipeline::~StreamPipeline() {
    stop();
}

Result<void> StreamPipeline::start_sink() {
    if (sink_.running())
        return {};
    auto result = sink_.start(
        CaptureFormat{settings_.rate_hz, settings_.channels},
        [this](const float* samples, std::size_t count) { on_capture(samples, count); });
    if (!result)
        return std::unexpected(result.error());
    return {};
}

Result<void> StreamPipeline::start(const StreamParams& params) {
    if (running_.load()) {
        return fail(ErrorCode::busy, "a stream is already active");
    }
    if (params.peer_ip.empty() || params.source_port == 0 || params.repair_port == 0) {
        return fail(ErrorCode::invalid_argument, "invalid Roc receiver endpoints");
    }

    auto context = RocContext::create();
    if (!context)
        return std::unexpected(context.error());
    context_ = std::move(*context);

    RocSenderOptions sender_options;
    sender_options.packet_ms = settings_.packet_ms;
    sender_options.fec_block_source = settings_.fec_block_source;
    sender_options.fec_block_repair = settings_.fec_block_repair;
    auto sender = RocSender::create(context_, sender_options);
    if (!sender)
        return std::unexpected(sender.error());
    if (auto r = sender->connect(params.peer_ip, params.source_port, params.repair_port); !r) {
        return std::unexpected(r.error());
    }
    senders_.clear();
    senders_.push_back(std::move(*sender));

    if (auto r = start_sink(); !r)
        return std::unexpected(r.error());

    ring_.clear();
    frames_sent_ = 0;
    overrun_samples_ = 0;
    underrun_frames_ = 0;
    write_errors_ = 0;
    running_ = true;
    sender_thread_ = std::thread([this] { sender_loop(); });
    logger()->info("stream pipeline started: 48 kHz float stereo -> L16/44.1k -> {}:{}",
                   params.peer_ip, params.source_port);
    return {};
}

void StreamPipeline::stop() {
    if (running_.exchange(false) && sender_thread_.joinable()) {
        sender_thread_.join();
    }
    senders_.clear();
    context_ = RocContext{};
    if (settings_.sink_per_session) {
        sink_.stop();
    }
    ring_.clear();
}

void StreamPipeline::on_capture(const float* samples, std::size_t count) {
    const std::size_t dropped = ring_.write(std::span<const float>(samples, count));
    if (dropped > 0) {
        overrun_samples_.fetch_add(dropped, std::memory_order_relaxed);
    }
    callback_count_.fetch_add(1, std::memory_order_relaxed);
}

void StreamPipeline::sender_loop() {
    const std::size_t channels = static_cast<std::size_t>(settings_.channels);
    const std::size_t frame_frames = static_cast<std::size_t>(settings_.rate_hz) / 100; // 10 ms
    const std::size_t frame_samples = frame_frames * channels;
    std::vector<float> frame(frame_samples, 0.0F);

    auto next = std::chrono::steady_clock::now();
    while (running_.load(std::memory_order_relaxed)) {
        const std::size_t got = ring_.read(frame);
        if (got < frame_samples) {
            std::fill(frame.begin() + static_cast<std::ptrdiff_t>(got), frame.end(), 0.0F);
            underrun_frames_.fetch_add(1, std::memory_order_relaxed);
        }

        for (auto& sender : senders_) {
            if (auto r = sender.write(frame.data(), frame.size()); !r) {
                write_errors_.fetch_add(1, std::memory_order_relaxed);
                break;
            }
        }
        frames_sent_.fetch_add(frame_frames, std::memory_order_relaxed);

        next += std::chrono::milliseconds(10);
        const auto now = std::chrono::steady_clock::now();
        if (now > next + std::chrono::milliseconds(100)) {
            next = now; // recover from a long stall
        }
        if (next > now) {
            std::this_thread::sleep_until(next);
        } else {
            std::this_thread::sleep_for(std::chrono::microseconds(500));
        }
    }
}

PipelineStats StreamPipeline::stats() const {
    PipelineStats out;
    out.frames_sent = frames_sent_.load(std::memory_order_relaxed);
    out.ring_overrun_samples = overrun_samples_.load(std::memory_order_relaxed);
    out.ring_underrun_frames = underrun_frames_.load(std::memory_order_relaxed);
    out.write_errors = write_errors_.load(std::memory_order_relaxed);
    out.ring_available_samples = ring_.available_samples();
    out.ring_capacity_samples = ring_.capacity_samples();
    out.capture_running = sink_.running();
    out.streaming = running_.load();
    return out;
}

} // namespace ar
