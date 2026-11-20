// SPDX-License-Identifier: MIT
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace ar {

// Single-producer / single-consumer lock-free ring for interleaved float
// samples. The producer is the PipeWire RT callback: no allocation, no locks,
// no syscalls. When full, the producer drops the oldest samples and reports
// the count so the sender thread can surface it in stats.
class FloatRingBuffer {
  public:
    explicit FloatRingBuffer(std::size_t capacity_samples)
        : capacity_(round_up_power_of_two(capacity_samples)), mask_(capacity_ - 1),
          buffer_(capacity_, 0.0F) {}

    FloatRingBuffer(const FloatRingBuffer&) = delete;
    FloatRingBuffer& operator=(const FloatRingBuffer&) = delete;

    // Returns the number of dropped (oldest) samples.
    std::size_t write(std::span<const float> samples) {
        if (samples.empty())
            return 0;
        std::size_t dropped = 0;
        std::size_t write_pos = write_pos_.load(std::memory_order_relaxed);

        // Make room by advancing the read pointer. Retry if the consumer moved
        // it concurrently; only the consumer increases it, so a failed CAS
        // means it advanced and we simply recompute.
        for (;;) {
            const std::size_t read_pos = read_pos_.load(std::memory_order_acquire);
            const std::size_t used = write_pos - read_pos;
            const std::size_t free = capacity_ - used;
            if (samples.size() <= free)
                break;
            const std::size_t need = samples.size() - free;
            std::size_t expected = read_pos;
            if (read_pos_.compare_exchange_strong(expected, read_pos + need,
                                                  std::memory_order_release,
                                                  std::memory_order_relaxed)) {
                dropped += need;
                break;
            }
        }

        for (std::size_t i = 0; i < samples.size(); ++i) {
            buffer_[(write_pos + i) & mask_] = samples[i];
        }
        write_pos_.store(write_pos + samples.size(), std::memory_order_release);
        return dropped;
    }

    // Returns the number of samples actually read.
    std::size_t read(std::span<float> out) {
        if (out.empty())
            return 0;
        const std::size_t write_pos = write_pos_.load(std::memory_order_acquire);
        const std::size_t read_pos = read_pos_.load(std::memory_order_relaxed);
        const std::size_t available = write_pos - read_pos;
        const std::size_t count = available < out.size() ? available : out.size();
        for (std::size_t i = 0; i < count; ++i) {
            out[i] = buffer_[(read_pos + i) & mask_];
        }
        read_pos_.store(read_pos + count, std::memory_order_release);
        return count;
    }

    [[nodiscard]] std::size_t available_samples() const {
        return write_pos_.load(std::memory_order_acquire) -
               read_pos_.load(std::memory_order_acquire);
    }

    [[nodiscard]] std::size_t capacity_samples() const {
        return capacity_;
    }

    void clear() {
        read_pos_.store(write_pos_.load(std::memory_order_acquire), std::memory_order_release);
    }

  private:
    static std::size_t round_up_power_of_two(std::size_t value) {
        std::size_t result = 1;
        while (result < value)
            result <<= 1;
        return result;
    }

    const std::size_t capacity_;
    const std::size_t mask_;
    std::vector<float> buffer_;
    alignas(64) std::atomic<std::size_t> write_pos_{0};
    alignas(64) std::atomic<std::size_t> read_pos_{0};
};

} // namespace ar
