// SPDX-License-Identifier: MIT
#pragma once

#include "audio/roc_sender.hpp"
#include "common/error.hpp"

#include <cstdint>
#include <span>
#include <string>

struct roc_receiver;

namespace ar {

struct RocReceiverOptions {
    int rate_hz{44100};
    int channels{2};
    int target_latency_ms{120};
};

struct RocReceiverPorts {
    std::uint16_t source_port{0};
    std::uint16_t repair_port{0};
};

class RocReceiver {
  public:
    RocReceiver() = default;
    ~RocReceiver();
    RocReceiver(RocReceiver&& other) noexcept;
    RocReceiver& operator=(RocReceiver&& other) noexcept;
    RocReceiver(const RocReceiver&) = delete;
    RocReceiver& operator=(const RocReceiver&) = delete;

    [[nodiscard]] static Result<RocReceiver> create(RocContext& context,
                                                    const RocReceiverOptions& options);

    // Binds source and repair endpoints. If ports are 0, ephemeral ports are allocated
    // and returned.
    [[nodiscard]] Result<RocReceiverPorts> bind(std::uint16_t source_port = 0,
                                               std::uint16_t repair_port = 0);

    // Reads decoded interleaved float32 samples into buffer.
    [[nodiscard]] Result<void> read(float* samples, std::size_t sample_count);

    void close();

    [[nodiscard]] bool valid() const {
        return receiver_ != nullptr;
    }

  private:
    ::roc_receiver* receiver_{nullptr};
};

} // namespace ar
