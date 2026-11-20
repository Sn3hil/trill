// SPDX-License-Identifier: MIT
#pragma once

#include "common/error.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

struct roc_context;
struct roc_sender;

namespace ar {

struct RocSenderOptions {
    int packet_ms{5};
    int fec_block_source{18};
    int fec_block_repair{10};
};

// RAII around libroc. The library is dynamically linked and never vendored.
class RocContext {
  public:
    RocContext() = default;
    ~RocContext();
    RocContext(RocContext&& other) noexcept;
    RocContext& operator=(RocContext&& other) noexcept;
    RocContext(const RocContext&) = delete;
    RocContext& operator=(const RocContext&) = delete;

    [[nodiscard]] static Result<RocContext> create();
    [[nodiscard]] ::roc_context* get() const {
        return context_;
    }
    [[nodiscard]] bool valid() const {
        return context_ != nullptr;
    }

  private:
    ::roc_context* context_{nullptr};
};

class RocSender {
  public:
    RocSender() = default;
    ~RocSender();
    RocSender(RocSender&& other) noexcept;
    RocSender& operator=(RocSender&& other) noexcept;
    RocSender(const RocSender&) = delete;
    RocSender& operator=(const RocSender&) = delete;

    [[nodiscard]] static Result<RocSender> create(RocContext& context,
                                                  const RocSenderOptions& options);

    // Source and repair endpoints, connected to the phone's receiver ports.
    [[nodiscard]] Result<void> connect(std::string_view peer_ip, std::uint16_t source_port,
                                       std::uint16_t repair_port);

    // Interleaved float32 stereo at 48 kHz. s16 L16 on the wire.
    [[nodiscard]] Result<void> write(const float* samples, std::size_t sample_count);

    void close();

  private:
    ::roc_sender* sender_{nullptr};
};

} // namespace ar
