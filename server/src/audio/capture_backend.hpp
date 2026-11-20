// SPDX-License-Identifier: MIT
#pragma once

#include "common/error.hpp"

#include <cstddef>
#include <functional>

namespace ar {

struct CaptureFormat {
    int rate_hz{48000};
    int channels{2};
};

// Capture sits behind this interface so a macOS backend can be added later.
// on_samples is called from a real-time thread with interleaved float samples.
class CaptureBackend {
  public:
    using FrameCallback = std::function<void(const float* samples, std::size_t count)>;

    virtual ~CaptureBackend() = default;
    virtual Result<void> start(CaptureFormat format, FrameCallback on_samples) = 0;
    virtual void stop() = 0;
    [[nodiscard]] virtual bool running() const = 0;
};

} // namespace ar
