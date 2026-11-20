// SPDX-License-Identifier: MIT
#pragma once

#include <chrono>
#include <memory>

namespace ar {

using SteadyClock = std::chrono::steady_clock;
using TimePoint = SteadyClock::time_point;

// Injectable clock so pairing windows and keepalive deadlines are testable.
class Clock {
  public:
    virtual ~Clock() = default;
    [[nodiscard]] virtual TimePoint now() const = 0;
};

class SystemClock final : public Clock {
  public:
    [[nodiscard]] TimePoint now() const override {
        return SteadyClock::now();
    }
};

class FakeClock final : public Clock {
  public:
    explicit FakeClock(TimePoint start = TimePoint{}) : now_(start) {}
    [[nodiscard]] TimePoint now() const override {
        return now_;
    }
    void advance(std::chrono::milliseconds delta) {
        now_ += delta;
    }
    void advance(std::chrono::seconds delta) {
        now_ += delta;
    }
    void set(TimePoint tp) {
        now_ = tp;
    }

  private:
    TimePoint now_;
};

} // namespace ar
