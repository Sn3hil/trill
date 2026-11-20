// SPDX-License-Identifier: MIT
#pragma once

#include "common/clock.hpp"
#include "common/error.hpp"
#include "crypto/spake2.hpp"
#include "protocol/messages.hpp"
#include "store/config.hpp"

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace ar {

// Owns the pairing window, the six-digit code, attempt accounting and one
// in-flight SPAKE2 exchange. The code is never logged.
class PairingManager {
  public:
    using OpenedCallback = std::function<void(const std::string& code, int seconds)>;
    using ClosedCallback = std::function<void(const std::string& reason)>;
    using PairedCallback = std::function<void(const std::string& device_id, const std::string& name,
                                              const std::string& peer_ip)>;

    PairingManager(const PairingConfig& config, std::string host_id, std::string host_name,
                   std::shared_ptr<Clock> clock);

    void set_callbacks(OpenedCallback opened, ClosedCallback closed, PairedCallback paired);

    // Open a window. Returns the code and its duration. ErrorCode::busy when a
    // window is already open.
    Result<std::pair<std::string, int>> open_window(int seconds = 0);

    void close(const std::string& reason);

    // Lazily expires the window. Returns the close reason when it just closed.
    std::optional<std::string> tick();

    [[nodiscard]] bool is_open() const;
    [[nodiscard]] int seconds_remaining() const;
    [[nodiscard]] int attempts_remaining() const {
        return attempts_remaining_;
    }
    [[nodiscard]] bool locked() const {
        return locked_;
    }
    [[nodiscard]] const std::string& host_name() const {
        return host_name_;
    }

    // Pairing exchange (ALPN tr-pair/1). peer_spki is the certificate hash the
    // host actually saw on this TLS leg.
    [[nodiscard]] Result<protocol::PairStartResponse> begin_pair(const protocol::PairStart& request,
                                                                 const std::string& peer_spki);
    [[nodiscard]] Result<void> finish_pair(const std::string& confirm_b64,
                                           const std::string& peer_ip);
    [[nodiscard]] bool has_pending() const {
        return pending_ != nullptr;
    }
    void cancel_pending() {
        pending_.reset();
    }

    // Test/monotonic accessor.
    [[nodiscard]] TimePoint expires_at() const {
        return expires_at_;
    }

  private:
    struct Pending {
        Spake2 spake;
        std::string peer_spki;
        std::string peer_name;
    };

    Result<void> ensure_open() const;
    void record_failure();

    PairingConfig config_;
    std::string host_id_;
    std::string host_name_;
    std::shared_ptr<Clock> clock_;

    bool open_{false};
    bool locked_{false};
    std::string code_;
    TimePoint expires_at_{};
    int attempts_remaining_{3};
    int window_seconds_{30};
    std::unique_ptr<Pending> pending_;

    OpenedCallback on_opened_;
    ClosedCallback on_closed_;
    PairedCallback on_paired_;
};

} // namespace ar
