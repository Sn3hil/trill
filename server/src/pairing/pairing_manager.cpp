// SPDX-License-Identifier: MIT
#include "pairing/pairing_manager.hpp"

#include "common/encoding.hpp"
#include "common/log.hpp"
#include "crypto/csprng.hpp"
#include "protocol/messages.hpp"

#include <algorithm>
#include <utility>

namespace ar {

PairingManager::PairingManager(const PairingConfig& config, std::string host_id,
                               std::string host_name, std::shared_ptr<Clock> clock)
    : config_(config), host_id_(std::move(host_id)), host_name_(std::move(host_name)),
      clock_(std::move(clock)), attempts_remaining_(config.max_attempts) {}

void PairingManager::set_callbacks(OpenedCallback opened, ClosedCallback closed,
                                   PairedCallback paired) {
    on_opened_ = std::move(opened);
    on_closed_ = std::move(closed);
    on_paired_ = std::move(paired);
}

Result<std::pair<std::string, int>> PairingManager::open_window(int seconds) {
    if (is_open()) {
        return fail(ErrorCode::busy, "a pairing window is already open");
    }
    const int duration = seconds > 0 ? std::min(seconds, 120) : config_.window_seconds;
    if (duration < 1) {
        return fail(ErrorCode::invalid_argument, "pairing window must be positive");
    }

    auto code = random_code6();
    if (!code)
        return std::unexpected(code.error());

    open_ = true;
    locked_ = false;
    code_ = *code;
    window_seconds_ = duration;
    expires_at_ = clock_->now() + std::chrono::seconds(duration);
    attempts_remaining_ = config_.max_attempts;
    pending_.reset();

    logger()->info("pairing window opened for {}s", duration);
    if (on_opened_)
        on_opened_(code_, duration);
    return std::make_pair(code_, duration);
}

void PairingManager::close(const std::string& reason) {
    if (!open_ && !locked_)
        return;
    open_ = false;
    locked_ = reason == "locked";
    code_.clear();
    pending_.reset();
    if (on_closed_)
        on_closed_(reason);
}

std::optional<std::string> PairingManager::tick() {
    if (!open_)
        return std::nullopt;
    if (clock_->now() < expires_at_)
        return std::nullopt;
    close("timeout");
    return std::string("timeout");
}

bool PairingManager::is_open() const {
    return open_ && !locked_ && clock_->now() < expires_at_;
}

int PairingManager::seconds_remaining() const {
    if (!is_open())
        return 0;
    const auto delta =
        std::chrono::duration_cast<std::chrono::seconds>(expires_at_ - clock_->now());
    return static_cast<int>(std::max<std::int64_t>(0, delta.count()));
}

Result<void> PairingManager::ensure_open() const {
    if (locked_)
        return fail(ErrorCode::pair_locked, "pairing window is locked");
    if (!is_open())
        return fail(ErrorCode::pair_closed, "no pairing window is open");
    return {};
}

Result<protocol::PairStartResponse> PairingManager::begin_pair(const protocol::PairStart& request,
                                                               const std::string& peer_spki) {
    if (auto ok = ensure_open(); !ok)
        return std::unexpected(ok.error());
    if (pending_ != nullptr) {
        return fail(ErrorCode::busy, "another pairing exchange is in progress");
    }

    if (request.method == protocol::kDevPairMethod) {
#ifdef TRILL_ENABLE_DEV_PAIRING
        if (!constant_time_equal(request.share_b64, code_)) {
            record_failure();
            return fail(ErrorCode::pair_failed, "incorrect pairing code");
        }
        if (on_paired_)
            on_paired_(peer_spki, request.name, {});
        close("success");
        return protocol::PairStartResponse{host_name_, {}, {}};
#else
        return fail(ErrorCode::unsupported, "dev pairing is not compiled in");
#endif
    }

    if (request.method != protocol::kSpakeMethod) {
        return fail(ErrorCode::unsupported, "unsupported pairing method");
    }

    auto share_bytes = base64_decode(request.share_b64);
    if (!share_bytes) {
        record_failure();
        return fail(ErrorCode::pair_failed, "invalid SPAKE2 share");
    }

    const std::string id_a = "tr-phone:" + peer_spki;
    const std::string id_b = "tr-host:" + host_id_;
    auto pending = std::make_unique<Pending>(
        Pending{Spake2(SpakeRole::b, code_, id_a, id_b), peer_spki, request.name});
    auto peer = pending->spake.process_peer_share(*share_bytes);
    if (!peer) {
        record_failure();
        return fail(ErrorCode::pair_failed, "invalid SPAKE2 exchange: " + peer.error().message);
    }

    auto own_share = pending->spake.share();
    auto confirm = pending->spake.own_confirm_b64();
    if (!own_share || !confirm) {
        record_failure();
        return fail(ErrorCode::crypto_error, "SPAKE2 response failed");
    }

    pending_ = std::move(pending);
    return protocol::PairStartResponse{host_name_, base64_encode(*own_share), *confirm};
}

Result<void> PairingManager::finish_pair(const std::string& confirm_b64,
                                         const std::string& peer_ip) {
    if (auto ok = ensure_open(); !ok)
        return std::unexpected(ok.error());
    if (pending_ == nullptr) {
        return fail(ErrorCode::pair_failed, "no pairing exchange in progress");
    }

    auto valid = pending_->spake.verify_peer_confirm_b64(confirm_b64);
    if (!valid) {
        record_failure();
        return std::unexpected(valid.error());
    }
    if (!*valid) {
        record_failure();
        return fail(ErrorCode::pair_failed, "pairing confirmation mismatch");
    }

    const std::string device_id = pending_->peer_spki;
    const std::string name = pending_->peer_name;
    pending_.reset();
    if (on_paired_)
        on_paired_(device_id, name, peer_ip);
    close("success");
    return {};
}

void PairingManager::record_failure() {
    if (attempts_remaining_ > 0)
        --attempts_remaining_;
    pending_.reset();
    if (attempts_remaining_ <= 0) {
        locked_ = true;
        close("locked");
    } else {
        logger()->warn("pairing attempt failed, {} remaining", attempts_remaining_);
    }
}

} // namespace ar
