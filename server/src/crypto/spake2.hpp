// SPDX-License-Identifier: MIT
#pragma once

#include "common/error.hpp"

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ar {

enum class SpakeRole { a, b };

// SPAKE2 over P-256 with SHA-256 / HKDF / HMAC (RFC 9382 ciphersuite).
//
// w is derived from the six-digit code as specified by PROTOCOL section 6:
//   w = OS2IP(HKDF-SHA256(ikm=code, salt="trill/spake2/w/v1",
//                         info="", L=48)) mod n
//
// The scalar is injectable so the RFC 9382 Appendix B vector and our
// pair_v1.json can be reproduced exactly.
class Spake2 {
  public:
    Spake2(SpakeRole role, std::string_view code, std::string_view id_a, std::string_view id_b,
           std::optional<std::array<std::uint8_t, 32>> injected_scalar = std::nullopt);
    ~Spake2();
    Spake2(Spake2&&) noexcept;
    Spake2& operator=(Spake2&&) noexcept;
    Spake2(const Spake2&) = delete;
    Spake2& operator=(const Spake2&) = delete;

    [[nodiscard]] static Result<std::string> derive_w(std::string_view code);

    [[nodiscard]] SpakeRole role() const;

    // Own public share, SEC1 uncompressed (0x04 || X || Y).
    [[nodiscard]] Result<std::vector<std::uint8_t>> share() const;

    // Validate and absorb the peer share, then derive K, TT and confirmation keys.
    [[nodiscard]] Result<void> process_peer_share(std::span<const std::uint8_t> peer);

    // Protocol confirmation: A sends MAC(KcA, pB), B sends MAC(KcB, pA).
    [[nodiscard]] Result<std::vector<std::uint8_t>> own_confirm() const;
    [[nodiscard]] Result<bool> verify_peer_confirm(std::span<const std::uint8_t> confirm) const;

    // Base64 convenience wrappers.
    [[nodiscard]] Result<std::string> own_confirm_b64() const;
    [[nodiscard]] Result<bool> verify_peer_confirm_b64(std::string_view confirm_b64) const;

    [[nodiscard]] bool ready() const;

    // --- Test accessors (no secrets leave the process through logs) ---------
    [[nodiscard]] std::vector<std::uint8_t> shared_point() const;
    [[nodiscard]] std::vector<std::uint8_t> transcript() const;
    [[nodiscard]] std::array<std::uint8_t, 32> hash_tt() const;
    [[nodiscard]] std::vector<std::uint8_t> ke() const;
    [[nodiscard]] std::vector<std::uint8_t> ka() const;
    [[nodiscard]] std::vector<std::uint8_t> kca() const;
    [[nodiscard]] std::vector<std::uint8_t> kcb() const;
    // RFC 9382 key confirmation over TT (used by the RFC test vector only).
    [[nodiscard]] Result<std::vector<std::uint8_t>> rfc_confirm_a() const;
    [[nodiscard]] Result<std::vector<std::uint8_t>> rfc_confirm_b() const;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ar
