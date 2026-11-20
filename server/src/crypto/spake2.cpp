// SPDX-License-Identifier: MIT
#include "crypto/spake2.hpp"

#include "common/encoding.hpp"
#include "crypto/hkdf.hpp"

#include <algorithm>
#include <cstring>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

namespace ar {
namespace {

// RFC 9382 section 6, P-256 M and N (compressed SEC1). Copied from the RFC.
constexpr std::string_view kM =
    "02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f";
constexpr std::string_view kN =
    "03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49";

constexpr std::string_view kWSecretSalt = "trill/spake2/w/v1";

struct BnDeleter {
    void operator()(BIGNUM* p) const {
        BN_free(p);
    }
};
using Bn = std::unique_ptr<BIGNUM, BnDeleter>;

struct BnCtxDeleter {
    void operator()(BN_CTX* p) const {
        BN_CTX_free(p);
    }
};
using BnCtx = std::unique_ptr<BN_CTX, BnCtxDeleter>;

struct EcGroupDeleter {
    void operator()(EC_GROUP* p) const {
        EC_GROUP_free(p);
    }
};
using EcGroup = std::unique_ptr<EC_GROUP, EcGroupDeleter>;

struct EcPointDeleter {
    void operator()(EC_POINT* p) const {
        EC_POINT_free(p);
    }
};
using EcPoint = std::unique_ptr<EC_POINT, EcPointDeleter>;

void append_len_prefixed(std::vector<std::uint8_t>& out, std::span<const std::uint8_t> data) {
    std::uint64_t len = data.size();
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((len >> (8 * i)) & 0xff));
    }
    out.insert(out.end(), data.begin(), data.end());
}

void append_len_prefixed(std::vector<std::uint8_t>& out, std::string_view data) {
    append_len_prefixed(out, std::span<const std::uint8_t>(
                                 reinterpret_cast<const std::uint8_t*>(data.data()), data.size()));
}

std::vector<std::uint8_t> bn_to_vec(const BIGNUM* bn) {
    std::vector<std::uint8_t> out(static_cast<std::size_t>(BN_num_bytes(bn)));
    if (!out.empty() && BN_bn2bin(bn, out.data()) != static_cast<int>(out.size())) {
        out.clear();
    }
    return out;
}

} // namespace

struct Spake2::Impl {
    SpakeRole role{SpakeRole::a};
    std::string id_a;
    std::string id_b;

    EcGroup group;
    BnCtx bn_ctx;
    Bn order;
    Bn w;
    Bn scalar;
    EcPoint m_point;
    EcPoint n_point;
    EcPoint own_share;

    bool peer_done{false};
    std::vector<std::uint8_t> own_share_bytes;
    std::vector<std::uint8_t> peer_share_bytes;
    std::vector<std::uint8_t> shared_point;
    std::vector<std::uint8_t> transcript;
    Sha256 hash{};
    std::vector<std::uint8_t> ke_bytes;
    std::vector<std::uint8_t> ka_bytes;
    std::vector<std::uint8_t> kca_bytes;
    std::vector<std::uint8_t> kcb_bytes;
};

Spake2::Spake2(SpakeRole role, std::string_view code, std::string_view id_a, std::string_view id_b,
               std::optional<std::array<std::uint8_t, 32>> injected_scalar)
    : impl_(std::make_unique<Impl>()) {
    impl_->role = role;
    impl_->id_a = std::string(id_a);
    impl_->id_b = std::string(id_b);
    impl_->group.reset(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    impl_->bn_ctx.reset(BN_CTX_new());
    if (!impl_->group || !impl_->bn_ctx)
        return;

    impl_->order.reset(BN_new());
    BN_CTX_start(impl_->bn_ctx.get());
    BIGNUM* order = BN_CTX_get(impl_->bn_ctx.get());
    if (!order || EC_GROUP_get_order(impl_->group.get(), order, impl_->bn_ctx.get()) != 1) {
        BN_CTX_end(impl_->bn_ctx.get());
        return;
    }
    impl_->order.reset(BN_dup(order));
    BN_CTX_end(impl_->bn_ctx.get());

    // M and N.
    auto m_bytes = hex_decode(kM);
    auto n_bytes = hex_decode(kN);
    if (!m_bytes || !n_bytes)
        return;
    impl_->m_point.reset(EC_POINT_new(impl_->group.get()));
    impl_->n_point.reset(EC_POINT_new(impl_->group.get()));
    if (!impl_->m_point || !impl_->n_point)
        return;
    if (EC_POINT_oct2point(impl_->group.get(), impl_->m_point.get(), m_bytes->data(),
                           m_bytes->size(), impl_->bn_ctx.get()) != 1 ||
        EC_POINT_oct2point(impl_->group.get(), impl_->n_point.get(), n_bytes->data(),
                           n_bytes->size(), impl_->bn_ctx.get()) != 1) {
        return;
    }

    // w = HKDF(...) mod n, or raw-w: for RFC vectors.
    if (code.starts_with("raw-w:")) {
        auto w_bytes = hex_decode(code.substr(6));
        if (!w_bytes)
            return;
        impl_->w.reset(BN_bin2bn(w_bytes->data(), static_cast<int>(w_bytes->size()), nullptr));
    } else {
        auto derived = derive_w(code);
        if (!derived)
            return;
        auto w_bytes = hex_decode(*derived);
        if (!w_bytes)
            return;
        impl_->w.reset(BN_bin2bn(w_bytes->data(), static_cast<int>(w_bytes->size()), nullptr));
    }
    if (!impl_->w)
        return;
    BN_set_flags(impl_->w.get(), BN_FLG_CONSTTIME);
    if (BN_mod(impl_->w.get(), impl_->w.get(), impl_->order.get(), impl_->bn_ctx.get()) != 1) {
        return;
    }

    // Ephemeral scalar x (role A) or y (role B).
    impl_->scalar.reset(BN_secure_new());
    if (!impl_->scalar)
        return;
    BN_set_flags(impl_->scalar.get(), BN_FLG_CONSTTIME);
    if (injected_scalar) {
        BN_bin2bn(injected_scalar->data(), static_cast<int>(injected_scalar->size()),
                  impl_->scalar.get());
        if (BN_cmp(impl_->scalar.get(), impl_->order.get()) >= 0 ||
            BN_is_zero(impl_->scalar.get())) {
            impl_->scalar.reset();
            return;
        }
    } else {
        do {
            if (BN_priv_rand_range(impl_->scalar.get(), impl_->order.get()) != 1) {
                impl_->scalar.reset();
                return;
            }
        } while (BN_is_zero(impl_->scalar.get()));
    }

    impl_->own_share.reset(EC_POINT_new(impl_->group.get()));
    if (!impl_->own_share)
        return;
    const EC_POINT* peer_point = role == SpakeRole::a ? impl_->m_point.get() : impl_->n_point.get();
    if (EC_POINT_mul(impl_->group.get(), impl_->own_share.get(), impl_->scalar.get(), peer_point,
                     impl_->w.get(), impl_->bn_ctx.get()) != 1) {
        impl_->own_share.reset();
        return;
    }

    const std::size_t len =
        EC_POINT_point2oct(impl_->group.get(), impl_->own_share.get(),
                           POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, impl_->bn_ctx.get());
    if (len == 0) {
        impl_->own_share.reset();
        return;
    }
    impl_->own_share_bytes.resize(len);
    if (EC_POINT_point2oct(impl_->group.get(), impl_->own_share.get(),
                           POINT_CONVERSION_UNCOMPRESSED, impl_->own_share_bytes.data(), len,
                           impl_->bn_ctx.get()) != len) {
        impl_->own_share.reset();
        impl_->own_share_bytes.clear();
    }
}

Spake2::~Spake2() = default;
Spake2::Spake2(Spake2&&) noexcept = default;
Spake2& Spake2::operator=(Spake2&&) noexcept = default;

Result<std::string> Spake2::derive_w(std::string_view code) {
    const auto salt = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(kWSecretSalt.data()), kWSecretSalt.size());
    auto ikm = std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(code.data()),
                                             code.size());
    auto hk = hkdf_sha256(ikm, salt, {}, 48);
    if (!hk)
        return std::unexpected(hk.error());

    BnCtx ctx(BN_CTX_new());
    EcGroup group(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    Bn order(BN_new());
    Bn w(BN_bin2bn(hk->data(), static_cast<int>(hk->size()), nullptr));
    if (!ctx || !group || !order || !w) {
        return fail(ErrorCode::crypto_error, "SPAKE2 w derivation failed");
    }
    if (EC_GROUP_get_order(group.get(), order.get(), ctx.get()) != 1 ||
        BN_mod(w.get(), w.get(), order.get(), ctx.get()) != 1) {
        return fail(ErrorCode::crypto_error, "SPAKE2 w reduction failed");
    }
    auto bytes = bn_to_vec(w.get());
    if (bytes.size() < 32) {
        std::vector<std::uint8_t> padded(32 - bytes.size(), 0);
        padded.insert(padded.end(), bytes.begin(), bytes.end());
        bytes = std::move(padded);
    }
    return hex_encode(bytes);
}

SpakeRole Spake2::role() const {
    return impl_->role;
}

Result<std::vector<std::uint8_t>> Spake2::share() const {
    if (impl_->own_share_bytes.empty()) {
        return fail(ErrorCode::crypto_error, "SPAKE2 share unavailable");
    }
    return impl_->own_share_bytes;
}

Result<void> Spake2::process_peer_share(std::span<const std::uint8_t> peer) {
    if (impl_->peer_done) {
        return fail(ErrorCode::protocol_error, "SPAKE2 peer share already processed");
    }
    if (!impl_->group || !impl_->own_share || peer.size() != 65 || peer[0] != 0x04) {
        return fail(ErrorCode::protocol_error, "invalid SPAKE2 peer share");
    }

    EcPoint peer_point(EC_POINT_new(impl_->group.get()));
    if (!peer_point || EC_POINT_oct2point(impl_->group.get(), peer_point.get(), peer.data(),
                                          peer.size(), impl_->bn_ctx.get()) != 1) {
        return fail(ErrorCode::protocol_error, "SPAKE2 peer share is not a curve point");
    }
    if (EC_POINT_is_at_infinity(impl_->group.get(), peer_point.get()) == 1 ||
        EC_POINT_is_on_curve(impl_->group.get(), peer_point.get(), impl_->bn_ctx.get()) != 1) {
        return fail(ErrorCode::protocol_error, "SPAKE2 peer share is invalid");
    }

    // K = scalar * (peer - w * other_point).
    const EC_POINT* other =
        impl_->role == SpakeRole::a ? impl_->n_point.get() : impl_->m_point.get();
    EcPoint w_other(EC_POINT_new(impl_->group.get()));
    EcPoint diff(EC_POINT_new(impl_->group.get()));
    EcPoint shared(EC_POINT_new(impl_->group.get()));
    if (!w_other || !diff || !shared) {
        return fail(ErrorCode::crypto_error, "SPAKE2 point allocation failed");
    }
    if (EC_POINT_mul(impl_->group.get(), w_other.get(), nullptr, other, impl_->w.get(),
                     impl_->bn_ctx.get()) != 1 ||
        EC_POINT_invert(impl_->group.get(), w_other.get(), impl_->bn_ctx.get()) != 1 ||
        EC_POINT_add(impl_->group.get(), diff.get(), peer_point.get(), w_other.get(),
                     impl_->bn_ctx.get()) != 1 ||
        EC_POINT_mul(impl_->group.get(), shared.get(), nullptr, diff.get(), impl_->scalar.get(),
                     impl_->bn_ctx.get()) != 1) {
        return fail(ErrorCode::crypto_error, "SPAKE2 shared point computation failed");
    }
    if (EC_POINT_is_at_infinity(impl_->group.get(), shared.get()) == 1) {
        return fail(ErrorCode::protocol_error, "SPAKE2 shared point is the identity");
    }

    auto encode = [&](const EC_POINT* point) -> Result<std::vector<std::uint8_t>> {
        const std::size_t len =
            EC_POINT_point2oct(impl_->group.get(), point, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0,
                               impl_->bn_ctx.get());
        if (len == 0)
            return fail(ErrorCode::crypto_error, "point encoding failed");
        std::vector<std::uint8_t> out(len);
        if (EC_POINT_point2oct(impl_->group.get(), point, POINT_CONVERSION_UNCOMPRESSED, out.data(),
                               len, impl_->bn_ctx.get()) != len) {
            return fail(ErrorCode::crypto_error, "point encoding failed");
        }
        return out;
    };

    auto k_bytes = encode(shared.get());
    if (!k_bytes)
        return std::unexpected(k_bytes.error());
    impl_->shared_point = *k_bytes;
    impl_->peer_share_bytes.assign(peer.begin(), peer.end());

    const auto& p_a =
        impl_->role == SpakeRole::a ? impl_->own_share_bytes : impl_->peer_share_bytes;
    const auto& p_b =
        impl_->role == SpakeRole::a ? impl_->peer_share_bytes : impl_->own_share_bytes;

    impl_->transcript.clear();
    append_len_prefixed(impl_->transcript, impl_->id_a);
    append_len_prefixed(impl_->transcript, impl_->id_b);
    append_len_prefixed(impl_->transcript, p_a);
    append_len_prefixed(impl_->transcript, p_b);
    append_len_prefixed(impl_->transcript, impl_->shared_point);
    auto w_bytes = bn_to_vec(impl_->w.get());
    if (w_bytes.size() < 32) {
        w_bytes.insert(w_bytes.begin(), 32 - w_bytes.size(), 0);
    }
    append_len_prefixed(impl_->transcript, w_bytes);

    impl_->hash = sha256(impl_->transcript);
    impl_->ke_bytes.assign(impl_->hash.begin(), impl_->hash.begin() + 16);
    impl_->ka_bytes.assign(impl_->hash.begin() + 16, impl_->hash.end());

    const std::string info = "ConfirmationKeys";
    auto kc = hkdf_sha256(impl_->ka_bytes, {},
                          std::span<const std::uint8_t>(
                              reinterpret_cast<const std::uint8_t*>(info.data()), info.size()),
                          32);
    if (!kc)
        return std::unexpected(kc.error());
    impl_->kca_bytes.assign(kc->begin(), kc->begin() + 16);
    impl_->kcb_bytes.assign(kc->begin() + 16, kc->end());

    impl_->peer_done = true;
    return {};
}

bool Spake2::ready() const {
    return impl_ && impl_->peer_done;
}

Result<std::vector<std::uint8_t>> Spake2::own_confirm() const {
    if (!ready())
        return fail(ErrorCode::internal, "SPAKE2 is not ready");
    const auto& key = impl_->role == SpakeRole::a ? impl_->kca_bytes : impl_->kcb_bytes;
    return hmac_sha256(key, impl_->peer_share_bytes);
}

Result<bool> Spake2::verify_peer_confirm(std::span<const std::uint8_t> confirm) const {
    if (!ready())
        return fail(ErrorCode::internal, "SPAKE2 is not ready");
    // Verify with the peer's key: B -> KcB, A -> KcA.
    const auto& key = impl_->role == SpakeRole::a ? impl_->kcb_bytes : impl_->kca_bytes;
    auto expected = hmac_sha256(key, impl_->own_share_bytes);
    if (!expected)
        return std::unexpected(expected.error());
    if (expected->size() != confirm.size())
        return false;
    return CRYPTO_memcmp(expected->data(), confirm.data(), confirm.size()) == 0;
}

Result<std::string> Spake2::own_confirm_b64() const {
    auto confirm = own_confirm();
    if (!confirm)
        return std::unexpected(confirm.error());
    return base64_encode(*confirm);
}

Result<bool> Spake2::verify_peer_confirm_b64(std::string_view confirm_b64) const {
    auto decoded = base64_decode(confirm_b64);
    if (!decoded)
        return std::unexpected(decoded.error());
    return verify_peer_confirm(*decoded);
}

std::vector<std::uint8_t> Spake2::shared_point() const {
    return impl_->shared_point;
}
std::vector<std::uint8_t> Spake2::transcript() const {
    return impl_->transcript;
}
std::array<std::uint8_t, 32> Spake2::hash_tt() const {
    return impl_->hash;
}
std::vector<std::uint8_t> Spake2::ke() const {
    return impl_->ke_bytes;
}
std::vector<std::uint8_t> Spake2::ka() const {
    return impl_->ka_bytes;
}
std::vector<std::uint8_t> Spake2::kca() const {
    return impl_->kca_bytes;
}
std::vector<std::uint8_t> Spake2::kcb() const {
    return impl_->kcb_bytes;
}

Result<std::vector<std::uint8_t>> Spake2::rfc_confirm_a() const {
    if (!ready())
        return fail(ErrorCode::internal, "SPAKE2 is not ready");
    return hmac_sha256(impl_->kca_bytes, impl_->transcript);
}

Result<std::vector<std::uint8_t>> Spake2::rfc_confirm_b() const {
    if (!ready())
        return fail(ErrorCode::internal, "SPAKE2 is not ready");
    return hmac_sha256(impl_->kcb_bytes, impl_->transcript);
}

} // namespace ar
