// SPDX-License-Identifier: MIT
#include "crypto/hkdf.hpp"

#include <memory>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

namespace ar {
namespace {

struct EvpPkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX* p) const {
        EVP_PKEY_CTX_free(p);
    }
};
using EvpPkeyCtx = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;

struct EvpMdCtxDeleter {
    void operator()(EVP_MD_CTX* p) const {
        EVP_MD_CTX_free(p);
    }
};
using EvpMdCtx = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;

struct EvpMacDeleter {
    void operator()(EVP_MAC* p) const {
        EVP_MAC_free(p);
    }
};
using EvpMac = std::unique_ptr<EVP_MAC, EvpMacDeleter>;

struct EvpMacCtxDeleter {
    void operator()(EVP_MAC_CTX* p) const {
        EVP_MAC_CTX_free(p);
    }
};
using EvpMacCtx = std::unique_ptr<EVP_MAC_CTX, EvpMacCtxDeleter>;

struct EvpDigestDeleter {
    void operator()(EVP_MD* p) const {
        EVP_MD_free(p);
    }
};
using EvpDigest = std::unique_ptr<EVP_MD, EvpDigestDeleter>;

} // namespace

Sha256 sha256(std::span<const std::uint8_t> data) {
    Sha256 out{};
    unsigned int len = 0;
    EvpMdCtx ctx(EVP_MD_CTX_new());
    if (!ctx)
        return out;
    if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1)
        return out;
    if (EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1)
        return out;
    if (EVP_DigestFinal_ex(ctx.get(), out.data(), &len) != 1)
        return out;
    return out;
}

Sha256 sha256(std::string_view data) {
    return sha256(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(data.data()),
                                                data.size()));
}

Result<std::vector<std::uint8_t>> hkdf_sha256(std::span<const std::uint8_t> ikm,
                                              std::span<const std::uint8_t> salt,
                                              std::span<const std::uint8_t> info,
                                              std::size_t length) {
    EvpPkeyCtx ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) != 1) {
        return fail(ErrorCode::crypto_error, "HKDF init failed");
    }
    if (EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) != 1 ||
        EVP_PKEY_CTX_set_hkdf_mode(ctx.get(), EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND) != 1) {
        return fail(ErrorCode::crypto_error, "HKDF setup failed");
    }
    if (!salt.empty() &&
        EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(), salt.data(), static_cast<int>(salt.size())) != 1) {
        return fail(ErrorCode::crypto_error, "HKDF salt failed");
    }
    if (!ikm.empty() &&
        EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), ikm.data(), static_cast<int>(ikm.size())) != 1) {
        return fail(ErrorCode::crypto_error, "HKDF key failed");
    }
    if (!info.empty() &&
        EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), info.data(), static_cast<int>(info.size())) != 1) {
        return fail(ErrorCode::crypto_error, "HKDF info failed");
    }

    std::vector<std::uint8_t> out(length);
    std::size_t out_len = length;
    if (EVP_PKEY_derive(ctx.get(), out.data(), &out_len) != 1 || out_len != length) {
        return fail(ErrorCode::crypto_error, "HKDF derive failed");
    }
    return out;
}

Result<std::vector<std::uint8_t>> hmac_sha256(std::span<const std::uint8_t> key,
                                              std::span<const std::uint8_t> message) {
    EvpMac mac(EVP_MAC_fetch(nullptr, "HMAC", nullptr));
    if (!mac)
        return fail(ErrorCode::crypto_error, "HMAC unavailable");

    EvpMacCtx ctx(EVP_MAC_CTX_new(mac.get()));
    if (!ctx)
        return fail(ErrorCode::crypto_error, "HMAC context failed");

    EvpDigest digest(EVP_MD_fetch(nullptr, "SHA256", nullptr));
    if (!digest)
        return fail(ErrorCode::crypto_error, "SHA256 unavailable");

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char*>("SHA256"), 0),
        OSSL_PARAM_construct_end()};

    if (EVP_MAC_init(ctx.get(), key.data(), key.size(), params) != 1) {
        return fail(ErrorCode::crypto_error, "HMAC init failed");
    }
    if (EVP_MAC_update(ctx.get(), message.data(), message.size()) != 1) {
        return fail(ErrorCode::crypto_error, "HMAC update failed");
    }
    std::vector<std::uint8_t> out(32);
    std::size_t out_len = out.size();
    if (EVP_MAC_final(ctx.get(), out.data(), &out_len, out.size()) != 1) {
        return fail(ErrorCode::crypto_error, "HMAC final failed");
    }
    out.resize(out_len);
    return out;
}

} // namespace ar
