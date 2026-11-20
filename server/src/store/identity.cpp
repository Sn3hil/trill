// SPDX-License-Identifier: MIT
#include "store/identity.hpp"

#include "common/paths.hpp"
#include "crypto/csprng.hpp"
#include "crypto/spki.hpp"

#include <chrono>
#include <cstdio>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <vector>

namespace ar {
namespace {

struct BioDeleter {
    void operator()(BIO* p) const {
        BIO_free(p);
    }
};
using Bio = std::unique_ptr<BIO, BioDeleter>;

struct BnDeleter {
    void operator()(BIGNUM* p) const {
        BN_free(p);
    }
};

struct PkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX* p) const {
        EVP_PKEY_CTX_free(p);
    }
};
using PkeyCtx = std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter>;

struct X509ExtDeleter {
    void operator()(X509_EXTENSION* p) const {
        X509_EXTENSION_free(p);
    }
};

Result<std::string> bio_to_string(BIO* bio) {
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio, &data);
    if (len <= 0 || data == nullptr) {
        return fail(ErrorCode::io_error, "empty PEM output");
    }
    return std::string(data, static_cast<std::size_t>(len));
}

} // namespace

HostIdentity::~HostIdentity() = default;
HostIdentity::HostIdentity(HostIdentity&&) noexcept = default;
HostIdentity& HostIdentity::operator=(HostIdentity&&) noexcept = default;

Result<HostIdentity> HostIdentity::load_or_create(const std::filesystem::path& identity_dir,
                                                  const std::string& common_name) {
    auto ensure = ensure_dir(identity_dir, 0700);
    if (!ensure)
        return std::unexpected(ensure.error());

    const auto key_path = identity_dir / "host.key";
    const auto cert_path = identity_dir / "host.crt";

    std::error_code ec;
    const bool have_key = std::filesystem::exists(key_path, ec);
    ec.clear();
    const bool have_cert = std::filesystem::exists(cert_path, ec);

    if (!have_key || !have_cert) {
        return generate(identity_dir, common_name);
    }

    HostIdentity id;
    id.key_path_ = key_path;
    id.cert_path_ = cert_path;

    {
        Bio bio(BIO_new_file(key_path.c_str(), "r"));
        if (!bio)
            return fail(ErrorCode::io_error, "cannot open " + key_path.string());
        EVP_PKEY* key = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
        if (key == nullptr) {
            return fail(ErrorCode::crypto_error, "cannot parse host private key");
        }
        id.key_.reset(key);
    }
    {
        Bio bio(BIO_new_file(cert_path.c_str(), "r"));
        if (!bio)
            return fail(ErrorCode::io_error, "cannot open " + cert_path.string());
        X509* cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
        if (cert == nullptr) {
            return fail(ErrorCode::crypto_error, "cannot parse host certificate");
        }
        id.cert_.reset(cert);
    }

    auto spki = spki_sha256_hex(id.cert_.get());
    if (!spki)
        return std::unexpected(spki.error());
    id.spki_hex_ = *spki;
    return id;
}

Result<HostIdentity> HostIdentity::generate(const std::filesystem::path& identity_dir,
                                            const std::string& common_name) {
    PkeyCtx ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) != 1 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1) != 1) {
        return fail(ErrorCode::crypto_error, "EC keygen setup failed");
    }
    EVP_PKEY* raw_key = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw_key) != 1) {
        return fail(ErrorCode::crypto_error, "EC keygen failed");
    }

    HostIdentity id;
    id.key_.reset(raw_key);
    id.key_path_ = identity_dir / "host.key";
    id.cert_path_ = identity_dir / "host.crt";

    id.cert_.reset(X509_new());
    if (!id.cert_)
        return fail(ErrorCode::crypto_error, "X509 allocation failed");

    X509_set_version(id.cert_.get(), 2);
    auto serial_bytes = random_bytes(16);
    if (!serial_bytes)
        return std::unexpected(serial_bytes.error());
    BIGNUM* serial =
        BN_bin2bn(serial_bytes->data(), static_cast<int>(serial_bytes->size()), nullptr);
    if (serial == nullptr)
        return fail(ErrorCode::crypto_error, "serial allocation failed");
    BN_set_negative(serial, 0);
    if (BN_is_zero(serial))
        BN_one(serial);
    ASN1_INTEGER* serial_int = BN_to_ASN1_INTEGER(serial, nullptr);
    BN_free(serial);
    if (serial_int == nullptr) {
        return fail(ErrorCode::crypto_error, "serial conversion failed");
    }
    const int serial_ok = X509_set_serialNumber(id.cert_.get(), serial_int);
    ASN1_INTEGER_free(serial_int);
    if (serial_ok != 1) {
        return fail(ErrorCode::crypto_error, "certificate serial failed");
    }

    X509_NAME* name = X509_get_subject_name(id.cert_.get());
    if (name == nullptr ||
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>(common_name.c_str()), -1,
                                   -1, 0) != 1 ||
        X509_set_issuer_name(id.cert_.get(), name) != 1) {
        return fail(ErrorCode::crypto_error, "certificate subject failed");
    }

    const auto now = std::chrono::system_clock::now();
    const auto not_before = std::chrono::system_clock::to_time_t(now - std::chrono::hours(24));
    const auto not_after =
        std::chrono::system_clock::to_time_t(now + std::chrono::hours(24 * 365 * 10));
    ASN1_TIME* nb = ASN1_TIME_set(nullptr, not_before);
    ASN1_TIME* na = ASN1_TIME_set(nullptr, not_after);
    if (nb == nullptr || na == nullptr || X509_set1_notBefore(id.cert_.get(), nb) != 1 ||
        X509_set1_notAfter(id.cert_.get(), na) != 1) {
        ASN1_TIME_free(nb);
        ASN1_TIME_free(na);
        return fail(ErrorCode::crypto_error, "certificate validity failed");
    }
    ASN1_TIME_free(nb);
    ASN1_TIME_free(na);

    if (X509_set_pubkey(id.cert_.get(), id.key_.get()) != 1) {
        return fail(ErrorCode::crypto_error, "certificate public key failed");
    }

    // Basic constraints: not a CA.
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_basic_constraints,
                                              const_cast<char*>("critical,CA:FALSE"));
    if (ext != nullptr) {
        X509_add_ext(id.cert_.get(), ext, -1);
        X509_EXTENSION_free(ext);
    }

    if (X509_sign(id.cert_.get(), id.key_.get(), EVP_sha256()) <= 0) {
        return fail(ErrorCode::crypto_error, "certificate signing failed");
    }

    auto spki = spki_sha256_hex(id.cert_.get());
    if (!spki)
        return std::unexpected(spki.error());
    id.spki_hex_ = *spki;

    auto key_pem = id.key_pem();
    auto cert_pem = id.cert_pem();
    if (!key_pem)
        return std::unexpected(key_pem.error());
    if (!cert_pem)
        return std::unexpected(cert_pem.error());

    if (auto r = write_file_atomic(id.key_path_, *key_pem, 0600); !r) {
        return std::unexpected(r.error());
    }
    if (auto r = write_file_atomic(id.cert_path_, *cert_pem, 0600); !r) {
        return std::unexpected(r.error());
    }
    return id;
}

Result<std::string> HostIdentity::cert_pem() const {
    if (!cert_)
        return fail(ErrorCode::internal, "no certificate");
    Bio bio(BIO_new(BIO_s_mem()));
    if (!bio || PEM_write_bio_X509(bio.get(), cert_.get()) != 1) {
        return fail(ErrorCode::crypto_error, "cannot encode certificate");
    }
    return bio_to_string(bio.get());
}

Result<std::string> HostIdentity::key_pem() const {
    if (!key_)
        return fail(ErrorCode::internal, "no key");
    Bio bio(BIO_new(BIO_s_mem()));
    if (!bio || PEM_write_bio_PrivateKey(bio.get(), key_.get(), nullptr, nullptr, 0, nullptr,
                                         nullptr) != 1) {
        return fail(ErrorCode::crypto_error, "cannot encode private key");
    }
    return bio_to_string(bio.get());
}

} // namespace ar
