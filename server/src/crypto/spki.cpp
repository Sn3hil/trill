// SPDX-License-Identifier: MIT
#include "crypto/spki.hpp"

#include "common/encoding.hpp"
#include "crypto/hkdf.hpp"

#include <memory>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

namespace ar {
namespace {

struct BioDeleter {
    void operator()(BIO* p) const {
        BIO_free(p);
    }
};
using Bio = std::unique_ptr<BIO, BioDeleter>;

struct X509Deleter {
    void operator()(X509* p) const {
        X509_free(p);
    }
};
using X509Ptr = std::unique_ptr<X509, X509Deleter>;

} // namespace

Result<std::string> spki_der_sha256_hex(std::span<const unsigned char> der) {
    const Sha256 digest = sha256(der);
    return hex_encode(digest);
}

Result<std::string> spki_sha256_hex(X509* certificate) {
    if (certificate == nullptr) {
        return fail(ErrorCode::invalid_argument, "null certificate");
    }
    unsigned char* der = nullptr;
    const int len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(certificate), &der);
    if (len <= 0 || der == nullptr) {
        return fail(ErrorCode::crypto_error, "cannot encode SPKI");
    }
    auto id =
        spki_der_sha256_hex(std::span<const unsigned char>(der, static_cast<std::size_t>(len)));
    OPENSSL_free(der);
    return id;
}

Result<std::string> spki_sha256_hex_from_pem(std::string_view pem) {
    Bio bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    if (!bio)
        return fail(ErrorCode::crypto_error, "BIO allocation failed");
    X509Ptr cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    if (!cert)
        return fail(ErrorCode::crypto_error, "cannot parse certificate");
    return spki_sha256_hex(cert.get());
}

} // namespace ar
