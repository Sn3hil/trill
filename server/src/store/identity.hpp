// SPDX-License-Identifier: MIT
#pragma once

#include "common/error.hpp"

#include <filesystem>
#include <memory>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <string>

namespace ar {

// Host identity: EC P-256 private key + self-signed X.509 certificate.
// Loaded from identity/host.key and identity/host.crt (created on first run
// with mode 0600 in a 0700 directory).
class HostIdentity {
  public:
    HostIdentity() = default;
    ~HostIdentity();
    HostIdentity(HostIdentity&&) noexcept;
    HostIdentity& operator=(HostIdentity&&) noexcept;
    HostIdentity(const HostIdentity&) = delete;
    HostIdentity& operator=(const HostIdentity&) = delete;

    static Result<HostIdentity> load_or_create(const std::filesystem::path& identity_dir,
                                               const std::string& common_name);

    [[nodiscard]] X509* cert() const {
        return cert_.get();
    }
    [[nodiscard]] EVP_PKEY* key() const {
        return key_.get();
    }
    [[nodiscard]] const std::string& spki_hex() const {
        return spki_hex_;
    }
    [[nodiscard]] bool valid() const {
        return key_ && cert_ && !spki_hex_.empty();
    }

    [[nodiscard]] Result<std::string> cert_pem() const;
    [[nodiscard]] Result<std::string> key_pem() const;

  private:
    struct PkeyDeleter {
        void operator()(EVP_PKEY* p) const {
            EVP_PKEY_free(p);
        }
    };
    struct X509Deleter {
        void operator()(X509* p) const {
            X509_free(p);
        }
    };
    using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDeleter>;
    using X509Ptr = std::unique_ptr<X509, X509Deleter>;

    static Result<HostIdentity> generate(const std::filesystem::path& identity_dir,
                                         const std::string& common_name);

    PkeyPtr key_;
    X509Ptr cert_;
    std::string spki_hex_;
    std::filesystem::path key_path_;
    std::filesystem::path cert_path_;
};

} // namespace ar
