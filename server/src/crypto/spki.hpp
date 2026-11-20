// SPDX-License-Identifier: MIT
#pragma once

#include "common/error.hpp"

#include <openssl/x509.h>
#include <span>
#include <string>
#include <string_view>

namespace ar {

// device_id = lowercase hex SHA-256 over the DER SubjectPublicKeyInfo.
[[nodiscard]] Result<std::string> spki_sha256_hex(X509* certificate);
[[nodiscard]] Result<std::string> spki_sha256_hex_from_pem(std::string_view pem);
[[nodiscard]] Result<std::string> spki_der_sha256_hex(std::span<const unsigned char> der);

} // namespace ar
