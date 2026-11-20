// SPDX-License-Identifier: MIT
#pragma once

#include <expected>
#include <string>
#include <string_view>
#include <utility>

namespace ar {

// Stable machine-readable error codes. The protocol subset maps 1:1 to the
// documented wire error codes; the rest are local/IPC codes.
enum class ErrorCode {
    ok = 0,
    bad_request,
    unsupported,
    version_mismatch,
    pair_closed,
    pair_failed,
    pair_locked,
    busy,
    not_paired,
    no_sink,
    stream_failed,
    internal,

    // Local errors.
    invalid_argument,
    io_error,
    not_found,
    ambiguous,
    permission_denied,
    crypto_error,
    protocol_error,
    timeout,
    daemon_not_running,
    phone_not_connected,
};

struct Error {
    ErrorCode code{ErrorCode::internal};
    std::string message;
};

[[nodiscard]] const char* to_string(ErrorCode code);
[[nodiscard]] std::string_view protocol_code(ErrorCode code);
[[nodiscard]] int cli_exit_code(ErrorCode code);

template <typename T> using Result = std::expected<T, Error>;

template <typename T>
[[nodiscard]] auto fail(ErrorCode code, std::string message) -> std::unexpected<Error> {
    return std::unexpected(Error{code, std::move(message)});
}

[[nodiscard]] inline auto fail(ErrorCode code, std::string message) -> std::unexpected<Error> {
    return std::unexpected(Error{code, std::move(message)});
}

} // namespace ar
