// SPDX-License-Identifier: MIT
#include "common/error.hpp"

namespace ar {

const char* to_string(ErrorCode code) {
    switch (code) {
    case ErrorCode::ok:
        return "ok";
    case ErrorCode::bad_request:
        return "bad_request";
    case ErrorCode::unsupported:
        return "unsupported";
    case ErrorCode::version_mismatch:
        return "version_mismatch";
    case ErrorCode::pair_closed:
        return "pair_closed";
    case ErrorCode::pair_failed:
        return "pair_failed";
    case ErrorCode::pair_locked:
        return "pair_locked";
    case ErrorCode::busy:
        return "busy";
    case ErrorCode::not_paired:
        return "not_paired";
    case ErrorCode::no_sink:
        return "no_sink";
    case ErrorCode::stream_failed:
        return "stream_failed";
    case ErrorCode::internal:
        return "internal";
    case ErrorCode::invalid_argument:
        return "invalid_argument";
    case ErrorCode::io_error:
        return "io_error";
    case ErrorCode::not_found:
        return "not_found";
    case ErrorCode::ambiguous:
        return "ambiguous";
    case ErrorCode::permission_denied:
        return "permission_denied";
    case ErrorCode::crypto_error:
        return "crypto_error";
    case ErrorCode::protocol_error:
        return "protocol_error";
    case ErrorCode::timeout:
        return "timeout";
    case ErrorCode::daemon_not_running:
        return "daemon_not_running";
    case ErrorCode::phone_not_connected:
        return "phone_not_connected";
    }
    return "internal";
}

std::string_view protocol_code(ErrorCode code) {
    switch (code) {
    case ErrorCode::ok:
        return "ok";
    case ErrorCode::bad_request:
    case ErrorCode::invalid_argument:
        return "bad_request";
    case ErrorCode::unsupported:
        return "unsupported";
    case ErrorCode::version_mismatch:
        return "version_mismatch";
    case ErrorCode::pair_closed:
        return "pair_closed";
    case ErrorCode::pair_failed:
        return "pair_failed";
    case ErrorCode::pair_locked:
        return "pair_locked";
    case ErrorCode::busy:
        return "busy";
    case ErrorCode::not_paired:
        return "not_paired";
    case ErrorCode::no_sink:
        return "no_sink";
    case ErrorCode::stream_failed:
        return "stream_failed";
    case ErrorCode::not_found:
        return "not_paired";
    case ErrorCode::phone_not_connected:
        return "busy";
    case ErrorCode::timeout:
        return "internal";
    case ErrorCode::crypto_error:
    case ErrorCode::protocol_error:
    case ErrorCode::ambiguous:
    case ErrorCode::permission_denied:
    case ErrorCode::io_error:
    case ErrorCode::daemon_not_running:
    case ErrorCode::internal:
        return "internal";
    }
    return "internal";
}

int cli_exit_code(ErrorCode code) {
    switch (code) {
    case ErrorCode::ok:
        return 0;
    case ErrorCode::invalid_argument:
        return 2;
    case ErrorCode::ambiguous:
        return 3;
    case ErrorCode::not_found:
        return 4;
    case ErrorCode::daemon_not_running:
        return 5;
    case ErrorCode::phone_not_connected:
    case ErrorCode::busy:
        return 6;
    default:
        return 1;
    }
}

} // namespace ar
