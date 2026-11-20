// SPDX-License-Identifier: MIT
#include "protocol/messages.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::string_view sv(reinterpret_cast<const char*>(data), size);
    auto env = ar::protocol::parse_envelope(sv);
    if (env) {
        (void)ar::protocol::parse_pair_start(env->body);
        (void)ar::protocol::parse_pair_confirm(env->body);
        (void)ar::protocol::parse_session_hello(env->body);
        (void)ar::protocol::parse_stream_start(env->body);
        (void)ar::protocol::parse_stream_stop(env->body);
        (void)ar::protocol::parse_device_rename(env->body);
    }
    return 0;
}
