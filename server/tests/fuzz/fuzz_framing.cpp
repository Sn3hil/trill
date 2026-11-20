// SPDX-License-Identifier: MIT
#include "net/framing.hpp"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    ar::FrameDecoder decoder;
    (void)decoder.feed(std::span<const uint8_t>(data, size));
    return 0;
}
