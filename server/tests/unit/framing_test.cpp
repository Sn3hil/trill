// SPDX-License-Identifier: MIT
#include "net/framing.hpp"

#include <gtest/gtest.h>

namespace ar {
namespace {

TEST(FramingTest, EncodeValidFrame) {
    const std::string payload = R"({"type":"ping"})";
    auto encoded = encode_frame(payload);
    ASSERT_TRUE(encoded.has_value());
    ASSERT_EQ(encoded->size(), kFrameHeaderSize + payload.size());

    // Check big-endian length
    std::uint32_t len = (static_cast<std::uint32_t>((*encoded)[0]) << 24) |
                        (static_cast<std::uint32_t>((*encoded)[1]) << 16) |
                        (static_cast<std::uint32_t>((*encoded)[2]) << 8) |
                        static_cast<std::uint32_t>((*encoded)[3]);
    EXPECT_EQ(len, payload.size());
    EXPECT_EQ(std::string_view(reinterpret_cast<const char*>(encoded->data() + 4), payload.size()),
              payload);
}

TEST(FramingTest, EncodeOversizedFrame) {
    std::string big_payload(kMaxFrameSize + 1, 'x');
    auto encoded = encode_frame(big_payload);
    EXPECT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, ErrorCode::bad_request);
}

TEST(FramingTest, EncodeEmptyFrame) {
    auto encoded = encode_frame("");
    EXPECT_FALSE(encoded.has_value());
    EXPECT_EQ(encoded.error().code, ErrorCode::bad_request);
}

TEST(FramingTest, DecoderFullFrame) {
    FrameDecoder decoder;
    const std::string payload = R"({"type":"ping"})";
    auto encoded = encode_frame(payload);
    ASSERT_TRUE(encoded.has_value());

    auto frames = decoder.feed(*encoded);
    ASSERT_TRUE(frames.has_value());
    ASSERT_EQ(frames->size(), 1u);
    EXPECT_EQ((*frames)[0], payload);
    EXPECT_EQ(decoder.buffered(), 0u);
}

TEST(FramingTest, DecoderIncrementalByteByByte) {
    FrameDecoder decoder;
    const std::string payload = R"({"type":"session.hello","name":"Test"})";
    auto encoded = encode_frame(payload);
    ASSERT_TRUE(encoded.has_value());

    std::vector<std::string> collected;
    for (std::size_t i = 0; i < encoded->size(); ++i) {
        std::span<const std::uint8_t> chunk(&(*encoded)[i], 1);
        auto frames = decoder.feed(chunk);
        ASSERT_TRUE(frames.has_value());
        for (auto& f : *frames) {
            collected.push_back(std::move(f));
        }
    }
    ASSERT_EQ(collected.size(), 1u);
    EXPECT_EQ(collected[0], payload);
    EXPECT_EQ(decoder.buffered(), 0u);
}

TEST(FramingTest, DecoderMultipleFramesInOneChunk) {
    FrameDecoder decoder;
    const std::string p1 = R"({"type":"ping"})";
    const std::string p2 = R"({"type":"pong"})";
    auto enc1 = encode_frame(p1);
    auto enc2 = encode_frame(p2);
    ASSERT_TRUE(enc1.has_value());
    ASSERT_TRUE(enc2.has_value());

    std::vector<std::uint8_t> combined;
    combined.insert(combined.end(), enc1->begin(), enc1->end());
    combined.insert(combined.end(), enc2->begin(), enc2->end());

    auto frames = decoder.feed(combined);
    ASSERT_TRUE(frames.has_value());
    ASSERT_EQ(frames->size(), 2u);
    EXPECT_EQ((*frames)[0], p1);
    EXPECT_EQ((*frames)[1], p2);
}

TEST(FramingTest, DecoderRejectZeroLengthFrame) {
    FrameDecoder decoder;
    // 4 zero bytes = length 0
    std::vector<std::uint8_t> bad = {0, 0, 0, 0};
    auto res = decoder.feed(bad);
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::protocol_error);
}

TEST(FramingTest, DecoderRejectOversizedLength) {
    FrameDecoder decoder;
    // Length 65537 = 0x00010001
    std::vector<std::uint8_t> bad = {0, 1, 0, 1};
    auto res = decoder.feed(bad);
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::protocol_error);
}

} // namespace
} // namespace ar
