// SPDX-License-Identifier: MIT
#include "audio/ring_buffer.hpp"

#include <gtest/gtest.h>
#include <vector>

namespace ar {
namespace {

TEST(RingBufferTest, CapacityPowerOfTwo) {
    FloatRingBuffer rb1(100);
    EXPECT_EQ(rb1.capacity_samples(), 128u);

    FloatRingBuffer rb2(256);
    EXPECT_EQ(rb2.capacity_samples(), 256u);

    FloatRingBuffer rb3(300);
    EXPECT_EQ(rb3.capacity_samples(), 512u);
}

TEST(RingBufferTest, WriteAndRead) {
    FloatRingBuffer rb(8); // capacity = 8
    EXPECT_EQ(rb.available_samples(), 0u);

    std::vector<float> in = {1.0f, 2.0f, 3.0f, 4.0f};
    std::size_t dropped = rb.write(in);
    EXPECT_EQ(dropped, 0u);
    EXPECT_EQ(rb.available_samples(), 4u);

    std::vector<float> out(4, 0.0f);
    std::size_t read_count = rb.read(out);
    EXPECT_EQ(read_count, 4u);
    EXPECT_EQ(out, in);
    EXPECT_EQ(rb.available_samples(), 0u);
}

TEST(RingBufferTest, WrapAround) {
    FloatRingBuffer rb(8); // capacity = 8

    // Write 6, read 6
    std::vector<float> data1 = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f};
    EXPECT_EQ(rb.write(data1), 0u);
    std::vector<float> out1(6);
    EXPECT_EQ(rb.read(out1), 6u);
    EXPECT_EQ(out1, data1);

    // Now write 6 again (indices 6..11, wrapping 8)
    std::vector<float> data2 = {7.0f, 8.0f, 9.0f, 10.0f, 11.0f, 12.0f};
    EXPECT_EQ(rb.write(data2), 0u);
    EXPECT_EQ(rb.available_samples(), 6u);

    std::vector<float> out2(6);
    EXPECT_EQ(rb.read(out2), 6u);
    EXPECT_EQ(out2, data2);
}

TEST(RingBufferTest, OverflowDropsAccounting) {
    FloatRingBuffer rb(8); // capacity = 8

    std::vector<float> data1 = {1.0f, 2.0f, 3.0f, 4.0f, 5.0f, 6.0f};
    EXPECT_EQ(rb.write(data1), 0u);

    // Write 4 more -> total 10 > 8, so 2 must be dropped
    std::vector<float> data2 = {7.0f, 8.0f, 9.0f, 10.0f};
    std::size_t dropped = rb.write(data2);
    EXPECT_EQ(dropped, 2u);
    EXPECT_EQ(rb.available_samples(), 8u);

    // Reading should yield remaining 8 samples: data1[2..5] + data2[0..3]
    // which is 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0
    std::vector<float> out(8);
    EXPECT_EQ(rb.read(out), 8u);
    std::vector<float> expected = {3.0f, 4.0f, 5.0f, 6.0f, 7.0f, 8.0f, 9.0f, 10.0f};
    EXPECT_EQ(out, expected);
}

TEST(RingBufferTest, Clear) {
    FloatRingBuffer rb(16);
    std::vector<float> in(10, 1.5f);
    rb.write(in);
    EXPECT_EQ(rb.available_samples(), 10u);

    rb.clear();
    EXPECT_EQ(rb.available_samples(), 0u);

    std::vector<float> out(10);
    EXPECT_EQ(rb.read(out), 0u);
}

} // namespace
} // namespace ar
