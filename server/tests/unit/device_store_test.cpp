// SPDX-License-Identifier: MIT
#include "store/device_store.hpp"

#include <filesystem>
#include <gtest/gtest.h>

namespace ar {
namespace {

class DeviceStoreTest : public ::testing::Test {
  protected:
    void SetUp() override {
        test_dir_ = std::filesystem::temp_directory_path() / "ar_device_store_test";
        std::error_code ec;
        std::filesystem::remove_all(test_dir_, ec);
        std::filesystem::create_directories(test_dir_, ec);
        devices_file_ = test_dir_ / "devices.json";
    }

    void TearDown() override {
        std::error_code ec;
        std::filesystem::remove_all(test_dir_, ec);
    }

    std::filesystem::path test_dir_;
    std::filesystem::path devices_file_;
};

TEST_F(DeviceStoreTest, EmptyStoreLoad) {
    auto store = DeviceStore::load(devices_file_);
    ASSERT_TRUE(store.has_value());
    EXPECT_TRUE(store->empty());
    EXPECT_EQ(store->size(), 0u);
}

TEST_F(DeviceStoreTest, UpsertSaveAndReload) {
    auto store1 = DeviceStore::load(devices_file_);
    ASSERT_TRUE(store1.has_value());

    const std::string id1 = "aaaaaaaa11111111222222223333333344444444555555556666666677777777";
    const std::string id2 = "bbbbbbbb11111111222222223333333344444444555555556666666677777777";

    ASSERT_TRUE(store1->upsert(id1, "Pixel 8", "192.168.1.10"));
    ASSERT_TRUE(store1->upsert(id2, "Galaxy S23", "192.168.1.20"));
    EXPECT_EQ(store1->size(), 2u);

    ASSERT_TRUE(store1->save());

    // Reload
    auto store2 = DeviceStore::load(devices_file_);
    ASSERT_TRUE(store2.has_value());
    EXPECT_EQ(store2->size(), 2u);

    const auto* d1 = store2->find_by_id(id1);
    ASSERT_NE(d1, nullptr);
    EXPECT_EQ(d1->name, "Pixel 8");
    EXPECT_EQ(d1->last_ip, "192.168.1.10");
}

TEST_F(DeviceStoreTest, Resolution) {
    auto store = DeviceStore::load(devices_file_);
    ASSERT_TRUE(store.has_value());

    const std::string id1 = "abcdef0111111111222222223333333344444444555555556666666677777777";
    const std::string id2 = "abc9999911111111222222223333333344444444555555556666666677777777";
    const std::string id3 = "1234567811111111222222223333333344444444555555556666666677777777";

    ASSERT_TRUE(store->upsert(id1, "Work Phone", "10.0.0.1"));
    ASSERT_TRUE(store->upsert(id2, "Work Phone", "10.0.0.2"));
    ASSERT_TRUE(store->upsert(id3, "Personal Phone", "10.0.0.3"));

    // Full ID match
    auto r1 = store->resolve(id1);
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(*r1, 0u);

    // Prefix match unique
    auto r_pref = store->resolve("abcdef");
    ASSERT_TRUE(r_pref.has_value());
    EXPECT_EQ(*r_pref, 0u);

    // Prefix match ambiguous
    auto r_amb_pref = store->resolve("abc");
    EXPECT_FALSE(r_amb_pref.has_value());
    EXPECT_EQ(r_amb_pref.error().code, ErrorCode::ambiguous);
    auto matches = store->matches("abc");
    EXPECT_EQ(matches.size(), 2u);

    // Name match case-insensitive
    auto r_name = store->resolve("personal phone");
    ASSERT_TRUE(r_name.has_value());
    EXPECT_EQ(*r_name, 2u);

    // Name match ambiguous
    auto r_amb_name = store->resolve("Work phone");
    EXPECT_FALSE(r_amb_name.has_value());
    EXPECT_EQ(r_amb_name.error().code, ErrorCode::ambiguous);

    // Not found
    auto r_none = store->resolve("nonexistent");
    EXPECT_FALSE(r_none.has_value());
    EXPECT_EQ(r_none.error().code, ErrorCode::not_found);
}

TEST_F(DeviceStoreTest, RenameAndRemove) {
    auto store = DeviceStore::load(devices_file_);
    ASSERT_TRUE(store.has_value());

    const std::string id = "1111111111111111222222223333333344444444555555556666666677777777";
    ASSERT_TRUE(store->upsert(id, "Old Name", "1.1.1.1"));

    ASSERT_TRUE(store->rename(id, "New Name"));
    const auto* d = store->find_by_id(id);
    ASSERT_NE(d, nullptr);
    EXPECT_EQ(d->name, "New Name");

    ASSERT_TRUE(store->remove(id));
    EXPECT_EQ(store->size(), 0u);
    EXPECT_EQ(store->find_by_id(id), nullptr);
}

TEST_F(DeviceStoreTest, TouchUpdatesLastSeenAndIp) {
    auto store = DeviceStore::load(devices_file_);
    ASSERT_TRUE(store.has_value());

    const std::string id = "2222222211111111222222223333333344444444555555556666666677777777";
    ASSERT_TRUE(store->upsert(id, "Phone", "1.1.1.1"));

    ASSERT_TRUE(store->touch(id, "1.1.1.2"));
    const auto* d = store->find_by_id(id);
    ASSERT_NE(d, nullptr);
    EXPECT_EQ(d->last_ip, "1.1.1.2");
}

} // namespace
} // namespace ar
