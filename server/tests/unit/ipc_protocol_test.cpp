// SPDX-License-Identifier: MIT
#include "ipc/ipc_protocol.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

namespace ar {
namespace {

TEST(IpcProtocolTest, ParseRequestValid) {
    auto req1 = ipc::parse_request(R"({"id":1,"cmd":"list"})");
    ASSERT_TRUE(req1.has_value());
    EXPECT_EQ(req1->id, 1u);
    EXPECT_EQ(req1->cmd, "list");
    EXPECT_TRUE(req1->args.is_null() || req1->args.empty());

    auto req2 = ipc::parse_request(R"({"id":2,"cmd":"start","args":{"device":"phone1"}})");
    ASSERT_TRUE(req2.has_value());
    EXPECT_EQ(req2->id, 2u);
    EXPECT_EQ(req2->cmd, "start");
    EXPECT_EQ(req2->args["device"], "phone1");
}

TEST(IpcProtocolTest, ParseRequestInvalid) {
    auto bad_json = ipc::parse_request("not json");
    EXPECT_FALSE(bad_json.has_value());

    auto missing_cmd = ipc::parse_request(R"({"id":1})");
    EXPECT_FALSE(missing_cmd.has_value());

    auto missing_id = ipc::parse_request(R"({"cmd":"list"})");
    EXPECT_FALSE(missing_id.has_value());
}

TEST(IpcProtocolTest, OkResponse) {
    auto str = ipc::ok(10, {{"state", "active"}});
    auto j = nlohmann::json::parse(str);
    EXPECT_EQ(j["re"], 10u);
    EXPECT_EQ(j["ok"], true);
    EXPECT_EQ(j["result"]["state"], "active");
}

TEST(IpcProtocolTest, ErrorResponse) {
    Error err{ErrorCode::not_found, "phone not found"};
    auto str = ipc::error(11, err, {{"device", "pixel"}});
    auto j = nlohmann::json::parse(str);
    EXPECT_EQ(j["re"], 11u);
    EXPECT_EQ(j["ok"], false);
    EXPECT_EQ(j["error"]["code"], "not_found");
    EXPECT_EQ(j["error"]["message"], "phone not found");
    EXPECT_EQ(j["error"]["device"], "pixel");
}

TEST(IpcProtocolTest, EventFormatting) {
    auto str = ipc::event("pair.progress", {{"seconds_remaining", 28}});
    auto j = nlohmann::json::parse(str);
    EXPECT_EQ(j["event"], "pair.progress");
    EXPECT_EQ(j["seconds_remaining"], 28);
}

} // namespace
} // namespace ar
