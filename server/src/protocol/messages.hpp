// SPDX-License-Identifier: MIT
#pragma once

#include "common/error.hpp"

#include <cstdint>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ar::protocol {

inline constexpr int kVersion = 1;
inline constexpr std::string_view kAlpnPair = "tr-pair/1";
inline constexpr std::string_view kAlpnCtrl = "tr-ctrl/1";
inline constexpr std::string_view kWireEncoding = "avp_l16_stereo_44100";
inline constexpr std::string_view kFec = "rs8m";
inline constexpr std::string_view kSpakeSuite = "P256-SHA256-HKDF-HMAC";
inline constexpr std::string_view kSpakeMethod = "spake2";
inline constexpr std::string_view kDevPairMethod = "dev-plain";

struct ErrorInfo {
    std::string code;
    std::string message;
};

struct Envelope {
    std::optional<std::uint64_t> id;
    std::string type;
    nlohmann::json body;
    bool is_event{false};
    bool is_response{false};
};

[[nodiscard]] Result<Envelope> parse_envelope(std::string_view json);

[[nodiscard]] std::string make_ok_response(std::uint64_t id, nlohmann::json fields);
[[nodiscard]] std::string make_error_response(std::uint64_t id, ErrorInfo error);
[[nodiscard]] std::string make_event(std::string_view type, nlohmann::json fields);

// ---- Pairing -------------------------------------------------------------
struct PairStart {
    int proto{0};
    std::string name;
    std::string method;
    std::string suite;
    std::string share_b64;
};

[[nodiscard]] Result<PairStart> parse_pair_start(const nlohmann::json& body);

struct PairStartResponse {
    std::string host_name;
    std::string share_b64;
    std::string confirm_b64;
};

[[nodiscard]] nlohmann::json to_json(const PairStartResponse& value);

struct PairConfirmRequest {
    std::string confirm_b64;
};

[[nodiscard]] Result<PairConfirmRequest> parse_pair_confirm(const nlohmann::json& body);

struct PairConfirmResponse {
    std::string host_id;
    std::string host_name;
};

[[nodiscard]] nlohmann::json to_json(const PairConfirmResponse& value);

// ---- Control session -----------------------------------------------------
struct SessionHello {
    int proto_min{0};
    int proto_max{0};
    std::string app;
    std::string name;
    std::string roc;
    std::vector<std::string> wire_encodings;
    std::vector<std::string> fec;
};

[[nodiscard]] Result<SessionHello> parse_session_hello(const nlohmann::json& body);

struct StreamInfo {
    int wire_rate_hz{44100};
    int channels{2};
    int packet_ms{5};
    int fec_block_ms{90};
    int min_latency_ms{120};
};

struct SinkInfo {
    std::string name;
    bool available{false};
};

struct Caps {
    bool multi{false};
    bool host_request{false};
};

struct SessionHelloResponse {
    int proto{kVersion};
    std::string host_name;
    std::string host_version;
    std::string roc{"0.4.0"};
    std::string wire_encoding{std::string(kWireEncoding)};
    std::string fec{std::string(kFec)};
    StreamInfo stream;
    SinkInfo sink;
    bool streaming{false};
    Caps caps;
};

[[nodiscard]] nlohmann::json to_json(const SessionHelloResponse& value);

struct StreamStart {
    std::uint16_t source_port{0};
    std::uint16_t repair_port{0};
    std::string wire_encoding;
    std::string fec;
    int target_latency_ms{0};
};

[[nodiscard]] Result<StreamStart> parse_stream_start(const nlohmann::json& body);

struct StreamStop {
    std::uint32_t stream_id{0};
};

[[nodiscard]] Result<StreamStop> parse_stream_stop(const nlohmann::json& body);

struct MicStart {
    std::string wire_encoding;
    std::string fec;
};

[[nodiscard]] Result<MicStart> parse_mic_start(const nlohmann::json& body);

struct MicStartResponse {
    std::uint32_t stream_id{0};
    std::uint16_t source_port{0};
    std::uint16_t repair_port{0};
    std::string state{"starting"};
};

[[nodiscard]] nlohmann::json to_json(const MicStartResponse& value);

struct MicStop {
    std::uint32_t stream_id{0};
};

[[nodiscard]] Result<MicStop> parse_mic_stop(const nlohmann::json& body);

struct MicStateEvent {
    std::uint32_t stream_id{0};
    std::string state;
    std::string reason;
};

[[nodiscard]] nlohmann::json to_json(const MicStateEvent& value);

struct DeviceRename {
    std::string name;
};

[[nodiscard]] Result<DeviceRename> parse_device_rename(const nlohmann::json& body);

struct HostStatus {
    bool sink_available{false};
    bool streaming{false};
    int other_sessions{0};
};

[[nodiscard]] nlohmann::json to_json(const HostStatus& value);

struct StreamStateEvent {
    std::uint32_t stream_id{0};
    std::string state;
    std::string reason;
};

[[nodiscard]] nlohmann::json to_json(const StreamStateEvent& value);

} // namespace ar::protocol
