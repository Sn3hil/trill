// SPDX-License-Identifier: MIT
#include "protocol/messages.hpp"

#include <algorithm>

namespace ar::protocol {
namespace {

Result<void> require_object(const nlohmann::json& body) {
    if (!body.is_object()) {
        return fail(ErrorCode::bad_request, "message body must be an object");
    }
    return {};
}

Result<std::string> require_string(const nlohmann::json& body, const char* key,
                                   std::size_t max_len = 256) {
    const auto it = body.find(key);
    if (it == body.end() || !it->is_string()) {
        return fail(ErrorCode::bad_request, std::string("missing string field '") + key + "'");
    }
    std::string value = it->get<std::string>();
    if (value.size() > max_len) {
        return fail(ErrorCode::bad_request, std::string("field '") + key + "' is too long");
    }
    return value;
}

Result<int> require_int(const nlohmann::json& body, const char* key) {
    const auto it = body.find(key);
    if (it == body.end() || !it->is_number_integer()) {
        return fail(ErrorCode::bad_request, std::string("missing integer field '") + key + "'");
    }
    return it->get<int>();
}

bool contains(const std::vector<std::string>& values, std::string_view wanted) {
    return std::find(values.begin(), values.end(), wanted) != values.end();
}

Result<std::vector<std::string>> require_string_array(const nlohmann::json& body, const char* key) {
    const auto it = body.find(key);
    if (it == body.end() || !it->is_array()) {
        return fail(ErrorCode::bad_request, std::string("missing array field '") + key + "'");
    }
    std::vector<std::string> out;
    for (const auto& item : *it) {
        if (!item.is_string()) {
            return fail(ErrorCode::bad_request,
                        std::string("field '") + key + "' must contain strings");
        }
        out.push_back(item.get<std::string>());
    }
    return out;
}

} // namespace

Result<Envelope> parse_envelope(std::string_view text) {
    nlohmann::json root = nlohmann::json::parse(text.begin(), text.end(), nullptr, false);
    if (root.is_discarded() || !root.is_object()) {
        return fail(ErrorCode::bad_request, "frame is not a JSON object");
    }

    Envelope env;
    if (const auto it = root.find("re"); it != root.end()) {
        if (!it->is_number_unsigned() && !it->is_number_integer()) {
            return fail(ErrorCode::bad_request, "'re' must be an integer");
        }
        env.is_response = true;
        const auto value = it->get<std::int64_t>();
        if (value < 0)
            return fail(ErrorCode::bad_request, "'re' must be positive");
        env.id = static_cast<std::uint64_t>(value);
    } else if (const auto id = root.find("id"); id != root.end()) {
        if (!id->is_number_unsigned() && !id->is_number_integer()) {
            return fail(ErrorCode::bad_request, "'id' must be an integer");
        }
        const auto value = id->get<std::int64_t>();
        if (value < 0)
            return fail(ErrorCode::bad_request, "'id' must be positive");
        env.id = static_cast<std::uint64_t>(value);
    }

    const auto type = root.find("type");
    if (type != root.end()) {
        if (!type->is_string())
            return fail(ErrorCode::bad_request, "'type' must be a string");
        env.type = type->get<std::string>();
        if (env.type.starts_with("event."))
            env.is_event = true;
    } else if (!env.is_response) {
        return fail(ErrorCode::bad_request, "message has no 'type'");
    }

    if (env.id && env.type.empty() && root.contains("ok")) {
        // Response envelope.
    } else if (env.id && !env.is_response && root.contains("ok")) {
        return fail(ErrorCode::bad_request, "request must not carry 'ok'");
    }

    env.body = root;
    return env;
}

std::string make_ok_response(std::uint64_t id, nlohmann::json fields) {
    nlohmann::json root = nlohmann::json::object();
    root["re"] = id;
    root["ok"] = true;
    if (fields.is_object()) {
        for (auto it = fields.begin(); it != fields.end(); ++it) {
            root[it.key()] = it.value();
        }
    }
    return root.dump();
}

std::string make_error_response(std::uint64_t id, ErrorInfo error) {
    nlohmann::json root{
        {"re", id}, {"ok", false}, {"error", {{"code", error.code}, {"message", error.message}}}};
    return root.dump();
}

std::string make_event(std::string_view type, nlohmann::json fields) {
    nlohmann::json root = nlohmann::json::object();
    root["type"] = type;
    if (fields.is_object()) {
        for (auto it = fields.begin(); it != fields.end(); ++it) {
            root[it.key()] = it.value();
        }
    }
    return root.dump();
}

Result<PairStart> parse_pair_start(const nlohmann::json& body) {
    if (auto r = require_object(body); !r)
        return std::unexpected(r.error());
    PairStart out;
    auto proto = require_int(body, "proto");
    if (!proto)
        return std::unexpected(proto.error());
    out.proto = *proto;
    auto name = require_string(body, "name", 63);
    if (!name)
        return std::unexpected(name.error());
    out.name = *name;
    auto method = require_string(body, "method", 32);
    if (!method)
        return std::unexpected(method.error());
    out.method = *method;
    auto suite = require_string(body, "suite", 64);
    if (!suite)
        return std::unexpected(suite.error());
    out.suite = *suite;
    if (out.method == kSpakeMethod) {
        auto share = require_string(body, "share", 512);
        if (!share)
            return std::unexpected(share.error());
        out.share_b64 = *share;
        if (out.suite != kSpakeSuite) {
            return fail(ErrorCode::unsupported, "unsupported SPAKE2 suite");
        }
    } else if (out.method == kDevPairMethod) {
        auto code = require_string(body, "code", 16);
        if (!code)
            return std::unexpected(code.error());
        out.share_b64.clear();
    } else {
        return fail(ErrorCode::unsupported, "unsupported pairing method");
    }
    if (out.proto != kVersion) {
        return fail(ErrorCode::version_mismatch, "unsupported pairing protocol version");
    }
    return out;
}

nlohmann::json to_json(const PairStartResponse& value) {
    return nlohmann::json{
        {"host_name", value.host_name}, {"share", value.share_b64}, {"confirm", value.confirm_b64}};
}

Result<PairConfirmRequest> parse_pair_confirm(const nlohmann::json& body) {
    if (auto r = require_object(body); !r)
        return std::unexpected(r.error());
    PairConfirmRequest out;
    auto confirm = require_string(body, "confirm", 256);
    if (!confirm)
        return std::unexpected(confirm.error());
    out.confirm_b64 = *confirm;
    return out;
}

nlohmann::json to_json(const PairConfirmResponse& value) {
    return nlohmann::json{{"host_id", value.host_id}, {"host_name", value.host_name}};
}

Result<SessionHello> parse_session_hello(const nlohmann::json& body) {
    if (auto r = require_object(body); !r)
        return std::unexpected(r.error());
    SessionHello out;
    auto min = require_int(body, "proto_min");
    if (!min)
        return std::unexpected(min.error());
    auto max = require_int(body, "proto_max");
    if (!max)
        return std::unexpected(max.error());
    out.proto_min = *min;
    out.proto_max = *max;
    if (out.proto_min < 1 || out.proto_max < out.proto_min || out.proto_max > kVersion) {
        // A peer may support a higher max; we simply have no overlap if min is higher.
        if (out.proto_min > kVersion) {
            return fail(ErrorCode::version_mismatch, "no common protocol version");
        }
    }
    auto app = require_string(body, "app", 64);
    if (!app)
        return std::unexpected(app.error());
    out.app = *app;
    auto name = require_string(body, "name", 63);
    if (!name)
        return std::unexpected(name.error());
    out.name = *name;
    auto roc = require_string(body, "roc", 32);
    if (!roc)
        return std::unexpected(roc.error());
    out.roc = *roc;
    auto enc = require_string_array(body, "wire_encodings");
    if (!enc)
        return std::unexpected(enc.error());
    out.wire_encodings = *enc;
    auto fec = require_string_array(body, "fec");
    if (!fec)
        return std::unexpected(fec.error());
    out.fec = *fec;
    if (!contains(out.wire_encodings, kWireEncoding)) {
        return fail(ErrorCode::version_mismatch, "no common wire encoding");
    }
    if (!contains(out.fec, kFec)) {
        return fail(ErrorCode::unsupported, "FEC rs8m is required");
    }
    return out;
}

nlohmann::json to_json(const SessionHelloResponse& value) {
    return nlohmann::json{
        {"proto", value.proto},
        {"host_name", value.host_name},
        {"host_version", value.host_version},
        {"roc", value.roc},
        {"wire_encoding", value.wire_encoding},
        {"fec", value.fec},
        {"stream",
         {{"wire_rate_hz", value.stream.wire_rate_hz},
          {"channels", value.stream.channels},
          {"packet_ms", value.stream.packet_ms},
          {"fec_block_ms", value.stream.fec_block_ms},
          {"min_latency_ms", value.stream.min_latency_ms}}},
        {"sink", {{"name", value.sink.name}, {"available", value.sink.available}}},
        {"streaming", value.streaming},
        {"caps", {{"multi", value.caps.multi}, {"host_request", value.caps.host_request}}}};
}

Result<StreamStart> parse_stream_start(const nlohmann::json& body) {
    if (auto r = require_object(body); !r)
        return std::unexpected(r.error());
    StreamStart out;
    const auto receiver = body.find("receiver");
    if (receiver == body.end() || !receiver->is_object()) {
        return fail(ErrorCode::bad_request, "missing receiver object");
    }
    auto source_port = require_int(*receiver, "source_port");
    if (!source_port)
        return std::unexpected(source_port.error());
    auto repair_port = require_int(*receiver, "repair_port");
    if (!repair_port)
        return std::unexpected(repair_port.error());
    if (*source_port < 1 || *source_port > 65535 || *repair_port < 1 || *repair_port > 65535) {
        return fail(ErrorCode::bad_request, "receiver ports out of range");
    }
    out.source_port = static_cast<std::uint16_t>(*source_port);
    out.repair_port = static_cast<std::uint16_t>(*repair_port);
    auto enc = require_string(body, "wire_encoding", 64);
    if (!enc)
        return std::unexpected(enc.error());
    out.wire_encoding = *enc;
    auto fec = require_string(body, "fec", 16);
    if (!fec)
        return std::unexpected(fec.error());
    out.fec = *fec;
    auto latency = require_int(body, "target_latency_ms");
    if (!latency)
        return std::unexpected(latency.error());
    out.target_latency_ms = *latency;
    if (out.wire_encoding != kWireEncoding) {
        return fail(ErrorCode::unsupported, "unsupported wire encoding");
    }
    if (out.fec != kFec) {
        return fail(ErrorCode::unsupported, "unsupported FEC encoding");
    }
    if (out.target_latency_ms < 0 || out.target_latency_ms > 5000) {
        return fail(ErrorCode::bad_request, "target_latency_ms out of range");
    }
    return out;
}

Result<StreamStop> parse_stream_stop(const nlohmann::json& body) {
    if (auto r = require_object(body); !r)
        return std::unexpected(r.error());
    auto id = require_int(body, "stream_id");
    if (!id)
        return std::unexpected(id.error());
    if (*id < 0)
        return fail(ErrorCode::bad_request, "stream_id must be positive");
    return StreamStop{static_cast<std::uint32_t>(*id)};
}

Result<MicStart> parse_mic_start(const nlohmann::json& body) {
    if (auto r = require_object(body); !r)
        return std::unexpected(r.error());
    MicStart out;
    auto enc = require_string(body, "wire_encoding", 64);
    if (!enc)
        return std::unexpected(enc.error());
    out.wire_encoding = *enc;
    auto fec = require_string(body, "fec", 16);
    if (!fec)
        return std::unexpected(fec.error());
    out.fec = *fec;
    if (out.wire_encoding != kWireEncoding) {
        return fail(ErrorCode::unsupported, "unsupported wire encoding");
    }
    if (out.fec != kFec) {
        return fail(ErrorCode::unsupported, "unsupported FEC encoding");
    }
    return out;
}

nlohmann::json to_json(const MicStartResponse& value) {
    return nlohmann::json{
        {"stream_id", value.stream_id},
        {"receiver",
         {{"source_port", value.source_port}, {"repair_port", value.repair_port}}},
        {"state", value.state}};
}

Result<MicStop> parse_mic_stop(const nlohmann::json& body) {
    if (auto r = require_object(body); !r)
        return std::unexpected(r.error());
    auto id = require_int(body, "stream_id");
    if (!id)
        return std::unexpected(id.error());
    if (*id < 0)
        return fail(ErrorCode::bad_request, "stream_id must be positive");
    return MicStop{static_cast<std::uint32_t>(*id)};
}

nlohmann::json to_json(const MicStateEvent& value) {
    nlohmann::json out{{"stream_id", value.stream_id}, {"state", value.state}};
    if (!value.reason.empty())
        out["reason"] = value.reason;
    return out;
}

Result<DeviceRename> parse_device_rename(const nlohmann::json& body) {
    if (auto r = require_object(body); !r)
        return std::unexpected(r.error());
    auto name = require_string(body, "name", 63);
    if (!name)
        return std::unexpected(name.error());
    if (name->empty())
        return fail(ErrorCode::bad_request, "name must not be empty");
    return DeviceRename{*name};
}

nlohmann::json to_json(const HostStatus& value) {
    return nlohmann::json{{"sink_available", value.sink_available},
                          {"streaming", value.streaming},
                          {"other_sessions", value.other_sessions}};
}

nlohmann::json to_json(const StreamStateEvent& value) {
    nlohmann::json out{{"stream_id", value.stream_id}, {"state", value.state}};
    if (!value.reason.empty())
        out["reason"] = value.reason;
    return out;
}

} // namespace ar::protocol
