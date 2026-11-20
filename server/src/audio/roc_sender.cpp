// SPDX-License-Identifier: MIT
#include "audio/roc_sender.hpp"

#include "common/log.hpp"

#include <memory>
#include <roc/config.h>
#include <roc/context.h>
#include <roc/endpoint.h>
#include <roc/frame.h>
#include <roc/sender.h>
#include <utility>

namespace ar {
namespace {

struct EndpointDeleter {
    void operator()(roc_endpoint* p) const {
        roc_endpoint_deallocate(p);
    }
};
using Endpoint = std::unique_ptr<roc_endpoint, EndpointDeleter>;

Result<Endpoint> make_endpoint(const std::string& uri) {
    roc_endpoint* raw = nullptr;
    if (roc_endpoint_allocate(&raw) != 0 || raw == nullptr) {
        return fail(ErrorCode::crypto_error, "roc_endpoint_allocate failed");
    }
    Endpoint endpoint(raw);
    if (roc_endpoint_set_uri(endpoint.get(), uri.c_str()) != 0) {
        return fail(ErrorCode::invalid_argument, "invalid Roc endpoint URI: " + uri);
    }
    return endpoint;
}

} // namespace

RocContext::~RocContext() {
    if (context_ != nullptr)
        roc_context_close(context_);
}

RocContext::RocContext(RocContext&& other) noexcept : context_(other.context_) {
    other.context_ = nullptr;
}

RocContext& RocContext::operator=(RocContext&& other) noexcept {
    if (this != &other) {
        if (context_ != nullptr)
            roc_context_close(context_);
        context_ = other.context_;
        other.context_ = nullptr;
    }
    return *this;
}

Result<RocContext> RocContext::create() {
    roc_context_config config{};
    config.max_packet_size = 0;
    config.max_frame_size = 0;

    RocContext context;
    if (roc_context_open(&config, &context.context_) != 0 || context.context_ == nullptr) {
        return fail(ErrorCode::internal, "roc_context_open failed (is libroc installed?)");
    }
    return context;
}

RocSender::~RocSender() {
    close();
}

RocSender::RocSender(RocSender&& other) noexcept : sender_(other.sender_) {
    other.sender_ = nullptr;
}

RocSender& RocSender::operator=(RocSender&& other) noexcept {
    if (this != &other) {
        close();
        sender_ = other.sender_;
        other.sender_ = nullptr;
    }
    return *this;
}

Result<RocSender> RocSender::create(RocContext& context, const RocSenderOptions& options) {
    if (!context.valid()) {
        return fail(ErrorCode::internal, "Roc context is not open");
    }

    roc_sender_config config{};
    config.frame_encoding.rate = 48000;
    config.frame_encoding.format = ROC_FORMAT_PCM_FLOAT32;
    config.frame_encoding.channels = ROC_CHANNEL_LAYOUT_STEREO;
    config.frame_encoding.tracks = 0;
    config.packet_encoding = ROC_PACKET_ENCODING_AVP_L16_STEREO;
    config.packet_length = static_cast<unsigned long long>(options.packet_ms) * 1'000'000ULL;
    config.packet_interleaving = 0;
    config.fec_encoding = ROC_FEC_ENCODING_RS8M;
    config.fec_block_source_packets = static_cast<unsigned int>(options.fec_block_source);
    config.fec_block_repair_packets = static_cast<unsigned int>(options.fec_block_repair);
    config.clock_source = ROC_CLOCK_SOURCE_EXTERNAL;

    RocSender sender;
    if (roc_sender_open(context.get(), &config, &sender.sender_) != 0 ||
        sender.sender_ == nullptr) {
        return fail(ErrorCode::internal, "roc_sender_open failed");
    }
    return sender;
}

Result<void> RocSender::connect(std::string_view peer_ip, std::uint16_t source_port,
                                std::uint16_t repair_port) {
    if (sender_ == nullptr) {
        return fail(ErrorCode::internal, "Roc sender is not open");
    }
    std::string host(peer_ip);
    // Strip interface scope ID if present (e.g. %wlan0)
    const auto pct = host.find('%');
    if (pct != std::string::npos) {
        host.resize(pct);
    }
    // Enclose IPv6 addresses in square brackets per Roc URI specification
    if (host.find(':') != std::string::npos && !host.starts_with('[')) {
        host = "[" + host + "]";
    }
    const auto source_uri = "rtp+rs8m://" + host + ":" + std::to_string(source_port);
    const auto repair_uri = "rs8m://" + host + ":" + std::to_string(repair_port);

    auto source = make_endpoint(source_uri);
    if (!source)
        return std::unexpected(source.error());
    auto repair = make_endpoint(repair_uri);
    if (!repair)
        return std::unexpected(repair.error());

    if (roc_sender_connect(sender_, ROC_SLOT_DEFAULT, ROC_INTERFACE_AUDIO_SOURCE, source->get()) !=
        0) {
        return fail(ErrorCode::stream_failed, "cannot connect Roc source endpoint " + source_uri);
    }
    if (roc_sender_connect(sender_, ROC_SLOT_DEFAULT, ROC_INTERFACE_AUDIO_REPAIR, repair->get()) !=
        0) {
        return fail(ErrorCode::stream_failed, "cannot connect Roc repair endpoint " + repair_uri);
    }
    logger()->info("Roc sender connected to {} (source {}, repair {})", host, source_port,
                   repair_port);
    return {};
}

Result<void> RocSender::write(const float* samples, std::size_t sample_count) {
    if (sender_ == nullptr) {
        return fail(ErrorCode::internal, "Roc sender is not open");
    }
    roc_frame frame{};
    frame.samples = const_cast<float*>(samples);
    frame.samples_size = sample_count * sizeof(float);
    if (roc_sender_write(sender_, &frame) != 0) {
        return fail(ErrorCode::stream_failed, "roc_sender_write failed");
    }
    return {};
}

void RocSender::close() {
    if (sender_ != nullptr) {
        roc_sender_close(sender_);
        sender_ = nullptr;
    }
}

} // namespace ar
