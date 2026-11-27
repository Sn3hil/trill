// SPDX-License-Identifier: MIT
#include "audio/roc_receiver.hpp"

#include "common/log.hpp"

#include <memory>
#include <roc/config.h>
#include <roc/context.h>
#include <roc/endpoint.h>
#include <roc/frame.h>
#include <roc/receiver.h>
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
        return fail(ErrorCode::internal, "roc_endpoint_allocate failed");
    }
    Endpoint endpoint(raw);
    if (roc_endpoint_set_uri(endpoint.get(), uri.c_str()) != 0) {
        return fail(ErrorCode::invalid_argument, "invalid Roc endpoint URI: " + uri);
    }
    return endpoint;
}

} // namespace

RocReceiver::~RocReceiver() {
    close();
}

RocReceiver::RocReceiver(RocReceiver&& other) noexcept : receiver_(other.receiver_) {
    other.receiver_ = nullptr;
}

RocReceiver& RocReceiver::operator=(RocReceiver&& other) noexcept {
    if (this != &other) {
        close();
        receiver_ = other.receiver_;
        other.receiver_ = nullptr;
    }
    return *this;
}

Result<RocReceiver> RocReceiver::create(RocContext& context, const RocReceiverOptions& options) {
    if (!context.valid()) {
        return fail(ErrorCode::internal, "Roc context is not open");
    }

    roc_receiver_config config{};
    config.frame_encoding.rate = static_cast<unsigned int>(options.rate_hz > 0 ? options.rate_hz : 44100);
    config.frame_encoding.format = ROC_FORMAT_PCM_FLOAT32;
    config.frame_encoding.channels = options.channels == 1 ? ROC_CHANNEL_LAYOUT_MONO : ROC_CHANNEL_LAYOUT_STEREO;
    config.frame_encoding.tracks = 0;
    config.clock_source = ROC_CLOCK_SOURCE_EXTERNAL;
    config.resampler_backend = ROC_RESAMPLER_BACKEND_DEFAULT;
    config.resampler_profile = ROC_RESAMPLER_PROFILE_DEFAULT;
    config.target_latency = static_cast<unsigned long long>(options.target_latency_ms) * 1'000'000ULL;

    RocReceiver receiver;
    if (roc_receiver_open(context.get(), &config, &receiver.receiver_) != 0 ||
        receiver.receiver_ == nullptr) {
        return fail(ErrorCode::internal, "roc_receiver_open failed");
    }
    return receiver;
}

Result<RocReceiverPorts> RocReceiver::bind(std::uint16_t source_port, std::uint16_t repair_port) {
    if (receiver_ == nullptr) {
        return fail(ErrorCode::internal, "receiver is not open");
    }

    const std::string src_uri = "rtp+rs8m://0.0.0.0:" + std::to_string(source_port);
    const std::string rep_uri = "rs8m://0.0.0.0:" + std::to_string(repair_port);

    auto src_ep = make_endpoint(src_uri);
    if (!src_ep)
        return std::unexpected(src_ep.error());

    auto rep_ep = make_endpoint(rep_uri);
    if (!rep_ep)
        return std::unexpected(rep_ep.error());

    if (roc_receiver_bind(receiver_, ROC_SLOT_DEFAULT, ROC_INTERFACE_AUDIO_SOURCE, src_ep->get()) !=
        0) {
        return fail(ErrorCode::io_error, "failed to bind Roc source endpoint to " + src_uri);
    }

    if (roc_receiver_bind(receiver_, ROC_SLOT_DEFAULT, ROC_INTERFACE_AUDIO_REPAIR, rep_ep->get()) !=
        0) {
        return fail(ErrorCode::io_error, "failed to bind Roc repair endpoint to " + rep_uri);
    }

    int bound_src = 0;
    int bound_rep = 0;
    if (roc_endpoint_get_port(src_ep->get(), &bound_src) != 0 || bound_src <= 0) {
        return fail(ErrorCode::internal, "failed to read bound source port");
    }
    if (roc_endpoint_get_port(rep_ep->get(), &bound_rep) != 0 || bound_rep <= 0) {
        return fail(ErrorCode::internal, "failed to read bound repair port");
    }

    return RocReceiverPorts{static_cast<std::uint16_t>(bound_src),
                            static_cast<std::uint16_t>(bound_rep)};
}

Result<void> RocReceiver::read(float* samples, std::size_t sample_count) {
    if (receiver_ == nullptr) {
        return fail(ErrorCode::internal, "receiver is not open");
    }

    roc_frame frame{};
    frame.samples = samples;
    frame.samples_size = sample_count * sizeof(float);

    if (roc_receiver_read(receiver_, &frame) != 0) {
        return fail(ErrorCode::io_error, "roc_receiver_read failed");
    }
    return {};
}

void RocReceiver::close() {
    if (receiver_ != nullptr) {
        roc_receiver_close(receiver_);
        receiver_ = nullptr;
    }
}

} // namespace ar
