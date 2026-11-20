// SPDX-License-Identifier: MIT
#include "audio/pw_sink.hpp"

#include "common/log.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <mutex>
#include <spa/param/audio/format-utils.h>
#include <spa/pod/builder.h>
#include <thread>

namespace ar {
namespace {

std::once_flag g_pw_init;

void ensure_pw_init() {
    std::call_once(g_pw_init, [] { pw_init(nullptr, nullptr); });
}

} // namespace

PwSink::PwSink(SinkOptions options) : options_(std::move(options)), format_{} {}
PwSink::~PwSink() {
    stop();
}

Result<void> PwSink::start(CaptureFormat format, FrameCallback on_samples) {
    if (running_.load()) {
        return fail(ErrorCode::busy, "PipeWire sink is already running");
    }
    ensure_pw_init();
    format_ = format;
    on_samples_ = std::move(on_samples);

    loop_ = pw_thread_loop_new("trill-pw", nullptr);
    if (loop_ == nullptr) {
        return fail(ErrorCode::internal, "pw_thread_loop_new failed");
    }
    context_ = pw_context_new(pw_thread_loop_get_loop(loop_), nullptr, 0);
    if (context_ == nullptr) {
        stop();
        return fail(ErrorCode::no_sink, "cannot create PipeWire context");
    }

    // The thread loop must be running before proxies are created or used on it.
    pw_thread_loop_lock(loop_);
    if (pw_thread_loop_start(loop_) < 0) {
        pw_thread_loop_unlock(loop_);
        stop();
        return fail(ErrorCode::no_sink, "cannot start PipeWire thread loop");
    }
    core_ = pw_context_connect(context_, nullptr, 0);
    if (core_ == nullptr) {
        pw_thread_loop_unlock(loop_);
        stop();
        return fail(ErrorCode::no_sink, "cannot connect to PipeWire (is pipewire running?)");
    }

    const auto stream_result = create_stream();
    pw_thread_loop_unlock(loop_);
    if (!stream_result) {
        stop();
        return std::unexpected(stream_result.error());
    }

    // Wait for the stream to reach a usable state. Startup only.
    pw_stream_state state = PW_STREAM_STATE_CONNECTING;
    for (int i = 0; i < 60; ++i) {
        pw_thread_loop_lock(loop_);
        state = pw_stream_get_state(stream_, nullptr);
        pw_thread_loop_unlock(loop_);
        if (state == PW_STREAM_STATE_PAUSED || state == PW_STREAM_STATE_STREAMING)
            break;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    if (state != PW_STREAM_STATE_PAUSED && state != PW_STREAM_STATE_STREAMING) {
        stop();
        return fail(ErrorCode::no_sink, "PipeWire sink did not become ready");
    }

    running_ = true;
    std::uint32_t node_id = 0;
    if (loop_ != nullptr) {
        pw_thread_loop_lock(loop_);
        node_id = pw_stream_get_node_id(stream_);
        pw_thread_loop_unlock(loop_);
    }
    logger()->info("virtual sink '{}' ready ({} Hz, {} ch, node {})", options_.name,
                   format_.rate_hz, format_.channels, node_id);
    return {};
}

Result<void> PwSink::create_stream() {
    auto* props = pw_properties_new(
        PW_KEY_NODE_NAME, options_.name.c_str(), PW_KEY_NODE_DESCRIPTION,
        options_.description.c_str(), PW_KEY_MEDIA_CLASS, "Audio/Sink", PW_KEY_MEDIA_TYPE, "Audio",
        PW_KEY_MEDIA_CATEGORY, "Playback", PW_KEY_AUDIO_RATE,
        std::to_string(format_.rate_hz).c_str(), PW_KEY_AUDIO_CHANNELS,
        std::to_string(format_.channels).c_str(), "audio.position", "[ FL, FR ]", "node.virtual",
        "true", "node.autoconnect", "true", "node.want-driver", "true", "node.always-process",
        "true", "node.pause-on-idle", "false", "port.group", "stream.0", nullptr);
    if (props == nullptr) {
        return fail(ErrorCode::internal, "pw_properties_new failed");
    }

    stream_ = pw_stream_new(core_, options_.name.c_str(), props);
    if (stream_ == nullptr) {
        return fail(ErrorCode::no_sink, "pw_stream_new failed");
    }

    static const pw_stream_events events = [] {
        pw_stream_events e{};
        e.version = PW_VERSION_STREAM_EVENTS;
        e.process = &PwSink::on_process;
        e.state_changed = &PwSink::on_state_changed;
        return e;
    }();
    spa_zero(stream_listener_);
    pw_stream_add_listener(stream_, &stream_listener_, &events, this);

    std::uint8_t pod_buffer[1024];
    spa_pod_builder builder = SPA_POD_BUILDER_INIT(pod_buffer, sizeof(pod_buffer));
    spa_audio_info_raw raw{};
    raw.format = SPA_AUDIO_FORMAT_F32_LE;
    raw.rate = static_cast<std::uint32_t>(format_.rate_hz);
    raw.channels = static_cast<std::uint32_t>(format_.channels);
    if (format_.channels > 0)
        raw.position[0] = SPA_AUDIO_CHANNEL_FL;
    if (format_.channels > 1)
        raw.position[1] = SPA_AUDIO_CHANNEL_FR;
    const spa_pod* params[1];
    params[0] = spa_format_audio_raw_build(&builder, SPA_PARAM_EnumFormat, &raw);
    if (params[0] == nullptr) {
        return fail(ErrorCode::internal, "cannot build audio format pod");
    }

    const auto flags =
        static_cast<pw_stream_flags>(PW_STREAM_FLAG_AUTOCONNECT | PW_STREAM_FLAG_RT_PROCESS |
                                     PW_STREAM_FLAG_MAP_BUFFERS | PW_STREAM_FLAG_ASYNC);
    if (pw_stream_connect(stream_, PW_DIRECTION_INPUT, PW_ID_ANY, flags, params, 1) < 0) {
        return fail(ErrorCode::no_sink, "pw_stream_connect failed");
    }
    return {};
}

void PwSink::on_process(void* userdata) {
    auto* self = static_cast<PwSink*>(userdata);
    if (!self->on_samples_)
        return;

    pw_buffer* buffer = pw_stream_dequeue_buffer(self->stream_);
    while (buffer != nullptr) {
        spa_buffer* spa_buf = buffer->buffer;
        if (spa_buf != nullptr && spa_buf->n_datas > 0) {
            spa_data& data = spa_buf->datas[0];
            if (data.data != nullptr && data.chunk != nullptr && data.chunk->size > 0) {
                const std::size_t offset = data.chunk->offset;
                const std::size_t max_size = data.maxsize;
                if (offset <= max_size) {
                    const std::size_t bytes =
                        std::min<std::size_t>(data.chunk->size, max_size - offset);
                    const auto* samples = reinterpret_cast<const float*>(
                        static_cast<const std::uint8_t*>(data.data) + offset);
                    self->on_samples_(samples, bytes / sizeof(float));
                    self->callback_count_.fetch_add(1, std::memory_order_relaxed);
                }
            }
        }
        pw_stream_queue_buffer(self->stream_, buffer);
        buffer = pw_stream_dequeue_buffer(self->stream_);
    }
}

void PwSink::on_state_changed(void* userdata, pw_stream_state /*old_state*/, pw_stream_state state,
                              const char* error) {
    auto* self = static_cast<PwSink*>(userdata);
    if (state == PW_STREAM_STATE_ERROR && error != nullptr) {
        logger()->warn("PipeWire sink error: {}", error);
        self->running_ = false;
    }
}

void PwSink::stop() {
    running_ = false;
    if (loop_ != nullptr) {
        // Destroy proxies while the loop is still alive, otherwise PipeWire
        // logs "impl_ext_end_proxy called from wrong context".
        pw_thread_loop_lock(loop_);
        if (stream_ != nullptr) {
            pw_stream_destroy(stream_);
            stream_ = nullptr;
        }
        if (core_ != nullptr) {
            pw_core_disconnect(core_);
            core_ = nullptr;
        }
        pw_thread_loop_unlock(loop_);
        pw_thread_loop_stop(loop_);
    }
    if (context_ != nullptr) {
        pw_context_destroy(context_);
        context_ = nullptr;
    }
    if (loop_ != nullptr) {
        pw_thread_loop_destroy(loop_);
        loop_ = nullptr;
    }
    on_samples_ = nullptr;
}

} // namespace ar
