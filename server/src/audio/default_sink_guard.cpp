// SPDX-License-Identifier: MIT
#include "audio/default_sink_guard.hpp"

#include "common/log.hpp"

#include <cassert>
#include <chrono>
#include <mutex>
#include <nlohmann/json.hpp>
#include <pipewire/extensions/metadata.h>
#include <pipewire/proxy.h>
#include <thread>

namespace ar {
namespace {

constexpr std::string_view kConfiguredKey = "default.configured.audio.sink";
constexpr std::string_view kActiveKey = "default.audio.sink";

std::once_flag g_pw_init;

void ensure_pw_init() {
    std::call_once(g_pw_init, [] { pw_init(nullptr, nullptr); });
}

} // namespace

DefaultSinkGuard::DefaultSinkGuard() = default;
DefaultSinkGuard::~DefaultSinkGuard() {
    stop();
}

Result<void> DefaultSinkGuard::start() {
    ensure_pw_init();
    loop_ = pw_thread_loop_new("trill-default-sink", nullptr);
    if (loop_ == nullptr) {
        return fail(ErrorCode::internal, "pw_thread_loop_new failed");
    }
    context_ = pw_context_new(pw_thread_loop_get_loop(loop_), nullptr, 0);
    if (context_ == nullptr) {
        teardown();
        return fail(ErrorCode::no_sink, "cannot create PipeWire context");
    }
    // The thread loop must be running before proxies are created or used on it.
    pw_thread_loop_lock(loop_);
    if (pw_thread_loop_start(loop_) < 0) {
        pw_thread_loop_unlock(loop_);
        teardown();
        return fail(ErrorCode::no_sink, "cannot start PipeWire thread loop");
    }
    core_ = pw_context_connect(context_, nullptr, 0);
    if (core_ == nullptr) {
        pw_thread_loop_unlock(loop_);
        teardown();
        return fail(ErrorCode::no_sink, "cannot connect to PipeWire");
    }

    registry_ = pw_core_get_registry(core_, PW_VERSION_REGISTRY, 0);
    if (registry_ == nullptr) {
        pw_thread_loop_unlock(loop_);
        teardown();
        return fail(ErrorCode::no_sink, "cannot get PipeWire registry");
    }

    static const pw_registry_events registry_events = [] {
        pw_registry_events e{};
        e.version = PW_VERSION_REGISTRY_EVENTS;
        e.global = &DefaultSinkGuard::on_global;
        return e;
    }();
    spa_zero(registry_listener_);
    pw_registry_add_listener(registry_, &registry_listener_, &registry_events, this);
    pw_thread_loop_unlock(loop_);

    // Wait for the metadata global. Property enumeration follows immediately.
    std::unique_lock lock(mutex_);
    for (int i = 0; i < 40 && metadata_ == nullptr; ++i) {
        lock.unlock();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        lock.lock();
    }
    if (metadata_ == nullptr) {
        lock.unlock();
        teardown();
        return fail(ErrorCode::no_sink, "PipeWire default metadata object not found");
    }
    return {};
}

void DefaultSinkGuard::stop() {
    teardown();
}

void DefaultSinkGuard::teardown() {
    if (loop_ != nullptr) {
        // Destroy proxies while the loop is still alive, otherwise PipeWire
        // logs "impl_ext_end_proxy called from wrong context".
        pw_thread_loop_lock(loop_);
    }
    if (metadata_ != nullptr) {
        pw_proxy_destroy(reinterpret_cast<pw_proxy*>(metadata_));
        metadata_ = nullptr;
    }
    if (registry_ != nullptr) {
        pw_proxy_destroy(reinterpret_cast<pw_proxy*>(registry_));
        registry_ = nullptr;
    }
    if (core_ != nullptr) {
        pw_core_disconnect(core_);
        core_ = nullptr;
    }
    if (loop_ != nullptr) {
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
}

void DefaultSinkGuard::on_global(void* data, std::uint32_t id, std::uint32_t /*permissions*/,
                                 const char* type, std::uint32_t /*version*/,
                                 const spa_dict* props) {
    static_cast<DefaultSinkGuard*>(data)->handle_global(id, type, props);
}

void DefaultSinkGuard::handle_global(std::uint32_t id, const char* type, const spa_dict* props) {
    if (type == nullptr || std::string_view(type) != PW_TYPE_INTERFACE_Metadata)
        return;
    const char* name = props != nullptr ? spa_dict_lookup(props, PW_KEY_METADATA_NAME) : nullptr;
    if (name == nullptr || std::string_view(name) != "default")
        return;
    if (metadata_ != nullptr)
        return;

    assert(registry_ != nullptr);
    metadata_ = static_cast<pw_metadata*>(
        pw_registry_bind(registry_, id, PW_TYPE_INTERFACE_Metadata, PW_VERSION_METADATA, 0));
    if (metadata_ == nullptr) {
        logger()->warn("cannot bind PipeWire default metadata");
        return;
    }

    static const pw_metadata_events metadata_events = [] {
        pw_metadata_events e{};
        e.version = PW_VERSION_METADATA_EVENTS;
        e.property = &DefaultSinkGuard::on_property;
        return e;
    }();
    spa_zero(metadata_listener_);
    pw_metadata_add_listener(metadata_, &metadata_listener_, &metadata_events, this);
}

int DefaultSinkGuard::on_property(void* data, std::uint32_t /*subject*/, const char* key,
                                  const char* /*type*/, const char* value) {
    static_cast<DefaultSinkGuard*>(data)->handle_property(key, value);
    return 0;
}

void DefaultSinkGuard::handle_property(const char* key, const char* value) {
    if (key == nullptr)
        return;
    const std::string_view k(key);
    if (k != kConfiguredKey && k != kActiveKey)
        return;
    std::lock_guard lock(mutex_);
    if (value == nullptr) {
        values_.erase(std::string(k));
    } else {
        values_[std::string(k)] = value;
    }
}

DefaultSinkGuard::Snapshot DefaultSinkGuard::snapshot() const {
    std::lock_guard lock(mutex_);
    return values_;
}

Result<void> DefaultSinkGuard::set_default_sink(std::string_view sink_name) {
    if (metadata_ == nullptr) {
        return fail(ErrorCode::no_sink, "default metadata is unavailable");
    }
    const std::string value = nlohmann::json{{"name", std::string(sink_name)}}.dump();
    if (loop_ != nullptr)
        pw_thread_loop_lock(loop_);
    int rc = 0;
    for (const auto key : {kConfiguredKey, kActiveKey}) {
        rc = pw_metadata_set_property(metadata_, 0, std::string(key).c_str(), "Spa:String:JSON",
                                      value.c_str());
        if (rc < 0)
            break;
    }
    if (loop_ != nullptr)
        pw_thread_loop_unlock(loop_);
    if (rc < 0) {
        return fail(ErrorCode::no_sink, "cannot set the default sink: " + std::to_string(rc));
    }
    return {};
}

Result<void> DefaultSinkGuard::restore(const Snapshot& snapshot) {
    if (metadata_ == nullptr) {
        return fail(ErrorCode::no_sink, "default metadata is unavailable");
    }
    if (loop_ != nullptr)
        pw_thread_loop_lock(loop_);
    int rc = 0;
    for (const auto key : {kConfiguredKey, kActiveKey}) {
        const auto it = snapshot.find(std::string(key));
        rc = pw_metadata_set_property(metadata_, 0, std::string(key).c_str(), "Spa:String:JSON",
                                      it == snapshot.end() ? nullptr : it->second.c_str());
        if (rc < 0)
            break;
    }
    if (loop_ != nullptr)
        pw_thread_loop_unlock(loop_);
    if (rc < 0) {
        return fail(ErrorCode::no_sink, "cannot restore the default sink: " + std::to_string(rc));
    }
    return {};
}

std::string DefaultSinkGuard::serialize(const Snapshot& snapshot) {
    nlohmann::json values = nlohmann::json::object();
    for (const auto& [key, value] : snapshot)
        values[key] = value;
    return nlohmann::json{{"version", 1}, {"values", std::move(values)}}.dump(2) + "\n";
}

Result<DefaultSinkGuard::Snapshot> DefaultSinkGuard::parse(std::string_view json) {
    nlohmann::json root = nlohmann::json::parse(json.begin(), json.end(), nullptr, false);
    if (root.is_discarded() || !root.is_object() || root.value("version", 0) != 1) {
        return fail(ErrorCode::invalid_argument, "invalid prev_default.json");
    }
    const auto values = root.find("values");
    if (values == root.end() || !values->is_object()) {
        return fail(ErrorCode::invalid_argument, "prev_default.json has no values");
    }
    Snapshot snapshot;
    for (auto it = values->begin(); it != values->end(); ++it) {
        if (!it.value().is_string()) {
            return fail(ErrorCode::invalid_argument, "prev_default.json value is not a string");
        }
        snapshot[it.key()] = it.value().get<std::string>();
    }
    return snapshot;
}

} // namespace ar
