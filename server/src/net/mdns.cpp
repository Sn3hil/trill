// SPDX-License-Identifier: MIT
#include "net/mdns.hpp"

#include "common/log.hpp"

#include <algorithm>
#include <avahi-common/error.h>
#include <avahi-common/malloc.h>
#include <avahi-common/strlst.h>
#include <cstring>
#include <unistd.h>

namespace ar {
namespace {

constexpr char kServiceType[] = "_trill._tcp";

std::string default_host_name() {
    char buf[256]{};
    if (::gethostname(buf, sizeof(buf) - 1) != 0 || buf[0] == '\0') {
        return "trill";
    }
    return buf;
}

} // namespace

MdnsPublisher::MdnsPublisher(std::string host_name, std::string id16, std::uint16_t port,
                             std::string roc_version)
    : host_name_(host_name.empty() ? default_host_name() : std::move(host_name)),
      id16_(std::move(id16)), roc_version_(std::move(roc_version)), port_(port) {}

MdnsPublisher::~MdnsPublisher() {
    stop();
}

Result<void> MdnsPublisher::start() {
    // The poll owns the avahi thread; the client is created against it.
    poll_ = avahi_threaded_poll_new();
    if (poll_ == nullptr) {
        return fail(ErrorCode::internal, "avahi_threaded_poll_new failed");
    }

    int error = 0;
    client_ = avahi_client_new(avahi_threaded_poll_get(poll_), AVAHI_CLIENT_NO_FAIL,
                               &MdnsPublisher::client_callback, this, &error);
    if (client_ == nullptr) {
        avahi_threaded_poll_free(poll_);
        poll_ = nullptr;
        return fail(ErrorCode::io_error,
                    std::string("avahi_client_new failed: ") + avahi_strerror(error));
    }

    if (avahi_threaded_poll_start(poll_) < 0) {
        avahi_client_free(client_);
        client_ = nullptr;
        avahi_threaded_poll_free(poll_);
        poll_ = nullptr;
        return fail(ErrorCode::io_error, "avahi_threaded_poll_start failed");
    }
    logger()->info("mDNS publisher started for {}", instance_name());
    return {};
}

void MdnsPublisher::stop() {
    if (stopped_.exchange(true))
        return;
    if (poll_ != nullptr) {
        avahi_threaded_poll_lock(poll_);
        if (group_ != nullptr) {
            avahi_entry_group_free(group_);
            group_ = nullptr;
        }
        if (client_ != nullptr) {
            avahi_client_free(client_);
            client_ = nullptr;
        }
        avahi_threaded_poll_unlock(poll_);
        avahi_threaded_poll_stop(poll_);
        avahi_threaded_poll_free(poll_);
        poll_ = nullptr;
    }
    available_ = false;
}

void MdnsPublisher::set_pairing(bool pairing) {
    pairing_ = pairing;
    if (poll_ == nullptr || client_ == nullptr)
        return;
    avahi_threaded_poll_lock(poll_);
    if (group_ != nullptr) {
        auto result = publish_locked();
        if (!result) {
            logger()->warn("mDNS TXT update failed: {}", result.error().message);
        }
    }
    avahi_threaded_poll_unlock(poll_);
}

std::string MdnsPublisher::instance_name() const {
    // <= 63 bytes; the id suffix helps distinguish multiple hosts.
    std::string name =
        host_name_ + " (" + id16_.substr(0, std::min<std::size_t>(6, id16_.size())) + ")";
    if (name.size() > 63)
        name.resize(63);
    return name;
}

void MdnsPublisher::client_callback(AvahiClient* client, AvahiClientState state, void* user) {
    static_cast<MdnsPublisher*>(user)->on_client_state(client, state);
}

void MdnsPublisher::on_client_state(AvahiClient* client, AvahiClientState state) {
    // avahi_client_new may invoke this callback before it returns, so the
    // member is not assigned yet. Always use the callback argument.
    if (client != nullptr && client_ == nullptr)
        client_ = client;
    switch (state) {
    case AVAHI_CLIENT_S_RUNNING: {
        if (group_ == nullptr) {
            group_ = avahi_entry_group_new(client, &MdnsPublisher::group_callback, this);
            if (group_ == nullptr) {
                logger()->warn("avahi_entry_group_new failed");
                return;
            }
        }
        if (auto result = publish_locked(); !result) {
            logger()->warn("mDNS publish failed: {}", result.error().message);
        }
        break;
    }
    case AVAHI_CLIENT_FAILURE:
        available_ = false;
        logger()->warn("avahi client failure: {}", avahi_strerror(avahi_client_errno(client)));
        break;
    case AVAHI_CLIENT_S_COLLISION:
    case AVAHI_CLIENT_S_REGISTERING:
        if (group_ != nullptr)
            avahi_entry_group_reset(group_);
        break;
    case AVAHI_CLIENT_CONNECTING:
        available_ = false;
        break;
    }
}

void MdnsPublisher::group_callback(AvahiEntryGroup* group, AvahiEntryGroupState state, void* user) {
    (void)group;
    static_cast<MdnsPublisher*>(user)->on_group_state(state);
}

void MdnsPublisher::on_group_state(AvahiEntryGroupState state) {
    switch (state) {
    case AVAHI_ENTRY_GROUP_ESTABLISHED:
        available_ = true;
        logger()->info("mDNS service established: {} port {}", instance_name(), port_);
        break;
    case AVAHI_ENTRY_GROUP_COLLISION:
        logger()->warn("mDNS name collision for {}", instance_name());
        break;
    case AVAHI_ENTRY_GROUP_FAILURE:
        available_ = false;
        logger()->warn("mDNS entry group failure: {}", avahi_strerror(avahi_client_errno(client_)));
        break;
    case AVAHI_ENTRY_GROUP_UNCOMMITED:
    case AVAHI_ENTRY_GROUP_REGISTERING:
        break;
    }
}

Result<void> MdnsPublisher::publish_locked() {
    if (group_ == nullptr) {
        return fail(ErrorCode::internal, "mDNS entry group is not ready");
    }
    avahi_entry_group_reset(group_);

    AvahiStringList* txt = nullptr;
    auto add = [&](const char* key, const std::string& value) {
        txt = avahi_string_list_add_pair(txt, key, value.c_str());
    };
    add("v", "1");
    add("id", id16_);
    add("name", host_name_.substr(0, 63));
    add("pair", pairing_ ? "1" : "0");
    add("proto", "1");
    add("roc", roc_version_);

    const int rc = avahi_entry_group_add_service_strlst(
        group_, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, static_cast<AvahiPublishFlags>(0),
        instance_name().c_str(), kServiceType, nullptr, nullptr, port_, txt);
    avahi_string_list_free(txt);
    if (rc < 0) {
        return fail(ErrorCode::io_error, std::string("add_service failed: ") + avahi_strerror(rc));
    }
    if (avahi_entry_group_commit(group_) < 0) {
        return fail(ErrorCode::io_error, "entry group commit failed");
    }
    return {};
}

void MdnsPublisher::withdraw_locked() {
    if (group_ != nullptr)
        avahi_entry_group_reset(group_);
}

} // namespace ar
