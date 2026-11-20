// SPDX-License-Identifier: MIT
#pragma once

#include "common/error.hpp"

#include <atomic>
#include <avahi-client/client.h>
#include <avahi-client/publish.h>
#include <avahi-common/thread-watch.h>
#include <cstdint>
#include <string>

namespace ar {

// Publishes _trill._tcp via Avahi. mDNS is discovery only and never
// trusted. Failure to publish (no avahi-daemon, blocked multicast) is logged
// and non-fatal; the phone can still use a manual host:port.
class MdnsPublisher {
  public:
    MdnsPublisher(std::string host_name, std::string id16, std::uint16_t port,
                  std::string roc_version);
    ~MdnsPublisher();

    MdnsPublisher(const MdnsPublisher&) = delete;
    MdnsPublisher& operator=(const MdnsPublisher&) = delete;

    [[nodiscard]] Result<void> start();
    void stop();

    void set_pairing(bool pairing);
    [[nodiscard]] bool available() const {
        return available_.load();
    }

  private:
    static void client_callback(AvahiClient* client, AvahiClientState state, void* user);
    static void group_callback(AvahiEntryGroup* group, AvahiEntryGroupState state, void* user);

    void on_client_state(AvahiClient* client, AvahiClientState state);
    void on_group_state(AvahiEntryGroupState state);
    Result<void> publish_locked();
    void withdraw_locked();
    std::string instance_name() const;

    std::string host_name_;
    std::string id16_;
    std::string roc_version_;
    std::uint16_t port_;
    AvahiThreadedPoll* poll_{nullptr};
    AvahiClient* client_{nullptr};
    AvahiEntryGroup* group_{nullptr};
    std::atomic<bool> available_{false};
    std::atomic<bool> pairing_{false};
    std::atomic<bool> stopped_{false};
};

} // namespace ar
