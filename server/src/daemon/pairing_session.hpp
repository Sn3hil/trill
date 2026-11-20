// SPDX-License-Identifier: MIT
#pragma once

#include "common/error.hpp"
#include "net/tls.hpp"
#include "pairing/pairing_manager.hpp"

#include <memory>
#include <nlohmann/json.hpp>
#include <string>

namespace ar {

// One pairing connection (ALPN tr-pair/1). Exactly two requests are accepted:
// pair.start and pair.confirm. Any failure replies once and closes the socket.
class PairingSession : public std::enable_shared_from_this<PairingSession> {
  public:
    PairingSession(TlsConnection::Ptr connection, PairingManager& pairing, std::string host_id,
                   std::string peer_ip);
    ~PairingSession();

    PairingSession(const PairingSession&) = delete;
    PairingSession& operator=(const PairingSession&) = delete;

    void start();

  private:
    void read_next();
    void handle_frame(const std::string& payload);
    void reply_ok(std::uint64_t id, nlohmann::json fields, bool close_after);
    void reply_error(std::uint64_t id, const Error& error);
    void fail(const Error& error);
    void close();

    TlsConnection::Ptr connection_;
    PairingManager& pairing_;
    std::string host_id_;
    std::string peer_ip_;
    std::string peer_spki_;
    bool started_{false};
    bool confirmed_{false};
    bool closed_{false};
};

} // namespace ar
