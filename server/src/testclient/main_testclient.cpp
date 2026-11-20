// SPDX-License-Identifier: MIT
// trill-testclient: a fake phone for end-to-end testing without Android.
#include "cli/ipc_client.hpp"
#include "common/encoding.hpp"
#include "common/error.hpp"
#include "common/log.hpp"
#include "common/paths.hpp"
#include "crypto/spake2.hpp"
#include "crypto/spki.hpp"
#include "net/framing.hpp"
#include "net/tls.hpp"
#include "protocol/messages.hpp"
#include "store/identity.hpp"

#include <CLI/CLI.hpp>
#include <array>
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <nlohmann/json.hpp>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <roc/config.h>
#include <roc/context.h>
#include <roc/endpoint.h>
#include <roc/frame.h>
#include <roc/receiver.h>
#include <string>
#include <sys/socket.h>
#include <sys/time.h>
#include <thread>
#include <vector>

namespace {

using ar::Error;
using ar::ErrorCode;
using ar::Result;
using nlohmann::json;

constexpr int kSampleRate = 48000;
constexpr int kChannels = 2;
constexpr int kFrameSamples = kSampleRate / 100; // 10 ms

struct EndpointDeleter {
    void operator()(roc_endpoint* endpoint) const {
        if (endpoint != nullptr)
            roc_endpoint_deallocate(endpoint);
    }
};
using Endpoint = std::unique_ptr<roc_endpoint, EndpointDeleter>;

Result<Endpoint> make_endpoint(const std::string& uri) {
    roc_endpoint* raw = nullptr;
    if (roc_endpoint_allocate(&raw) != 0 || raw == nullptr) {
        return ar::fail(ErrorCode::internal, "roc_endpoint_allocate failed");
    }
    Endpoint endpoint(raw);
    if (roc_endpoint_set_uri(endpoint.get(), uri.c_str()) != 0) {
        return ar::fail(ErrorCode::invalid_argument, "invalid Roc URI " + uri);
    }
    return endpoint;
}

// Blocking TLS client. The testclient is single-threaded, so this keeps the
// pairing and streaming flows linear and easy to debug.
class SyncTls {
  public:
    explicit SyncTls(std::shared_ptr<asio::ssl::context> context)
        : context_(std::move(context)), stream_(io_, *context_) {}

    ~SyncTls() {
        std::error_code ec;
        stream_.lowest_layer().close(ec);
    }

    SyncTls(const SyncTls&) = delete;
    SyncTls& operator=(const SyncTls&) = delete;

    Result<void> connect(const std::string& host, std::uint16_t port, const std::string& alpn) {
        std::error_code ec;
        asio::ip::tcp::resolver resolver(io_);
        const auto endpoints = resolver.resolve(host, std::to_string(port), ec);
        if (ec) {
            return ar::fail(ErrorCode::io_error, "cannot resolve " + host + ": " + ec.message());
        }
        asio::connect(stream_.lowest_layer(), endpoints, ec);
        if (ec) {
            return ar::fail(ErrorCode::io_error, "cannot connect to " + host + ":" +
                                                     std::to_string(port) + ": " + ec.message());
        }
        stream_.lowest_layer().set_option(asio::ip::tcp::no_delay(true), ec);
        set_receive_timeout(1000);

        std::vector<unsigned char> wire;
        wire.push_back(static_cast<unsigned char>(alpn.size()));
        wire.insert(wire.end(), alpn.begin(), alpn.end());
        SSL_set_alpn_protos(stream_.native_handle(), wire.data(),
                            static_cast<unsigned int>(wire.size()));
        std::error_code addr_ec;
        (void)asio::ip::make_address(host, addr_ec);
        if (addr_ec) {
            SSL_ctrl(stream_.native_handle(), SSL_CTRL_SET_TLSEXT_HOSTNAME,
                     TLSEXT_NAMETYPE_host_name, const_cast<char*>(host.c_str()));
        }
        stream_.handshake(asio::ssl::stream_base::client, ec);
        if (ec) {
            return ar::fail(ErrorCode::crypto_error, "TLS handshake failed: " + ec.message());
        }
        const unsigned char* selected = nullptr;
        unsigned int length = 0;
        SSL_get0_alpn_selected(stream_.native_handle(), &selected, &length);
        if (selected == nullptr || length == 0 ||
            std::string(reinterpret_cast<const char*>(selected), length) != alpn) {
            return ar::fail(ErrorCode::protocol_error, "server did not select " + alpn);
        }
        return {};
    }

    Result<std::string> peer_spki_hex() {
        X509* cert = SSL_get1_peer_certificate(stream_.native_handle());
        if (cert == nullptr) {
            return ar::fail(ErrorCode::not_paired, "host presented no certificate");
        }
        auto result = ar::spki_sha256_hex(cert);
        X509_free(cert);
        return result;
    }

    std::string peer_ip() const {
        std::error_code ec;
        const auto endpoint = stream_.lowest_layer().remote_endpoint(ec);
        return ec ? std::string() : endpoint.address().to_string();
    }

    Result<void> write_json(const json& message) {
        auto frame = ar::encode_frame(message.dump());
        if (!frame)
            return std::unexpected(frame.error());
        std::error_code ec;
        asio::write(stream_, asio::buffer(*frame), ec);
        if (ec) {
            return ar::fail(ErrorCode::io_error, "write failed: " + ec.message());
        }
        return {};
    }

    Result<json> read_json() {
        std::array<std::uint8_t, 4> header{};
        std::error_code ec;
        asio::read(stream_, asio::buffer(header), ec);
        if (ec) {
            return ar::fail(ec == asio::error::would_block || ec == asio::error::try_again
                                ? ErrorCode::timeout
                                : ErrorCode::io_error,
                            "read header failed: " + ec.message());
        }
        const std::uint32_t length = (static_cast<std::uint32_t>(header[0]) << 24) |
                                     (static_cast<std::uint32_t>(header[1]) << 16) |
                                     (static_cast<std::uint32_t>(header[2]) << 8) |
                                     static_cast<std::uint32_t>(header[3]);
        if (length == 0 || length > ar::kMaxFrameSize) {
            return ar::fail(ErrorCode::protocol_error, "invalid frame length from host");
        }
        std::string payload(length, '\0');
        asio::read(stream_, asio::buffer(payload.data(), payload.size()), ec);
        if (ec) {
            return ar::fail(ErrorCode::io_error, "read body failed: " + ec.message());
        }
        auto parsed = json::parse(payload.begin(), payload.end(), nullptr, false);
        if (parsed.is_discarded() || !parsed.is_object()) {
            return ar::fail(ErrorCode::protocol_error, "host sent invalid JSON");
        }
        return parsed;
    }

    bool has_data() {
        std::error_code ec;
        return stream_.lowest_layer().available(ec) > 0 && !ec;
    }

    void close() {
        std::error_code ec;
        stream_.lowest_layer().close(ec);
    }

  private:
    void set_receive_timeout(int milliseconds) {
        timeval tv{};
        tv.tv_sec = milliseconds / 1000;
        tv.tv_usec = (milliseconds % 1000) * 1000;
        ::setsockopt(stream_.lowest_layer().native_handle(), SOL_SOCKET, SO_RCVTIMEO, &tv,
                     sizeof(tv));
    }

    std::shared_ptr<asio::ssl::context> context_;
    asio::io_context io_;
    asio::ssl::stream<asio::ip::tcp::socket> stream_;
};

// Binds the phone's Roc receiver and reads 48 kHz float stereo frames.
class RocReceiver {
  public:
    RocReceiver() = default;
    ~RocReceiver() {
        close();
    }
    RocReceiver(const RocReceiver&) = delete;
    RocReceiver& operator=(const RocReceiver&) = delete;

    Result<void> open() {
        roc_context_config context_config{};
        if (roc_context_open(&context_config, &context_) != 0 || context_ == nullptr) {
            return ar::fail(ErrorCode::internal, "roc_context_open failed");
        }
        roc_receiver_config config{};
        config.frame_encoding.rate = kSampleRate;
        config.frame_encoding.format = ROC_FORMAT_PCM_FLOAT32;
        config.frame_encoding.channels = ROC_CHANNEL_LAYOUT_STEREO;
        config.frame_encoding.tracks = 0;
        config.clock_source = ROC_CLOCK_SOURCE_EXTERNAL;
        config.target_latency = 120ULL * 1000ULL * 1000ULL;
        if (roc_receiver_open(context_, &config, &receiver_) != 0 || receiver_ == nullptr) {
            return ar::fail(ErrorCode::internal, "roc_receiver_open failed");
        }
        return {};
    }

    Result<void> bind_ephemeral() {
        auto source = make_endpoint("rtp+rs8m://0.0.0.0:0");
        if (!source)
            return std::unexpected(source.error());
        if (roc_receiver_bind(receiver_, ROC_SLOT_DEFAULT, ROC_INTERFACE_AUDIO_SOURCE,
                              source->get()) != 0) {
            return ar::fail(ErrorCode::stream_failed, "cannot bind the Roc source endpoint");
        }
        int source_port = 0;
        if (roc_endpoint_get_port(source->get(), &source_port) != 0) {
            return ar::fail(ErrorCode::stream_failed, "cannot read the Roc source port");
        }

        auto repair = make_endpoint("rs8m://0.0.0.0:0");
        if (!repair)
            return std::unexpected(repair.error());
        if (roc_receiver_bind(receiver_, ROC_SLOT_DEFAULT, ROC_INTERFACE_AUDIO_REPAIR,
                              repair->get()) != 0) {
            return ar::fail(ErrorCode::stream_failed, "cannot bind the Roc repair endpoint");
        }
        int repair_port = 0;
        if (roc_endpoint_get_port(repair->get(), &repair_port) != 0) {
            return ar::fail(ErrorCode::stream_failed, "cannot read the Roc repair port");
        }
        source_port_ = static_cast<std::uint16_t>(source_port);
        repair_port_ = static_cast<std::uint16_t>(repair_port);
        return {};
    }

    Result<void> read(float* samples, std::size_t sample_count) {
        roc_frame frame{};
        frame.samples = samples;
        frame.samples_size = sample_count * sizeof(float);
        if (roc_receiver_read(receiver_, &frame) != 0) {
            return ar::fail(ErrorCode::stream_failed, "roc_receiver_read failed");
        }
        return {};
    }

    void close() {
        if (receiver_ != nullptr) {
            roc_receiver_close(receiver_);
            receiver_ = nullptr;
        }
        if (context_ != nullptr) {
            roc_context_close(context_);
            context_ = nullptr;
        }
    }

    [[nodiscard]] std::uint16_t source_port() const {
        return source_port_;
    }
    [[nodiscard]] std::uint16_t repair_port() const {
        return repair_port_;
    }

  private:
    roc_context* context_{nullptr};
    roc_receiver* receiver_{nullptr};
    std::uint16_t source_port_{0};
    std::uint16_t repair_port_{0};
};

// Minimal 16-bit PCM WAV writer for the received float frames.
class WavWriter {
  public:
    Result<void> open(const std::filesystem::path& path) {
        file_.open(path, std::ios::binary | std::ios::trunc);
        if (!file_) {
            return ar::fail(ErrorCode::io_error, "cannot create " + path.string());
        }
        write_header(0);
        return {};
    }

    Result<void> write(const float* samples, std::size_t sample_count) {
        std::vector<std::int16_t> pcm(sample_count);
        for (std::size_t i = 0; i < sample_count; ++i) {
            float value = samples[i];
            if (value > 1.0F)
                value = 1.0F;
            if (value < -1.0F)
                value = -1.0F;
            pcm[i] = static_cast<std::int16_t>(value * 32767.0F);
        }
        file_.write(reinterpret_cast<const char*>(pcm.data()),
                    static_cast<std::streamsize>(pcm.size() * sizeof(std::int16_t)));
        if (!file_)
            return ar::fail(ErrorCode::io_error, "cannot write the WAV file");
        data_bytes_ += pcm.size() * sizeof(std::int16_t);
        return {};
    }

    void close() {
        if (!file_.is_open())
            return;
        file_.seekp(0);
        write_header(static_cast<std::uint32_t>(data_bytes_));
        file_.close();
    }

    [[nodiscard]] std::uint64_t data_bytes() const {
        return data_bytes_;
    }

  private:
    void write_header(std::uint32_t data_size) {
        const std::uint32_t riff_size = 36 + data_size;
        const std::uint16_t channels = kChannels;
        const std::uint32_t rate = kSampleRate;
        const std::uint16_t bits = 16;
        const std::uint32_t byte_rate = rate * channels * bits / 8;
        const std::uint16_t block_align = static_cast<std::uint16_t>(channels * bits / 8);

        char header[44]{};
        std::memcpy(header, "RIFF", 4);
        std::memcpy(header + 4, &riff_size, 4);
        std::memcpy(header + 8, "WAVEfmt ", 8);
        const std::uint32_t fmt_size = 16;
        std::uint16_t format = 1;
        std::memcpy(header + 16, &fmt_size, 4);
        std::memcpy(header + 20, &format, 2);
        std::memcpy(header + 22, &channels, 2);
        std::memcpy(header + 24, &rate, 4);
        std::memcpy(header + 28, &byte_rate, 4);
        std::memcpy(header + 32, &block_align, 2);
        std::memcpy(header + 34, &bits, 2);
        std::memcpy(header + 36, "data", 4);
        std::memcpy(header + 40, &data_size, 4);
        file_.write(header, sizeof(header));
    }

    std::ofstream file_;
    std::uint64_t data_bytes_{0};
};

Result<json> request(SyncTls& tls, std::uint64_t id, json message, const std::string& what) {
    message["id"] = id;
    if (auto r = tls.write_json(message); !r)
        return std::unexpected(r.error());
    // Events are asynchronous notifications; the host may interleave them with
    // a response (stream.state running/stopped). Skip them until the reply.
    while (true) {
        auto response = tls.read_json();
        if (!response)
            return std::unexpected(response.error());
        if (response->contains("event") ||
            response->value("type", std::string()).starts_with("event."))
            continue;
        if (!response->value("ok", false)) {
            const auto error = response->value("error", json::object());
            return ar::fail(ar::error_code_from_name(error.value("code", std::string())),
                            what + ": " + error.value("message", std::string("failed")) +
                                " (raw: " + response->dump() + ")");
        }
        if (response->value("re", std::uint64_t{0}) != id) {
            return ar::fail(ErrorCode::protocol_error, what + ": mismatched response id");
        }
        return response;
    }
}

Result<void> pair_spake2(SyncTls& tls, const ar::HostIdentity& identity,
                         const std::string& runtime_code, const std::string& name) {
    auto host_spki = tls.peer_spki_hex();
    if (!host_spki)
        return std::unexpected(host_spki.error());

    ar::Spake2 spake(ar::SpakeRole::a, runtime_code, "tr-phone:" + identity.spki_hex(),
                     "tr-host:" + *host_spki);
    auto share = spake.share();
    if (!share)
        return std::unexpected(share.error());
    auto start = request(tls, 1,
                         json{{"type", "pair.start"},
                              {"proto", ar::protocol::kVersion},
                              {"name", name},
                              {"method", std::string(ar::protocol::kSpakeMethod)},
                              {"suite", std::string(ar::protocol::kSpakeSuite)},
                              {"share", ar::base64_encode(*share)}},
                         "pair.start");
    if (!start)
        return std::unexpected(start.error());

    auto peer_share = ar::base64_decode(start->value("share", std::string()));
    if (!peer_share)
        return std::unexpected(peer_share.error());
    if (auto r = spake.process_peer_share(*peer_share); !r)
        return r;

    auto host_confirm = spake.verify_peer_confirm_b64(start->value("confirm", std::string()));
    if (!host_confirm)
        return std::unexpected(host_confirm.error());
    if (!*host_confirm) {
        return ar::fail(ErrorCode::pair_failed, "host confirmation did not verify");
    }
    auto own_confirm = spake.own_confirm_b64();
    if (!own_confirm)
        return std::unexpected(own_confirm.error());

    auto confirm =
        request(tls, 2, json{{"type", "pair.confirm"}, {"confirm", *own_confirm}}, "pair.confirm");
    if (!confirm)
        return std::unexpected(confirm.error());
    if (confirm->value("host_id", std::string()) != *host_spki) {
        return ar::fail(ErrorCode::crypto_error, "host certificate changed during pairing");
    }
    return {};
}

Result<void> pair_dev(SyncTls& tls, const std::string& runtime_code, const std::string& name) {
    auto response = request(tls, 1,
                            json{{"type", "pair.start"},
                                 {"proto", ar::protocol::kVersion},
                                 {"name", name},
                                 {"method", std::string(ar::protocol::kDevPairMethod)},
                                 {"code", runtime_code}},
                            "pair.start (dev)");
    if (!response)
        return std::unexpected(response.error());
    return {};
}

Result<json> hello(SyncTls& tls, const std::string& name) {
    return request(tls, 1,
                   json{{"type", "session.hello"},
                        {"proto_min", 1},
                        {"proto_max", ar::protocol::kVersion},
                        {"app", "trill-testclient"},
                        {"name", name},
                        {"roc", "0.4"},
                        {"wire_encodings", json::array({std::string(ar::protocol::kWireEncoding)})},
                        {"fec", json::array({std::string(ar::protocol::kFec)})}},
                   "session.hello");
}

} // namespace

int main(int argc, char** argv) {
    std::cout << std::unitbuf;
    CLI::App app{"Fake phone: pair, connect, receive Roc audio into a WAV",
                 "trill-testclient"};
    app.set_version_flag("--version", TRILL_VERSION);

    std::string host = "127.0.0.1";
    int port = 47800;
    std::string code;
    std::string name = "Test Phone";
    std::string wav_path = "trill-testclient.wav";
    std::string identity_dir;
    int duration = 10;
    int target_latency_ms = 120;
    bool skip_pair = false;
    bool dev_pairing = false;
    bool no_wav = false;
    bool login_only = false;

    app.add_option("--host", host, "Host IPv4 address or name")->default_val(host);
    app.add_option("--port", port, "Control port")->default_val(port);
    app.add_option("--code", code, "Six-digit pairing code");
    app.add_option("--name", name, "Phone label shown on the host")->default_val(name);
    app.add_option("--wav", wav_path, "Output WAV path")->default_val(wav_path);
    app.add_option("--identity-dir", identity_dir, "Directory for the testclient certificate");
    app.add_option("--duration", duration, "Seconds of audio to receive")->default_val(duration);
    app.add_option("--target-latency-ms", target_latency_ms, "Receiver target latency")
        ->default_val(target_latency_ms);
    app.add_flag("--skip-pair", skip_pair, "Reuse an existing pin (no --code needed)");
    app.add_flag("--dev-pairing", dev_pairing, "Use dev-plain pairing (debug daemon)");
    app.add_flag("--null", no_wav, "Discard audio instead of writing a WAV");
    app.add_flag("--login-only", login_only, "Pair and say hello, then exit");

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& error) {
        const int rc = app.exit(error);
        return rc == 0 ? 0 : 2;
    }
    if (code.empty() && !skip_pair) {
        std::cerr << "trill-testclient: --code is required unless --skip-pair is set\n";
        return 2;
    }
    if (port < 1 || port > 65535 || duration <= 0) {
        std::cerr << "trill-testclient: invalid --port or --duration\n";
        return 2;
    }

    auto paths = ar::resolve_paths();
    if (!paths) {
        std::cerr << "trill-testclient: " << paths.error().message << '\n';
        return 1;
    }
    const std::filesystem::path identity_path = identity_dir.empty()
                                                    ? paths->config_dir / "testclient-identity"
                                                    : std::filesystem::path(identity_dir);
    auto identity = ar::HostIdentity::load_or_create(identity_path, "trill-phone");
    if (!identity) {
        std::cerr << "trill-testclient: " << identity.error().message << '\n';
        return 1;
    }
    std::cout << "testclient id " << ar::short_id(identity->spki_hex()) << '\n';

    auto cert = identity->cert_pem();
    auto key = identity->key_pem();
    if (!cert || !key) {
        std::cerr << "trill-testclient: cannot export the identity\n";
        return 1;
    }

    if (!skip_pair) {
        auto context = ar::make_client_tls_context(*cert, *key);
        if (!context) {
            std::cerr << "trill-testclient: " << context.error().message << '\n';
            return 1;
        }
        SyncTls tls(*context);
        if (auto r = tls.connect(host, static_cast<std::uint16_t>(port),
                                 std::string(ar::protocol::kAlpnPair));
            !r) {
            std::cerr << "trill-testclient: " << r.error().message << '\n';
            return 1;
        }
        Result<void> result =
            dev_pairing ? pair_dev(tls, code, name) : pair_spake2(tls, *identity, code, name);
        if (!result) {
            std::cerr << "trill-testclient: pairing failed: " << result.error().message
                      << '\n';
            return 1;
        }
        std::cout << "paired with the host\n";
        tls.close();
    } else if (!code.empty()) {
        std::cout << "skipping pairing (using the existing pin)\n";
    }

    auto context = ar::make_client_tls_context(*cert, *key);
    if (!context) {
        std::cerr << "trill-testclient: " << context.error().message << '\n';
        return 1;
    }
    SyncTls tls(*context);
    if (auto r = tls.connect(host, static_cast<std::uint16_t>(port),
                             std::string(ar::protocol::kAlpnCtrl));
        !r) {
        std::cerr << "trill-testclient: " << r.error().message << '\n';
        return 1;
    }
    auto hello_response = hello(tls, name);
    if (!hello_response) {
        std::cerr << "trill-testclient: " << hello_response.error().message << '\n';
        return 1;
    }
    std::cout << "connected to '" << hello_response->value("host_name", std::string("host"))
              << "' (protocol " << hello_response->value("proto", 0) << ")\n";
    if (login_only) {
        tls.close();
        return 0;
    }

    RocReceiver receiver;
    if (auto r = receiver.open(); !r) {
        std::cerr << "trill-testclient: " << r.error().message << '\n';
        return 1;
    }
    if (auto r = receiver.bind_ephemeral(); !r) {
        std::cerr << "trill-testclient: " << r.error().message << '\n';
        return 1;
    }
    std::cout << "Roc receiver bound: source " << receiver.source_port() << ", repair "
              << receiver.repair_port() << '\n';

    const int host_min_latency =
        hello_response->value("stream", json::object()).value("min_latency_ms", 120);
    if (target_latency_ms < host_min_latency)
        target_latency_ms = host_min_latency;

    auto start = request(tls, 2,
                         json{{"type", "stream.start"},
                              {"receiver", json{{"source_port", receiver.source_port()},
                                                {"repair_port", receiver.repair_port()}}},
                              {"wire_encoding", std::string(ar::protocol::kWireEncoding)},
                              {"fec", std::string(ar::protocol::kFec)},
                              {"target_latency_ms", target_latency_ms}},
                         "stream.start");
    if (!start) {
        std::cerr << "trill-testclient: " << start.error().message << '\n';
        return 1;
    }
    const std::uint32_t stream_id = start->value("stream_id", 0);
    std::cout << "host accepted stream " << stream_id << "; receiving for " << duration << "s\n";

    WavWriter wav;
    if (!no_wav) {
        if (auto r = wav.open(wav_path); !r) {
            std::cerr << "trill-testclient: " << r.error().message << '\n';
            return 1;
        }
    }

    std::vector<float> frame(static_cast<std::size_t>(kFrameSamples) * kChannels);
    std::uint64_t frames_received = 0;
    std::uint64_t next_ping = 0;
    bool host_stopped = false;
    const auto start_time = std::chrono::steady_clock::now();
    const auto deadline = start_time + std::chrono::seconds(duration);

    while (std::chrono::steady_clock::now() < deadline) {
        const auto before = std::chrono::steady_clock::now();
        if (auto r = receiver.read(frame.data(), frame.size()); !r) {
            std::cerr << "trill-testclient: " << r.error().message << '\n';
            break;
        }
        if (!no_wav) {
            if (auto r = wav.write(frame.data(), frame.size()); !r) {
                std::cerr << "trill-testclient: " << r.error().message << '\n';
                break;
            }
        }
        ++frames_received;

        if (frames_received >= next_ping) {
            next_ping = frames_received + 500; // 5 s at 10 ms frames
            if (auto r = request(tls, 100 + frames_received / 500, json{{"type", "ping"}}, "ping");
                !r) {
                std::cerr << "trill-testclient: " << r.error().message << '\n';
                break;
            }
        }

        while (tls.has_data()) {
            auto message = tls.read_json();
            if (!message)
                break;
            if (message->value("type", std::string()) == "event.stream.state" &&
                message->value("state", std::string()) == "stopped") {
                std::cout << "host stopped the stream: "
                          << message->value("reason", std::string("unknown")) << '\n';
                host_stopped = true;
                break;
            }
        }
        if (host_stopped)
            break;

        // Pace the external-clock receiver at 10 ms.
        const auto target = before + std::chrono::milliseconds(10);
        std::this_thread::sleep_until(target);
    }

    if (!host_stopped) {
        (void)request(tls, 10000, json{{"type", "stream.stop"}, {"stream_id", stream_id}},
                      "stream.stop");
    }
    tls.close();
    if (!no_wav)
        wav.close();

    const double seconds = static_cast<double>(frames_received) * 10.0 / 1000.0;
    std::cout << "received " << frames_received << " frames (" << seconds << "s, "
              << (no_wav ? 0 : static_cast<std::uint64_t>(wav.data_bytes())) << " bytes of PCM)";
    if (!no_wav)
        std::cout << " -> " << wav_path;
    std::cout << '\n';
    return frames_received > 0 ? 0 : 1;
}
