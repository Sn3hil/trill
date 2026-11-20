# trill

Stream PipeWire audio from a Linux PC to a phone over Wi-Fi.

The phone is the Roc receiver; the host exposes a PipeWire virtual sink and
sends PCM over RTP + Reed-Solomon FEC. Control and pairing run over mutual
TLS 1.3. The protocol contract lives in `docs/PROTOCOL.md` (source:
`Protocol & Integration Contract.md` at the repository root until M0 freezes
it into `protocol/`).

## Layout

```
server/       C++23 daemon, CLI, fake-phone test client
protocol/     shared schema, golden files, SPAKE2 vectors
docs/         protocol, plans, implementation notes
flake.nix     dev shell, package, NixOS module
```

## Build

```sh
nix develop
cmake -S server -B build/debug --preset debug
cmake --build build/debug
ctest --test-dir build/debug --output-on-failure
```

Presets available: `debug`, `release`, `asan`, `tsan`.

Binaries produced: `trilld` (daemon), `trill` (CLI), `trill-testclient` (fake phone for testing).

## Testing

Run the full end-to-end smoke test (starts headless PipeWire, WirePlumber, the daemon, fake phone, streams 440 Hz tone, verifies non-silent received audio RMS, tests host-initiated stop and shutdown):

```sh
./scripts/e2e-smoke.sh
```

Nix package build:

```sh
nix build
```

## Quick start

```sh
trilld &
trill pair
trill status
```

`trill pair` prints a six-digit code. Enter it in the phone app. Audio is
started from the phone by default; `trill start <device>` asks a
connected phone to start once `caps.host_request` is supported.

## License

MIT. `libroc` is dynamically linked and not redistributed.
