#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# End-to-end smoke test: real PipeWire + daemon + fake phone + Roc receiver.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/build/release"
TMP="$(mktemp -d /tmp/opencode/ar_e2e_XXXXXX)"
chmod 0700 "$TMP"
mkdir -p "$TMP/config" "$TMP/state" "$TMP/runtime" "$TMP/client_id"
chmod 0700 "$TMP"/config "$TMP"/state "$TMP"/runtime "$TMP"/client_id
export XDG_CONFIG_HOME="$TMP/config"
export XDG_STATE_HOME="$TMP/state"
export XDG_RUNTIME_DIR="$TMP/runtime"

SOCK="$TMP/runtime/trill/ctl.sock"
PORT=47830
PIDS=()

cleanup() {
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null; done
    sleep 0.2
    for pid in "${PIDS[@]}"; do kill -9 "$pid" 2>/dev/null; done
    wait 2>/dev/null
    rm -rf "$TMP"
}
trap cleanup EXIT

fail() { echo "FAIL: $*"; exit 1; }

echo "[1] starting PipeWire + WirePlumber"
pipewire >"$TMP/pipewire.log" 2>&1 & PIDS+=($!)
for i in $(seq 1 50); do pw-cli info 0 >/dev/null 2>&1 && break; sleep 0.1; done
pw-cli info 0 >/dev/null 2>&1 || fail "PipeWire did not start"
wireplumber >"$TMP/wireplumber.log" 2>&1 & PIDS+=($!)
sleep 0.5

echo "[2] starting daemon on port $PORT"
"$BIN/trilld" --control-port "$PORT" >"$TMP/daemon.log" 2>&1 & PIDS+=($!)
DAEMON_PID=$!
for i in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { cat "$TMP/daemon.log"; fail "daemon socket missing"; }
"$BIN/trill" --socket "$SOCK" status || fail "status failed"

echo "[3] pairing"
PAIR_OUTPUT=$( (printf '{"id":1,"cmd":"pair","args":{"timeout":30}}\n'; sleep 0.2) | socat - UNIX-CONNECT:"$SOCK" )
CODE=$(printf '%s' "$PAIR_OUTPUT" | grep '"code"' | jq -r '.result.code')
[ -n "$CODE" ] && [ "$CODE" != null ] || { echo "$PAIR_OUTPUT"; fail "no pairing code"; }
echo "  code acquired (${#CODE} digits)"

python3 - "$TMP/tone.wav" <<'PY'
import math, struct, sys, wave
path = sys.argv[1]
rate, secs = 48000, 5
with wave.open(path, "wb") as w:
    w.setnchannels(2); w.setsampwidth(2); w.setframerate(rate)
    frames = bytearray()
    for i in range(rate * secs):
        v = int(0.3 * 32767 * math.sin(2 * math.pi * 440 * i / rate))
        frames += struct.pack("<hh", v, v)
    w.writeframes(bytes(frames))
PY

echo "[4] streaming test"
"$BIN/trill-testclient" --port "$PORT" --code "$CODE" --identity-dir "$TMP/client_id" \
    --duration 7 --wav "$TMP/out.wav" >"$TMP/testclient.log" 2>&1 &
TCPID=$!; PIDS+=($TCPID)
for i in $(seq 1 100); do grep -q "host accepted stream" "$TMP/testclient.log" && break; sleep 0.1; done
grep -q "host accepted stream" "$TMP/testclient.log" || { cat "$TMP/testclient.log"; fail "stream never started"; }
echo "  stream accepted; playing test tone into 'trill' sink"

pw-play --target trill "$TMP/tone.wav" >"$TMP/pwplay.log" 2>&1
wait "$TCPID" || { cat "$TMP/testclient.log"; fail "testclient failed"; }
PIDS=("${PIDS[@]/$TCPID}")

echo "[5] results"
grep -E "paired|connected|accepted|received|stopped" "$TMP/testclient.log" || true
SIZE=$(stat -c %s "$TMP/out.wav")
echo "  WAV size: $SIZE bytes"
if [ "$SIZE" -le 100000 ]; then
    echo "--- testclient.log"; cat "$TMP/testclient.log"
    echo "--- daemon.log"; tail -40 "$TMP/daemon.log"
    echo "--- pwplay.log"; cat "$TMP/pwplay.log"
    fail "WAV too small ($SIZE); no audio captured"
fi

python3 - "$TMP/out.wav" <<'PY'
import math, struct, sys, wave
with wave.open(sys.argv[1], "rb") as w:
    n = w.getnframes()
    data = w.readframes(n)
samples = struct.unpack("<%dh" % (len(data) // 2), data)
rms = math.sqrt(sum(s * s for s in samples) / len(samples)) / 32767.0
print(f"  duration {n / 48000:.2f}s, RMS {rms:.4f}")
if n < 48000 * 4 or rms < 0.05:
    sys.exit(1)
PY
if [ $? -ne 0 ]; then
    echo "--- pwplay.log"; cat "$TMP/pwplay.log"
    echo "--- daemon.log"; tail -30 "$TMP/daemon.log"
    fail "captured WAV is silent or malformed"
fi

echo "[6] host-initiated stop"
"$BIN/trill-testclient" --port "$PORT" --skip-pair --identity-dir "$TMP/client_id" \
    --duration 15 --wav "$TMP/out2.wav" >"$TMP/testclient2.log" 2>&1 &
TCPID2=$!; PIDS+=($TCPID2)
for i in $(seq 1 100); do grep -q "host accepted stream" "$TMP/testclient2.log" && break; sleep 0.1; done
grep -q "host accepted stream" "$TMP/testclient2.log" || { cat "$TMP/testclient2.log"; fail "second stream never started"; }
pw-play --target trill "$TMP/tone.wav" >"$TMP/pwplay2.log" 2>&1 &
PWPLAY=$!; PIDS+=($PWPLAY)
sleep 1
"$BIN/trill" --socket "$SOCK" stop || fail "CLI stop failed"
wait "$TCPID2" || { cat "$TMP/testclient2.log"; fail "testclient 2 failed"; }
PIDS=("${PIDS[@]/$TCPID2}")
kill "$PWPLAY" 2>/dev/null || true
grep -q "host stopped the stream: user" "$TMP/testclient2.log" ||
    { cat "$TMP/testclient2.log"; fail "phone did not observe host-initiated stop"; }
echo "  phone saw host-initiated stop"

"$BIN/trill" --socket "$SOCK" status
"$BIN/trill" --socket "$SOCK" shutdown
wait "$DAEMON_PID" || true
echo "PASS"
