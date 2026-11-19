#!/usr/bin/env bash
#
# Containerlab evidence run for the optional OpenFlow 1.3 feature.
#
# Deploys one switch, an external Ryu controller and two hosts, verifies the
# controller session, PACKET_IN/PACKET_OUT learning, flow installation and
# bidirectional forwarding, then writes a transcript under
# /tmp/opencode/evidence-openflow-*.
#
# Usage:
#   ./tests/containerlab-openflow.sh
#   KEEP=1 ./tests/containerlab-openflow.sh
#   RUNTIME=podman ./tests/containerlab-openflow.sh
#
# Requirements: cargo, containerlab and a container runtime. The runtime is
# auto-detected (docker when reachable, otherwise podman); containerlab may be
# setuid-root, in which case no sudo is needed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO="${CARGO:-$HOME/.cargo/bin/cargo}"
KEEP="${KEEP:-0}"
EVIDENCE_DIR="${EVIDENCE_DIR:-/tmp/opencode/evidence-openflow-$(date +%Y%m%d-%H%M%S)}"
LAB="$EVIDENCE_DIR/openflow.clab.yml"
STARTUP="$EVIDENCE_DIR/startup.cfg"
LOG="$EVIDENCE_DIR/transcript.txt"
mkdir -p "$EVIDENCE_DIR"

say() { printf '\n\n=== %s ===\n' "$*" | tee -a "$LOG"; }
note() { printf '%s\n' "$*" | tee -a "$LOG"; }
fail() { printf '\nFAIL: %s\n' "$*" | tee -a "$LOG" >&2; exit 1; }

command -v containerlab >/dev/null 2>&1 || fail "containerlab is not installed"
command -v "$CARGO" >/dev/null 2>&1 || fail "cargo not found at $CARGO"

if [ -z "${RUNTIME:-}" ]; then
    if docker info >/dev/null 2>&1; then
        RUNTIME=docker
    elif podman info >/dev/null 2>&1; then
        RUNTIME=podman
    else
        fail "no usable docker or podman runtime"
    fi
fi

cli() {
    local node="$1"
    shift
    containerlab exec -t "$LAB" --runtime "$RUNTIME" \
        --cmd "/opt/switch cli --host 127.0.0.1 --port 830 -c '$*'" \
        --label "clab-node-name=$node"
}

show() {
    local node="$1" cmd="$2" out
    printf '\n$ %s# %s\n' "$node" "$cmd" | tee -a "$LOG"
    out="$(cli "$node" "$cmd" 2>&1 || true)"
    printf '%s\n' "$out" | tee -a "$LOG"
}

cleanup() {
    if [ "${DEPLOYED:-0}" = "1" ] && [ "$KEEP" != "1" ]; then
        say "destroying lab"
        containerlab destroy -t "$LAB" --runtime "$RUNTIME" >/dev/null 2>&1 || true
    elif [ "${DEPLOYED:-0}" = "1" ]; then
        say "KEEP=1: leaving the lab deployed"
        note "lab: $LAB"
    fi
}
trap cleanup EXIT

say "environment"
note "date:         $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
note "host:         $(uname -srm)"
note "containerlab: $(containerlab version 2>/dev/null | awk '/version:/ {print $NF; exit}')"
note "runtime:      $RUNTIME"
note "switch binary: $ROOT/target/debug/switch"
note "evidence:     $EVIDENCE_DIR"

say "building the switch"
"$CARGO" build --manifest-path "$ROOT/Cargo.toml" 2>&1 | tee -a "$LOG"

cat >"$STARTUP" <<'EOF'
feature disable stp
feature enable openflow
openflow controller 172.20.20.100 6653
openflow fail-mode secure
EOF

cat >"$LAB" <<EOF
name: clab-of-evidence
topology:
  nodes:
    ryu:
      kind: linux
      image: docker.io/osrg/ryu:latest
      mgmt-ipv4: 172.20.20.100
      cmd: ryu-manager ryu.app.simple_switch_13
    sw:
      kind: linux
      image: docker.io/library/fedora:42
      mgmt-ipv4: 172.20.20.10
      binds:
        - $ROOT/target/debug/switch:/opt/switch:ro
        - $STARTUP:/etc/switch/startup.cfg:ro
      cmd: /opt/switch daemon --ports eth1,eth2 --tcp 830 --config /etc/switch/startup.cfg
    h1:
      kind: linux
      image: docker.io/library/alpine:latest
      mgmt-ipv4: 172.20.20.11
      exec:
        - ip addr add 10.10.0.1/24 dev eth1
        - ip link set eth1 up
    h2:
      kind: linux
      image: docker.io/library/alpine:latest
      mgmt-ipv4: 172.20.20.12
      exec:
        - ip addr add 10.10.0.2/24 dev eth1
        - ip link set eth1 up
  links:
    - endpoints: ["sw:eth1", "h1:eth1"]
    - endpoints: ["sw:eth2", "h2:eth1"]
EOF

say "deploying the OpenFlow lab"
DEPLOYED=1
containerlab deploy -t "$LAB" --runtime "$RUNTIME" 2>&1 | tee -a "$LOG"

say "waiting for the switch CLI and controller session"
for _ in $(seq 1 90); do
    out="$(cli sw "show openflow" 2>&1 || true)"
    if printf '%s\n' "$out" | grep -q "Session:      connected"; then
        break
    fi
    sleep 1
done
printf '%s\n' "$out" | tee -a "$LOG"
printf '%s\n' "$out" | grep -q "Session:      connected" ||
    fail "switch did not attach to the Ryu controller"

say "show openflow before traffic"
show sw "show openflow"

say "forwarding: h1 to h2 (Ryu learns and installs flows)"
PING1="$(containerlab exec -t "$LAB" --runtime "$RUNTIME" \
    --cmd "ping -c 3 -W 2 10.10.0.2" \
    --label clab-node-name=h1 2>&1)"
printf '%s\n' "$PING1" | tee -a "$LOG"
printf '%s\n' "$PING1" | grep -q "0% packet loss" || fail "h1 -> h2 ping failed"

say "show openflow after learning"
show sw "show openflow"

say "forwarding: h2 to h1"
PING2="$(containerlab exec -t "$LAB" --runtime "$RUNTIME" \
    --cmd "ping -c 2 -W 2 10.10.0.1" \
    --label clab-node-name=h2 2>&1)"
printf '%s\n' "$PING2" | tee -a "$LOG"
printf '%s\n' "$PING2" | grep -q "0% packet loss" || fail "h2 -> h1 ping failed"

say "Ryu controller log"
RYU_LOG="$(containerlab logs -t "$LAB" --runtime "$RUNTIME" -n ryu --tail 80 2>&1 || true)"
printf '%s\n' "$RYU_LOG" | tee -a "$LOG"
printf '%s\n' "$RYU_LOG" | grep -q "simple_switch_13" ||
    fail "Ryu simple_switch_13 was not loaded"
printf '%s\n' "$RYU_LOG" | grep -q "packet in" ||
    fail "Ryu did not receive any PACKET_IN"
if printf '%s\n' "$RYU_LOG" | grep -q "Traceback\|malformed"; then
    fail "Ryu reported malformed OpenFlow packets"
fi

say "final OpenFlow counters"
FINAL="$(cli sw "show openflow" 2>&1 || true)"
printf '%s\n' "$FINAL" | tee -a "$LOG"
FLOWS="$(printf '%s\n' "$FINAL" | sed -n 's/.*Flow entries:[[:space:]]*\([0-9][0-9]*\).*/\1/p')"
ERRORS="$(printf '%s\n' "$FINAL" | sed -n 's/.*errors[[:space:]]*\([0-9][0-9]*\).*/\1/p')"
[ -n "$FLOWS" ] || fail "could not read the flow-entry count"
[ -n "$ERRORS" ] || fail "could not read the OpenFlow error count"
[ "$FLOWS" -ge 3 ] || fail "expected at least 3 installed flows, got $FLOWS"
[ "$ERRORS" -eq 0 ] || fail "expected 0 OpenFlow errors, got $ERRORS"

say "result"
note "PASS: Ryu session established, $FLOWS flows installed, errors 0,"
note "      h1 -> h2 and h2 -> h1 forwarded without loss."
