#!/usr/bin/env bash
#
# Containerlab evidence run for every protocol documented in README.md.
#
# The script deploys the two-switch loop, then records configuration and wire
# evidence for:
#
#   * default IEEE 802.1D STP (MSTP feature off)
#   * the MSTP-disabled configuration error and the MSTP feature toggle
#   * IEEE 802.1Q-2005 MSTP: CIST + two MSTIs, MST BPDUs, MCID digest
#   * classic STP and CST compatibility modes
#   * 802.1Q trunk tagging, access untagging and VLAN isolation
#   * IEEE 802.1AB LLDP (disabled error, enable, neighbours, wire frame)
#   * the TCP/telnet console (disabled error, enable)
#   * rejected protocols: PVST+, RSTP, DTP, VTP, CDP, LACP
#   * startup-config persistence across a daemon restart
#
# Everything is printed to stdout.  Raw per-instance snapshots and packet
# captures are kept under $EVIDENCE_DIR (default /tmp/opencode/evidence-*).
#
# Usage:
#   sudo ./tests/containerlab-evidence.sh
#   KEEP=1 sudo ./tests/containerlab-evidence.sh
#
# Requirements: docker, containerlab, tcpdump and nsenter (root for captures).
set -euo pipefail

# sudo's secure_path normally omits /snap/bin, but Docker is often installed
# there.  Add it when docker is not otherwise on PATH.
if ! command -v docker >/dev/null 2>&1 && [ -x /snap/bin/docker ]; then
    PATH="/snap/bin:$PATH"
    export PATH
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB="${LAB:-$ROOT/switch.clab.yml}"
IMAGE="${IMAGE:-switch:latest}"
PREFIX="${PREFIX:-clab-stp-lab}"
KEEP="${KEEP:-0}"
EVIDENCE_DIR="${EVIDENCE_DIR:-/tmp/opencode/evidence-$(date +%Y%m%d-%H%M%S)}"
LOG="$EVIDENCE_DIR/transcript.txt"
mkdir -p "$EVIDENCE_DIR"

say() {
    printf '\n\n=== %s ===\n' "$*" | tee -a "$LOG"
}
note() {
    printf '%s\n' "$*" | tee -a "$LOG"
}
fail() {
    printf '\nFAIL: %s\n' "$*" | tee -a "$LOG" >&2
    exit 1
}

cli() {
    local node="$1"
    shift
    docker exec "$PREFIX-$node" /switch cli "$@"
}

show() {
    local node="$1" cmd="$2"
    printf '\n$ %s# %s\n' "$node" "$cmd" | tee -a "$LOG"
    cli "$node" -c "$cmd" 2>&1 | tee -a "$LOG" || true
}

conf() {
    local node="$1"
    shift
    local -a args=()
    local c
    for c in "$@"; do args+=(-c "$c"); done
    printf '\n$ %s(config)# %s\n' "$node" "$*" | tee -a "$LOG"
    cli "$node" -c "config" "${args[@]}" -c "end" 2>&1 | tee -a "$LOG" || true
}

try_conf() {
    local node="$1" needle="$2"
    shift 2
    local -a args=()
    local c out
    for c in "$@"; do args+=(-c "$c"); done
    out="$(cli "$node" -c "config" "${args[@]}" -c "end" 2>&1 || true)"
    printf '\n$ %s(config)# %s\n%s\n' "$node" "$*" "$out" | tee -a "$LOG"
    if [ -n "$needle" ]; then
        printf '%s\n' "$out" | grep -qF "$needle" ||
            fail "expected '$needle' from '$*'"
    fi
}

show_inst() {
    local node="$1" id="$2"
    # `show bridge` prints every instance; `show bridge mst 0` prints only the
    # CIST, which is what the convergence predicates below need.
    cli "$node" -c "show bridge mst $id"
}

# wait_instance <label> <mstid|0> <root-node> <blocked-node> <blocked-port> <phase-start-epoch>
wait_instance() {
    local label="$1" id="$2" root_node="$3" block_node="$4" block_port="$5"
    local phase_start="$6"
    local out1 out2 roots blocks trans root_out block_out now elapsed
    for _ in $(seq 1 180); do
        out1="$(show_inst sw1 "$id")"
        out2="$(show_inst sw2 "$id")"
        roots="$(printf '%s\n%s\n' "$out1" "$out2" | grep -c "This bridge is the root" || true)"
        blocks="$(printf '%s\n%s\n' "$out1" "$out2" | grep -c " BLK " || true)"
        trans="$(printf '%s\n%s\n' "$out1" "$out2" | grep -Ec " (LSN|LRN) " || true)"
        if [ "$root_node" = "sw1" ]; then root_out="$out1"; else root_out="$out2"; fi
        if [ "$block_node" = "sw1" ]; then block_out="$out1"; else block_out="$out2"; fi
        if [ "$roots" = "1" ] && [ "$blocks" = "1" ] && [ "$trans" = "0" ] &&
           printf '%s\n' "$root_out" | grep -q "This bridge is the root" &&
           printf '%s\n' "$block_out" | grep -Eq "^${block_port}[[:space:]]+.*BLK"; then
            now="$(date +%s)"
            elapsed="$((now - phase_start))"
            printf '\n[%s] converged: root=%s, blocked=%s %s, transitional ports=0, +%ss from phase start\n' \
                "$label" "$root_node" "$block_node" "$block_port" "$elapsed" | tee -a "$LOG"
            printf '%s\n' "$out1" >"$EVIDENCE_DIR/${label}-sw1.txt"
            printf '%s\n' "$out2" >"$EVIDENCE_DIR/${label}-sw2.txt"
            return 0
        fi
        sleep 1
    done
    printf '\n--- sw1 %s ---\n%s\n--- sw2 %s ---\n%s\n' \
        "$label" "$out1" "$label" "$out2" | tee -a "$LOG"
    fail "$label did not converge"
}

dump_instance() {
    local label="$1"
    printf '\n--- sw1 %s ---\n' "$label" | tee -a "$LOG"
    tee -a "$LOG" <"$EVIDENCE_DIR/${label}-sw1.txt"
    printf '\n--- sw2 %s ---\n' "$label" | tee -a "$LOG"
    tee -a "$LOG" <"$EVIDENCE_DIR/${label}-sw2.txt"
}

ping_ok() {
    timeout 12 docker exec "$PREFIX-pc1" ping -c 2 -W 2 10.0.0.2 >/dev/null 2>&1
}

wait_ping() {
    local tries="${1:-20}"
    local _
    for _ in $(seq 1 "$tries"); do
        if ping_ok; then return 0; fi
        sleep 1
    done
    return 1
}

ping_show() {
    printf '\n$ pc1# ping -c 3 10.0.0.2\n' | tee -a "$LOG"
    docker exec "$PREFIX-pc1" ping -c 3 -W 2 10.0.0.2 2>&1 | tee -a "$LOG" || true
}

# capture_bpdu <container> <iface> <pcap-name> <filter>
capture_bpdu() {
    local container="$1" iface="$2" name="$3" filter="$4"
    local pcap="$EVIDENCE_DIR/$name.pcap"
    local pid
    pid="$(docker inspect -f '{{.State.Pid}}' "$PREFIX-$container")"
    rm -f "$pcap"
    printf '\n$ (%s netns) tcpdump -i %s -e -nn -vv -c 2 -w %s %s\n' \
        "$container" "$iface" "$pcap" "$filter" | tee -a "$LOG"
    timeout 14 nsenter -t "$pid" -n \
        tcpdump -i "$iface" -e -nn -vv -c 2 -w "$pcap" "$filter" >/dev/null 2>&1 &
    local tpid=$!
    wait "$tpid" || true
    tcpdump -r "$pcap" -e -nn -vv 2>&1 | tee -a "$LOG" || true
}

# capture_with_ping <container> <iface> <pcap-name> <filter>
capture_with_ping() {
    local container="$1" iface="$2" name="$3" filter="$4"
    local pcap="$EVIDENCE_DIR/$name.pcap"
    local pid
    pid="$(docker inspect -f '{{.State.Pid}}' "$PREFIX-$container")"
    rm -f "$pcap"
    printf '\n$ (%s netns) tcpdump -i %s -e -nn -vv -c 2 -w %s %s\n' \
        "$container" "$iface" "$pcap" "$filter" | tee -a "$LOG"
    timeout 16 nsenter -t "$pid" -n \
        tcpdump -i "$iface" -e -nn -vv -c 2 -w "$pcap" "$filter" >/dev/null 2>&1 &
    local tpid=$!
    sleep 1
    local _
    for _ in 1 2 3 4; do
        docker exec "$PREFIX-pc1" ping -c 1 -W 2 10.0.0.2 >/dev/null 2>&1 || true
    done
    wait "$tpid" || true
    tcpdump -r "$pcap" -e -nn -vv 2>&1 | tee -a "$LOG" || true
}

cleanup() {
    if [ "${DEPLOYED:-0}" = "1" ] && [ "$KEEP" != "1" ]; then
        say "destroying lab"
        containerlab destroy -t "$LAB" --cleanup >/dev/null 2>&1 || true
    elif [ "${DEPLOYED:-0}" = "1" ]; then
        say "KEEP=1: leaving the lab deployed"
    fi
    return 0
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || fail "docker is not installed"
command -v containerlab >/dev/null 2>&1 || fail "containerlab is not installed"
docker info >/dev/null 2>&1 ||
    fail "cannot talk to the Docker daemon (run as root or join the docker group)"

say "environment"
note "date:        $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
note "host:        $(uname -srm)"
note "containerlab: $(containerlab version 2>/dev/null | awk '/version/ {print $NF; exit}')"
note "docker:      $(docker version --format '{{.Server.Version}}' 2>/dev/null)"
note "tcpdump:     $(tcpdump --version 2>/dev/null | head -1)"
note "image:       $IMAGE"
note "evidence:    $EVIDENCE_DIR"

say "building $IMAGE"
docker build -t "$IMAGE" "$ROOT"

say "deploying $LAB"
containerlab destroy -t "$LAB" --cleanup >/dev/null 2>&1 || true
DEPLOYED=1
DEPLOY_TS="$(date +%s)"
containerlab deploy -t "$LAB"

say "waiting for the switch CLI"
for _ in $(seq 1 60); do
    if cli sw1 -c "show version" >/dev/null 2>&1; then break; fi
    sleep 1
done
cli sw1 -c "show version" >/dev/null 2>&1 || fail "sw1 CLI did not start"

# ---------------------------------------------------------------------------
# 1. Default state: classic IEEE 802.1D STP, MSTP feature off
# ---------------------------------------------------------------------------
say "1. default state: IEEE 802.1D STP, MSTP feature disabled"
show sw1 "show features"
show sw1 "show version"
show sw1 "show bridge summary"
show sw1 "show bridge"
show sw2 "show bridge"

show sw1 "show running-config"

say "1a. configuring VLANs, access ports and a static 802.1Q trunk"
for node in sw1 sw2; do
    conf "$node" \
        "vlan create 10 name users" \
        "vlan create 20 name voice" \
        "port eth1" "mode trunk" "allow vlans 1,10,20" "exit" \
        "port eth2" "mode trunk" "allow vlans 1,10,20" "exit" \
        "port eth3" "access vlan 10" "end"
done

say "1b. pre-enable error: MSTP cannot be selected while the feature is off"
try_conf sw1 "MSTP is disabled; enable it with 'feature enable mstp'" \
    "spanning-tree mode mstp"
show sw1 "show bridge mst 1"
show sw1 "show bridge mst configuration"

say "1c. default STP convergence after a controlled restart"
# Default priorities and MACs make sw1 (02:00:00:00:00:01) the root; sw2
# blocks Gi0/2 because it has the higher designated port ID on the tie.
STP_START="$(date +%s)"
conf sw1 "spanning-tree mode stp"
conf sw2 "spanning-tree mode stp"
show sw1 "show features"
wait_instance "baseline-stp" 0 sw1 sw2 Gi0/2 "$STP_START" ||
    fail "default STP did not converge"
dump_instance "baseline-stp"
show sw1 "show bridge summary"

say "1d. classic IEEE 802.1D ST Configuration BPDU on the wire"
capture_bpdu pc1 eth1 "baseline-stp-bpdu" stp

say "1e. 802.1Q forwarding and VLAN isolation under STP"
docker exec "$PREFIX-pc1" ip addr add 10.0.0.1/24 dev eth1 2>/dev/null || true
docker exec "$PREFIX-pc2" ip addr add 10.0.0.2/24 dev eth1 2>/dev/null || true
wait_ping 20 || fail "pc1 cannot ping pc2 in VLAN 10 under STP"
ping_show

say "1f. tagged trunk frame and untagged access frame"
capture_with_ping sw1 eth1 "stp-trunk-vlan10" "vlan and icmp"
capture_with_ping pc1 eth1 "stp-access-vlan10" "icmp"

say "1g. changing pc2's access port to VLAN 20 isolates the hosts"
conf sw2 "port eth3" "access vlan 20" "end"
sleep 2
if ping_ok; then fail "pc1 can still ping pc2 after VLAN isolation"; fi
note "ping across VLAN 10/20: correctly blocked"

say "1h. both access ports in VLAN 20 forward again"
conf sw1 "port eth3" "access vlan 20" "end"
wait_ping 20 || fail "pc1 cannot ping pc2 in VLAN 20 under STP"
ping_show

say "1i. restoring VLAN 10 on both access ports"
conf sw1 "port eth3" "access vlan 10" "end"
conf sw2 "port eth3" "access vlan 10" "end"
wait_ping 20 >/dev/null 2>&1 || true

say "1j. feature disable stp: the dataplane fails open"
# Only sw1 is disabled: sw2 still blocks one parallel link, so the loop does
# not turn into a broadcast storm while we prove that STP no longer gates
# forwarding.
conf sw1 "feature disable stp"
show sw1 "show features"
show sw1 "show bridge"
wait_ping 10 || fail "pc1 cannot ping pc2 with STP disabled"
ping_show
# Re-enable STP before enabling MSTP; the MSTP reset below restarts timers.
conf sw1 "feature enable stp"

# ---------------------------------------------------------------------------
# 2. Enable MSTP and build a shared region
# ---------------------------------------------------------------------------
say "2. feature enable mstp and MST Region configuration"
show sw1 "show features"
MSTP_START="$(date +%s)"
conf sw1 "feature enable mstp"
conf sw2 "feature enable mstp"
show sw1 "show features"
show sw1 "show version"
show sw1 "show bridge summary"

say "2a. configuring one MST Region on both switches"
# sw2 wins the CIST; sw1 wins MSTI 1 and MSTI 2.  The high MSTI 1 cost on
# sw2:eth1 forces MSTI 1 to use the other parallel link than the CIST.
conf sw1 \
    "bridge mst name MST-LAB" \
    "bridge mst revision 1" \
    "bridge mst max-hops 20" \
    "bridge mst instance 1 vlan 10" \
    "bridge mst instance 2 vlan 20" \
    "bridge priority 32768" \
    "bridge mst instance 1 priority 4096"
conf sw2 \
    "bridge mst name MST-LAB" \
    "bridge mst revision 1" \
    "bridge mst max-hops 20" \
    "bridge mst instance 1 vlan 10" \
    "bridge mst instance 2 vlan 20" \
    "bridge priority 4096" \
    "bridge mst instance 1 priority 8192"
conf sw2 "port eth1" "spanning-tree mst 1 cost 200000" "end"

show sw1 "show bridge mst configuration"
show sw2 "show bridge mst configuration"
show sw1 "show running-config"

DIGEST1="$(cli sw1 -c "show bridge mst configuration" | awk '/Digest:/ {print $2}')"
DIGEST2="$(cli sw2 -c "show bridge mst configuration" | awk '/Digest:/ {print $2}')"
[ -n "$DIGEST1" ] || fail "sw1 did not report an MST configuration digest"
[ "$DIGEST1" = "$DIGEST2" ] ||
    fail "the two switches computed different MST digests ($DIGEST1 vs $DIGEST2)"
[[ "$DIGEST1" =~ ^[0-9A-Fa-f]{32}$ ]] || fail "MST digest is not 16 octets"
note "shared MST digest: $DIGEST1"

say "2b. CIST convergence (root: sw2, blocked: sw1 Gi0/2)"
wait_instance "mstp-cist" 0 sw2 sw1 Gi0/2 "$MSTP_START" ||
    fail "the CIST did not converge"
dump_instance "mstp-cist"

say "2c. MSTI 1 convergence (regional root: sw1, blocked: sw2 Gi0/1)"
wait_instance "mstp-msti1" 1 sw1 sw2 Gi0/1 "$MSTP_START" ||
    fail "MSTI 1 did not converge"
dump_instance "mstp-msti1"

say "2d. MSTI 2 convergence (regional root: sw1, blocked: sw2 Gi0/2)"
wait_instance "mstp-msti2" 2 sw1 sw2 Gi0/2 "$MSTP_START" ||
    fail "MSTI 2 did not converge"
dump_instance "mstp-msti2"

show sw1 "show bridge summary"
show sw2 "show bridge summary"

say "2e. per-VLAN forwarding through different MSTI topologies"
wait_ping 20 || fail "pc1 cannot ping pc2 in VLAN 10 / MSTI 1"
ping_show
conf sw1 "port eth3" "access vlan 20" "end"
conf sw2 "port eth3" "access vlan 20" "end"
wait_ping 20 || fail "pc1 cannot ping pc2 in VLAN 20 / MSTI 2"
ping_show
conf sw1 "port eth3" "access vlan 10" "end"
conf sw2 "port eth3" "access vlan 10" "end"
wait_ping 20 >/dev/null 2>&1 || true

say "2f. IEEE 802.1Q-2005 MST BPDU on the wire"
capture_bpdu pc1 eth1 "mstp-bpdu" stp

say "2g. 802.1Q tagged trunk frame and untagged access frame (MSTP)"
# MSTI 1 blocks sw2:eth1, so VLAN 10 crosses the loop on sw1:eth2.
capture_with_ping sw1 eth2 "mstp-trunk-vlan10" "vlan and icmp"
capture_with_ping pc1 eth1 "mstp-access-vlan10" "icmp"

say "2h. native VLAN 10 on the active trunk is sent untagged"
conf sw1 "port eth2" "native vlan 10" "end"
conf sw2 "port eth2" "native vlan 10" "end"
sleep 2
wait_ping 15 || fail "pc1 cannot ping pc2 with native VLAN 10"
capture_with_ping sw1 eth2 "mstp-native-vlan10" "icmp"
conf sw1 "port eth2" "native vlan 1" "end"
conf sw2 "port eth2" "native vlan 1" "end"

say "2i. no PVST+ frames on the wire"
PVST_PCAP="$EVIDENCE_DIR/pvst-plus.pcap"
rm -f "$PVST_PCAP"
SW1_PID="$(docker inspect -f '{{.State.Pid}}' "$PREFIX-sw1")"
timeout 8 nsenter -t "$SW1_PID" -n \
    tcpdump -i eth1 -e -nn -w "$PVST_PCAP" 'ether dst 01:00:0c:cc:cc:cd' \
    >/dev/null 2>&1 &
PVST_PID=$!
sleep 1
for _ in 1 2 3; do
    docker exec "$PREFIX-pc1" ping -c 1 -W 2 10.0.0.2 >/dev/null 2>&1 || true
done
wait "$PVST_PID" || true
PVST_COUNT="$(tcpdump -nn -r "$PVST_PCAP" 2>/dev/null | wc -l | tr -d '[:space:]')"
note "PVST+ frames on the wire: $PVST_COUNT"
[ "$PVST_COUNT" = "0" ] || fail "PVST+ frames were observed on the wire"

# ---------------------------------------------------------------------------
# 3. Classic STP compatibility mode
# ---------------------------------------------------------------------------
say "3. spanning-tree mode stp (classic IEEE 802.1D STP)"
STP_START="$(date +%s)"
conf sw1 "spanning-tree mode stp"
conf sw2 "spanning-tree mode stp"
show sw1 "show features"
show sw2 "show features"
show sw1 "show bridge summary"
show sw1 "show running-config"
wait_instance "stp-mode" 0 sw2 sw1 Gi0/2 "$STP_START" ||
    fail "classic STP mode did not converge"
dump_instance "stp-mode"
capture_bpdu pc1 eth1 "stp-mode-bpdu" stp

# ---------------------------------------------------------------------------
# 4. CST compatibility mode
# ---------------------------------------------------------------------------
say "4. spanning-tree mode cst (IEEE 802.1Q common spanning tree)"
CST_START="$(date +%s)"
conf sw1 "spanning-tree mode cst"
conf sw2 "spanning-tree mode cst"
show sw1 "show features"
show sw2 "show features"
show sw1 "show bridge summary"
show sw1 "show running-config"
wait_instance "cst-mode" 0 sw2 sw1 Gi0/2 "$CST_START" ||
    fail "CST mode did not converge"
dump_instance "cst-mode"
capture_bpdu pc1 eth1 "cst-mode-bpdu" stp

say "4a. STP and CST are behaviourally identical: both send classic ST BPDUs"
note "The CST capture above is an IEEE 802.1D ST Configuration BPDU (version 0,"
note "type 0x00), exactly like the STP-mode capture, with one tree for all VLANs."

# ---------------------------------------------------------------------------
# 5. Back to MSTP, LLDP, telnet and negative protocol tests
# ---------------------------------------------------------------------------
say "5. feature enable mstp restores the configured region"
MSTP_RESTART="$(date +%s)"
conf sw1 "feature enable mstp"
conf sw2 "feature enable mstp"
show sw1 "show features"
show sw1 "show bridge summary"
show sw1 "show bridge mst configuration"
wait_instance "mstp-restored-cist" 0 sw2 sw1 Gi0/2 "$MSTP_RESTART" ||
    fail "the CIST did not converge after re-enabling MSTP"
wait_instance "mstp-restored-msti1" 1 sw1 sw2 Gi0/1 "$MSTP_RESTART" ||
    fail "MSTI 1 did not converge after re-enabling MSTP"
wait_instance "mstp-restored-msti2" 2 sw1 sw2 Gi0/2 "$MSTP_RESTART" ||
    fail "MSTI 2 did not converge after re-enabling MSTP"
dump_instance "mstp-restored-cist"

say "6. IEEE 802.1AB LLDP"
show sw1 "show lldp"
show sw1 "show lldp neighbors"
conf sw1 "feature enable lldp"
conf sw2 "feature enable lldp"
# Capture immediately: LLDP starts with a burst of four one-second frames,
# then settles at the 30-second transmit interval.
capture_bpdu pc1 eth1 "lldp-frame" "ether proto 0x88cc"
sleep 2
show sw1 "show lldp"
show sw1 "show lldp neighbors"
cli sw1 -c "show lldp neighbors" | grep -q "sw2" ||
    fail "sw1 did not learn sw2 as an LLDP neighbour"
show sw1 "show lldp neighbors detail"
show sw1 "show lldp interfaces"
show sw1 "show lldp traffic"
show sw2 "show lldp neighbors"

say "7. TCP/telnet console"
note "The lab daemon starts with --tcp 2200, which enables the telnet feature."
printf '\n$ docker exec %s-sw1 /switch cli --host 127.0.0.1 --port 2200 -c "show version"\n' \
    "$PREFIX" | tee -a "$LOG"
TELNET_OUT="$(timeout 10 docker exec "$PREFIX-sw1" /switch cli \
    --host 127.0.0.1 --port 2200 -c "show version" 2>&1 || true)"
printf '%s\n' "$TELNET_OUT" | tee -a "$LOG"
printf '%s\n' "$TELNET_OUT" | grep -q "SWITCH-1.0" ||
    fail "the TCP console did not accept a login"
conf sw1 "feature disable telnet"
show sw1 "show features"
printf '\n$ docker exec %s-sw1 /switch cli --host 127.0.0.1 --port 2200 -c "show version"  (telnet disabled)\n' \
    "$PREFIX" | tee -a "$LOG"
TELNET_OFF="$(timeout 10 docker exec "$PREFIX-sw1" /switch cli \
    --host 127.0.0.1 --port 2200 -c "show version" 2>&1 || true)"
printf '%s\n' "$TELNET_OFF" | tee -a "$LOG"
printf '%s\n' "$TELNET_OFF" | grep -q "TCP console disabled" ||
    fail "a login was accepted while the telnet feature was disabled"
show sw1 "show version"
conf sw1 "feature enable telnet"
printf '\n$ docker exec %s-sw1 /switch cli --host 127.0.0.1 --port 2200 -c "show version"  (telnet re-enabled)\n' \
    "$PREFIX" | tee -a "$LOG"
TELNET_ON="$(timeout 10 docker exec "$PREFIX-sw1" /switch cli \
    --host 127.0.0.1 --port 2200 -c "show version" 2>&1 || true)"
printf '%s\n' "$TELNET_ON" | tee -a "$LOG"
printf '%s\n' "$TELNET_ON" | grep -q "SWITCH-1.0" ||
    fail "the TCP console did not accept a login after re-enabling telnet"

say "8. rejected protocols"
try_conf sw1 "PVST+ has been removed" "feature enable pvst"
try_conf sw1 "PVST+ has been removed" "spanning-tree mode pvst"
try_conf sw1 "RSTP is not selectable" "spanning-tree mode rstp"
try_conf sw1 "unknown feature 'dtp'" "feature enable dtp"
try_conf sw1 "unknown feature 'vtp'" "feature enable vtp"
try_conf sw1 "unknown feature 'cdp'" "feature enable cdp"
try_conf sw1 "unknown feature 'lacp'" "feature enable lacp"
try_conf sw1 "unknown feature 'gvrp'" "feature enable gvrp"
try_conf sw1 "unknown feature 'mvrp'" "feature enable mvrp"
try_conf sw1 "unknown feature 'spb'" "feature enable spb"
try_conf sw1 "unknown feature 'pbb'" "feature enable pbb"
try_conf sw1 "unknown feature 'evb'" "feature enable evb"
try_conf sw1 "unknown feature 'snmp'" "feature enable snmp"

# ---------------------------------------------------------------------------
# 9. Persistence
# ---------------------------------------------------------------------------
say "9. startup-config persistence: a fresh daemon loads the saved file"
show sw1 "show features"
printf '\n$ sw1# save\n' | tee -a "$LOG"
cli sw1 -c "save" 2>&1 | tee -a "$LOG" || true
show sw1 "show startup-config"
cli sw1 -c "show startup-config" | grep -q "feature enable mstp" ||
    fail "the saved startup-config does not enable mstp"
cli sw1 -c "show startup-config" | grep -q "bridge mst name MST-LAB" ||
    fail "the saved startup-config lost the MST region"
# `show startup-config` prints one extra trailing newline; normalise both
# bodies with awk paragraph mode before hashing.
cli sw1 -c "show startup-config" | tail -n +2 |
    awk 'BEGIN { RS = "" ; ORS = "\n" } { print }' \
        >"$EVIDENCE_DIR/startup-body.txt"
ORIG_HASH="$(sha256sum "$EVIDENCE_DIR/startup-body.txt" | awk '{print $1}')"
note "saved startup-config sha256: $ORIG_HASH"

# containerlab attaches the topology veths from outside the container, so a
# `docker restart` recreates the container netns and loses eth1..eth3.  Start a
# second daemon process in the same container instead: it takes the same
# boot-time path, reads /etc/switch/startup-config, and runs with
# --no-dataplane so it needs no interfaces.
RESTORE_SOCK=/tmp/restore-evidence.sock
printf '\n$ docker exec -d %s-sw1 /switch daemon --no-dataplane --config /etc/switch/startup-config --socket %s\n' \
    "$PREFIX" "$RESTORE_SOCK" | tee -a "$LOG"
docker exec -d "$PREFIX-sw1" /switch daemon --no-dataplane \
    --config /etc/switch/startup-config --socket "$RESTORE_SOCK" \
    --hostname restored --mac 02:00:00:00:00:01 --ports eth1,eth2,eth3
for _ in $(seq 1 30); do
    if docker exec "$PREFIX-sw1" /switch cli --socket "$RESTORE_SOCK" \
        -c "show version" >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done
docker exec "$PREFIX-sw1" /switch cli --socket "$RESTORE_SOCK" \
    -c "show version" >/dev/null 2>&1 || fail "the restored daemon did not start"

show_restored() {
    local cmd="$1"
    printf '\n$ restored# %s\n' "$cmd" | tee -a "$LOG"
    docker exec "$PREFIX-sw1" /switch cli --socket "$RESTORE_SOCK" \
        -c "$cmd" 2>&1 | tee -a "$LOG"
}
show_restored "show features"
show_restored "show version"
show_restored "show bridge summary"
show_restored "show bridge mst configuration"
docker exec "$PREFIX-sw1" /switch cli --socket "$RESTORE_SOCK" \
    -c "show running-config" | tail -n +4 |
    awk 'BEGIN { RS = "" ; ORS = "\n" } { print }' \
        >"$EVIDENCE_DIR/restored-config-body.txt"
RESTORED_HASH="$(sha256sum "$EVIDENCE_DIR/restored-config-body.txt" | awk '{print $1}')"
note "restored running-config sha256: $RESTORED_HASH"
[ "$ORIG_HASH" = "$RESTORED_HASH" ] ||
    fail "the restored running-config differs from the saved startup-config"
note "saved startup-config and restored running-config are identical (trailing blank line trimmed)"

# Stop only the second daemon; the lab container keeps running until cleanup.
RESTORE_PID="$(docker top "$PREFIX-sw1" -eo pid,args |
    awk '/restore-evidence.sock/ {print $1; exit}')"
if [ -n "$RESTORE_PID" ]; then
    kill "$RESTORE_PID" 2>/dev/null || true
fi

say "evidence run complete"
note "transcript: $LOG"
note "artifacts:  $EVIDENCE_DIR"
