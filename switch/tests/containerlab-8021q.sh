#!/usr/bin/env bash
#
# End-to-end containerlab check for the IEEE 802.1Q-2005 MSTP implementation.
#
# Verifies:
#   * the lab image builds and the two-switch loop comes up;
#   * both switches join the same MST Region (same name, revision and digest);
#   * the CIST elects sw2 as root and blocks one parallel link;
#   * MSTI 1 elects sw1 as regional root, independently of the CIST;
#   * MSTI 1 uses a different root port than the CIST (per-instance cost);
#   * VLAN 10 (MSTI 1) and VLAN 20 (MSTI 2) both forward across the loop;
#   * moving one access port to VLAN 20 isolates the hosts;
#   * MST BPDUs (version 3, type 0x02) are sent untagged to
#     01:80:c2:00:00:00 and carry the MST Configuration Identifier;
#   * no PVST+ frames appear, and PVST+ configuration is rejected.
#
# Usage:
#   ./tests/containerlab-8021q.sh
#   KEEP=1 ./tests/containerlab-8021q.sh    # keep the lab for debugging
#
# Requirements: docker (with permission to run containers), containerlab.
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

say() { printf '\n== %s\n' "$*"; }
fail() {
    printf '\nFAIL: %s\n' "$*" >&2
    exit 1
}

sw_cli() {
    local node="$1"
    shift
    docker exec "$PREFIX-$node" /switch cli "$@"
}

pc() {
    local node="$1"
    shift
    docker exec "$PREFIX-$node" "$@"
}

mst_show() {
    local node="$1"
    local mstid="$2"
    sw_cli "$node" -c "show bridge mst $mstid"
}

mst_digest() {
    sw_cli "$1" -c "show bridge mst configuration" | awk '/Digest:/ { print $2 }'
}

ping_ok() {
    timeout 12 docker exec "$PREFIX-pc1" ping -c 2 -W 2 10.0.0.2 >/dev/null 2>&1
}

wait_ping() {
    local tries="${1:-10}"
    local _
    for _ in $(seq 1 "$tries"); do
        if ping_ok; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# Wait until the CIST on the two switches has converged to one root and one
# blocked parallel link, with no listening/learning ports left.
wait_cist() {
    local out1 out2 roots blocks trans
    for _ in $(seq 1 120); do
        out1="$(mst_show sw1 0)"
        out2="$(mst_show sw2 0)"
        roots="$(printf '%s\n%s\n' "$out1" "$out2" | grep -c "This bridge is the root" || true)"
        blocks="$(printf '%s\n%s\n' "$out1" "$out2" | grep -c " BLK " || true)"
        trans="$(printf '%s\n%s\n' "$out1" "$out2" | grep -Ec " (LSN|LRN) " || true)"
        if [ "$roots" = "1" ] && [ "$blocks" = "1" ] && [ "$trans" = "0" ] &&
           printf '%s\n' "$out2" | grep -q "This bridge is the root" &&
           printf '%s\n' "$out1" | grep -q " FWD "; then
            printf '%s\n' "$out1" >"$WIRE_DIR/cist-sw1.txt"
            printf '%s\n' "$out2" >"$WIRE_DIR/cist-sw2.txt"
            return 0
        fi
        sleep 1
    done
    printf '\n--- sw1 CIST ---\n%s\n--- sw2 CIST ---\n%s\n' "$out1" "$out2" >&2
    return 1
}

# Wait for one MSTI to converge with the given regional root and blocked port.
wait_msti() {
    local id="$1" root_node="$2" blocked_node="$3" blocked_port="$4"
    local out1 out2 roots blocks trans root_out
    for _ in $(seq 1 90); do
        out1="$(mst_show sw1 "$id")"
        out2="$(mst_show sw2 "$id")"
        roots="$(printf '%s\n%s\n' "$out1" "$out2" | grep -c "This bridge is the root" || true)"
        blocks="$(printf '%s\n%s\n' "$out1" "$out2" | grep -c " BLK " || true)"
        trans="$(printf '%s\n%s\n' "$out1" "$out2" | grep -Ec " (LSN|LRN) " || true)"
        if [ "$root_node" = "sw1" ]; then root_out="$out1"; else root_out="$out2"; fi
        if [ "$roots" = "1" ] && [ "$blocks" = "1" ] && [ "$trans" = "0" ] &&
           printf '%s\n' "$root_out" | grep -q "This bridge is the root"; then
            if [ "$blocked_node" = "sw1" ]; then
                if printf '%s\n' "$out1" | grep -Eq "^${blocked_port} .*BLK"; then
                    printf '%s\n' "$out1" >"$WIRE_DIR/msti${id}-sw1.txt"
                    printf '%s\n' "$out2" >"$WIRE_DIR/msti${id}-sw2.txt"
                    return 0
                fi
            else
                if printf '%s\n' "$out2" | grep -Eq "^${blocked_port} .*BLK"; then
                    printf '%s\n' "$out1" >"$WIRE_DIR/msti${id}-sw1.txt"
                    printf '%s\n' "$out2" >"$WIRE_DIR/msti${id}-sw2.txt"
                    return 0
                fi
            fi
        fi
        sleep 1
    done
    printf '\n--- sw1 MSTI %s ---\n%s\n--- sw2 MSTI %s ---\n%s\n' \
        "$id" "$out1" "$id" "$out2" >&2
    return 1
}

configure_mst_region() {
    local node="$1" cist_priority="$2" msti1_priority="$3"
    sw_cli "$node" -c "config" \
        -c "feature enable mstp" \
        -c "spanning-tree mode mstp" \
        -c "bridge mst name MST-LAB" \
        -c "bridge mst revision 1" \
        -c "bridge mst instance 1 vlan 10" \
        -c "bridge mst instance 2 vlan 20" \
        -c "bridge priority $cist_priority" \
        -c "bridge mst instance 1 priority $msti1_priority" \
        -c "vlan create 10 name users" \
        -c "vlan create 20 name voice" \
        -c "port eth1" -c "mode trunk" -c "allow vlans 1,10,20" -c "exit" \
        -c "port eth2" -c "mode trunk" -c "allow vlans 1,10,20" -c "exit" \
        -c "port eth3" -c "access vlan 10" -c "end" >/dev/null
}

wire_checks() {
    command -v tcpdump >/dev/null 2>&1 || {
        say "skipping wire checks: tcpdump is not installed"
        return 0
    }
    command -v nsenter >/dev/null 2>&1 || {
        say "skipping wire checks: nsenter is not installed"
        return 0
    }
    [ "$(id -u)" = "0" ] || {
        say "skipping wire checks: root is needed for 'nsenter'"
        return 0
    }

    local pc1_pid sw1_pid
    pc1_pid="$(docker inspect -f '{{.State.Pid}}' "$PREFIX-pc1" 2>/dev/null || true)"
    sw1_pid="$(docker inspect -f '{{.State.Pid}}' "$PREFIX-sw1" 2>/dev/null || true)"
    if [ -z "$pc1_pid" ] || [ "$pc1_pid" = "0" ] ||
       [ -z "$sw1_pid" ] || [ "$sw1_pid" = "0" ]; then
        say "skipping wire checks: container network namespaces not found"
        return 0
    fi

    say "restoring VLAN 10 on both access ports for wire-level capture"
    sw_cli sw2 -c "config" -c "port eth3" -c "access vlan 10" -c "end" >/dev/null
    sw_cli sw1 -c "config" -c "port eth3" -c "access vlan 10" -c "end" >/dev/null
    wait_ping 15 >/dev/null 2>&1 || true

    say "capturing MST BPDUs and 802.1Q trunk traffic"
    timeout 12 nsenter -t "$pc1_pid" -n \
        tcpdump -i eth1 -e -nn -vv -c 2 -w "$WIRE_DIR/bpdu.pcap" stp \
        >/dev/null 2>&1 &
    local bpdu_pid=$!
    # MSTI 1 blocks sw2:eth1, so VLAN 10 crosses the loop on sw1:eth2.
    timeout 14 nsenter -t "$sw1_pid" -n \
        tcpdump -i eth2 -e -nn -vv -c 2 -w "$WIRE_DIR/trunk.pcap" \
        'vlan and icmp' >/dev/null 2>&1 &
    local trunk_pid=$!
    timeout 6 nsenter -t "$pc1_pid" -n \
        tcpdump -i eth1 -e -nn -w "$WIRE_DIR/pvst.pcap" \
        'ether dst 01:00:0c:cc:cc:cd' >/dev/null 2>&1 &
    local pvst_pid=$!

    sleep 1
    local _
    for _ in 1 2 3 4 5; do
        pc pc1 ping -c 1 -W 2 10.0.0.2 >/dev/null 2>&1 || true
    done
    wait "$bpdu_pid" || true
    wait "$trunk_pid" || true
    wait "$pvst_pid" || true

    local bpdu_count trunk_count pvst_count
    bpdu_count="$(tcpdump -nn -r "$WIRE_DIR/bpdu.pcap" 2>/dev/null | wc -l | tr -d '[:space:]')"
    trunk_count="$(tcpdump -nn -r "$WIRE_DIR/trunk.pcap" 2>/dev/null | wc -l | tr -d '[:space:]')"
    pvst_count="$(tcpdump -nn -r "$WIRE_DIR/pvst.pcap" 2>/dev/null | wc -l | tr -d '[:space:]')"

    [ "$bpdu_count" -ge 1 ] || fail "no MST BPDUs captured on the access link"
    [ "$trunk_count" -ge 1 ] || fail "no tagged 802.1Q frames captured on the trunk"
    [ "$pvst_count" -eq 0 ] || fail "PVST+ frames were observed on the wire"

    local bpdu_text trunk_text
    bpdu_text="$(tcpdump -r "$WIRE_DIR/bpdu.pcap" -e -nn -vv 2>&1)"
    trunk_text="$(tcpdump -r "$WIRE_DIR/trunk.pcap" -e -nn -vv 2>&1)"
    printf '%s\n' "$bpdu_text" | grep -q "01:80:c2:00:00:00" ||
        fail "MST BPDU does not use destination 01:80:c2:00:00:00"
    if printf '%s\n' "$bpdu_text" | grep -q "802.1Q"; then
        fail "MST BPDU was tagged; IEEE 802.1Q MST BPDUs must be untagged"
    fi
    printf '%s\n' "$bpdu_text" |
        grep -Eqi "MSTP|802\.1s|Multiple Spanning Tree" ||
        fail "captured BPDU is not reported as an IEEE 802.1Q MST BPDU"
    printf '%s\n' "$bpdu_text" |
        grep -Eq "MCID|MSTI" ||
        fail "captured BPDU has no MST Configuration Identifier or MSTI messages"
    printf '%s\n' "$trunk_text" | grep -q "vlan 10" ||
        fail "trunk capture does not show an 802.1Q tag for VLAN 10"

    printf '\nMST BPDU:\n%s\n' "$bpdu_text"
    printf '\n802.1Q trunk frame:\n%s\n' "$trunk_text"
    printf 'PVST+ frames on the wire: %s\n' "$pvst_count"
}

cleanup() {
    if [ "${DEPLOYED:-0}" = "1" ] && [ "$KEEP" != "1" ]; then
        say "destroying lab"
        containerlab destroy -t "$LAB" --cleanup >/dev/null 2>&1 || true
    elif [ "${DEPLOYED:-0}" = "1" ]; then
        say "KEEP=1: leaving lab deployed"
    fi
    [ -n "${WIRE_DIR:-}" ] && rm -rf "$WIRE_DIR"
    return 0
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || fail "docker is not installed"
command -v containerlab >/dev/null 2>&1 || fail "containerlab is not installed"

docker info >/dev/null 2>&1 ||
    fail "cannot talk to the Docker daemon (run as root or join the docker group)"

WIRE_DIR="$(mktemp -d)"

say "building $IMAGE"
docker build -t "$IMAGE" "$ROOT"

say "deploying $LAB"
containerlab destroy -t "$LAB" --cleanup >/dev/null 2>&1 || true
DEPLOYED=1
containerlab deploy -t "$LAB"

say "waiting for the switch CLI"
for _ in $(seq 1 60); do
    if sw_cli sw1 -c "show version" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
sw_cli sw1 -c "show version" >/dev/null 2>&1 || fail "sw1 CLI did not start"

say "configuring one MST Region on both switches"
# sw2 wins the CIST; sw1 wins MSTI 1.  The MSTI 1 port cost on sw2:eth1 makes
# MSTI 1 use the other parallel link than the CIST, proving per-instance state.
configure_mst_region sw1 32768 4096
configure_mst_region sw2 4096 8192
sw_cli sw2 -c "config" -c "port eth1" -c "spanning-tree mst 1 cost 200000" -c "end" >/dev/null

say "checking the MSTP report"
summary="$(sw_cli sw1 -c "show bridge summary")"
printf '%s\n' "$summary"
printf '%s\n' "$summary" | grep -q "Multiple Spanning Tree (MSTP)" ||
    fail "show bridge summary does not report MSTP"
printf '%s\n' "$summary" | grep -q "1 CIST + 2 MSTIs" ||
    fail "expected one CIST and two MSTIs"

say "checking the MST Configuration Identifier"
cfg1="$(sw_cli sw1 -c "show bridge mst configuration")"
cfg2="$(sw_cli sw2 -c "show bridge mst configuration")"
printf '\n--- sw1 ---\n%s\n--- sw2 ---\n%s\n' "$cfg1" "$cfg2"
printf '%s\n' "$cfg1" | grep -q "Name:.*MST-LAB" || fail "sw1 MST name is wrong"
printf '%s\n' "$cfg1" | grep -q "Revision: 1" || fail "sw1 MST revision is wrong"
printf '%s\n' "$cfg1" | grep -q "Max hops:" || fail "sw1 max hops is missing"
printf '%s\n' "$cfg1" | grep -Eq "^1 +10" || fail "VLAN 10 is not mapped to MSTI 1"
printf '%s\n' "$cfg1" | grep -Eq "^2 +20" || fail "VLAN 20 is not mapped to MSTI 2"
digest1="$(mst_digest sw1)"
digest2="$(mst_digest sw2)"
[ -n "$digest1" ] || fail "sw1 did not report an MST configuration digest"
[ "$digest1" = "$digest2" ] ||
    fail "the two switches computed different MST digests ($digest1 vs $digest2)"
[[ "$digest1" =~ ^[0-9A-Fa-f]{32}$ ]] || fail "MST digest is not 16 octets"
printf 'shared MST digest: %s\n' "$digest1"

say "waiting for CIST convergence (root: sw2)"
wait_cist || fail "the CIST did not converge to sw2 as root with one blocked link"
printf '\n--- sw1 CIST ---\n%s\n--- sw2 CIST ---\n%s\n' \
    "$(cat "$WIRE_DIR/cist-sw1.txt")" "$(cat "$WIRE_DIR/cist-sw2.txt")"
grep -q "This bridge is the root" "$WIRE_DIR/cist-sw2.txt" ||
    fail "sw2 is not the CIST root"
if grep -q "This bridge is the root" "$WIRE_DIR/cist-sw1.txt"; then
    fail "sw1 must not be the CIST root"
fi
grep -Eq "^Gi0/2 .*BLK" "$WIRE_DIR/cist-sw1.txt" ||
    fail "the CIST did not block sw1 Gi0/2"

say "waiting for MSTI 1 convergence (regional root: sw1, blocked: sw2:eth1)"
wait_msti 1 sw1 sw2 Gi0/1 ||
    fail "MSTI 1 did not converge to sw1 as regional root with sw2 Gi0/1 blocked"
printf '\n--- sw1 MSTI 1 ---\n%s\n--- sw2 MSTI 1 ---\n%s\n' \
    "$(cat "$WIRE_DIR/msti1-sw1.txt")" "$(cat "$WIRE_DIR/msti1-sw2.txt")"
grep -q "This bridge is the root" "$WIRE_DIR/msti1-sw1.txt" ||
    fail "sw1 is not the MSTI 1 regional root"
grep -Eq "^Gi0/2 .*Root" "$WIRE_DIR/msti1-sw2.txt" ||
    fail "MSTI 1 did not select sw2 Gi0/2 as its root port"

say "waiting for MSTI 2 convergence (regional root: sw1, blocked: sw2:eth2)"
wait_msti 2 sw1 sw2 Gi0/2 ||
    fail "MSTI 2 did not converge to sw1 as regional root with sw2 Gi0/2 blocked"
printf '\n--- sw1 MSTI 2 ---\n%s\n--- sw2 MSTI 2 ---\n%s\n' \
    "$(cat "$WIRE_DIR/msti2-sw1.txt")" "$(cat "$WIRE_DIR/msti2-sw2.txt")"
grep -Eq "^Gi0/2 .*BLK" "$WIRE_DIR/msti2-sw2.txt" ||
    fail "MSTI 2 did not block sw2 Gi0/2"

say "checking the per-instance root list in the summary"
summary1="$(sw_cli sw1 -c "show bridge summary")"
summary2="$(sw_cli sw2 -c "show bridge summary")"
printf '\n--- sw1 summary ---\n%s\n--- sw2 summary ---\n%s\n' "$summary1" "$summary2"
printf '%s\n' "$summary1" | grep -q "Root bridge for: MSTI 1, MSTI 2" ||
    fail "sw1 summary does not list MSTI 1 and MSTI 2 as rooted instances"
printf '%s\n' "$summary2" | grep -q "Root bridge for: CIST" ||
    fail "sw2 summary does not list the CIST as its rooted instance"

say "configuring host addresses"
pc pc1 ip addr add 10.0.0.1/24 dev eth1 2>/dev/null || true
pc pc2 ip addr add 10.0.0.2/24 dev eth1 2>/dev/null || true

say "VLAN 10 (MSTI 1) should forward across the loop"
wait_ping 20 || fail "pc1 cannot ping pc2 in VLAN 10 (MSTI 1)"
printf 'ping in VLAN 10 / MSTI 1: OK\n'

say "changing pc2's access port to VLAN 20 should isolate the hosts"
sw_cli sw2 -c "config" -c "port eth3" -c "access vlan 20" -c "end" >/dev/null
sleep 2
if ping_ok; then
    fail "pc1 can still ping pc2 after VLAN isolation"
fi
printf 'ping across VLAN 10/20: correctly blocked\n'

say "VLAN 20 (MSTI 2) should forward when both access ports use it"
sw_cli sw1 -c "config" -c "port eth3" -c "access vlan 20" -c "end" >/dev/null
wait_ping 20 || fail "pc1 cannot ping pc2 in VLAN 20 (MSTI 2)"
printf 'ping in VLAN 20 / MSTI 2: OK\n'

say "checking that PVST+ configuration is rejected"
pvst_out="$(sw_cli sw1 -c "config" -c "feature enable pvst" 2>&1 || true)"
if ! printf '%s\n' "$pvst_out" | grep -q "PVST+ has been removed"; then
    fail "the CLI did not reject the removed PVST+ feature"
fi

wire_checks

say "checking the mstp feature toggle"
sw_cli sw1 -c "config" -c "feature disable mstp" -c "end" >/dev/null
sw_cli sw1 -c "show features" | grep -Eq "^mstp +disabled" ||
    fail "feature disable mstp did not disable the mstp feature"
sw_cli sw1 -c "show bridge summary" | grep -q "IEEE 802.1D Spanning Tree Protocol (STP)" ||
    fail "disabling mstp did not fall back to IEEE 802.1D STP"
mstp_err="$(sw_cli sw1 -c "config" -c "spanning-tree mode mstp" -c "end" 2>&1 || true)"
printf '%s\n' "$mstp_err" | grep -q "MSTP is disabled" ||
    fail "the CLI allowed 'spanning-tree mode mstp' while the feature was disabled"
sw_cli sw1 -c "config" -c "feature enable mstp" -c "end" >/dev/null
sw_cli sw1 -c "show features" | grep -Eq "^mstp +enabled" ||
    fail "feature enable mstp did not enable the mstp feature"
sw_cli sw1 -c "show bridge summary" | grep -q "Multiple Spanning Tree (MSTP)" ||
    fail "enabling mstp did not return to MSTP"
printf 'mstp feature toggle: OK\n'

say "all IEEE 802.1Q-2005 MSTP containerlab checks passed"
