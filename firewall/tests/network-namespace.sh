#!/bin/bash
# End-to-end dataplane test without containerlab. Builds two network
# namespaces connected through the firewall and checks policy, stateful
# return traffic, source NAT and deny behaviour.
#
# Requires root (network namespaces, veth pairs, AF_PACKET).
set -u

FW=${FW:-$(cd "$(dirname "$0")/.." && pwd)/target/release/firewall}
CLI_PORT=${CLI_PORT:-13200}
GUI_PORT=${GUI_PORT:-18080}
TMPDIR=$(mktemp -d /tmp/fw-ns.XXXXXX)
CONF=$TMPDIR/firewall.conf
LOG=$TMPDIR/daemon.log
FAILED=0
ADMIN_PASS=lab-admin-password
COOKIE_JAR=$TMPDIR/cookies.txt
DAEMON_PID=

if [ "$(id -u)" -ne 0 ]; then
    echo "network-namespace.sh must run as root (try: sudo $0)" >&2
    exit 2
fi
if [ ! -x "$FW" ]; then
    echo "missing $FW; run 'cargo build --release' first" >&2
    exit 2
fi

cleanup() {
    if [ -n "$DAEMON_PID" ]; then
        kill "$DAEMON_PID" 2>/dev/null
        wait "$DAEMON_PID" 2>/dev/null
    fi
    ip netns del fw_ns_lan 2>/dev/null
    ip netns del fw_ns_wan 2>/dev/null
    ip link del fwlan0 2>/dev/null
    ip link del fwwan0 2>/dev/null
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILED=1; }

cli() {
    VELA_CLI_USERNAME=admin VELA_CLI_PASSWORD="$ADMIN_PASS" \
        "$FW" cli --port "$CLI_PORT" "$@"
}

ip netns add fw_ns_lan
ip netns add fw_ns_wan
ip link add fwlan0 type veth peer name hlan0
ip link add fwwan0 type veth peer name hwan0
ip link set hlan0 netns fw_ns_lan
ip link set hwan0 netns fw_ns_wan
ip addr add 192.168.10.1/24 dev fwlan0
ip addr add 10.0.0.1/24 dev fwwan0
ip link set fwlan0 up
ip link set fwwan0 up
ip netns exec fw_ns_lan ip link set lo up
ip netns exec fw_ns_wan ip link set lo up
ip netns exec fw_ns_lan ip addr add 192.168.10.10/24 dev hlan0
ip netns exec fw_ns_lan ip link set hlan0 up
ip netns exec fw_ns_lan ip route add default via 192.168.10.1
ip netns exec fw_ns_wan ip addr add 10.0.0.99/24 dev hwan0
ip netns exec fw_ns_wan ip link set hwan0 up
ip netns exec fw_ns_wan ip route add default via 10.0.0.1
sysctl -qw net.ipv4.ip_forward=0
sysctl -qw net.ipv6.conf.all.forwarding=0 2>/dev/null || true
sysctl -qw net.ipv4.conf.all.send_redirects=0
sysctl -qw net.ipv4.conf.fwlan0.send_redirects=0
sysctl -qw net.ipv4.conf.fwwan0.send_redirects=0

cat >"$CONF" <<'CONF'
system hostname lab
system logging on
interface fwlan0 zone lan address 192.168.10.1/24
interface fwwan0 zone wan address 10.0.0.1/24
policy 10 lan wan any any icmp any permit nat
policy 20 wan lan any any icmp any permit
CONF

VELA_ADMIN_PASSWORD="$ADMIN_PASS" "$FW" daemon --config "$CONF" \
    --cli-port "$CLI_PORT" --gui-port "$GUI_PORT" >"$LOG" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 50); do
    if cli -c "show version" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

# Prime ARP so the first-packet ARP drop does not affect the assertions.
ip netns exec fw_ns_lan ping -c 1 -W 1 10.0.0.99 >/dev/null 2>&1
ip netns exec fw_ns_wan ping -c 1 -W 1 192.168.10.10 >/dev/null 2>&1

out=$(ip netns exec fw_ns_lan ping -c 3 -W 2 10.0.0.99 2>&1)
if echo "$out" | grep -qE '[1-9][0-9]* received'; then
    pass "lan -> wan ping traverses policy 10"
else
    fail "lan -> wan ping: $out"
fi

sessions=$(cli -c "show sessions")
if echo "$sessions" | grep -q '10.0.0.1:'; then
    pass "lan flow is source-NATed to 10.0.0.1"
else
    fail "no SNAT session: $sessions"
fi

out=$(ip netns exec fw_ns_wan ping -c 3 -W 2 192.168.10.10 2>&1)
if echo "$out" | grep -qE '[1-9][0-9]* received'; then
    pass "wan -> lan ping traverses policy 20"
else
    fail "wan -> lan ping: $out"
fi

cli -c "policy add 5 wan lan any any icmp any deny" >/dev/null
out=$(ip netns exec fw_ns_wan ping -c 2 -W 1 192.168.10.10 2>&1)
if echo "$out" | grep -q '100% packet loss'; then
    pass "deny policy 5 blocks wan -> lan"
else
    fail "deny policy did not block: $out"
fi

cli -c "policy delete 5" >/dev/null
out=$(ip netns exec fw_ns_wan ping -c 3 -W 2 192.168.10.10 2>&1)
if echo "$out" | grep -qE '[1-9][0-9]* received'; then
    pass "deleting policy 5 restores forwarding"
else
    fail "forwarding not restored: $out"
fi

if curl -fsk -c "$COOKIE_JAR" -H 'Content-Type: application/json' \
        -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PASS\"}" \
        "https://127.0.0.1:$GUI_PORT/api/v1/auth/login" >/dev/null \
   && curl -fsk -b "$COOKIE_JAR" "https://127.0.0.1:$GUI_PORT/api/v1/state" \
        | grep -q '"hostname":"lab"'; then
    pass "web GUI login and /api/v1/state over TLS are live"
else
    fail "web GUI did not return authenticated state"
fi

if grep -q 'permit 192.168.10.10' "$LOG"; then
    pass "dataplane logged a permit decision"
else
    fail "no permit decision in log"
fi

if [ "$FAILED" -eq 0 ]; then
    echo "ALL CHECKS PASSED"
else
    echo "SOME CHECKS FAILED"
    echo "--- daemon log ---"
    cat "$LOG"
fi
exit "$FAILED"
