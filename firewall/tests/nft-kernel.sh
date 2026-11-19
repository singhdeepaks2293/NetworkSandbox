#!/bin/bash
# Exercise the opt-in nftables backend in an isolated network namespace:
# forwarding, default deny, destination NAT and masquerade.
#
# Requires root (network namespaces, veth pairs, nftables).
set -u

FW=${FW:-$(cd "$(dirname "$0")/.." && pwd)/target/release/firewall}
TMPDIR=$(mktemp -d /tmp/fw-nft.XXXXXX)
FAILED=0
SERVER_PID=
DOMAIN=fw-nft-$$

if [ "$(id -u)" -ne 0 ]; then
    echo "nft-kernel.sh must run as root (try: sudo $0)" >&2
    exit 2
fi
if [ ! -x "$FW" ]; then
    echo "missing $FW; run 'cargo build --release' first" >&2
    exit 2
fi

cleanup() {
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null
    [ -n "$SERVER_PID" ] && wait "$SERVER_PID" 2>/dev/null
    ip netns del "${DOMAIN}-lan" 2>/dev/null
    ip netns del "${DOMAIN}-wan" 2>/dev/null
    ip netns del "${DOMAIN}-fw" 2>/dev/null
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILED=1; }

ns_fw=${DOMAIN}-fw
ns_lan=${DOMAIN}-lan
ns_wan=${DOMAIN}-wan

ip netns add "$ns_fw"
ip netns add "$ns_lan"
ip netns add "$ns_wan"
ip link add lan0 type veth peer name eth0
ip link set lan0 netns "$ns_lan"
ip link set eth0 netns "$ns_fw"
ip link add wan0 type veth peer name eth1
ip link set wan0 netns "$ns_wan"
ip link set eth1 netns "$ns_fw"
for n in "$ns_fw" "$ns_lan" "$ns_wan"; do ip -n "$n" link set lo up; done
ip -n "$ns_fw" link set eth0 up
ip -n "$ns_fw" link set eth1 up
ip -n "$ns_lan" link set lan0 up
ip -n "$ns_wan" link set wan0 up
ip -n "$ns_fw" addr add 192.0.2.1/24 dev eth0
ip -n "$ns_fw" addr add 203.0.113.1/24 dev eth1
ip -n "$ns_lan" addr add 192.0.2.10/24 dev lan0
ip -n "$ns_wan" addr add 203.0.113.10/24 dev wan0
ip -n "$ns_lan" route add default via 192.0.2.1
ip -n "$ns_wan" route add default via 203.0.113.1
ip netns exec "$ns_fw" sysctl -qw net.ipv4.ip_forward=1

write_base() {
    cat <<CONF
system hostname nft-kernel
interface eth0 zone lan address 192.0.2.1/24
interface eth1 zone wan address 203.0.113.1/24
CONF
}
{ write_base; echo "policy 10 lan wan any any icmp any permit"; echo "policy 20 lan wan any any tcp 80 permit"; } >"$TMPDIR/allow.conf"
{ write_base; echo "policy 10 lan wan any any icmp any permit"; echo "policy 20 lan wan any any tcp 80 deny"; } >"$TMPDIR/deny.conf"
{ write_base; echo "policy 20 lan wan any any tcp 80 reject"; } >"$TMPDIR/reject.conf"
{ write_base; echo "dnat 1 tcp any 8080 203.0.113.10 80"; echo "policy 10 lan wan any any tcp 8080 permit"; echo "policy 20 lan wan any any tcp 80 permit"; } >"$TMPDIR/dnat.conf"
{ write_base; echo "policy 10 lan wan any any tcp 80 permit nat"; } >"$TMPDIR/masq.conf"

ip netns exec "$ns_wan" python3 -m http.server 80 --bind 0.0.0.0 >"$TMPDIR/http.log" 2>&1 &
SERVER_PID=$!
sleep 0.7

apply() { ip netns exec "$ns_fw" "$FW" nft-apply --config "$TMPDIR/$1.conf"; }
contains() { ip netns exec "$ns_fw" nft list table inet vela | grep -q "$1"; }

apply allow
if ip netns exec "$ns_lan" ping -c1 -W2 -q 203.0.113.10 >/dev/null; then pass "allow: ICMP forwarded"; else fail "allow: ICMP blocked"; fi
if ip netns exec "$ns_lan" curl -fsS --max-time 2 http://203.0.113.10/ >/dev/null; then pass "allow: tcp/80 forwarded"; else fail "allow: tcp/80 blocked"; fi
if contains 'ct state == established accept' && contains 'counter'; then pass "allow: state and counter rules present"; else fail "allow: expected state/counter rules missing"; fi

apply deny
if ip netns exec "$ns_lan" ping -c1 -W2 -q 203.0.113.10 >/dev/null; then pass "deny: unrelated ICMP still forwarded"; else fail "deny: ICMP blocked"; fi
if ip netns exec "$ns_lan" curl -fsS --max-time 2 http://203.0.113.10/ >/dev/null; then fail "deny: tcp/80 still forwarded"; else pass "deny: tcp/80 blocked"; fi
if contains 'tcp dport 80.*drop'; then pass "deny: drop rule installed"; else fail "deny: drop rule missing"; fi

apply reject
start=$(date +%s%N)
if ip netns exec "$ns_lan" curl -fsS --max-time 2 http://203.0.113.10/ >/dev/null; then
    fail "reject: tcp/80 was accepted"
else
    elapsed=$(( ($(date +%s%N) - start) / 1000000 ))
    if [ "$elapsed" -lt 1500 ]; then
        pass "reject: tcp/80 rejected in ${elapsed}ms"
    else
        fail "reject: tcp/80 timed out (${elapsed}ms)"
    fi
fi
if contains 'reject'; then pass "reject: rule installed"; else fail "reject: rule missing"; fi

apply dnat
if ip netns exec "$ns_lan" curl -fsS --max-time 2 http://203.0.113.1:8080/ >/dev/null; then pass "dnat: tcp/8080 translated to wan tcp/80"; else fail "dnat: translated connection failed"; fi
if contains 'dnat ip to 203.0.113.10:80'; then pass "dnat: translation rule installed"; else fail "dnat: translation rule missing"; fi

apply masq
if ip netns exec "$ns_lan" curl -fsS --max-time 2 http://203.0.113.10/ >/dev/null; then pass "masq: outbound tcp/80 forwarded"; else fail "masq: outbound tcp/80 blocked"; fi
sleep 0.2
if grep -q '203\.0\.113\.1 ' "$TMPDIR/http.log"; then pass "masq: server observed translated source"; else fail "masq: server did not observe 203.0.113.1"; fi

ip netns exec "$ns_fw" "$FW" nft-remove
if ip netns exec "$ns_fw" nft list table inet vela >/dev/null 2>&1; then fail "remove: inet vela still present"; else pass "remove: inet vela removed"; fi

exit "$FAILED"
