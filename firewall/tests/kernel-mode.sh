#!/bin/bash
# Daemon-managed kernel dataplane (`system dataplane kernel`), end to end:
# startup install + verification, commits reconciled into the kernel,
# inexact configurations refused, external drift repaired, health reporting,
# and the single-enforcement-path lock.
#
# Requires root (network namespaces, veth pairs, nftables) and python3.
# Status: written in Stage 2, NOT YET RUN. Record the first result in
# EVIDENCE.md and fix this script if the environment differs.
set -u

FW=${FW:-$(cd "$(dirname "$0")/.." && pwd)/target/release/firewall}
TMPDIR=$(mktemp -d /tmp/fw-kmode.XXXXXX)
FAILED=0
SERVER_PID=
DAEMON_PID=
DOMAIN=fw-kmode-$$
PASSWORD=kernel-mode-test-password

if [ "$(id -u)" -ne 0 ]; then
    echo "kernel-mode.sh must run as root (try: sudo $0)" >&2
    exit 2
fi
if [ ! -x "$FW" ]; then
    echo "missing $FW; run 'cargo build --release' first" >&2
    exit 2
fi

ns_fw=${DOMAIN}-fw
ns_lan=${DOMAIN}-lan
ns_wan=${DOMAIN}-wan

cleanup() {
    [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null && wait "$DAEMON_PID" 2>/dev/null
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null && wait "$SERVER_PID" 2>/dev/null
    ip netns exec "$ns_fw" "$FW" nft-remove >/dev/null 2>&1
    ip netns del "$ns_lan" 2>/dev/null
    ip netns del "$ns_wan" 2>/dev/null
    ip netns del "$ns_fw" 2>/dev/null
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILED=1; }

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
# Kernel mode: the kernel forwards and nftables enforces.
ip netns exec "$ns_fw" sysctl -qw net.ipv4.ip_forward=1

cat >"$TMPDIR/firewall.conf" <<CONF
system hostname kernel-mode
system dataplane kernel
interface eth0 zone lan address 192.0.2.1/24
interface eth1 zone wan address 203.0.113.1/24
policy 10 lan wan any any icmp any permit
policy 20 lan wan any any tcp 80 permit
CONF

ip netns exec "$ns_wan" python3 -m http.server 80 --bind 0.0.0.0 >"$TMPDIR/http.log" 2>&1 &
SERVER_PID=$!

http_ok() {
    ip netns exec "$ns_lan" python3 - <<'PY' >/dev/null 2>&1
import urllib.request
urllib.request.urlopen("http://203.0.113.10/", timeout=3).read()
PY
}
cli() {
    ip netns exec "$ns_fw" env VELA_CLI_USERNAME=admin VELA_CLI_PASSWORD="$PASSWORD" \
        "$FW" cli --port 2200 -c "$1" 2>&1
}
health() {
    ip netns exec "$ns_fw" python3 - <<'PY' 2>/dev/null
import ssl, urllib.request, urllib.error
ctx = ssl._create_unverified_context()
try:
    print(urllib.request.urlopen("https://127.0.0.1:8080/healthz", context=ctx, timeout=3).read().decode())
except urllib.error.HTTPError as e:
    print(e.code, e.read().decode())
PY
}
rules() { ip netns exec "$ns_fw" nft list table inet vela 2>/dev/null; }

# 1. Startup installs and verifies the ruleset.
ip netns exec "$ns_fw" env VELA_ADMIN_PASSWORD="$PASSWORD" \
    "$FW" daemon --config "$TMPDIR/firewall.conf" >"$TMPDIR/daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 50); do grep -q "installed and verified" "$TMPDIR/daemon.log" && break; sleep 0.2; done
if grep -q "installed and verified" "$TMPDIR/daemon.log"; then pass "startup installed and verified the kernel ruleset"; else fail "startup: $(cat "$TMPDIR/daemon.log")"; fi
rules | grep -q 'vela:' && pass "rules carry generation tags" || fail "no vela: tags in the table"
sleep 0.5
http_ok && pass "permitted tcp/80 is forwarded by the kernel" || fail "tcp/80 blocked under policy 20"
health | grep -q '"dataplane":"kernel"' && pass "health reports the verified kernel dataplane" || fail "health: $(health)"

# 2. The AF_PACKET engine is not forwarding in parallel (one enforcement path).
out=$(ip netns exec "$ns_fw" "$FW" nft-apply --config "$TMPDIR/firewall.conf" 2>&1)
echo "$out" | grep -q "daemon is running" && pass "nft-apply refused while the daemon owns enforcement" || fail "nft-apply: $out"

# 3. Commits reach the kernel.
out=$(cli "policy delete 20")
sleep 0.3
if echo "$out" | grep -q "deleted" && ! http_ok; then pass "deleting policy 20 blocks tcp/80 in the kernel"; else fail "delete: $out"; fi
out=$(cli "policy add 20 lan wan any any tcp 80 permit")
sleep 0.3
if echo "$out" | grep -q "policy added" && http_ok; then pass "adding policy 20 back permits tcp/80"; else fail "add: $out"; fi

# 4. A configuration the kernel cannot enforce exactly is refused; the
#    running ruleset is untouched.
before=$(rules | md5sum)
out=$(cli "policy add 30 lan wan any any tcp 443 permit user alice")
if echo "$out" | grep -q "cannot enforce" && [ "$(rules | md5sum)" = "$before" ]; then
    pass "user-scoped policy refused in kernel mode, ruleset unchanged"
else
    fail "inexact commit: $out"
fi

# 5. External drift is detected and repaired by the monitor (5 s period).
ip netns exec "$ns_fw" nft insert rule inet vela forward tcp dport 22 accept comment intruder
sleep 7
if ! rules | grep -q intruder && grep -q "drift detected" "$TMPDIR/daemon.log"; then
    pass "foreign rule removed and drift logged"
else
    fail "drift not repaired: $(grep drift "$TMPDIR/daemon.log")"
fi
http_ok && pass "policy still enforced after reconciliation" || fail "tcp/80 broken after reconcile"

# 6. Kernel forwarding off is reported (fail closed: nothing passes).
ip netns exec "$ns_fw" sysctl -qw net.ipv4.ip_forward=0
sleep 6
health | grep -q 'degraded' && pass "forwarding off reported as degraded" || fail "health with forwarding off: $(health)"
ip netns exec "$ns_fw" sysctl -qw net.ipv4.ip_forward=1

# 7. After the daemon exits the last verified ruleset stays enforced.
kill "$DAEMON_PID"; wait "$DAEMON_PID" 2>/dev/null; DAEMON_PID=
rules | grep -q 'vela:' && pass "ruleset persists after the daemon exits" || fail "table vanished on exit"

if [ "$FAILED" -eq 0 ]; then echo "kernel-mode: all checks passed"; else echo "kernel-mode: FAILURES (daemon log: $TMPDIR/daemon.log)"; trap - EXIT; fi
exit "$FAILED"
