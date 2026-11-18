#!/bin/bash
# Containerlab smoke test for firewall.clab.yml.
#
# Deploys the lab, checks forwarding, stateful return traffic, SNAT and a
# deny policy through the deployed containers, then destroys the lab.
set -u

LAB=${LAB:-firewall.clab.yml}
IMAGE=${IMAGE:-firewall:latest}
PREFIX=clab-firewall-lab
FAILED=0

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILED=1; }

command -v containerlab >/dev/null || {
    echo "containerlab is not installed" >&2
    exit 2
}
docker image inspect "$IMAGE" >/dev/null 2>&1 || {
    echo "docker image $IMAGE not found; run 'make image'" >&2
    exit 2
}

containerlab deploy -t "$LAB" --reconfigure >/dev/null || exit 2
trap 'containerlab destroy -t "$LAB" --cleanup >/dev/null 2>&1' EXIT

# Let the firewall daemon bind its sockets and the hosts get their routes.
sleep 2

ip netns exec "$PREFIX-pc-lan" ping -c 1 -W 1 10.0.0.99 >/dev/null 2>&1
ip netns exec "$PREFIX-pc-wan" ping -c 1 -W 1 192.168.10.10 >/dev/null 2>&1

out=$(ip netns exec "$PREFIX-pc-lan" ping -c 3 -W 2 10.0.0.99 2>&1)
if echo "$out" | grep -qE '[1-9][0-9]* received'; then
    pass "pc-lan -> pc-wan"
else
    fail "pc-lan -> pc-wan: $out"
fi

out=$(ip netns exec "$PREFIX-pc-wan" ping -c 3 -W 2 192.168.10.10 2>&1)
if echo "$out" | grep -qE '[1-9][0-9]* received'; then
    pass "pc-wan -> pc-lan"
else
    fail "pc-wan -> pc-lan: $out"
fi

sessions=$(docker exec "$PREFIX-fw" /firewall cli --port 2200 -c "show sessions")
if echo "$sessions" | grep -q '10.0.0.1:'; then
    pass "source NAT session present"
else
    fail "no SNAT session: $sessions"
fi

docker exec "$PREFIX-fw" /firewall cli --port 2200 \
    -c "policy add 5 wan lan any any icmp any deny" >/dev/null
out=$(ip netns exec "$PREFIX-pc-wan" ping -c 2 -W 1 192.168.10.10 2>&1)
if echo "$out" | grep -q '100% packet loss'; then
    pass "deny policy blocks pc-wan -> pc-lan"
else
    fail "deny policy did not block: $out"
fi

if [ "$FAILED" -eq 0 ]; then
    echo "ALL CHECKS PASSED"
else
    echo "SOME CHECKS FAILED"
fi
exit "$FAILED"
