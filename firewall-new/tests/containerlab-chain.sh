#!/bin/bash
# Containerlab chain test: pc1 --- sw1 --- fw1 --- fw2 --- sw2 --- pc2
#
# Exercises two switches, two firewalls, source NAT on both firewalls,
# stateful return traffic, DNAT with URL filtering and a deny policy.
set -u

LAB=${LAB:-firewall-chain.clab.yml}
PREFIX=clab-fw-chain-lab
FAILED=0

pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILED=1; }

command -v containerlab >/dev/null || { echo "containerlab is not installed" >&2; exit 2; }
docker image inspect switch:latest >/dev/null 2>&1 || { echo "switch:latest missing (see /home/deepak/NetworkSandbox/switch)" >&2; exit 2; }
docker image inspect firewall:latest >/dev/null 2>&1 || { echo "firewall:latest missing; run 'make image'" >&2; exit 2; }

# Containerlab starts node processes before wiring veth pairs. switchd treats
# the resulting ENETDOWN on its receive sockets as fatal, so give it a short
# delay after the links exist by wrapping the stock image in busybox/alpine.
if ! docker image inspect switch-delayed:latest >/dev/null 2>&1; then
    tmp=$(mktemp -d)
    cid=$(docker create switch:latest)
    docker cp "$cid:/switch" "$tmp/switch" >/dev/null
    docker rm "$cid" >/dev/null
    printf '%s\n' 'FROM alpine:3.19' 'COPY switch /switch' 'ENTRYPOINT ["/bin/sh","-c","sleep 2; exec /switch \"$@\"","--"]' >"$tmp/Dockerfile"
    docker build -t switch-delayed:latest "$tmp" >/dev/null || { rm -rf "$tmp"; exit 2; }
    rm -rf "$tmp"
fi

if ! docker ps -a --format '{{.Names}}' | grep -qx "$PREFIX-fw1"; then
    containerlab deploy -t "$LAB" --reconfigure >/dev/null || exit 2
fi

for _ in $(seq 1 30); do
    if docker exec "$PREFIX-sw1" /switch cli -c "config" -c "no feature stp" -c "end" >/dev/null 2>&1 \
       && docker exec "$PREFIX-sw2" /switch cli -c "config" -c "no feature stp" -c "end" >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done
sleep 1

for _ in $(seq 1 30); do
    docker exec "$PREFIX-fw1" /firewall cli --port 2200 -c "show version" >/dev/null 2>&1 \
        && docker exec "$PREFIX-fw2" /firewall cli --port 2200 -c "show version" >/dev/null 2>&1 \
        && break
    sleep 0.5
done

docker exec "$PREFIX-pc1" ping -c 1 -W 1 192.168.2.10 >/dev/null 2>&1
docker exec "$PREFIX-pc2" ping -c 1 -W 1 192.168.1.10 >/dev/null 2>&1

out=$(docker exec "$PREFIX-pc1" ping -c 3 -W 2 192.168.2.10 2>&1)
if echo "$out" | grep -qE '[1-9][0-9]* packets received'; then
    pass "pc1 -> sw1 -> fw1 -> fw2 -> sw2 -> pc2 (ICMP)"
else
    fail "pc1 -> pc2: $out"
fi

out=$(docker exec "$PREFIX-pc2" ping -c 3 -W 2 192.168.1.10 2>&1)
if echo "$out" | grep -qE '[1-9][0-9]* packets received'; then
    pass "pc2 -> sw2 -> fw2 -> fw1 -> sw1 -> pc1 (ICMP, reverse direction)"
else
    fail "pc2 -> pc1: $out"
fi

sessions1=$(docker exec "$PREFIX-fw1" /firewall cli --port 2200 -c "show sessions")
sessions2=$(docker exec "$PREFIX-fw2" /firewall cli --port 2200 -c "show sessions")
if echo "$sessions1" | grep -q '10.0.0.1:' && echo "$sessions2" | grep -q '10.0.0.2:'; then
    pass "both firewalls hold source-NAT sessions"
else
    fail "missing NAT sessions"
fi

docker exec "$PREFIX-pc2" sh -c 'echo chain-ok | nc -l -p 9000 -w 5' >/tmp/chain-nc.out 2>&1 &
sleep 0.5
tcp_out=$(docker exec "$PREFIX-pc1" sh -c 'echo probe | nc -w 3 192.168.2.10 9000' 2>&1)
if echo "$tcp_out" | grep -q 'chain-ok'; then
    pass "TCP 9000 traverses both firewalls and returns data"
else
    fail "TCP 9000 through chain: $tcp_out"
fi

sessions1=$(docker exec "$PREFIX-fw1" /firewall cli --port 2200 -c "show sessions")
if echo "$sessions1" | grep -qE '^[^ ]+ +6 +'; then
    pass "fw1 tracks the TCP flow"
else
    fail "no TCP session on fw1"
fi

# DNAT plus URL filtering: fw2 forwards 192.168.2.1:8080 to pc2:8080 and
# blocks HTTP requests whose Host header matches the block list. A listener
# completes the TCP handshake but never replies, so the client sends its GET
# and the firewall log shows whether that request was blocked.
docker exec -d "$PREFIX-pc2" sh -c 'sleep 20 | nc -l -p 8080'
sleep 0.5
docker exec "$PREFIX-pc1" sh -c 'printf "GET / HTTP/1.1\r\nHost: evil.test\r\nConnection: close\r\n\r\n" | nc -w 3 192.168.2.1 8080' >/dev/null 2>&1
sleep 0.5
if docker logs "$PREFIX-fw2" 2>&1 | grep -q 'url-filter strict: evil.test'; then
    pass "DNAT forwards to pc2 and the URL filter blocks evil.test"
else
    fail "URL filter did not log a block for evil.test"
fi
docker exec "$PREFIX-pc2" pkill nc >/dev/null 2>&1

docker exec -d "$PREFIX-pc2" sh -c 'sleep 20 | nc -l -p 8080'
sleep 0.5
docker exec "$PREFIX-pc1" sh -c 'printf "GET / HTTP/1.1\r\nHost: good.test\r\nConnection: close\r\n\r\n" | nc -w 3 192.168.2.1 8080' >/dev/null 2>&1
sleep 0.5
if docker logs "$PREFIX-fw2" 2>&1 | grep -q 'url-filter strict: good.test'; then
    fail "URL filter blocked the unlisted host good.test"
else
    pass "DNAT and URL filtering permit an unlisted host"
fi
docker exec "$PREFIX-pc2" pkill nc >/dev/null 2>&1

sessions2=$(docker exec "$PREFIX-fw2" /firewall cli --port 2200 -c "show sessions")
if echo "$sessions2" | grep -q 'dnat 192.168.2.10:8080'; then
    pass "fw2 records the destination-NAT mapping"
else
    fail "no DNAT session on fw2"
fi

docker exec "$PREFIX-fw2" /firewall cli --port 2200 \
    -c "policy add 5 transit lan2 any any icmp any deny" >/dev/null
out=$(docker exec "$PREFIX-pc1" ping -c 2 -W 1 192.168.2.10 2>&1)
if echo "$out" | grep -q '100% packet loss'; then
    pass "deny policy on fw2 blocks the chain"
else
    fail "deny policy on fw2 did not block: $out"
fi
docker exec "$PREFIX-fw2" /firewall cli --port 2200 -c "policy delete 5" >/dev/null
out=$(docker exec "$PREFIX-pc1" ping -c 3 -W 2 192.168.2.10 2>&1)
if echo "$out" | grep -qE '[1-9][0-9]* packets received'; then
    pass "chain recovers after deleting the deny policy"
else
    fail "chain did not recover: $out"
fi

echo
echo "fw1 sessions:"; echo "$sessions1"
echo "fw2 sessions:"; echo "$sessions2"
echo "fw1 log tail:"; docker logs "$PREFIX-fw1" 2>&1 | tail -5
echo "fw2 log tail:"; docker logs "$PREFIX-fw2" 2>&1 | tail -5

if [ "$FAILED" -eq 0 ]; then
    echo "ALL CHECKS PASSED"
else
    echo "SOME CHECKS FAILED"
fi
exit "$FAILED"
