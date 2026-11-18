# firewall

A small, original stateful IPv4 firewall written in Rust. It runs as a
userspace forwarding engine over AF_PACKET sockets, with a command line and a
web GUI for configuration and observation.

This is an educational project. It is not affiliated with, derived from, or a
compatible replacement for any commercial firewall product.

## Features

- VDOM-style virtual firewall partitions: interfaces, zones, default routes,
  policies, DNAT and sessions are scoped to a named VDOM.
- Stateful inspection for TCP, UDP and ICMP with configurable timeouts.
- First-match policy by lowest rule id, with zone pairs, address objects and
  groups, services, applications, permit/deny, logging and source NAT.
- Destination NAT (port forwarding), evaluated before local delivery.
- URL filtering by HTTP `Host` or TLS SNI, with block/allow entries and a small
  built-in category list.
- IPS and antivirus profiles using literal patterns (`\xNN`, `\n`, `\r`, `\t`,
  `\\` escapes supported).
- Per-policy traffic shaping (token bucket, kbit/s).
- Per-zone SYN and ICMP flood limits.
- Text or JSON flow logging, GUI session/policy views, config validation.
- ARP resolution, TTL decrement and checksum rewriting.
- TCP state tracking (SYN_SENT, SYN_RECV, ESTABLISHED, CLOSING, TIME_WAIT,
  CLOSED) with per-state timeouts. Only a clean SYN opens a TCP flow; stray
  ACKs, packets after RST and SYNs inside an established flow are dropped.
- Return traffic is inspected with the same URL/IPS/AV profile as the
  forward direction. A flow whose policy is deleted, disabled or changed to
  deny is cut off.
- Ingress sanity drops: fragments, martian source/destination, LAND, and
  invalid TCP flag combinations.
- ICMP Time Exceeded (traceroute works through the firewall) and Network
  Unreachable on no route, rate limited per zone.
- Policy actions `permit`, `deny` and `reject` (TCP RST or ICMP unreachable);
  `disable` and `name <word>` options; per-policy hit counters in
  `show policies`.
- Connection-table protection: `system max-sessions`, `system
  max-sessions-per-ip`; `zone <z> udp-flood <pps>` limits new UDP flows.

## Build

```sh
cargo test
cargo build --release
```

A static build used by the container images:

```sh
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
cargo build --release --target x86_64-unknown-linux-musl
make image   # builds firewall:latest with a static musl binary
```

## Run

```sh
sudo ./target/release/firewall daemon --config examples/default.conf
```

The daemon needs `CAP_NET_RAW`/root to open AF_PACKET sockets. The CLI and GUI
both require an authenticated administrator; both bind loopback by default.
The GUI uses TLS with a generated self-signed certificate when no certificate
is configured. On first start the daemon creates the `admin` administrator and
writes its generated password to a mode-0600 file beside the config
(`<config>.bootstrap-password`), printing the username and file path. Set
`VELA_ADMIN_PASSWORD` instead to supply your own initial password.

```sh
export VELA_CLI_USERNAME=admin VELA_CLI_PASSWORD='the bootstrap password'
./target/release/firewall cli --port 2200 -c "show policies"
./target/release/firewall cli --port 2200 -c "show sessions"
./target/release/firewall cli --port 2200 -c "policy add 100 trust untrust any any any any deny"
# or reuse a GUI-created API token:
VELA_API_TOKEN=vela_... ./target/release/firewall cli -c "show version"
```

Management settings include `system cli-bind`, `system gui-bind`,
`system tls on|off`, `system tls-cert`, `system tls-key`, `system api-rate`,
`system api-burst`, `system max-body`, `system max-packet`,
`system max-inspection`, `system source-rate` and `system source-burst`.
For a lost password run `firewall password-reset-token --config PATH
--username NAME`, then POST the token and a new password to
`/api/v1/auth/password-reset`.

## Kernel nftables backend (opt-in)

The daemon's userspace engine remains the default dataplane. An explicit
command installs the same IPv4 zones, policies, state rules, logging, counters,
DNAT and masquerade rules into the kernel:

```sh
sudo ./target/release/firewall nft-apply --config examples/ngfw.conf
sudo nft list table inet vela
sudo ./target/release/firewall nft-remove
```

Ownership is limited to `inet vela`; no other table is flushed or modified.
Each apply atomically replaces that table, so re-run `nft-apply` after
configuration changes. Kernel enforcement does not start automatically and
does not track later GUI/CLI edits. Do not run the userspace forwarding engine
and the kernel rules for the same traffic at the same time. IPv6 is not yet
translated; `Cidr` and packet handling are IPv4-only.

## Configuration

See `examples/default.conf` for the small baseline, `examples/ngfw.conf` for
the full policy set and `examples/ngfw-vdoms.conf` for two isolated tenants.
The language is line oriented; `#` starts a comment. A `vdom <name>` line
starts a partition; everything after it applies to that VDOM until the next
`vdom` line. The default partition is `root`.

```text
system hostname fw1
system logging on
system log-format json
interface eth1 zone lan1 address 192.168.1.1/24
interface eth2 zone wan address 203.0.113.2/24
route default eth2 via 203.0.113.1
address web 192.168.10.20
address-group servers web
service web tcp 8080
app-def internal-web tcp 8080
url-filter corp block gambling malware phishing
url-filter corp allow corp.example
ips-profile edge
ips-signature edge 1 \x2fetc\x2fpasswd
av-profile av
av-signature av 1 EICAR
shaper branch 2000
zone wan syn-flood 400
zone wan icmp-flood 200
dnat 10 tcp any 8080 192.168.10.20 80
policy 10 lan1 wan @servers any tcp @web permit app internal-web url corp ips edge av av shaper branch log
policy 20 wan lan1 any any tcp 80 permit log
policy 100 any any any any any any deny log
```

Policies are evaluated in ascending id order within the ingress VDOM. Source
NAT is applied when the policy has `nat`; it is skipped for flows that were
destination-NATed. Interfaces, zones, routes, policies, DNAT rules and conntrack
entries are per-VDOM. Address, service, application, URL-filter, IPS, AV and
shaper objects are shared by every VDOM. A VDOM may have one default route.

## Tests

```sh
cargo test
sudo bash tests/nft-kernel.sh
```

`tests/network-namespace.sh` builds a local namespace topology.
`tests/nft-kernel.sh` checks the nftables backend in an isolated topology:
default deny, state rules, counters, reject, DNAT, masquerade and table
removal. Both scripts need root and a release build. The containerlab chain test needs the
`switch:latest` and `firewall:latest` images:

```sh
sudo containerlab deploy -t firewall-chain.clab.yml
sudo bash tests/containerlab-chain.sh
sudo containerlab destroy -t firewall-chain.clab.yml --cleanup
```

The chain test covers ICMP in both directions, source NAT on both hops, TCP
through the chain, DNAT, URL blocking/allowing and an inserted deny policy.

## Limitations

- IPv4 only; no IPv6, VLAN tags or ALG. Fragments are dropped, not reassembled.
- TCP tracking does not check sequence numbers, so a spoofed RST for a known
  5-tuple still closes a flow.
- HTTP/TLS and signature inspection see one packet at a time, so requests
  split across TCP segments may not match.
- Signature profiles are literal substring matches, not real IPS/AV engines.
- The CLI and GUI share the same administrators and RBAC, but the CLI
  transport is plaintext; bind it to loopback or tunnel it. The GUI supports
  TLS and still should be exposed only on a trusted management network.
- ARP misses drop the first packet rather than queueing it.
- No high-availability, routing protocols, VPN or user identity.
- VDOMs isolate forwarding configuration, not administrative access; the GUI
  and CLI are device-wide and object names are shared across VDOMs.
