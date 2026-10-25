# switch — a tiny educational IEEE 802.1Q VLAN switch with its own CLI

`switch` is a single static Rust binary (≈0.6 MB, well under 2 MB as a
`FROM scratch` image) that behaves like a small access switch. It is meant for
labs: you get real IEEE 802.1Q VLAN bridging, per-VLAN MAC learning, flooding,
and an **IEEE 802.1Q-2005 Multiple Spanning Tree Protocol (MSTP)** implementation
with one CIST plus up to 64 MSTIs, configured through a compact, vendor-neutral
CLI. MSTP is an optional feature and is **disabled by default**: a fresh switch
runs classic IEEE 802.1D STP. Enable it with `feature enable mstp`.

The bridge implements the VLAN bridging and spanning-tree mechanisms itself —
including 802.1Q tag handling, MST BPDU encoding/decoding, the MST Configuration
Identifier, the CIST/MSTI priority vectors and the spanning-tree state machines —
so the packets on the wire are real standard frames you can capture with
`tcpdump`/Wireshark. Once MSTP is enabled, VLANs are mapped to MSTIs and each
instance runs its own topology instead of Cisco's per-VLAN PVST+.

> **Conformance boundary:** this is an IEEE 802.1Q-2005 **MSTP** implementation
> (Clauses 13–14) with the CIST and MSTIs, MST BPDUs, the MST Configuration
> Identifier, Master Ports and per-instance port state. MSTP is enabled with
> `feature enable mstp`; without it the bridge runs classic IEEE 802.1D STP.
> The CIST compatibility mode remains selectable for interoperability. It is not
> a complete implementation of every 802.1Q feature (see
> [Standards conformance](#standards-conformance)).

```
        ┌─────────────── sw1 ───────────────┐        ┌─────────────── sw2 ───────────────┐
        │ Gi0/1 ═════════════════════════════╪════════╪═ Gi0/1                           │
        │ Gi0/2 ═════════════════════════════╪════════╪═ Gi0/2   (blocked by the CIST)   │
        │ Gi0/3 ─── access VLAN 1 ── pc1    │        │═ Gi0/3 ─── access VLAN 1 ── pc2   │
        └───────────────────────────────────┘        └───────────────────────────────────┘
          STP/CIST blocks one link; after `feature enable mstp`, MSTI 1 may block
          the other link on the same loop.
```

## Features

Baseline (always available):

| Area | What you get |
|------|--------------|
| Interfaces | any Linux interface (`eth1`, `eth2`, ...), with display names such as `Gi0/1` |
| VLANs | create/delete VLANs 1–4094, names, suspend/active |
| 802.1Q tagging | PCP/DEI/VID parsing, priority tags (VID 0), reserved VID 4095 discard, tag insertion on trunk egress |
| Access ports | `mode access`, `access vlan N`, untagged ingress/egress |
| Trunks | `mode trunk`, native VLAN, allowed-VLAN lists (`add`/`remove`/`except`), ingress filtering |
| Switching | per-VLAN MAC learning, unknown-unicast/broadcast flooding, MAC move detection, aging |
| MSTP | IEEE 802.1Q-2005 Clauses 13–14: one CIST plus up to 64 MSTIs, MST Configuration Identifier (name/revision/HMAC-MD5 digest), VLAN→MSTID mapping, per-instance priority vectors, Master Ports, per-instance forwarding. Classic STP/CST compatibility modes are also selectable |
| LLDP | IEEE 802.1AB-2026 discovery: advertisements, per-port neighbor table, TTL aging |
| CLI | user/admin/config/port/VLAN modes, `show` commands, startup-config persistence |
| Transports | Unix socket, local `switch cli`, optional TCP (telnet-style) console |

Optional features, off by default and enabled with `feature enable NAME`:

| Feature | Default | What it enables |
|---------|---------|-----------------|
| `mstp` | off | MSTP (CIST + MSTIs). Enable it to run MSTP; while off the bridge runs classic IEEE 802.1D STP with one tree |
| `portfast` | off | `edge on` on access ports (immediate forwarding) |
| `bpdu-guard` | off | err-disable a portfast port that receives a BPDU |
| `lldp` | off | transmit/receive IEEE 802.1AB LLDP advertisements and keep a neighbor table |
| `telnet` | off | allow CLI logins on the TCP listener (`--tcp PORT` enables the listener and this feature; `feature disable telnet` blocks new logins) |

`vlan`, `stp`, `trunking` and `mac-learning` are on by default and can be
turned off (`feature disable ...`) to demonstrate what breaks without them.
`mstp` is off by default: `feature enable mstp` selects MSTP and reactivates the
configured MSTIs; `feature disable mstp` returns to classic IEEE 802.1D STP
with one tree for every VLAN. There is no `pvst` feature: MSTP (CIST + MSTIs)
replaces per-VLAN PVST+.

## Build and run

Requirements: Rust (tested with 1.75) and Linux. Raw sockets need `CAP_NET_RAW`.

```bash
cargo build --release            # target/release/switch, ~1 MB
cargo test                       # packet, STP, VLAN and CLI unit tests

# real dataplane (needs interfaces to exist)
sudo ./target/release/switch daemon --ports eth1,eth2,eth3 --tcp 2200

# no privileges needed: CLI + STP timers only, no raw sockets
./target/release/switch daemon --no-dataplane --ports eth1,eth2,eth3

# in another terminal
./target/release/switch cli
# one-shot (repeat -c to keep one configuration session)
./target/release/switch cli -c "config" -c "vlan create 10 name users" -c "end"
./target/release/switch cli -c "show bridge"
# or over TCP
./target/release/switch cli --host 127.0.0.1 --port 2200
```

The daemon writes its startup configuration to `/etc/switch/startup-config`
(falling back to `/tmp/switch/startup-config` when not writable). Use
`save` to persist immediately; changes are also auto-saved a couple of
seconds after the last change. The file is written in the native command
syntax shown below; IOS spellings are still accepted when it is loaded, so
older configs keep working.

### CLI example

```
sw1> admin
sw1# config
sw1(config)# device name sw1
sw1(config)# vlan create 10 name users
sw1(config)# vlan create 20 name voice
sw1(config)# port eth1
sw1(config-port)# mode trunk
sw1(config-port)# native vlan 10
sw1(config-port)# allow vlans 10,20
sw1(config-port)# exit
sw1(config)# port eth2
sw1(config-port)# access vlan 10
sw1(config-port)# edge on                  ! requires: feature enable portfast
sw1(config-port)# exit
sw1(config)# feature enable mstp
sw1(config)# spanning-tree mode mstp
sw1(config)# bridge priority 4096          ! CIST bridge priority
sw1(config)# bridge mst name REGION-A
sw1(config)# bridge mst revision 1
sw1(config)# bridge mst instance 1 vlan 10
sw1(config)# bridge mst instance 1 priority 4096
sw1(config)# bridge mst instance 2 vlan 20
sw1(config)# end
sw1# show vlans
sw1# show trunk
sw1# show bridge
sw1# show bridge mst 1
sw1# show bridge mst configuration
sw1# show bridge summary
sw1# show fdb
sw1# save
```

MSTP is off by default. Enable the feature first; `feature enable mstp`
selects MSTP automatically, so the following `spanning-tree mode mstp` is
optional but explicit. MSTP configuration is split between the CIST and the
MSTIs. All bridges in a region must use the same name, revision and
VLAN→MSTID mapping; the switch computes the standard HMAC-MD5 digest and
advertises it in every MST BPDU:

```
sw1(config)# feature enable mstp
sw1(config)# spanning-tree mode mstp
sw1(config)# bridge mst name REGION-A
sw1(config)# bridge mst revision 1
sw1(config)# bridge mst instance 1 vlan 10
sw1(config)# bridge mst instance 1 priority 4096
sw1(config)# bridge mst instance 2 vlan 20,30
sw1(config)# bridge mst max-hops 20
sw1(config)# bridge priority 4096          ! CIST priority
sw1(config)# bridge hello 2
sw1(config)# bridge max-age 20
sw1(config)# bridge forward-delay 15
```

Per-port parameters can override the CIST or an individual MSTI:

```
sw1(config)# port eth1
sw1(config-port)# spanning-tree cost 20000        ! CIST external cost
sw1(config-port)# spanning-tree priority 128      ! CIST port priority
sw1(config-port)# spanning-tree mst 1 cost 200000
sw1(config-port)# spanning-tree mst 1 priority 96
```

The old per-VLAN spellings (`bridge vlan 10 priority 4096`,
`spanning-tree vlan 10 hello-time 2`, ...) are accepted as compatibility
aliases and apply to the CIST.

Feature flags are global configuration commands:

```
sw1(config)# feature enable portfast
sw1(config)# feature enable bpdu-guard
sw1(config)# feature enable mstp      ! enable MSTP; use the CIST + MSTIs
sw1(config)# feature disable mstp     ! fall back to classic IEEE 802.1D STP
sw1(config)# feature disable stp      ! stop STP (all ports keep forwarding)
sw1(config)# feature enable stp
```

## Containerlab

A ready lab is in [`switch.clab.yml`](switch.clab.yml): two switches with two
parallel links (a deliberate loop) and two Alpine hosts, one behind each switch.
The topology uses fixed system MAC addresses so the CIST and MSTI elections are
deterministic.

```bash
docker build -t switch:latest .
containerlab deploy -t switch.clab.yml

# watch the CIST: one switch is root, one parallel port goes BLK
docker exec -it clab-stp-lab-sw1 /switch cli -c "show bridge"
docker exec -it clab-stp-lab-sw1 /switch cli -c "show bridge summary"
docker exec -it clab-stp-lab-sw2 /switch cli -c "show ports"

# per-instance view: the MSTIs may elect a different root and block other ports
docker exec -it clab-stp-lab-sw1 /switch cli -c "show bridge mst 1"
docker exec -it clab-stp-lab-sw2 /switch cli -c "show bridge mst 1"
docker exec -it clab-stp-lab-sw1 /switch cli -c "show bridge mst configuration"

# console over TCP from inside a node
docker exec -it clab-stp-lab-sw1 /switch cli --host 127.0.0.1 --port 2200
```

The automated end-to-end check builds the image, deploys the lab, enables MSTP
and configures a shared MST Region on both switches, then verifies that the
CIST and each MSTI converge independently. It then verifies 802.1Q VLAN forwarding and VLAN
isolation. When run as root with `tcpdump` available, it also captures the wire
protocol and checks for an untagged IEEE 802.1Q MST BPDU (version 3, type
`0x02`) to `01:80:c2:00:00:00` carrying the MST Configuration Identifier, a
VLAN 10 tag on the active trunk, and the absence of PVST+ frames:

```bash
./tests/containerlab-8021q.sh          # if you already have Docker access
sudo ./tests/containerlab-8021q.sh     # run as root (wire capture needs it)
KEEP=1 sudo ./tests/containerlab-8021q.sh   # keep it for inspection
make lab-test                          # same script through the Makefile
```

The script needs Docker access (usually root or membership in the `docker`
group), `containerlab`, and network access to pull `alpine:3.19` if it is not
already present. It takes about two minutes because STP listens and learns for
two forward delays. The wire captures require root (for `nsenter`) and
`tcpdump`; they are skipped with a message when those are unavailable.

### Full protocol evidence

[`EVIDENCE.md`](EVIDENCE.md) is a protocol-by-protocol report generated by one
containerlab run. The evidence script exercises every protocol documented in
this README: default IEEE 802.1D STP, the MSTP-disabled configuration error,
MSTP with a CIST and two MSTIs, classic STP and CST compatibility modes,
802.1Q tagging/native VLAN/VLAN isolation, LLDP, the TCP console, rejected
protocols (PVST+, RSTP, DTP, VTP, CDP, LACP) and startup-config persistence
across a daemon reload. Each section records the CLI transcript, convergence
time and, where relevant, the raw frame:

```bash
sudo ./tests/containerlab-evidence.sh
KEEP=1 sudo ./tests/containerlab-evidence.sh   # leave the lab deployed
```

The full transcript and the `.pcap` captures are written to
`/tmp/opencode/evidence-<timestamp>/`; the run takes roughly fifteen minutes
because every STP/MSTP instance listens and learns for two forward delays.

Manual end-to-end check. The first election takes about 30 s (two forward
delays):

```bash
docker exec clab-stp-lab-pc1 ip addr add 10.0.0.1/24 dev eth1
docker exec clab-stp-lab-pc2 ip addr add 10.0.0.2/24 dev eth1
docker exec clab-stp-lab-pc1 ping -c 3 10.0.0.2
```

To build an MST Region, map VLANs to MSTIs, and verify per-instance
forwarding and isolation:

```bash
# identical region name, revision and VLAN mapping on both switches
for sw in sw1 sw2; do
  docker exec clab-stp-lab-$sw /switch cli -c "config" \
    -c "feature enable mstp" \
    -c "spanning-tree mode mstp" \
    -c "bridge mst name MST-LAB" -c "bridge mst revision 1" \
    -c "bridge mst instance 1 vlan 10" -c "bridge mst instance 2 vlan 20" \
    -c "vlan create 10" -c "vlan create 20" \
    -c "port eth1" -c "mode trunk" -c "allow vlans 1,10,20" -c "exit" \
    -c "port eth2" -c "mode trunk" -c "allow vlans 1,10,20" -c "exit" \
    -c "port eth3" -c "access vlan 10" -c "end"
done
sleep 35
docker exec clab-stp-lab-pc1 ping -c 3 10.0.0.2        # passes over VLAN 10

# CIST and MSTI 1 can have different roots and different blocked ports
docker exec clab-stp-lab-sw1 /switch cli -c "show bridge mst 0"
docker exec clab-stp-lab-sw1 /switch cli -c "show bridge mst 1"
docker exec clab-stp-lab-sw1 /switch cli -c "show bridge mst configuration"

# now isolate them (VLAN 10 vs 20): ping fails
docker exec clab-stp-lab-sw2 /switch cli -c "config" \
  -c "port eth3" -c "access vlan 20" -c "end"
```

The lab file sets `cmd: daemon --ports eth1,eth2,eth3 --tcp 2200 --hostname sw1`.
The image entrypoint is `/switch`, so `cmd` contains only arguments. Ports must
be listed explicitly because containerlab creates them after the container
starts; the daemon retries attaching missing interfaces every second, so that
ordering is harmless.

The image is built `FROM scratch`; it has no shell. Use `docker exec ... /switch ...`
rather than `bash`, or attach another container that has a shell for traffic
tests (`apk add tcpdump` in `pc1`).

If your runtime drops capabilities, run the switch container with `NET_RAW`
(and `NET_ADMIN` only if you want to toggle link state). Containerlab 0.57 runs
nodes privileged by default, so the example topology needs no capability
settings; direct `docker run` needs `--cap-add=NET_RAW`.

## How the switch forwards

1. **Ingress** — an `AF_PACKET`/`SOCK_RAW` socket per port receives every frame.
   Linux usually removes the 802.1Q header before handing a frame to a packet
   socket, so the daemon requests `PACKET_AUXDATA` and re-inserts the tag from
   the control message (the same mechanism `tcpdump` uses to display VLAN tags).
2. **802.1Q classification** — an untagged frame belongs to the port PVID
   (access VLAN or trunk native VLAN); a priority-tagged frame (VID 0) also
   uses the PVID but keeps PCP/DEI; a tagged frame is accepted only on a trunk
   whose allowed list contains its VID. Tags are never accepted on access
   ports, and VID 4095 is discarded.
3. **BPDUs** — untagged IEEE 802.1Q MST BPDUs (and ST/RST BPDUs for
   interoperability) to `01:80:C2:00:00:00` with LLC `42 42 03` are consumed by
   the MSTP engine and never switched. Tagged BPDUs and Cisco PVST+ SNAP frames
   are not treated as standard BPDUs.
4. **Filtering** — VLAN membership, ingress filtering, the per-MSTID STP state
   (only `forwarding` passes data; `learning` only learns) and reserved
   link-local multicast are checked.
5. **Learning** — source MAC → (VLAN, port) with aging (default 300 s); moves
   are logged.
6. **Forwarding** — known unicast goes to one port; unknown unicast, broadcast
   and multicast are flooded to all *forwarding* ports in the VLAN only.
7. **Egress** — access ports and the trunk native VLAN send untagged; other
   trunk VLANs insert an 802.1Q tag with the ingress PCP/DEI preserved.

No Linux bridge, VLAN sub-interfaces or kernel STP are involved: the daemon
owns the whole forwarding path, so the CLI state and the dataplane cannot
disagree.

## Spanning tree (STP by default, MSTP optional)

A fresh switch runs **classic IEEE 802.1D STP** with one tree for every VLAN.
`feature enable mstp` switches to **MSTP** (IEEE 802.1Q-2005 Clauses 13–14):
one Common and Internal Spanning Tree (CIST) plus up to 64 Multiple Spanning
Tree Instances (MSTIs). Each VLAN is mapped to exactly one MSTID; the default
maps every VLAN to the CIST (MSTID 0). Different MSTIs can elect different roots
and block different links, while still sharing one MST Region and one BPDU
format.

* **MST Region** — the MST Configuration Identifier is the triple
  `(name, revision, digest)`, where the digest is the standard HMAC-MD5 over
  the VID→MSTID table with the IEEE 802.1Q-2005 key. Two bridges belong to the
  same region only when all three match. `show bridge mst configuration`
  prints the name, revision, digest and VLAN mapping.
* **Bridge IDs** — the CIST uses the 2-byte priority (default `32768`,
  configurable in steps of 4096) followed by the system MAC with system-ID
  extension 0. An MSTI bridge ID uses that MSTI's own priority with the MSTID in
  the low 12 bits, so `bridge mst instance 1 priority 4096` makes this bridge
  `1001.<mac>` for MSTI 1.
* **Vectors** — the CIST compares
  `(root id, external cost, regional root, internal cost, designated bridge,
  designated port)`; an MSTI compares
  `(regional root, internal cost, designated bridge, designated port)`. Ports
  become Root, Designated, Alternate/Backup or Master and send BPDUs when they
  are designated for the CIST or any MSTI.
* **Master Ports** — when a CIST Root Port faces a bridge outside the region,
  the MSTI sees that port as its Master Port and mirrors the CIST state at the
  boundary (13.12, 13.16.4).
* **Timers and transitions** — hello 2 s, max age 20 s, forward delay 15 s,
  configured with `bridge hello`, `bridge max-age` and `bridge forward-delay`.
  Ports move blocking/discarding → listening → learning → forwarding, one
  forward delay per step, independently for the CIST and each MSTI.
* **Hop count** — `bridge mst max-hops` (default 20) is carried in MST BPDUs
  and decremented on internal messages; a message whose remaining hops reach
  zero is discarded.
* **Topology changes** — each instance carries its own TC flag. A CIST topology
  change also marks the boundary MSTIs, and BPDUs are sent towards the root.
* **BPDU format** — one untagged Ethernet frame to `01:80:c2:00:00:00`, LLC
  `42 42 03`, no SNAP. MST BPDUs use protocol version 3, type `0x02`, a
  102-octet base and 16 octets per MSTI (14.3.3). The 51-octet MST
  Configuration Identifier and the Version 3 Length are validated on receipt
  (14.4); malformed version-3 BPDUs fall back to RSTP handling.
* **VLAN scope** — BPDUs are untagged and processed before VLAN
  classification, so one MST BPDU carries the CIST and every MSTI for the port.
  Tagged BPDUs are ignored.

`spanning-tree mode stp` and `spanning-tree mode cst` remain available as
compatibility modes. On this switch they are **behaviourally identical**: both
send classic IEEE 802.1D ST BPDUs and use one tree for every VLAN, because the
CST is the 802.1Q application of STP to the VLAN bridge. They differ only in
the reported protocol name. `feature disable mstp` selects `mode stp`
automatically, and `spanning-tree mode stp` is the explicit classic-STP
selection. `spanning-tree mode mstp` is rejected while the `mstp` feature is
disabled. This is not PVST+: there is no `01:00:0c:cc:cc:cd` destination and
no Cisco SNAP PID. DTP, VTP, CDP and EtherChannel are not implemented, so
configure trunks statically on a peer. See
[Standards conformance](#standards-conformance) for the exact scope.

## Standards conformance

This project implements the VLAN bridging and MSTP parts of IEEE 802.1Q-2005.
MSTP (CIST plus MSTIs) is available but disabled by default; a fresh switch
runs classic IEEE 802.1D STP. Enable MSTP with `feature enable mstp`. This is
not an SST-only or PVST+ implementation.

### Implemented

| Area | Reference | Notes |
|------|-----------|-------|
| VLAN-aware bridging | 802.1Q-2005 5.3, 6.7, 8.5–8.8 | PVID, access/trunk ports, ingress filtering, per-VLAN learning and flooding |
| 802.1Q tag format | 802.1Q-2005 Clause 9 | TPID `0x8100`, PCP/DEI/VID, VID 0 priority tags, VID 4095 discard |
| MSTP protocol | 802.1Q-2005 Clause 13 | CIST plus up to 64 MSTIs, per-instance roles, states and forwarding |
| MST Configuration Table | 802.1Q-2005 8.9, 12.12 | VID→MSTID mapping, exclusivity enforced by the CLI |
| MST Configuration Identifier | 802.1Q-2005 13.7 | name (32 octets), revision, HMAC-MD5 digest with the standard key |
| CIST/MSTI vectors | 802.1Q-2005 13.9–13.11 | external/internal path cost, regional root, designated bridge/port |
| Master Ports and boundary | 802.1Q-2005 13.12, 13.16.4 | MSTI Master Port at a region boundary; state mirrors the CIST |
| MST BPDUs | 802.1Q-2005 14.3.3, 14.4 | version 3, type `0x02`, 102-octet base + 16 octets/MSTI, validation |
| Per-instance management | 802.1Q-2005 12.8, 12.12 | CIST/MSTI priority, internal/external cost, port priority, max hops |
| STP/CST compatibility | 802.1Q-2005 13.6, IEEE 802.1D STP | `mode stp|cst`, ST/RST BPDU receive, TCN |
| LLDP | IEEE 802.1AB-2026 | optional, single-frame base LLDPDU |

### Boundaries and simplifications

| Area | Status |
|------|--------|
| RSTP rapid transition | Proposal/agreement flags are encoded and honoured in a simplified form; the full 802.1D-2004 sync/agreement state machine is not modelled, so transitions use the configured forward delay |
| BPDU filter / root guard | Not implemented (BPDU guard and portfast are) |
| Force protocol version management | `mode stp`, `mode cst` and `mode mstp` only; no per-port force version |
| MSTIs | Up to 64; a conformant MST Bridge must support at least 2, which this does |
| GVRP/MVRP/SPB, PBB, EVB | Out of scope |
| L3, ACLs, QoS scheduling, LACP, SNMP | Out of scope |

### What the wire shows

MSTP sends an untagged **MST BPDU** (protocol version 3, type `0x02`) with a
51-octet MST Configuration Identifier and one 16-octet message per MSTI. With
two MSTIs the 802.3 payload is 137 octets (3 LLC + 102 base + 2 × 16):

```text
02:00:00:00:00:01 > 01:80:c2:00:00:00, 802.3, length 137:
LLC, dsap STP (0x42), ssap STP (0x42), ctrl 0x03:
STP 802.1s, Rapid STP, CIST Flags [none], length 134
    CIST root-id 1000.02:00:00:00:00:02, CIST ext-pathcost 0
    v3len 96, MCID Name MST-LAB, rev 1, digest ac36...
    CIST bridge-id 1000.02:00:00:00:00:01, CIST remaining-hops 20
    MSTI 1 regional-root-id 1001.02:00:00:00:00:01, pathcost 0
    MSTI 2 regional-root-id 8002.02:00:00:00:00:01, pathcost 0
```

The exact `tcpdump` rendering depends on its version; the automated lab check
asserts the destination MAC, the untagged encapsulation and that the capture is
decoded as an MST BPDU. In `mode stp` or `mode cst` the switch instead sends a
classic IEEE 802.1D ST Configuration BPDU (version 0, type `0x00`, 35-octet
body), which is still accepted on receive for interoperability.

### Interoperability

Within one region, all bridges must use the same name, revision and VLAN
mapping; the digest check decides whether a received BPDU is internal (MST) or
external (a different region or an STP/RSTP bridge). At a boundary, the MSTIs
use a Master Port and mirror the CIST state, so a loop through another region is
still broken by the CIST. The switch accepts ST and RST BPDUs, and `mode stp`
or `mode cst` makes it send them exclusively. It does not implement DTP, VTP,
CDP or EtherChannel, so configure trunks statically on a peer.

## LLDP

LLDP is an optional feature (`feature enable lldp`) implementing the
single-frame protocol of **IEEE 802.1AB-2026**:

* **Frames** — EtherType `0x88CC`, destination `01:80:c2:00:00:0e`
  ("nearest bridge"), untagged. Frames are link-local: they are never learned,
  flooded or forwarded, and they are accepted regardless of STP state.
* **Advertised TLVs** — Chassis ID (system MAC), Port ID (Linux interface
  name), TTL, port description (when configured), system name, system
  description and system capabilities (bridge).
* **Timing** — one advertisement every 30 s with a hold multiplier of 4
  (TTL 120 s), plus four one-second advertisements after a link comes up or
  the feature is enabled. Neighbours are aged out when their TTL expires,
  withdrawn on a TTL-0 shutdown PDU, and dropped when the link goes down.
* **Receive TLVs** — port/system descriptions, system capabilities and
  management address are decoded and shown; unknown and organisational TLVs
  (LLDP-MED, ...) are ignored safely.
* **Scope** — base single-frame LLDPDUs. The multiframe PDU amendment and the
  YANG management model folded into the 2026 edition are not implemented.

```
sw1# show lldp
sw1# show lldp neighbors
sw1# show lldp neighbors detail
sw1# show lldp interface eth1
sw1# show lldp traffic
```

## CLI surface

The native vocabulary is deliberately independent of any vendor CLI. The
familiar IOS spellings (`configure terminal`, `switchport ...`,
`show spanning-tree`, `write memory`, ...) still work as aliases.

| Mode | Main commands |
|------|---------------|
| user (`>`) | `admin`, `show`, `quit` |
| admin (`#`) | `config`, `show ...`, `save`, `clear fdb`, `clear counters`, `debug stp on\|off`, `user` |
| global config | `device name NAME`, `vlan create ID [name NAME]`, `vlan delete ID`, `vlan ID`, `port IF`, `spanning-tree mode mstp\|stp\|cst`, `bridge priority N`, `bridge hello N`, `bridge max-age N`, `bridge forward-delay N`, `bridge mst name NAME`, `bridge mst revision N`, `bridge mst max-hops N`, `bridge mst instance ID vlan LIST`, `bridge mst instance ID priority N`, `feature enable\|disable NAME`, `mac aging SEC`, `logging on\|off` |
| port config | `mode access\|trunk`, `access vlan N`, `native vlan N`, `allow vlans ...`, `edge on\|off`, `guard on\|off`, `spanning-tree cost N`, `spanning-tree priority N`, `spanning-tree mst ID cost\|priority N`, `link up\|down`, `description`, `speed`, `duplex` |
| VLAN config | `name`, `state active\|suspend` |

New-style `show` commands: `version`, `vlans`, `ports` (brief table), `port IF`,
`trunk`, `counters [IF]`, `bridge [vlan N|mst ID|mst configuration|summary]`,
`fdb [vlan N|interface IF|count|static]`,
`lldp [neighbors [detail]|interface [IF]|traffic]`, `config`, `startup-config`,
`features`, `log`, `clock`.

`show spanning-tree vlan N` selects the MSTI that carries the VLAN.
`show spanning-tree mst ID` selects one instance (`mst 0` is the CIST), and
`show spanning-tree mst configuration` prints the name, revision, digest and
VLAN mapping. `bridge mode ieee|stp|802.1q|cst` and `bridge mode mstp` select
the protocol; `pvst` and `pvst+` are rejected with an explanation.

The TCP console has **no authentication** and speaks a plain line protocol with
minimal telnet IAC stripping. Use it only inside isolated lab networks. Note
that each `switch cli -c ...` invocation is a separate session: use several
`-c` options (as above) when you need to stay in configuration mode.

## Layout

```
src/packet.rs     Ethernet/802.1Q/LLC, ST/RST/MST BPDU encode+decode (unit tested)
src/model.rs      VLANs, ports, VLAN bit sets, MAC table, MST configuration/digest
src/stp.rs        MSTP engine: CIST + MSTIs, roles, Master Ports, timers, BPDUs
src/md5.rs        MD5 and HMAC-MD5 used by the MST Configuration Identifier
src/lldp.rs       IEEE 802.1AB LLDP PDUs, advertisement timers, neighbor table
src/dataplane.rs  AF_PACKET sockets, 802.1Q ingress/egress, learning, flooding
src/cli.rs        vendor-neutral CLI, show output, startup-config
src/main.rs       daemon, Unix/TCP console, client, signal handling
tests/            containerlab end-to-end check for 802.1Q and MSTP
```

## Limitations (on purpose)

* MSTP is implemented with a simplified RSTP-style transition: proposal and
  agreement flags are present, but the full rapid sync/agreement state machine
  is not modelled, so ports still use the configured forward delay. There is no
  BPDU filter or root guard. GVRP, MVRP, SPB and PBB are out of scope. See
  [Standards conformance](#standards-conformance).
* Static trunks only; DTP/VTP are not implemented.
* No L3, ACLs, port security, QoS scheduling, mirroring, LACP or SNMP.
  PCP/DEI are preserved on tagged egress, but there is no priority queueing.
* LLDP is single-frame only; no LLDP-MED, multiframe PDUs or YANG management.
* Single process, one MAC table per VLAN, software forwarding (fine for labs,
  not for throughput).
* Ports come from `--ports` or are auto-detected from `eth*`/`en*` (excluding
  `eth0`, normally the management NIC). Interfaces that appear after startup
  are attached automatically, which is what makes containerlab veths work.
* CLI line editing is minimal (no history/arrow keys); the TCP console has no
  login.
* `except` in `allow vlans ... except` is treated like `remove` from the current
  list, not "all except".

## License

MIT.

## Files

```
Cargo.toml
Dockerfile
Makefile
switch.clab.yml
examples/startup-config
EVIDENCE.md
tests/containerlab-8021q.sh
tests/containerlab-evidence.sh
src/*.rs
```
