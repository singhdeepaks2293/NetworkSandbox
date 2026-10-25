# Protocol evidence: IEEE 802.1Q-2005 MSTP and the switch protocol stack

This document records a single, reproducible containerlab run that exercises
every protocol described in [`README.md`](README.md). It is evidence, not a
tutorial: each section pairs the configuration that was entered with the CLI
output and, where the protocol is visible on the wire, the captured frame.

The run was produced by [`tests/containerlab-evidence.sh`](tests/containerlab-evidence.sh)
on **2026-10-25**. The complete transcript and all packet captures are kept
under `/tmp/opencode/evidence-20261025-142009/`:

| Artifact | Contents |
|----------|----------|
| `transcript.txt` | full stdout/stderr of the run |
| `*-sw1.txt`, `*-sw2.txt` | per-instance `show bridge` snapshots at convergence |
| `baseline-stp-bpdu.pcap` | classic IEEE 802.1D ST Configuration BPDU |
| `mstp-bpdu.pcap` | IEEE 802.1Q-2005 MST BPDU (version 3) |
| `stp-mode-bpdu.pcap`, `cst-mode-bpdu.pcap` | compatibility-mode ST BPDUs |
| `stp-trunk-vlan10.pcap`, `mstp-trunk-vlan10.pcap` | tagged 802.1Q trunk frames |
| `stp-access-vlan10.pcap`, `mstp-access-vlan10.pcap` | untagged access frames |
| `mstp-native-vlan10.pcap` | native-VLAN traffic sent untagged |
| `lldp-frame.pcap` | IEEE 802.1AB LLDPDU |
| `pvst-plus.pcap` | 8-second filter for PVST+ BPDUs (zero frames) |
| `startup-body.txt`, `restored-config-body.txt` | persisted vs. reloaded configuration |

## 1. Result summary

| # | Protocol / behaviour | Standard | Verdict | Section |
|---|----------------------|----------|---------|---------|
| 1 | Classic spanning tree, MSTP disabled by default | IEEE 802.1D | PASS | [§3](#3-default-state-mstp-disabled-ieee-8021d-stp) |
| 2 | MSTP configuration rejected while the feature is off | — | PASS (exact error) | [§3.2](#32-pre-enable-configuration-error) |
| 3 | MSTP CIST, two switches, one region | IEEE 802.1Q-2005 Cl. 13–14 | PASS | [§4](#4-enabling-mstp-and-building-a-region) |
| 4 | MSTI 1 and MSTI 2 elect different roots and block different ports | IEEE 802.1Q-2005 Cl. 13.12 | PASS | [§4.3](#43-msti-convergence-and-per-instance-topology) |
| 5 | MST BPDU: version 3, MCID name/revision/digest, per-MSTI records | IEEE 802.1Q-2005 Cl. 14.3 | PASS | [§4.5](#45-mst-bpdu-on-the-wire) |
| 6 | Per-VLAN forwarding over different MSTIs | IEEE 802.1Q-2005 | PASS | [§4.4](#44-per-vlan-forwarding-through-different-mstis) |
| 7 | 802.1Q trunk tagging and access untagging | IEEE 802.1Q | PASS | [§3.4](#34-8021q-tagging-on-trunk-and-access) |
| 8 | Native VLAN is transmitted untagged | IEEE 802.1Q | PASS | [§4.6](#46-native-vlan-10-is-untagged) |
| 9 | VLAN isolation (VLAN 10 vs. VLAN 20) | IEEE 802.1Q | PASS | [§3.5](#35-vlan-isolation) |
| 10 | Classic STP compatibility mode | IEEE 802.1D | PASS | [§5](#5-compatibility-modes-stp-and-cst) |
| 11 | CST compatibility mode | IEEE 802.1Q CST | PASS | [§5](#5-compatibility-modes-stp-and-cst) |
| 12 | LLDP discovery, neighbour table and wire frame | IEEE 802.1AB-2026 | PASS | [§6](#6-lldp) |
| 13 | TCP (telnet-style) console and feature gate | — | PASS | [§7](#7-tcp-console) |
| 14 | PVST+, RSTP, DTP, VTP, CDP, LACP rejected | — | PASS (exact errors) | [§8](#8-rejected-protocols) |
| 15 | Startup-config persistence across a daemon reload | — | PASS (hash match) | [§9](#9-persistence-across-a-daemon-reload) |
| 16 | STP fail-open when the feature is disabled | — | PASS | [§3.6](#36-fail-open-with-stp-disabled) |

The two properties the task centred on are visible in the first two rows of the
transcript:

* a fresh switch reports `mstp disabled` and runs classic STP;
* `spanning-tree mode mstp` is refused until `feature enable mstp` is entered.

## 2. Environment and method

### 2.1 Environment

The values below are copied from the transcript header:

```text
date:        2026-10-25T08:50:09Z
host:        Linux 6.8.0-110-generic x86_64
containerlab: 0.57.0
docker:      29.8.0
tcpdump:     tcpdump version 4.99.4
image:       switch:latest
```

`switch:latest` is built from the repository `Dockerfile`: Rust 1.75 on Alpine,
statically linked against musl, and copied into a `FROM scratch` runtime image.
The switch therefore has no shell of its own; every command in this document is
either `/switch cli ...` inside a node or `docker exec` from the host.

### 2.2 Topology

[`switch.clab.yml`](switch.clab.yml) deploys two switches and two Alpine hosts:

```text
        sw1                                   sw2
   Gi0/1 +--------- 802.1Q trunk ---------+ Gi0/1
         |                                 |
   Gi0/2 +--------- 802.1Q trunk ---------+ Gi0/2
         |                                 |
   Gi0/3 +---- pc1 (10.0.0.1/24)           |
                                   Gi0/3 +---- pc2 (10.0.0.2/24)
```

The two parallel switch-to-switch links form a deliberate loop. Fixed system
MAC addresses make the elections deterministic:

| Node | System MAC | CLI names |
|------|------------|-----------|
| `sw1` | `02:00:00:00:00:01` | `eth1`→`Gi0/1`, `eth2`→`Gi0/2`, `eth3`→`Gi0/3` |
| `sw2` | `02:00:00:00:00:02` | `eth1`→`Gi0/1`, `eth2`→`Gi0/2`, `eth3`→`Gi0/3` |

Both daemons start with `--tcp 2200`, which enables the TCP listener and the
`telnet` feature. The switch's startup-config path is
`/etc/switch/startup-config`, which is also what the persistence test reloads.

### 2.3 Convergence predicate

"Converged" in this document has a precise, machine-checked meaning. The script
polls `show bridge mst <id>` on both switches once per second for up to 180 s
and accepts only when all of the following hold:

1. exactly one switch prints `This bridge is the root` for that instance;
2. exactly one port across both switches is in `BLK`;
3. no port on either switch is in `LSN` (listening) or `LRN` (learning);
4. the root is the expected switch and the blocked port is the expected port.

The expected blocked port differs per instance, which is the whole point of
MSTP: the CIST blocks `sw1 Gi0/2`, MSTI 1 blocks `sw2 Gi0/1`, and MSTI 2 blocks
`sw2 Gi0/2`. Timings are measured from the start of the configuration phase,
not from the first BPDU, and include the full two-forward-delay listen/learn
cycle (15 s + 15 s).

### 2.4 Reproducing the run

```bash
cd switch
sudo ./tests/containerlab-evidence.sh
KEEP=1 sudo ./tests/containerlab-evidence.sh   # leave the lab up
```

The script needs `docker`, `containerlab`, `tcpdump`, `nsenter` and root (or
Docker group membership plus `CAP_NET_RAW`). It destroys and redeploys the lab
itself, and writes the transcript and captures to
`/tmp/opencode/evidence-<timestamp>/`. On this host the test commands are
allow-listed in `/etc/sudoers.d/switch-lab`, so the script runs without
interactive prompts.

## 3. Default state: MSTP disabled, IEEE 802.1D STP

### 3.1 Feature state and protocol

The first command after deploy is `show features`:

```text
$ sw1# show features
Feature                     State
--------------------------- -------
vlan                        enabled
stp                         enabled
mstp                        disabled
trunking                    enabled
mac-learning                enabled
portfast                    disabled
bpdu-guard                  disabled
lldp                        disabled
telnet                      enabled
```

`mstp` is **disabled**; `telnet` is enabled only because the lab daemon was
started with `--tcp 2200`. `show version` and `show bridge summary` report the
same state in protocol terms:

```text
$ sw1# show version
SWITCH-1.0 (0.1.0)
  Educational layer-2 switch (Rust)
  Hostname: sw1
  System MAC: 0200.0000.0001
  Serial: SW020000000001
  Uptime: 0 weeks, 0 days, 0 hours, 0 minutes
  Spanning tree: IEEE 802.1D STP   VLANs: 1   Ports: 3
  Features: vlan, stp, trunking, mac-learning, telnet

$ sw1# show bridge summary
Switch is in IEEE 802.1D Spanning Tree Protocol (STP) mode
Root bridge for: CIST
MSTP feature is disabled; running one STP tree for all VLANs
EtherChannel misconfig guard is disabled
Portfast Default is disabled
BPDU Guard is disabled
1 spanning tree instance (1 CIST + 0 MSTIs)
```

The running configuration confirms that the default is explicit and
persistable; there is no hidden MSTP state:

```text
feature enable vlan
feature enable stp
feature disable mstp
feature enable trunking
feature enable mac-learning
feature disable portfast
feature disable bpdu-guard
feature disable lldp
feature enable telnet
!
bridge mode stp
bridge priority 32768
bridge mst name 0200.0000.0001
```

The default MST region name is the system MAC and the default revision is 0.
The digest is the standard all-CIST digest `AC36177F50283CD4B83821D8AB26DE62`,
which is the same value an MSTP bridge computes for a region that maps every
VLAN to MSTID 0. That is a useful sanity check even while MSTP is disabled:
the configuration machinery is present, only the protocol is gated.

The first `show bridge` was taken in the same second as the deploy, before the
AF_PACKET dataplane had attached the container interfaces, so every port is
reported as `Dis DIS`:

```text
$ sw1# show bridge
IEEE 802.1D Spanning Tree Protocol (STP)
  Spanning tree enabled protocol stp
  Root ID    Priority    32768
             Address     0200.0000.0001
             This bridge is the root
             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec
...
Gi0/1               Dis  DIS 4         128.1 P2p
Gi0/2               Dis  DIS 4         128.2 P2p
Gi0/3               Dis  DIS 4         128.3 P2p
```

This is a link-attachment artifact, not a spanning-tree state: §3.3 shows the
same ports forwarding after the dataplane is up.

### 3.2 Pre-enable configuration error

With `mstp` off, selecting MSTP is rejected before any state changes:

```text
$ sw1(config)# spanning-tree mode mstp
% MSTP is disabled; enable it with 'feature enable mstp'

$ sw1# show bridge mst 1
% MST instance 1 is not configured
```

`show bridge mst configuration` still prints the (default) region, but the
instance table contains only the CIST:

```text
MST configuration
  Name:     0200.0000.0001
  Revision: 0
  Digest:   AC36177F50283CD4B83821D8AB26DE62
  Max hops: 20

Instance  Vlans mapped
--------  -------------------------------------
0 (CIST)  1-4094
```

The error text is deliberately actionable: it names the exact command that
unlocks the mode. The same gate applies to `feature enable pvst` and to the
removed `rapid-pvst`/`rstp` modes (§8).

### 3.3 STP convergence

VLANs, trunk ports and access ports were configured first:

```text
vlan create 10 name users
vlan create 20 name voice
port eth1
 mode trunk
 allow vlans 1,10,20
port eth2
 mode trunk
 allow vlans 1,10,20
port eth3
 access vlan 10
```

`spanning-tree mode stp` was then entered on both switches to force a clean
re-election. The script measured:

```text
[baseline-stp] converged: root=sw1, blocked=sw2 Gi0/2, transitional ports=0, +31s from phase start
```

The resulting tables show one root and one blocked alternate port:

```text
--- sw1 baseline-stp ---
IEEE 802.1D Spanning Tree Protocol (STP)
  Spanning tree enabled protocol stp
  Root ID    Priority    32768
             Address     0200.0000.0001
             This bridge is the root
...
Gi0/1               Desg FWD 4         128.1 P2p
Gi0/2               Desg FWD 4         128.2 P2p
Gi0/3               Desg FWD 4         128.3 P2p

--- sw2 baseline-stp ---
  Root ID    Priority    32768
             Address     0200.0000.0001
             Cost        4
             Port        1 (Gi0/1)
...
Gi0/1               Root FWD 4         128.1 P2p
Gi0/2               Altn BLK 4         128.2 P2p
Gi0/3               Desg FWD 4         128.3 P2p
```

The cost `4` is the IEEE 802.1D short cost for a 1 Gbit/s link (the lab veth
pair). `sw2` blocks `Gi0/2` because both links offer the same root path cost
and the designated port ID (`128.1`) on `Gi0/1` is better than `128.2`.

### 3.4 802.1Q tagging on trunk and access

With `pc1` at `10.0.0.1/24` and `pc2` at `10.0.0.2/24`, a ping crosses
VLAN 10:

```text
$ pc1# ping -c 3 10.0.0.2
64 bytes from 10.0.0.2: seq=0 ttl=64 time=0.155 ms
64 bytes from 10.0.0.2: seq=1 ttl=64 time=0.227 ms
64 bytes from 10.0.0.2: seq=2 ttl=64 time=0.366 ms
--- 10.0.0.2 ping statistics ---
3 packets transmitted, 3 packets received, 0% packet loss
round-trip min/avg/max = 0.155/0.249/0.366 ms
```

On the active trunk (`sw1 eth1`) the same ICMP exchange carries an 802.1Q tag:

```text
$ (sw1 netns) tcpdump -i eth1 -e -nn -vv -c 2 ... vlan and icmp
14:20:53.804611 aa:c1:ab:94:f1:da > aa:c1:ab:38:0e:5f, ethertype 802.1Q (0x8100), length 102: vlan 10, p 0, ethertype IPv4 (0x0800), (tos 0x0, ttl 64, id 4967, offset 0, flags [DF], proto ICMP (1), length 84)
    10.0.0.1 > 10.0.0.2: ICMP echo request, id 25, seq 0, length 64
14:20:53.804674 aa:c1:ab:38:0e:5f > aa:c1:ab:94:f1:da, ethertype 802.1Q (0x8100), length 102: vlan 10, p 0, ethertype IPv4 (0x0800), (tos 0x0, ttl 64, id 57770, offset 0, flags [none], proto ICMP (1), length 84)
    10.0.0.2 > 10.0.0.1: ICMP echo reply, id 25, seq 0, length 64
```

On the access port (`pc1 eth1`) the same frames are untagged:

```text
$ (pc1 netns) tcpdump -i eth1 -e -nn -vv -c 2 ... icmp
14:20:56.065087 aa:c1:ab:94:f1:da > aa:c1:ab:38:0e:5f, ethertype IPv4 (0x0800), length 98: (tos 0x0, ttl 64, id 6919, offset 0, flags [DF], proto ICMP (1), length 84)
    10.0.0.1 > 10.0.0.2: ICMP echo request, id 49, seq 0, length 64
14:20:56.065255 aa:c1:ab:38:0e:5f > aa:c1:ab:94:f1:da, ethertype IPv4 (0x0800), length 98: (tos 0x0, ttl 64, id 58180, offset 0, flags [none], proto ICMP (1), length 84)
    10.0.0.2 > 10.0.0.1: ICMP echo reply, id 49, seq 0, length 64
```

The 4-byte difference (`102` vs. `98` bytes) is the 802.1Q tag. This is the
basic bridging contract: tag on trunk egress, strip on access egress.

### 3.5 VLAN isolation

Moving only `pc2`'s access port to VLAN 20 breaks the path:

```text
$ sw2(config)# port eth3 access vlan 20 end
ping across VLAN 10/20: correctly blocked
```

The script asserts that the ping fails; it does not merely print the result.
Moving `sw1`'s access port to VLAN 20 as well restores connectivity:

```text
$ sw1(config)# port eth3 access vlan 20 end

$ pc1# ping -c 3 10.0.0.2
64 bytes from 10.0.0.2: seq=0 ttl=64 time=0.177 ms
64 bytes from 10.0.0.2: seq=1 ttl=64 time=0.364 ms
64 bytes from 10.0.0.2: seq=2 ttl=64 time=0.659 ms
3 packets transmitted, 3 packets received, 0% packet loss
round-trip min/avg/max = 0.177/0.400/0.659 ms
```

Both ports were then returned to VLAN 10 for the MSTP phase.

### 3.6 Fail-open with STP disabled

`feature disable stp` on `sw1` stops the spanning-tree engine and, by design,
stops gating forwarding. `show bridge` says so explicitly:

```text
$ sw1(config)# feature disable stp
Feature 'stp' disabled.

$ sw1# show bridge
% spanning tree is disabled (enable it with 'feature enable stp')

$ pc1# ping -c 3 10.0.0.2
3 packets transmitted, 3 packets received, 0% packet loss
```

Only `sw1` was disabled; `sw2` still blocked one parallel link, so the lab did
not turn into a broadcast storm while proving the fail-open behaviour.

## 4. Enabling MSTP and building a region

### 4.1 Feature toggle

`feature enable mstp` changes the feature state and selects MSTP in one step:

```text
$ sw1(config)# feature enable mstp
Feature 'mstp' enabled.

$ sw1# show features
...
mstp                        enabled
...

$ sw1# show version
  Spanning tree: IEEE 802.1Q-2005 MSTP (CIST + 0 MSTIs)   VLANs: 3   Ports: 3
  Features: vlan, stp, mstp, trunking, mac-learning, telnet

$ sw1# show bridge summary
Switch is in IEEE 802.1Q-2005 Multiple Spanning Tree (MSTP) mode
Root bridge for: CIST
MST configuration: name '0200.0000.0001' revision 0
MST digest: AC36177F50283CD4B83821D8AB26DE62
1 spanning tree instance (1 CIST + 0 MSTIs)
```

At this point the region is still the default (name = system MAC, revision 0,
all VLANs on the CIST), so the digest is still the standard all-CIST value.
No MSTI exists yet: `CIST + 0 MSTIs`.

### 4.2 Region configuration and digest

Both switches were given the same name, revision and VLAN mapping, and
different priorities so that the CIST and the MSTIs elect different roots
(shown one command per line; the transcript records each block as a single
line):

```text
# sw1
bridge mst name MST-LAB
bridge mst revision 1
bridge mst max-hops 20
bridge mst instance 1 vlan 10
bridge mst instance 2 vlan 20
bridge priority 32768
bridge mst instance 1 priority 4096

# sw2
bridge mst name MST-LAB
bridge mst revision 1
bridge mst max-hops 20
bridge mst instance 1 vlan 10
bridge mst instance 2 vlan 20
bridge priority 4096
bridge mst instance 1 priority 8192
port eth1
 spanning-tree mst 1 cost 200000
```

The high MSTI 1 cost on `sw2 eth1` is what forces MSTI 1 to use the other
parallel link than the CIST. Both switches compute the same 16-octet digest:

```text
$ sw1# show bridge mst configuration
MST configuration
  Name:     MST-LAB
  Revision: 1
  Digest:   9357EBB7A8D74DD5FEF4F2BAB50531AA
  Max hops: 20

Instance  Vlans mapped
--------  -------------------------------------
0 (CIST)  1-9,11-19,21-4094
1         10  (priority 4096)
2         20  (priority 32768)

$ sw2# show bridge mst configuration
  Name:     MST-LAB
  Revision: 1
  Digest:   9357EBB7A8D74DD5FEF4F2BAB50531AA
...
1         10  (priority 8192)
2         20  (priority 32768)
```

The script parses the digest from both switches and fails the run unless they
are equal and match `^[0-9A-Fa-f]{32}$`. This is the operational test for
"same region": identical name, revision and VLAN→MSTID mapping produce the
same HMAC-MD5 digest; any difference would make the two bridges external to
each other, and the MSTIs would fall back to Master Ports.

The saved running configuration shows the whole region in persistent form:

```text
feature enable mstp
...
bridge priority 32768
bridge mst name MST-LAB
bridge mst revision 1
bridge mst instance 1 vlan 10
bridge mst instance 1 priority 4096
bridge mst instance 2 vlan 20
```

### 4.3 MSTI convergence and per-instance topology

The CIST converged in 32 s with `sw2` as root and `sw1 Gi0/2` blocked:

```text
[mstp-cist] converged: root=sw2, blocked=sw1 Gi0/2, transitional ports=0, +31s from phase start

--- sw1 mstp-cist ---
  Root ID    Priority    4096
             Address     0200.0000.0002
             Cost        20000
             Port        1 (Gi0/1)
...
Gi0/1               Root FWD 4         128.1 P2p
Gi0/2               Altn BLK 4         128.2 P2p
Gi0/3               Desg FWD 4         128.3 P2p

--- sw2 mstp-cist ---
  Root ID    Priority    4096
             Address     0200.0000.0002
             This bridge is the root
...
Gi0/1               Desg FWD 4         128.1 P2p
Gi0/2               Desg FWD 4         128.2 P2p
Gi0/3               Desg FWD 4         128.3 P2p
```

MSTI 1 converged in 32 s with `sw1` as regional root and `sw2 Gi0/1` blocked:

```text
[mstp-msti1] converged: root=sw1, blocked=sw2 Gi0/1, transitional ports=0, +32s from phase start

--- sw1 mstp-msti1 ---
IEEE 802.1Q-2005 MSTI 1
  Root ID    Priority    4097
             Address     0200.0000.0001
             This bridge is the root
...
Gi0/1               Desg FWD 20000     128.1 P2p
Gi0/2               Desg FWD 20000     128.2 P2p
Gi0/3               Desg FWD 20000     128.3 P2p

--- sw2 mstp-msti1 ---
  Root ID    Priority    4097
             Address     0200.0000.0001
             Cost        20000
             Port        2 (Gi0/2)
...
Gi0/1               Altn BLK 200000    128.1 P2p
Gi0/2               Root FWD 20000     128.2 P2p
Gi0/3               Desg FWD 20000     128.3 P2p
```

MSTI 2 converged in 32 s with `sw1` as regional root and `sw2 Gi0/2` blocked:

```text
[mstp-msti2] converged: root=sw1, blocked=sw2 Gi0/2, transitional ports=0, +32s from phase start

--- sw2 mstp-msti2 ---
  Root ID    Priority    32770
             Address     0200.0000.0001
             Cost        20000
             Port        1 (Gi0/1)
...
Gi0/1               Root FWD 20000     128.1 P2p
Gi0/2               Altn BLK 20000     128.2 P2p
Gi0/3               Desg FWD 20000     128.3 P2p
```

The three instances now use two different blocked ports on the same physical
topology:

| Instance | Root | Blocked port on `sw2` | VLANs |
|----------|------|------------------------|-------|
| CIST (0) | `sw2` | — (`sw1 Gi0/2` is blocked) | 1–9, 11–19, 21–4094 |
| MSTI 1 | `sw1` | `Gi0/1` | 10 |
| MSTI 2 | `sw1` | `Gi0/2` | 20 |

The bridge IDs show the extended system ID in the low 12 bits: the CIST root
is `1000.0200.0000.0002` (priority 4096), MSTI 1 is `1001.0200.0000.0001`
(priority 4096 + MSTID 1), and MSTI 2 is `8002.0200.0000.0001`
(priority 32768 + MSTID 2). `show bridge summary` summarises the split:

```text
$ sw1# show bridge summary
Switch is in IEEE 802.1Q-2005 Multiple Spanning Tree (MSTP) mode
Root bridge for: MSTI 1, MSTI 2
MST configuration: name 'MST-LAB' revision 1
MST digest: 9357EBB7A8D74DD5FEF4F2BAB50531AA
Extended system ID is enabled (CIST + 2 MSTIs)
...
3 spanning tree instances (1 CIST + 2 MSTIs)

$ sw2# show bridge summary
Root bridge for: CIST
MST configuration: name 'MST-LAB' revision 1
MST digest: 9357EBB7A8D74DD5FEF4F2BAB50531AA
3 spanning tree instances (1 CIST + 2 MSTIs)
```

### 4.4 Per-VLAN forwarding through different MSTIs

VLAN 10 is mapped to MSTI 1, whose active path is `sw1 Gi0/2` ↔ `sw2 Gi0/2`;
VLAN 20 is mapped to MSTI 2, whose active path is `sw1 Gi0/1` ↔ `sw2 Gi0/1`.
Both VLANs pass traffic:

```text
$ pc1# ping -c 3 10.0.0.2        # VLAN 10 / MSTI 1
3 packets transmitted, 3 packets received, 0% packet loss
round-trip min/avg/max = 0.214/0.335/0.485 ms

$ sw1(config)# port eth3 access vlan 20
$ sw2(config)# port eth3 access vlan 20

$ pc1# ping -c 3 10.0.0.2        # VLAN 20 / MSTI 2
3 packets transmitted, 3 packets received, 0% packet loss
round-trip min/avg/max = 0.229/0.426/0.612 ms
```

This is the load-sharing property MSTP exists to provide: the same two links
carry different VLANs in opposite directions, while the CIST still provides a
loop-free default for every other VLAN.

### 4.5 MST BPDU on the wire

The capture on `pc1 eth1` (the access port, where `sw1` transmits its BPDUs as
the designated bridge) shows an IEEE 802.1Q-2005 MST BPDU:

```text
14:21:52.067344 02:00:00:00:00:01 > 01:80:c2:00:00:00, 802.3, length 137:
    LLC, dsap STP (0x42) Individual, ssap STP (0x42) Command, ctrl 0x03:
    STP 802.1s, Rapid STP, CIST Flags [Topology change, Learn, Forward], length 134
    port-role Designated, CIST root-id 1000.02:00:00:00:00:02, CIST ext-pathcost 0
    CIST regional-root-id 1000.02:00:00:00:00:02, CIST port-id 8003,
    message-age 0.00s, max-age 20.00s, hello-time 2.00s, forwarding-delay 15.00s
    v3len 96, MCID Name MST-LAB, rev 1,
        digest 9357ebb7a8d74dd5fef4f2bab50531aa, CIST int-root-pathcost 20000,
    CIST bridge-id 8000.02:00:00:00:00:01, CIST remaining-hops 19
    MSTI 1, Flags [Topology change, Learn, Forward], port-role Designated
        MSTI regional-root-id 1001.02:00:00:00:00:01, pathcost 0
        MSTI bridge-prio 1, port-prio 8, hops 20
    MSTI 2, Flags [Topology change, Learn, Forward], port-role Designated
        MSTI regional-root-id 8002.02:00:00:00:00:01, pathcost 0
        MSTI bridge-prio 8, port-prio 8, hops 20
```

The decode confirms every field the implementation claims:

* destination `01:80:c2:00:00:00`, LLC `42 42 03`, no SNAP;
* protocol version 3 (`STP 802.1s`), type `0x02` (RST/MST), length `134`;
* Version 3 Length `96` = `64 + 16 × 2` MSTI records, exactly the two MSTIs;
* MCID name `MST-LAB`, revision `1`, digest
  `9357ebb7a8d74dd5fef4f2bab50531aa`, matching the CLI;
* CIST root `1000.02:00:00:00:00:02`, regional root the same, internal root
  path cost `20000`, remaining hops `19`;
* MSTI 1 regional root `1001.02:00:00:00:00:01` and MSTI 2 regional root
  `8002.02:00:00:00:00:01`, each with its own bridge priority in the low 12
  bits.

The base BPDU is 102 octets and each MSTI record adds 16, so the 134-octet
BPDU in the capture is `102 + 2 × 16`. The 802.3 length `137` adds the 3-octet
LLC header. This is the wire-level proof that the switch is speaking MSTP, not
RSTP-with-extra-fields and not PVST+.

### 4.6 Native VLAN 10 is untagged

Setting native VLAN 10 on the active trunk (`sw1 eth2` / `sw2 eth2`) changes
the egress encapsulation for that VLAN:

```text
$ sw1(config)# port eth2 native vlan 10
$ sw2(config)# port eth2 native vlan 10

$ (sw1 netns) tcpdump -i eth2 -e -nn -vv -c 2 ... icmp
14:22:02.162182 aa:c1:ab:94:f1:da > aa:c1:ab:38:0e:5f, ethertype IPv4 (0x0800), length 98: (tos 0x0, ttl 64, id 28378, offset 0, flags [DF], proto ICMP (1), length 84)
    10.0.0.1 > 10.0.0.2: ICMP echo request, id 194, seq 0, length 64
14:22:02.162238 aa:c1:ab:38:0e:5f > aa:c1:ab:94:f1:da, ethertype IPv4 (0x0800), length 98: (tos 0x0, ttl 64, id 25788, offset 0, flags [none], proto ICMP (1), length 84)
    10.0.0.2 > 10.0.0.1: ICMP echo reply, id 194, seq 0, length 64
```

The frame is 98 bytes, not 102, and has no `0x8100` tag: VLAN 10 is now the
native VLAN and is sent untagged. The configuration was reverted to native
VLAN 1 afterwards. The important part is that this did not disturb the MSTP
topology: native VLAN is an egress-encapsulation property, not a tree.

### 4.7 No PVST+ frames

The script captured for 8 seconds on `sw1 eth1` with the PVST+ destination
filter `ether dst 01:00:0c:cc:cc:cd`, while pinging across the lab:

```text
PVST+ frames on the wire: 0
```

The run fails if the count is non-zero. This is the negative control for the
claim that MSTP replaced per-VLAN PVST+: the switch never emits Cisco's PVST+
BPDUs, and its BPDUs are addressed to the IEEE nearest-bridge MAC.

## 5. Compatibility modes: STP and CST

MSTP can be turned off without discarding the region. `spanning-tree mode stp`
on both switches returns to classic IEEE 802.1D behaviour:

```text
$ sw1(config)# spanning-tree mode stp
Spanning tree mode is IEEE 802.1D STP.

$ sw1# show bridge summary
Switch is in IEEE 802.1D Spanning Tree Protocol (STP) mode
Root bridge for: CIST
MSTP feature is disabled; running one STP tree for all VLANs
1 spanning tree instance (1 CIST + 0 MSTIs)
```

`spanning-tree mode cst` selects the 802.1Q common spanning tree:

```text
$ sw1(config)# spanning-tree mode cst
Spanning tree mode is IEEE 802.1Q common spanning tree (CST).

$ sw1# show bridge summary
Switch is in IEEE 802.1Q common spanning tree (CST) mode
Root bridge for: CIST
MSTP feature is disabled; running one CST tree for all VLANs
1 spanning tree instance (1 CIST + 0 MSTIs)
```

Both modes converged to the same topology, with `sw2` as root and `sw1 Gi0/2`
blocked, in 31 s:

```text
[stp-mode] converged: root=sw2, blocked=sw1 Gi0/2, transitional ports=0, +32s from phase start
[cst-mode] converged: root=sw2, blocked=sw1 Gi0/2, transitional ports=0, +31s from phase start
```

The captures are classic IEEE 802.1D ST Configuration BPDUs in both cases:

```text
14:22:43.732317 02:00:00:00:00:01 > 01:80:c2:00:00:00, 802.3, length 38: LLC, dsap STP (0x42) Individual, ssap STP (0x42) Command, ctrl 0x03: STP 802.1d, Config, Flags [Topology change], bridge-id 8000.02:00:00:00:00:01.8003, length 35
    message-age 0.00s, max-age 20.00s, hello-time 2.00s, forwarding-delay 15.00s
    root-id 1000.02:00:00:00:00:02, root-pathcost 4
```

This is intentional and documented: on this switch STP and CST are
**behaviourally identical** — one tree for every VLAN, classic ST BPDUs — and
differ only in the protocol name printed by `show`. The CST is the 802.1Q
application of STP to a VLAN bridge, so the identical wire format is the
expected result, not a shortcut.

Re-enabling the feature restores the stored region without re-entering it:

```text
$ sw1(config)# feature enable mstp
Feature 'mstp' enabled.

$ sw1# show bridge mst configuration
  Name:     MST-LAB
  Revision: 1
  Digest:   9357EBB7A8D74DD5FEF4F2BAB50531AA
```

The CIST and both MSTIs then converged again with the same roots and blocked
ports (31 s, 31 s and 32 s), proving that the mode changes did not lose the
region or the per-instance parameters.

## 6. LLDP

LLDP is off by default, and the CLI says how to enable it:

```text
$ sw1# show lldp
LLDP is disabled.
Enable it with 'feature enable lldp'.

$ sw1# show lldp neighbors
LLDP is disabled.
Enable it with 'feature enable lldp'.
```

After `feature enable lldp` on both switches, the immediate fast-start burst
was captured on `pc1 eth1`:

```text
14:23:49.665780 02:00:00:00:00:01 > 01:80:c2:00:00:0e, ethertype LLDP (0x88cc), length 67: LLDP, length 53
    Chassis ID TLV (1), length 7
      Subtype MAC address (4): 02:00:00:00:00:01
    Port ID TLV (2), length 5
      Subtype Interface Name (5): eth3
    Time to Live TLV (3), length 2: TTL 120s
    System Name TLV (5), length 3: sw1
    System Description TLV (6), length 18
      SWITCH-1.0 (0.1.0)
    System Capabilities TLV (7), length 4
      System  Capabilities [Bridge] (0x0004)
      Enabled Capabilities [Bridge] (0x0004)
    End TLV (0), length 0
```

The destination is the IEEE 802.1AB nearest-bridge multicast
`01:80:c2:00:00:0e`; the chassis ID is the system MAC, the port ID is the Linux
interface name, and the TTL is 120 s (30 s interval × hold multiplier 4). The
mandatory TLVs and the optional system TLVs are all present in the expected
order.

Both switches learned each other on both parallel links:

```text
$ sw1# show lldp neighbors
Local Port    Chassis ID           Port ID              Hold  Capabilities    System Name
----------    ----------           -------              ----  ------------    -----------
Gi0/1         0200.0000.0002       eth1                 120   bridge          sw2
Gi0/2         0200.0000.0002       eth2                 120   bridge          sw2

$ sw1# show lldp neighbors detail
Local port: Gi0/1
  Chassis ID: 0200.0000.0002 (MAC address)
  Port ID: eth1 (interface name)
  TTL: 120 seconds
  System name: sw2
  System description: SWITCH-1.0 (0.1.0)
  Capabilities: bridge
  Enabled capabilities: bridge
  Management address: none
  Last update: 0s ago
...
```

The per-port counters show the fast-start burst and the steady state:

```text
$ sw1# show lldp interfaces
Port                  Tx         Rx   Errors  Ageouts  Neighbor
----------      --------   --------   ------  -------  --------
Gi0/1                  5          5        0        0  sw2 (eth1)
Gi0/2                  5          5        0        0  sw2 (eth2)
Gi0/3                  5          0        0        0  -

$ sw1# show lldp traffic
LLDP traffic:
  Transmit frames: 15
  Receive frames: 10
  Receive errors: 0
  Ageouts: 0
  Neighbors: 2
```

`Gi0/3` is the host-facing port: it transmits but receives no LLDP, which is
why it has no neighbour. The script fails the run unless `show lldp neighbors`
contains `sw2`.

## 7. TCP console

The lab daemon is started with `--tcp 2200`, so the telnet feature is enabled
at boot and a TCP login succeeds:

```text
$ docker exec clab-stp-lab-sw1 /switch cli --host 127.0.0.1 --port 2200 -c "show version"
SWITCH-1.0 (0.1.0)
  Hostname: sw1
  ...
  Features: vlan, stp, mstp, trunking, mac-learning, lldp, telnet
```

Disabling the feature closes the console to new logins without stopping the
listener:

```text
$ sw1(config)# feature disable telnet
Feature 'telnet' disabled.

$ docker exec clab-stp-lab-sw1 /switch cli --host 127.0.0.1 --port 2200 -c "show version"
% TCP console disabled (enable with 'feature telnet')
```

The local Unix-socket CLI still works while the TCP console is blocked:

```text
$ sw1# show version
  Features: vlan, stp, mstp, trunking, mac-learning, lldp
```

Re-enabling restores the login. The script asserts all three outcomes: a
successful login, the exact refusal string, and a successful login after
re-enabling.

## 8. Rejected protocols

Every protocol that this switch deliberately does not implement is rejected
with a specific message. This is part of the evidence because "not
implemented" is only safe when the configuration cannot silently succeed.

| Command | Output |
|---------|--------|
| `feature enable pvst` | `% PVST+ has been removed; use IEEE 802.1Q-2005 MSTP (spanning-tree mode mstp)` |
| `spanning-tree mode pvst` | `% PVST+ has been removed; use MSTP (IEEE 802.1Q-2005) or the CIST compatibility mode` |
| `spanning-tree mode rstp` | `% RSTP is not selectable on its own; use 'spanning-tree mode mstp'` |
| `feature enable dtp` | `% unknown feature 'dtp' (known: vlan, stp, mstp, trunking, mac-learning, portfast, bpdu-guard, lldp, telnet)` |
| `feature enable vtp` | `% unknown feature 'vtp' (...)` |
| `feature enable cdp` | `% unknown feature 'cdp' (...)` |
| `feature enable lacp` | `% unknown feature 'lacp' (...)` |
| `feature enable gvrp` | `% unknown feature 'gvrp' (...)` |
| `feature enable mvrp` | `% unknown feature 'mvrp' (...)` |
| `feature enable spb` | `% unknown feature 'spb' (...)` |
| `feature enable pbb` | `% unknown feature 'pbb' (...)` |
| `feature enable evb` | `% unknown feature 'evb' (...)` |
| `feature enable snmp` | `% unknown feature 'snmp' (...)` |

The parenthesised list is identical in every `unknown feature` message:
`vlan, stp, mstp, trunking, mac-learning, portfast, bpdu-guard, lldp, telnet`.
It is abbreviated as `(...)` in the table above.

Two of these deserve a note:

* **RSTP is not a mode of its own.** MSTP BPDUs are RSTP-format BPDUs
  (version 3, type `0x02`) with the MST payload; selecting `rstp` alone would
  produce a protocol the rest of the implementation does not model. The
  message points at the supported path.
* **DTP, VTP, CDP and LACP are absent, not disabled.** Their feature names do
  not exist, so there is no hidden state to persist. Trunks are static and
  link aggregation is out of scope, as documented in the README.

## 9. Persistence across a daemon reload

The last section saves the running configuration and verifies that a fresh
daemon process reloads exactly what was saved. The saved file starts with the
feature block and the region:

```text
$ sw1# save
Building configuration...
[OK]

$ sw1# show startup-config
Startup configuration:
!
version 1.0
device name sw1
!
feature enable vlan
feature enable stp
feature enable mstp
...
bridge mst name MST-LAB
bridge mst revision 1
bridge mst instance 1 vlan 10
bridge mst instance 1 priority 4096
bridge mst instance 2 vlan 20
!
end
```

The script asserts that the file contains `feature enable mstp` and
`bridge mst name MST-LAB`, then hashes the configuration body (the CLI adds a
single trailing blank line, which is trimmed before hashing).

### Why the reload is not a `docker restart`

An early version of this test restarted the container. That is not usable with
this lab: containerlab attaches the topology veths from outside the container,
so a container restart recreates the network namespace and the switch's
`eth1`–`eth3` disappear. Inspecting the restarted node showed only the
management interface:

```text
$ nsenter -t <sw1-pid> -n ip -br link
lo               UNKNOWN        00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP>
eth0@if497       UP             02:23:5c:b3:8e:8c <BROADCAST,MULTICAST,UP,LOWER_UP>
```

The daemon had loaded the configuration, but with no dataplane ports LLDP and
STP could not run, and the post-restart `show bridge summary` was an isolated
bridge that considered itself root for every instance. That would have been
misleading evidence.

The script therefore starts a **second daemon process in the same container**
with the saved file:

```text
$ docker exec -d clab-stp-lab-sw1 /switch daemon --no-dataplane --config /etc/switch/startup-config --socket /tmp/restore-evidence.sock
```

This is the same boot-time code path that a real restart takes
(`load_config` on `/etc/switch/startup-config`), without disturbing the lab's
veths. `--no-dataplane` is required only because the second process must not
open a second set of AF_PACKET sockets.

### Reloaded protocol state

The fresh daemon reports the persisted feature state and the MST region:

```text
$ restored# show features
Feature                     State
--------------------------- -------
vlan                        enabled
stp                         enabled
mstp                        enabled
trunking                    enabled
mac-learning                enabled
portfast                    disabled
bpdu-guard                  disabled
lldp                        enabled
telnet                      enabled

$ restored# show version
SWITCH-1.0 (0.1.0)
  Educational layer-2 switch (Rust)
  Hostname: sw1
  System MAC: 0200.0000.0001
  Serial: SW020000000001
  Uptime: 0 weeks, 0 days, 0 hours, 0 minutes
  Spanning tree: IEEE 802.1Q-2005 MSTP (CIST + 2 MSTIs)   VLANs: 3   Ports: 3
  Features: vlan, stp, mstp, trunking, mac-learning, lldp, telnet

$ restored# show bridge summary
Switch is in IEEE 802.1Q-2005 Multiple Spanning Tree (MSTP) mode
Root bridge for: CIST, MSTI 1, MSTI 2
MST configuration: name 'MST-LAB' revision 1
MST digest: 9357EBB7A8D74DD5FEF4F2BAB50531AA
Extended system ID is enabled (CIST + 2 MSTIs)
EtherChannel misconfig guard is disabled
Portfast Default is disabled
BPDU Guard is disabled
3 spanning tree instances (1 CIST + 2 MSTIs)

$ restored# show bridge mst configuration
MST configuration
  Name:     MST-LAB
  Revision: 1
  Digest:   9357EBB7A8D74DD5FEF4F2BAB50531AA
  Max hops: 20

Instance  Vlans mapped
--------  -------------------------------------
0 (CIST)  1-9,11-19,21-4094
1         10  (priority 4096)
2         20  (priority 32768)
```

The isolated daemon has no peers, so it considers itself root for every
instance; the point of this section is the persisted feature state, region
identity, VLAN mapping and per-instance priority, all of which match the live
switch.

The saved startup-config and the reloaded running-config are compared after
normalising the trailing newline:

```text
saved startup-config sha256:     2bbd97369d6279f02655308dbccc397650219d14ff1eb5f9ec2b89e7e921c8d9
restored running-config sha256:  2bbd97369d6279f02655308dbccc397650219d14ff1eb5f9ec2b89e7e921c8d9
saved startup-config and restored running-config are identical (trailing blank line trimmed)
```

This closes the loop on the feature gate: `feature enable mstp` is not only a
runtime flag, it is part of the persisted configuration and is replayed by
`load_config`. A switch that came back with `mstp` disabled would have failed
this check.

## 10. Observations and boundaries

* **MSTP is opt-in.** A fresh switch is a classic IEEE 802.1D bridge. Nothing
  in this run depends on MSTP being on by default; the pre-enable error is
  asserted, not merely observed.
* **The region is identified by data, not by a name alone.** The two switches
  agree because name, revision and VLAN mapping agree; the digest
  `9357EBB7A8D74DD5FEF4F2BAB50531AA` is computed independently on each side
  and compared by the script.
* **The CIST and the MSTIs are genuinely independent.** Three instances, two
  different blocked ports, and per-VLAN forwarding through different links.
* **MSTP BPDUs are untagged and addressed to `01:80:c2:00:00:00`.** The
  capture shows version 3, the MCID, the CIST vector and two MSTI records.
  There are no PVST+ frames.
* **STP and CST are compatibility names for the same behaviour** on this
  switch: one tree, classic ST BPDUs. This is stated in the README and
  demonstrated by identical captures.
* **LLDP is link-local and independent of STP.** It is received and
  transmitted regardless of port state, uses the nearest-bridge multicast
  address, and its neighbours are runtime state.
* **The TCP console is feature-gated.** Disabling `telnet` refuses new TCP
  logins while the Unix socket and the local CLI keep working.
* **The lab is destroyed at the end of the run.** `KEEP=1` leaves it up for
  inspection; the transcript and captures remain under
  `/tmp/opencode/evidence-*`.

## 11. Reproduction checklist

1. Build the image: `docker build -t switch:latest .`
2. Run the evidence script as root:
   `sudo ./tests/containerlab-evidence.sh`
3. Confirm the last line is `=== evidence run complete ===` and that the
   script exits 0.
4. Compare the transcript with this document; convergence times may vary by a
   second or two, but roots, blocked ports, digests and frame decodes must
   match.
5. For a focused regression run, `make lab-test` runs
   [`tests/containerlab-8021q.sh`](tests/containerlab-8021q.sh), which covers
   the MSTP/802.1Q subset.

The unit-test suite complements this evidence:

```text
cargo test
test result: ok. 70 passed; 0 failed
```

Those tests cover the packet codec, the MST configuration digest vectors, the
per-instance election, the feature gate and the state-machine regression that
this evidence run exercised in the lab.
