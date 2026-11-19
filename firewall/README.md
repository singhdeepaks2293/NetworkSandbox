# firewall

A lightweight, original next-generation firewall written in Rust for
learning how products like FortiGate and PAN-OS work inside. It runs as a
userspace forwarding engine over AF_PACKET sockets, with a CLI in three
styles (native, FortiOS-style and PAN-OS-style), a REST API and a web GUI,
all editing one configuration model.

This is an educational project. It is not affiliated with, derived from,
endorsed by, or a compatible replacement for any Fortinet or Palo Alto
Networks product. The vendor-style CLIs reproduce each product's command
*style* for teaching and cover a subset of commands.

## Features

Next-generation features:

- **App-ID.** Applications are identified from payload, not port: about 50
  built in, including SSL, HTTP, SSH, DNS, QUIC, SMB, RDP, SIP, BitTorrent,
  WireGuard, databases and mail, plus SaaS apps (YouTube, Facebook, GitHub,
  Microsoft 365, Slack, ChatGPT, Claude...) from the HTTP `Host` or TLS SNI.
  Server-first protocols (SMTP, FTP, POP3, IMAP, MySQL) are identified from
  the reply. Each app has a category, subcategory, risk and parent.
- **Two-stage policy evaluation.** A TCP flow matches its rule provisionally
  while the handshake completes; once App-ID has a verdict the rulebase runs
  again, and a deny cuts the flow off. Unidentified flows become
  `unknown-tcp` / `unknown-udp` after four payload packets.
- **Stream reassembly for App-ID.** Up to 4 KB per direction is reassembled
  in TCP sequence order while a flow is pending, so a ClientHello or HTTP
  request split across segments is classified from the whole message (a
  split hello is `github`, not plain `ssl`). Retransmitted bytes are trimmed.
- **User-ID.** IP-to-user mappings, static in the config or pushed at runtime
  by an identity source through the REST API or CLI (with timeouts); user
  groups (nested); policies match users, groups, `known-user` or `unknown`.
- **Default rules.** `intrazone-default` and `interzone-default` per VDOM, and
  per-zone intrazone overrides (FortiOS `set intrazone allow`). They show in
  policy listings and lookups, count hits and are logged by name.
- **High availability.** Active/passive pairs with signed heartbeats,
  priority election (optional preemption, split-brain resolution), config
  and session synchronization, gratuitous ARP on failover and manual
  suspend/resume.
- **WireGuard VPN.** The protocol implemented in Rust (Noise_IKpsk2,
  ChaCha20-Poly1305, BLAKE2s, replay window, rekey and keepalive timers),
  interoperability-tested against boringtun. Tunnels are interfaces in a
  zone, so policies, NAT, App-ID and User-ID apply to VPN traffic; peers'
  allowed IPs route into the tunnel and are enforced on decryption.
- **IPv6 (dual stack).** IPv6 interface addresses and routes, IPv6 entries
  in address objects and policies, Neighbor Discovery, ICMPv6, and the same
  policy engine, zones, default rules, App-ID and profiles as IPv4.
- **`application-default`.** A rule can require each app's standard ports, so
  SSL on 8443 or HTTP on 443 does not match.
- **List policies.** Every match field is a list, as on FortiOS and PAN-OS:
  zones, addresses (with negation), services and applications. Applications
  can be named directly, through application groups, or as
  `category:<name>`.
- **Security profiles** (URL filter, IPS, antivirus) per policy or through a
  reusable profile group.
- **NAT rulebases.** Per-policy NAT (FortiOS style), a separate source-NAT
  rulebase (PAN-OS NAT rules, FortiOS central SNAT) and destination NAT.
- **FortiOS-style and PAN-OS-style CLIs**, including their policy lookup
  tools (`diagnose firewall iprope lookup`, `test security-policy-match`).

Firewall foundation:

- VDOM-style virtual firewalls (PAN-OS vsys in the PAN-OS-style CLI).
- Stateful TCP/UDP/ICMP inspection with a TCP state machine; only a clean SYN
  opens a flow; return traffic is inspected with the same profiles.
- Static routes with longest-prefix match and administrative distance.
- Address objects and groups, service objects with port ranges, service groups.
- URL filtering by HTTP `Host` or TLS SNI with categories, allow and block lists.
- IPS and antivirus profiles using literal patterns.
- Per-policy traffic shaping, per-zone SYN/ICMP/UDP flood limits, session
  table limits, per-source rate limiting.
- Ingress sanity drops (fragments, martians, LAND, bad TCP flags), ICMP Time
  Exceeded and Unreachable, `reject` actions (TCP RST / ICMP unreachable).
- Candidate/running configuration with diff, commit, rollback and audit;
  zone membership, policies, routes, objects, NAT and profiles apply live.
- Text or JSON flow logs, per-policy hit counters, an opt-in nftables backend.

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
`system max-inspection`, `system source-rate`, `system source-burst`,
`system kernel-forwarding refuse|warn` and `system cli-remote-plaintext on|off`.

### Fail-closed startup and truthful health

The userspace engine receives *copies* of frames through AF_PACKET; it cannot
stop the kernel from routing the originals. If kernel forwarding is on, traffic
would reach its destination unfiltered alongside the firewall. So before
starting the dataplane the daemon checks `net.ipv4.ip_forward`,
`net.ipv6.conf.all.forwarding` and the per-interface `forwarding` switches of
every configured interface, and **refuses to start** if any is on:

```sh
sudo sysctl -w net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0
```

`system kernel-forwarding warn` starts anyway and reports the firewall as
degraded. A monitor re-checks every 5 seconds and logs changes.

`GET /healthz` (also `/api/v1/health`) returns `200 {"status":"ok","dataplane":"enforcing"}`
only when the packet loop is running, every configured interface is attached
and kernel forwarding is off. Otherwise it returns **503**
`{"status":"degraded"}`; authenticated callers also get the list of problems.
`dataplane` is `off` for `--dry-run`/`--no-dataplane`. The system API
(`/api/v1/system`) carries the same information under `enforcement`.

The CLI transport is plaintext and carries credentials, so the daemon refuses
a non-loopback `system cli-bind` unless `system cli-remote-plaintext on`.

### Configuration commits

Every write path (GUI/REST candidate commit, native CLI `policy add|delete`,
FortiOS- and PAN-OS-style commits, rollback, restore) goes through one
serialized commit: validate, save to disk, activate, record history, bump the
revision. Commits are refused when they are based on an outdated revision, so
two administrators cannot silently overwrite each other:

- `GET /api/config` returns `X-Config-Revision`; a client that sends it back
  as `X-Config-Base` when staging gets **409 Conflict** if another commit
  landed in between. Committing a candidate staged before another commit is
  also refused with 409.
- A FortiOS-style `edit` block or a PAN-OS-style candidate started before
  another commit is refused on `next`/`end`/`commit`; `abort` (FortiOS) or
  `revert` (PAN-OS) starts again from the running configuration.

After a commit, each open session is re-checked on its next packet against
the new rulebase (same zones, translated destination, application and user as
its first lookup). It survives only if the same policy still matches and
permits it, so narrowing a permit or inserting a deny above it cuts flows that
are already open.
For a lost password run `firewall password-reset-token --config PATH
--username NAME`, then POST the token and a new password to
`/api/v1/auth/password-reset`.

## Web GUI

Open `https://<gui-bind>:<gui-port>/` (loopback by default) and sign in with
an administrator account. The GUI configures everything the CLI does for
day-to-day operation, in the way commercial firewalls work:

- **Candidate configuration.** Every form edit goes into a candidate; the top
  bar shows `Commit (N)`. *Commit* shows the diff first, then applies it
  through the same pipeline as the CLI (in kernel mode the kernel ruleset is
  installed and verified before the commit succeeds). *Discard* drops the
  candidate; System → Configuration also offers rollback, backup download,
  restore and an advanced raw editor.
- **Pages:** Dashboard (health, enforcement, traffic, interfaces); Network
  (interface zones, static IPv4/IPv6 routes); Policy & Objects (security
  policies with reorder, enable/disable and hit counts, default rules, source
  and destination NAT, addresses and groups, services and groups, custom
  applications and application groups); Security Profiles (URL filters, IPS
  and payload signatures, profile groups, shapers, zone flood protection);
  User & Authentication (User-ID mappings, user groups and maps,
  administrators and API tokens, password change); Monitor (sessions, traffic
  log, policy hit counts); System (settings, HA suspend/resume, VPN view,
  configuration, audit log); Tools (policy match test).
- **One parser.** Forms send structured edits (`POST /api/v1/configuration/edit`,
  one object per edit); the server applies them to the canonical text and
  re-parses it with the CLI's parser, so the GUI cannot produce a configuration
  the CLI would reject. Edits based on an outdated revision get 409.
- **Security.** Separate same-origin JS/CSS under a strict CSP (`script-src
  'self'`, no inline code); all values rendered as text, never HTML; CSRF
  token on every write; read-only roles (`security_analyst`, `auditor`) see no
  edit controls and are refused by the server.
- **Not editable in the GUI:** adding or removing interfaces (needs a restart),
  WireGuard keys and HA settings (CLI or raw editor).

UI tests: `node tests/ui-model.test.js` (no dependencies) checks that every
object kind round-trips byte-for-byte through the forms' model;
`tests/ui-e2e.js` drives the real UI in jsdom against a running daemon (see
the file header).

## Kernel nftables dataplane (opt-in)

The userspace AF_PACKET engine is the default dataplane (mode A). With
`system dataplane kernel` (mode B) the daemon enforces in the kernel instead:

```text
system dataplane kernel
```

```sh
sudo sysctl -w net.ipv4.ip_forward=1     # the kernel forwards in this mode
sudo ./target/release/firewall daemon --config firewall.conf
sudo nft list table inet vela            # rules carry comment "vela:<generation>:<n>"
```

- **One enforcement path.** In kernel mode the AF_PACKET engine does not
  forward; the kernel-forwarding refusal of mode A does not apply. The mode is
  fixed at startup (changing `system dataplane` needs a restart).
- **Exact or refused.** The kernel plan never weakens a policy. A
  configuration is refused, with the reasons, when it contains anything the
  kernel cannot enforce exactly: App-ID, address negation, user-scoped rules,
  permits with URL/IPS/AV/shaper/profile-group inspection, IPv6 parts or
  unrepresentable services in a deny (dropping them would widen access), zone
  flood protection, `source-rate`, HA or WireGuard. Use mode A for those.
- **Startup.** The running configuration is installed atomically, read back
  over netlink and verified before the daemon reports healthy. If that fails,
  the table is replaced by a drop-all forward chain (lockdown) and the daemon
  exits with the error.
- **Every commit** (GUI, REST, every CLI style, rollback, restore) goes
  kernel first: install, verify; if that fails the previous ruleset is
  reinstalled and verified and the commit is refused; if that fails too,
  forwarding is locked down and the firewall reports degraded. Only after the
  kernel accepted the change is it saved to disk and activated.
- **Verification** compares chains, hooks, chain policies and every rule's
  tag in order, so a missing, foreign, reordered or replaced rule is detected.
- **Drift.** Every 5 seconds the monitor re-verifies the table. On an
  external change it reinstalls the running configuration (logged as `kernel
  dataplane drift detected ...`), or locks down if that fails.
- **Health.** `/healthz` reports `"dataplane":"kernel"` only while the
  installed ruleset is verified and `net.ipv4.ip_forward` is 1; otherwise 503
  `degraded`.
- **Shutdown.** The table is left in place when the daemon exits or crashes,
  so the last verified ruleset keeps being enforced. `firewall nft-remove`
  deletes it.
- **Ownership** is limited to `inet vela`; no other table is flushed or
  modified. IPv6 address matching is not translated (see the exactness rule).

`firewall nft-apply --config PATH` still installs a ruleset once, for
diagnostics, and applies the same exactness rule. It refuses to run while a
daemon using the same configuration holds `<config>.lock`.

## Configuration

See `examples/ngfw-appid.conf` for App-ID, list policies, groups and NAT
rulebases, `examples/ngfw.conf` for the classic policy set and
`examples/ngfw-vdoms.conf` for two isolated tenants. The language is line
oriented; `#` starts a comment. A `vdom <n>` line starts a partition;
everything after it applies to that VDOM until the next `vdom` line.

```text
interface port1 zone untrust address 203.0.113.2/24
interface port2 zone trust address 10.0.0.1/24
route default port1 via 203.0.113.1
route 172.16.0.0/12 port3 via 10.1.0.254 distance 20 name lab

address quarantine 10.0.0.66
service web tcp 80,443,8000-8080
service-group basics web dns
app-group social facebook instagram category:social-networking
profile-group default url corp ips edge av av

#      id  src-zones dst-zones [!]src,...  dst,... proto port|@svc,...|application-default action [options]
policy 10  trust     untrust   any         any     tcp   application-default deny app social
policy 20  trust,dmz untrust   !@quarantine any    any   @basics             permit group default name out
snat   10  trust     untrust   10.0.0.0/24 any     masquerade name lan-out
dnat   1   tcp 203.0.113.2/32 443 10.1.0.10 443 name web-vip
```

User-ID and default rules:

```text
user-group admins alice corp\\bob
user-group staff admins carol
user-map 10.0.5.0/24 kiosk
policy 50 trust untrust any any tcp 22 permit user admins
policy 60 trust untrust any any any any permit user known-user
default-rule intrazone allow log            # PAN-OS default
default-rule intrazone deny zone guest      # per-zone override
default-rule interzone deny
```

Without `default-rule` lines both default rules deny, as in earlier
versions, so upgrading never opens traffic. PAN-OS itself ships with
intrazone allowed; add `default-rule intrazone allow` for that behaviour.

Policies are evaluated in ascending id order within the ingress VDOM. Zone
lists accept `any`. Policy options: `nat`, `nolog`, `disable`, `name <n>`,
`app <a,b,...>`, `user <u,g,...>`, `url <f>`, `ips <p>`, `av <p>`, `shaper <s>`, `group <g>`.
A policy's own `nat` wins; otherwise the first matching `snat` rule applies;
DNAT-ed flows are not source-NATed. Address, service, application, profile
and shaper objects are shared by every VDOM.

## App-ID

`show applications [filter]` (or `get application list` / `show applications`
in the vendor styles) lists the catalog. While a TCP flow's application is
unknown, permit rules that name applications match provisionally and deny
rules that name applications are skipped (a rule cannot deny an app it has not
seen yet). When the first payload is classified the rulebase is evaluated
again with the application; a resulting deny drops the packet, logs
`app <name>: policy <id> deny` and removes the session, and a reject also
sends a TCP RST. Custom `app-def` applications are identified by port.
`show sessions` shows each flow's application.

## High availability

Two units with the same interfaces form an active/passive pair over a
dedicated HA link (an address the OS owns, not a dataplane interface). See
`examples/ha-a.conf` and `examples/ha-b.conf`.

```text
ha mode active-passive
ha priority 200                 # the higher (priority, node id) is active
ha bind 192.0.2.1:7600          # this unit's HA address
ha peer 192.0.2.2:7600
ha secret <at least 16 characters>
ha preempt off                  # on: a higher-priority unit takes over when it joins
ha hello 200                    # ms between heartbeats
ha dead 1000                    # ms of silence before the peer is down
```

- Heartbeats are HMAC-SHA256 signed with per-node sequence numbers, so a
  forged or replayed datagram is ignored.
- The passive unit forwards nothing and answers no ARP. The unit that becomes
  active sends gratuitous ARP for every interface address.
- The active unit pushes its configuration whenever the peer's differs.
  Hostname, `ha` settings and management binds/certificates stay node-local.
- The active unit pushes its session table every second (up to
  `ha max-sync-sessions`, default 20000), so established TCP flows, NAT
  translations, App-ID labels and users survive a failover.
- If both units are active (the HA link failed), the lower-ranked one steps
  down when the link returns.
- `show ha`, `ha suspend` / `ha resume` (native); `get system ha status`,
  `execute ha failover set 1` / `unset 1` (FortiOS style);
  `show high-availability state`, `request high-availability state
  suspend|functional` (PAN-OS style).

HA settings are read at start-up; restart the daemon after changing them.
Session sync sends the full table each second, which suits labs, not large
production tables.

## IPv6

```text
interface eth1 zone trust address 10.0.0.1/24 address6 2001:db8:1::1/64
route6 default eth2 via 2001:db8:ffff::1
route6 2001:db8:50::/48 eth1 via 2001:db8:1::fe distance 5
address web-servers 10.1.0.10 2001:db8:10::10      # one object, both families
policy 30 untrust trust any @web-servers tcp 443 permit
policy 40 trust untrust 2001:db8:1::/64 any any any permit
```

- An address list decides which family a rule matches: IPv4 prefixes match
  only IPv4, IPv6 prefixes only IPv6, and `any` both. Named objects can hold
  both. Zones, services, applications, users, profiles and default rules
  apply to both families. See `examples/dual-stack.conf`.
- Neighbor Discovery: Neighbor Solicitations for our addresses get a Neighbor
  Advertisement; neighbors are learned from NS/NA options; a cache miss sends
  an NS to the solicited-node group. NDP messages must have hop limit 255.
- Each interface also has a link-local address derived from its MAC (EUI-64).
- ICMPv6 echo to our addresses is answered. Time Exceeded, Destination
  Unreachable (no route; administratively prohibited for `reject`) and TCP RST
  are sent as for IPv4. Extension headers are walked; fragments are dropped.
- Stateful tracking, App-ID with reassembly, URL/IPS/AV inspection and hit
  counters work as for IPv4; `show sessions` lists both families.
- FortiOS style: `set ip6-address` on an interface and `set ip6` on an
  address (FortiOS itself uses separate `address6` objects). PAN-OS style:
  `layer3 ipv6 address` and IPv6 `ip-netmask` values.

Zone flood limits (`syn-flood`, `udp-flood`, `icmp-flood`) apply to IPv6 and
share the IPv4 counters, so a zone's limit covers both families.

User-ID maps IPv4 sources only. So that IPv6 cannot be used to bypass
user-scoped rules, they **fail closed** for IPv6 sources: a user-scoped
`deny`/`reject` applies to every IPv6 source, and a user-scoped `permit` never
matches one (unless it lists `unknown`).

Not implemented for IPv6: NAT66/NPTv6, DNAT, router advertisements, User-ID
mappings, HA session sync, IPv6 inside WireGuard and the kernel nftables backend (which now guards its IPv4
address matches so they can never match an IPv6 packet).

## TLS decryption (inspection engine; not yet in the dataplane)

`src/tls_inspect.rs` is a working TLS inspection engine, tested with real
rustls clients and servers. It is **not yet connected to packet forwarding**:
that needs the firewall to terminate TCP towards both client and server (a
userspace TCP proxy), which is the next step. No policy option enables it yet,
so nothing is silently claimed.

How it works:

1. The client's ClientHello is held. The engine connects to the real server
   with the same SNI and verifies its certificate against Mozilla's roots
   (`webpki-roots`) plus configured extra roots. A server that fails
   verification is never impersonated.
2. The client is then answered with a certificate for the same name, forged
   on the fly and signed by the firewall's CA (cached per name).
3. Decrypted traffic is inspected: the HTTP request line and Host, so URL
   filtering sees paths, not just the SNI; IPS signatures on requests;
   antivirus signatures on responses (a sliding 4 KB window).
4. A block sends an HTTP 403 replacement page inside the client's TLS session.
5. Exempt hosts and non-TLS traffic pass through byte for byte.

Create the CA now with `firewall ssl-ca-generate --out DIR [--name CN]`:
`ca.crt` is installed on clients; `ca.key` is written mode 0600 and never
overwritten. Decryption breaks certificate-pinned apps and must only be used
where users have been told and agreed.

## WireGuard VPN

```text
vpn wireguard wg0 private-key <base64> listen-port 51820 address 10.99.0.1/24 zone vpn
vpn wireguard-peer wg0 site-b public-key <base64> allowed-ips 10.99.0.2/32,10.2.0.0/24 endpoint 203.0.113.2:51820 keepalive 25
policy 10 trust vpn any any any any permit
```

- `firewall wg-genkey` and `firewall wg-pubkey` (stdin) make keys in the same
  format as `wg genkey` / `wg pubkey`, so peers can be stock WireGuard.
- The tunnel is an interface (`wg0`) in its zone. Traffic to a peer's allowed
  IPs is routed into it (the most specific prefix wins against routes).
- Decrypted packets enter the firewall as traffic arriving on `wg0` and are
  checked against policy like any other zone; a packet whose inner source is
  not in the sending peer's allowed IPs is dropped.
- The listen port on the firewall's own addresses is answered by the tunnel;
  unknown keys are silently ignored, as WireGuard does.
- Handshakes start on demand (packets wait in a small queue), retry every
  5 s for up to 90 s, rekey after 120 s and reject keys after 180 s. A peer's
  endpoint is learned from authenticated packets (roaming).
- `show vpn` lists tunnels, peers, endpoints, last handshake and byte counts.
  Peer changes apply on commit; a new tunnel or address needs a restart.

Not implemented: cookie replies under load, IPv6 inner packets, and IPsec.
After an HA failover the new active unit re-handshakes with its peers.

## User-ID

Mappings come from three places, most specific first: dynamic logins (an
identity source such as a script reading directory logon events, a VPN or a
captive portal), then static `user-map` lines. A dynamic mapping expires
after its timeout, if it has one. Sessions record the user they started with.

```sh
# CLI
firewall cli -c "user-id login 10.0.0.5 alice timeout 3600"
firewall cli -c "show users"
# REST (needs an administrator with write access)
curl -k -H "Authorization: Bearer $TOKEN" -d '{"ip":"10.0.0.5","user":"alice","timeout":3600}' \
     https://127.0.0.1:8080/api/v1/user-id/login
curl -k -H "Authorization: Bearer $TOKEN" https://127.0.0.1:8080/api/v1/user-id
```

The PAN-OS-style CLI adds `source-user` in rules, `set user-group`,
`request user-id login user <u> ip <ip> [timeout <s>]` and
`show user ip-user-mapping all`; the FortiOS-style CLI adds `config user
group`, `set users` / `set groups` in policies and
`diagnose firewall auth list`. There is no directory (LDAP/AD) connector:
groups are configured, and logins are pushed.

## Vendor-style CLIs

Each CLI connection picks its own style; `system cli-style fortios|panos`
sets the default for new connections, and `cli-style <name>` switches the
current one. Read-only administrators can show but not change anything.

FortiOS style: `config` / `edit` / `set` / `unset` / `append` / `next` /
`end` / `abort`, changes applied on `next` and `end`; tables `system global`,
`system interface`, `system zone`, `firewall address|addrgrp|service
custom|service group|policy|vip|central-snat-map|shaper traffic-shaper`,
`application group`, `router static`, `webfilter profile`, `ips sensor`,
`antivirus profile` and `config vdom`; predefined services such as `HTTPS`,
`DNS` and `SSH` are created on first use. Tools: `show`, `get system status`,
`get router info routing-table all`, `get application list`,
`diagnose sys session list`, and
`diagnose firewall iprope lookup <src> <sport> <dst> <dport> <proto> <srcintf> [app]`.

```text
FGT-LAB # config firewall policy
FGT-LAB (policy) # edit 0
FGT-LAB (1) # set srcintf "inside"
FGT-LAB (1) # set dstintf "port2"
FGT-LAB (1) # set srcaddr "all"
FGT-LAB (1) # set dstaddr "all"
FGT-LAB (1) # set service "ALL"
FGT-LAB (1) # set app-category "social-networking"
FGT-LAB (1) # set action deny
FGT-LAB (1) # next
```

PAN-OS style: operational mode (`configure`, `show config running|candidate`,
`show running security-policy`, `show session all`, `show system info`,
`show interface all`, `show applications`, `test security-policy-match`) and
configuration mode (`set`, `delete`, `move`, `rename`, `show [path]`,
`commit`, `revert`, `run <op>`), with `set vsys <name> ...` for other VDOMs.
Objects: zones, addresses, address groups, services, service groups,
application groups, `profiles url-filtering|vulnerability|virus`,
profile groups, `rulebase security`, `rulebase nat` (source and destination
translation) and virtual-router static routes. A failed commit keeps the
candidate.

```text
admin@PA-LAB# set rulebase security rules allow-web from trust to untrust source any destination any application [ ssl github ] service application-default action allow
admin@PA-LAB# commit
Configuration committed successfully
admin@PA-LAB# run test security-policy-match from trust to untrust source 10.0.0.5 destination 8.8.8.8 protocol 6 destination-port 443 application ssl
```

Default rules: `set rulebase default-security-rules rules intrazone-default
action allow [log-end yes]` (PAN-OS style) and `config system zone` / `set
intrazone allow` (FortiOS style).

Differences from the real products, by design: names instead of numeric
FortiGuard ids; web filter, IPS and AV profiles take categories, domains and
literal signatures directly; intrazone traffic is denied until you allow it;
interface address or VDOM changes still need a daemon restart.

## Tests

```sh
cargo test                      # 175 unit/engine tests, no privileges needed
node tests/ui-model.test.js     # GUI object model round trip
sudo bash tests/nft-kernel.sh
sudo bash tests/kernel-mode.sh  # daemon-managed kernel dataplane
```

See `AUDIT.md` for the Stage 1 audit and `EVIDENCE.md` for recorded runs.

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

- No VLAN tags or ALGs. Fragments (IPv4 and IPv6) are dropped, not reassembled.
- App-ID reassembles in-order bytes only: a segment that arrives after a gap
  is not buffered, and classification falls back to what it has after eight
  payload packets or 4 KB. URL/IPS/AV inspection is still per packet. App-ID
  signatures are short and readable, not a commercial signature set.
- When App-ID moves a flow to a different permit rule, the source NAT chosen
  at the first packet is kept.
- TCP tracking does not check sequence numbers, so a spoofed RST for a known
  5-tuple still closes a flow.
- Signature profiles are literal substring matches, not real IPS/AV engines.
- TLS decryption exists as an engine but is not in the dataplane yet; no
  IPsec or dynamic routing. HA is active/passive
  only (no active/active, link monitoring or virtual MACs). User-ID
  has no LDAP/AD connector; mappings are pushed or static.
- The CLI transport is plaintext; the daemon refuses a non-loopback bind
  unless `system cli-remote-plaintext on`. Tunnel it instead. The GUI supports
  TLS and should still be exposed only on a trusted network.
- ARP misses drop the first packet rather than queueing it.
- The kernel dataplane refuses every configuration it cannot enforce exactly
  (see "Kernel nftables dataplane"); those features need the userspace engine.
- VDOMs isolate forwarding configuration, not administrative access.
