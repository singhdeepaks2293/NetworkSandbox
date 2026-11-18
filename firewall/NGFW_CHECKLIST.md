# VELA NGFW Feature Checklist

Audit date: 2026-11-18  
Scope: `/home/deepak/NetworkSandbox/prompt.txt` (master prompt) against the `firewall/` implementation.  
Rule: a feature is checked only when the repository contains a working implementation and it has been exercised. A UI page, API stub, or unused field does not count as implemented.

## Status legend

- `[x]` Implemented and verified in this repository.
- `[~]` Partial: some behavior exists, but a required part is missing or only tested indirectly.
- `[ ]` Not implemented, or present only as an empty/decorative surface.

## Verdict

**The product is not a complete NGFW against the master prompt.** It is a working educational stateful IPv4 firewall with userspace AF_PACKET forwarding, VDOM-like partitions, NAT, a small inspection layer, authentication/RBAC, candidate configuration, a REST API, a vanilla-JS UI, a basic CLI, and containerlab integration tests.

The largest missing areas are kernel enforcement (`nftables`/conntrack/NFQUEUE/eBPF), IPv6, VPN, DNS security, TLS inspection, real application control, ClamAV integration, the required React/Vite UI, the full CLI hierarchy/diagnostics, SQLite/OpenAPI, Compose/health checks/graceful shutdown, and performance/security test suites.

## 1. Product scope and isolation

- [x] Standalone firewall only; no router/switch/lab-manager product.
- [x] One independent configuration, auth store, logs and runtime state per container.
- [x] Multiple firewall instances can run simultaneously; verified with `firewall-chain.clab.yml` (`fw1` + `fw2`).
- [~] Independent runtime state is process-local and in-memory; no persistent session/state database.
- [ ] Docker Compose one-command deployment.
- [ ] Documented supported deployment modes (routed container, dedicated netns, lab/veth).
- [ ] Explicit Windows/macOS Docker Desktop limitations.

## 2. Backend technology stack

- [x] Rust stable.
- [ ] Tokio async runtime.
- [ ] Axum HTTP framework.
- [x] Serde-based JSON serialization (`serde_json`).
- [~] Clap-like command parsing is hand-written; Clap itself is not used.
- [ ] SQLx + SQLite persistent management database.
- [ ] Tracing structured logging.
- [ ] Rustls/TLS for the management API.
- [x] Userspace AF_PACKET packet engine.
- [ ] nftables kernel filtering/NAT.
- [ ] Kernel conntrack integration.
- [ ] NFQUEUE selective userspace inspection.
- [ ] eBPF/XDP optional acceleration.
- [x] Linux network namespaces and veth integration tests.
- [~] Modular source modules, but not a Rust workspace with independent crates.
- [x] Startup loads and validates persistent configuration.
- [~] Startup reconciles intended state with the kernel; there is no kernel enforcement plane to reconcile.
- [x] Configuration load failures are reported clearly.

## 3. Architecture and separation

- [~] Separate management/control code from packet processing (`gui`/`cli`/`auth` vs `dataplane`), but all in one process and one binary.
- [~] Policy, NAT, inspection, API, CLI, auth and logging are modules; many required modules do not exist.
- [ ] `firewall-engine`, `packet-filter`, `policy-engine`, `nat-engine`, `dpi-engine`, `ips-engine`, `dns-security`, `web-filter`, `application-control`, `vpn-manager` as separate components.
- [x] No unnecessary microservices.
- [~] Management crash behavior: dataplane runs in its own thread, but process/thread failure is not supervised or recoverable.
- [ ] Defined behavior for database unavailable.
- [ ] Defined behavior for host OOM.
- [ ] Kernel enforcement continues if management plane is unavailable (no kernel enforcement plane exists).

## 4. Interfaces and zones

- [x] Multiple interfaces.
- [x] WAN/LAN/DMZ/custom zone names (free-form zone strings).
- [x] Interface IPv4 address configuration.
- [x] Interface-to-zone assignment.
- [x] Interface MTU field.
- [x] Interface RX/TX packet and drop counters.
- [x] Interface MAC field/automatic MAC reporting.
- [x] Basic interface management page and CLI `show interfaces`.
- [~] Link status: the UI infers "up" from an assigned address; it does not query kernel link state.
- [~] RX/TX bytes exist in monitoring JSON, but the interface table shows packets only.
- [~] Interface errors: aggregate errors exist; per-interface error counters are not exposed.
- [ ] IPv6 addresses, filtering and routes.
- [ ] General static routes; only one default route per VDOM is supported.
- [ ] Multiple gateways / gateway objects.
- [ ] DHCP client.
- [ ] VLAN interfaces.
- [ ] DNS configuration page.
- [ ] Network diagnostics page.
- [ ] Kernel application of interface addresses/MTU/routes; packet engine uses configured values, but the host/container kernel is not configured.
- [ ] Clear host-networking requirements beyond the containerlab examples.

## 5. Stateful firewall

- [x] IPv4 filtering.
- [ ] IPv6 filtering.
- [x] TCP, UDP and ICMP filtering.
- [x] Connection tracking and stateful return traffic.
- [~] NEW/ESTABLISHED/RELATED/INVALID state model; implementation tracks forward/reverse sessions and timeouts, not the full state taxonomy.
- [x] Default deny when no policy matches.
- [x] Source and destination IP filtering.
- [~] Destination port filtering; there is no source-port field.
- [x] Protocol filtering.
- [x] Zone-pair filtering.
- [~] Interface-based filtering only through interface-to-zone mapping; no explicit ingress/egress interface rule fields.
- [x] Address objects and address groups.
- [ ] Service groups.
- [x] Rule ordering by ascending rule ID.
- [ ] Rule enable/disable.
- [ ] Rule names.
- [ ] Rule descriptions.
- [ ] Per-rule hit counters.
- [ ] Last-match timestamps.
- [x] Per-rule logging toggle.
- [x] Basic policy validation.
- [x] Permit and deny actions.
- [ ] Reject action (TCP reset / ICMP unreachable).
- [x] Log action behavior through per-rule logging and policy logs.
- [~] Rate limiting through shapers and zone flood limits; no general per-rule rate limit.
- [ ] Rules compiled into kernel enforcement rules.
- [~] "Never report active unless enforcement succeeded": configuration commit is atomic in memory/file, but there is no kernel apply-and-verify step.
- [ ] IPv4/IPv6 packet normalization: no fragmentation handling, no VLAN tags.

## 6. NAT engine

- [x] Source NAT.
- [x] Destination NAT.
- [x] PAT/port translation for TCP/UDP.
- [x] Masquerading to the egress interface address.
- [x] Port forwarding (DNAT).
- [~] Static NAT: a one-to-one DNAT can be expressed, but there is no distinct static-NAT object/type.
- [x] NAT rule ordering by ascending rule ID.
- [ ] NAT event logging with translated addresses/ports.
- [x] NAT translation monitoring in the session table.
- [x] NAT configuration through full config editor/API.
- [~] NAT configuration through CLI/UI: DNAT is visible; there are no dedicated NAT add/edit forms or CLI NAT commands.
- [ ] nftables/kernel NAT implementation.
- [x] NAT tested in an actual packet-forwarding chain (SNAT on both hops, DNAT, return traffic).

## 7. Policy management

- [x] Rule ID.
- [ ] Rule name.
- [ ] Rule description.
- [x] Source zone.
- [x] Destination zone.
- [x] Source addresses and source address groups.
- [x] Destination addresses and destination address groups.
- [x] Service object reference.
- [x] Protocol field.
- [ ] Source ports.
- [x] Destination port/service.
- [x] Application restriction field.
- [ ] Schedule.
- [~] Security profiles: separate app/URL/IPS/AV fields exist; no single reusable security-profile object.
- [x] Logging toggle.
- [x] Action.
- [ ] Enabled/disabled state.
- [ ] Drag-and-drop rule ordering.
- [~] Search/filter/sorting: API supports text filtering for sessions/logs; policy table has no UI search/sort/filter.
- [ ] Rule duplication.
- [ ] Bulk enable/disable.
- [ ] Unused-rule identification.
- [ ] Shadowed-rule detection.
- [x] Policy validation.
- [~] Policy preview: configuration diff exists, but no rule-impact preview.
- [x] Configuration diff.
- [x] No silent reordering by ID.

## 8. Deep Packet Inspection

- [~] Protocol identification: mostly configured app-definition matching by protocol/port, not content-based protocol identification.
- [x] HTTP metadata inspection (`Host`).
- [x] TLS metadata inspection (ClientHello SNI).
- [ ] DNS inspection.
- [ ] Protocol anomaly detection.
- [~] Configurable inspection rules: literal URL/signature entries, not a general rule language.
- [x] Inspection event logging.
- [x] Metadata-vs-encrypted-payload limitation documented (README).
- [~] One-packet inspection only; split TCP requests may be missed.

## 9. Intrusion Prevention System

- [x] Signature-based literal payload matching.
- [ ] Rule severity.
- [ ] Signature categories.
- [x] Source/destination information in event logs.
- [x] Detection logs.
- [ ] Alert-only mode.
- [x] Drop mode for matching flows.
- [ ] Per-signature enable/disable.
- [ ] Signature update mechanism.
- [ ] Documented signature format and safe update process.
- [ ] Test-traffic validation for signatures.
- [ ] Real IPS engine/stream reassembly.
- [ ] Kernel/NFQUEUE integration.

## 10. Application control

- [~] Application identification by configured protocol/port (`app-def`).
- [ ] Application categories.
- [x] Allow/block through policy application field.
- [ ] Application usage statistics.
- [x] Application-based firewall rules.
- [~] Unknown application handling: unmatched apps simply do not match; no explicit unknown policy.
- [ ] Content/metadata-based classification.
- [ ] Top-application dashboard/report.

## 11. DNS security

- [ ] DNS query logging.
- [ ] Domain allowlists.
- [ ] Domain blocklists.
- [ ] Threat-domain blocking.
- [ ] DNS response inspection.
- [ ] DNS filtering policies.
- [ ] Custom domain groups.
- [ ] Domain-based policy rules.
- [ ] DNS over UDP/TCP/TLS/HTTPS handling.

## 12. Web filtering

- [x] Domain filtering by HTTP `Host` and TLS SNI.
- [~] URL filtering only at host level; no path/query visibility.
- [x] Category-based filtering architecture with a small built-in domain list.
- [x] Allowlist.
- [x] Blocklist.
- [ ] Custom categories.
- [x] Policy-based URL-filter attachment.
- [x] Web access logs through flow logs.
- [x] HTTPS/QUIC/encrypted-DNS/certificate-pinning limitations documented.
- [ ] QUIC/HTTP3 visibility.
- [ ] Full URL category database.

## 13. TLS inspection

- [ ] Optional TLS interception module.
- [ ] Certificate authority management.
- [ ] Inspection policies.
- [ ] Certificate validation.
- [ ] Exclusion lists.
- [ ] Certificate generation and rotation.
- [ ] TLS inspection logging.
- [ ] Explicit administrative enablement and trust deployment.
- [ ] Encrypted private-key storage.
- [ ] Pinning/mTLS/QUIC compatibility documentation.
- [ ] Any TLS interception implementation at all.

## 14. Malware protection

- [~] Inline literal AV signature matching (`av-profile`/`av-signature`).
- [ ] ClamAV or other supported antivirus integration.
- [ ] Real file extraction/scanning.
- [x] Malware detection events in flow logs.
- [ ] Scan status.
- [ ] Signature update status.
- [~] Configurable scanning policies via profile attachment.
- [x] Documented limitation that inspection is one packet at a time.
- [ ] File-type coverage disclosure.
- [ ] Quarantine/action policy beyond drop.

## 15. DoS protection

- [x] SYN flood threshold per zone.
- [x] ICMP flood threshold per zone.
- [ ] UDP flood threshold.
- [ ] Excessive connection creation limit.
- [ ] Connection table exhaustion protection/limit.
- [ ] Per-source rate limiting.
- [ ] Automatic temporary source blocking (current flood check drops packets in a time window; no address ban list).
- [x] Flood event logging.
- [x] Per-interface packet/drop statistics.
- [x] Documentation that this is not volumetric DDoS mitigation.
- [ ] Configurable global memory/session limits.

## 16. VPN

- [ ] WireGuard management.
- [ ] IPsec management.
- [ ] Peer management.
- [ ] Tunnel configuration.
- [ ] Allowed IPs.
- [ ] Tunnel status.
- [ ] Peer statistics.
- [ ] Key management.
- [ ] Connection logs.
- [ ] VPN firewall policies.
- [ ] Kernel module/capability documentation.
- [~] `/api/v1/vpn` exists but returns an empty placeholder.
- [ ] VPN UI pages.

## 17. Web management UI

- [x] Original, responsive visual design with working login.
- [x] Real backend data for dashboard cards, interfaces, policies, sessions, logs, objects and configuration.
- [x] Confirmation dialogs for rollback/apply.
- [x] Error messages and success notices for configuration actions.
- [x] Loading/empty states in several tables.
- [~] Search/filter: sessions/logs endpoints support query parameters; controls are limited.
- [ ] Pagination in the UI.
- [~] Responsive layout exists, but not tested across a device matrix.
- [x] Login page connected to Argon2/RBAC backend.
- [x] Logout.
- [x] Configuration stage/diff/commit/discard/rollback/backup.
- [~] Dashboard status: packet counts, sessions, errors, interface counters, recent events, policy summary.
- [ ] Dashboard CPU usage display.
- [ ] Dashboard RAM usage display.
- [ ] Dashboard disk usage display.
- [ ] Network throughput chart.
- [ ] Total/blocked connection charts.
- [ ] Security threat count.
- [ ] VPN status widget.
- [ ] Top applications/sources/destinations.
- [ ] Time-range filters.
- [ ] Real charts (no decorative charts currently).
- [ ] Network pages: zones, gateways, VLANs, DNS, diagnostics.
- [ ] Policy & Objects pages: NAT policies, address groups, service groups, schedules.
- [ ] Security profile pages: DNS filtering, application control, TLS inspection, DoS protection.
- [ ] VPN pages: WireGuard, IPsec, peers, tunnels, monitoring.
- [ ] Monitor pages: traffic, bandwidth, applications, packet capture.
- [ ] Logs pages: firewall, security, DNS, VPN, system, audit, reports.
- [ ] Administration pages: administrators, roles, authentication, API tokens, system settings, updates.
- [ ] Per-rule add/edit/delete/reorder forms.
- [ ] Role-aware UI hiding of forbidden actions (backend rejects writes, but buttons remain visible).
- [ ] Every UI button works: several required actions are absent rather than present and broken.
- [ ] All required tables load real data: required tables for missing pages do not exist.

## 18. CLI

- [x] Non-interactive and TCP line-mode command execution.
- [x] `show version`, `show config`, `show interfaces`, `show policies`, `show sessions`, `show stats`.
- [x] `policy add`, `policy delete`, `save`.
- [ ] Persistent interactive shell with prompt/modes.
- [ ] Hierarchical configuration modes (`enable`, `configure terminal`, `config-if`, etc.).
- [ ] Tab completion.
- [ ] Context-sensitive `?` help.
- [ ] Command history.
- [ ] Shared authenticated CLI.
- [ ] Optional web terminal.
- [ ] Required `show system status` / `resources`.
- [ ] `show interfaces statistics`.
- [ ] `show zones`.
- [ ] `show routes`.
- [ ] `show firewall policies` / `policy-hitcounts`.
- [ ] `show firewall sessions` / `statistics`.
- [ ] `show nat translations`.
- [ ] `show security threats`.
- [ ] `show application statistics`.
- [ ] `show vpn status`.
- [ ] `show log traffic` / `security`.
- [ ] `show running-config`.
- [ ] `diagnose system resource`.
- [ ] `diagnose firewall session` / `policy`.
- [ ] `diagnose packet capture`.
- [ ] `diagnose network interface` / `connectivity`.
- [ ] `diagnose dns` / `vpn`.
- [ ] Configuration commands for interface, zone, policy, NAT, objects, security profile, VPN, user.
- [ ] `commit`, `rollback`, `show candidate-config`, `show configuration-diff`, `backup`, `restore`.
- [ ] CLI command parser unit tests.

## 19. Shared configuration management

- [x] Candidate configuration.
- [x] Running configuration stored separately.
- [x] Validation before commit.
- [~] Dependency/conflict checks: parse and live-interface compatibility only.
- [ ] Explicit enforcement-plan generation.
- [ ] Kernel apply-and-verify step.
- [x] Commit updates running configuration.
- [x] Audit entries for stage/commit/rollback/restore.
- [x] Rollback to previous configuration.
- [~] Failed apply restores previous state: file write is ordered before in-memory swap, but interface-change commits are rejected rather than applied.
- [x] Configuration diff.
- [x] Persistence to the config file with atomic rename.
- [x] Backup JSON export and restore API.
- [~] Config survives process restart if the config path is persistent; no Compose volume exists to guarantee this.
- [x] Invalid configuration is rejected before replacing valid state.
- [~] Versioned export/import exists as a custom JSON envelope; no YAML and no formal schema/version.
- [x] Shared model between API/UI/CLI.
- [x] VDOM-scoped config sections.
- [ ] Per-VDOM administrative contexts/roles.

## 20. REST API

- [x] Versioned endpoint families for system, interfaces, zones, routes, policies, NAT, objects, security, VPN placeholder, sessions, logs, monitoring, configuration and administrators.
- [ ] OpenAPI specification/documentation.
- [x] Authentication (session cookie and Bearer API token).
- [x] Backend authorization checks.
- [~] Input validation: parser validation exists; not every endpoint validates every field/type.
- [~] Rate limiting: login throttling only; no general API rate limit.
- [x] Audit logging for auth and config actions.
- [x] Structured JSON error responses.
- [ ] WebSocket or server-sent events for live monitoring; UI polls.
- [x] Unauthenticated privileged operations are not exposed; `/healthz` is read-only.
- [~] API token listing endpoint; tokens can be created/revoked, but there is no list route/UI.
- [ ] MFA endpoints.
- [ ] Packet-capture endpoint.
- [ ] VPN endpoint behavior beyond an empty placeholder.
- [ ] API examples/schema tests.

## 21. Authentication and access control

- [x] Secure administrator authentication.
- [x] Argon2id password hashing.
- [x] Five roles: super admin, firewall admin, network engineer, security analyst, auditor.
- [x] Backend RBAC, including read-only auditor writes denied.
- [x] Administrator create/list/delete.
- [x] Session expiration (8 hours).
- [x] API token creation/revocation and Bearer auth.
- [~] API token permissions: role is stored, but there is no token list/management UI.
- [x] Login attempt throttling.
- [x] Audit trails.
- [x] CSRF protection for cookie-authenticated writes.
- [x] No hardcoded credentials; bootstrap admin via environment or random file.
- [x] Password hashes/secrets stored in mode-0600 files.
- [ ] Optional MFA/TOTP.
- [ ] Secure password reset workflow.
- [ ] Per-role UI behavior.
- [ ] API authorization test suite in the repository.
- [~] Administrator page: API exists, but no UI page.

## 22. Monitoring and logging

- [x] Text/JSON flow logs.
- [x] Allowed/blocked traffic logs.
- [~] NAT events are represented in session state, not dedicated NAT log events.
- [x] Security inspection logs for URL/IPS/AV actions.
- [ ] DNS event logs.
- [ ] VPN event logs.
- [x] Administrative audit log.
- [x] System/startup messages on stdout.
- [x] Log search/filter via query parameters.
- [x] Offset/limit paging in API.
- [ ] Date/time range filters.
- [ ] CSV/JSON export of logs.
- [ ] Log rotation.
- [ ] Configurable retention.
- [x] Bounded in-memory log buffer (200 lines).
- [x] CPU load average and CPU count.
- [x] Memory totals/available.
- [x] Disk totals/free.
- [x] Interface counters.
- [~] Throughput: cumulative RX/TX bytes only; no rate calculation.
- [x] Active sessions.
- [ ] Connection creation rate.
- [~] Firewall rule counters: only aggregate accepted/denied; no per-rule counters.
- [x] Packet-drop counters.
- [ ] Monitoring charts or historical time series.
- [ ] Unbounded queue prevention for sessions; the session table has no explicit maximum.

## 23. Docker deployment

- [x] Dockerfile (multi-stage, musl, scratch runtime).
- [ ] Docker Compose file.
- [~] Environment configuration: `VELA_ADMIN_USER`/`VELA_ADMIN_PASSWORD` only.
- [ ] Environment example file.
- [ ] Persistent volume configuration for config/auth/logs.
- [ ] Docker health check command/integration.
- [~] Startup validation: config/auth load; no preflight network/capability checks.
- [ ] Graceful shutdown / SIGTERM handling.
- [x] Structured stdout logs for traffic when JSON is configured.
- [ ] Upgrade instructions.
- [~] Backup/restore instructions; API exists, guide is minimal/incomplete.
- [x] Multiple independent containers verified on one host.
- [x] Non-privileged lab deployment uses default Docker capabilities in containerlab.
- [~] Least capability documentation: `NET_RAW` is mentioned; `NET_ADMIN` and namespace modes are not fully documented.
- [ ] Runs as non-root inside the container.
- [ ] Host networking requirement matrix.
- [ ] Windows/macOS Docker Desktop behavior documented.

## 24. Lite/full resource profiles

- [~] A single lightweight process exists and advanced inspection is configuration-driven.
- [ ] Explicit Lite profile.
- [ ] Explicit Full NGFW profile.
- [ ] Independent enable/disable switches for every inspection engine.
- [ ] Lazy start/stop of resource-heavy engines.
- [x] Bounded traffic log buffer.
- [ ] Configurable memory limits.
- [ ] Bounded queues for every subsystem.
- [ ] Throughput/latency/CPU/memory benchmarks.
- [ ] Lite-vs-full comparison with recorded hardware and method.

## 25. Security engineering

- [~] Safe Rust mostly, with unsafe libc/AF_PACKET code.
- [x] Strict parser validation for configuration.
- [~] Least privilege: packet engine needs root/CAP_NET_RAW; container defaults are not hardened with a non-root user.
- [x] Secure defaults for authentication and cookie flags.
- [x] No hardcoded credentials.
- [x] No unauthenticated administration.
- [x] Secret files mode 0600.
- [ ] Dependency audit in CI.
- [x] Structured security/audit logging.
- [ ] Secure update validation (no update mechanism).
- [x] Low command-injection surface; no shell execution of user input.
- [x] Configuration injection handled through parser and validation.
- [~] API authorization tests exist manually; not committed as an automated suite.
- [x] Administrative audit logging.
- [~] Safe behavior when the API/UI fails: control-plane thread may die while packet engine continues; no health supervisor.
- [ ] Safe behavior when the database fails (no database).
- [ ] Safe behavior on OOM/resource exhaustion: no global session/memory bound.
- [ ] Kernel plane continues last known-good policy (no kernel plane).

## 26. Testing

- [x] Unit tests for parsing, policy matching, NAT config, VDOM, checksums and auth (26 passing).
- [~] Rule ordering tests exist indirectly; no dedicated enable/disable/reorder tests.
- [x] Configuration serialization/round-trip tests.
- [x] Authentication/RBAC unit tests.
- [ ] CLI parser tests.
- [x] LAN-to-WAN and WAN-to-LAN integration test.
- [x] Stateful return traffic integration test.
- [x] NAT/SNAT integration test.
- [x] Port forwarding/DNAT integration test.
- [x] URL block/allow integration test.
- [x] Policy update/deny/recovery integration test.
- [x] Rollback API test (manual).
- [~] Zone isolation tested through chain/policy labs.
- [ ] IPv6 integration test.
- [ ] Container restart persistence test.
- [~] Unauthorized API/access tests performed manually.
- [x] Invalid credentials test (unit/manual).
- [~] Privilege-escalation attempts tested manually.
- [x] Invalid configuration tests.
- [ ] Malformed packet tests.
- [ ] Excessive connection/resource exhaustion tests.
- [~] Invalid administrative operation tests.
- [x] UI login/dashboard/policy view tested manually via CDP.
- [x] UI configuration commit/rollback tested manually.
- [x] UI log viewing tested manually.
- [ ] Automated UI test suite.
- [~] CLI command execution tested manually; no interactive mode tests.
- [ ] Performance benchmarks: throughput, PPS, latency, CPU, memory, connection rate, concurrent sessions.
- [ ] Lite/full performance comparison.
- [x] Containerlab chain test: 10/10 checks passed.
- [x] Containerlab policy test: 4/4 checks passed.
- [x] Root network-namespace test exists; not part of the verified run in this audit.

## 27. Required deliverables and documentation

- [~] Source repository present; not a Rust workspace.
- [x] Firewall engine (userspace).
- [ ] Kernel packet-enforcement integration.
- [x] Basic policy engine.
- [x] Basic NAT engine.
- [~] Security inspection modules are literal-pattern prototypes, not full engines.
- [x] REST API.
- [~] CLI exists but not the required professional interactive CLI.
- [~] Web UI exists but not the required React/TypeScript/Vite application.
- [ ] Database schema and migrations.
- [x] Dockerfile.
- [ ] Docker Compose configuration.
- [ ] Environment example file.
- [x] Unit tests.
- [x] Integration tests.
- [~] Security tests are mostly manual.
- [ ] Performance benchmark tools.
- [ ] API documentation (OpenAPI).
- [~] CLI documentation is a short help text.
- [~] Installation guide is a README section.
- [x] Configuration guide.
- [ ] Troubleshooting guide.
- [~] Backup/restore guide is only partially described.
- [ ] Architecture documentation.
- [x] Exact build/test/run commands in README.
- [ ] Upgrade/rollback deployment guide.
- [x] Clean-room/EVIDENCE note.

## 28. Definition of done

- [x] Builds successfully.
- [x] Docker image builds successfully.
- [x] Container starts successfully.
- [x] Web UI connects to the real backend.
- [~] CLI works, but is not the required interactive/hierarchical CLI.
- [x] UI and CLI share one configuration model.
- [ ] Firewall rules are enforced by the kernel; they are enforced in userspace.
- [x] NAT works in an actual packet-forwarding test.
- [x] Stateful connection tracking works.
- [~] Configuration persists after restart; file persistence exists, but the restart test and Docker volume guarantee are missing.
- [x] Commit and rollback work.
- [x] Authentication and RBAC work.
- [x] Logs reflect real traffic.
- [~] Monitoring reports real measurements, but not all required metrics and no charts.
- [x] Multiple independent firewall containers can run on the supported Linux host.
- [x] Critical containerlab integration tests pass.
- [~] Documentation describes actual functionality and limitations, but several required guides are absent.

## 29. Highest-priority gaps

1. Replace or supplement userspace AF_PACKET forwarding with `nftables` + kernel conntrack, or explicitly scope the product as educational userspace-only.
2. Add IPv6, general static routes, VLANs and DHCP support.
3. Add VPN, DNS security and TLS inspection modules, including safe key storage.
4. Replace literal IPS/AV with documented engines or clearly mark them as prototypes.
5. Build the required React/TypeScript/Vite UI pages, forms, charts and administration screens.
6. Build the hierarchical interactive CLI with completion, help, diagnostics and commit/rollback.
7. Add Compose, volumes, health check, SIGTERM shutdown, non-root runtime and deployment-mode docs.
8. Add OpenAPI, SQLite persistence/migrations and API rate limiting.
9. Add automated security/API/UI/CLI and restart-persistence tests.
10. Add performance benchmarks for Lite and Full profiles.

## 30. Reproduce the verified baseline

```sh
cd /home/deepak/NetworkSandbox/firewall
export PATH="$HOME/.cargo/bin:$PATH"

cargo test
cargo build --release

# Host-level packet forwarding test
echo 3y3 | sudo -S ./tests/containerlab-policy.sh

# Two-firewall chain, NAT, DNAT, URL and policy-recovery test
echo 3y3 | sudo -S ./tests/containerlab-chain.sh

# Current live control-plane instance
curl http://10.228.197.24:8080/healthz
```

Expected verified results at this audit:

```text
cargo test: 26 passed; 0 failed
containerlab-policy.sh: ALL CHECKS PASSED (4/4)
containerlab-chain.sh: ALL CHECKS PASSED (10/10)
healthz: {"product":"VELA NGFW","status":"ok","version":"0.1.0"}
```
