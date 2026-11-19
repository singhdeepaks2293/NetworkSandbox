# Stage 1 Audit — NetworkSandbox Firewall

- **Date:** 2026-11-19
- **Commit audited:** `8312f73` (HEAD of `main`)
- **Scope:** `firewall/` only. Sections 8–9 of the master prompt (SDN / OpenFlow) are deferred and were not audited.
- **Method:** source reading plus targeted greps, and the unit test suite. No source file was changed during the audit.
- **Revised:** 2026-11-19, after implementation on branch `stage2-enforcement-safety` (see Section 10). Two findings were retracted (C8, M2).

## 1. Baseline test results

| Suite | Command | Result |
| --- | --- | --- |
| Unit tests | `cargo test --release` (rustc/cargo 1.91.1) | **134 passed, 0 failed**, 0 compiler warnings |
| `tests/network-namespace.sh` | — | **Not run**: audit sandbox has no `ip` tool or netns privileges |
| `tests/nft-kernel.sh` | — | **Not run**: same reason |
| `tests/containerlab-policy.sh`, `containerlab-chain.sh` | — | **Not run**: no containerlab |

Stage 2 must run the four integration scripts on a Linux host with root and record the results before changing code.

## 2. Verdict

The firewall is a well-tested userspace engine whose **policy logic is solid but whose enforcement guarantees are not**. Two issues can make it fail open on a real host, the status it reports cannot be trusted, and the CLI can change policy outside the commit pipeline. Fix these (Stages 2–3) before adding features.

## 3. Critical findings

| # | Finding | Evidence | Impact | Stage |
| --- | --- | --- | --- | --- |
| C1 | **Fail-open if kernel forwarding is on.** The daemon never checks or sets `net.ipv4.ip_forward` or `net.ipv6.conf.*.forwarding`. AF_PACKET receives copies of frames; it does not stop the kernel from routing them. Only the lab YAML and test scripts set `ip_forward=0`. | `main.rs` (no sysctl handling); `firewall.clab.yml:29`; `tests/network-namespace.sh:68` | On a host with forwarding enabled, traffic is routed by the kernel unfiltered, alongside the firewall. A daemon crash (release profile is `panic = "abort"`) leaves the kernel forwarding. | 2 |
| C2 | **Interfaces silently skipped.** An interface that is missing or whose socket fails to open is logged and skipped; the daemon carries on. | `dataplane.rs:535–540`, `:562–566` | Combined with C1, that interface's traffic bypasses inspection; without C1 it is black-holed. Either way nothing reports it. | 2 |
| C3 | **Health is always "ok".** `/healthz` and `/api/v1/health` return a fixed `{"status":"ok"}`. | `gui.rs:392–396` | No way to detect a degraded or non-enforcing firewall. | 2 |
| C4 | **nftables mode is not integrated.** `nft-apply` / `nft-remove` are one-shot subcommands. Commits never reconcile the kernel table, and nothing stops `nft-apply` from running while the AF_PACKET daemon is also forwarding. `nft-kernel.sh` turns `ip_forward` on. | `main.rs:33–34`, `:355–377`; `tests/nft-kernel.sh:60` | Two enforcement paths can process the same traffic; kernel rules go stale after any commit. | 2 |
| C5 | **User-scoped deny rules do not apply to IPv6.** User-ID is not implemented on the IPv6 path, so the user is always unknown there. A rule such as `deny user contractors` never matches IPv6 traffic, and a rule matching `unknown` matches every IPv6 host. | `dataplane_v6.rs:17–18`; `model.rs:2225–2233` | Policy bypass by switching to IPv6. Stage 2 must confirm with a test. | 2 |
| C6 | **IPv6 has no DoS limits.** SYN/UDP flood limits exist only on IPv4. | `dataplane_v6.rs:17–18` | Flood protection is bypassed by using IPv6. | 2 (flag) / 5 (fix) |
| C7 | **Native CLI bypasses the commit pipeline.** `policy add` / `policy delete` write the running config directly: no live-compatibility check, no history entry (cannot roll back), no revision bump, no audit record, and a read-modify-write race with other writers. On a save failure the running config silently diverges from disk. | `cli.rs:447–492` | Untracked, unauditable policy changes; lost updates. | 3 |
| C8 | ~~`policy delete <id>` deletes that ID in every VDOM.~~ **Retracted 2026-11-19:** policy IDs are unique across all VDOMs (the parser rejects a duplicate ID in another VDOM), so an ID always names exactly one policy. | `model.rs` duplicate-id check | None | — |
| C9 | **Lost updates between GUI and CLI.** The GUI candidate is a full config text with no base revision. If a FortiOS/PAN-OS CLI commit lands after the GUI candidate was staged, committing the candidate overwrites the CLI change. | `dataplane.rs:924–938` vs `:988–1003` | Silent revert of another admin's committed change. | 3 |
| C10 | **Existing sessions survive policy narrowing.** Per packet, an existing session only checks that its policy ID still exists, is enabled and is `permit`. Narrowing that policy's addresses, ports or apps, or inserting a deny above it, does not cut sessions already open. | `dataplane.rs:1411–1430`, `:1530–1547` | A revoked path stays open for the life of the session (up to the established timeout). | 3 |

## 4. Other findings

| # | Finding | Evidence | Stage |
| --- | --- | --- | --- |
| M1 | Traffic and security logs are an in-memory ring of 200 lines; no persistence or export (syslog/file). | `dataplane.rs:855` | 3 or 5 |
| M2 | ~~CLI config changes are not audited.~~ **Retracted 2026-11-19:** every CLI command is audited as `cli.command` (`cli.rs`, native and vendor styles). | `cli.rs:101–110` | — |
| M3 | Rollback history is 20 revisions in memory, lost on restart; on-disk backups are written but rollback does not use them. | `dataplane.rs:1005–1030` | 3 |
| M4 | The CLI transport has no TLS. Safe while bound to loopback (the default), but nothing warns or refuses when `cli_bind` is set to a non-loopback address. | `cli.rs`; `model.rs:705` | 2 |
| M5 | Login throttling is per username only; spraying many usernames is limited only by the per-IP API rate limit. | `auth.rs:576–607` | 7 |
| M6 | TLS inspection engine is not in the packet path; only CA generation is wired (`main.rs:346`). Matches the checklist. | `tls_inspect.rs`; `main.rs:346` | 5 |
| M7 | Several `sessions.lock()` calls per packet on the IPv4 path. Not a bug; a likely hot-path cost for Stage 7 benchmarks. | `dataplane.rs:1402–1500` | 7 |

## 5. Feature matrix

Legend — **In path:** enforced on live traffic. **Tested:** unit tests exist and passed in this audit (integration not run). **Fail-safe:** behaves safely when it or its dependency fails.

| Feature | Exists | In path | Tested | Fail-safe | Status |
| --- | --- | --- | --- | --- | --- |
| AF_PACKET IPv4 forwarding | Yes | Yes | Unit | **No** (C1, C2) | Partial |
| IPv6 forwarding (NDP, ICMPv6, stateful TCP) | Yes | Yes | Unit | **No** (C1) | Partial |
| Default deny / default intrazone-interzone rules | Yes | Yes | Unit | Yes | Implemented |
| Stateful TCP (SYN-only creation, per-state timeouts, INVALID drop) | Yes | Yes | Unit | Yes | Implemented; no sequence-window checks |
| Session revalidation on policy change | Partial | Partial | Unit | **No** (C10) | Partial |
| Fragments | Dropped | Yes | Unit | Yes (drop) | Not implemented (by design today) |
| VLAN tags | No | — | — | — | Not started |
| SNAT / PAT / DNAT (IPv4) | Yes | Yes | Unit | Yes | Implemented |
| NAT66 / IPv6 DNAT | No | — | — | — | Not started |
| Static routes, LPM | Yes | Yes | Unit | Yes | Implemented |
| App-ID (content-based, 4 KB reassembly, `application-default`) | Yes | Yes | Unit | Yes | Implemented within stated limits |
| User-ID (IPv4) | Yes | Yes | Unit | Yes | Implemented |
| User-ID (IPv6) | No | — | — | **No** (C5) | Not started; bypass risk |
| URL filtering (Host/SNI) | Yes | Yes | Unit | Yes | Partial (host level only) |
| IPS / AV (literal signatures, per packet) | Yes | Yes | Unit | Yes | Partial (no stream matching; "AV" is signature matching only) |
| DNS security | No | — | — | — | Not started |
| TLS inspection | Engine only | No | Unit | — | Partial (not wired) |
| DoS: SYN/UDP flood, session limits (IPv4) | Yes | Yes | Unit | Yes | Implemented |
| DoS (IPv6) | No | — | — | **No** (C6) | Not started |
| nftables backend (IPv4 L3/L4, NAT, `inet vela`, atomic) | Yes | Only via `nft-apply` | Unit | **No** (C4) | Partial |
| nftables IPv6 | No | — | — | — | Not started |
| Candidate / commit / diff / rollback (GUI, FortiOS, PAN-OS) | Yes | Yes | Unit | **No** (C9) | Partial |
| Native CLI policy changes | Yes | Yes | — | **No** (C7, C8) | Partial |
| Truthful health / enforcement status | No | — | — | **No** (C3) | Not started |
| Auth: Argon2, sessions, tokens, RBAC, login throttle, API rate limit, body limit | Yes | Yes | Unit | Yes | Implemented |
| Management TLS (GUI/API) | Yes, default on | Yes | Unit | Yes | Implemented |
| Audit log | Yes (GUI) | — | Unit | Partial (M2) | Partial |
| Traffic / security logs | Yes (200-line ring) | — | — | Partial (M1) | Partial |
| WireGuard (IPv4) | Yes | Yes | Unit + boringtun interop | Yes | Implemented |
| HA active-passive | Yes | Yes | Unit | Not assessed | Implemented (IPv4 sessions only) |
| FortiOS / PAN-OS CLI styles | Yes | — | Unit | — | Implemented |
| GUI | Read-only views + raw editor | — | Partial | — | Partial (see prompt Section 10.2) |

## 6. Master-prompt Section 2 facts

| Prompt claim | Result |
| --- | --- |
| File inventory and line counts | Confirmed at `8312f73` |
| No separate NAT/routing/conntrack/IPS/logging modules | Confirmed; logic is in `dataplane.rs` and `model.rs` |
| ~134 unit tests | Confirmed: exactly 134, all passing |
| nftables uses nfnetlink, owns only `inet vela`, atomic batch | Confirmed (`nft.rs:1–7`) |
| nftables IPv4-only, IPv6 left to userspace | Confirmed (`nft.rs:498`, `:548–550`) |
| GUI/CLI bind loopback by default; Argon2 in use | Confirmed (`model.rs:705–706`; `auth.rs:630–639`) |
| Management TLS | **Correction:** TLS is on by default (`model.rs`, `tls: true`); the checklist marks it `[ ]` |
| TLS inspection not in the packet path | Confirmed |
| Checklist scored against `phase1-5.txt` and inconsistent | Confirmed (see Section 7) |
| New finding not in the prompt | C1 (kernel forwarding fail-open) and C5/C6 (IPv6 policy and DoS gaps) |

## 7. Checklist rebase plan

`NGFW_CHECKLIST.md` has 659 lines: 229 `[x]`, 78 `[~]`, 194 `[ ]`.

1. **Mark Superseded** (from `phase1-5.txt`, contrary to the lightweight rule): Docker Compose (lines 31, 451, 550), Tokio (38), Axum (39), SQLx/SQLite (42), Tracing (43), OpenAPI (383, 556), React/TypeScript/Vite UI (547), separate engine crates (Section 3 list).
2. **Mark Deferred:** NFQUEUE (48, 193), kernel conntrack integration (47), eBPF/XDP (49), all OpenFlow/SDN items.
3. **Fix contradictions:** line 44 Rustls/TLS `[ ]` → `[x]`; lines 46 and 134 nftables `[ ]` → `[~]` (IPv4 only, not integrated with the daemon); line 93 IPv6 filtering `[x]` → `[~]` (no User-ID, DoS or NAT on IPv6).
4. **Add** C1–C10 as open items so the checklist reflects enforcement safety, not just features.
5. Replace the three states with the prompt's five: Implemented and verified · Partial · Planned · Superseded · Not started.

## 8. Proposed Stage 2 scope

In order:

1. Run the four integration scripts on a privileged Linux host; record results in `EVIDENCE.md`.
2. **C1:** at startup, refuse to start (or force `ip_forward=0` and `ipv6 forwarding=0` on dataplane interfaces, per a config switch) when kernel forwarding would bypass the engine; re-check periodically; report `degraded` if it changes.
3. **C2 + C3:** per-interface enforcement state; any configured interface not attached → `degraded`; real health endpoint with saved / committed / applied / verified / degraded.
4. **C4:** daemon-managed nftables mode with mutual exclusion from AF_PACKET forwarding, verification read-back, rollback and drift detection; `nft-apply` kept as a diagnostic tool that refuses to run while the daemon is enforcing.
5. **C5 + C6:** until IPv6 User-ID and DoS exist, reject at commit any config whose user-scoped or DoS-dependent policies would also match IPv6 traffic, with a clear error. Regression test for each.
6. **M4:** refuse a non-loopback `cli_bind` without TLS, or warn loudly at startup.
7. Feature-toggle zero-cost-off measurement (prompt 4.2).


## 9. Open questions for the maintainer

1. For C1, should the daemon **refuse to start** when kernel forwarding is on, or **set it to 0** itself? Setting sysctls in a shared netns can break other workloads; refusing is the safer default.
2. For C5/C6, is rejecting IPv6-affecting user/DoS policies at commit acceptable until those features exist, or should IPv6 be disabled entirely when such policies are present?
3. Which host will run the privileged integration tests (your machine, CI, a VM)?

## 10. Status on branch `stage2-enforcement-safety` (2026-11-19)

| # | Status | What changed | Test |
| --- | --- | --- | --- |
| C1 | Fixed | Startup refuses the dataplane while IPv4/IPv6 kernel forwarding is on (global or per interface); `system kernel-forwarding warn` starts degraded; 5 s monitor. Lab topologies and the netns script now also disable IPv6 forwarding. | `c1_kernel_forwarding_problems_are_detected` |
| C2 | Fixed | Missing or unopenable interfaces recorded as enforcement problems. | `c2_c3_enforcement_problems_report_degraded_state` |
| C3 | Fixed | `/healthz` returns 503 `degraded` with problems (details for authenticated callers); `/api/v1/system` has `enforcement`. | same |
| C4 | Fixed (Stage 2b) | Daemon holds `<config>.lock`; `nft-apply` refuses while it is held. `system dataplane kernel` makes nftables daemon-managed: AF_PACKET closed, exact-or-refused plan, verified installs, restore/lockdown on failure, drift repair. | `nft::tests::*` exactness/verify tests; `engine_tests::kernel_*`, `drift_*`; `tests/kernel-mode.sh` (not yet run) |
| C5 | Fixed | User-scoped rules fail closed for IPv6 sources. | `c5_user_scoped_rules_fail_closed_for_ipv6_sources` |
| C6 | Fixed | IPv6 SYN/UDP/ICMP zone flood limits, sharing IPv4 counters. | `c6_ipv6_syn_flood_limit_applies_and_shares_the_ipv4_counter` |
| C7 | Fixed | Native CLI `policy add/delete` use the commit path (history, revision, save before activation). | `c7_native_cli_policy_changes_use_the_commit_path` |
| C8 | Retracted | — | — |
| C9 | Fixed | Serialized commits with base-revision checks: GUI/REST (`X-Config-Revision` / `X-Config-Base`, 409), native CLI, FortiOS drafts, PAN-OS candidates. | `c9_stale_candidate_and_stale_edits_are_refused`, `c9_draft_older_than_running_is_refused_on_next`, `c9_candidate_older_than_running_is_refused_at_commit` |
| C10 | Fixed | IPv4 and IPv6 sessions carry the revision they were checked against and are re-evaluated after a commit. | `c10_*` (4 tests) |
| M4 | Fixed | Non-loopback CLI bind refused unless `system cli-remote-plaintext on`. | settings round-trip test |
| M1, M3, M5, M6, M7 | Open | — | — |

`cargo test --release`: 147 passed, 0 failed. A deliberate-breakage run (fixes disabled) failed 7 of the new tests, confirming they guard the fixes. Integration scripts still need a privileged host.

### Stage 2b addendum: silent weakening found in the existing kernel backend

While implementing kernel mode, two pre-existing problems in `nft.rs` were found and fixed:

| # | Finding | Impact | Fix |
| --- | --- | --- | --- |
| C11 | Permits with URL/IPS/AV/shaper/profile-group profiles, and user-scoped permits, were translated into plain `accept` rules. | Kernel mode would forward traffic the userspace engine inspects or restricts. | `kernel_problems` refuses them. |
| C12 | IPv6 prefixes and unrepresentable services in a **deny** were dropped from the plan, so the deny vanished and a later permit matched. | Access widened in kernel mode. | `kernel_problems` refuses such denies. |
