# Verification checklist — NetworkSandbox Firewall

This file is for a **reviewer** (a person or another LLM) checking that each
stage of the master prompt was really done. It is not the feature list (that is
`NGFW_CHECKLIST.md`) and not the audit (`AUDIT.md`).

## How to use this file

1. Work from the repository root, on the branch under review. Run every
   command yourself. **Never mark a check PASS without running it in this
   session**; paste the command and the relevant output line as evidence.
2. Do the global checks (G) first, then the checks for the stage under review.
   Checks marked **[root]** need a privileged Linux host (root, network
   namespaces, nftables, containerlab); if you cannot run them, mark them
   `NOT RUN`, never `PASS`.
3. For every FAIL, follow **If it fails**, and read the cited prompt section
   before changing anything. The prompt is the authority on *what* must be
   true; the code is the authority on *what is* true. If they disagree, report
   the contradiction rather than forcing one to match the other (prompt §0).
4. Finish with the report template at the end of this file.

### Where the prompt is

`Master Engineering Prompt — NetworkSandbox Firewall (NGFW) v2` (maintainer's
Claude Doc). Export it as Markdown to `firewall/docs/MASTER_PROMPT.md` so
reviewers can read it; until then the rule each check enforces is quoted
below. Section numbers (§) refer to that prompt:

| § | Topic | § | Topic |
| --- | --- | --- | --- |
| 0 | How to run stages | 7 | Core NGFW features |
| 2 | Ground truth of the repo | 8–9 | SDN / OpenFlow — **deferred, must not be implemented** |
| 3 | Non-negotiable principles | 10 | Management plane, GUI–CLI parity |
| 4 | Enablement model, dataplane modes | 11 | Performance |
| 5 | nftables backend (mode B) | 12 | Testing |
| 6 | Configuration lifecycle | 13–16 | Docs, stages, strict rules, report format |

### Baselines

| Point | Commit / branch | `cargo test --release` |
| --- | --- | --- |
| Before any stage | `8312f73` | 134 passed |
| After Stage 2a (enforcement safety) | `f94280d` on `stage2-enforcement-safety` | 147 passed |
| After Stage 2b (kernel dataplane) | `stage2-kernel-dataplane` | 165 passed |
| After Stage 6 (GUI) | `stage6-gui` | 175 passed; `node tests/ui-model.test.js` passes |

A later stage must never have **fewer** passing tests than the previous row.

---

## G — Global checks (run for every stage)

Run from the repository root. Each command is safe to copy as is.

```sh
cd firewall
# G1  builds with no warnings                         expect: 0
cargo build --release 2>&1 | grep -c '^warning'
# G2  all tests pass                                  expect: ok. N passed; 0 failed  (N >= last baseline)
cargo test --release 2>&1 | grep '^test result'
# G3  no test removed or ignored                      expect: count >= last baseline, then no output
cargo test --release -- --list 2>/dev/null | grep -c ': test$'
grep -rn '#\[ignore\]' src
cd ..
# G4  switch untouched (prompt §1, §15)               expect: no output
git diff --stat 8312f73..HEAD -- switch/
# G5  no SDN/OpenFlow code (§8-9 deferred, §15)       expect: 0
grep -rniE 'openflow|ofpt_|of_controller' firewall/src | wc -l
# G6  dependencies (§3.8)                             expect: the same 16 crates as 8312f73, or each new one justified
git diff 8312f73..HEAD -- firewall/Cargo.toml
# G7  evidence recorded (§12, §13)                    expect: a row for this stage; privileged scripts marked run or not run
tail -20 firewall/EVIDENCE.md
```

- **G8 — claims match evidence (§3.9):** for each line changed in
  `NGFW_CHECKLIST.md` in this stage, every new `[x]` names a test that exists
  (`cargo test --release -- --list` lists it).
- **G9 — tests really guard the change:** for each fix, break it on purpose
  (for example make the guard `return true`), run its test, then restore. The
  test must fail while broken and pass after the restore.

**If G1–G3 fail:** fix the code, never the test, unless the test is provably
wrong — then say so in the stage report (§15: "do not remove, skip or weaken
tests"). **If G4/G5 fail:** revert those changes; switch and SDN work belong to
other prompts. **If G6 fails:** remove the dependency or add a measured
justification (§3.8, §11). **If G7/G8 fail:** correct the docs to say exactly
what ran; downgrade `[x]` to `[~]` where a test is missing. **If G9 fails:**
the test does not cover the fix; strengthen it until breaking the fix breaks
the test.

---

## Stage 1 — Audit (read-only) — DONE

Prompt rule (§0, §14): Stage 1 changes no source file; it writes
`firewall/AUDIT.md`, records baseline tests and plans the checklist rebase.

| # | Check | How | Expected |
| --- | --- | --- | --- |
| 1.1 | Audit exists | `test -f firewall/AUDIT.md` | present |
| 1.2 | Baseline recorded | `grep -n '134 passed' firewall/AUDIT.md firewall/EVIDENCE.md` | both |
| 1.3 | Findings cite evidence | read `AUDIT.md` §3–4 | every finding has file:line evidence |
| 1.4 | Retractions are explicit | `grep -n Retracted firewall/AUDIT.md` | C8 and M2 retracted with reasons |
| 1.5 | Checklist rebased (§13) | `grep -cF -- '- [s]' firewall/NGFW_CHECKLIST.md` | Tokio/Axum/SQLx/React/Compose items marked superseded |

**If it fails:** re-run the audit read-only, add the missing evidence, and do
not mix code changes into Stage 1.

---

For every `cargo test --release <filter>` below, the expected output is
`test result: ok. <n> passed; 0 failed` with the count given.
Run them from `firewall/`.

## Stage 2a — Enforcement safety — DONE (unit-tested; integration NOT RUN)

Prompt rules: fail closed (§3.2), one authoritative path (§3.3), truthful
status (§3.4), §4.3.

| # | Finding | Check | Expected |
| --- | --- | --- | --- |
| 2a.1 | C1 kernel forwarding bypass | `cargo test --release c1_kernel_forwarding` | 1 passed |
| 2a.2 | C1 refusal wired at startup | `grep -n 'refusing to start the dataplane' firewall/src/main.rs` | present, guarded by `!kernel_mode` |
| 2a.3 | C1 labs updated | `grep -n 'ipv6.conf.all.forwarding: 0' firewall/*.clab.yml` | in both topologies |
| 2a.4 | C2/C3 truthful health | `cargo test --release c2_c3` | 1 passed |
| 2a.5 | C3 503 when degraded | `grep -n '503' firewall/src/gui.rs` | health route returns 503 when problems exist |
| 2a.6 | C4 lock | `grep -n 'daemon_lock' firewall/src/main.rs` | taken by daemon, checked by `nft-apply` |
| 2a.7 | C5 IPv6 user rules fail closed | `cargo test --release c5_` | 1 passed |
| 2a.8 | C6 IPv6 flood limits | `cargo test --release c6_` | 1 passed |
| 2a.9 | C7 CLI through commit path | `cargo test --release c7_` | 1 passed |
| 2a.10 | C9 stale edits refused | `cargo test --release c9_` | 3 passed (engine, FortiOS, PAN-OS) |
| 2a.11 | C10 sessions re-checked | `cargo test --release c10_` | 4 passed |
| 2a.12 | M4 plaintext CLI | `grep -n 'cli-remote-plaintext' firewall/src/main.rs` | non-loopback bind refused unless set |
| 2a.13 **[root]** | Integration | `sudo bash firewall/tests/network-namespace.sh` | all PASS; record in `EVIDENCE.md` |
| 2a.14 **[root]** | Integration | containerlab policy and chain tests (README "Tests") | all PASS; record in `EVIDENCE.md` |

**If it fails:** 2a.1–2a.12 → see `AUDIT.md` §10 for the intended fix of each
finding. 2a.13–2a.14 → the most likely cause is the new fail-closed default:
check the daemon log for `refusing to start the dataplane`, and make the test
topology disable `net.ipv4.ip_forward` and `net.ipv6.conf.all.forwarding`
rather than setting `system kernel-forwarding warn`.

---

## Stage 2b — Daemon-managed kernel dataplane — DONE (unit/fake-tested; real kernel NOT RUN)

Prompt rules (§4.3, §5, §3.5): explicit opt-in; capability check; atomic
apply; verification by read-back; restore the last verified ruleset on
failure; startup reconciliation; external-modification detection; documented
shutdown; **no silent weakening** — anything not exactly enforceable is
refused.

| # | Check | Command | Expected |
| --- | --- | --- | --- |
| 2b.1 | Opt-in setting | `grep -n '"dataplane" =>' firewall/src/model.rs` | `userspace` (default) or `kernel` |
| 2b.2 | One path: AF_PACKET closed in kernel mode | `grep -n 'enforcing && !kernel_mode' firewall/src/main.rs` | `engine.run` and the forwarding monitor only start in userspace mode |
| 2b.3 | Exact or refused | `cargo test --release nft::tests` | all pass, including `inspection_profiles_are_refused_not_weakened`, `deny_with_ipv6_parts_is_refused_because_it_would_widen`, `deny_with_unrepresentable_service_is_refused`, `user_scoped_rules_are_refused`, `userspace_only_features_are_refused` |
| 2b.4 | Rules tagged | `cargo test --release every_rule_gets_a_unique_generation_tag` | 1 passed |
| 2b.5 | Read-back parser | `cargo test --release dump_` | 2 passed |
| 2b.6 | Verification detects drift | `cargo test --release verify_detects` | 1 passed (missing, foreign, reordered, policy change, extra chain) |
| 2b.7 | Commit: restore on failure | `cargo test --release kernel_failure_restores` | 1 passed |
| 2b.8 | Commit: lockdown when restore fails | `cargo test --release when_restore_also_fails` | 1 passed |
| 2b.9 | Startup reconcile / lockdown | `cargo test --release -- kernel_mode_starts kernel_startup_failure` | 2 passed |
| 2b.10 | Drift repaired | `cargo test --release drift_is_detected` | 1 passed |
| 2b.11 | Refused before kernel touched | `cargo test --release inexact_configurations` | 1 passed |
| 2b.12 | Rollback keeps history on failure | `cargo test --release kernel_mode_rollback` | 1 passed |
| 2b.13 | Mode change needs restart | `cargo test --release switching_dataplane_mode` | 1 passed |
| 2b.14 | Ownership limited to `inet vela` (§5.1) | `grep -n 'pub const TABLE' firewall/src/nft.rs` and read `plan_inner`, `destroy_table`, `install_lockdown` | only the `vela` table is created or destroyed |
| 2b.15 | Shutdown documented (§5.2) | `grep -n 'Shutdown' firewall/README.md` | table persists on exit; `nft-remove` deletes it |
| 2b.16 **[root]** | Real kernel end to end | `cd firewall && cargo build --release && sudo bash tests/kernel-mode.sh` | every line `PASS:` and `kernel-mode: all checks passed`; record in `EVIDENCE.md` |
| 2b.17 **[root]** | Existing backend test still passes | `sudo bash firewall/tests/nft-kernel.sh` | all PASS |
| 2b.18 **[root]** | Operator tooling works | `sudo nft list table inet vela` while kernel mode runs | lists cleanly; each rule shows `comment "vela:<16 hex>:<n>"` |

**If it fails:**
- 2b.3 → a feature reaches the kernel plan without being exact. Add it to
  `nft::kernel_problems` (refuse), never translate it into a looser rule (§3.5).
- 2b.16 *"startup"* → netlink dump or verification fails on a real kernel.
  Check `dmesg` and the daemon log. Compare `nft --debug=netlink list table inet
  vela` with `parse_chain` / `parse_rule` in `nft.rs` (attribute numbers:
  rule TABLE=1, CHAIN=2, USERDATA=7; chain TABLE=1, NAME=3, HOOK=4,
  POLICY=5). Fix the parser and add a unit test with the real bytes.
- 2b.16 *"drift not repaired"* → the monitor thread (main.rs, kernel mode)
  is not running or `kernel_reconcile` cannot take `commit_lock`.
- 2b.17/2b.18 → if `nft list` errors on user data, the tag is not a valid
  comment TLV (`[0, len, text…, 0]`, see `plan_tagged`).
- 2b.16 *"nft-apply"* → the daemon lock is not held in kernel mode.

---

## Stage 2 — still open (NOT DONE)

These §4–§5 items were not implemented; a reviewer must report them as open,
not as failures of the work above.

| # | Item | Prompt | What to do |
| --- | --- | --- | --- |
| 2o.1 | Feature toggles cost nothing when off, measured | §4.2 | Benchmark per-packet cost with all toggles off vs `8312f73`; record in `EVIDENCE.md` |
| 2o.2 | nftables IPv6 matching and NAT | §5.2 | Translate `Cidr6` with `nfproto` guards; then lift the IPv6-in-deny refusal; extend `nft-kernel.sh` |
| 2o.3 | Kernel counters into policy hit counters | §5.2 | Read rule counters in the dump; map by tag to policy ids |
| 2o.4 | "Needs Rust" handoff design (NFQUEUE) | §5.3 | Proposal only, fail-closed without `queue-bypass`; until then refusal stays |

---

## Stage 3 — Configuration lifecycle — PARTIAL

Done in 2a: one serialized commit path; base-revision checks (409); CLI through
the pipeline; save before activate; kernel before save in mode B.

| # | Item | Prompt | Status / check |
| --- | --- | --- | --- |
| 3.1 | Commit never reported enforced before verification | §6, §14 | kernel mode: covered by 2b.7–2b.8; userspace: add a test that a failed apply is never reported as enforced |
| 3.2 | Separate statuses saved / validated / committed / applied / verified / degraded | §6 | OPEN: expose per-commit status in API, GUI and CLI |
| 3.3 | Rollback to any retained version; history survives restart | §6 | OPEN: history is 20 entries in memory (AUDIT M3) |
| 3.4 | Config format migration test | §6 | OPEN: no format change yet; required with the first one |
| 3.5 | Persistent traffic/security logs | AUDIT M1 | OPEN |

**If it fails / when doing it:** build on `Engine::kernel_then_save`,
`apply_config_from` and `commit_lock`; do not add a second pipeline (§6).

---

## Stage 4 — SDN / OpenFlow — DEFERRED

Check only that nothing was implemented: G5 must pass. **If it fails:** remove
the code (§15).

## Stage 6 — GUI parity — DONE (jsdom-tested; real browser NOT CHECKED)

Prompt rules (§10): the GUI does everything the CLI does for routine
configuration, through the same REST API and commit pipeline; stays a
lightweight vanilla-JS UI embedded in the binary; every status comes from
runtime state.

```sh
cd firewall
# 6.1 editor + GUI edit path unit tests                 expect: 7 passed, then 3 passed
cargo test --release editor::
cargo test --release gui_edits
# 6.2 every object kind round-trips through the forms   expect: "47 objects round-tripped across 22 kinds"
node tests/ui-model.test.js
# 6.3 strict CSP, no inline code                         expect: script-src 'self'; and 0
grep -o "script-src [^;]*" src/gui.rs
grep -c -E 'onclick=|style=' src/ui/index.html
# 6.4 no HTML parsing of data                            expect: :0 for both files
grep -c -E 'innerHTML|outerHTML|insertAdjacentHTML|document.write' src/ui/app.js src/ui/model.js
```

| # | Check | How | Expected |
| --- | --- | --- | --- |
| 6.5 | Real UI end to end | start `firewall daemon --config tests/fixtures/ui-sample.conf --dry-run` with `VELA_ADMIN_PASSWORD` set, `npm install jsdom@24`, then `VELA_PASSWORD=… node tests/ui-e2e.js` | `ui-e2e: all checks passed` (11 PASS lines) |
| 6.6 | Parity with §10.2 | open each page listed in README "Web GUI" | every §10.2 row is editable or explicitly view-only (VPN keys, HA settings, interface add/remove) |
| 6.7 | Real browser (manual) | open the GUI in Firefox and Chrome, light and dark mode | no console errors; dialogs open and close; tables scroll; layout usable at 1280px and on a phone width |

**If it fails:** 6.2 → a kind's `build()` no longer matches `Config::to_text`
(option order or normalisation changed): fix `src/ui/model.js`, never loosen
the test. 6.3/6.4 → remove the inline code or HTML parsing (§10.1). 6.5 →
read the FAIL line; most UI failures are a page throwing during render (look
for "Could not load this page") or a form field id mismatch (`#f-<key>`).
6.7 → if `<dialog>` misbehaves, check `modal()` in `app.js`.

## Stages 5 and 7 — NOT STARTED

When a stage is done, add a section here in the same shape (rule, checks with
commands and expected output, *If it fails*). Minimum checks:

| Stage | Must show |
| --- | --- |
| 5 — Core NGFW (§7) | each feature in the packet path with an engine test (synthetic frames), malformed-input tests for every new parser, bounded buffers, `NGFW_CHECKLIST.md` updated honestly |
| 7 — Performance and docs (§11, §13) | committed benchmark scripts, numbers in `EVIDENCE.md`, no comparison claims without them, README commands that actually work |

---

## Reviewer report template

```text
Stage reviewed:        <e.g. 2b>
Branch / commit:       <git rev-parse --short HEAD>
Environment:           <OS, kernel, rustc, root yes/no>

Global:   G1 PASS|FAIL  G2 ... G9   (paste command + key output line each)
Stage:    <id> PASS|FAIL|NOT RUN   evidence: <command + output line>
          ...
Failures: <id>: what failed, prompt §, action taken or recommended
Open items carried forward: <list>
Contradictions between prompt and code: <list or none>
Verdict:  ACCEPT | ACCEPT WITH OPEN ITEMS | REJECT
```
