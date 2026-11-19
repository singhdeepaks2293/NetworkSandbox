# Evidence and clean-room notes

This project is an original implementation. No vendor source code, binaries,
configuration files or assets were copied into it. A firmware image was
examined only to understand which behaviors are worth modeling and to record
observable facts below.

## Artifacts examined

| Artifact | SHA-256 |
| --- | --- |
| `FGT_VM64_KVM-v8.0.2.F-build0251-FORTINET.out.kvm.zip` | `9d24eb3bf0a686f26c498ecad4a7057d814a2d280bc576b86cbf4b3dee7c4559` |
| Extracted qcow2 disk | `3e0957b2ae5a993ea6af4ab8d0e038dcee8550d2391f8353fe731493832494aa` |
| Extracted `datafs2.tar.gz` | `06190f7c6f1bd54420e879a1e9f2a1ab7079fc91fea0c10ae24a88a335e15003` |
| Extracted `flatkc2` kernel | `74ce0403272248fcb752855361310a85cd7a94c4463871637a57963e1dc09339` |

Observations were made with standard unpacking, hashing and read-only parsing
tools. Nothing from the image is executed by this project or shipped with it.

## Observed behavior used as inspiration

- Policies combine source/destination zones and addresses, services,
  applications, security profiles and NAT, and are evaluated in order.
- Configuration is organized as named objects (addresses, address groups,
  services, profiles) referenced by policy rules.
- Logging can be emitted as text or structured JSON.
- Security profiles attach inspection to permitted flows rather than to
  interfaces, so a rule can permit a flow and still block a matching URL,
  signature or file pattern.

These are functional ideas. All names, parsing, data structures, packet
handling and tests in this repository were written from scratch.

## Deliberate differences

- A single small policy table with first-match by ascending id instead of
  vendor-specific rule bases and implicit rules.
- URL/IPS/AV inspection is stateless per packet and based on literal patterns.
- No vendor configuration syntax, object model, CLI hierarchy or GUI assets
  are reproduced.
- Partitioning is a small original VDOM-like model: one flat configuration file
  with `vdom` sections, shared named objects, and no administrative VDOM
  contexts, inter-VDOM links or per-VDOM management roles.

## Recorded test runs

| Date | Commit / branch | Command | Result |
| --- | --- | --- | --- |
| 2026-11-19 | `8312f73` (baseline) | `cargo test --release` (rustc 1.91.1) | 134 passed, 0 failed |
| 2026-11-19 | `stage2-enforcement-safety` | `cargo test --release` (rustc 1.91.1) | 147 passed, 0 failed (13 new regression tests) |
| 2026-11-19 | `stage2-enforcement-safety`, fixes disabled on purpose | `cargo test --release` | 7 of the new tests failed as expected (C10 ×4, C2/C3, C6, C5), confirming they guard the fixes; fixes then restored |

| 2026-11-19 | `stage2-kernel-dataplane` | `cargo test --release` | 165 passed, 0 failed (18 new: exactness, tagging, netlink parse, verify, fake-backend kernel mode) |
| 2026-11-19 | `stage2-kernel-dataplane`, guards disabled on purpose | `cargo test --release` | verify off, classifier off, restore off: 8 tests failed; drift repair off: 1 test failed; all restored to 165/165 |

| 2026-11-20 | `stage6-gui` | `cargo test --release` | 175 passed, 0 failed (10 new: editor module, GUI edit path, kernel-mode edit refusal) |
| 2026-11-20 | `stage6-gui` | `node tests/ui-model.test.js` | 47 objects across 22 kinds round-tripped byte-identically |
| 2026-11-20 | `stage6-gui` | `node tests/ui-e2e.js` (jsdom 24, daemon `--dry-run` on `tests/fixtures/ui-sample.conf`) | 12 PASS: login, 27 pages render, create/edit/reorder via forms, inline and server validation errors, diff + commit (collapsed context, full-diff toggle, up-to-date status), policy match, change markers (new, changed, deleted, disabled), HTML injection rendered as text, discard, read-only role (no controls, 403), CSRF enforced |

| 2026-11-20 | `stage6-gui` | `cargo +1.85 build --release --locked` | FAILED, also at baseline `8312f73`: locked `time 0.3.55` (via rcgen) needs Rust 1.88; the Dockerfile's `rust:1.85-alpine` could not build the image |
| 2026-11-20 | `stage6-gui` | `cargo +1.89 build --release --locked` and `cargo +1.89 test --release --locked` | built; 175 passed, 0 failed → Dockerfile moved to `rust:1.89-alpine`, `rust-version = "1.89"` |

Not yet run on this branch: `tests/network-namespace.sh`, `tests/nft-kernel.sh`,
`tests/containerlab-policy.sh`, `tests/containerlab-chain.sh`, and the new
`tests/kernel-mode.sh` (written in Stage 2, never executed). The GUI has not
been checked in a real browser (only jsdom): visual layout, dark mode and
`<dialog>` behaviour need a manual look. `docker build` has not been run
(no Docker in that environment, and the musl/Alpine build is untested): run
`make image` and record the result. They need root,
network namespaces and containerlab, which the environment used for these runs
did not have. Run them on a privileged Linux host and add the results here
before merging.
