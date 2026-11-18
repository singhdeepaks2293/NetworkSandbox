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
