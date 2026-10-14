# Third-party notices and public-source scope

The root MIT license covers this public tree's original capx code. It does not replace licenses on third-party files or create rights to distribute proprietary runtimes.

- CryptoJS is included in `capx-desktop/frontend/dist/crypto-js.min.js`. Copyright (c) 2009–2013 Jeff Mott and (c) 2013–2016 Evan Vosberg; MIT. The original license is in `third-party/CryptoJS-LICENSE.txt`. [Upstream license](https://github.com/brix/crypto-js/blob/develop/LICENSE).
- MinHook and its HDE components are included as source under `capx/internal/hook/native/minhook`. Copyright and redistribution notices remain in each source file; the complete original notice including HDE terms is in `third-party/MinHook-LICENSE.txt`, with additional per-file notices in `third-party/MinHook.txt` and `third-party/HDE.txt`.
- GitHub-compiled binaries/static libraries may incorporate Go and Rust standard libraries. `third-party/Go-LICENSE.txt`, `Rust-LICENSE-MIT.txt`, `Rust-LICENSE-APACHE.txt` and `Rust-COPYRIGHT.txt` preserve the corresponding upstream notices. Source-only repository uploads do not contain those compiled libraries.
- Wails generated bindings/runtime and Go dependencies retain their upstream licenses. Module/version inventory and available cache license copies are in `third-party/go-modules.json` and `third-party/go/`. Go dependency implementation source is downloaded by Go, not vendored in this repository. Before distributing a binary, include licenses for its actual dependencies, including any platform-specific optional modules.

The private workspace's F12 Frida agent, WeChat version-offset tables and private protobuf debug bridge are excluded. Their attribution referred to e0e1-wx / wx-hook / WMPFDebugger, whose permissions and compatibility were not fully established. WMPFDebugger's published license is [GPL version 2](https://github.com/evi0s/WMPFDebugger/blob/main/LICENSE). This public tree uses a separately authored standard CDP client and does not redistribute or automatically install those components. Users obtain any external provider independently under its own terms.

No WeChat installer/client, Npcap runtime/driver, Frida executable, Python runtime, iOS agent/signing material, device support image, real phone screenshot or pairing identity is included. [Npcap redistribution terms](https://npcap.com/oem/redist) must be checked before any separate binary packaging.

Compatibility with HaE rule formats and DNSLog APIs does not bundle those applications. The internal default rules and integration code remain capx source; third-party rule uploads keep their original terms. The old optional Node miniprogram-automator sidecar is excluded from this release.
