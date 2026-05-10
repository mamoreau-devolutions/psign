# Roadmap: Authenticode tooling on Linux

The primary `signtool-rs` binary is **Windows-first**: it depends on **`windows`**, **WinVerifyTrust**, **SignerSignEx3**, and OS **CryptSIP** registration. A practical Linux story is **phased**: keep Windows as the reference implementation while carving out **portable** pieces.

**Cross-tool comparison (native signtool vs AzureSignTool vs Artifact Signing vs this repo):** [`gap-analysis-signing-platforms.md`](gap-analysis-signing-platforms.md).

## Phase 0 — CI and hygiene

- **`ci-unix`**: `cargo fmt --check`, `cargo metadata --locked`, **`cargo clippy`** on portable digest + trust crates + **`signtool-rs` lib (`-D warnings`)**, **`cargo test -p signtool-sip-digest --lib`**, **`cargo test -p signtool-authenticode-trust --lib`**, **`cargo check -p signtool-rs`**, **`cargo test -p signtool-rs --lib`** (see `.github/workflows/ci-unix.yml`).
- **Cargo aliases** (repo `.cargo/config.toml`): `cargo digest-check` / `cargo digest-test` expand to the portable digest + **`signtool-authenticode-trust`** crates (no Windows stub binary required); `cargo unix-lib-check` mirrors **`cargo check -p signtool-rs --lib`** (Linux/macOS portable surface); **`cargo windows-bin`** builds the **`signtool-windows`** executable (**`-p signtool-rs --bin signtool-windows`**) because **`default-members`** omit the root crate; **`cargo depgraph`** wraps **`cargo run -p signtool-rs --bin depgraph`** so manifest generation works with **`default-members`**.
- **Workspace `default-members`** (root `Cargo.toml`): a bare **`cargo build`** / **`cargo test`** at the repo root targets **`signtool-sip-digest`**, **`signtool-digest-cli`**, and **`signtool-authenticode-trust`**. Use **`cargo build --workspace`** or **`-p signtool-rs`** when you need the main crate on a Windows checkout.
- **Local Linux/macOS mirror of CI** (from repo root, `--locked` optional but matches CI):  
  `cargo test -p signtool-sip-digest --lib --locked`, `cargo test -p signtool-authenticode-trust --lib --locked`, and `cargo test -p signtool-digest-cli --locked`, or `cargo digest-test`.  
  Install the portable CLI only: `cargo install --path crates/signtool-digest-cli --locked` (binary name **`signtool-portable`**).
- The **`signtool-rs`** **CLI binary** on non-Windows is a **stub** that exits with an explanatory message; **`win`** is behind **`#[cfg(windows)]`** so **`windows`** is not a dependency on Linux.

## Phase 1 — Workspace split: `signtool-sip-digest` (done)

- **`crates/signtool-sip-digest`** holds portable digest modules (**no `windows` dependency**). The Win32 binary re-exports them from **`src/win/sip_rust/mod.rs`** and keeps thin **`sign_*`** helpers that need **`GlobalOpts`**.
- **`ci-unix`** runs **`cargo test -p signtool-sip-digest --lib --locked`** (see `.github/workflows/ci-unix.yml`).
- **CLI:** **`signtool-portable`** (`crates/signtool-digest-cli`, binary name `signtool-portable`) — `pe-digest`, `verify-pe` (digest-only PKCS#7 consistency), **`trust-verify-pe`** / **`trust-verify-cab`** / **`trust-verify-catalog`** / **`trust-verify-detached`** (explicit-anchor trust + picky chain), `pe-has-page-hashes`, `pe-page-hash-info`, `verify-pe-page-hashes`, `pe-authenticode-ranges` (Authenticode digest file segments), `verify-cab`, `verify-msi`, `verify-esd`, `verify-msix`, `verify-catalog`, `verify-script`, `cab-digest`. Runs on Linux/macOS; does **not** call `WinVerifyTrust`.
- **Trust library:** **`signtool-authenticode-trust`** — see **[authenticode-trust-stack.md](authenticode-trust-stack.md)** and **[authroot-linux-verify.md](authroot-linux-verify.md)**.
- Remaining Linux work: optional **revocation**, **PinRules**, and full CryptoAPI policy parity still need dedicated design; digest CLI extras (JSON output, stdin) remain optional.

## Phase 2 — PKCS#7 / CMS utilities without WinTrust

- **Verify-only** paths that parse **Embedded PKCS#7**, **SPC_PE_IMAGE_DATA**, **indirect data**, and **RFC3161** timestamps can live behind **`ring`** / **`cms`** / **`x509-parser`** (already partially aligned via `cms` / `authenticode` crates).
- **Signing** on Linux without a hardware CSP or Windows SIP remains **non-parity** unless integrating **OpenSSL** / **Azure Key Vault** / **pkcs11** — document as **optional backends**, not drop-in `signtool.exe` replacement.

### Stretch: Linux-friendly replacements for AzureSignTool / Artifact Signing

Order-of-effort sketch (each step needs tests + fixtures):

1. **Portable CMS producer** — Finish **`SignedData`** assembly for **PE** (`SpcIndirectData` + **`WIN_CERTIFICATE`** embed) using existing **`pe_digest`** / stubs in [`pkcs7.rs`](../crates/signtool-sip-digest/src/pkcs7.rs) and [`pe_embed.rs`](../crates/signtool-sip-digest/src/pe_embed.rs).
2. **Remote signing adapters on Unix** — Small **`reqwest`** clients mirroring **`azure_kv_sign.rs`** (KV `keys/sign`) and **`artifact_signing_rest.rs`** (codesigning `:sign` LRO) behind Cargo features, emitting **raw signature bytes** for step (1).
3. **Additional embedders** — CAB, MSI streams, MSIX ZIP manipulation (hardest: **`AppxSipCreateIndirectData`**-equivalent APPX blob + publisher binding rules).
4. **RFC3161 request/sign** — Replace stub [`timestamp.rs`](../crates/signtool-sip-digest/src/timestamp.rs) for post-sign or nested countersignatures.

Until Phase 2 completes, **verify-first Linux CI** remains the supported story; **production signing** stays on **`signtool-windows`** (or native **`signtool.exe`**).

## Phase 3 — Container formats that are OS-agnostic

Already aligned in Rust for **cleartext** subjects:

- **MSIX / APPX / bundles** (ZIP layout) — `sip_rust::msix_digest` (encrypted **Eappx** stays out of scope without Windows crypto). **`signtool-portable verify-msix`** exercises the same portable ZIP/hash path on Linux; **manifest publisher vs PKCS#7 signer** enforcement remains **`AppxSip`** / **`SignerSignEx*`** on Windows.
- **MSI** OLE tree — `sip_rust::msi_digest`.
- **ESD / WIM** prefix hash — `sip_rust::esd_digest`.
- **PE / CAB / catalog** digests — pure byte/layout algorithms; **deployment policy** still differs without WinTrust.

## Environment variables — portable CLI vs Windows binary

| Surface | `SIGNTOOL_RS_*` / related | Notes |
|---------|---------------------------|--------|
| **`signtool-portable`** (Linux/macOS) | None required | Subcommands take **paths on the argv** only (`verify-pe`, **`trust-verify-pe`** + **`--anchor-dir` / `--authroot-cab`**, `verify-msix`, …). |
| **`signtool-rs` stub** (non-Windows) | N/A | Stub exits before Win32; env vars from parity docs do not apply. |
| **`signtool-rs` on Windows** | **`SIGNTOOL_RS_RUST_SIP`**, **`SIGNTOOL_PAGE_HASHES`** (via **`--no-page-hashes`**) | Post-sign Rust SIP digest gates and **`SignerSignEx3`** page-hash hint — see [`signtool-cli-matrix.json`](signtool-cli-matrix.json), [`rust-sip-architecture.md`](rust-sip-architecture.md). |
| **Parity scripts / CI** | **`SIGNTOOL_EXE`**, **`SIGNTOOL_RS_TEST_PFX`**, **`SIGNTOOL_RS_MSIX_*`**, … | Full matrix and semantics in [`ci-parity.md`](ci-parity.md). |

## Explicit non-goals (unless upstream specs + test vectors appear)

- **VBA / `mso.dll`** SIP.
- **Encrypted MSIX** (`.eappx`, `.emsix`, encrypted bundles).
- **ExtensionsSip** third-party DLL chains.
- **Full** `signtool.exe` argv parity on Linux without a Windows ABI shim.

## Summary

Short term: **Unix CI for fmt + lockfile** + document this split. Medium term: **extract digest library + Linux `cargo test`** for parity-heavy code. Long term: optional **verify-focused** CLI on Linux (done); **sign** remains Windows-first until **Phase 2 stretch** (portable PKCS#7 + embed + optional KV/REST signers on Unix) lands behind explicit milestones.
