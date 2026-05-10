# Roadmap: Authenticode tooling on Linux

The primary `signtool-rs` binary is **Windows-first**: it depends on **`windows`**, **WinVerifyTrust**, **SignerSignEx3**, and OS **CryptSIP** registration. A practical Linux story is **phased**: keep Windows as the reference implementation while carving out **portable** pieces.

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

Short term: **Unix CI for fmt + lockfile** + document this split. Medium term: **extract digest library + Linux `cargo test`** for parity-heavy code. Long term: optional **verify-focused** CLI on Linux; **sign** remains Windows-first or provider-specific.
