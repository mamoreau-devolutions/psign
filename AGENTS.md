# Agent guide — signtool-rs

This repository is a **Rust port** of the Windows SDK **`signtool.exe`** (Authenticode sign / verify / timestamp / remove, plus related flows). Portable digest logic mirrors inbox SIP hashing where implemented; the full CLI depends on Win32 (**`WinVerifyTrust`**, **`SignerSignEx3`**, CryptSIP).

## Workspace layout

| Area | Path | Notes |
|------|------|--------|
| Root package (Windows CLI + lib) | `Cargo.toml` (package **`signtool-rs`**) | **`windows`** crate feature deps under **`cfg(windows)`**; non-Windows builds use a stub **`main`**. |
| Portable digest library | `crates/signtool-sip-digest` | No **`windows`** dependency; Linux-safe unit tests. |
| Portable Authenticode trust | `crates/signtool-authenticode-trust` | Anchors + picky chain; **`signtool-portable`** **`trust-verify-pe`**, **`trust-verify-cab`**, **`trust-verify-catalog`**, **`trust-verify-detached`** — no OS trust store. |
| Portable CLI | `crates/signtool-digest-cli` | Binary **`signtool-portable`**. |
| Win32 implementation | `src/win/` | Verify, sign, timestamp, catalog, detached PKCS#7, etc. |
| argv / response files | `src/native_argv.rs`, `src/response_argv.rs` | Shared with stub builds for **`cargo check`** on Unix. |

**Important:** **`default-members`** are the three crates under **`crates/`** (digest, digest CLI, authenticode-trust). A bare **`cargo build`** or **`cargo test`** at the repo root does **not** build the **`signtool-rs`** binary unless you use **`--workspace`** or **`-p signtool-rs`**.

## Cargo aliases (`.cargo/config.toml`)

- **`cargo windows-bin`** — build **`signtool-windows`** exe (**`-p signtool-rs --bin signtool-windows`**).
- **`cargo digest-check`** / **`cargo digest-test`** — portable digest + trust crates (see **`.cargo/config.toml`**).
- **`cargo unix-lib-check`** — **`signtool-rs`** library on non-Windows (stub-friendly).
- **`cargo depgraph`** — **`depgraph`** binary (**needs `-p`** because of **`default-members`**).

## Commands agents should run

**After substantive edits**

```text
cargo fmt --all
cargo clippy --workspace --all-targets --locked
cargo test --workspace --locked
```

On Linux/macOS, match **`ci-unix`**: fmt check, metadata **`--locked`**, clippy **`-D warnings`** on **`signtool-sip-digest`**, **`signtool-digest-cli`**, **`signtool-authenticode-trust`**, **`signtool-rs --lib`**, then **`cargo test -p signtool-sip-digest --lib`**, **`cargo test -p signtool-authenticode-trust --lib`**, **`cargo test -p signtool-digest-cli`**, and **`cargo test -p signtool-rs --lib`**.

**Windows-only parity** (when changing verify/sign/timestamp behavior): build **`signtool-rs`** and run **`scripts/run-parity-diff.ps1`** or **`scripts/ci/run-exhaustive-parity-ci.ps1`** with env vars described in **`docs/ci-parity.md`**.

## Documentation map

| Doc | Purpose |
|-----|---------|
| **`docs/windows-signing-components.md`** | Reference map of **`signtool.exe`**, **`mssign32`**, **`WINTRUST`**, SIP DLLs, **`imagehlp`**; includes a mermaid relationship diagram. |
| **`docs/rust-sip-architecture.md`** | Rust SIP digest add-ons vs OS SIP. |
| **`docs/rust-sip-gaps.md`** | Known limitations (MSIX sign gap, `/ph`, PKCS#7 encode, VBA, encrypted MSIX, …). |
| **`docs/rust-sip-spec-refs.md`** | Spec links + PE page-hash / **`SignerSignEx3`** notes. |
| **`docs/ci-parity.md`** | CI steps, **`SIGNTOOL_RS_*`** env vars, parity gates. |
| **`docs/roadmap-authenticode-linux.md`** | Unix/portable subset and **`signtool-portable`**. |
| **`docs/authenticode-trust-stack.md`** | Portable trust crate split (picky vs digest vs CMS). |
| **`docs/authroot-linux-verify.md`** | Anchor dir + AuthRoot CAB usage on Linux. |
| **`docs/plan-linux-authenticode-trust-verify.md`** | Technical plan (CTL, test matrix, risks). |
| **`docs/signtool-cli-matrix.json`** | Machine-checked native ↔ Rust CLI mapping (with **`signtool-cli-matrix.md`** summary). |

Do **not** commit **`parity-output/`** or **`reversing/`** — they are **gitignored** (local parity JSON, **`depgraph`** output, optional vendor DLL copies).

## Implementation conventions

- **Edition:** Rust **2024**.
- **Portable crypto / ASN.1:** Prefer existing crates (**`cms`**, **`authenticode`**, **`sha2`**, …) and patterns in **`signtool-sip-digest`**.
- **Windows API:** Use the **`windows`** crate bindings already wired in **`src/win/`**; keep new FFI narrow and documented.
- **Parity:** Prefer extending **`scripts/run-parity-diff.ps1`** scenarios and/or corpus fixtures over one-off manual checks; **`documented_*`** classifications are allowed non-fatal rows when native limitations are intentional.

## PR / commit hygiene

- Keep changes scoped to the requested behavior; avoid drive-by refactors.
- Do not add tracked binaries, IDA databases, or parity JSON under ignored dirs.
- If you add user-facing flags, update **`docs/signtool-cli-matrix.json`** (and generated/summary **`signtool-cli-matrix.md`** if that file is maintained by hand in sync).
