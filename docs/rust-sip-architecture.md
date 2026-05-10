# Rust SIP architecture

## Goals

- Optional **Rust-backed PE Authenticode digest** and **embedded PKCS#7 parse/compare** for parity with OS signing (`SignerSignEx3`).
- Future: full PKCS#7 `SignedData` encode + `WIN_CERTIFICATE` embed without `SignerSignEx3` (Tier 1a completion).

## PE parsing strategy

Hand-rolled COFF/optional-header traversal was deferred: **`object`** + the **`authenticode`** crate’s `PeTrait` impl match upstream digest semantics and avoid maintaining parallel PE layouts (alternative crates such as `pelite` or using only `goblin` would duplicate `authenticode-rs` assumptions).

## Dependencies (`signtool-sip-digest`)

| Crate | Role |
|-------|------|
| [`authenticode`](https://crates.io/crates/authenticode) | PE image digest (`authenticode_digest`), WIN_CERTIFICATE iteration, `AuthenticodeSignature` CMS parse |
| [`object`](https://crates.io/crates/object) | `PeFile32` / `PeFile64` implementing `PeTrait` |
| [`sha2`](https://crates.io/crates/sha2) | SHA-256 hasher passed into `authenticode_digest` |
| [`cms`](https://crates.io/crates/cms) / [`der`](https://crates.io/crates/der) | Catalog / CAB PKCS#7 indirect-data plumbing |
| **Future** | Windows `CryptMsgOpenToEncode` or fuller `cms` encode for PKCS#7 production signing |

**Why not hand-roll PE parsing?** The main `signtool-rs` binary still uses **`goblin`** in `depgraph`; digest code standardizes on **`object`** to match `authenticode-rs` and avoid duplicate COFF logic.

## Portable crate (`crates/signtool-sip-digest/src/`)

| File | Responsibility |
|------|----------------|
| `lib.rs` | Crate root; `verify_script_digest_consistency` router |
| `pe_digest.rs` | PE / WinMD Authenticode image digest + ordered **`pe_authenticode_digest_file_ranges`** (matches `authenticode-rs` segment layout) |
| `verify_pe.rs` | Compare recomputed digest vs PKCS#7 indirect data for each embedded Authenticode cert |
| `cab_digest.rs`, `catalog_digest.rs`, `msi_digest.rs`, `esd_digest.rs`, `msix_digest.rs` | Format-specific SIP digest recomputation |
| `ps_script.rs`, `wsh_script.rs` | Script strip/hash heuristics vs PKCS#7 |
| `pkcs7.rs` | PKCS#7 builder **stub** + notes |
| `pe_embed.rs` | `WIN_CERTIFICATE` embed path — **stub** |
| `timestamp.rs` | RFC3161 embed notes — **stub** (Tier 1b) |
| `page_hashes.rs` | PE page-hash CMS extract + Authenticode payload peel / flat table parse (Tier 1c); segment verify still Win32 |

## Linux / macOS CLI (`crates/signtool-digest-cli`)

The **`signtool-digest`** binary wraps **`signtool-sip-digest`** for scripting and CI (e.g. `pe-digest`, `verify-msix`, `pe-has-page-hashes`, `pe-page-hash-info`, `verify-pe-page-hashes`, `pe-authenticode-ranges`, …). It performs **digest vs PKCS#7 indirect data** checks, **PE Authenticode digest segment listing**, and **PE page-hash tooling** (OID presence, structured parse, experimental contiguous raw-byte verification — not a full **`WinVerifyTrust`** `/ph` clone).

## Win32 adapter (`src/win/sip_rust/`)

| File | Responsibility |
|------|----------------|
| `mod.rs` | Re-exports `signtool_sip_digest::*` for existing `crate::win::sip_rust::…` call sites |
| `sign_pe.rs`, `sign_script.rs`, `sign_msi.rs`, `sign_esd.rs`, `sign_msix.rs`, `sign_cab.rs`, `sign_catalog.rs` | Post-sign digest gates (`GlobalOpts` / debug logging) |

## Routing

- **Default:** [`sign_core::sign_with_mssign32`](../src/win/sign_core.rs).
- **`--rust-sip pe`:** Still signs with **`SignerSignEx3`** today; after signing, recomputes the PE Authenticode digest in Rust and asserts it matches the PKCS#7 **indirect** digest (experimental parity gate).
- **`--rust-sip script`:** After signing, compares PKCS#7 indirect digest to Rust recomputation: PowerShell-class uses **UTF-16 range removal** (`pwrshsip.dll`); WSH uses **`wshext.dll`** strip + UTF-16 LE payload + **u32** begin-marker offset (see `wsh_script.rs`, [`windows-signing-components.md`](windows-signing-components.md)).

### SIP DLL inventory

Optional local copies of inbox DLLs: [`scripts/copy-windows-signing-binaries.ps1`](../scripts/copy-windows-signing-binaries.ps1). Roles and SIP relationships: [`windows-signing-components.md`](windows-signing-components.md); CryptSIP GUIDs: [`rust-sip-machine-registry.md`](rust-sip-machine-registry.md).

### Verify digest add-ons

After a successful **embedded** `WinVerifyTrust`, optional flags recompute the SIP digest in Rust and compare to PKCS#7 indirect data (PE, scripts, MSI, ESD, cleartext MSIX, CAB, catalog). **`verify --rust-sip-all-digest-checks`** turns on every `--rust-sip-*-digest-check` at once. Encrypted MSIX extensions (`.eappx`, `.emsix`, …) are rejected by the MSIX checker with an explicit message — see [`rust-sip-gaps.md`](rust-sip-gaps.md).

## Security

See [`rust-sip-threat-model.md`](rust-sip-threat-model.md).
