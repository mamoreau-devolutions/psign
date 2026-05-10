# Feature gap analysis: native signtool, AzureSignTool, Artifact Signing vs signtool-rs

This document compares **Windows SDK `signtool.exe`**, **AzureSignTool**, **Azure Artifact Signing (Trusted Signing)**, and this repository’s **`signtool-windows`** / **`signtool-portable`**. It is the product-facing companion to the engineering-focused [`rust-sip-gaps.md`](rust-sip-gaps.md) and [`parity-matrix.md`](parity-matrix.md).

**Concrete reversing steps (IDA, ilspycmd, writable copies of Kits binaries):** [`reversing-playbook-authenticode.md`](reversing-playbook-authenticode.md).

**Linux hybrid pipelines (REST hash sign, verify-only, what is still Windows-only):** [`linux-signing-pipelines.md`](linux-signing-pipelines.md).

## Format × capability matrix

Legend: **Sign** = produce/embed Authenticode; **WT verify** = `WinVerifyTrust`-style OS verify; **Digest** = recompute SIP indirect data vs PKCS#7; **Trust** = portable CMS + explicit anchors.

| Subject format | Native `signtool` | `signtool-windows` | `signtool-portable` |
|----------------|-------------------|--------------------|---------------------|
| PE / WinMD | Sign, WT verify | Sign, WT verify, optional `--rust-sip pe` | Digest, inspect, trust-verify-pe |
| CAB | Sign, WT verify | Same | verify-cab, trust-verify-cab, cab-digest |
| MSI | Sign, WT verify | Same | verify-msi |
| ESD / WIM | Sign, WT verify | Same | verify-esd |
| MSIX / APPX (cleartext) | Sign, WT verify | Same (+ `--dlib` / `--dmdf`) | verify-msix |
| MSIX encrypted | Sign (OS) | Delegates OS | **Rejected** (explicit error) |
| Catalog `.cat` | Sign, WT verify | WT + Rust assists | verify-catalog, trust-verify-catalog |
| PS scripts | Sign, WT verify | Same | verify-script |
| WSH `.js`/`.vbs`/`.wsf` | Sign, WT verify | Same | verify-script |
| Detached PKCS#7 | Verify | Verify | trust-verify-detached |
| VBA / `mso.dll` SIP | Sign (OS) | OS | **Not portable** |
| Extension SIP DLLs | Sign (OS) | OS | **Not portable** |

**AzureSignTool** targets the same **embedding path as SignTool** (Windows): typically PE (and same SIP stack as invoked by `SignerSignEx3`). It does **not** define new subject formats—it replaces the CSP with **KV `keys/sign`**.

**Artifact Signing REST** (`:sign` LRO) returns **signature material** for a **hash**; embedding still requires **Windows `SignerSignEx3` + dlib** or **future portable PKCS#7 + embed** (see roadmap).

## Executive summary

| Goal | Today | Gap |
|------|--------|-----|
| **Drop-in Linux replacement for `signtool.exe` sign/verify** | Not supported | Signing and WinTrust-backed verify require Windows CryptAPI/SIP (`SignerSignEx3`, `WinVerifyTrust`). |
| **Drop-in Linux replacement for AzureSignTool** | Partial | **`azure-key-vault-sign-digest`** on **`signtool-portable`** (**`--features azure-kv-sign-portable`**) performs the Key Vault **`keys/sign`** step (**digest file → signature**). **Embedding** Authenticode still requires **`signtool-windows`** (`SignerSignEx3`). Full **`sign`** with KV callback remains Windows (**`--features azure-kv-sign`**). |
| **Drop-in Linux replacement for Artifact Signing (dlib / REST)** | Partial | **`artifact-signing-submit`** (**`--features artifact-signing-rest`**) runs on **Linux/macOS** via **`signtool-portable`** or on Windows via **`signtool-windows`** — same **`:sign`** LRO (**hash → JSON**). **Embedding** PKCS#7 still requires **`SignerSignEx3`** + dlib or future portable CMS/embed. **`signtool-portable`** validates **`--dmdf`** JSON without network. |
| **Linux verify + digest parity for many Authenticode formats** | Supported | **`signtool-portable`** covers PE, CAB, MSI, ESD/WIM, cleartext MSIX, catalog, scripts; **`trust-verify-*`** adds anchor-based CMS trust (see [`authenticode-trust-stack.md`](authenticode-trust-stack.md)). |
| **Maximum Authenticode subject formats** | Windows signs all SIP-registered types Rust can digest-check | **Encrypted MSIX**, **VBA/mso**, **extension SIP DLLs**, **standalone `.p7x`** subject handling — see [`rust-sip-gaps.md`](rust-sip-gaps.md). |

**Practical Linux path today:** Use **`signtool-portable`** for **digest computation**, **Key Vault `keys/sign`** on digest files (**`azure-key-vault-sign-digest`** with **`--features azure-kv-sign-portable`**), **`:sign` REST** (**`artifact-signing-submit`** with **`--features artifact-signing-rest`**), **inspect**, and **verify/trust** across supported formats. **Embed** Authenticode (PKCS#7 into the subject) still requires **`signtool-windows`** / **`SignerSignEx3`** (or native **`signtool.exe`**) until portable CMS+embed lands. Cookbook: [`linux-signing-pipelines.md`](linux-signing-pipelines.md).

**Long-term Linux signing** (if required): implement portable **CMS `SignedData` production** + **format-specific embedding** (PE `WIN_CERTIFICATE`, CAB PKCS#7 placement, MSI digital signature streams, MSIX `ContentTypes` / manifest glue, etc.) and combine with **remote signing** (KV REST, Artifact Signing `:sign` LRO). [`pkcs7.rs`](crates/signtool-sip-digest/src/pkcs7.rs) holds parse/replace helpers; [`pe_embed.rs`](crates/signtool-sip-digest/src/pe_embed.rs) can **wrap PKCS#7**, **append** attribute-certificate rows, and **recompute the PE image `CheckSum`** (experimental — **no** full CMS sign pipeline).

---

## Native Windows SDK `signtool.exe`

**Strengths:** Full Authenticode lifecycle — **sign**, **verify** (many policies), **timestamp**, **remove**, **catalog** ops, **sealing** / AppX constraints, response files, broad switch surface ([`signtool-cli-matrix.json`](signtool-cli-matrix.json)).

**This repo (`signtool-windows`):**

| Area | Parity |
|------|--------|
| verify (embedded, detached, catalog) | High — WinTrust + Rust paths for detached/catalog |
| sign / timestamp | **`SignerSignEx3`** / **`SignerTimeStampEx3`** Rust core |
| remove | Partial (`/s`, PKCS#7 `/u`/`/c` paths — see parity matrix) |
| catdb | Partial |
| Every obscure `/switch` | See **`cli-parity-backlog.md`** |

**Portable digest-only checks** after native sign: **`verify-pe`**, **`--rust-sip-*`** family on **`signtool-windows`**.

---

## AzureSignTool

**Model:** .NET tool — hash file, call **Azure Key Vault `keys/sign`**, integrate with **`SignerSignEx3`** (or equivalent) on Windows for PKCS#7 embedding.

**This repo:**

| AzureSignTool concept | `signtool-windows` | `signtool-portable` |
|-----------------------|-------------------|---------------------|
| KV URL, cert name, auth (MI / SP / token) | Yes (`--features azure-kv-sign`) | **`azure-key-vault-sign-digest`** (`--features azure-kv-sign-portable`) — digest file only |
| Batch / parallelism / exit HRESULTs | Mapped (`--input-file-list`, `--exit-codes azuresigntool`, …) | N/A |
| ECDSA keys | Supported on KV path (alg derived from cert) | Same JWS algs (**ES256**/…) inferred from certificate **`cer`** |

**Gap:** Embedding PKCS#7 into subjects is still **Windows + SIP**. Portable KV signs an **opaque digest blob**; wiring signature bytes into **`SignedData`** + **`WIN_CERTIFICATE`** (etc.) remains future work.

Details: [`migration-azuresigntool.md`](migration-azuresigntool.md).

---

## Azure Artifact Signing (Trusted Signing)

**Models:**

1. **Decoupled digest DLL** — `Azure.CodeSigning.Dlib.dll` + **`SignerSignEx3`** + **`--dmdf`** metadata (same family as native SignTool).
2. **REST** — Certificate profile **`:sign`** LRO (`*.codesigning.azure.net`), OAuth scope **`https://codesigning.azure.net/.default`**.

**This repo:**

| Surface | Implementation |
|---------|----------------|
| Decoupled sign (`--dlib`, `--trusted-signing-dlib-root`, `--dmdf`) | **`signtool-windows`** only |
| REST hash signing | **`artifact-signing-submit`** (`--features artifact-signing-rest`) on **`signtool-windows`** or **`signtool-portable`** |
| Metadata validation without signing | **`signtool-portable artifact-signing-metadata-check`** |

**Gap:** REST output is **not** wired into a portable Authenticode embedder; docs state MVP is hash signing / diagnostics. [`migration-artifact-signing.md`](migration-artifact-signing.md).

---

## `signtool-portable` (Linux/macOS)

**Commands (verify / inspect / digest tools):** See [`roadmap-authenticode-linux.md`](roadmap-authenticode-linux.md) and **`signtool-portable --help`**.

**Remote signing steps (no embed):** With **`--features azure-kv-sign-portable`**, **`azure-key-vault-sign-digest`** performs Azure Key Vault **`keys/sign`** on a **raw digest file** (same REST shape as AzureSignTool’s remote step). With **`--features artifact-signing-rest`**, **`artifact-signing-submit`** calls Trusted Signing **`:sign`**. Neither writes PKCS#7 into a PE/CAB/MSI subject without **`signtool-windows`** (or future portable CMS embed).

**Formats with portable digest + PKCS#7 consistency (and optional trust):**

- PE / WinMD-style CLI metadata (multi-signed PEs: **`list-pe-pkcs7`**, **`extract-pe-pkcs7 --index`**, **`inspect-pe-spc-indirect --index`** share the same certificate-table PKCS#7 row order)
- CAB
- MSI (OLE Signify layout)
- ESD / WIM prefix
- Cleartext MSIX / APPX / bundles (encrypted variants rejected)
- Catalog `.cat` (CMS digest consistency; not full CTL membership / `CryptCATAdmin` policy)
- PowerShell-class scripts, WSH `.js`/`.vbs`/`.wsf` (heuristic strip/hash — may diverge from COM Unicode conversion edge cases)

**Not full Authenticode lifecycle:** No **`sign`** / **`timestamp`** / **`remove`** verbs, no **`--dlib`** decoupled DLL path, and no embedding **SignedData** into subjects on Linux (see PKCS#7 stubs in **`signtool-sip-digest`**).

---

## Reverse engineering notes (IDA / ILSpy / ilspycmd)

See **[`reversing-playbook-authenticode.md`](reversing-playbook-authenticode.md)** for copy-to-writable-directory (**Program Files** permission pitfall), **ilspycmd** one-liners, and xref hints.

When filing issues, prefer **parity scenario IDs** from [`parity-matrix.md`](parity-matrix.md) and **gap IDs** from [`rust-sip-gaps.md`](rust-sip-gaps.md) (e.g. **`linux_trust_rfc3161_tsa_crypto_gap`**).

---

## Validation matrix (what to run)

| Tier | Command / script | Platform |
|------|-------------------|----------|
| Unix CI | `cargo digest-test` / workflows in **`ci-unix.yml`** | Linux |
| Unix local mirror | **`scripts/linux-portable-validation.sh`** (from repo root; bash); **`signtool-portable append-pe-pkcs7`** / **`pe-checksum --strict`** for PE layout experiments | Linux / WSL / Git Bash |
| Pipelines narrative | [`linux-signing-pipelines.md`](linux-signing-pipelines.md) | Linux-focused |
| Windows parity | `./scripts/run-parity-diff.ps1`, `./scripts/ci/run-exhaustive-parity-ci.ps1` | Windows |
| MSIX focus | `./scripts/msix-parity-sign.ps1` | Windows |
| Optional KV / Artifact env tests | Ignored tests in **`tests/parity_signtool.rs`** | Windows |
| Portable REST HTTP mocks | **`cargo test -p signtool-azure-kv-rest`** / **`cargo test -p signtool-codesigning-rest`** (mockito; no cloud) | Linux CI |

---

## Related documents

- [`linux-signing-pipelines.md`](linux-signing-pipelines.md) — Linux verify + hybrid Artifact REST flows.
- [`reversing-playbook-authenticode.md`](reversing-playbook-authenticode.md) — IDA / ilspycmd workflow.
- [`roadmap-authenticode-linux.md`](roadmap-authenticode-linux.md) — phased Linux strategy.
- [`rust-sip-gaps.md`](rust-sip-gaps.md) — SIP/Tier 1b/1c engineering backlog.
- [`parity-matrix.md`](parity-matrix.md) — scenario status.
- [`psa-interoperability.md`](psa-interoperability.md) — PowerShell OpenAuthenticode overlap.
