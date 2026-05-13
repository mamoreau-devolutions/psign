# Feature gap analysis: native signtool, AzureSignTool, Artifact Signing vs psign

This document compares **Windows SDK `signtool.exe`**, **AzureSignTool**, **Azure Artifact Signing (Trusted Signing)**, and this repository’s **`psign-tool`** / **`psign-tool portable`**. It is the product-facing companion to the engineering-focused [`rust-sip-gaps.md`](rust-sip-gaps.md) and [`parity-matrix.md`](parity-matrix.md).

**Writable copies of Kits / System32 binaries (read-only install dirs):** [`writable-signing-binaries.md`](writable-signing-binaries.md).

**Linux hybrid pipelines (REST hash sign, verify-only, what is still Windows-only):** [`linux-signing-pipelines.md`](linux-signing-pipelines.md).

## Format × capability matrix

Legend: **Sign** = produce/embed Authenticode; **WT verify** = `WinVerifyTrust`-style OS verify; **Digest** = recompute SIP indirect data vs PKCS#7; **Trust** = portable CMS + explicit anchors.

| Subject format | Native `signtool` | `psign-tool` | `psign-tool portable` |
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
| **Drop-in Linux replacement for AzureSignTool** | Partial | **`azure-key-vault-sign-digest`** on **`psign-tool portable`** (**`--features azure-kv-sign-portable`**) performs the Key Vault **`keys/sign`** step (**digest file → signature**). Use **`pe-digest --encoding raw`** for the **PE image** hash file; use **`pe-signer-rs256-prehash --encoding raw`** (optional **`--signer-index`** for the *N*th **`SignerInfo`** inside the selected PKCS#7 row) when you need the **CMS authenticated-attribute** **SHA-256** prehash (**32** octets) for **`RS256`** on an **existing embedded PKCS#7** (see [`migration-azuresigntool.md`](migration-azuresigntool.md)). **Embedding** Authenticode still requires **`psign-tool`** (`SignerSignEx3`) or a portable **`SignedData`** rebuild. Full **`sign`** with KV callback remains Windows (**`--features azure-kv-sign`**). |
| **Drop-in Linux replacement for Artifact Signing (dlib / REST)** | Partial | **`artifact-signing-submit`** (**`--features artifact-signing-rest`**) runs on **Linux/macOS** via **`psign-tool portable`** or on Windows via **`psign-tool`** — same **`:sign`** LRO (**hash → JSON**). **Embedding** PKCS#7 still requires **`SignerSignEx3`** + dlib or future portable CMS/embed. **`psign-tool portable`** validates **`--dmdf`** JSON without network. |
| **Linux verify + digest parity for many Authenticode formats** | Supported | **`psign-tool portable`** covers PE, CAB, MSI, ESD/WIM, cleartext MSIX, catalog, scripts; **`trust-verify-*`** adds anchor-based CMS trust (see [`authenticode-trust-stack.md`](authenticode-trust-stack.md)). |
| **Maximum Authenticode subject formats** | Windows signs all SIP-registered types Rust can digest-check | **Encrypted MSIX**, **VBA/mso**, **extension SIP DLLs**, **standalone `.p7x`** subject handling — see [`rust-sip-gaps.md`](rust-sip-gaps.md). |

**Practical Linux path today:** Use **`psign-tool portable`** for **digest computation**, **Key Vault `keys/sign`** on digest files (**`azure-key-vault-sign-digest`** with **`--features azure-kv-sign-portable`**), **`:sign` REST** (**`artifact-signing-submit`** with **`--features artifact-signing-rest`**), **inspect**, and **verify/trust** across supported formats. **Embed** Authenticode (PKCS#7 into the subject) still requires **`psign-tool`** / **`SignerSignEx3`** (or native **`signtool.exe`**) until portable CMS+embed lands. Cookbook: [`linux-signing-pipelines.md`](linux-signing-pipelines.md).

**Long-term Linux signing** (if required): implement portable **CMS `SignerInfo` production** (inside **`SignedData`**) + **format-specific embedding** (PE `WIN_CERTIFICATE`, CAB PKCS#7 placement, MSI digital signature streams, MSIX `ContentTypes` / manifest glue, etc.) and combine with **remote signing** (KV REST, Artifact Signing `:sign` LRO). [`pkcs7.rs`](crates/psign-sip-digest/src/pkcs7.rs) holds parse/replace helpers, **`signed_data_replace_first_signer_info`**, **`encode_pkcs7_content_info_signed_data_der`**, **RSA PKCS#1 RS256** prehash ↔ **`SignerInfo.signature`** parity tests (`rsa_pkcs1v15_signed_attrs_verify`), and **`signer_info_sha256_digest_over_signed_attrs`** (documented KV **`RS256`** input shape); [`pe_embed.rs`](crates/psign-sip-digest/src/pe_embed.rs) can **wrap PKCS#7**, **append** rows (including after signer splice experiments), and **recompute `CheckSum`**. **`psign-tool portable pe-signer-rs256-prehash`** surfaces the **32-byte** prehash for Linux KV workflows; **unsigned→signed** / timestamp / CAB·MSI embed remain backlog (see [`rust-sip-gaps.md`](rust-sip-gaps.md)).

---

## Native Windows SDK `signtool.exe`

**Strengths:** Full Authenticode lifecycle — **sign**, **verify** (many policies), **timestamp**, **remove**, **catalog** ops, **sealing** / AppX constraints, response files, broad switch surface ([`psign-cli-matrix.json`](psign-cli-matrix.json)).

**This repo (`psign-tool`):**

| Area | Parity |
|------|--------|
| verify (embedded, detached, catalog) | High — WinTrust + Rust paths for detached/catalog |
| sign / timestamp | **`SignerSignEx3`** / **`SignerTimeStampEx3`** Rust core |
| remove | Partial (`/s`, PKCS#7 `/u`/`/c` paths — see parity matrix) |
| catdb | Partial |
| Every obscure `/switch` | See **`cli-parity-backlog.md`** |

**Portable digest-only checks** after native sign: **`verify-pe`**, **`--rust-sip-*`** family on **`psign-tool`**.

---

## AzureSignTool

**Model:** .NET tool — hash file, call **Azure Key Vault `keys/sign`**, integrate with **`SignerSignEx3`** (or equivalent) on Windows for PKCS#7 embedding.

**This repo:**

| AzureSignTool concept | `psign-tool` | `psign-tool portable` |
|-----------------------|-------------------|---------------------|
| KV URL, cert name, auth (MI / SP / token) | Yes (`--features azure-kv-sign`) | **`azure-key-vault-sign-digest`** (`--features azure-kv-sign-portable`) — digest file only |
| Batch / parallelism / exit HRESULTs | Mapped (`--input-file-list`, `--exit-codes azuresigntool`, …) | N/A |
| ECDSA keys | Supported on KV path (alg derived from cert) | Same JWS algs (**ES256**/…) inferred from certificate **`cer`** |

**Gap:** Embedding PKCS#7 into subjects is still **Windows + SIP** for production **greenfield** signing. Portable KV signs an **opaque digest blob** — use the correct digest for your pipeline (**image** vs **CMS signer** prehash; **`pe-signer-rs256-prehash`** for the latter on PE). Wiring KV-returned **`encryptedDigest`** into **`SignedData`** + **`WIN_CERTIFICATE`** is partially supported in **`psign-sip-digest`** (helpers + tests); end-to-end Linux **sign** without **`SignerSignEx3`** remains future work.

Details: [`migration-azuresigntool.md`](migration-azuresigntool.md).

---

## Azure Artifact Signing (Trusted Signing)

**Models:**

1. **Decoupled digest DLL** — `Azure.CodeSigning.Dlib.dll` + **`SignerSignEx3`** + **`--dmdf`** metadata (same family as native SignTool).
2. **REST** — Certificate profile **`:sign`** LRO (`*.codesigning.azure.net`), OAuth scope **`https://codesigning.azure.net/.default`**.

**This repo:**

| Surface | Implementation |
|---------|----------------|
| Decoupled sign (`--dlib`, `--trusted-signing-dlib-root`, `--dmdf`) | **`psign-tool`** only |
| REST hash signing | **`artifact-signing-submit`** (`--features artifact-signing-rest`) on **`psign-tool`** or **`psign-tool portable`** |
| Metadata validation without signing | **`psign-tool portable artifact-signing-metadata-check`** |

**Gap:** REST output is **not** wired into a portable Authenticode embedder; docs state MVP is hash signing / diagnostics. [`migration-artifact-signing.md`](migration-artifact-signing.md).

---

## `psign-tool portable` (Linux/macOS)

**Commands (verify / inspect / digest tools):** See [`roadmap-authenticode-linux.md`](roadmap-authenticode-linux.md) and **`psign-tool portable --help`**.

**Remote signing steps (no embed):** With **`--features azure-kv-sign-portable`**, **`azure-key-vault-sign-digest`** performs Azure Key Vault **`keys/sign`** on a **raw digest file** (same REST shape as AzureSignTool’s remote step). **`pe-signer-rs256-prehash`**, **`cab-signer-rs256-prehash`**, **`msi-signer-rs256-prehash`**, and **`catalog-signer-rs256-prehash`** (**`--encoding raw`**) emit the **32-byte** **`RS256`** input over **`SignerInfo.signedAttrs`** (distinct from subject-layout digests and from **`verify-catalog`**’s CTL **`eContent`** / PKCS#9 checks). With **`--features artifact-signing-rest`**, **`artifact-signing-submit`** calls Trusted Signing **`:sign`**. Neither writes PKCS#7 into a PE/CAB/MSI subject without **`psign-tool`** (or future portable CMS embed).

**RFC 3161 TSA helpers (Linux-side, no embed):** **`rfc3161-timestamp-req`** builds **`TimeStampReq`** DER from **`--digest-hex`** / **`--digest-file`** (message-imprint preimage; optional **`--nonce`**, **`--cert-req`**) for **`curl`** / OpenSSL **`ts`** against a timestamp URL. **`rfc3161-timestamp-resp-inspect`** prints **`pki_status`** / **`pki_status_int`** (raw status INTEGER) / **`granted`** / token length, **`time_stamp_token_prefix_hex`** (first **16** octets of the raw **`timeStampToken`** TLV, or **`-`** when absent — handy for **`ContentInfo`** / CMS shape checks), **`status_strings_json`** (**`PKIFreeText`**), **`fail_info_tlv_hex`**, and **`fail_info_flags_json`** (RFC 2510 Appendix A **`PKIFailureInfo`** bit names through **`badPOP`**, then **`bit_N`**; **`null`** when the **`BIT STRING`** body is not decodable). Optional **`rfc3161-timestamp-http-post`** (**`--features timestamp-http`**) performs the HTTPS POST without **`curl`**. None of this replaces **`SignerTimeStampEx3`** or **`CryptVerifyTimeStampSignature`**.

**Formats with portable digest + PKCS#7 consistency (and optional trust):**

- PE / WinMD-style CLI metadata (multi-signed PEs: **`list-pe-pkcs7`**, **`extract-pe-pkcs7 --index`**, **`inspect-pe-spc-indirect --index`** share the same certificate-table PKCS#7 row order)
- CAB
- MSI (OLE Signify layout)
- ESD / WIM prefix
- Cleartext MSIX / APPX / bundles (encrypted variants rejected)
- Catalog `.cat` (CMS digest consistency; not full CTL membership / `CryptCATAdmin` policy)
- PowerShell-class scripts, WSH `.js`/`.vbs`/`.wsf` (heuristic strip/hash — may diverge from COM Unicode conversion edge cases)

**Not full Authenticode lifecycle:** No **`sign`** / **`timestamp`** / **`remove`** verbs, no **`--dlib`** decoupled DLL path, and no turnkey embedding of a **brand-new** **SignedData** into subjects on Linux — but **`psign-sip-digest`** already supports parse/replace indirect data, PKCS#9 **`messageDigest`** refresh, **`SignerInfo`** splice + signature octets, **`ContentInfo`** re-encode, **`WIN_CERTIFICATE`** append/wrap, and portable **`pe-` / `cab-` / `msi-signer-rs256-prehash`** for KV **`RS256`** digest extraction from embedded PKCS#7 (PE cert table, CAB tail, MSI **`DigitalSignature`** stream).

---

## Studying native vs managed surfaces (no vendor tooling in-repo)

Use **public documentation**, **this repo’s parity tests**, and **writable copies** of binaries (see [`writable-signing-binaries.md`](writable-signing-binaries.md) and **`scripts/prepare-writable-signing-binaries.ps1`**) when you need to inspect behavior next to a PE outside protected install paths.

| Original / surface | Mechanism | Typical study angle |
|--------------------|-----------|----------------------|
| Windows SDK **`signtool.exe`** | Native PE | Writable **`signtool.exe`**; map **`SignerSignEx3`**, **`WinVerifyTrust`** to docs and `psign-tool` paths |
| **`mssign32.dll`**, **`crypt32.dll`**, **`WINTRUST.dll`** | Native PE | Writable copies; follow **`SignerSignEx3`**, **`CryptMsg*`**, SIP glue vs [`windows-signing-components.md`](windows-signing-components.md) |
| **AzureSignTool** | .NET | **`AzureSignTool.dll`** / **`AzureSign.Core.dll`** vs [`psign-azure-kv-rest`](../crates/psign-azure-kv-rest/) and [`migration-azuresigntool.md`](migration-azuresigntool.md) |
| **Artifact Signing** managed client | .NET | **`Microsoft.ArtifactSigning.Client.dll`** vs [`psign-codesigning-rest`](../crates/psign-codesigning-rest/) |
| **`Azure.CodeSigning.Dlib.dll`** | Native PE | Decoupled digest exports vs **`SIGNER_DIGEST_SIGN_INFO`** ([`windows-signing-components.md`](windows-signing-components.md)) |

When filing issues, prefer **parity scenario IDs** from [`parity-matrix.md`](parity-matrix.md) and **gap IDs** from [`rust-sip-gaps.md`](rust-sip-gaps.md) (e.g. **`linux_trust_rfc3161_tsa_crypto_gap`**).

---

## Validation matrix (what to run)

| Tier | Command / script | Platform |
|------|-------------------|----------|
| Unix CI | `cargo digest-test` / workflows in **`ci-unix.yml`** | Linux |
| Unix local mirror | **`scripts/linux-portable-validation.sh`** (from repo root; bash); **`psign-tool portable append-pe-pkcs7`** / **`pe-checksum --strict`** for PE layout experiments | Linux / WSL / Git Bash |
| Pipelines narrative | [`linux-signing-pipelines.md`](linux-signing-pipelines.md) | Linux-focused |
| Windows parity | `./scripts/run-parity-diff.ps1`, `./scripts/ci/run-exhaustive-parity-ci.ps1` | Windows |
| Writable native signing binaries | **`pwsh -File scripts/prepare-writable-signing-binaries.ps1`** → **`parity-output/writable-signing-binaries`** (gitignored) | Windows |
| MSIX focus | `./scripts/msix-parity-sign.ps1` | Windows |
| Optional KV / Artifact env tests | Ignored tests in **`tests/parity_signtool.rs`** | Windows |
| Portable REST HTTP mocks | **`cargo test -p psign-azure-kv-rest`** / **`cargo test -p psign-codesigning-rest`** (mockito; no cloud) | Linux CI |
| Portable CMS **RS256** prehash parity | **`rust-sip-parity.yml`** job **`portable-cms-rs256-linux`**: **`rsa_pkcs1v15_signed_attrs_verify`** + **`signer_rs256_prehash`** + **`cab_rs256_`** + **`cab_rsa_sha256_signer_prehash`** + **`msi_rs256_`** + **`msi_pkcs7_`** + **`cat_rs256_`** + **`catalog_rsa_sha256_signer_prehash`** + **`wim_verify_rejects`** + **`_unsigned_errors_`** + **`portable_verify_negative_`** + **`inspect_pkcs7_parity_`** + **`detached_trust_`** + **`data_plane_base_url`** + **`psign-azure-kv-rest --lib`** (KV URL + JWS helpers) | Linux (also covered by **`ci-unix.yml`**) |

---

## Related documents

- [`linux-signing-pipelines.md`](linux-signing-pipelines.md) — Linux verify + hybrid Artifact REST flows.
- [`writable-signing-binaries.md`](writable-signing-binaries.md) — writable **`signtool.exe`** / **`WINTRUST.dll`** / **`mssign32.dll`** copies for local study.
- [`roadmap-authenticode-linux.md`](roadmap-authenticode-linux.md) — phased Linux strategy.
- [`rust-sip-gaps.md`](rust-sip-gaps.md) — SIP/Tier 1b/1c engineering backlog.
- [`parity-matrix.md`](parity-matrix.md) — scenario status.
- [`psa-interoperability.md`](psa-interoperability.md) — PowerShell OpenAuthenticode overlap.
