# Rust SIP — what is still missing

This doc complements [`rust-sip-architecture.md`](rust-sip-architecture.md) and the parity matrix. **Rust SIP** means optional digest recomputation vs PKCS#7 indirect data after (or beside) OS **`WinVerifyTrust`** / **`SignerSignEx3`** — not replacing CryptSIP registration. Portable digest code lives in **`crates/signtool-sip-digest`** (Linux CI runs its unit tests). The **`signtool-rs`**
crate **`check`**s on Linux with a stub **`main`**; full **`win`** / **`WinVerifyTrust`** paths remain Windows-only.
Use **`signtool-portable`** ([`crates/signtool-digest-cli`](../crates/signtool-digest-cli)) on Unix for portable digest / PKCS#7 consistency checks.

**CI parity:** On Ubuntu, **`ci-unix`** runs **`cargo clippy -D warnings`** on **`signtool-sip-digest`**, **`signtool-digest-cli`**, **`signtool-authenticode-trust`**, and the **`signtool-rs` library** (CLI/`win` stays Windows-only). `signtool-digest-cli` integration tests run **`pe-digest`**, **`verify-pe`**, **`trust-verify-pe`** (failure without anchors; success with extracted embedded root + **`--as-of`** inside cert validity), **`pe-has-page-hashes`**, **`pe-page-hash-info`**, **`verify-pe-page-hashes`** (expects failure on tiny fixtures — no page-hash attrs), and **`pe-authenticode-ranges`** on **`tiny32.signed.efi`** / **`tiny64.signed.efi`** (golden SHA-256 hex + expect **`no`** page-hash attributes / empty info for those fixtures).

## Covered today (registry SIPs on a typical Windows install)

| OS DLL | Formats | Rust module / CLI |
|--------|---------|-------------------|
| `WINTRUST.DLL` | PE / WinMD, CAB, `.cat` | `pe_digest`, `cab_digest`, `catalog_digest`; `verify --rust-sip-*-digest-check` |
| `pwrshsip.dll` | PowerShell-class scripts | `ps_script`; `--rust-sip script` |
| `wshext.dll` | WSH `.js` / `.vbs` / `.wsf` | `wsh_script` |
| `MSISIP.DLL` | `.msi` | `msi_digest` |
| `EsdSip.dll` | `.wim` / `.esd` | `esd_digest` |
| `AppxSip.dll` | Cleartext `.msix` / `.appx` / bundles | `msix_digest` |

Use **`verify --rust-sip-all-digest-checks`** to enable every experimental digest add-on for embedded verify in one flag.

## Intentionally not covered (same SIP DLL, different code path)

| Subject | Why |
|---------|-----|
| **Encrypted** MSIX / APPX (`.eappx`, `.emsix`, `.eappxbundle`, `.emsixbundle`) | **`EappxSip*`** / **`EappxBundleSip*`** — COM + **`EncryptedAppxHeader`** / keys; not a cleartext ZIP rehash. Rust checker returns an explicit error if you force MSIX digest parity on these extensions. |
| **`ExtensionsSipGetSignedDataMsg`** | Dispatches to **optional third-party DLLs** enumerated from the package — not portable in-tree. |
| **Standalone `.p7x`** (**`P7xSip*`**) | Container extract (**PKCX** → inner PKCS#7); **`P7xSipVerifyIndirectData`** is effectively a null-check stub in **`AppxSip.dll`**. No separate “subject digest” to recompute beyond normal Authenticode. |
| **`mso.dll` / VBA** | Indirect data ultimately asks **`VBE7.DLL`** (`DllVbeGetHashOfCodeProjectEx`, …). Pure Rust would duplicate the VBA runtime and OLE project graph; optional future work is **FFI into `VBE7`**, not a small digest module. |

## Native `signtool` / Win32 backlog (not SIP-specific)

Split digest (`/dg`, `/ds`, …), sealing (`/seal`, `/itos`, …), biometric/enclave verify policies, PKCS#7-only product modes, etc. — see [`cli-parity-backlog.md`](cli-parity-backlog.md) and [`signtool-cli-matrix.json`](signtool-cli-matrix.json).

## Tier 1b / 1c style gaps inside Rust SIP

| Item | Status |
|------|--------|
| PE **PKCS#7 encode** + **`WIN_CERTIFICATE`** embed entirely in Rust | **`pe_embed`**: **`wrap_pkcs7_der_authenticode_win_certificate`** + **`pe_append_authenticode_pkcs7_certificate`** (grow attribute cert table, patch security directory, **`pe_compute_image_checksum`**). **`pkcs7.rs`** parses/replaces **`SpcIndirectDataContent`**, **`encode_pkcs7_content_info_signed_data_der`** (**`SignedData` → DER `ContentInfo`** for embedding once a **`SignedData`** exists); **`signtool-portable`** inspect/extract/index/append PKCS#7 rows. Full **CMS `SignerInfo` producer** (digest binding, certs, optional timestamps) + unsigned-first-sign workflow still OS-delegated / missing. |
| **MSIX/Appx `CryptSIPDllCreateIndirectData`** | **`AppxSipCreateIndirectData`** / **`AppxBundleSipCreateIndirectData`** build the **APPX `SpcIndirectData`** blob at sign time; **`msix_digest`** only **verifies** recomputed AX\* vs PKCS#7 — see [`windows-signing-components.md`](windows-signing-components.md) (**AppxSip.dll**) and [`rust-sip-spec-refs.md`](rust-sip-spec-refs.md). |
| **RFC3161** timestamp construction in Rust | Stub (`crates/signtool-sip-digest/src/timestamp.rs` — `Rfc3161TimestampRequestPlan` / `build_timestamp_request_bytes` placeholder). Portable trust **`--prefer-timestamp-signing-time`** reads nested **`TSTInfo.genTime`** / PKCS#9 **`signing-time`** for **`exact_date`** (`crates/signtool-authenticode-trust/src/rfc3161_extract.rs`); **TSA signature / `MessageImprint` verification is not implemented** — see **`linux_trust_rfc3161_tsa_crypto_gap`**. |
| **`/ph`** **page hashes** (`SPC_PE_IMAGE_PAGE_HASHES`) | Portable **CMS extract** + **payload peel** + **flat `(offset,digest)*` parse** + **experimental contiguous file-offset verify** (`page_hashes`, CLI **`pe-has-page-hashes`** / **`pe-page-hash-info`** / **`verify-pe-page-hashes`**). Differs from **`WinVerifyTrust`** where checksum / security-directory handling diverges — native **`verify --verify-page-hashes`** remains the strict `/ph` reference. |
| **MSIX/Appx `SignerSignEx3` signing** (`signtool-rs sign` on `.msix`) | **`APPX_SIP_CLIENT_DATA`** + **`SIGNER_SIGN_EX2_PARAMS`** as **`pSipData`** for all cleartext **`MsixFamily`** paths (embedded and **`/dlib`** decoupled) so **`AppxSip.dll`** receives **`SIP_SUBJECTINFO.pClientData`**. CI may still record **`documented_rust_msix_sign_ex3_gap`** when native succeeds but Rust fails (**`CRYPT_E_NO_PROVIDER`** `0x80092006`, publisher / manifest mismatches, etc.). **`CreateFileW`** subject handle + **`--debug`** diagnostics remain; **`pCryptoPolicy`** is still **`NULL`** — see [**SignerSignEx3 / SIP glue**](rust-sip-spec-refs.md#signersignex3-and-sip-glue). **Publisher-vs-signer binding** is enforced in **`AppxSip.dll`** (manifest vs PKCS#7 signer), not in **`msix_digest`** — see [`windows-signing-components.md`](windows-signing-components.md). |
| **MSI installer policies** (`DisableSizeVerification`, `DisableLegacyVerification`) | Native **`MsiSIPVerifyIndirectData`** reads **`HKLM\Software\Policies\Microsoft\Windows\Installer`**. Portable **`msi_digest`** does not — digest parity targets the **OLE Signify-style layout**, not every enterprise policy branch. See **`MSISIP.DLL`** in [`windows-signing-components.md`](windows-signing-components.md). |
| **Catalog `.cat` — CTL members vs PKCS#7 self-check** | **`catalog_digest`** verifies **`messageDigest` ↔ hash(`eContent`)** for all **`SignerInfo`** rows (CMS consistency). **`WinVerifyTrust`** file ↔ catalog resolution (**`CryptCATAdminCalcHashFromFileHandle`**, CTL membership, policy) is **not** ported — see catalog notes under [`windows-signing-components.md`](windows-signing-components.md) and [`rust-sip-spec-refs.md`](rust-sip-spec-refs.md). |
| **PE Authenticode — OS trust / revocation / PinRules** | Portable **`trust-verify-*`** + **`signtool-authenticode-trust`** validate PKCS#7 + paths against **explicit anchors** (AuthRoot CAB certs + CTL thumbprints where **`SignedData`** framing matches). There is **no** Linux equivalent of **`CertVerifyCertificateChainPolicy`** with enterprise trust, **CTL PinRules**, or **revocation** unless added later — see [`authenticode-trust-stack.md`](authenticode-trust-stack.md). |

### Linux portable trust — stable gap identifiers (enterprise / CryptoAPI parity)

Use these labels in issues and release notes when scoping non-goals vs future work:

| ID | Topic |
|----|--------|
| **`linux_trust_no_revocation`** | No CRL / OCSP fetch or **`CERT_CHAIN_REVOCATION_CHECK_*`** parity in portable trust. |
| **`linux_trust_no_pinrules`** | No **`PinRulesSTL`** / auto-update pinning semantics. |
| **`linux_trust_no_disallowed_stl`** | No **`disallowedcertstl.cab`** fail-closed thumbprint set (only explicit anchors today). |
| **`linux_trust_no_trusted_publisher`** | No **`TrustedPublisher`** / enterprise policy stores. |
| **`linux_trust_rfc3161_tsa_crypto_gap`** | Portable trust extracts RFC3161 **`genTime`** / PKCS#9 **`signing-time`** for picky **`exact_date`** only; **no** RFC3161 token signature verification, TSA chain, or **`MessageImprint`** check (unlike a full **`CryptVerifyTimeStampSignature`**-style path). |

Prioritize based on whether you need **offline signing** without `mssign32` or **stronger verify-only parity** with `/ph`.

## Next milestones (suggested order)

1. **PE page-hash segments** — Align **contiguous verify** with **`WinVerifyTrust`** exclusions (checksum field, security dir pointer, certificate table) and add a fixture signed **with** `/ph` for regression tests (Linux CI via `signtool-portable` / `signtool-sip-digest`).
2. **Rust PKCS#7 encode + `WIN_CERTIFICATE` embed** — Outer **`ContentInfo`** re-encode from **`SignedData`** exists (**`encode_pkcs7_content_info_signed_data_der`**); still need **`SignerInfo`** assembly + remote signature octets. Unblocks offline PE experiments once CMS production lands; intersects split-digest (`/dg`, `/ds`) backlog.
3. **Encrypted MSIX (`EappxSip*`)** — Requires Windows encrypted-package crypto or constrained FFI; not a ZIP-only digest.
4. **VBA / `mso.dll`** — Only viable near-term via **`VBE7`** FFI or accepting permanent OS delegation.
5. **`signtool.exe` CLI backlog** — Sealing, biometric/enclave policy GUIDs, PKCS#7 product modes — see `cli-parity-backlog.md`.
