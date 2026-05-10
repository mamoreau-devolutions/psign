# Authenticode trust stack (portable)

This describes how **`crates/signtool-authenticode-trust`** composes crates for **Linux/macOS-style** Authenticode trust checks without **`CertGetCertificateChain`** / **`WinVerifyTrust`**.

## Responsibility split

| Layer | Crate | Role |
|-------|--------|------|
| PKCS#7 shell, **`SignerInfo`**, authenticated attributes | **`cms`**, **`der`** (via **`authenticode`** / **`picky`**) | Parse **`SignedData`**, locate **`messageDigest`**, carry DER blobs. |
| PE layout, indirect **`SpcIndirectData`**, image digest | **`authenticode`**, **`signtool-sip-digest`** | Enumerate embedded PKCS#7 from the PE certificate table; recompute **`pe_authenticode_digest`** for the embedded hash algorithm. |
| CMS Authenticode rules + X.509 chain verification | **`picky`** (`AuthenticodeSignature`, `authenticode_verifier`, `Cert::verifier`) | Validate **`messageDigest`** vs provided digest, signature over authenticated attributes, TBSCertificate signatures along **`issuer_chain`**, Basic Constraints / dates / EKU policy hooks. |
| Trust anchors | This crate (**`anchor`**, **`authroot_cab`**, **`authroot_ctl`**) | Phase A: load **`*.crt`/`*.cer`/`*.pem`** from **`--anchor-dir`**. Phase B: CAB **`*.stl`** → PKCS#7 **`SignedData`** **`eContent`** CTL parse for **SHA-1 subject identifiers** plus PKCS#7-embedded certs. |
| Policy knobs | **`policy::AuthenticodeTrustPolicy`** | Default **strict** code-signing EKU; CLI **`allow-loose-signing-cert`**, **`--prefer-timestamp-signing-time`** / **`--require-valid-timestamp`** (see [**Verification instant / timestamps**](#verification-instant--timestamps)), **`--as-of YYYY-MM-DD`** for **`exact_date`**. |
| Portable CLI | **`signtool-portable`** | **`trust-verify-pe`**, **`trust-verify-cab`**, **`trust-verify-catalog`**, **`trust-verify-detached`** share anchor flags; detached uses [`pkcs7_wire::normalize_pkcs7_der_for_authenticode`](../crates/signtool-sip-digest/src/pkcs7_wire.rs). |

## Verification order (per PKCS#7 blob)

1. Parse PKCS#7 with **`authenticode-rs`** to read the embedded **`messageDigest`** and infer **`PeAuthenticodeHashKind`**.
2. Recompute the PE Authenticode digest with **`pe_authenticode_digest`**; fail fast if it does not match.
3. Parse the same DER with picky **`AuthenticodeSignature::from_der`** and run **`authenticode_verifier()`** with **`require_basic_authenticode_validation(pe_digest)`**, **`ignore_chain_check()`** (chain is validated explicitly below), and **`exact_date`** (see [Verification instant / timestamps](#verification-instant--timestamps)).
4. Merge picky-decoded embedded certs with anchor / CAB-extracted certs; resolve the signing cert; walk **`issuer_chain_excluding_leaf`** to the terminal root.
5. Require the terminal root’s **SHA-1 thumbprint** (full cert DER, Windows-style) to appear in the configured **`AnchorStore`**.
6. **`leaf.verifier().chain(...).exact_date(...).verify()`** to validate signatures along the path.

Normative background and CTL/bootstrap notes live in **[plan-linux-authenticode-trust-verify.md](plan-linux-authenticode-trust-verify.md)**.

## Verification instant / timestamps

**`exact_date`** passed to picky controls not-before / not-after checks on the chain. Resolution order:

1. **`--as-of YYYY-MM-DD`** (CLI) / **`verification_instant_override`** — fixed UTC midnight for reproducible CI or expired-leaf fixtures.
2. Otherwise, if **`prefer_timestamp_signing_time`** is **false** (default): wall clock **`UtcDate::now()`**.
3. If **`prefer_timestamp_signing_time`** is **true**: **[`rfc3161_extract::utc_date_from_authenticode_timestamp_token`](../crates/signtool-authenticode-trust/src/rfc3161_extract.rs)** scans CMS **`SignedData`** **`SignerInfo`** rows — **first** nested PKCS#7 with **`id-ct-TSTInfo`** encapsulated content and a parsable **`TSTInfo.genTime`** wins; if none, the **first** PKCS#9 **`signing-time`** in signed attributes wins. If still none and **`require_valid_timestamp`** is set, verification fails; if **`require_valid_timestamp`** is unset, falls back to wall clock.

**Security note:** extraction uses DER structure only. There is **no** verification that the timestamp token’s CMS signature matches the TSA, that **`MessageImprint`** matches the primary signature digest, or that the TSA chain is trusted — see **`linux_trust_rfc3161_tsa_crypto_gap`** in [`rust-sip-gaps.md`](rust-sip-gaps.md).

## Non-goals (MVP)

- OS **AuthRoot** / **Intermediate** stores, **PinRules**, enterprise **TrustedPublisher**, or **revocation** (CRL/OCSP).
- Full RFC3161 **token** verification (TSA chain + signed **`MessageImprint`** + **`TSTInfo`** integrity); portable code only uses extracted times for **`exact_date`**.
