# Linux signing pipelines (what works today)

**`signtool-portable`** on Linux/macOS does **not** embed Authenticode PKCS#7 into PE/CAB/MSIX yet (`pe_embed.rs` / CMS producer stubs — see [`rust-sip-gaps.md`](rust-sip-gaps.md)). This page describes **practical hybrid** flows and **verify-only** flows.

For tool-by-tool gaps vs **`signtool.exe`**, AzureSignTool, and Artifact Signing, see [`gap-analysis-signing-platforms.md`](gap-analysis-signing-platforms.md). For IDA / **ilspycmd** workflows on native binaries, see [`reversing-playbook-authenticode.md`](reversing-playbook-authenticode.md).

## 1. Verify-only on Linux (recommended CI gate)

After any Windows signing job:

| Format | Commands |
|--------|----------|
| PE | `verify-pe`, `trust-verify-pe` (+ anchors), `inspect-authenticode` |
| CAB | `verify-cab`, `trust-verify-cab` |
| MSI / ESD / MSIX / catalog / scripts | matching **`verify-*`** |

Automation: **`cargo digest-test`**, **`scripts/linux-portable-validation.sh`**, GitHub **`ci-unix`**. Windows differential parity: **`scripts/run-parity-diff.ps1`** (see [`ci-parity.md`](ci-parity.md)).

## 2. Azure Artifact Signing — digest + REST on Linux, embed on Windows

Build **`signtool-portable`** with **`--features artifact-signing-rest`**.

1. **Subject digest** (raw bytes for REST body):

   ```bash
   signtool-portable pe-digest --algorithm sha256 --encoding raw --output digest.bin ./MyApp.exe
   # CAB:
   signtool-portable cab-digest --algorithm sha256 --encoding raw --output digest.bin ./My.cab
   ```

2. **`:sign` LRO** (same as **`signtool-windows artifact-signing-submit`**):

   ```bash
   signtool-portable artifact-signing-submit \
     --region REGION --account-name ACCOUNT --profile-name PROFILE \
     --digest-file digest.bin --signature-algorithm RS256 \
     --managed-identity   # or --access-token / tenant + client-id + client-secret
   ```

3. **Embed** PKCS#7 / complete Authenticode: still **`signtool-windows`** + **`SignerSignEx3`** (and typically **`--dlib`** / **`--dmdf`** for Trusted Signing) until a portable embedder exists.

Optional debug: **`SIGNTOOL_PORTABLE_DEBUG=1`**.

Details: [`migration-artifact-signing.md`](migration-artifact-signing.md).

## 3. AzureSignTool — Key Vault digest sign on Linux

**Partial.** Use **`pe-digest` / `cab-digest`** (**`--encoding raw`**) plus **`azure-key-vault-sign-digest`** with **`--features azure-kv-sign-portable`** for the **`keys/sign`** HTTP step (see [`migration-azuresigntool.md`](migration-azuresigntool.md)). **Embed** PKCS#7 on Windows with **`signtool-windows`** (`--features azure-kv-sign`) or native **`signtool.exe`**.

Details: [`migration-azuresigntool.md`](migration-azuresigntool.md).

## 4. Roadmap — portable embed + more formats

Ordered backlog (engineering): [`roadmap-authenticode-linux.md`](roadmap-authenticode-linux.md) (Phase 2 stretch: PKCS#7 + PE **`WIN_CERTIFICATE`**, then CAB/MSI/MSIX). SIP coverage limits: [`rust-sip-gaps.md`](rust-sip-gaps.md).

**PE checksum:** **`signtool-portable pe-checksum ./file.exe`** compares optional-header **`CheckSum`** to **`pe_compute_image_checksum`** (same algorithm used after **`append-pe-pkcs7`**). **`--strict`** fails when they differ.

**Library + CLI:** [`signtool-sip-digest::pkcs7`](../crates/signtool-sip-digest/src/pkcs7.rs) exposes **`parse_pe_pkcs7_spc_indirect_data`** (read **`SpcIndirectDataContent`** from an embedded PE PKCS#7), **`spc_indirect_data_replace_message_digest`** (swap the **`messageDigest`** octets while keeping **`SpcPeImageData`**), and **`signed_data_replace_encapsulated_spc_indirect`** (rewrite **`SignedData.encapContentInfo.eContent`** — **`SignerInfo`** signature becomes invalid until rebuilt; see doc comment). On Linux, **`signtool-portable inspect-pe-spc-indirect ./file.exe`** prints JSON (OIDs, digest hex, SIP match flag) for the same structure—use **`--index N`** to match the *N*th PKCS#7 row (**`list-pe-pkcs7`** / **`extract-pe-pkcs7`** order)—useful before a portable **`SignedData`** / **`WIN_CERTIFICATE`** rebuild exists. **`signtool-portable extract-pe-pkcs7 ./file.exe`** writes embedded PKCS#7 DER to stdout (or **`--output`**); use **`--index N`** for the *N*th **`WIN_CERT_TYPE_PKCS_SIGNED_DATA`** row (multi-signed binaries). **`signtool-portable list-pe-pkcs7 ./file.exe`** prints **`pkcs7_entries`** and each row’s **`byte_len`** (same index order as **`extract-pe-pkcs7`**). **`signtool-portable append-pe-pkcs7 --pe in.exe --pkcs7 blob.der --output out.exe`** appends a PKCS#7 row via **`pe_embed`** and refreshes the PE **image checksum** (experimental — not a full CMS signer).
