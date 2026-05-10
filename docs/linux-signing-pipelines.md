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

## 3. AzureSignTool equivalent on Linux

**Not supported end-to-end.** Key Vault **`keys/sign`** is wired only in **`signtool-windows`** (`--features azure-kv-sign`). Plan: Windows job for sign+embed; Linux job for **`trust-verify-*`** / **`verify-*`**.

Details: [`migration-azuresigntool.md`](migration-azuresigntool.md).

## 4. Roadmap — portable embed + more formats

Ordered backlog (engineering): [`roadmap-authenticode-linux.md`](roadmap-authenticode-linux.md) (Phase 2 stretch: PKCS#7 + PE **`WIN_CERTIFICATE`**, then CAB/MSI/MSIX). SIP coverage limits: [`rust-sip-gaps.md`](rust-sip-gaps.md).
