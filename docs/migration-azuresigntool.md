# Migrating from AzureSignTool

This project can replace **AzureSignTool** for Windows signing when built with **`--features azure-kv-sign`**. **`signtool-portable`** covers digest checks, verification, and (with **`--features azure-kv-sign-portable`**) the Key Vault **`keys/sign`** step on **digest files** — not full **`sign`** / embed (that stays **`signtool-windows`**).

**Azure Artifact Signing (Trusted Signing)** via Microsoft’s decoupled **`Azure.CodeSigning.Dlib.dll`** is **not** the Key Vault path: use **`--dlib`** / **`--trusted-signing-dlib-root`** with **`--dmdf`** only (never mixed with **`--azure-key-vault-url`**). See [`migration-artifact-signing.md`](migration-artifact-signing.md). PowerShell OpenAuthenticode overlap (inspect JSON, REST submit, EKU prefix selection) is summarized in [`psa-interoperability.md`](psa-interoperability.md).

## Signing (`signtool-windows`)

Build:

```text
cargo build -p signtool-rs --features azure-kv-sign --release --bin signtool-windows
```

Typical Azure-shaped invocation:

```text
signtool-windows.exe sign ^
  --azure-key-vault-url https://myvault.vault.azure.net ^
  --azure-key-vault-certificate my-cert ^
  --azure-key-vault-managed-identity ^
  --timestamp-url http://timestamp.digicert.com ^
  --timestamp-digest sha256 ^
  --file-digest sha256 ^
  -ifl files.txt ^
  path\to\*.dll ^
  other.exe
```

### Flags mapped from AzureSignTool

| AzureSignTool | signtool-windows |
|---------------|------------------|
| `-kvu` / `--azure-key-vault-url` | Same |
| `-kvc` | `--azure-key-vault-certificate` |
| `-kvcv` | `--azure-key-vault-certificate-version` |
| `-kvi`, `-kvs`, `-kvt` | Client credential trio |
| `-kva` | `--azure-key-vault-accesstoken` |
| `-kvm` | `--azure-key-vault-managed-identity` |
| `-au` | `--azure-authority` |
| `-tr`, `-td`, `-t`, `-fd`, `-d`, `-du`, `-ph`, `-nph`, `-as` | Existing sign flags (`--timestamp-url`, `--legacy-timestamp-url`, …) |
| `-ac` (repeatable) | `--ac` repeatable (`Vec`) |
| `-ifl` | `--input-file-list` |
| `-coe` | `--continue-on-error` |
| `-mdop` | `--max-degree-of-parallelism` |

**`-s` (skip signed)** in AzureSignTool conflicts with native **`/s` (certificate store name)** in this tool. Use **`--skip-signed`** instead.

### Authentication notes

- **Managed identity** calls the IMDS endpoint (`169.254.169.254`) with resource `https://vault.azure.net`, matching common VM/App Service scenarios.
- **Client credentials** use the v2.0 OAuth endpoint at `{authority}/{tenant}/oauth2/v2.0/token` with scope `https://vault.azure.net/.default`.
- **Access token** bypass (`-kva`) sends the bearer token directly to Key Vault REST.

Signing uses RSA PKCS#1 v1.5 over the file digest via Key Vault **`keys/sign`** (`RS256` / `RS384` / `RS512`). SHA-1 file digest is not supported on this path.

### Exit codes

AzureSignTool documents HRESULT-style batch exits (`README` **Exit Codes**):

| Outcome | Value |
|--------|------|
| Success | `0` |
| Partial success | `0x20000001` |
| All failed | `0xA0000002` |

Enable the same behavior with:

- **`--exit-codes azuresigntool`** (alias `azure`), or  
- Environment **`SIGNTOOL_RS_EXIT_CODES=azure`** (or `azuresigntool`).

The helper binary **`azure-sign-tool-compat`** sets the environment default to Azure HRESULT semantics before running the same CLI entry point.

Default **`signtool`** exit codes remain **`0` / `1` / `2`**.

### Linux / CI: Key Vault **`keys/sign`** on a raw digest

Build **`signtool-portable`** with **`--features azure-kv-sign-portable`**. Produce **`digest.bin`** with **`pe-digest`** / **`cab-digest`** (**`--encoding raw`**), then:

```bash
signtool-portable azure-key-vault-sign-digest \
  --azure-key-vault-url https://myvault.vault.azure.net \
  --azure-key-vault-certificate my-cert \
  --digest-file digest.bin \
  --digest-algorithm sha256 \
  --azure-key-vault-managed-identity
```

Stdout prints **standard base64** signature bytes (no PEM). **`--signature-output PATH`** writes **raw** signature. **ECDSA** certificates use **ES256** / **ES384** / **ES512** automatically (same as **`signtool-windows`** KV path). Embedding into a PE/CAB still requires Windows **`SignerSignEx3`** (this repo) or a **future portable CMS `SignedData` builder** that consumes these signature octets.

**Experimental (Linux PE layout only):** **`signtool-portable append-pe-pkcs7`** appends PKCS#7 DER as a new **`WIN_CERTIFICATE`** row and recomputes **`CheckSum`**. Use **`pe-checksum --strict`** on the output to gate ImageHlp-style checksum parity. This **does not** assemble PKCS#7 from KV signature bytes — it is for tooling / prototypes until portable **`SignedData`** encode lands.

## Verification with **`signtool-portable`**

AzureSignTool does not verify signatures. After signing on Windows, use portable verification on Linux/macOS CI agents where helpful, for example:

```text
signtool-portable verify-pe -- <artifact>
```

For **trust** validation with **explicit anchors** (no OS certificate store), use **`trust-verify-pe`** (or format-specific **`trust-verify-*`** commands). Short-lived signing certificates—common with Artifact Signing profiles—**need RFC3161 timestamping** at sign time so signatures remain verifiable after the leaf expires; combine digest checks with timestamp-aware trust options when applicable:

```text
signtool-portable trust-verify-pe ./artifact.exe \
  --prefer-timestamp-signing-time \
  --require-valid-timestamp \
  --anchor-dir ./anchors \
  --authroot-cab ./authroot.stl.cab
```

Optional **`--as-of YYYY-MM-DD`** fixes the verification instant for reproducible CI. More background and flag mapping: [`migration-artifact-signing.md`](migration-artifact-signing.md#portable-post-sign-verification).

Use the appropriate portable subcommands for your format (`verify-pe`, catalog checks, **`artifact-signing-metadata-check`** for JSON templates, etc.) as documented in that crate.

## Integration testing

Exercise the Key Vault path against a real vault (managed identity or client secret), then compare **`signtool-windows verify`** and **`signtool-portable`** results with a known-good AzureSignTool-signed artifact.
