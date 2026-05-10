# Azure Trusted Signing (Artifact Signing) with signtool-windows

Microsoft **Artifact Signing** (often called **Trusted Signing**) integrates with native **SignTool** through a **decoupled digest DLL** (`Azure.CodeSigning.Dlib.dll`) and a **JSON metadata file** consumed via **`/dmdf`**. Official setup: [Set up signing integrations](https://learn.microsoft.com/azure/artifact-signing/how-to-signing-integrations) and the [Microsoft.ArtifactSigning.Client](https://www.nuget.org/packages/Microsoft.ArtifactSigning.Client) package.

**signtool-windows** uses the same Win32 bridge as SignTool: **`SignerSignEx3`** with **`SIGNER_DIGEST_SIGN_INFO`** pointing at the DLL exports (this repo prefers **`AuthenticodeDigestSignExWithFileHandle`** when present, matching Microsoft’s Azure dlib).

**signtool-portable** cannot load the mixed-mode/.NET dlib or call **`SignerSignEx3`**; use it **after** embedding for digest consistency checks and **anchor-based trust verification** (see [Portable post-sign verification](#portable-post-sign-verification) below). With **`--features artifact-signing-rest`** it can still call the same **`:sign`** REST LRO as **`signtool-windows`** (hash in → JSON out — embedding remains a separate step).

### Optional: Azure Code Signing **REST** hash signing (experimental)

PowerShell OpenAuthenticode can sign via the **`Azure.CodeSigning.Sdk`** client against the same **data-plane** API documented in Azure REST specs (**`CertificateProfileOperations_Sign`**, host template **`https://{region}.codesigning.azure.net/`**, OAuth scope **`https://codesigning.azure.net/.default`**).

With **`cargo build -p signtool-rs --features artifact-signing-rest --bin signtool-windows`**:

```powershell
signtool-windows.exe artifact-signing-submit `
  --region westus `
  --account-name myAccount `
  --profile-name myProfile `
  --digest-file .\digest.sha256.bin `
  --signature-algorithm RS256 `
  --managed-identity
```

This runs the **`:sign`** LRO and prints the final JSON (**`signature`**, **`signingCertificate`**, …). It does **not** embed an Authenticode PKCS#7 into a PE by itself — combine with your signing pipeline or continue using **`--dlib`** / **`--trusted-signing-dlib-root`** for **`SignerSignEx3`** embedding.

#### Linux / CI: same REST helper from **`signtool-portable`**

Build or install with **`--features artifact-signing-rest`**, then use **`artifact-signing-submit`** with the same flags as Windows. Produce a raw Authenticode digest file from an unsigned PE with **`pe-digest --encoding raw --output digest.bin`** (SHA-256 → 32 bytes).

```bash
cargo build -p signtool-digest-cli --features artifact-signing-rest --locked
./target/debug/signtool-portable pe-digest --algorithm sha256 --encoding raw --output digest.bin ./MyApp.exe
./target/debug/signtool-portable artifact-signing-submit \
  --region westus --account-name myAccount --profile-name myProfile \
  --digest-file digest.bin --signature-algorithm RS256 --managed-identity
```

Optional debug logs: **`SIGNTOOL_PORTABLE_DEBUG=1`**.

## Flag mapping (Microsoft sample → signtool-windows)

| SignTool / docs | signtool-windows |
|-----------------|------------------|
| `/dlib` path to `Azure.CodeSigning.Dlib.dll` | `--dlib <path>` |
| Same, but NuGet extract root | `--trusted-signing-dlib-root <root>` → resolves to `<root>\bin\x64\Azure.CodeSigning.Dlib.dll` or `<root>\bin\x86\...` matching **this executable’s** architecture (`cfg!(target_pointer_width)`) |
| `/dmdf` metadata JSON | `--dmdf <path>` |
| `/fd SHA256` | `--digest sha256` |
| `/tr` RFC3161 URL | `--timestamp-url <url>` |
| `/td SHA256` | `--timestamp-digest sha256` |

**`--dlib` and `--trusted-signing-dlib-root` are mutually exclusive** (Clap `conflicts_with`).

### Example (PE)

Adjust paths to your extracted NuGet layout and metadata file:

```powershell
signtool-windows.exe sign `
  --digest sha256 `
  --timestamp-url http://timestamp.acs.microsoft.com/ `
  --timestamp-digest sha256 `
  --trusted-signing-dlib-root "D:\pkgs\Microsoft.ArtifactSigning.Client\extracted" `
  --dmdf "D:\configs\artifact-signing-metadata.json" `
  --auto-select `
  .\MyApp.exe
```

Or pass the DLL explicitly:

```powershell
signtool-windows.exe sign `
  --digest sha256 `
  --timestamp-url http://timestamp.acs.microsoft.com/ `
  --timestamp-digest sha256 `
  --dlib "D:\pkgs\...\bin\x64\Azure.CodeSigning.Dlib.dll" `
  --dmdf "D:\configs\artifact-signing-metadata.json" `
  --auto-select `
  .\MyApp.exe
```

Microsoft recommends **`http://timestamp.acs.microsoft.com/`** with **`SHA256`** timestamp digest for **short-lived profile certificates** so signatures remain verifiable after the signing certificate expires.

### Metadata JSON (`--dmdf`)

Follow Microsoft’s documented shape: regional **`Endpoint`**, **`CodeSigningAccountName`**, **`CertificateProfileName`**, and optionally **`ExcludeCredentials`** (array of credential type names to exclude from the Azure credential chain). Keep **`Endpoint`** aligned with your Artifact Signing region.

Validate checked-in templates **without signing** using portable **`artifact-signing-metadata-check`**:

```bash
signtool-portable artifact-signing-metadata-check --path ./artifact-signing-metadata.json
# or
cat ./artifact-signing-metadata.json | signtool-portable artifact-signing-metadata-check
```

## Runtime layout: NuGet `bin\x64` or `bin\x86`

Deploy the **full** `bin\x64` or `bin\x86` folder from the NuGet package next to **`Azure.CodeSigning.Dlib.dll`** (dependent assemblies and loaders). The process loading the dlib must find those DLLs—typically by keeping the **working directory** or **DLL search path** consistent with how you extracted the package.

Prerequisites:

- **.NET 8** runtime where Microsoft’s tooling expects it.
- **Architecture match**: use **x64** dlib with **64-bit** `signtool-windows`, **x86** with **32-bit** builds. Mismatch commonly surfaces as **`LoadLibraryW` failures** (see troubleshooting).

### Troubleshooting `LoadLibraryW` failures

When **`--dlib`** (or the path resolved from **`--trusted-signing-dlib-root`**) fails to load, verify:

1. **.NET 8** is installed and repairable on the machine.
2. The **entire** `bin\<arch>` directory from the NuGet package is deployed so dependent DLLs resolve.
3. **PE architecture** of **`Azure.CodeSigning.Dlib.dll`** matches **`signtool-windows`** (x64 vs x86).

## Conflict matrix: Artifact Signing vs Azure Key Vault

**Artifact Signing** uses **decoupled digest** mode only (**`--dlib`** or **`--trusted-signing-dlib-root`** **+** **`--dmdf`**).

**Azure Key Vault** signing (**`--azure-key-vault-url`** and related flags) is a **separate** implementation path. **`signtool-windows` rejects combining Key Vault options with `--dlib`, `--dmdf`, or `--trusted-signing-dlib-root`.**

If your team uses both workflows, keep them on **different invocations** or build targets—do not mix flags on one command line.

For migrating from **AzureSignTool** (KV-focused CLI), see [`migration-azuresigntool.md`](migration-azuresigntool.md).

## Portable post-sign verification

On Linux/macOS (or Windows without the dlib), use **`signtool-portable`** after the signed artifact exists:

1. **`verify-pe`** — PKCS#7 indirect digest vs recomputed PE digest (no trust anchors).
2. **`trust-verify-pe`** — CMS validation **plus** explicit anchor trust (**`--anchor-dir`**, **`--authroot-cab`**) and policy options.

Short-lived signing certificates **require a valid RFC3161 timestamp** for verification long after profile expiry. Combine digest verification with trust verification options such as:

- **`--prefer-timestamp-signing-time`** — prefer timestamp token time for **`exact_date`**-style checks.
- **`--require-valid-timestamp`** — fail if no usable timestamp exists (use with **`--prefer-timestamp-signing-time`**).
- **`--as-of YYYY-MM-DD`** — reproducible verification date.
- **`--anchor-dir`** / **`--authroot-cab`** — supply roots explicitly (portable path does not use the OS store).

Example:

```bash
signtool-portable verify-pe ./MyApp.exe
signtool-portable trust-verify-pe ./MyApp.exe \
  --prefer-timestamp-signing-time \
  --require-valid-timestamp \
  --anchor-dir ./anchors \
  --authroot-cab ./authroot.stl.cab
```

## MSIX / APPX

MSIX uses the same **`SignerSignEx3`** SIP stack and the same decoupled **`--dlib` / `--dmdf`** bridge. **`--page-hashes`** for MSIX requires decoupled digest inputs. See also [`rust-sip-spec-refs.md`](rust-sip-spec-refs.md).

## CI / gated parity recipe

Optional integration test (ignored by default) exercises decoupled signing when environment variables point at real fixtures. See **`artifact_signing_decoupled_pe_executes`** in [`tests/parity_signtool.rs`](../tests/parity_signtool.rs) and the **Artifact Signing** row in [`ci-parity.md`](ci-parity.md).

Required-style variables when running that test locally:

| Variable | Purpose |
|----------|---------|
| `SIGNTOOL_RS_ARTIFACT_SIGNING_UNSIGNED_PE` | Unsigned PE to copy and sign |
| `SIGNTOOL_RS_ARTIFACT_SIGNING_METADATA` | Path to `--dmdf` JSON |
| `SIGNTOOL_RS_ARTIFACT_SIGNING_DLIB` | Explicit `--dlib` path (**or** use root below) |
| `SIGNTOOL_RS_ARTIFACT_SIGNING_DLIB_ROOT` | NuGet extract root for `--trusted-signing-dlib-root` |
| `SIGNTOOL_RS_ARTIFACT_SIGNING_TIMESTAMP_URL` | RFC3161 URL (e.g. ACS) |
| `SIGNTOOL_RS_ARTIFACT_SIGNING_TEST_PFX` | PFX for cert selection in this tool’s store/PFX path |
| `SIGNTOOL_RS_ARTIFACT_SIGNING_TEST_PFX_PASSWORD` | Optional PFX password |

Either **`SIGNTOOL_RS_ARTIFACT_SIGNING_DLIB`** or **`SIGNTOOL_RS_ARTIFACT_SIGNING_DLIB_ROOT`** must be set; the test prefers **`_DLIB`** when both are present.

<a id="rest-hash-signing-gated-smoke-test"></a>

### REST hash signing (gated smoke test)

Build with **`--features artifact-signing-rest`**, then run the ignored test **`artifact_signing_rest_submit_smoke`** when you have a **Trusted Signing** account and a **raw digest file** (for example **32 bytes** for SHA-256):

```powershell
cargo test -p signtool-rs --features artifact-signing-rest `
  --test parity_signtool artifact_signing_rest_submit_smoke -- --ignored --nocapture
```

| Variable | Purpose |
|----------|---------|
| `SIGNTOOL_RS_ARTIFACT_SIGNING_REST_REGION` | Regional segment (e.g. `westus`) |
| `SIGNTOOL_RS_ARTIFACT_SIGNING_REST_ACCOUNT_NAME` | Code signing account name |
| `SIGNTOOL_RS_ARTIFACT_SIGNING_REST_PROFILE_NAME` | Certificate profile name |
| `SIGNTOOL_RS_ARTIFACT_SIGNING_REST_DIGEST_FILE` | Path to raw digest bytes |
| `SIGNTOOL_RS_ARTIFACT_SIGNING_REST_SIGNATURE_ALGORITHM` | Optional (default API/`RS256`) |

Authentication (**one** path):

| Variable | Purpose |
|----------|---------|
| `SIGNTOOL_RS_ARTIFACT_SIGNING_REST_ACCESS_TOKEN` | Bearer token for **`https://codesigning.azure.net/.default`** |
| `SIGNTOOL_RS_ARTIFACT_SIGNING_REST_MANAGED_IDENTITY` | Set to **`1`** / **`true`** / **`yes`** for IMDS (VMs/containers) |
| `SIGNTOOL_RS_ARTIFACT_SIGNING_REST_TENANT_ID` | With client credentials |
| `SIGNTOOL_RS_ARTIFACT_SIGNING_REST_CLIENT_ID` | With client credentials |
| `SIGNTOOL_RS_ARTIFACT_SIGNING_REST_CLIENT_SECRET` | With client credentials |
