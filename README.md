# signtool-rs

`signtool-rs` is a **Rust port** of the Windows SDK **`signtool.exe`** behavior
(sign, verify, timestamp, remove, and related Authenticode flows), validated with
differential parity tests against the native tool where CI fixtures allow.

## Current command coverage

- `verify`: WinVerifyTrust-backed implementation with policy modes (`default`, `pa`, `pg`).
- `sign`: Rust mssign32 core (`SignerSignEx3`) with PFX/system-store cert selection, RFC3161 sign-time timestamping, and decoupled-digest bridge flow (`--dlib` or `--trusted-signing-dlib-root` + `--dmdf`) for MSIX parity and [Azure Artifact Signing / Trusted Signing](docs/migration-artifact-signing.md).
- `inspect-signature`: JSON dump of PKCS#7 signers, timestamp OIDs, and nested signatures (`1.3.6.1.4.1.311.2.4.1`) — same parser as **`signtool-portable inspect-authenticode`** ([docs/psa-interoperability.md](docs/psa-interoperability.md)).
- `timestamp`: Rust mssign32 core (`SignerTimeStampEx3`/`SignerTimeStampEx2`) plus AppX restrictions.

## MSIX parity notes

- MSIX/AppX signing requires `--timestamp-url` in the current parity profile.
- Sign-time digest controls now distinguish file digest (`--digest`, native `/fd`) and RFC3161 timestamp digest (`--timestamp-digest`, native `/td`).
- Decoupled digest inputs (`--dlib` + `--dmdf`) are executed via a native-signature bridge path and parity-gated in CI scenarios.

## Build

```powershell
cargo build
```

At the repo root, **`cargo build`** targets **`default-members`** only (**portable digest crates**). On Windows, build the **`signtool-windows`** executable with **`cargo windows-bin`** or **`cargo build -p signtool-rs --bin signtool-windows`** (see [`.cargo/config.toml`](.cargo/config.toml)). Optional Cargo features: **`azure-kv-sign`** (Key Vault digest callback), **`artifact-signing-rest`** (**`artifact-signing-submit`** LRO against **`*.codesigning.azure.net`**).

## Linux / portable digest tooling

The **`signtool-windows`** CLI (package **`signtool-rs`**) is Windows-only (stub exits on other targets). Cross-platform pieces live in **`signtool-sip-digest`** and the **`signtool-portable`** binary (`crates/signtool-digest-cli`). They exercise the same PE-derived Authenticode digest logic used for **PE and WinMD** (CLI metadata), plus CAB, MSI, ESD/WIM, cleartext MSIX, catalog, and scripts—without **`WinVerifyTrust`**.

**Feature gaps vs native `signtool`, AzureSignTool, and Azure Artifact Signing:** [`docs/gap-analysis-signing-platforms.md`](docs/gap-analysis-signing-platforms.md).

From the repo root (see [`docs/roadmap-authenticode-linux.md`](docs/roadmap-authenticode-linux.md)):

```sh
cargo install --path crates/signtool-digest-cli --locked   # installs `signtool-portable`
# Optional: Azure Code Signing `:sign` LRO on Linux/macOS (same as `signtool-windows artifact-signing-submit`):
# cargo install --path crates/signtool-digest-cli --locked --features artifact-signing-rest
cargo digest-test    # alias: sip-digest + authenticode-trust + codesigning-rest lib tests + digest-cli integration tests
cargo digest-check   # alias: `cargo check` on portable workspace crates (includes `signtool-codesigning-rest`)
```

Unix CI (`ci-unix`) runs **`cargo fmt`**, strict **`clippy -D warnings`** on those crates plus the **`signtool-rs` library**, and the digest CLI tests. Local mirror (bash): **`scripts/linux-portable-validation.sh`** from the repo root.

## Generate binary manifest and dependency graph

```powershell
cargo run -p signtool-rs --bin depgraph -- --signtool "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
# Same thing (workspace default-members omit the main crate; the alias supplies `-p signtool-rs`):
cargo depgraph -- --signtool "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
```

Output files (gitignored **`parity-output/`**):

- `parity-output/binary-manifest.json`
- `parity-output/dependency-graph.json`

Component reference (**exe/DLL roles**, SIP map, relationship diagram): [`docs/windows-signing-components.md`](docs/windows-signing-components.md).

### Optional local copies of inbox signing binaries

```powershell
./scripts/copy-windows-signing-binaries.ps1
# Optional: amd64 + WOW64 crypt32.dll (large).
./scripts/copy-windows-signing-binaries.ps1 -IncludeCrypt32
```

Writes **`parity-output/vendor-binaries/`** (WOW64 under **`syswow64/`**): inbox SIP DLLs, **`imagehlp.dll`**, optional **`crypt32.dll`**, Office **`mso.dll`** / **`VBE7.DLL`** when found, plus SDK **`mssign32.dll`** and **`signtool.exe`** when **Windows Kits\10\bin** is installed.

## Run tests

```powershell
cargo test --workspace
cargo test --test parity_signtool -- --ignored --nocapture
./scripts/run-parity-diff.ps1 -FailOnSemantic
```

`-FailOnSemantic` requires `SIGNTOOL_RS_UNSIGNED_FIXTURE` and `SIGNTOOL_RS_TEST_PFX`. Add `-FailOnSemanticExhaustive` when timestamp, MSIX package, and detached PKCS#7 env vars are also set (see [`docs/ci-parity.md`](docs/ci-parity.md)).

## CI parity (GitHub Actions)

The **`windows`** workflow builds the repo, bootstraps the public Devolutions test CA/PFX (pinned raw URLs — no signing secrets), derives signed/detached fixtures, packs a minimal unsigned MSIX, and runs `./scripts/ci/run-exhaustive-parity-ci.ps1`. Details and extension workflows live in [`docs/ci-parity.md`](docs/ci-parity.md). The workflow fails only on `semanticMismatchCount` in the generated **`parity-output/parity-report.json`** (that directory is gitignored; the JSON is a CI artifact or local output); rows classified `documented_*` (for example UTF-16 response files native cannot parse) do not fail the gate.

Local mirror of the CI orchestrator:

```powershell
cargo build -p signtool-rs --bin signtool-windows
./scripts/ci/run-exhaustive-parity-ci.ps1
```

## MSIX parity signing script

Use the dedicated local parity runner to sign the same unsigned MSIX with native `signtool.exe` and `signtool-windows`, then compare verification outcomes:

```powershell
$env:SIGNTOOL_RS_MSIX_UNSIGNED_FIXTURE="D:\path\unsigned.msix"
$env:SIGNTOOL_RS_MSIX_TEST_PFX="D:\path\authenticode-test-cert.pfx"
$env:SIGNTOOL_RS_MSIX_TEST_PFX_PASSWORD="CodeSign123!"
$env:SIGNTOOL_RS_MSIX_TIMESTAMP_URL="http://timestamp.digicert.com"
./scripts/msix-parity-sign.ps1 -FailOnSemantic
```

If you already imported the Devolutions test cert into `CurrentUser\\My`, you can use thumbprint mode instead of a PFX:

```powershell
$env:SIGNTOOL_RS_MSIX_UNSIGNED_FIXTURE="D:\path\unsigned.msix"
$env:SIGNTOOL_RS_MSIX_TEST_CERT_SHA1="A9FDF3593E91689CC93B1CEBED5E8FFC1F6FEE38"
$env:SIGNTOOL_RS_MSIX_TIMESTAMP_URL="http://timestamp.digicert.com"
./scripts/msix-parity-sign.ps1 -FailOnSemantic
```

Optional decoupled digest parity:

```powershell
$env:SIGNTOOL_RS_MSIX_DLIB="D:\path\provider.dll"
$env:SIGNTOOL_RS_MSIX_DMDF="D:\path\metadata.json"
./scripts/msix-parity-sign.ps1 -UseDecoupledDigest -FailOnSemantic
```

Report artifact:

- `parity-output/msix-parity-sign-report.json`

You can also invoke the focused path through the main harness:

```powershell
./scripts/run-parity-diff.ps1 -MsixOnly -FailOnSemantic
```
