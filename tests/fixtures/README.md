Place local test fixtures here.

Suggested corpus:
- `unsigned.exe`
- `signed-valid.exe`
- `signed-expired.exe`
- `signed-bad-digest.exe`

MSIX parity fixtures:
- `unsigned.msix` (an unsigned package copied for native/rust sign comparisons)
- optional decoupled assets referenced by env:
  - `SIGNTOOL_RS_MSIX_DLIB`
  - `SIGNTOOL_RS_MSIX_DMDF`

Devolutions test cert quick setup (trusted local testing only):
- `SIGNTOOL_RS_MSIX_TEST_PFX` -> path to `authenticode-test-cert.pfx`
- `SIGNTOOL_RS_MSIX_TEST_PFX_PASSWORD` -> usually `CodeSign123!`
- `SIGNTOOL_RS_MSIX_TEST_CERT_SHA1` -> alternative when cert is already imported in `CurrentUser\My`
- `SIGNTOOL_RS_MSIX_TIMESTAMP_URL` -> RFC3161 timestamp URL for parity runs

MSIX minimal pack layout (CI-generated unsigned package):

- `msix-minimal/AppxManifest.xml` — Identity publisher `CN=Test Code Signing Certificate` (matches Devolutions test signing cert). CI copies `target/debug/signtool-windows.exe` as `noop.exe` and adds `Assets/StoreLogo.png` before `MakeAppx pack`.

Optional MSI parity (`scripts/run-parity-diff.ps1`):
- `SIGNTOOL_RS_MSI_UNSIGNED_FIXTURE` -> path to an unsigned `.msi` (not bundled in-repo)
- Reuses `SIGNTOOL_RS_TEST_PFX` / `_PASSWORD` with PE parity
- Optional `SIGNTOOL_RS_MSI_TIMESTAMP_URL` for sign-time RFC3161 (native `/tr` `/td SHA256`)

## Linux Authenticode trust (`signtool-portable trust-verify-pe`)

Digest-only PE checks use **`tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi`** and **`tiny64.signed.efi`** (upstream **`authenticode-rs`** corpora; see that subtree’s license/README). **`trust-verify-pe`** needs **configured roots**. CI extracts the embedded terminal root into a temp **`--anchor-dir`** and passes **`--as-of 2023-07-01`** because the test signing cert expires in **2023** (wall-clock verification would fail).

Optional stronger coverage (not required for default CI):

- **Pinned `authrootstl.cab`:** download from Microsoft’s distribution channel, record **`SHA256`** in your pipeline, pass **`--authroot-cab`** plus any enterprise **`--anchor-dir`** roots.
- **Signed PE with known publisher:** e.g. a redistributable third-party binary — cache in CI, document **license** and **hash pins** here when you add it.

Do **not** commit proprietary Microsoft AuthRoot CABs or non-redistributable binaries without clearing licensing; prefer hashes + cache populated by CI secrets or manual runner setup.
