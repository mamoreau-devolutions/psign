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

- `msix-minimal/AppxManifest.xml` — Identity publisher `CN=Test Code Signing Certificate` (matches Devolutions test signing cert). CI copies `target/debug/psign-tool-windows.exe` as `noop.exe` and adds `Assets/StoreLogo.png` before `MakeAppx pack`.

Optional MSI parity (`scripts/run-parity-diff.ps1`):
- `SIGNTOOL_RS_MSI_UNSIGNED_FIXTURE` -> path to an unsigned `.msi` (not bundled in-repo)
- Reuses `SIGNTOOL_RS_TEST_PFX` / `_PASSWORD` with PE parity
- Optional `SIGNTOOL_RS_MSI_TIMESTAMP_URL` for sign-time RFC3161 (native `/tr` `/td SHA256`)

## Linux Authenticode trust (`psign-tool-portable trust-verify-pe`)

Digest-only PE checks use **`tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi`** and **`tiny64.signed.efi`** (upstream **`authenticode-rs`** corpora; see that subtree’s license/README). **`trust-verify-pe`** needs **configured roots**. CI extracts the embedded terminal root into a temp **`--anchor-dir`** and passes **`--as-of 2023-07-01`** because the test signing cert expires in **2023** (wall-clock verification would fail).

Signed CAB RS256 / PKCS#7 extract tests use **`tests/fixtures/cab-authenticode-upstream/tiny-signed.cab`** (Devolutions test PFX + SDK **`signtool sign`**; regenerate via **`scripts/ci/build-signed-cab-fixture.ps1`** after **`bootstrap-devolutions-authenticode.ps1`**).

MSI PKCS#7 extract / RS256 tests use **`tests/fixtures/msi-authenticode-upstream/tiny-pkcs7-stub.msi`** — an **OLE stub** with **`\\u{5}DigitalSignature`** = **`tiny32`** PKCS#7; **`verify-msi`** intentionally fails. Regenerate: **`scripts/ci/build-msi-signature-stub.ps1`** or **`cargo run -p psign-sip-digest --bin psign-gen-msi-signature-stub`** (see that directory’s **`README.md`**).

Catalog **RS256** tests use **`tests/fixtures/catalog-authenticode-upstream/tiny32-content.cat`** (same PKCS#7 bytes as **`extract-pe-pkcs7`** on **`tiny32.signed.efi`**); **`verify-catalog`** fails (Authenticode vs CTL PKCS#9 scan). Regenerate: **`scripts/ci/build-catalog-pe-pkcs7-fixture.ps1`**.

**`unsigned-sample.ps1`** / **`unsigned-sample.vbs`** (and siblings) are **unsigned** script bodies used by **`psign-digest-cli`** tests (**`verify-script`** / **`portable_verify_negative_script_*`**) to assert marker-not-found failures.

Optional stronger coverage (not required for default CI):

- **Pinned `authrootstl.cab`:** download from Microsoft’s distribution channel, record **`SHA256`** in your pipeline, pass **`--authroot-cab`** plus any enterprise **`--anchor-dir`** roots.
- **Signed PE with known publisher:** e.g. a redistributable third-party binary — cache in CI, document **license** and **hash pins** here when you add it.

Do **not** commit proprietary Microsoft AuthRoot CABs or non-redistributable binaries without clearing licensing; prefer hashes + cache populated by CI secrets or manual runner setup.
