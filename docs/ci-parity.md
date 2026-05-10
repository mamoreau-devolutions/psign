# CI parity tiers

GitHub Actions exercises differential parity between native `signtool.exe` and **`signtool-windows`** (crate **`signtool-rs`**). Certificate material comes from the public **Devolutions Authenticode** test PKI ([`devolutions-authenticode`](https://github.com/Devolutions/devolutions-authenticode)): `authenticode-test-ca.crt` and `authenticode-test-cert.pfx` with password `CodeSign123!` (test-only; do not use in production).

## Tier 1 — Default workflow (`windows.yml`)

Runs on every push, PR, and daily schedule.

1. **`scripts/ci/bootstrap-devolutions-authenticode.ps1`** — Downloads CA + PFX from raw URLs pinned to a fixed commit SHA, imports the CA into the machine (or user) trusted root, sets `SIGNTOOL_RS_TEST_PFX*` and timestamp URLs.
2. **`scripts/ci/prepare-parity-fixtures.ps1`** — Native-signs a temp PE (`SIGNTOOL_RS_SIGNED_FIXTURE`) for timestamp scenarios; produces detached PKCS#7 via native `signtool sign /p7 …` (`SIGNTOOL_RS_DETACHED_*`).
3. **`scripts/ci/pack-minimal-msix.ps1`** — Packs [`tests/fixtures/msix-minimal/`](../tests/fixtures/msix-minimal/AppxManifest.xml) + `noop.exe` (copy of the built `signtool-windows.exe`) into an unsigned `.msix`.
4. **`scripts/ci/pack-minimal-winmd.ps1`** — Copies the same unsigned `signtool-windows.exe` to **`SIGNTOOL_RS_WINMD_UNSIGNED_FIXTURE`** (`.winmd` extension) so **`run-parity-diff`** exercises WinMD SIP scenarios; **`SIGNTOOL_RS_WINMD_TIMESTAMP_URL`** mirrors **`SIGNTOOL_RS_TIMESTAMP_URL`** when set after bootstrap.
5. **`scripts/run-parity-diff.ps1 -FailOnSemantic -FailOnSemanticExhaustive`** — Static CLI matrix, remove scenarios, PE + script description parity, timestamp exits, detached verify, catalog path if env set, MSIX semantic blocks when env present, WinMD scenarios when the WinMD fixture env is set, etc. Exhaustive mode asserts that core PE, timestamp, MSIX package, and detached env vars are all set before running.
6. **`scripts/msix-parity-sign.ps1 -FailOnSemantic`** — Focused MSIX sign/verify report (`parity-output/msix-parity-sign-report.json`).

Artifacts: `parity-output/parity-report.json`, `parity-output/msix-parity-sign-report.json` (uploaded as workflow artifacts). The **`parity-output/`** directory is gitignored, so clones do not contain those JSON files until you run parity locally or download CI artifacts.

## Local `run-parity-diff.ps1` snapshot

Optional parity scenarios are gated on environment variables (`SIGNTOOL_RS_MSIX_*`, `SIGNTOOL_RS_SIGNED_FIXTURE` + timestamp URL, detached PKCS#7 paths, catalog paths, and so on). If only a **subset** is set—for example an MSIX fixture path without the matching PFX and RFC3161 URL—the script still appends those scenarios and you may see `semantic_mismatch` rows that disappear once variables are cleared or the full matrix is provided.

For a **baseline** report matching the static tier (verify/remove scenarios only, no optional blocks), clear process env vars whose names start with `SIGNTOOL_RS_`, then run `scripts/run-parity-diff.ps1`. Expect **21** scenarios, `missingScenarioCount: 0`, and `semanticMismatchCount: 0` (UTF-16 `@rsp` remains `documented_native_utf16_rsp_gap`, not a semantic failure).

## Tier 2 — Extensions (`parity-extensions.yml`)

Manual **`workflow_dispatch`** only.

| Input | Requires secrets | Behavior |
|-------|------------------|----------|
| **MSIX decoupled** | `SIGNTOOL_RS_MSIX_DLIB`, `SIGNTOOL_RS_MSIX_DMDF` | Repacks minimal MSIX, runs `msix-parity-sign.ps1 -UseDecoupledDigest` (same **`documented_rust_msix_sign_ex3_gap`** vs **`semantic_mismatch`** rules as embedded MSIX when sign exits differ). If you run **`run-parity-diff.ps1`** with those env vars set, **`artifact_msix_decoupled_semantic`** uses the same classification. |
| **Catalog verify** | `SIGNTOOL_RS_CATALOG_TARGET`, `SIGNTOOL_RS_CATALOG_FILE` | Runs `signtool-windows verify <target> --catalog <cat>`, then the same with `--os-version-check 386:10.0.26100.0`. Optional exhaustive parity records both as `artifact_catalog_*`. |
| **Artifact Signing decoupled** | `SIGNTOOL_RS_ARTIFACT_SIGNING_*` (see below) | Optional local-only parity: run `cargo test -p signtool-rs --test parity_signtool artifact_signing_decoupled_pe_executes -- --ignored --nocapture` when fixtures + Microsoft dlib/metadata are available. Not wired into GitHub Actions by default. |

**Artifact Signing env vars** (for the ignored test `artifact_signing_decoupled_pe_executes` and manual recipes): `SIGNTOOL_RS_ARTIFACT_SIGNING_UNSIGNED_PE`, `SIGNTOOL_RS_ARTIFACT_SIGNING_METADATA`, `SIGNTOOL_RS_ARTIFACT_SIGNING_TIMESTAMP_URL`, `SIGNTOOL_RS_ARTIFACT_SIGNING_TEST_PFX`, optional `SIGNTOOL_RS_ARTIFACT_SIGNING_TEST_PFX_PASSWORD`, and either `SIGNTOOL_RS_ARTIFACT_SIGNING_DLIB` **or** `SIGNTOOL_RS_ARTIFACT_SIGNING_DLIB_ROOT`. Details: [`migration-artifact-signing.md`](migration-artifact-signing.md#ci--gated-parity-recipe).

## Operator notes

- Quick native ↔ Rust exit-code smoke over PE (and optional WinMD when env vars are set): [`scripts/sip-format-smoke.ps1`](../scripts/sip-format-smoke.ps1).
- WinMD parity: Tier 1 CI sets `SIGNTOOL_RS_WINMD_UNSIGNED_FIXTURE` via [`pack-minimal-winmd.ps1`](../scripts/ci/pack-minimal-winmd.ps1) (PE bytes, `.winmd` extension). Locally, point `SIGNTOOL_RS_WINMD_UNSIGNED_FIXTURE` at any unsigned `.winmd` plus the same `SIGNTOOL_RS_TEST_PFX` / password as PE; optional `SIGNTOOL_RS_WINMD_TIMESTAMP_URL` for RFC3161 (CI mirrors `SIGNTOOL_RS_TIMESTAMP_URL`).
- To change the pinned Devolutions commit, edit `$CommitSha` in [`scripts/ci/bootstrap-devolutions-authenticode.ps1`](../scripts/ci/bootstrap-devolutions-authenticode.ps1).
- If detached PKCS#7 generation fails on a future SDK, adjust [`scripts/ci/prepare-parity-fixtures.ps1`](../scripts/ci/prepare-parity-fixtures.ps1) (`/p7` fallback flags).
- Scenario inventory and semantics are summarized in [`parity-matrix.md`](parity-matrix.md).
