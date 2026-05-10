#!/usr/bin/env bash
# Mirror portable checks useful on Linux CI (see .github/workflows/ci-unix.yml).
# Run from repository root: bash scripts/linux-portable-validation.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "== rustfmt (check) =="
cargo fmt --all --check

echo "== Cargo.lock =="
cargo metadata --locked --format-version 1 >/dev/null

echo "== clippy portable crates =="
cargo clippy -p signtool-sip-digest -p signtool-digest-cli -p signtool-authenticode-trust \
  -p signtool-codesigning-rest \
  --all-targets --locked -- -D warnings

echo "== clippy digest-cli (artifact-signing-rest) =="
cargo clippy -p signtool-digest-cli --all-targets --features artifact-signing-rest --locked -- -D warnings

echo "== clippy signtool-rs lib (stub on Unix) =="
cargo clippy -p signtool-rs --lib --locked -- -D warnings

echo "== unit tests: sip-digest =="
cargo test -p signtool-sip-digest --lib --locked

echo "== unit tests: authenticode-trust =="
cargo test -p signtool-authenticode-trust --lib --locked

echo "== unit tests: codesigning-rest =="
cargo test -p signtool-codesigning-rest --lib --locked

echo "== integration: signtool-portable (digest-cli) =="
cargo test -p signtool-digest-cli --locked

echo "== integration: signtool-portable (artifact-signing-rest) =="
cargo test -p signtool-digest-cli --features artifact-signing-rest --locked

echo "== signtool-rs library tests (argv / response files) =="
cargo test -p signtool-rs --lib --locked

echo "== check signtool-rs binaries + lib =="
cargo check -p signtool-rs --bins --lib --locked

echo "== OK: linux portable validation complete =="
