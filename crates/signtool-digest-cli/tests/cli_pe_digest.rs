//! End-to-end CLI smoke test (runs on Linux CI).

use assert_cmd::Command;
use predicates::prelude::*;
use signtool_authenticode_trust::pe_first_pkcs7_terminal_root;
use std::path::PathBuf;

#[test]
fn binary_reports_name_and_version_flag() {
    let mut cmd = Command::cargo_bin("signtool-digest").unwrap();
    cmd.arg("--version");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("signtool-digest"))
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_lists_core_subcommands() {
    let mut cmd = Command::cargo_bin("signtool-digest").unwrap();
    cmd.arg("--help");
    let assert = cmd.assert().success();
    let out = std::str::from_utf8(&assert.get_output().stdout).expect("utf-8 help output");
    for needle in [
        "pe-digest",
        "verify-pe",
        "trust-verify-pe",
        "trust-verify-cab",
        "trust-verify-catalog",
        "trust-verify-detached",
        "verify-cab",
        "verify-msi",
        "verify-esd",
        "verify-msix",
        "verify-catalog",
        "verify-script",
    ] {
        assert!(
            out.contains(needle),
            "help output should mention subcommand {needle:?}"
        );
    }
}

fn tiny32_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi")
}

fn tiny64_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/pe-authenticode-upstream/tiny64.signed.efi")
}

#[test]
fn pe_digest_sha256_tiny32_matches_upstream_golden_fixture() {
    let fixture = tiny32_fixture();
    let mut cmd = Command::cargo_bin("signtool-digest").unwrap();
    cmd.args(["pe-digest", "--algorithm", "sha256"])
        .arg(&fixture);
    cmd.assert()
        .success()
        .stdout("4f5b3633fc51d9447beb5c546e9ae6e58d6eb42d1e96d623dc168d97013c08a8\n");
}

#[test]
fn pe_digest_sha256_tiny64_matches_upstream_golden_fixture() {
    let fixture = tiny64_fixture();
    let mut cmd = Command::cargo_bin("signtool-digest").unwrap();
    cmd.args(["pe-digest", "--algorithm", "sha256"])
        .arg(&fixture);
    cmd.assert()
        .success()
        .stdout("a82d7e4f091c44ec75d97746b3461c8ea9151e2313f8e9a4330432ee5f25b2ae\n");
}

#[test]
fn trust_verify_pe_succeeds_with_extracted_embedded_root_anchor() {
    let fixture = tiny32_fixture();
    let bytes = std::fs::read(&fixture).expect("read fixture");
    let root = pe_first_pkcs7_terminal_root(&bytes).expect("terminal root");
    let dir = tempfile::tempdir().expect("tempdir");
    let der = root.to_der().expect("root DER");
    std::fs::write(dir.path().join("anchor.crt"), der).expect("write anchor");

    let mut cmd = Command::cargo_bin("signtool-digest").unwrap();
    cmd.arg("trust-verify-pe")
        .arg("--anchor-dir")
        .arg(dir.path())
        .args(["--as-of", "2023-07-01"])
        .arg(&fixture);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("trust-verify-pe: ok"));
}

#[test]
fn trust_verify_pe_ok_with_prefer_timestamp_signing_time_and_as_of() {
    let fixture = tiny32_fixture();
    let bytes = std::fs::read(&fixture).expect("read fixture");
    let root = pe_first_pkcs7_terminal_root(&bytes).expect("terminal root");
    let dir = tempfile::tempdir().expect("tempdir");
    let der = root.to_der().expect("root DER");
    std::fs::write(dir.path().join("anchor.crt"), der).expect("write anchor");

    let mut cmd = Command::cargo_bin("signtool-digest").unwrap();
    cmd.arg("trust-verify-pe")
        .arg("--anchor-dir")
        .arg(dir.path())
        .arg("--prefer-timestamp-signing-time")
        .args(["--as-of", "2023-07-01"])
        .arg(&fixture);
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("trust-verify-pe: ok"));
}

#[test]
fn trust_verify_pe_errors_without_configured_anchors() {
    let mut cmd = Command::cargo_bin("signtool-digest").unwrap();
    cmd.arg("trust-verify-pe").arg(tiny32_fixture());
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("no trust anchors"));
}

#[test]
fn verify_pe_pkcs7_indirect_digest_matches_on_tiny32_fixture() {
    let mut cmd = Command::cargo_bin("signtool-digest").unwrap();
    cmd.arg("verify-pe").arg(tiny32_fixture());
    cmd.assert().success();
}

#[test]
fn verify_pe_pkcs7_indirect_digest_matches_on_tiny64_fixture() {
    let mut cmd = Command::cargo_bin("signtool-digest").unwrap();
    cmd.arg("verify-pe").arg(tiny64_fixture());
    cmd.assert().success();
}

#[test]
fn pe_has_page_hashes_is_no_on_upstream_tiny_fixtures() {
    for fixture in [tiny32_fixture(), tiny64_fixture()] {
        let mut cmd = Command::cargo_bin("signtool-digest").unwrap();
        cmd.arg("pe-has-page-hashes").arg(&fixture);
        cmd.assert().success().stdout("no\n");
    }
}

#[test]
fn pe_page_hash_info_is_empty_on_upstream_tiny_fixtures() {
    for fixture in [tiny32_fixture(), tiny64_fixture()] {
        let mut cmd = Command::cargo_bin("signtool-digest").unwrap();
        cmd.arg("pe-page-hash-info").arg(&fixture);
        cmd.assert().success().stdout("");
    }
}

#[test]
fn verify_pe_page_hashes_fails_when_upstream_tiny_has_no_page_hash_attrs() {
    let mut cmd = Command::cargo_bin("signtool-digest").unwrap();
    cmd.arg("verify-pe-page-hashes").arg(tiny32_fixture());
    cmd.assert().failure();
}

#[test]
fn pe_authenticode_ranges_prints_start_end_lines_on_tiny_fixture() {
    let mut cmd = Command::cargo_bin("signtool-digest").unwrap();
    cmd.arg("pe-authenticode-ranges").arg(tiny32_fixture());
    let assert = cmd.assert().success();
    let out = std::str::from_utf8(&assert.get_output().stdout).expect("utf8");
    assert!(!out.trim().is_empty(), "expected non-empty range listing");
    for line in out.lines() {
        assert!(
            line.starts_with("start=") && line.contains(" end="),
            "unexpected line: {line:?}"
        );
    }
}
