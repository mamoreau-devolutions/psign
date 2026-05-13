#![cfg(windows)]

//! Cross-CLI parity between **`psign-tool portable verify-pe`** and the Rust PE Authenticode digest check
//! wired behind **`psign-tool verify --rust-sip-pe-digest-check`**.
//!
//! On stock Windows trust stores the upstream **`tiny*.signed.efi`** fixtures do **not** satisfy
//! WinVerifyTrust, so the Windows CLI exits before it can run the Rust SIP digest pass. These tests
//! therefore compare the portable CLI against the same **`verify_pe_authenticode_digest_consistency`**
//! helper that `--rust-sip-pe-digest-check` invokes after a successful embedded verify.

use assert_cmd::Command;
use std::path::PathBuf;

fn portable_cmd() -> Command {
    let mut cmd = Command::cargo_bin("psign-tool").expect("psign-tool binary");
    cmd.arg("portable");
    cmd
}

fn tiny32_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi")
}

fn tiny64_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/pe-authenticode-upstream/tiny64.signed.efi")
}

#[test]
fn portable_verify_pe_agrees_with_windows_rust_sip_pe_digest_routine_tiny32() {
    let fixture = tiny32_fixture();
    assert!(fixture.is_file(), "fixture missing: {}", fixture.display());

    let mut digest_cmd = portable_cmd();
    digest_cmd.arg("verify-pe").arg(&fixture);
    digest_cmd.assert().success();

    let bytes = std::fs::read(&fixture).expect("read fixture");
    psign::win::sip_rust::verify_pe::verify_pe_authenticode_digest_consistency(&bytes).expect(
        "Rust SIP PE digest consistency (same routine as post-WinTrust --rust-sip-pe-digest-check)",
    );
}

#[test]
fn portable_verify_pe_agrees_with_windows_rust_sip_pe_digest_routine_tiny64() {
    let fixture = tiny64_fixture();
    assert!(fixture.is_file(), "fixture missing: {}", fixture.display());

    let mut digest_cmd = portable_cmd();
    digest_cmd.arg("verify-pe").arg(&fixture);
    digest_cmd.assert().success();

    let bytes = std::fs::read(&fixture).expect("read fixture");
    psign::win::sip_rust::verify_pe::verify_pe_authenticode_digest_consistency(&bytes).expect(
        "Rust SIP PE digest consistency (same routine as post-WinTrust --rust-sip-pe-digest-check)",
    );
}
