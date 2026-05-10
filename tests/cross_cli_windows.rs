#![cfg(windows)]

//! Cross-CLI parity between **`signtool-portable verify-pe`** and the Rust PE Authenticode digest check
//! wired behind **`signtool-windows verify --rust-sip-pe-digest-check`**.
//!
//! On stock Windows trust stores the upstream **`tiny*.signed.efi`** fixtures do **not** satisfy
//! WinVerifyTrust, so the Windows CLI exits before it can run the Rust SIP digest pass. These tests
//! therefore compare the portable CLI against the same **`verify_pe_authenticode_digest_consistency`**
//! helper that `--rust-sip-pe-digest-check` invokes after a successful embedded verify.

use assert_cmd::Command;
use std::path::PathBuf;

fn portable_exe() -> PathBuf {
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".into());
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(profile)
        .join("signtool-portable.exe")
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
    let portable = portable_exe();
    assert!(
        portable.is_file(),
        "signtool-portable missing at {} — run `cargo build --workspace` or `cargo build -p signtool-digest-cli --bin signtool-portable` first",
        portable.display()
    );

    let fixture = tiny32_fixture();
    assert!(fixture.is_file(), "fixture missing: {}", fixture.display());

    let mut digest_cmd = Command::new(&portable);
    digest_cmd.arg("verify-pe").arg(&fixture);
    digest_cmd.assert().success();

    let bytes = std::fs::read(&fixture).expect("read fixture");
    signtool_rs::win::sip_rust::verify_pe::verify_pe_authenticode_digest_consistency(&bytes)
        .expect("Rust SIP PE digest consistency (same routine as post-WinTrust --rust-sip-pe-digest-check)");
}

#[test]
fn portable_verify_pe_agrees_with_windows_rust_sip_pe_digest_routine_tiny64() {
    let portable = portable_exe();
    assert!(
        portable.is_file(),
        "signtool-portable missing at {} — run `cargo build --workspace` or `cargo build -p signtool-digest-cli --bin signtool-portable` first",
        portable.display()
    );

    let fixture = tiny64_fixture();
    assert!(fixture.is_file(), "fixture missing: {}", fixture.display());

    let mut digest_cmd = Command::new(&portable);
    digest_cmd.arg("verify-pe").arg(&fixture);
    digest_cmd.assert().success();

    let bytes = std::fs::read(&fixture).expect("read fixture");
    signtool_rs::win::sip_rust::verify_pe::verify_pe_authenticode_digest_consistency(&bytes)
        .expect("Rust SIP PE digest consistency (same routine as post-WinTrust --rust-sip-pe-digest-check)");
}
