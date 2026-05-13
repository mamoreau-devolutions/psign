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

fn package_fixture(rel: &str) -> PathBuf {
    let separator = std::path::MAIN_SEPARATOR.to_string();
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/package-signing")
        .join(rel.replace('/', &separator))
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

#[test]
fn portable_nupkg_fixture_commands_work_through_windows_binary() {
    let signed = package_fixture("signed/sample.signed.nupkg");
    let unsigned = package_fixture("unsigned/sample.nupkg");
    assert!(signed.is_file(), "fixture missing: {}", signed.display());
    assert!(
        unsigned.is_file(),
        "fixture missing: {}",
        unsigned.display()
    );

    let mut info_cmd = portable_cmd();
    info_cmd.arg("nupkg-signature-info").arg(&signed);
    info_cmd
        .assert()
        .success()
        .stdout(predicates::str::contains("signed=yes"))
        .stdout(predicates::str::contains("signature_file=.signature.p7s"))
        .stdout(predicates::str::contains("signature_stored=yes"));

    let mut digest_cmd = portable_cmd();
    digest_cmd
        .arg("nupkg-digest")
        .arg(&unsigned)
        .arg("--algorithm")
        .arg("sha256");
    digest_cmd.assert().success();
}

#[test]
fn portable_vsix_fixture_command_works_through_windows_binary() {
    let signed = package_fixture("signed/sample.signed.vsix");
    assert!(signed.is_file(), "fixture missing: {}", signed.display());

    let mut cmd = portable_cmd();
    cmd.arg("vsix-signature-info").arg(&signed);
    cmd.assert()
        .success()
        .stdout(predicates::str::contains("opc_signature=yes"))
        .stdout(predicates::str::contains(
            "signature_origin=package/services/digital-signature/origin.psdsor",
        ))
        .stdout(predicates::str::contains("signature_parts=1"));
}
