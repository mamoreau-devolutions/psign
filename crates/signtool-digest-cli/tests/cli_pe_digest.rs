//! End-to-end CLI smoke test (runs on Linux CI).

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;
use signtool_authenticode_trust::pe_first_pkcs7_terminal_root;
use std::path::PathBuf;

#[test]
fn binary_reports_name_and_version_flag() {
    let mut cmd = Command::cargo_bin("signtool-portable").unwrap();
    cmd.arg("--version");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("signtool-portable"))
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_lists_core_subcommands() {
    let mut cmd = Command::cargo_bin("signtool-portable").unwrap();
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
        "cab-digest",
        "pe-has-page-hashes",
        "pe-page-hash-info",
        "verify-pe-page-hashes",
        "pe-authenticode-ranges",
        "artifact-signing-metadata-check",
        "inspect-authenticode",
        "inspect-pe-spc-indirect",
        "extract-pe-pkcs7",
    ] {
        assert!(
            out.contains(needle),
            "help output should mention subcommand {needle:?}"
        );
    }
}

fn decode_hex_lower(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "even hex length");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn pe_digest_raw_output_file_matches_known_sha256_tiny32() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("digest.bin");
    let mut cmd = Command::cargo_bin("signtool-portable").unwrap();
    cmd.args([
        "pe-digest",
        "--algorithm",
        "sha256",
        "--encoding",
        "raw",
        "--output",
    ])
    .arg(&out)
    .arg(tiny32_fixture());
    cmd.assert().success();
    let raw = std::fs::read(&out).unwrap();
    assert_eq!(raw.len(), 32);
    let expected_hex = "4f5b3633fc51d9447beb5c546e9ae6e58d6eb42d1e96d623dc168d97013c08a8";
    assert_eq!(raw, decode_hex_lower(expected_hex));
}

#[cfg(feature = "azure-kv-sign-portable")]
#[test]
fn help_lists_azure_key_vault_sign_digest_when_feature_enabled() {
    let mut cmd = Command::cargo_bin("signtool-portable").unwrap();
    cmd.arg("--help");
    let assert = cmd.assert().success();
    let out = std::str::from_utf8(&assert.get_output().stdout).expect("utf-8 help");
    assert!(
        out.contains("azure-key-vault-sign-digest"),
        "help should list azure-key-vault-sign-digest when built with azure-kv-sign-portable"
    );
}

#[cfg(feature = "artifact-signing-rest")]
#[test]
fn help_lists_artifact_signing_submit_when_feature_enabled() {
    let mut cmd = Command::cargo_bin("signtool-portable").unwrap();
    cmd.arg("--help");
    let assert = cmd.assert().success();
    let out = std::str::from_utf8(&assert.get_output().stdout).expect("utf-8 help");
    assert!(
        out.contains("artifact-signing-submit"),
        "help should list artifact-signing-submit when built with artifact-signing-rest"
    );
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
    let mut cmd = Command::cargo_bin("signtool-portable").unwrap();
    cmd.args(["pe-digest", "--algorithm", "sha256"])
        .arg(&fixture);
    cmd.assert()
        .success()
        .stdout("4f5b3633fc51d9447beb5c546e9ae6e58d6eb42d1e96d623dc168d97013c08a8\n");
}

#[test]
fn pe_digest_sha256_tiny64_matches_upstream_golden_fixture() {
    let fixture = tiny64_fixture();
    let mut cmd = Command::cargo_bin("signtool-portable").unwrap();
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

    let mut cmd = Command::cargo_bin("signtool-portable").unwrap();
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

    let mut cmd = Command::cargo_bin("signtool-portable").unwrap();
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
    let mut cmd = Command::cargo_bin("signtool-portable").unwrap();
    cmd.arg("trust-verify-pe").arg(tiny32_fixture());
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("no trust anchors"));
}

#[test]
fn verify_pe_pkcs7_indirect_digest_matches_on_tiny32_fixture() {
    let mut cmd = Command::cargo_bin("signtool-portable").unwrap();
    cmd.arg("verify-pe").arg(tiny32_fixture());
    cmd.assert().success();
}

#[test]
fn inspect_authenticode_pe_outputs_json_with_signers() {
    let mut cmd = Command::cargo_bin("signtool-portable").unwrap();
    cmd.args(["inspect-authenticode", "--input", "pe"])
        .arg(tiny32_fixture());
    let assert = cmd.assert().success();
    let out = std::str::from_utf8(&assert.get_output().stdout).expect("utf8");
    let v: Value = serde_json::from_str(out.trim()).expect("inspect JSON");
    let entries = v
        .get("entries")
        .and_then(Value::as_array)
        .expect("top-level entries[]");
    assert!(
        !entries.is_empty(),
        "expected ≥1 attribute-cert PKCS#7 on signed PE fixture"
    );
    let pkcs7 = entries[0].get("pkcs7").expect("pkcs7 object");
    let signers = pkcs7
        .get("signers")
        .and_then(Value::as_array)
        .expect("signers[]");
    assert!(
        !signers.is_empty(),
        "expected ≥1 signer in outer SignedData"
    );
    assert!(
        pkcs7.get("nested_signatures").is_some(),
        "nested_signatures field should be present"
    );
}

#[test]
fn extract_pe_pkcs7_stdout_matches_verify_pe_helper() {
    let pe = std::fs::read(tiny32_fixture()).expect("read tiny32");
    let expected = signtool_sip_digest::verify_pe::pe_first_pkcs7_signed_data_der(&pe)
        .expect("library extract");
    let mut cmd = Command::cargo_bin("signtool-portable").unwrap();
    cmd.arg("extract-pe-pkcs7").arg(tiny32_fixture());
    let assert = cmd.assert().success();
    assert_eq!(
        assert.get_output().stdout.as_slice(),
        expected.as_slice(),
        "CLI stdout PKCS#7 must match verify_pe::pe_first_pkcs7_signed_data_der"
    );
}

#[test]
fn extract_pe_pkcs7_output_file_matches_verify_pe_helper() {
    let pe = std::fs::read(tiny32_fixture()).expect("read tiny32");
    let expected = signtool_sip_digest::verify_pe::pe_first_pkcs7_signed_data_der(&pe)
        .expect("library extract");
    let dir = tempfile::tempdir().expect("tempdir");
    let out_path = dir.path().join("embedded.p7");
    let mut cmd = Command::cargo_bin("signtool-portable").unwrap();
    cmd.arg("extract-pe-pkcs7")
        .arg(tiny32_fixture())
        .arg("--output")
        .arg(&out_path);
    cmd.assert().success();
    let written = std::fs::read(&out_path).expect("read output");
    assert_eq!(written.as_slice(), expected.as_slice());
}

#[test]
fn inspect_pe_spc_indirect_matches_sip_digest_on_tiny_fixture() {
    let mut cmd = Command::cargo_bin("signtool-portable").unwrap();
    cmd.arg("inspect-pe-spc-indirect").arg(tiny32_fixture());
    let assert = cmd.assert().success();
    let out = std::str::from_utf8(&assert.get_output().stdout).expect("utf8");
    let v: Value = serde_json::from_str(out.trim()).expect("inspect-pe-spc-indirect JSON");
    assert_eq!(
        v.get("message_digest_matches_pe_image_digest")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        v.get("image_data_value_type_oid").and_then(Value::as_str),
        Some("1.3.6.1.4.1.311.2.1.15")
    );
    assert_eq!(
        v.get("digest_algorithm_oid").and_then(Value::as_str),
        Some("2.16.840.1.101.3.4.2.1")
    );
}

#[test]
fn verify_pe_pkcs7_indirect_digest_matches_on_tiny64_fixture() {
    let mut cmd = Command::cargo_bin("signtool-portable").unwrap();
    cmd.arg("verify-pe").arg(tiny64_fixture());
    cmd.assert().success();
}

#[test]
fn pe_has_page_hashes_is_no_on_upstream_tiny_fixtures() {
    for fixture in [tiny32_fixture(), tiny64_fixture()] {
        let mut cmd = Command::cargo_bin("signtool-portable").unwrap();
        cmd.arg("pe-has-page-hashes").arg(&fixture);
        cmd.assert().success().stdout("no\n");
    }
}

#[test]
fn pe_page_hash_info_is_empty_on_upstream_tiny_fixtures() {
    for fixture in [tiny32_fixture(), tiny64_fixture()] {
        let mut cmd = Command::cargo_bin("signtool-portable").unwrap();
        cmd.arg("pe-page-hash-info").arg(&fixture);
        cmd.assert().success().stdout("");
    }
}

#[test]
fn verify_pe_page_hashes_fails_when_upstream_tiny_has_no_page_hash_attrs() {
    let mut cmd = Command::cargo_bin("signtool-portable").unwrap();
    cmd.arg("verify-pe-page-hashes").arg(tiny32_fixture());
    cmd.assert().failure();
}

#[test]
fn pe_authenticode_ranges_prints_start_end_lines_on_tiny_fixture() {
    let mut cmd = Command::cargo_bin("signtool-portable").unwrap();
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

#[test]
fn artifact_signing_metadata_check_accepts_valid_json_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("meta.json");
    std::fs::write(
        &path,
        r#"{"Endpoint":"https://example.test/rpcsign","CodeSigningAccountName":"acct","CertificateProfileName":"prof","ExcludeCredentials":["ManagedIdentityCredential"]}"#,
    )
    .unwrap();
    let mut cmd = Command::cargo_bin("signtool-portable").unwrap();
    cmd.args(["artifact-signing-metadata-check", "--path"])
        .arg(&path);
    cmd.assert().success().stdout(predicate::str::contains(
        "artifact-signing-metadata-check: ok",
    ));
}

#[test]
fn artifact_signing_metadata_check_rejects_empty_profile_name() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.json");
    std::fs::write(
        &path,
        r#"{"Endpoint":"https://example.test/rpcsign","CodeSigningAccountName":"acct","CertificateProfileName":"  "}"#,
    )
    .unwrap();
    let mut cmd = Command::cargo_bin("signtool-portable").unwrap();
    cmd.args(["artifact-signing-metadata-check", "--path"])
        .arg(&path);
    cmd.assert().failure();
}
