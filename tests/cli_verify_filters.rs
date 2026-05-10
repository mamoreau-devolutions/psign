#![cfg(windows)]

//! CLI parsing for verify filters (parity with native `/sha1`, `/ca`, `/u`, `/p7content`).

use assert_cmd::Command;
use clap::Parser;
use predicates::prelude::*;
use signtool_rs::cli::{Cli, Command as SubCommand, DigestAlgorithm, RustSipBackend, VerifyPolicy};
use std::ffi::OsString;
use std::fs;
use std::path::Path;

#[test]
fn verify_os_version_check_parses() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "verify",
        "--policy",
        "pa",
        "--os-version-check",
        "386:10.0.26100.0",
        "x.exe",
    ])
    .expect("parse");
    let SubCommand::Verify(v) = c.command else {
        panic!("expected verify");
    };
    assert_eq!(v.os_version_check.as_deref(), Some("386:10.0.26100.0"));
}

#[test]
fn verify_os_version_check_requires_catalog_at_runtime() {
    let tmp = std::env::temp_dir().join("signtool_rs_osver_guard_probe.bin");
    fs::write(&tmp, b"x").unwrap();
    Command::cargo_bin("signtool-rs")
        .expect("binary")
        .args([
            "verify",
            "--policy",
            "pa",
            "--os-version-check",
            "386:10.0.0.0",
        ])
        .arg(&tmp)
        .assert()
        .failure()
        .stderr(predicate::str::contains("catalog"));
    let _ = fs::remove_file(&tmp);
}

#[test]
fn verify_repeatable_thumbprints_and_quiet_short_parse() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "-q",
        "verify",
        "--signer-thumbprint-sha1",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "--signer-thumbprint-sha1",
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        "--intermediate-ca-sha1",
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
        "--warn-if-missing-eku",
        "1.3.6.1.5.5.7.3.3",
        "--policy",
        "pa",
        "x.exe",
    ])
    .expect("parse");

    assert!(c.global.quiet);
    let SubCommand::Verify(v) = c.command else {
        panic!("expected verify");
    };
    assert_eq!(v.signer_thumbprint_sha1.len(), 2);
    assert_eq!(v.intermediate_ca_sha1.len(), 1);
    assert_eq!(v.warn_if_missing_eku.len(), 1);
}

#[test]
fn verify_accepts_multiple_trailing_files() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "verify",
        "--policy",
        "pa",
        "first.dll",
        "second.dll",
    ])
    .expect("parse");
    let SubCommand::Verify(v) = c.command else {
        panic!("expected verify");
    };
    assert_eq!(v.files.len(), 2);
    assert_eq!(v.files[0], Path::new("first.dll"));
    assert_eq!(v.files[1], Path::new("second.dll"));
}

#[test]
fn sign_accepts_multiple_trailing_files() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "sign",
        "--f",
        "a.pfx",
        "--fd",
        "sha256",
        "one.dll",
        "two.dll",
    ])
    .expect("parse");
    let SubCommand::Sign(s) = c.command else {
        panic!("expected sign");
    };
    assert_eq!(s.files.len(), 2);
    assert_eq!(s.files[0], Path::new("one.dll"));
    assert_eq!(s.files[1], Path::new("two.dll"));
}

#[test]
fn timestamp_accepts_multiple_trailing_files() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "timestamp",
        "--tr",
        "http://ts.example/rfc3161",
        "--td",
        "sha256",
        "a.exe",
        "b.exe",
    ])
    .expect("parse");
    let SubCommand::Timestamp(t) = c.command else {
        panic!("expected timestamp");
    };
    assert_eq!(t.files.len(), 2);
    assert_eq!(t.files[0], Path::new("a.exe"));
    assert_eq!(t.files[1], Path::new("b.exe"));
}

#[test]
fn remove_accepts_multiple_trailing_files() {
    let c = Cli::try_parse_from(["signtool-rs", "remove", "--s", "x.exe", "y.exe"]).expect("parse");
    let SubCommand::Remove(r) = c.command else {
        panic!("expected remove");
    };
    assert!(r.strip_signature);
    assert_eq!(r.files.len(), 2);
}

#[test]
fn verify_detached_rejects_multiple_content_files() {
    Command::cargo_bin("signtool-rs")
        .expect("binary available")
        .args(["verify", "--detached-pkcs7", "sig.p7s", "a.exe", "b.exe"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "detached PKCS#7 verify supports exactly one content file",
        ));
}

#[test]
fn verify_detached_content_without_detached_errors_at_runtime() {
    Command::cargo_bin("signtool-rs")
        .expect("binary available")
        .args(["verify", "--detached-pkcs7-content", "content.bin", "x.exe"])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "detached-pkcs7-content requires --detached-pkcs7",
        ));
}

#[test]
#[cfg(windows)]
fn verify_wrong_signer_thumbprint_fails_on_signed_pe() {
    let fixture =
        Path::new(r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe");
    if !fixture.exists() {
        return;
    }
    Command::cargo_bin("signtool-rs")
        .expect("binary available")
        .args([
            "verify",
            "--policy",
            "pa",
            "--signer-thumbprint-sha1",
            "0000000000000000000000000000000000000000",
            fixture.to_str().expect("utf8 path"),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("thumbprint"));
}

#[test]
fn verify_pca_warn_flags_conflict_at_runtime() {
    Command::cargo_bin("signtool-rs")
        .expect("binary available")
        .args(["verify", "--warn-pca-2010", "--no-warn-pca-2010", "x.exe"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("warn-pca-2010"));
}

#[test]
fn sign_ph_and_nph_mutually_exclusive() {
    Command::cargo_bin("signtool-rs")
        .expect("binary available")
        .args(["sign", "--page-hashes", "--no-page-hashes", "nope.exe"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("mutually exclusive"));
}

#[test]
fn verify_detached_p7s_alias_parses() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "verify",
        "content.bin",
        "--p7s",
        "sig.p7s",
        "--policy",
        "pa",
    ])
    .expect("parse");
    let SubCommand::Verify(v) = c.command else {
        panic!("expected verify");
    };
    assert_eq!(
        v.detached_pkcs7
            .as_ref()
            .map(|p| p.to_string_lossy().to_string()),
        Some("sig.p7s".into())
    );
}

#[test]
fn verify_vr_alias_sets_revocation_check() {
    let c = Cli::try_parse_from(["signtool-rs", "verify", "--vr", "--policy", "pa", "x.exe"])
        .expect("parse");
    let SubCommand::Verify(v) = c.command else {
        panic!("expected verify");
    };
    assert!(v.revocation_check);
}

#[test]
fn verify_testroot_alias_sets_allow_test_root() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "verify",
        "--testroot",
        "--policy",
        "pa",
        "x.exe",
    ])
    .expect("parse");
    let SubCommand::Verify(v) = c.command else {
        panic!("expected verify");
    };
    assert!(v.allow_test_root);
}

#[test]
fn verify_sl_sets_flag_and_runs_embedded_path() {
    let c = Cli::try_parse_from(["signtool-rs", "verify", "--sl", "--policy", "pa", "x.exe"])
        .expect("parse");
    let SubCommand::Verify(v) = c.command else {
        panic!("expected verify");
    };
    assert!(v.verify_sealing_signatures);
}

#[test]
#[cfg(windows)]
fn verify_sl_rejects_detached_pkcs7() {
    let mut cmd = Command::cargo_bin("signtool-rs").unwrap();
    cmd.args([
        "verify",
        "--policy",
        "pa",
        "--verify-sealing-signatures",
        "--detached-pkcs7",
        "missing.p7s",
        "content.bin",
    ]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("not supported"));
}

#[test]
fn at_response_file_single_invocation() {
    let dir = std::env::temp_dir();
    let rsp = dir.join(format!("signtool_rs_rsp_single_{}.txt", line!()));
    std::fs::write(
        &rsp,
        "verify\n--policy\npa\nnonexistent_signtool_rs_rsp_target.exe\n",
    )
    .expect("write rsp");
    let at = format!("@{}", rsp.display());
    Command::cargo_bin("signtool-rs")
        .expect("binary available")
        .arg(&at)
        .assert()
        .failure();
    let _ = std::fs::remove_file(&rsp);
}

#[test]
fn timestamp_force_not_implemented() {
    Command::cargo_bin("signtool-rs")
        .expect("binary available")
        .args([
            "timestamp",
            "--t",
            "http://ts.example/legacy",
            "--force",
            "x.exe",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("/force"));
}

#[test]
fn timestamp_nosealwarn_not_implemented() {
    Command::cargo_bin("signtool-rs")
        .expect("binary available")
        .args([
            "timestamp",
            "--t",
            "http://ts.example/legacy",
            "--nosealwarn",
            "x.exe",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("/nosealwarn"));
}

#[test]
fn verify_tw_alias_equivalent_to_long_flag() {
    let c = Cli::try_parse_from(["signtool-rs", "verify", "--tw", "--policy", "pa", "x.exe"])
        .expect("parse");
    let SubCommand::Verify(v) = c.command else {
        panic!("expected verify");
    };
    assert!(v.warn_if_not_timestamped);
}

#[test]
fn sign_seal_tseal_url_parses() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "sign",
        "--f",
        "c.pfx",
        "--fd",
        "sha256",
        "--tseal",
        "http://ts.example/seal",
        "--td",
        "sha256",
        "sealed.msix",
    ])
    .expect("parse");
    let SubCommand::Sign(s) = c.command else {
        panic!("expected sign");
    };
    assert!(s.timestamp_url.is_none());
    assert_eq!(
        s.seal_timestamp_url.as_deref(),
        Some("http://ts.example/seal")
    );
}

#[test]
fn sign_tr_and_tseal_conflict() {
    assert!(
        Cli::try_parse_from([
            "signtool-rs",
            "sign",
            "--f",
            "a.pfx",
            "--fd",
            "sha256",
            "--tr",
            "http://a",
            "--tseal",
            "http://b",
            "x.exe",
        ])
        .is_err()
    );
}

#[test]
fn sign_fd_and_tr_aliases_parse() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "sign",
        "--f",
        "cert.pfx",
        "--fd",
        "sha384",
        "--tr",
        "http://timestamp.example/ts",
        "--td",
        "sha512",
        "out.exe",
    ])
    .expect("parse");
    let SubCommand::Sign(s) = c.command else {
        panic!("expected sign");
    };
    assert_eq!(s.digest, DigestAlgorithm::Sha384);
    assert_eq!(
        s.timestamp_url.as_deref(),
        Some("http://timestamp.example/ts")
    );
    assert_eq!(s.timestamp_digest, Some(DigestAlgorithm::Sha512));
}

#[test]
fn sign_auth_pairs_parse() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "sign",
        "--f",
        "a.pfx",
        "--fd",
        "sha256",
        "--sign-auth",
        "1.3.6.1.4.1.999",
        "attr-value",
        "x.exe",
    ])
    .expect("parse");
    let SubCommand::Sign(s) = c.command else {
        panic!("expected sign");
    };
    assert_eq!(
        s.sign_auth_pairs,
        vec!["1.3.6.1.4.1.999".to_string(), "attr-value".to_string()]
    );
}

#[test]
fn sign_certificate_template_alias_c_parses() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "sign",
        "--f",
        "a.pfx",
        "--fd",
        "sha256",
        "--c",
        "MyTemplate",
        "x.exe",
    ])
    .expect("parse");
    let SubCommand::Sign(s) = c.command else {
        panic!("expected sign");
    };
    assert_eq!(s.certificate_template.as_deref(), Some("MyTemplate"));
}

#[test]
fn sign_seal_not_implemented_before_crypto() {
    Command::cargo_bin("signtool-rs")
        .expect("binary available")
        .args([
            "sign",
            "--f",
            "missing.pfx",
            "--digest",
            "sha256",
            "--seal",
            "nope.exe",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("/seal"));
}

#[test]
fn sign_certificate_template_not_implemented() {
    Command::cargo_bin("signtool-rs")
        .expect("binary available")
        .args([
            "sign",
            "--f",
            "missing.pfx",
            "--digest",
            "sha256",
            "--certificate-template",
            "T",
            "nope.exe",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("/c"));
}

#[test]
fn timestamp_native_style_aliases_parse() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "timestamp",
        "--tr",
        "http://ts.example/rfc3161",
        "--td",
        "sha384",
        "--tp",
        "1",
        "signed.exe",
    ])
    .expect("parse");
    let SubCommand::Timestamp(t) = c.command else {
        panic!("expected timestamp");
    };
    assert_eq!(t.rfc3161_url.as_deref(), Some("http://ts.example/rfc3161"));
    assert_eq!(t.digest, DigestAlgorithm::Sha384);
    assert_eq!(t.signature_index, Some(1));
}

#[test]
fn timestamp_tseal_url_parses() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "timestamp",
        "--tseal",
        "http://ts.example/seal",
        "--td",
        "sha256",
        "pkg.msix",
    ])
    .expect("parse");
    let SubCommand::Timestamp(t) = c.command else {
        panic!("expected timestamp");
    };
    assert!(t.rfc3161_url.is_none());
    assert_eq!(
        t.seal_timestamp_url.as_deref(),
        Some("http://ts.example/seal")
    );
}

#[test]
fn timestamp_tr_and_tseal_conflict() {
    assert!(
        Cli::try_parse_from([
            "signtool-rs",
            "timestamp",
            "--tr",
            "http://a",
            "--tseal",
            "http://b",
            "--td",
            "sha256",
            "x.exe",
        ])
        .is_err()
    );
}

#[test]
#[cfg(windows)]
fn remove_strip_chain_missing_file_is_not_stub_error() {
    Command::cargo_bin("signtool-rs")
        .expect("binary available")
        .args(["remove", "--c", "signtool_rs_remove_c_missing_xyz.exe"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not implemented").not());
}

#[test]
fn remove_requires_one_mode() {
    Command::cargo_bin("signtool-rs")
        .expect("binary available")
        .args(["remove", "nope.exe"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("requires one of"));
}

#[test]
#[cfg(windows)]
fn windows_slash_argv_normalizes_to_clap_verify() {
    let raw = vec![
        OsString::from("signtool-rs"),
        OsString::from("verify"),
        OsString::from("/pa"),
        OsString::from("/q"),
        OsString::from("fixture.exe"),
    ];
    let n = signtool_rs::native_argv::normalize_native_signtool_argv(raw);
    let c = Cli::try_parse_from(n).expect("parse after slash normalization");
    assert!(c.global.quiet);
    let SubCommand::Verify(v) = c.command else {
        panic!("expected verify");
    };
    assert_eq!(v.policy, VerifyPolicy::Pa);
}

#[test]
fn verify_page_hashes_requires_verbose() {
    let mut cmd = Command::cargo_bin("signtool-rs").unwrap();
    cmd.args([
        "verify",
        "--policy",
        "pa",
        "--verify-page-hashes",
        "definitely_missing_signtool_rs_xyz.exe",
    ]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("requires --verbose (-v)"));
}

#[test]
fn verify_print_description_requires_verbose() {
    let mut cmd = Command::cargo_bin("signtool-rs").unwrap();
    cmd.args([
        "verify",
        "--policy",
        "pa",
        "--print-description",
        "definitely_missing_signtool_rs_xyz.exe",
    ]);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("requires --verbose (-v)"));
}

#[test]
#[cfg(windows)]
fn remove_strip_signature_rejects_powershell_script() {
    let ps1 =
        std::env::temp_dir().join(format!("signtool_rs_remove_cli_{}.ps1", std::process::id()));
    std::fs::write(&ps1, "# parity-remove-test\n").expect("write ps1");
    let mut cmd = Command::cargo_bin("signtool-rs").unwrap();
    cmd.arg("remove").arg("--strip-signature").arg(&ps1);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("script-signed"));
    let _ = std::fs::remove_file(&ps1);
}

#[test]
#[cfg(windows)]
fn remove_strip_signature_rejects_js_script() {
    let js = std::env::temp_dir().join(format!("signtool_rs_remove_cli_{}.js", std::process::id()));
    std::fs::write(&js, "// parity-remove-test\n").expect("write js");
    let mut cmd = Command::cargo_bin("signtool-rs").unwrap();
    cmd.arg("remove").arg("--strip-signature").arg(&js);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("script-signed"));
    let _ = std::fs::remove_file(&js);
}

#[test]
#[cfg(windows)]
fn remove_strip_signature_rejects_vbs_script() {
    let vbs =
        std::env::temp_dir().join(format!("signtool_rs_remove_cli_{}.vbs", std::process::id()));
    std::fs::write(&vbs, "' parity-remove-test\n").expect("write vbs");
    let mut cmd = Command::cargo_bin("signtool-rs").unwrap();
    cmd.arg("remove").arg("--strip-signature").arg(&vbs);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("script-signed"));
    let _ = std::fs::remove_file(&vbs);
}

#[test]
#[cfg(windows)]
fn remove_strip_signature_rejects_msix_package() {
    let msix = std::env::temp_dir().join(format!(
        "signtool_rs_remove_cli_{}.msix",
        std::process::id()
    ));
    std::fs::write(&msix, b"not-a-real-msix").expect("write msix");
    let mut cmd = Command::cargo_bin("signtool-rs").unwrap();
    cmd.arg("remove").arg("--strip-signature").arg(&msix);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("AppX/MSIX"));
    let _ = std::fs::remove_file(&msix);
}

#[test]
#[cfg(windows)]
fn remove_strip_signature_rejects_unknown_extension() {
    let weird = std::env::temp_dir().join(format!(
        "signtool_rs_remove_cli_{}.xyz_unknown_fmt",
        std::process::id()
    ));
    std::fs::write(&weird, b"x").expect("write junk");
    let mut cmd = Command::cargo_bin("signtool-rs").unwrap();
    cmd.arg("remove").arg("--strip-signature").arg(&weird);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("PE-image-backed"));
    let _ = std::fs::remove_file(&weird);
}

#[test]
#[cfg(windows)]
fn remove_strip_signature_rejects_windows_installer_msi() {
    let msi =
        std::env::temp_dir().join(format!("signtool_rs_remove_cli_{}.msi", std::process::id()));
    std::fs::write(&msi, b"not-a-real-msi").expect("write msi");
    let mut cmd = Command::cargo_bin("signtool-rs").unwrap();
    cmd.arg("remove").arg("--strip-signature").arg(&msi);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Windows Installer"));
    let _ = std::fs::remove_file(&msi);
}

#[test]
#[cfg(windows)]
fn remove_strip_signature_rejects_wim_image() {
    let wim =
        std::env::temp_dir().join(format!("signtool_rs_remove_cli_{}.wim", std::process::id()));
    std::fs::write(&wim, b"not-a-real-wim").expect("write wim");
    let mut cmd = Command::cargo_bin("signtool-rs").unwrap();
    cmd.arg("remove").arg("--strip-signature").arg(&wim);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("WIM/ESD"));
    let _ = std::fs::remove_file(&wim);
}

#[test]
#[cfg(windows)]
fn remove_strip_signature_rejects_wsf_script() {
    let wsf =
        std::env::temp_dir().join(format!("signtool_rs_remove_cli_{}.wsf", std::process::id()));
    std::fs::write(
        &wsf,
        r#"<?xml version="1.0"?><package><job id="t"><script>//x</script></job></package>"#,
    )
    .expect("write wsf");
    let mut cmd = Command::cargo_bin("signtool-rs").unwrap();
    cmd.arg("remove").arg("--strip-signature").arg(&wsf);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("script-signed"));
    let _ = std::fs::remove_file(&wsf);
}

#[test]
#[cfg(windows)]
fn windows_slash_argv_normalizes_sign_sa_two_values() {
    let raw = vec![
        OsString::from("signtool-rs"),
        OsString::from("sign"),
        OsString::from("/f"),
        OsString::from("a.pfx"),
        OsString::from("/fd"),
        OsString::from("sha256"),
        OsString::from("/sa"),
        OsString::from("1.3.6.1.4.1.999"),
        OsString::from("hello"),
        OsString::from("x.exe"),
    ];
    let n = signtool_rs::native_argv::normalize_native_signtool_argv(raw);
    let c = Cli::try_parse_from(n).expect("parse sign /sa");
    let SubCommand::Sign(s) = c.command else {
        panic!("expected sign");
    };
    assert_eq!(
        s.sign_auth_pairs,
        vec!["1.3.6.1.4.1.999".to_string(), "hello".to_string()]
    );
}

#[test]
fn sign_rust_sip_script_parses() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "sign",
        "--pfx",
        "a.pfx",
        "--digest",
        "sha256",
        "--rust-sip",
        "script",
        "x.ps1",
    ])
    .expect("parse");
    let SubCommand::Sign(s) = c.command else {
        panic!("expected sign");
    };
    assert_eq!(s.rust_sip, Some(RustSipBackend::Script));
}

#[test]
fn sign_rust_sip_pe_parses() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "sign",
        "--pfx",
        "a.pfx",
        "--digest",
        "sha256",
        "--rust-sip",
        "pe",
        "x.exe",
    ])
    .expect("parse");
    let SubCommand::Sign(s) = c.command else {
        panic!("expected sign");
    };
    assert_eq!(s.rust_sip, Some(RustSipBackend::Pe));
}

#[test]
fn sign_rust_sip_msi_parses() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "sign",
        "--pfx",
        "a.pfx",
        "--digest",
        "sha256",
        "--rust-sip",
        "msi",
        "x.msi",
    ])
    .expect("parse");
    let SubCommand::Sign(s) = c.command else {
        panic!("expected sign");
    };
    assert_eq!(s.rust_sip, Some(RustSipBackend::Msi));
}

#[test]
fn sign_rust_sip_msix_parses() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "sign",
        "--pfx",
        "a.pfx",
        "--digest",
        "sha256",
        "--rust-sip",
        "msix",
        "x.msix",
    ])
    .expect("parse");
    let SubCommand::Sign(s) = c.command else {
        panic!("expected sign");
    };
    assert_eq!(s.rust_sip, Some(RustSipBackend::Msix));
}

#[test]
fn sign_rust_sip_esd_parses() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "sign",
        "--pfx",
        "a.pfx",
        "--digest",
        "sha256",
        "--rust-sip",
        "esd",
        "x.wim",
    ])
    .expect("parse");
    let SubCommand::Sign(s) = c.command else {
        panic!("expected sign");
    };
    assert_eq!(s.rust_sip, Some(RustSipBackend::Esd));
}

#[test]
fn sign_rust_sip_cab_parses() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "sign",
        "--pfx",
        "a.pfx",
        "--digest",
        "sha256",
        "--rust-sip",
        "cab",
        "x.cab",
    ])
    .expect("parse");
    let SubCommand::Sign(s) = c.command else {
        panic!("expected sign");
    };
    assert_eq!(s.rust_sip, Some(RustSipBackend::Cab));
}

#[test]
fn sign_rust_sip_catalog_parses() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "sign",
        "--pfx",
        "a.pfx",
        "--digest",
        "sha256",
        "--rust-sip",
        "catalog",
        "x.cat",
    ])
    .expect("parse");
    let SubCommand::Sign(s) = c.command else {
        panic!("expected sign");
    };
    assert_eq!(s.rust_sip, Some(RustSipBackend::Catalog));
}

#[test]
fn verify_rust_sip_script_digest_check_parses() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "verify",
        "--policy",
        "pa",
        "--rust-sip-script-digest-check",
        "x.ps1",
    ])
    .expect("parse");
    let SubCommand::Verify(v) = c.command else {
        panic!("expected verify");
    };
    assert!(v.rust_sip_script_digest_check);
}

#[test]
fn verify_rust_sip_pe_digest_check_parses() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "verify",
        "--policy",
        "pa",
        "--rust-sip-pe-digest-check",
        "x.exe",
    ])
    .expect("parse");
    let SubCommand::Verify(v) = c.command else {
        panic!("expected verify");
    };
    assert!(v.rust_sip_pe_digest_check);
}

#[test]
fn verify_rust_sip_msi_digest_check_parses() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "verify",
        "--policy",
        "pa",
        "--rust-sip-msi-digest-check",
        "x.msi",
    ])
    .expect("parse");
    let SubCommand::Verify(v) = c.command else {
        panic!("expected verify");
    };
    assert!(v.rust_sip_msi_digest_check);
}

#[test]
fn verify_rust_sip_msix_digest_check_parses() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "verify",
        "--policy",
        "pa",
        "--rust-sip-msix-digest-check",
        "x.msix",
    ])
    .expect("parse");
    let SubCommand::Verify(v) = c.command else {
        panic!("expected verify");
    };
    assert!(v.rust_sip_msix_digest_check);
}

#[test]
fn verify_rust_sip_esd_digest_check_parses() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "verify",
        "--policy",
        "pa",
        "--rust-sip-esd-digest-check",
        "x.esd",
    ])
    .expect("parse");
    let SubCommand::Verify(v) = c.command else {
        panic!("expected verify");
    };
    assert!(v.rust_sip_esd_digest_check);
}

#[test]
fn verify_rust_sip_cab_digest_check_parses() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "verify",
        "--policy",
        "pa",
        "--rust-sip-cab-digest-check",
        "x.cab",
    ])
    .expect("parse");
    let SubCommand::Verify(v) = c.command else {
        panic!("expected verify");
    };
    assert!(v.rust_sip_cab_digest_check);
}

#[test]
fn verify_rust_sip_catalog_digest_check_parses() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "verify",
        "--policy",
        "pa",
        "--rust-sip-catalog-digest-check",
        "x.cat",
    ])
    .expect("parse");
    let SubCommand::Verify(v) = c.command else {
        panic!("expected verify");
    };
    assert!(v.rust_sip_catalog_digest_check);
}

#[test]
fn verify_rust_sip_all_digest_checks_parses() {
    let c = Cli::try_parse_from([
        "signtool-rs",
        "verify",
        "--policy",
        "pa",
        "--rust-sip-all-digest-checks",
        "x.exe",
    ])
    .expect("parse");
    let SubCommand::Verify(v) = c.command else {
        panic!("expected verify");
    };
    assert!(v.rust_sip_all_digest_checks);
}
