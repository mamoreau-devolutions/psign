//! Cross-platform helper over [`signtool_sip_digest`] — **no WinVerifyTrust**.
//!
//! Use this on Linux/macOS to compute PE image digests or to check PKCS#7 indirect-data consistency
//! for formats implemented in `signtool-sip-digest`. This does **not** replace full `signtool-rs` verify.

use anyhow::{Context, Result, anyhow};
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Deserialize;
use signtool_authenticode_trust::{
    AuthenticodeTrustPolicy, TrustVerifyPeOptions, TrustVerifyPeReport,
    inspect_authenticode_pkcs7_der, inspect_pe_authenticode, parse_verification_date_ymd,
    trust_verify_cab_bytes, trust_verify_catalog_bytes, trust_verify_detached_bytes,
    trust_verify_pe_bytes,
};
use signtool_sip_digest::cab_digest::{
    compute_cab_authenticode_digest, parse_cab_context, verify_cab_digest_consistency,
};
use signtool_sip_digest::catalog_digest;
use signtool_sip_digest::esd_digest;
use signtool_sip_digest::msi_digest;
use signtool_sip_digest::msix_digest;
use signtool_sip_digest::page_hashes::{self, PageHashAttrKind};
use signtool_sip_digest::pe_digest::{
    PeAuthenticodeHashKind, pe_authenticode_digest, pe_authenticode_digest_file_ranges,
};
use signtool_sip_digest::verify_pe;
use signtool_sip_digest::verify_script_digest_consistency;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "signtool-portable")]
#[command(version, about = "Portable Authenticode SIP digest utilities (no Windows CryptoAPI)", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args, Clone, Debug)]
struct TrustVerifySharedArgs {
    #[arg(long, value_name = "DIR")]
    anchor_dir: Option<PathBuf>,
    #[arg(long, value_name = "PATH")]
    authroot_cab: Option<PathBuf>,
    /// Require **`--authroot-cab`** file SHA-256 (64 lowercase hex chars) to match before ingest.
    #[arg(long, value_name = "HEX64")]
    expect_authroot_cab_sha256: Option<String>,
    #[arg(long)]
    verbose_chain: bool,
    /// Skip picky’s strict **code signing** checks on the signing certificate (`ignore_signing_certificate_check`).
    #[arg(long)]
    allow_loose_signing_cert: bool,
    /// Prefer nested RFC3161 **`TSTInfo.genTime`** (unsigned attrs) and PKCS#9 **`signing-time`** for picky **`exact_date`** (timestamp token signatures are **not** verified).
    #[arg(long)]
    prefer_timestamp_signing_time: bool,
    /// With **`--prefer-timestamp-signing-time`**, fail when no usable timestamp token exists.
    #[arg(long)]
    require_valid_timestamp: bool,
    /// Use this UTC date (YYYY-MM-DD) for **`exact_date`** instead of wall clock (for expired fixtures / reproducible CI).
    #[arg(long, value_name = "YYYY-MM-DD")]
    as_of: Option<String>,
}

fn trust_verify_options_from_shared(a: &TrustVerifySharedArgs) -> Result<TrustVerifyPeOptions> {
    let expect_authroot_cab_sha256 = match &a.expect_authroot_cab_sha256 {
        Some(s) => Some(parse_sha256_hex(s)?),
        None => None,
    };
    let verification_instant_override = match &a.as_of {
        Some(s) => Some(parse_verification_date_ymd(s)?),
        None => None,
    };
    Ok(TrustVerifyPeOptions {
        anchor_dir: a.anchor_dir.clone(),
        authroot_cab: a.authroot_cab.clone(),
        expect_authroot_cab_sha256,
        verification_instant_override,
        verbose_chain: a.verbose_chain,
        policy: AuthenticodeTrustPolicy {
            strict_code_signing_eku: !a.allow_loose_signing_cert,
            prefer_timestamp_signing_time: a.prefer_timestamp_signing_time,
            require_valid_timestamp: a.require_valid_timestamp,
        },
    })
}

fn parse_sha256_hex(s: &str) -> Result<[u8; 32]> {
    let hex = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    let hex = hex.strip_prefix("0X").unwrap_or(hex);
    if hex.len() != 64 {
        return Err(anyhow!(
            "expect 64 hex chars for SHA-256, got {}",
            hex.len()
        ));
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let byte =
            u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| anyhow!("invalid hex"))?;
        out[i] = byte;
    }
    Ok(out)
}

fn print_trust_ok(prefix: &str, report: &TrustVerifyPeReport) {
    println!(
        "{prefix}: ok — verified {} PKCS#7 entr(y/ies); {} anchor thumbprint(s)",
        report.pkcs7_entries_verified, report.anchor_thumbprints
    );
}

#[derive(Subcommand)]
enum Command {
    /// Print lowercase hex of the PE/WinMD **Authenticode image digest** (unsigned PE is OK).
    PeDigest {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = HashAlg::Sha256)]
        algorithm: HashAlg,
    },
    /// Require embedded PKCS#7; compare indirect digest to Rust PE recomputation for each Authenticode cert.
    VerifyPe { path: PathBuf },
    /// Verify PE Authenticode **trust**: PKCS#7 CMS validation + certificate chain to **explicit** anchors (no OS store).
    ///
    /// Supply **`--anchor-dir`** (Phase A: `.crt`/`.cer`/`.pem`) and/or **`--authroot-cab`** (extract certs + CTL thumbs from AuthRoot-style CAB `.stl` payloads). **`verify-pe`** remains digest-only; this subcommand adds chain + policy checks.
    TrustVerifyPe {
        path: PathBuf,
        #[command(flatten)]
        shared: TrustVerifySharedArgs,
    },
    /// Same trust pipeline as **`trust-verify-pe`** after CAB SIP digest consistency (**`verify-cab`**).
    TrustVerifyCab {
        path: PathBuf,
        #[command(flatten)]
        shared: TrustVerifySharedArgs,
    },
    /// CMS catalog digest consistency (**`verify-catalog`**) plus PKCS#7 chain to anchors when Authenticode-wrapped.
    TrustVerifyCatalog {
        path: PathBuf,
        #[command(flatten)]
        shared: TrustVerifySharedArgs,
    },
    /// Detached PKCS#7 vs raw **`content`** bytes (digest inferred from PKCS#7 indirect length); PKCS#7 blob normalized like Win32 `CryptVerifyDetachedMessageSignature` helpers.
    TrustVerifyDetached {
        content: PathBuf,
        signature: PathBuf,
        #[command(flatten)]
        shared: TrustVerifySharedArgs,
    },
    /// Print whether embedded PKCS#7 bytes contain **SPC_PE_IMAGE_PAGE_HASHES** attribute OIDs (V1/V2 DER scan).
    ///
    /// Outputs `yes` or `no` (does **not** validate page segments vs file bytes — use **`verify-pe-page-hashes`** for the experimental Rust check).
    PeHasPageHashes { path: PathBuf },
    /// Print structured **`SPC_PE_IMAGE_PAGE_HASHES`** rows from CMS **signed** attributes (one line per signer location).
    ///
    /// Includes **`parsed_page_hash_pairs`** when DER peeling + flat-table parsing succeeds (`-` otherwise).
    /// Empty stdout means no matching authenticated attributes were found. Does **not** validate pages vs file bytes.
    PePageHashInfo { path: PathBuf },
    /// **Experimental:** parse embedded page-hash tables and verify **contiguous raw file ranges** (see `signtool_sip_digest::page_hashes::verify_pe_embedded_page_hash_tables`).
    ///
    /// Not a full `WinVerifyTrust` `/ph` clone — checksum / cert-directory exclusions may differ from native.
    VerifyPePageHashes { path: PathBuf },
    /// Print ordered **[`start`,`end`)** file byte ranges included in **PE Authenticode image digest** (same layout as `authenticode-rs` / `pe_authenticode_digest`).
    ///
    /// One line per range: `start=N end=M` (half-open end). Useful on Linux for tooling / future page-hash alignment vs `WinTrust`.
    PeAuthenticodeRanges { path: PathBuf },
    /// CAB with embedded PKCS#7: compare indirect digest to Rust CAB hash.
    VerifyCab { path: PathBuf },
    /// Signed MSI: compare PKCS#7 indirect digest to Rust OLE fingerprint (and extended stream if present).
    VerifyMsi { path: PathBuf },
    /// Signed WIM/ESD: compare PKCS#7 indirect digest to Rust prefix hash.
    VerifyEsd { path: PathBuf },
    /// Cleartext MSIX/APPX/bundle: compare PKCS#7 indirect digest to Rust ZIP rehash (encrypted extensions rejected).
    VerifyMsix { path: PathBuf },
    /// Signed catalog `.cat`: compare PKCS#7 indirect digest to Rust catalog digest scan.
    VerifyCatalog { path: PathBuf },
    /// Script signed file (PowerShell-class or WSH): compare PKCS#7 indirect digest to Rust heuristic strip/hash.
    VerifyScript { path: PathBuf },
    /// Inspect PKCS#7 layers: signers, timestamp-related attribute OIDs, nested signatures (`1.3.6.1.4.1.311.2.4.1`). JSON to stdout.
    InspectAuthenticode {
        path: PathBuf,
        /// Treat **`path`** as a PE image (**embedded** attribute certs) vs raw PKCS#7 bytes.
        #[arg(long, value_enum, default_value_t = InspectInputKind::Pe)]
        input: InspectInputKind,
    },
    /// Validate JSON metadata shape for Microsoft Artifact Signing (`Endpoint`, `CodeSigningAccountName`, `CertificateProfileName`; optional `ExcludeCredentials` string array). No network / no signing.
    ///
    /// Reads **`--path`** or stdin when omitted (use `-` for stdin explicitly).
    ArtifactSigningMetadataCheck {
        #[arg(long, value_name = "PATH")]
        path: Option<PathBuf>,
    },
    /// Print lowercase hex CAB Authenticode digest **without** requiring PKCS#7 (unsigned / structural check).
    ///
    /// Algorithm must match what will be used at signing time (default SHA-256).
    CabDigest {
        path: PathBuf,
        #[arg(long, value_enum, default_value_t = HashAlg::Sha256)]
        algorithm: HashAlg,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum InspectInputKind {
    Pe,
    Pkcs7,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum HashAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl From<HashAlg> for PeAuthenticodeHashKind {
    fn from(value: HashAlg) -> Self {
        match value {
            HashAlg::Sha1 => Self::Sha1,
            HashAlg::Sha256 => Self::Sha256,
            HashAlg::Sha384 => Self::Sha384,
            HashAlg::Sha512 => Self::Sha512,
        }
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct ArtifactSigningMetadataDoc {
    Endpoint: String,
    CodeSigningAccountName: String,
    CertificateProfileName: String,
    #[serde(default)]
    ExcludeCredentials: Option<Vec<String>>,
}

fn read_json_input(path: Option<&Path>) -> Result<Vec<u8>> {
    use std::io::Read;
    match path {
        None => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .context("read JSON from stdin")?;
            Ok(buf)
        }
        Some(p) if p.as_os_str() == "-" => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .context("read JSON from stdin")?;
            Ok(buf)
        }
        Some(p) => std::fs::read(p).with_context(|| format!("read {}", p.display())),
    }
}

fn run_artifact_signing_metadata_check(path: Option<PathBuf>) -> Result<()> {
    let raw = read_json_input(path.as_deref())?;
    if raw.is_empty() {
        return Err(anyhow!("metadata JSON is empty"));
    }
    let doc: ArtifactSigningMetadataDoc = serde_json::from_slice(&raw)
        .context("parse Artifact Signing metadata JSON")?;
    if doc.Endpoint.trim().is_empty() {
        return Err(anyhow!("Endpoint must be a non-empty string"));
    }
    if doc.CodeSigningAccountName.trim().is_empty() {
        return Err(anyhow!("CodeSigningAccountName must be a non-empty string"));
    }
    if doc.CertificateProfileName.trim().is_empty() {
        return Err(anyhow!("CertificateProfileName must be a non-empty string"));
    }
    if let Some(exc) = &doc.ExcludeCredentials {
        for (i, s) in exc.iter().enumerate() {
            if s.trim().is_empty() {
                return Err(anyhow!(
                    "ExcludeCredentials[{i}] must be a non-empty string"
                ));
            }
        }
    }
    println!("artifact-signing-metadata-check: ok");
    Ok(())
}

fn script_ext_from_path(path: &Path) -> Result<&str> {
    let ext = path
        .extension()
        .and_then(OsStr::to_str)
        .filter(|e| !e.is_empty())
        .with_context(|| format!("could not infer script extension from {}", path.display()))?;
    Ok(ext)
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::PeDigest { path, algorithm } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let digest = pe_authenticode_digest(&bytes, algorithm.into())?;
            println!("{}", hex_lower(&digest));
        }
        Command::VerifyPe { path } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            verify_pe::verify_pe_authenticode_digest_consistency(&bytes)
                .with_context(|| format!("verify-pe {}", path.display()))?;
        }
        Command::TrustVerifyPe { path, shared } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let opts = trust_verify_options_from_shared(&shared)?;
            let report = trust_verify_pe_bytes(&bytes, &opts)
                .with_context(|| format!("trust-verify-pe {}", path.display()))?;
            print_trust_ok("trust-verify-pe", &report);
        }
        Command::TrustVerifyCab { path, shared } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let opts = trust_verify_options_from_shared(&shared)?;
            let report = trust_verify_cab_bytes(&bytes, &opts)
                .with_context(|| format!("trust-verify-cab {}", path.display()))?;
            print_trust_ok("trust-verify-cab", &report);
        }
        Command::TrustVerifyCatalog { path, shared } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let opts = trust_verify_options_from_shared(&shared)?;
            let report = trust_verify_catalog_bytes(&bytes, &opts)
                .with_context(|| format!("trust-verify-catalog {}", path.display()))?;
            print_trust_ok("trust-verify-catalog", &report);
        }
        Command::TrustVerifyDetached {
            content,
            signature,
            shared,
        } => {
            let content_bytes =
                std::fs::read(&content).with_context(|| format!("read {}", content.display()))?;
            let sig_bytes = std::fs::read(&signature)
                .with_context(|| format!("read {}", signature.display()))?;
            let opts = trust_verify_options_from_shared(&shared)?;
            let report = trust_verify_detached_bytes(&content_bytes, &sig_bytes, &opts)
                .with_context(|| format!("trust-verify-detached {}", content.display()))?;
            print_trust_ok("trust-verify-detached", &report);
        }
        Command::PeHasPageHashes { path } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let present = page_hashes::pe_embedded_pkcs7_contains_page_hash_attribute(&bytes)
                .with_context(|| format!("pe-has-page-hashes {}", path.display()))?;
            println!("{}", if present { "yes" } else { "no" });
        }
        Command::PePageHashInfo { path } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let rows = page_hashes::pe_collect_page_hash_auth_attributes(&bytes)
                .with_context(|| format!("pe-page-hash-info {}", path.display()))?;
            for loc in rows {
                let v1 = loc
                    .values
                    .iter()
                    .filter(|v| v.kind == PageHashAttrKind::V1)
                    .count();
                let v2 = loc
                    .values
                    .iter()
                    .filter(|v| v.kind == PageHashAttrKind::V2)
                    .count();
                let total_bytes: usize = loc.values.iter().map(|v| v.value_der.len()).sum();
                let mut parsed_pairs = 0usize;
                let mut parse_ok = true;
                for v in &loc.values {
                    match page_hashes::parse_page_hash_attribute_entries(&v.value_der, v.kind) {
                        Ok(entries) => parsed_pairs += entries.len(),
                        Err(_) => parse_ok = false,
                    }
                }
                let parsed_field = if parse_ok {
                    parsed_pairs.to_string()
                } else {
                    "-".to_string()
                };
                println!(
                    "pkcs7_index={} signer_index={} v1_values={} v2_values={} value_bytes_total={} parsed_page_hash_pairs={}",
                    loc.pkcs7_index, loc.signer_index, v1, v2, total_bytes, parsed_field
                );
            }
        }
        Command::VerifyPePageHashes { path } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            page_hashes::verify_pe_embedded_page_hash_tables(&bytes)
                .with_context(|| format!("verify-pe-page-hashes {}", path.display()))?;
        }
        Command::PeAuthenticodeRanges { path } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let ranges = pe_authenticode_digest_file_ranges(&bytes)
                .with_context(|| format!("pe-authenticode-ranges {}", path.display()))?;
            for r in ranges {
                println!("start={} end={}", r.start, r.end);
            }
        }
        Command::VerifyCab { path } => {
            verify_cab_digest_consistency(&path)
                .with_context(|| format!("verify-cab {}", path.display()))?;
        }
        Command::VerifyMsi { path } => {
            msi_digest::verify_msi_digest_consistency(&path)
                .with_context(|| format!("verify-msi {}", path.display()))?;
        }
        Command::VerifyEsd { path } => {
            esd_digest::verify_wim_esd_digest_consistency(&path)
                .with_context(|| format!("verify-esd {}", path.display()))?;
        }
        Command::VerifyMsix { path } => {
            msix_digest::verify_msix_digest_consistency(&path)
                .with_context(|| format!("verify-msix {}", path.display()))?;
        }
        Command::VerifyCatalog { path } => {
            catalog_digest::verify_catalog_digest_consistency(&path)
                .with_context(|| format!("verify-catalog {}", path.display()))?;
        }
        Command::VerifyScript { path } => {
            let raw = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let ext = script_ext_from_path(&path)?;
            verify_script_digest_consistency(&raw, ext)
                .with_context(|| format!("verify-script {}", path.display()))?;
        }
        Command::InspectAuthenticode { path, input } => {
            let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let json = match input {
                InspectInputKind::Pe => serde_json::to_string_pretty(&inspect_pe_authenticode(&bytes)?)?,
                InspectInputKind::Pkcs7 => {
                    serde_json::to_string_pretty(&inspect_authenticode_pkcs7_der(&bytes)?)?
                }
            };
            println!("{json}");
        }
        Command::ArtifactSigningMetadataCheck { path } => {
            run_artifact_signing_metadata_check(path)?;
        }
        Command::CabDigest { path, algorithm } => {
            let data = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
            let ctx = parse_cab_context(&data)?;
            let digest = compute_cab_authenticode_digest(&data, &ctx, algorithm.into())?;
            println!("{}", hex_lower(&digest));
        }
    }
    Ok(())
}
