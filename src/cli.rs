use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "signtool-rs",
    version,
    about = "Rust reimplementation of signtool.exe"
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalOpts,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Args, Debug, Clone)]
pub struct GlobalOpts {
    /// Quiet mode (native `/q`): suppress stdout on success.
    #[arg(short = 'q', long, global = true)]
    pub quiet: bool,
    /// Verbose mode (native `/v`).
    #[arg(short = 'v', long, global = true)]
    pub verbose: bool,
    /// Debug diagnostics (native `/debug`).
    #[arg(long, global = true)]
    pub debug: bool,
}

#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)] // Subcommands mirror native `signtool` argv shapes; indirection hurts clap ergonomics.
pub enum Command {
    /// Verify embedded Authenticode signature on a file.
    Verify(VerifyArgs),
    /// Sign a file using mssign32 (`SignerSignEx3`).
    Sign(SignArgs),
    /// Add timestamp to an existing signature.
    Timestamp(TimestampArgs),
    /// Add or remove catalog files in a catalog database (native `catdb`).
    Catdb(CatdbArgs),
    /// Remove embedded signature data from a PE file (native `remove`).
    Remove(RemoveArgs),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum VerifyPolicy {
    Default,
    Pa,
    Pg,
}

/// Experimental Rust SIP backend selector (`sign --rust-sip …`, `SIGNTOOL_RS_RUST_SIP`).
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum RustSipBackend {
    /// PE / PE-like WinMD post-sign Authenticode digest consistency check after OS signing.
    #[value(name = "pe")]
    Pe,
    /// Scripts: PowerShell-class (`pwrshsip.dll` markers) and WSH `.js`/`.vbs`/`.wsf` (`wshext.dll` strip + offset dword hash); PKCS#7 indirect digest parity (experimental).
    #[value(name = "script")]
    Script,
    /// Windows Installer `.msi` — OLE structured-storage Authenticode fingerprint vs PKCS#7 (`MSISIP.DLL`; Signify-compatible traversal).
    #[value(name = "msi")]
    Msi,
    /// WIM/ESD (`.wim`, `.esd`) — prefix digest vs PKCS#7 per `EsdSip.dll` (`GetHashDataOffset` / embedded signature tail).
    #[value(name = "esd")]
    Esd,
    /// MSIX/AppX flat packages and bundles (`.msix`, `.appx`, `.msixbundle`, `.appxbundle`) — APPX PKCS#7 blob vs ZIP-derived hashes per `AppxSip.dll` / osslsigncode `appx.c`.
    #[value(name = "msix")]
    Msix,
    /// Cabinet `.cab` — MSCF digest vs PKCS#7 per `WINTRUST` CAB SIP / osslsigncode `cab.c`.
    #[value(name = "cab")]
    Cab,
    /// PKCS#7 `.cat` catalog — CMS digest over encapsulated CTL `eContent` vs PKCS#9 `messageDigest` (`WINTRUST` SIP).
    #[value(name = "catalog")]
    Catalog,
    /// Ignore `SIGNTOOL_RS_RUST_SIP` for this invocation.
    #[value(name = "off")]
    Off,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum DigestAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    /// Native `/fd certHash` — digest algorithm follows the signing certificate.
    #[value(name = "cert-hash", alias = "certHash")]
    CertHash,
}

impl DigestAlgorithm {
    pub fn as_signtool_name(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha384 => "SHA384",
            Self::Sha512 => "SHA512",
            Self::CertHash => "certHash",
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum CatalogSearchMode {
    /// Native `/a` — try catalog resolution then embedded signature.
    All,
    /// Native `/ad` — default catalog database.
    #[value(name = "default-db")]
    DefaultDb,
    /// Native `/as` — system component (driver) catalog database.
    System,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum CatalogHashAlgorithm {
    Sha1,
    Sha256,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum Pkcs7ContentEmbedding {
    Embedded,
    DetachedSignedData,
    Pkcs7DetachedSignedData,
}

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Verification policy mode.
    #[arg(long, value_enum, default_value_t = VerifyPolicy::Default)]
    pub policy: VerifyPolicy,
    /// Custom policy GUID for `--policy pg`.
    #[arg(long)]
    pub policy_guid: Option<String>,
    /// Enable revocation checks.
    #[arg(long, visible_alias = "vr")]
    pub revocation_check: bool,
    /// Optional detached PKCS#7 signature file.
    #[arg(long, visible_alias = "p7s", conflicts_with = "catalog")]
    pub detached_pkcs7: Option<PathBuf>,
    /// Optional catalog file (native `/c`).
    #[arg(long, visible_alias = "c", conflicts_with = "detached_pkcs7")]
    pub catalog: Option<PathBuf>,
    /// Catalog database search mode (native `/a`, `/ad`, `/as`).
    #[arg(long, value_enum)]
    pub catalog_search: Option<CatalogSearchMode>,
    /// Catalog database GUID (native `/ag`).
    #[arg(long, visible_alias = "ag")]
    pub catalog_database_guid: Option<String>,
    /// Hash algorithm for catalog member lookup (native `/hash`).
    #[arg(long, visible_alias = "hash", value_enum, default_value_t = CatalogHashAlgorithm::Sha256)]
    pub catalog_hash_algorithm: CatalogHashAlgorithm,
    /// OS/platform validity context for **catalog** verification (native `/o <ver>` with `/a`/`/c`/…; enables `WTD_USE_DEFAULT_OSVER_CHECK`). Not valid for embedded `/pa` verify on current signtool.
    #[arg(long)]
    pub os_version_check: Option<String>,
    /// Verify using kernel-mode driver policy (native `/kp`).
    #[arg(long, visible_alias = "kp")]
    pub kernel_policy: bool,
    /// Verify all signatures where available (native `/all`).
    #[arg(long, visible_alias = "all")]
    pub all_signatures: bool,
    /// Allow test roots when building chain.
    #[arg(long, visible_alias = "testroot")]
    pub allow_test_root: bool,
    /// Warn (exit code 2) if the signature is not timestamped (native `/tw`).
    #[arg(long, visible_alias = "tw")]
    pub warn_if_not_timestamped: bool,
    /// Verify only the signature at this index (native `/ds`).
    #[arg(long, visible_alias = "ds")]
    pub signature_index: Option<u32>,
    /// Multiple verification semantics (native `/ms`) — compatibility flag.
    #[arg(long, visible_alias = "ms")]
    pub multiple_semantics: bool,
    /// Treat input as PKCS#7-centric verification (native `/p7`) — limited parity.
    #[arg(long, visible_alias = "p7")]
    pub verify_pkcs7_file: bool,
    /// Print description / URL when available (native `/d`; requires `-v` / `--verbose` like native).
    #[arg(long, visible_alias = "d")]
    pub print_description: bool,
    /// Print and verify page hashes (native `/ph`; requires `-v` / `--verbose` like native).
    #[arg(long, visible_alias = "ph")]
    pub verify_page_hashes: bool,
    /// Require signing chain to a root whose subject contains this string (native `/r`).
    #[arg(long, visible_alias = "r")]
    pub chain_root_subject: Option<String>,
    /// Signer certificate SHA1 thumbprint(s); verification succeeds if any matches (native `/sha1`, repeatable).
    #[arg(long, visible_alias = "sha1", action = clap::ArgAction::Append)]
    pub signer_thumbprint_sha1: Vec<String>,
    /// Intermediate CA certificate SHA1 thumbprint(s); at least one must appear in the chain (native `/ca`, repeatable).
    #[arg(long, visible_alias = "ca", action = clap::ArgAction::Append)]
    pub intermediate_ca_sha1: Vec<String>,
    /// Emit warning (exit 2) if the signer cert lacks this EKU OID (native verify `/u`, repeatable).
    #[arg(long, visible_alias = "u", action = clap::ArgAction::Append)]
    pub warn_if_missing_eku: Vec<String>,
    /// Content file for detached PKCS#7 verification (native `/p7content`); default is the first verify target path.
    #[arg(long, visible_alias = "p7content")]
    pub detached_pkcs7_content: Option<PathBuf>,
    /// Warn (exit 2) if Microsoft Windows PCA 2010 appears in the chain (native `/w2010pca`).
    #[arg(long, visible_alias = "w2010pca")]
    pub warn_pca_2010: bool,
    /// Suppress PCA 2010 chain warnings, including driver-policy defaults (native `/now2010pca`).
    #[arg(long, visible_alias = "now2010pca")]
    pub no_warn_pca_2010: bool,
    /// Verify sealing signatures (native `/sl`) via WinTrust `WSS_VERIFY_SEALING` (embedded verify only).
    #[arg(long, visible_alias = "sl")]
    pub verify_sealing_signatures: bool,
    /// After a successful embedded WinTrust verification, recompute the PE Authenticode digest in Rust and compare it to the PKCS#7 indirect digest (experimental).
    #[arg(long = "rust-sip-pe-digest-check")]
    pub rust_sip_pe_digest_check: bool,
    /// After embedded WinTrust success on signed scripts (PowerShell-class or WSH), run the Rust digest heuristic vs PKCS#7 (experimental).
    #[arg(long = "rust-sip-script-digest-check")]
    pub rust_sip_script_digest_check: bool,
    /// After embedded WinTrust success on a signed `.msi`, run the Rust MSI SIP digest vs PKCS#7 and optional `MsiDigitalSignatureEx` pre-hash (experimental).
    #[arg(long = "rust-sip-msi-digest-check")]
    pub rust_sip_msi_digest_check: bool,
    /// After embedded WinTrust success on a signed WIM/ESD file, run the Rust ESD SIP prefix digest vs PKCS#7 (experimental).
    #[arg(long = "rust-sip-esd-digest-check")]
    pub rust_sip_esd_digest_check: bool,
    /// After embedded WinTrust success on a signed `.msix`/`.appx`/`.msixbundle`/`.appxbundle`, compare PKCS#7 APPX blob with Rust ZIP hashes (experimental).
    #[arg(long = "rust-sip-msix-digest-check")]
    pub rust_sip_msix_digest_check: bool,
    /// After embedded WinTrust success on a signed `.cab`, recompute the CAB MSCF digest in Rust vs PKCS#7 (experimental).
    #[arg(long = "rust-sip-cab-digest-check")]
    pub rust_sip_cab_digest_check: bool,
    /// After embedded WinTrust success on a signed `.cat`, compare CMS `eContent` digest with PKCS#9 `messageDigest` (experimental).
    #[arg(long = "rust-sip-catalog-digest-check")]
    pub rust_sip_catalog_digest_check: bool,
    /// Shorthand: enable every `--rust-sip-*-digest-check` option above for embedded verify (experimental). Cleartext MSIX only; encrypted `.eappx`/`.emsix` subjects fail with an explicit error from the MSIX checker.
    #[arg(long = "rust-sip-all-digest-checks")]
    pub rust_sip_all_digest_checks: bool,
    /// Verify with biometric signing policy (native `/bp`) — not implemented.
    #[arg(long, visible_alias = "bp")]
    pub biometric_policy: bool,
    /// Verify with enclave signing policy (native `/enclave`) — not implemented.
    #[arg(long, visible_alias = "enclave")]
    pub enclave_policy: bool,
    /// Files to verify (native `<filename(s)>`; one or more trailing paths).
    #[arg(required = true)]
    pub files: Vec<PathBuf>,
}

#[derive(Args, Debug)]
pub struct SignArgs {
    /// PFX file to use.
    #[arg(long, visible_alias = "f")]
    pub pfx: Option<PathBuf>,
    /// Optional password for the PFX.
    #[arg(long, visible_alias = "p")]
    pub password: Option<String>,
    /// Automatically select the best certificate.
    #[arg(long, visible_alias = "a")]
    pub auto_select: bool,
    /// Subject-name match for cert selection.
    #[arg(long, visible_alias = "n")]
    pub subject_name: Option<String>,
    /// Issuer substring filter for cert selection (native `/i`).
    #[arg(long, visible_alias = "i")]
    pub issuer_name: Option<String>,
    /// SHA1 thumbprint for cert selection.
    #[arg(long, visible_alias = "sha1")]
    pub cert_sha1: Option<String>,
    /// CSP name for cert private key.
    #[arg(long, visible_alias = "csp")]
    pub csp: Option<String>,
    /// Key container name.
    #[arg(long, visible_alias = "kc")]
    pub key_container: Option<String>,
    /// Use machine store.
    #[arg(long, visible_alias = "sm")]
    pub machine_store: bool,
    /// Certificate store name for non-PFX selection (default: MY).
    #[arg(long, visible_alias = "s", default_value = "MY")]
    pub store_name: String,
    /// Append signature instead of replacing.
    #[arg(long, visible_alias = "as")]
    pub append_signature: bool,
    /// Generate page hashes (native `/ph`; requires decoupled digest for MSIX).
    #[arg(long, visible_alias = "ph")]
    pub page_hashes: bool,
    /// Suppress page hashes for PE when supported (native `/nph`; sets `SIGNTOOL_PAGE_HASHES=0` for `SignerSignEx3`).
    #[arg(long, visible_alias = "nph")]
    pub no_page_hashes: bool,
    /// Decoupled digest provider DLL (native `/dlib`).
    #[arg(long, visible_alias = "dlib")]
    pub dlib: Option<PathBuf>,
    /// Decoupled digest metadata file (native `/dmdf`).
    #[arg(long, visible_alias = "dmdf")]
    pub dmdf: Option<PathBuf>,
    /// Digest algorithm for signing (native `/fd`).
    #[arg(long, visible_alias = "fd", value_enum, default_value_t = DigestAlgorithm::Sha256)]
    pub digest: DigestAlgorithm,
    /// RFC3161 timestamp URL at sign time (native `/tr`).
    #[arg(
        long,
        visible_alias = "tr",
        conflicts_with_all = ["legacy_timestamp_url", "seal_timestamp_url"]
    )]
    pub timestamp_url: Option<String>,
    /// Legacy Authenticode timestamp URL at sign time (native `/t`).
    #[arg(
        long,
        visible_alias = "t",
        conflicts_with_all = ["timestamp_url", "seal_timestamp_url"]
    )]
    pub legacy_timestamp_url: Option<String>,
    /// RFC3161 timestamp URL for sealed packages at sign time (native sign `/tseal`). Mutually exclusive with `--timestamp-url` and `--legacy-timestamp-url`; uses the same `SignerSignEx3` RFC3161 path as `/tr` in this implementation.
    #[arg(
        long,
        visible_alias = "tseal",
        conflicts_with_all = ["timestamp_url", "legacy_timestamp_url"]
    )]
    pub seal_timestamp_url: Option<String>,
    /// RFC3161 timestamp digest algorithm (native `/td`).
    #[arg(long, visible_alias = "td", value_enum)]
    pub timestamp_digest: Option<DigestAlgorithm>,
    /// Authenticode description string (native `/d` on `sign`).
    #[arg(long, visible_alias = "d")]
    pub description: Option<String>,
    /// Authenticode description URL (native `/du`).
    #[arg(long, visible_alias = "du")]
    pub description_url: Option<String>,
    /// Additional certificate file to include in the signature (native `/ac`).
    #[arg(long, visible_alias = "ac")]
    pub additional_cert: Option<PathBuf>,
    /// Root certificate subject substring the signing cert must chain to (native `/r`).
    #[arg(long, visible_alias = "r")]
    pub root_subject_name: Option<String>,
    /// Enhanced key usage OID or friendly string required on the signing cert (native `/u`).
    #[arg(long, visible_alias = "u")]
    pub eku_oid: Option<String>,
    /// Require Windows System Component Verification EKU (native `/uw`).
    #[arg(long, visible_alias = "uw")]
    pub eku_windows_system_component: bool,
    /// Split digest: generate digest and unsigned PKCS#7 (native `/dg`).
    #[arg(long, visible_alias = "dg")]
    pub digest_generate: Option<PathBuf>,
    /// Split digest: sign digest file only (native `/ds`).
    #[arg(long, visible_alias = "ds")]
    pub digest_sign_only: bool,
    /// Split digest: ingest signed digest (native `/di`).
    #[arg(long, visible_alias = "di")]
    pub digest_ingest: Option<PathBuf>,
    /// With `--digest-generate`, emit XML (native `/dxml`).
    #[arg(long, visible_alias = "dxml")]
    pub digest_xml: bool,
    /// Write PKCS#7 output for each file (native `/p7`) — not fully implemented for all formats.
    #[arg(long, visible_alias = "p7")]
    pub pkcs7_output_dir: Option<PathBuf>,
    /// PKCS#7 content OID (native `/p7co`).
    #[arg(long, visible_alias = "p7co")]
    pub pkcs7_content_oid: Option<String>,
    #[arg(long, visible_alias = "p7ce", value_enum)]
    pub pkcs7_content_embedding: Option<Pkcs7ContentEmbedding>,
    /// Certificate template name for cert selection (native `/c`).
    #[arg(long = "certificate-template", visible_alias = "c")]
    pub certificate_template: Option<String>,
    /// OID and UTF-8 value as authenticated attributes (native `/sa OID value`; repeatable).
    #[arg(
        long = "sign-auth",
        visible_alias = "sa",
        action = clap::ArgAction::Append,
        num_args = 2,
        value_names = ["OID", "VALUE"]
    )]
    pub sign_auth_pairs: Vec<String>,
    /// Warn if file digest algorithm differs from signing cert signature hash (native `/fdchw`) — not implemented.
    #[arg(long = "fdchw")]
    pub warn_fd_digest_vs_cert_signature_hash: bool,
    /// Warn if RFC3161 timestamp digest differs from signing cert signature hash (native `/tdchw`) — not implemented.
    #[arg(long = "tdchw")]
    pub warn_td_digest_vs_cert_signature_hash: bool,
    /// Relaxed PE marker check (native `/rmc`, MS12-024) — not implemented.
    #[arg(long = "rmc")]
    pub relaxed_pe_marker_check: bool,
    /// Add sealing signature when supported (native `/seal`) — not implemented.
    #[arg(long = "seal")]
    pub add_sealing_signature: bool,
    /// Primary signature with intent-to-seal (native `/itos`) — not implemented.
    #[arg(long = "itos")]
    pub intent_to_seal: bool,
    /// Remove existing signature/seal when required for sealing (native `/force`) — not implemented.
    #[arg(long = "force")]
    pub force_seal_or_resign: bool,
    /// Sealing warnings do not change exit code (native `/nosealwarn`) — not implemented.
    #[arg(long = "nosealwarn")]
    pub sign_no_seal_warn: bool,
    /// Enclave warnings do not change exit code (native `/noenclavewarn`) — not implemented.
    #[arg(long = "noenclavewarn")]
    pub sign_no_enclave_warn: bool,
    /// Experimental Rust SIP behavior (`pe` / `script` / `msi` / `esd` / `msix` / `cab` = post-sign digest consistency check). Override with env `SIGNTOOL_RS_RUST_SIP` when unset; use `off` to ignore the env var.
    #[arg(long = "rust-sip", value_enum)]
    pub rust_sip: Option<RustSipBackend>,
    /// File(s) to sign (native trailing `<filename(s)>`).
    #[arg(required = true)]
    pub files: Vec<PathBuf>,
}

#[derive(Args, Debug)]
pub struct TimestampArgs {
    /// RFC3161 timestamp URL (native `/tr`).
    #[arg(
        long,
        visible_alias = "tr",
        conflicts_with_all = ["legacy_url", "seal_timestamp_url"]
    )]
    pub rfc3161_url: Option<String>,
    /// Legacy Authenticode timestamp URL (native `/t`).
    #[arg(
        long,
        visible_alias = "t",
        conflicts_with_all = ["rfc3161_url", "seal_timestamp_url"]
    )]
    pub legacy_url: Option<String>,
    /// RFC3161 timestamp URL for sealed files (native timestamp `/tseal`). Uses the same `SignerTimeStampEx3` path as `--rfc3161-url` in this implementation.
    #[arg(
        long,
        visible_alias = "tseal",
        conflicts_with_all = ["rfc3161_url", "legacy_url"]
    )]
    pub seal_timestamp_url: Option<String>,
    /// Timestamp digest algorithm (native `/td`).
    #[arg(long, visible_alias = "td", value_enum, default_value_t = DigestAlgorithm::Sha256)]
    pub digest: DigestAlgorithm,
    /// Timestamp the signature at this index (native `/tp`).
    #[arg(long, visible_alias = "tp")]
    pub signature_index: Option<u32>,
    /// Timestamp PKCS#7 files (native `/p7`) — not implemented.
    #[arg(long, visible_alias = "p7")]
    pub timestamp_pkcs7_files: bool,
    /// Remove sealing signature before timestamping (native `/force`) — not implemented.
    #[arg(long, visible_alias = "force")]
    pub remove_seal: bool,
    /// Sealing-removal warnings do not affect exit code (native `/nosealwarn`) — not implemented.
    #[arg(long, visible_alias = "nosealwarn")]
    pub no_seal_warn: bool,
    /// File(s) with an existing signature to timestamp (native trailing `<filename(s)>`).
    #[arg(required = true)]
    pub files: Vec<PathBuf>,
}

#[derive(Args, Debug)]
pub struct CatdbArgs {
    /// Operate on the default catalog database instead of the driver database (native `/d`).
    #[arg(long, visible_alias = "d")]
    pub default_database: bool,
    /// Operate on the catalog database identified by this GUID (native `/g`).
    #[arg(long, visible_alias = "g")]
    pub database_guid: Option<String>,
    /// Remove catalogs from the database (native `/r`).
    #[arg(long, visible_alias = "r")]
    pub remove: bool,
    /// Generate unique catalog names when adding (native `/u`).
    #[arg(long, visible_alias = "u")]
    pub unique_name: bool,
    /// Catalog files to add or remove.
    pub catalogs: Vec<PathBuf>,
}

#[derive(Args, Debug)]
pub struct RemoveArgs {
    /// Remove signature(s) entirely (native `/s`).
    #[arg(long, visible_alias = "s")]
    pub strip_signature: bool,
    /// Remove all certificates except the signer from the embedded signature (native `/c`).
    #[arg(long, visible_alias = "c")]
    pub strip_chain_except_signer: bool,
    /// Remove unauthenticated attributes (e.g. dual signatures, timestamps) (native `/u`).
    #[arg(long, visible_alias = "u")]
    pub strip_unauthenticated_attributes: bool,
    /// PE/COFF file(s) to modify (native trailing `<filename(s)>`).
    #[arg(required = true)]
    pub files: Vec<PathBuf>,
}
