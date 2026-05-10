//! Shared PKCS#7 Authenticode trust step (digest already known).

use crate::anchor::{AnchorStore, cert_sha1_thumbprint};
use crate::chain::{issuer_chain_excluding_leaf, merge_unique_certs, terminal_root_cert};
use crate::policy::AuthenticodeTrustPolicy;
use anyhow::{Result, anyhow};
use picky::x509::certificate::Cert;
use picky::x509::date::UtcDate;
use picky::x509::pkcs7::authenticode::AuthenticodeSignature;

/// Verify picky Authenticode PKCS#7 cryptographic checks and certificate chain to configured anchors.
///
/// `subject_digest` must match the PKCS#7 indirect **`messageDigest`** (same bytes used for PE/CAB
/// Authenticode image digest, etc.).
#[allow(clippy::too_many_arguments)]
pub fn verify_authenticode_pkcs7_trust(
    pkcs7_der: &[u8],
    pkcs7_index: usize,
    subject_digest: &[u8],
    anchors: &AnchorStore,
    anchor_certs: &[Cert],
    policy: &AuthenticodeTrustPolicy,
    verification_instant: &UtcDate,
    verbose_chain: bool,
) -> Result<()> {
    let picky_sig =
        AuthenticodeSignature::from_der(pkcs7_der).map_err(|e| anyhow!("picky PKCS#7: {e}"))?;

    if policy.strict_code_signing_eku {
        picky_sig
            .authenticode_verifier()
            .require_basic_authenticode_validation(subject_digest.to_vec())
            .ignore_chain_check()
            .exact_date(verification_instant)
            .require_signing_certificate_check()
            .verify()
            .map_err(|e| anyhow!("picky Authenticode validation (PKCS#7 {pkcs7_index}): {e}"))?;
    } else {
        picky_sig
            .authenticode_verifier()
            .require_basic_authenticode_validation(subject_digest.to_vec())
            .ignore_chain_check()
            .exact_date(verification_instant)
            .ignore_signing_certificate_check()
            .verify()
            .map_err(|e| anyhow!("picky Authenticode validation (PKCS#7 {pkcs7_index}): {e}"))?;
    }

    let embedded = picky_sig.0.decode_certificates();
    let merged = merge_unique_certs(embedded, anchor_certs.iter().cloned())?;

    let leaf = picky_sig
        .signing_certificate(&merged)
        .map_err(|e| anyhow!("resolve signing certificate: {e}"))?;

    let chain_vec = issuer_chain_excluding_leaf(leaf, &merged)?;
    let root = terminal_root_cert(leaf, &chain_vec);

    let root_thumb = cert_sha1_thumbprint(root)?;
    if !anchors.contains_thumbprint(&root_thumb) {
        return Err(anyhow!(
            "terminal root certificate is not in the anchor store (SHA-1 thumbprint {:02x}{:02x}…)",
            root_thumb[0],
            root_thumb[1]
        ));
    }

    if verbose_chain {
        let thumb_hex: String = root_thumb.iter().map(|b| format!("{b:02x}")).collect();
        eprintln!(
            "trust-verify: PKCS#7[{pkcs7_index}] leaf subject: {}",
            leaf.subject_name()
        );
        for (i, c) in chain_vec.iter().enumerate() {
            eprintln!(
                "trust-verify:   chain[{i}] subject: {} issuer: {}",
                c.subject_name(),
                c.issuer_name()
            );
        }
        eprintln!(
            "trust-verify:   root subject: {} (thumb SHA-1 {thumb_hex})",
            root.subject_name(),
        );
    }

    leaf.verifier()
        .chain(chain_vec.iter().copied())
        .exact_date(verification_instant)
        .verify()
        .map_err(|e| anyhow!("certificate chain verification (PKCS#7 {pkcs7_index}): {e}"))?;

    Ok(())
}
