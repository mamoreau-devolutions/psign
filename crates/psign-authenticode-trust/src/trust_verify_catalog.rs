//! Catalog `.cat` Authenticode trust (CMS digest consistency + PKCS#7 chain).

use crate::trust_pkcs7::verify_authenticode_pkcs7_trust;
use crate::trust_verify_pe::{TrustVerifyPeOptions, TrustVerifyPeReport, load_trust_material};
use crate::verification_instant::resolve_verification_instant_for_pkcs7;
use anyhow::{Result, anyhow};
use authenticode::AuthenticodeSignature;
use psign_sip_digest::catalog_digest;

pub fn trust_verify_catalog_bytes(
    data: &[u8],
    opts: &TrustVerifyPeOptions,
) -> Result<TrustVerifyPeReport> {
    catalog_digest::verify_catalog_digest_consistency_bytes(data)?;

    let (anchors, anchor_certs) = load_trust_material(opts)?;

    let sig = AuthenticodeSignature::from_bytes(data).map_err(|e| {
        anyhow!(
            "catalog PKCS#7 is not Authenticode-wrapped for picky trust (digest-only path still works via verify-catalog): {e}"
        )
    })?;
    let digest = sig.digest().to_vec();

    let verification_instant = resolve_verification_instant_for_pkcs7(
        data,
        &opts.policy,
        opts.verification_instant_override.as_ref(),
    )?;
    verify_authenticode_pkcs7_trust(
        data,
        0,
        digest.as_slice(),
        &anchors,
        &anchor_certs,
        &opts.policy,
        &verification_instant,
        opts.verbose_chain,
    )?;

    Ok(TrustVerifyPeReport {
        pkcs7_entries_verified: 1,
        anchor_thumbprints: anchors.thumbprint_count(),
    })
}
