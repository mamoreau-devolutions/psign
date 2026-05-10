//! Detached PKCS#7 Authenticode trust (content bytes vs indirect digest).

use crate::trust_pkcs7::verify_authenticode_pkcs7_trust;
use crate::trust_verify_pe::{TrustVerifyPeOptions, TrustVerifyPeReport, load_trust_material};
use crate::verification_instant::resolve_verification_instant_for_pkcs7;
use anyhow::{Result, anyhow};
use authenticode::AuthenticodeSignature;
use digest::Digest;
use signtool_sip_digest::pe_digest::PeAuthenticodeHashKind;
use signtool_sip_digest::pkcs7_wire::normalize_pkcs7_der_for_authenticode;

fn hash_content_implicit(content: &[u8], embedded_len: usize) -> Result<Vec<u8>> {
    let kind = PeAuthenticodeHashKind::from_digest_byte_len(embedded_len)?;
    Ok(match kind {
        PeAuthenticodeHashKind::Sha1 => sha1::Sha1::digest(content).to_vec(),
        PeAuthenticodeHashKind::Sha256 => sha2::Sha256::digest(content).to_vec(),
        PeAuthenticodeHashKind::Sha384 => sha2::Sha384::digest(content).to_vec(),
        PeAuthenticodeHashKind::Sha512 => sha2::Sha512::digest(content).to_vec(),
    })
}

pub fn trust_verify_detached_bytes(
    content: &[u8],
    pkcs7_der: &[u8],
    opts: &TrustVerifyPeOptions,
) -> Result<TrustVerifyPeReport> {
    let (anchors, anchor_certs) = load_trust_material(opts)?;
    let normalized = normalize_pkcs7_der_for_authenticode(pkcs7_der);
    let slice = normalized.as_ref();

    let sig =
        AuthenticodeSignature::from_bytes(slice).map_err(|e| anyhow!("detached PKCS#7: {e}"))?;
    let embedded_digest = sig.digest();
    let computed = hash_content_implicit(content, embedded_digest.len())?;
    if computed.as_slice() != embedded_digest {
        return Err(anyhow!(
            "detached content digest does not match PKCS#7 indirect digest (algorithm inferred from embedded digest length)"
        ));
    }

    let verification_instant = resolve_verification_instant_for_pkcs7(
        slice,
        &opts.policy,
        opts.verification_instant_override.as_ref(),
    )?;
    verify_authenticode_pkcs7_trust(
        slice,
        0,
        computed.as_slice(),
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
