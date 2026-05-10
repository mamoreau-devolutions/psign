use super::pe_digest::{ParsedPe, PeAuthenticodeHashKind, pe_authenticode_digest};
use anyhow::{Result, anyhow};
use authenticode::{AttributeCertificateIterator, WIN_CERT_TYPE_PKCS_SIGNED_DATA};

#[derive(Debug, Clone)]
pub struct PeDigestConsistencyResult {
    pub recomputed_digest_hex: String,
    pub matched_attribute_certificate_index: usize,
    pub pkcs7_authenticode_entries: usize,
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Ensure every PKCS#7 Authenticode attribute certificate's indirect digest matches the Rust PE image digest
/// for the inferred hash algorithm (from embedded digest length).
pub fn verify_pe_authenticode_digest_consistency(
    bytes: &[u8],
) -> Result<PeDigestConsistencyResult> {
    let parsed = ParsedPe::parse(bytes)?;
    let pe = parsed.as_pe_trait();
    let Some(iter) = AttributeCertificateIterator::new(pe)
        .map_err(|e| anyhow!("certificate table invalid: {e}"))?
    else {
        return Err(anyhow!("PE has no certificate table"));
    };

    let mut pkcs7_count = 0usize;
    let mut last_hex = String::new();
    let mut last_idx = 0usize;

    for (idx, entry) in iter.enumerate() {
        let attr = entry.map_err(|e| anyhow!("attribute certificate entry invalid: {e}"))?;
        if attr.certificate_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA {
            continue;
        }
        let sig = attr
            .get_authenticode_signature()
            .map_err(|e| anyhow!("PKCS#7 Authenticode parse failed: {e}"))?;
        pkcs7_count += 1;
        let embedded = sig.digest();
        let kind = PeAuthenticodeHashKind::from_digest_byte_len(embedded.len())?;
        let computed = pe_authenticode_digest(bytes, kind)?;
        if computed.as_slice() != embedded {
            return Err(anyhow!(
                "Rust SIP digest mismatch for PKCS#7 entry {idx}: recomputed {} vs embedded {}",
                hex_lower(&computed),
                hex_lower(embedded)
            ));
        }
        last_hex = hex_lower(&computed);
        last_idx = idx;
    }

    if pkcs7_count == 0 {
        return Err(anyhow!(
            "no PKCS#7 Authenticode entries found in certificate table"
        ));
    }

    Ok(PeDigestConsistencyResult {
        recomputed_digest_hex: last_hex,
        matched_attribute_certificate_index: last_idx,
        pkcs7_authenticode_entries: pkcs7_count,
    })
}

/// Invoke `f(index, pkcs7_der)` for each `WIN_CERT_TYPE_PKCS_SIGNED_DATA` attribute certificate.
///
/// Returns how many PKCS#7 blobs were visited. Fails if the PE has no certificate table or no PKCS#7 entries.
pub fn for_each_pe_pkcs7_signed_data(
    bytes: &[u8],
    mut f: impl FnMut(usize, &[u8]) -> Result<()>,
) -> Result<usize> {
    let parsed = ParsedPe::parse(bytes)?;
    let pe = parsed.as_pe_trait();
    let Some(iter) = AttributeCertificateIterator::new(pe)
        .map_err(|e| anyhow!("certificate table invalid: {e}"))?
    else {
        return Err(anyhow!("PE has no certificate table"));
    };

    let mut pkcs7_count = 0usize;
    for (idx, entry) in iter.enumerate() {
        let attr = entry.map_err(|e| anyhow!("attribute certificate entry invalid: {e}"))?;
        if attr.certificate_type != WIN_CERT_TYPE_PKCS_SIGNED_DATA {
            continue;
        }
        f(idx, attr.data)?;
        pkcs7_count += 1;
    }

    if pkcs7_count == 0 {
        return Err(anyhow!(
            "no PKCS#7 Authenticode entries found in certificate table"
        ));
    }

    Ok(pkcs7_count)
}
