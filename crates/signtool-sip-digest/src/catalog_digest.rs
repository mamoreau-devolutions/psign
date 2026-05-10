//! Windows `.cat` catalog files are a single PKCS#7 `SignedData` blob whose encapsulated content
//! type is usually Microsoft CTL (`1.3.6.1.4.1.311.10.1`), not `SPC_INDIRECT_DATA`, so
//! [`authenticode::AuthenticodeSignature`] does not apply.
//!
//! CMS signing uses the PKCS#9 **`messageDigest`** authenticated attribute; per PKCS#9/CMS practice
//! it matches the digest algorithm in `SignedData` applied to the **payload octets of
//! `EncapsulatedContentInfo.eContent`** (see RFC 5652). We locate the digest inside Microsoft’s
//! wrapped attribute values by scanning for a DER **`OCTET STRING`** whose contents equal that hash.

use super::pe_digest::PeAuthenticodeHashKind;
use anyhow::{Result, anyhow};
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::asn1::ObjectIdentifier;
use der::{Decode, SliceReader};
use digest::Digest;
use std::path::Path;

const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const ID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");

const OID_SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");

fn digest_kind_from_digest_alg_oid(oid: ObjectIdentifier) -> Result<PeAuthenticodeHashKind> {
    if oid == OID_SHA1 {
        Ok(PeAuthenticodeHashKind::Sha1)
    } else if oid == OID_SHA256 {
        Ok(PeAuthenticodeHashKind::Sha256)
    } else if oid == OID_SHA384 {
        Ok(PeAuthenticodeHashKind::Sha384)
    } else if oid == OID_SHA512 {
        Ok(PeAuthenticodeHashKind::Sha512)
    } else {
        Err(anyhow!(
            "unsupported digest algorithm OID {} in catalog SignedData",
            oid
        ))
    }
}

fn hash_econtent(kind: PeAuthenticodeHashKind, econtent: &[u8]) -> Vec<u8> {
    match kind {
        PeAuthenticodeHashKind::Sha1 => sha1::Sha1::digest(econtent).to_vec(),
        PeAuthenticodeHashKind::Sha256 => sha2::Sha256::digest(econtent).to_vec(),
        PeAuthenticodeHashKind::Sha384 => sha2::Sha384::digest(econtent).to_vec(),
        PeAuthenticodeHashKind::Sha512 => sha2::Sha512::digest(econtent).to_vec(),
    }
}

/// Return true if `blob` contains a DER-encoded OCTET STRING (tag `0x04`) whose value equals `expected`.
fn blob_contains_octet_string_digest(blob: &[u8], expected: &[u8]) -> bool {
    let len = expected.len();
    let mut i = 0usize;
    while i + 2 + len <= blob.len() {
        if blob[i] == 0x04 {
            let lb = blob[i + 1];
            if lb as usize == len && blob[i + 2..i + 2 + len] == *expected {
                return true;
            }
            // Two-byte length form 0x81 <len> for digest sizes ≤255 (e.g. SHA-384/512).
            if lb == 0x81
                && let Some(l2) = blob.get(i + 2).copied()
                && l2 as usize == len
                && blob.get(i + 3..i + 3 + len) == Some(expected)
            {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn pkcs9_message_digest_matches(
    attrs: &cms::signed_data::SignedAttributes,
    computed: &[u8],
) -> Result<()> {
    for attr in attrs.iter() {
        if attr.oid != ID_MESSAGE_DIGEST {
            continue;
        }
        for val in attr.values.iter() {
            let payload = val.value();
            if blob_contains_octet_string_digest(payload, computed) {
                return Ok(());
            }
        }
        return Err(anyhow!(
            "PKCS#9 messageDigest signed attribute present but no OCTET STRING matched eContent hash"
        ));
    }
    Err(anyhow!(
        "catalog SignerInfo is missing PKCS#9 messageDigest authenticated attribute"
    ))
}

/// Verify each `SignerInfo`'s PKCS#9 `messageDigest` matches the CMS digest over encapsulated `eContent`.
pub fn verify_catalog_digest_consistency_bytes(data: &[u8]) -> Result<()> {
    let mut r = SliceReader::new(data).map_err(|_| anyhow!("empty catalog file"))?;
    let ci = ContentInfo::decode(&mut r).map_err(|e| anyhow!("catalog PKCS#7 ContentInfo: {e}"))?;
    if ci.content_type != ID_SIGNED_DATA {
        return Err(anyhow!(
            "catalog root content type is not SignedData (got {})",
            ci.content_type
        ));
    }
    let sd: SignedData = ci
        .content
        .decode_as()
        .map_err(|e| anyhow!("catalog SignedData: {e}"))?;

    if sd.digest_algorithms.len() != 1 {
        return Err(anyhow!(
            "expected one digest algorithm in SignedData, got {}",
            sd.digest_algorithms.len()
        ));
    }
    let ref_alg = sd.digest_algorithms.as_slice()[0].clone();

    let econtent = sd
        .encap_content_info
        .econtent
        .as_ref()
        .map(|a| a.value())
        .unwrap_or_default();

    let n_signers = sd.signer_infos.0.len();
    if n_signers == 0 {
        return Err(anyhow!("catalog SignedData has no SignerInfo"));
    }

    for si in sd.signer_infos.0.iter() {
        if si.digest_alg != ref_alg {
            return Err(anyhow!(
                "SignerInfo digestAlgorithm does not match SignedData.digestAlgorithms"
            ));
        }
        let kind = digest_kind_from_digest_alg_oid(si.digest_alg.oid)?;
        let computed = hash_econtent(kind, econtent);
        let attrs = si
            .signed_attrs
            .as_ref()
            .ok_or_else(|| anyhow!("catalog SignerInfo missing authenticated attributes"))?;
        pkcs9_message_digest_matches(attrs, &computed)?;
    }

    Ok(())
}

/// PKCS#7 CTL catalog file: CMS `eContent` digest vs PKCS#9 `messageDigest` (all signers).
pub fn verify_catalog_digest_consistency(path: &Path) -> Result<()> {
    let data = std::fs::read(path)?;
    verify_catalog_digest_consistency_bytes(&data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn octet_string_scan_finds_sha256() {
        let digest = [7u8; 32];
        let mut blob = vec![0x6c, 0x40, 0x30, 0x04, 0x20];
        blob.extend_from_slice(&digest);
        blob.push(0xff);
        assert!(blob_contains_octet_string_digest(&blob, &digest));
    }

    #[test]
    fn octet_string_scan_long_len_form_sha384() {
        let digest = [9u8; 48];
        let mut blob = vec![0x04, 0x81, 48];
        blob.extend_from_slice(&digest);
        assert!(blob_contains_octet_string_digest(&blob, &digest));
    }
}
