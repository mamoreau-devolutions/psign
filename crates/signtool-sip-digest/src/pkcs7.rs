//! PKCS#7 `SignedData` production for a standalone Rust signer (Tier 1a completion).
//!
//! Today, signing remains OS-delegated (`SignerSignEx3` / `mssign32` in `signtool-rs`). A future path may use
//! Windows `CryptMsgOpenToEncode` or the `cms` crate to assemble `SPC_INDIRECT_DATA` and embed `WIN_CERTIFICATE` entries.
//!
//! Format-specific **subject digests** feeding `SpcIndirectData` live elsewhere: [`crate::pe_digest`] (PE image hash),
//! [`crate::cab_digest`] (MSCF CAB layout), [`crate::msi_digest`] (OLE compound), [`crate::msix_digest`] (APPX AX\* blob under OID **`1.3.6.1.4.1.311.2.1.30`**), etc. Encoding those payloads into PKCS#7 is the missing producer piece.
//!
//! **Milestone:** The **`authenticode`** crate publishes ASN.1 structs (`SpcIndirectDataContent`, `DigestInfo`, …) with `der` **Decode**/**Encode**.
//! [`parse_pe_pkcs7_spc_indirect_data`] and [`spc_indirect_data_replace_message_digest`] support **Linux-side digest substitution** before a future **`SignedData`** signer assembles countersignatures / PKCS#9 attributes. **`WIN_CERTIFICATE`** embedding remains [`crate::pe_embed`].

use anyhow::{Result, anyhow};
use authenticode::{DigestInfo, SpcIndirectDataContent};
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::asn1::{ObjectIdentifier, OctetString};
use der::{Decode, Encode, SliceReader};

/// CMS **`signedData`** content type OID (`id-signedData`).
const ID_SIGNED_DATA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

/// CMS **`data`** content type OID (`id-data`).
pub const PKCS7_ID_DATA_OID: &str = "1.2.840.113549.1.7.1";

/// CMS **`signedData`** content type OID (string form).
pub const PKCS7_ID_SIGNED_DATA_OID: &str = "1.2.840.113549.1.7.2";

fn signed_data_from_pkcs7_der(pkcs7_der: &[u8]) -> Result<SignedData> {
    let normalized = crate::pkcs7_wire::normalize_pkcs7_der_for_authenticode(pkcs7_der);
    let bytes = normalized.as_ref();
    let mut r = SliceReader::new(bytes).map_err(|_| anyhow!("empty PKCS#7"))?;
    let ci = ContentInfo::decode(&mut r).map_err(|e| anyhow!("PKCS#7 ContentInfo decode: {e}"))?;
    if ci.content_type != ID_SIGNED_DATA_OID {
        return Err(anyhow!(
            "PKCS#7 root content type is not SignedData (got {})",
            ci.content_type
        ));
    }
    ci.content
        .decode_as::<SignedData>()
        .map_err(|e| anyhow!("SignedData: {e}"))
}

/// Decode **`SpcIndirectDataContent`** from the first embedded **`WIN_CERT_TYPE_PKCS_SIGNED_DATA`** PKCS#7 on **`pe_image`**.
///
/// Fails if there is no certificate table, no PKCS#7 entry, or CMS parsing does not yield encapsulated Authenticode content.
pub fn parse_pe_pkcs7_spc_indirect_data(pe_image: &[u8]) -> Result<SpcIndirectDataContent> {
    let pkcs7 = crate::verify_pe::pe_first_pkcs7_signed_data_der(pe_image)?;
    let sd = signed_data_from_pkcs7_der(&pkcs7)?;
    let encap_any = sd
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| anyhow!("SignedData missing encapsulated content"))?;
    encap_any
        .decode_as::<SpcIndirectDataContent>()
        .map_err(|e| anyhow!("SpcIndirectDataContent: {e}"))
}

/// Clone **`template.data`** (including **`SpcPeImageData`** bits) and replace **`messageDigest.digest`** with **`new_digest`**.
///
/// **`digest_algorithm`** is copied from the template; **`new_digest`** must match the template digest **octet length**
/// (Authenticode PE uses 20 / 32 / 48 / 64 bytes for SHA-1 / SHA-256 / SHA-384 / SHA-512).
pub fn spc_indirect_data_replace_message_digest(
    template: &SpcIndirectDataContent,
    new_digest: &[u8],
) -> Result<SpcIndirectDataContent> {
    let old_len = template.message_digest.digest.as_bytes().len();
    if new_digest.len() != old_len {
        return Err(anyhow!(
            "digest length {} does not match template Authenticode digest field ({old_len} octets)",
            new_digest.len(),
        ));
    }
    let digest =
        OctetString::new(new_digest.to_vec()).map_err(|e| anyhow!("digest OCTET STRING: {e}"))?;
    Ok(SpcIndirectDataContent {
        data: template.data.clone(),
        message_digest: DigestInfo {
            digest_algorithm: template.message_digest.digest_algorithm.clone(),
            digest,
        },
    })
}

/// DER-encode **`SpcIndirectDataContent`** (what CMS **`eContent`** carries for **`SPC_INDIRECT_DATA_OBJID`**).
pub fn encode_spc_indirect_data_der(indirect: &SpcIndirectDataContent) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    indirect
        .encode_to_vec(&mut out)
        .map_err(|e| anyhow!("encode SpcIndirectDataContent: {e}"))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use authenticode::SpcIndirectDataContent;
    use der::Decode;

    #[test]
    fn signed_data_oid_matches_rfc_display_form() {
        assert!(PKCS7_ID_SIGNED_DATA_OID.ends_with(".7.2"));
        assert!(PKCS7_ID_DATA_OID.ends_with(".7.1"));
    }

    fn assert_spc_round_trip_and_digest_matches_sip(pe_bytes: &[u8]) {
        let indirect = parse_pe_pkcs7_spc_indirect_data(pe_bytes).expect("parse indirect");

        let re_encoded = encode_spc_indirect_data_der(&indirect).expect("encode");
        let again = SpcIndirectDataContent::from_der(re_encoded.as_slice()).expect("re-decode");
        assert_eq!(indirect, again);

        let digest = crate::pe_digest::pe_authenticode_digest(
            pe_bytes,
            crate::pe_digest::PeAuthenticodeHashKind::Sha256,
        )
        .expect("PE digest");
        assert_eq!(
            indirect.message_digest.digest.as_bytes(),
            digest.as_slice(),
            "embedded DigestInfo must match Rust SIP PE digest"
        );
    }

    #[test]
    fn spc_indirect_data_der_round_trips_from_upstream_tiny32_signed_efi() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        assert_spc_round_trip_and_digest_matches_sip(pe_bytes);
    }

    #[test]
    fn spc_indirect_data_der_round_trips_from_upstream_tiny64_signed_efi() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny64.signed.efi");
        assert_spc_round_trip_and_digest_matches_sip(pe_bytes);
    }

    #[test]
    fn replace_message_digest_preserves_pe_image_blob_and_round_trips() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let indirect = parse_pe_pkcs7_spc_indirect_data(pe_bytes).expect("parse");
        let digest = crate::pe_digest::pe_authenticode_digest(
            pe_bytes,
            crate::pe_digest::PeAuthenticodeHashKind::Sha256,
        )
        .expect("sip digest");

        let replaced = spc_indirect_data_replace_message_digest(&indirect, digest.as_slice())
            .expect("replace");
        assert_eq!(replaced, indirect);

        let wrong_len = vec![0u8; 31];
        assert!(spc_indirect_data_replace_message_digest(&indirect, &wrong_len).is_err());

        let mut flipped = digest.clone();
        flipped[0] ^= 0xff;
        let patched = spc_indirect_data_replace_message_digest(&indirect, &flipped).expect("patch");
        assert_ne!(patched, indirect);
        assert_eq!(patched.message_digest.digest.as_bytes(), flipped.as_slice());
        assert_eq!(patched.data, indirect.data);
        encode_spc_indirect_data_der(&patched).expect("encode patched");
    }
}
