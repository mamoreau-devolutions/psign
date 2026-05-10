//! PKCS#7 `SignedData` production for a standalone Rust signer (Tier 1a completion).
//!
//! Today, signing remains OS-delegated (`SignerSignEx3` / `mssign32` in `signtool-rs`). A future path may use
//! Windows `CryptMsgOpenToEncode` or the `cms` crate to assemble `SPC_INDIRECT_DATA` and embed `WIN_CERTIFICATE` entries.
//!
//! Format-specific **subject digests** feeding `SpcIndirectData` live elsewhere: [`crate::pe_digest`] (PE image hash),
//! [`crate::cab_digest`] (MSCF CAB layout), [`crate::msi_digest`] (OLE compound), [`crate::msix_digest`] (APPX AX\* blob under OID **`1.3.6.1.4.1.311.2.1.30`**), etc. Encoding those payloads into PKCS#7 is the missing producer piece; [`crate::pe_embed`] can append **`WIN_CERTIFICATE`** rows once PKCS#7 DER exists.
//!
//! **Milestone:** The **`authenticode`** crate publishes ASN.1 structs (`SpcIndirectDataContent`, `DigestInfo`, …) with `der` **Decode**/**Encode**.
//! [`parse_pe_pkcs7_spc_indirect_data_at`] / [`parse_pe_pkcs7_spc_indirect_data`] and [`spc_indirect_data_replace_message_digest`] support **Linux-side digest substitution** before a future **`SignedData`** signer assembles countersignatures / PKCS#9 attributes. **`WIN_CERTIFICATE`** embedding remains [`crate::pe_embed`].

use anyhow::{Result, anyhow};
use authenticode::{DigestInfo, SpcIndirectDataContent};
use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use der::asn1::{Any, ObjectIdentifier, OctetString};
use der::{Decode, Encode, Reader, SliceReader};

/// CMS **`signedData`** content type OID (`id-signedData`).
const ID_SIGNED_DATA_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

/// CMS **`data`** content type OID (`id-data`).
pub const PKCS7_ID_DATA_OID: &str = "1.2.840.113549.1.7.1";

/// CMS **`signedData`** content type OID (string form).
pub const PKCS7_ID_SIGNED_DATA_OID: &str = "1.2.840.113549.1.7.2";

/// Encode **`SignedData`** as a PKCS#7 **`ContentInfo`** (**`contentType`** = **`id-signedData`**, RFC 5652).
///
/// This is a **building block** for portable Authenticode: mutating **`SignedData`** (e.g. new **`SignerInfo`**
/// with remote signature octets) then calling this function yields DER for **`pe_embed`**. Re-encoding an
/// unmodified structure is tested for **decode → encode → decode** stability on fixtures; **byte-for-byte**
/// equality with a given **`signtool.exe`** / **`CryptMsgOpenToEncode`** output is **not** guaranteed.
pub fn encode_pkcs7_content_info_signed_data_der(sd: &SignedData) -> Result<Vec<u8>> {
    let sd_der = sd
        .to_der()
        .map_err(|e| anyhow!("encode SignedData: {e}"))?;
    let mut rd = SliceReader::new(sd_der.as_slice()).map_err(|e| anyhow!("SignedData DER reader: {e}"))?;
    let content = Any::decode(&mut rd).map_err(|e| anyhow!("SignedData as CMS Any: {e}"))?;
    let ci = ContentInfo {
        content_type: ID_SIGNED_DATA_OID,
        content,
    };
    ci.to_der()
        .map_err(|e| anyhow!("encode ContentInfo: {e}"))
}

/// Decode **`SignedData`** from PKCS#7 DER (**outer `ContentInfo`** with **`contentType`** **`id-signedData`**).
///
/// Accepts the same blob layout as embedded PE **`WIN_CERT_TYPE_PKCS_SIGNED_DATA`** rows (after optional
/// [`crate::pkcs7_wire::normalize_pkcs7_der_for_authenticode`] trimming).
pub fn parse_pkcs7_signed_data_der(pkcs7_der: &[u8]) -> Result<SignedData> {
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

/// Decode **`SpcIndirectDataContent`** from the **`pkcs7_index`**-th embedded **`WIN_CERT_TYPE_PKCS_SIGNED_DATA`** PKCS#7 (**`0`** = first), certificate-table order.
///
/// Fails if there is no certificate table, no PKCS#7 row at **`pkcs7_index`**, or CMS parsing does not yield encapsulated Authenticode content.
pub fn parse_pe_pkcs7_spc_indirect_data_at(
    pe_image: &[u8],
    pkcs7_index: usize,
) -> Result<SpcIndirectDataContent> {
    let pkcs7 = crate::verify_pe::pe_nth_pkcs7_signed_data_der(pe_image, pkcs7_index)?;
    let sd = parse_pkcs7_signed_data_der(&pkcs7)?;
    let encap_any = sd
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or_else(|| anyhow!("SignedData missing encapsulated content"))?;
    encap_any
        .decode_as::<SpcIndirectDataContent>()
        .map_err(|e| anyhow!("SpcIndirectDataContent: {e}"))
}

/// Decode **`SpcIndirectDataContent`** from the **first** embedded PKCS#7 (same as **`pkcs7_index`** **`0`**).
///
/// See [`parse_pe_pkcs7_spc_indirect_data_at`] for multi-signed PEs.
pub fn parse_pe_pkcs7_spc_indirect_data(pe_image: &[u8]) -> Result<SpcIndirectDataContent> {
    parse_pe_pkcs7_spc_indirect_data_at(pe_image, 0)
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

/// Replace **`SignedData.encapContentInfo.eContent`** with **`indirect`** while keeping **`digestAlgorithms`**, **`certificates`**, **`crls`**, and **`signerInfos`** unchanged.
///
/// **`template`** must already use **`eContentType`** **`authenticode::SPC_INDIRECT_DATA_OBJID`** (Authenticode **`SpcIndirectDataContent`**).
///
/// **Cryptographic note:** Swapping the indirect payload **invalidates** the existing **`SignerInfo`** signature (PKCS#9 **`messageDigest`** / **`contentType`** attrs no longer match **`encryptedDigest`**). Use for **tests**, **`verify-pe`** negative cases, or pipelines that also rebuild **`SignerInfo`** and signature octets (remote signing).
pub fn signed_data_replace_encapsulated_spc_indirect(
    template: &SignedData,
    indirect: &SpcIndirectDataContent,
) -> Result<SignedData> {
    if template.encap_content_info.econtent_type != authenticode::SPC_INDIRECT_DATA_OBJID {
        return Err(anyhow!(
            "SignedData encap content type is not SPC_INDIRECT_DATA (got {})",
            template.encap_content_info.econtent_type
        ));
    }
    let der = encode_spc_indirect_data_der(indirect)?;
    let mut rd =
        SliceReader::new(der.as_slice()).map_err(|e| anyhow!("indirect DER reader: {e}"))?;
    let econtent = Any::decode(&mut rd).map_err(|e| anyhow!("SpcIndirectData as CMS Any: {e}"))?;
    rd.finish(())
        .map_err(|e| anyhow!("trailing octets after SpcIndirectDataContent DER: {e}"))?;
    let mut out = template.clone();
    out.encap_content_info.econtent = Some(econtent);
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
    fn parse_pe_pkcs7_spc_indirect_at_index_zero_matches_helper() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let a = parse_pe_pkcs7_spc_indirect_data(pe_bytes).expect("parse");
        let b = parse_pe_pkcs7_spc_indirect_data_at(pe_bytes, 0).expect("parse at 0");
        assert_eq!(a, b);
    }

    #[test]
    fn parse_pe_pkcs7_spc_indirect_at_index_one_errors_on_single_signed_fixture() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        assert!(parse_pe_pkcs7_spc_indirect_data_at(pe_bytes, 1).is_err());
    }

    #[test]
    fn signed_data_to_der_round_trips() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let pkcs7 = crate::verify_pe::pe_nth_pkcs7_signed_data_der(pe_bytes, 0).expect("pkcs7");
        let sd = parse_pkcs7_signed_data_der(&pkcs7).expect("SignedData");
        let der = sd.to_der().expect("to_der");
        let again = SignedData::from_der(der.as_slice()).expect("from_der");
        assert_eq!(sd, again);
    }

    #[test]
    fn content_info_encode_decode_round_trip_on_tiny32_pkcs7() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let pkcs7 = crate::verify_pe::pe_nth_pkcs7_signed_data_der(pe_bytes, 0).expect("pkcs7");
        let normalized = crate::pkcs7_wire::normalize_pkcs7_der_for_authenticode(&pkcs7);
        let bytes = normalized.as_ref();
        let mut r = SliceReader::new(bytes).expect("reader");
        let ci = ContentInfo::decode(&mut r).expect("ContentInfo");
        let sd = ci
            .content
            .decode_as::<SignedData>()
            .expect("inner SignedData");
        let out = encode_pkcs7_content_info_signed_data_der(&sd).expect("encode");
        let mut r2 = SliceReader::new(out.as_slice()).expect("reader2");
        let ci2 = ContentInfo::decode(&mut r2).expect("ContentInfo2");
        let sd2 = ci2
            .content
            .decode_as::<SignedData>()
            .expect("SignedData2");
        assert_eq!(sd, sd2);
    }

    #[test]
    fn signed_data_replace_encap_round_trips_identical_indirect_through_pkcs7() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let pkcs7 = crate::verify_pe::pe_nth_pkcs7_signed_data_der(pe_bytes, 0).expect("pkcs7");
        let sd = parse_pkcs7_signed_data_der(&pkcs7).expect("SignedData");
        let indirect = parse_pe_pkcs7_spc_indirect_data(pe_bytes).expect("indirect");
        let sd2 =
            signed_data_replace_encapsulated_spc_indirect(&sd, &indirect).expect("replace encap");
        assert_eq!(sd, sd2);
        let out = encode_pkcs7_content_info_signed_data_der(&sd2).expect("encode outer");
        let sd3 = parse_pkcs7_signed_data_der(&out).expect("re-parse");
        assert_eq!(sd, sd3);
    }

    #[test]
    fn signed_data_replace_encap_preserves_flipped_digest_through_pkcs7_reencode() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let pkcs7 = crate::verify_pe::pe_nth_pkcs7_signed_data_der(pe_bytes, 0).expect("pkcs7");
        let sd = parse_pkcs7_signed_data_der(&pkcs7).expect("SignedData");
        let indirect = parse_pe_pkcs7_spc_indirect_data(pe_bytes).expect("indirect");
        let mut flipped_digest = indirect.message_digest.digest.as_bytes().to_vec();
        flipped_digest[0] ^= 0xff;
        let flipped =
            spc_indirect_data_replace_message_digest(&indirect, &flipped_digest).expect("flip");
        let sd_m =
            signed_data_replace_encapsulated_spc_indirect(&sd, &flipped).expect("mut encap");
        let pkcs7_out = encode_pkcs7_content_info_signed_data_der(&sd_m).expect("encode");
        let sd_r = parse_pkcs7_signed_data_der(&pkcs7_out).expect("parse mutated");
        let encap = sd_r
            .encap_content_info
            .econtent
            .as_ref()
            .expect("econtent");
        let got = encap
            .decode_as::<SpcIndirectDataContent>()
            .expect("indirect decode");
        assert_eq!(got, flipped);
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
