//! PKCS#7 `SignedData` production for a standalone Rust signer (Tier 1a completion).
//!
//! Today, signing remains OS-delegated (`SignerSignEx3` / `mssign32` in `signtool-rs`). A future path may use
//! Windows `CryptMsgOpenToEncode` or the `cms` crate to assemble `SPC_INDIRECT_DATA` and embed `WIN_CERTIFICATE` entries.
//!
//! Format-specific **subject digests** feeding `SpcIndirectData` live elsewhere: [`crate::pe_digest`] (PE image hash),
//! [`crate::cab_digest`] (MSCF CAB layout), [`crate::msi_digest`] (OLE compound), [`crate::msix_digest`] (APPX AX\* blob under OID **`1.3.6.1.4.1.311.2.1.30`**), etc. Encoding those payloads into PKCS#7 is the missing producer piece.
//!
//! **Milestone:** The **`authenticode`** crate publishes ASN.1 structs (`SpcIndirectDataContent`, `DigestInfo`, …) with `der` **Decode**/**Encode**.
//! Round-trip **DER stability** for the encapsulated Authenticode payload (decoded from CMS like [`AuthenticodeSignature`](authenticode::AuthenticodeSignature)) is regression-tested here—building **`SignerInfo`**, certificates, and **`WIN_CERTIFICATE`** glue remains future work (see [`crate::pe_embed`]).

/// CMS **`data`** content type OID (`id-data`).
pub const PKCS7_ID_DATA_OID: &str = "1.2.840.113549.1.7.1";

/// CMS **`signedData`** content type OID.
pub const PKCS7_ID_SIGNED_DATA_OID: &str = "1.2.840.113549.1.7.2";

#[cfg(test)]
mod tests {
    use super::*;
    use authenticode::{
        AttributeCertificateIterator, SpcIndirectDataContent, WIN_CERT_TYPE_PKCS_SIGNED_DATA,
    };
    use cms::content_info::ContentInfo;
    use cms::signed_data::SignedData;
    use der::asn1::ObjectIdentifier;
    use der::{Decode, Encode, SliceReader};

    const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");

    #[test]
    fn signed_data_oid_matches_rfc_display_form() {
        assert!(PKCS7_ID_SIGNED_DATA_OID.ends_with(".7.2"));
        assert!(PKCS7_ID_DATA_OID.ends_with(".7.1"));
    }

    fn signed_data_from_pkcs7_der(pkcs7_der: &[u8]) -> SignedData {
        let normalized = crate::pkcs7_wire::normalize_pkcs7_der_for_authenticode(pkcs7_der);
        let bytes = normalized.as_ref();
        let mut r = SliceReader::new(bytes).expect("pkcs7 reader");
        let ci = ContentInfo::decode(&mut r).expect("ContentInfo");
        assert_eq!(ci.content_type, ID_SIGNED_DATA);
        ci.content
            .decode_as::<SignedData>()
            .expect("SignedData decode")
    }

    fn first_pkcs7_from_pe(pe_bytes: &[u8]) -> Vec<u8> {
        let parsed = crate::pe_digest::ParsedPe::parse(pe_bytes).expect("PE parse");
        let pe = parsed.as_pe_trait();
        let Some(iter) = AttributeCertificateIterator::new(pe).expect("cert table parse") else {
            panic!("no certificate table");
        };
        for entry in iter {
            let attr = entry.expect("attr cert entry");
            if attr.certificate_type == WIN_CERT_TYPE_PKCS_SIGNED_DATA {
                return attr.data.to_vec();
            }
        }
        panic!("no PKCS#7 attr cert");
    }

    /// Encoded `SpcIndirectDataContent` must round-trip through `der` **Encode** so portable tooling can later
    /// rewrite **`DigestInfo`** (subject digest) while preserving **`SpcPeImageData`** (`data.value`) bits.
    #[test]
    fn spc_indirect_data_der_round_trips_from_upstream_tiny32_signed_efi() {
        let pe_bytes =
            include_bytes!("../../../tests/fixtures/pe-authenticode-upstream/tiny32.signed.efi");
        let pkcs7 = first_pkcs7_from_pe(pe_bytes);
        let sd = signed_data_from_pkcs7_der(&pkcs7);
        let encap_any = sd
            .encap_content_info
            .econtent
            .as_ref()
            .expect("missing encap econtent");
        let indirect = encap_any
            .decode_as::<SpcIndirectDataContent>()
            .expect("SpcIndirectDataContent CMS decode");

        let mut re_encoded = Vec::new();
        indirect
            .encode_to_vec(&mut re_encoded)
            .expect("encode SpcIndirectDataContent");

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
}
