//! Best-effort RFC3161 / Authenticode nested timestamp extraction for verification instant selection.
//!
//! Extracts **`genTime`** from CMS **`id-ct-TSTInfo`** timestamp tokens (typically carried in
//! **`SignerInfo` unsigned attributes**) and falls back to PKCS#9 **`signing-time`** in signed
//! attributes. **Does not** cryptographically verify the timestamp (TSA chain, **`MessageImprint`**).

use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerInfo};
use der::asn1::{GeneralizedTime, ObjectIdentifier, OctetStringRef};
use der::{Decode, Header, Reader, SliceReader, Tag};
use picky::x509::date::UtcDate;
use x509_cert::attr::Attribute;
use x509_cert::time::Time;

const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
/// **`id-ct-TSTInfo`** (RFC 3161).
const ID_CT_TSTINFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
/// PKCS#9 **`signing-time`**.
const ID_SIGNING_TIME: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
/// **`id-aa-timeStampToken`** (RFC 5035 / CMS).
const ID_AA_TIME_STAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.14");
/// Microsoft nested Authenticode timestamp attribute (common on PE).
const OID_MS_TIMESTAMP_TOKEN: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.311.3.3.1");

/// Returns signing time from an embedded timestamp token and/or PKCS#9 **`signing-time`** when
/// parsing succeeds.
///
/// **Precedence:** nested RFC3161 **`TSTInfo.genTime`** from unsigned attributes on any signer, then
/// PKCS#9 **`signing-time`** from the **first** signer that carries it.
///
/// On failure returns **`None`**; callers fall back to wall-clock **`UtcDate::now()`** unless
/// [`crate::policy::AuthenticodeTrustPolicy::require_valid_timestamp`] forces an error.
pub fn utc_date_from_authenticode_timestamp_token(pkcs7_der: &[u8]) -> Option<UtcDate> {
    let sd = signed_data_from_pkcs7(pkcs7_der)?;
    let mut signing_time_fallback = None;

    for si in sd.signer_infos.0.iter() {
        if let Some(d) = utc_date_from_signer_unsigned_attrs(si) {
            return Some(d);
        }
        if signing_time_fallback.is_none() {
            signing_time_fallback = utc_date_from_signer_signed_attrs(si);
        }
    }
    signing_time_fallback
}

fn signed_data_from_pkcs7(pkcs7_der: &[u8]) -> Option<SignedData> {
    let mut r = SliceReader::new(pkcs7_der).ok()?;
    let ci = ContentInfo::decode(&mut r).ok()?;
    if ci.content_type != ID_SIGNED_DATA {
        return None;
    }
    ci.content.decode_as::<SignedData>().ok()
}

fn utc_date_from_signer_unsigned_attrs(si: &SignerInfo) -> Option<UtcDate> {
    let attrs = si.unsigned_attrs.as_ref()?;
    for attr in attrs.iter() {
        if timestamp_attr_priority(attr).is_none() {
            continue;
        }
        if let Some(d) = utc_date_from_timestamp_attribute(attr) {
            return Some(d);
        }
    }
    for attr in attrs.iter() {
        if timestamp_attr_priority(attr).is_some() {
            continue;
        }
        if let Some(d) = utc_date_from_timestamp_attribute(attr) {
            return Some(d);
        }
    }
    None
}

/// Lower sorts first: known timestamp OIDs before probing arbitrary attributes.
fn timestamp_attr_priority(attr: &Attribute) -> Option<u8> {
    if attr.oid == ID_AA_TIME_STAMP_TOKEN {
        return Some(0);
    }
    if attr.oid == OID_MS_TIMESTAMP_TOKEN {
        return Some(1);
    }
    None
}

fn utc_date_from_timestamp_attribute(attr: &Attribute) -> Option<UtcDate> {
    for val in attr.values.iter() {
        let payload = attribute_value_bytes(val);
        if let Some(d) = utc_date_from_unsigned_attr_payload(payload) {
            return Some(d);
        }
    }
    None
}

fn attribute_value_bytes(val: &der::asn1::Any) -> &[u8] {
    val.value()
}

fn utc_date_from_unsigned_attr_payload(payload: &[u8]) -> Option<UtcDate> {
    try_extract_from_nested_pkcs7(payload)
}

fn try_extract_from_nested_pkcs7(bytes: &[u8]) -> Option<UtcDate> {
    let ci = decode_content_info_loose(bytes)?;
    extract_gentime_from_timestamp_content_info(&ci)
}

fn decode_content_info_loose(bytes: &[u8]) -> Option<ContentInfo> {
    let mut r = SliceReader::new(bytes).ok()?;
    if let Ok(ci) = ContentInfo::decode(&mut r) {
        return Some(ci);
    }
    let inner = peel_octet_string_outer(bytes)?;
    let mut r2 = SliceReader::new(inner).ok()?;
    ContentInfo::decode(&mut r2).ok()
}

fn peel_octet_string_outer(bytes: &[u8]) -> Option<&[u8]> {
    let mut r = SliceReader::new(bytes).ok()?;
    let o = OctetStringRef::decode(&mut r).ok()?;
    Some(o.as_bytes())
}

fn extract_gentime_from_timestamp_content_info(ci: &ContentInfo) -> Option<UtcDate> {
    if ci.content_type != ID_SIGNED_DATA {
        return None;
    }
    let sd: SignedData = ci.content.decode_as().ok()?;
    gentime_from_signed_data_timestamp(&sd)
}

fn gentime_from_signed_data_timestamp(sd: &SignedData) -> Option<UtcDate> {
    let encap = &sd.encap_content_info;
    if encap.econtent_type != ID_CT_TSTINFO {
        return None;
    }
    let any = encap.econtent.as_ref()?;
    let tst = tstinfo_bytes_from_encapsulated_econtent(any)?;
    tstinfo_gen_time(tst)
}

fn tstinfo_bytes_from_encapsulated_econtent(any: &der::asn1::Any) -> Option<&[u8]> {
    peel_to_tstinfo_sequence(any.value())
}

fn peel_to_tstinfo_sequence(mut sl: &[u8]) -> Option<&[u8]> {
    for _ in 0..8 {
        if sl.is_empty() {
            return None;
        }
        match sl.first().copied()? {
            0x30 => return Some(sl),
            0x04 => sl = peel_octet_string_outer(sl)?,
            tag if tag == 0xa0 || tag == 0xa1 => {
                let mut r = SliceReader::new(sl).ok()?;
                let h = Header::decode(&mut r).ok()?;
                if !h.tag.is_constructed() {
                    return None;
                }
                sl = r.read_slice(h.length).ok()?;
            }
            _ => return None,
        }
    }
    None
}

fn tstinfo_gen_time(tstinfo_der: &[u8]) -> Option<UtcDate> {
    let mut r = SliceReader::new(tstinfo_der).ok()?;
    let hdr = Header::decode(&mut r).ok()?;
    if hdr.tag != Tag::Sequence {
        return None;
    }
    let inner = r.read_slice(hdr.length).ok()?;
    let mut sr = SliceReader::new(inner).ok()?;
    der_skip_tlv(&mut sr)?;
    der_skip_tlv(&mut sr)?;
    der_skip_tlv(&mut sr)?;
    der_skip_tlv(&mut sr)?;
    let gt = GeneralizedTime::decode(&mut sr).ok()?;
    utc_date_from_der_generalized_time(gt)
}

fn utc_date_from_der_generalized_time(gt: GeneralizedTime) -> Option<UtcDate> {
    let secs = i64::try_from(gt.to_unix_duration().as_secs()).ok()?;
    let odt = time::OffsetDateTime::from_unix_timestamp(secs).ok()?;
    Some(UtcDate::from(odt))
}

fn der_skip_tlv<'a, R: Reader<'a>>(reader: &mut R) -> Option<()> {
    let hdr = Header::decode(reader).ok()?;
    reader.read_slice(hdr.length).ok()?;
    Some(())
}

fn utc_date_from_signer_signed_attrs(si: &SignerInfo) -> Option<UtcDate> {
    let attrs = si.signed_attrs.as_ref()?;
    for attr in attrs.iter() {
        if attr.oid != ID_SIGNING_TIME {
            continue;
        }
        for val in attr.values.iter() {
            if let Some(d) = utc_date_from_signing_time_any(attribute_value_bytes(val)) {
                return Some(d);
            }
        }
    }
    None
}

fn utc_date_from_signing_time_any(bytes: &[u8]) -> Option<UtcDate> {
    let t = Time::decode(&mut SliceReader::new(bytes).ok()?).ok()?;
    let secs = i64::try_from(t.to_unix_duration().as_secs()).ok()?;
    let odt = time::OffsetDateTime::from_unix_timestamp(secs).ok()?;
    Some(UtcDate::from(odt))
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::DateTime;
    use der::Encode;
    use der::asn1::UtcTime;

    #[test]
    fn signing_time_utctime_roundtrip() {
        let dt = DateTime::new(2023, 6, 15, 12, 30, 45).unwrap();
        let ut = UtcTime::from_date_time(dt).unwrap();
        let der = ut.to_der().unwrap();
        let d = utc_date_from_signing_time_any(&der).unwrap();
        assert_eq!(d.year(), 2023);
        assert_eq!(d.month(), 6);
        assert_eq!(d.day(), 15);
    }

    #[test]
    fn signing_time_generalized_roundtrip() {
        let dt = DateTime::new(2023, 7, 1, 12, 0, 0).unwrap();
        let gt = GeneralizedTime::from_date_time(dt);
        let der = gt.to_der().unwrap();
        let d = utc_date_from_signing_time_any(&der).unwrap();
        assert_eq!(d.year(), 2023);
        assert_eq!(d.month(), 7);
        assert_eq!(d.day(), 1);
    }

    #[test]
    fn tstinfo_gen_time_skips_fixed_fields() {
        let buf: &[u8] = &[
            0x30, 0x58, 0x02, 0x01, 0x01, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x84, 0x59,
            0x0a, 0x04, 0x01, 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
            0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x02, 0x03,
            0x01, 0xe2, 0x40, 0x18, 0x0f, 0x32, 0x30, 0x32, 0x33, 0x30, 0x37, 0x30, 0x31, 0x31,
            0x32, 0x30, 0x30, 0x30, 0x30, 0x5a,
        ];
        let d = tstinfo_gen_time(buf).unwrap();
        assert_eq!(d.year(), 2023);
        assert_eq!(d.month(), 7);
        assert_eq!(d.day(), 1);
    }
}
