//! RFC3161 countersignature embedding for a Rust-produced PKCS#7 (Tier 1b).
//!
//! Parity should begin with presence + successful timestamp verification before DER equality.
//!
//! ## Current status
//!
//! Encoding a **`TimeStampReq`** / verifying a **`TimeStampToken`** against a production TSA is still outstanding.
//! Portable trust reads nested **`TSTInfo.genTime`** / PKCS#9 **`signing-time`** for **`exact_date`**
//! when **`--prefer-timestamp-signing-time`** is set; **TSA-side request encoding** (this module) is still a stub.

/// Placeholder for future **`TimeStampReq`** construction from an imprint preimage (RFC 3161 §3.2).
#[derive(Debug, Clone)]
pub struct Rfc3161TimestampRequestPlan {
    pub digest_alg_oid: &'static str,
}

impl Default for Rfc3161TimestampRequestPlan {
    fn default() -> Self {
        Self {
            digest_alg_oid: "2.16.840.1.101.3.4.2.1",
        }
    }
}

/// Reserved hook — returns **`None`** until ASN.1 encode + HTTP transport are implemented.
pub fn build_timestamp_request_bytes(
    _plan: &Rfc3161TimestampRequestPlan,
    _imprint_preimage: &[u8],
) -> Option<Vec<u8>> {
    None
}
