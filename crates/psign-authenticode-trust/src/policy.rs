//! Trust policy knobs (Authenticode EKU strictness).

#[derive(Debug, Clone, Copy)]
pub struct AuthenticodeTrustPolicy {
    /// When true (default), picky enforces Authenticode **code signing** EKU rules on the signer.
    pub strict_code_signing_eku: bool,
    /// Prefer RFC3161 / Authenticode nested timestamp signing time for **`exact_date`** when present.
    pub prefer_timestamp_signing_time: bool,
    /// When **`prefer_timestamp_signing_time`** is set, fail if no usable timestamp token is found.
    pub require_valid_timestamp: bool,
}

impl Default for AuthenticodeTrustPolicy {
    fn default() -> Self {
        Self {
            strict_code_signing_eku: true,
            prefer_timestamp_signing_time: false,
            require_valid_timestamp: false,
        }
    }
}
