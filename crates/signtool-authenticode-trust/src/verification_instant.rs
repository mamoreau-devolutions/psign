//! Resolve picky **`exact_date`** instant from policy (wall clock vs timestamp token).

use crate::policy::AuthenticodeTrustPolicy;
use crate::rfc3161_extract::utc_date_from_authenticode_timestamp_token;
use anyhow::{Result, anyhow};
use picky::x509::date::UtcDate;

/// Calendar date at UTC midnight for **`exact_date`** (fixtures / reproducible CI).
pub fn parse_verification_date_ymd(s: &str) -> Result<UtcDate> {
    let p: Vec<&str> = s.trim().split('-').collect();
    if p.len() != 3 {
        return Err(anyhow!("expected YYYY-MM-DD"));
    }
    let y: u16 = p[0].parse().map_err(|_| anyhow!("invalid year"))?;
    let m: u8 = p[1].parse().map_err(|_| anyhow!("invalid month"))?;
    let d: u8 = p[2].parse().map_err(|_| anyhow!("invalid day"))?;
    UtcDate::ymd(y, m, d).ok_or_else(|| anyhow!("invalid calendar date {y}-{m:02}-{d:02}"))
}

pub fn resolve_verification_utc_date(
    pkcs7_der: &[u8],
    policy: &AuthenticodeTrustPolicy,
) -> Result<UtcDate> {
    if !policy.prefer_timestamp_signing_time {
        return Ok(UtcDate::now());
    }
    match utc_date_from_authenticode_timestamp_token(pkcs7_der) {
        Some(d) => Ok(d),
        None if policy.require_valid_timestamp => Err(anyhow!(
            "timestamp required by policy but no usable RFC3161 / Authenticode timestamp token was found"
        )),
        None => Ok(UtcDate::now()),
    }
}

pub fn resolve_verification_instant_for_pkcs7(
    pkcs7_der: &[u8],
    policy: &AuthenticodeTrustPolicy,
    instant_override: Option<&UtcDate>,
) -> Result<UtcDate> {
    if let Some(d) = instant_override {
        return Ok(d.clone());
    }
    resolve_verification_utc_date(pkcs7_der, policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_verification_date_ymd_accepts_iso_day() {
        parse_verification_date_ymd("2023-07-01").unwrap();
        assert!(parse_verification_date_ymd("not-a-date").is_err());
        assert!(parse_verification_date_ymd("2023-13-01").is_err());
    }
}
