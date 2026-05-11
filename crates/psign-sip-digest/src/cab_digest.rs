//! Windows CAB Authenticode digest (`WINTRUST.DLL` SIP for `.cab`) vs PKCS#7 indirect digest.
//!
//! Algorithm follows **osslsigncode** [`cab.c`](https://github.com/mtrojnar/osslsigncode/blob/master/cab.c)
//! (`cab_digest_calc` / `cab_ctx_get`): MSCF header with selective fields, optional chained-cabinet
//! name strings, `CFFOLDER` table, then raw cabinet bytes up to the PKCS#7 blob.

use super::pe_digest::PeAuthenticodeHashKind;
use anyhow::{Result, anyhow};
use authenticode::AuthenticodeSignature;
use digest::Digest;
use std::path::Path;

const FLAG_PREV_CABINET: u16 = 0x0001;
const FLAG_NEXT_CABINET: u16 = 0x0002;
const FLAG_RESERVE_PRESENT: u16 = 0x0004;

const AB_RESERVE_EXPECTED: u32 = 0x0010_0000;
const SIGNED_HEADER_EXTRA: u32 = 20;

/// Parsed CAB layout relevant to Authenticode hashing (see osslsigncode `CAB_CTX`).
#[derive(Clone, Debug)]
pub struct CabCtx {
    pub header_size: u32,
    pub sigpos: u32,
    pub siglen: u32,
    pub fileend: u32,
    pub flags: u16,
}

enum RunningHasher {
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
}

impl RunningHasher {
    fn new(kind: PeAuthenticodeHashKind) -> Self {
        match kind {
            PeAuthenticodeHashKind::Sha1 => Self::Sha1(sha1::Sha1::new()),
            PeAuthenticodeHashKind::Sha256 => Self::Sha256(sha2::Sha256::new()),
            PeAuthenticodeHashKind::Sha384 => Self::Sha384(sha2::Sha384::new()),
            PeAuthenticodeHashKind::Sha512 => Self::Sha512(sha2::Sha512::new()),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha1(h) => Digest::update(h, bytes),
            Self::Sha256(h) => Digest::update(h, bytes),
            Self::Sha384(h) => Digest::update(h, bytes),
            Self::Sha512(h) => Digest::update(h, bytes),
        }
    }

    fn finalize(self) -> Vec<u8> {
        match self {
            Self::Sha1(h) => Digest::finalize(h).to_vec(),
            Self::Sha256(h) => Digest::finalize(h).to_vec(),
            Self::Sha384(h) => Digest::finalize(h).to_vec(),
            Self::Sha512(h) => Digest::finalize(h).to_vec(),
        }
    }
}

fn read_u16_le(buf: &[u8], off: usize) -> Result<u16> {
    buf.get(off..off + 2)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| anyhow!("read past end at {off}"))
}

fn read_u32_le(buf: &[u8], off: usize) -> Result<u32> {
    buf.get(off..off + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| anyhow!("read past end at {off}"))
}

/// Validate CAB layout and signature extents (osslsigncode `cab_ctx_get`).
pub fn parse_cab_context(data: &[u8]) -> Result<CabCtx> {
    if data.len() < 44 {
        return Err(anyhow!("CAB file too short"));
    }
    if &data[0..4] != b"MSCF" {
        return Err(anyhow!("not a CAB file (missing MSCF signature)"));
    }
    if read_u32_le(data, 4)? != 0 {
        return Err(anyhow!("CAB reserved1 must be zero"));
    }

    let flags = read_u16_le(data, 30)?;
    if flags & FLAG_PREV_CABINET != 0 {
        return Err(anyhow!(
            "multivolume CAB (FLAG_PREV_CABINET) is unsupported for Rust SIP digest"
        ));
    }

    let fileend = u32::try_from(data.len()).map_err(|_| anyhow!("CAB file too large"))?;
    let mut header_size = 0u32;
    let mut sigpos = 0u32;
    let mut siglen = 0u32;

    if flags & FLAG_RESERVE_PRESENT != 0 {
        header_size = read_u32_le(data, 36)?;
        if header_size != SIGNED_HEADER_EXTRA {
            return Err(anyhow!(
                "unsupported CAB additional header size {header_size} (expected {SIGNED_HEADER_EXTRA})"
            ));
        }
        let ab_reserved = read_u32_le(data, 40)?;
        if ab_reserved != AB_RESERVE_EXPECTED {
            return Err(anyhow!(
                "unexpected CAB abReserve value 0x{ab_reserved:08x} (expected 0x00100000)"
            ));
        }
        sigpos = read_u32_le(data, 44)?;
        siglen = read_u32_le(data, 48)?;
        if (sigpos > 0 && siglen == 0) || (sigpos == 0 && siglen > 0) {
            return Err(anyhow!("corrupt CAB signature extent (sigpos/siglen)"));
        }
        if sigpos < fileend && sigpos.saturating_add(siglen) != fileend {
            return Err(anyhow!(
                "CAB signature extent does not match file size (sigpos={sigpos}, siglen={siglen}, file={fileend})"
            ));
        }
        if sigpos >= fileend {
            return Err(anyhow!("CAB sigpos past end of file"));
        }
    }

    Ok(CabCtx {
        header_size,
        sigpos,
        siglen,
        fileend,
        flags,
    })
}

fn hash_sz_field(
    hasher: &mut RunningHasher,
    data: &[u8],
    mut idx: usize,
    fileend: usize,
) -> Result<usize> {
    while idx < fileend {
        let b = data[idx];
        hasher.update(&[b]);
        idx += 1;
        if b == 0 {
            break;
        }
    }
    Ok(idx)
}

/// Recompute the CAB image digest (`cab_digest_calc`).
pub fn compute_cab_authenticode_digest(
    data: &[u8],
    ctx: &CabCtx,
    kind: PeAuthenticodeHashKind,
) -> Result<Vec<u8>> {
    let mut hasher = RunningHasher::new(kind);
    let fileend = usize::try_from(ctx.fileend).map_err(|_| anyhow!("file end"))?;

    hasher.update(&data[0..4]);

    if ctx.sigpos != 0 {
        let sigpos = usize::try_from(ctx.sigpos).map_err(|_| anyhow!("sigpos"))?;
        let coff_files = read_u32_le(data, 16)? as usize;
        let nfolders = read_u16_le(data, 26)? as usize;
        let flags = read_u16_le(data, 30)?;

        hasher.update(&data[8..16]);
        hasher.update(&data[16..20]);
        hasher.update(&data[20..26]);
        hasher.update(&data[26..28]);
        hasher.update(&data[28..30]);
        hasher.update(&data[30..32]);
        hasher.update(&data[32..34]);
        hasher.update(&data[56..60]);

        let mut idx = 60usize;
        if flags & FLAG_NEXT_CABINET != 0 {
            idx = hash_sz_field(&mut hasher, data, idx, sigpos)?;
            idx = hash_sz_field(&mut hasher, data, idx, sigpos)?;
        }

        let mut remaining = nfolders;
        while remaining > 0 && idx < sigpos {
            let end = idx
                .checked_add(8)
                .ok_or_else(|| anyhow!("folder table overflow"))?;
            if end > sigpos {
                return Err(anyhow!("CFFOLDER entries overflow signature offset"));
            }
            hasher.update(&data[idx..end]);
            idx = end;
            remaining -= 1;
        }
        if remaining != 0 {
            return Err(anyhow!("truncated CFFOLDER table"));
        }
        if idx != coff_files {
            return Err(anyhow!(
                "corrupt CAB coffFiles: expected header to end at 0x{coff_files:x}, got 0x{idx:x}"
            ));
        }
        if sigpos > fileend {
            return Err(anyhow!("sigpos past file"));
        }
        hasher.update(&data[idx..sigpos]);
    } else {
        hasher.update(&data[8..fileend]);
    }

    Ok(hasher.finalize())
}

/// **RS256** prehash (**SHA-256** over authenticated **`signedAttrs`**) from embedded CAB PKCS#7.
///
/// Same contract as [`crate::pkcs7::signed_data_rsa_sha256_signer_prehash_digest`] on the tail
/// **`SignedData`** extracted by [`cab_signature_pkcs7_der`] (Azure Key Vault **`keys/sign`** input for
/// **RSA SHA-256** re-signing of **`SignerInfo`**).
pub fn cab_rsa_sha256_signer_prehash_digest(data: &[u8], signer_index: usize) -> Result<Vec<u8>> {
    let pkcs7 = cab_signature_pkcs7_der(data)?;
    let sd = crate::pkcs7::parse_pkcs7_signed_data_der(pkcs7)?;
    crate::pkcs7::signed_data_rsa_sha256_signer_prehash_digest(&sd, signer_index)
}

/// PKCS#7 `SignedData` bytes embedded at the tail of a signed CAB (`sigpos`..`sigpos+siglen`).
pub fn cab_signature_pkcs7_der(data: &[u8]) -> Result<&[u8]> {
    let ctx = parse_cab_context(data)?;
    if ctx.header_size != SIGNED_HEADER_EXTRA || ctx.sigpos == 0 || ctx.siglen == 0 {
        return Err(anyhow!(
            "CAB has no embedded Authenticode signature (expected reserve header + PKCS#7)"
        ));
    }
    let sig_start = usize::try_from(ctx.sigpos).map_err(|_| anyhow!("sigpos"))?;
    let sig_end = sig_start
        .checked_add(ctx.siglen as usize)
        .ok_or_else(|| anyhow!("signature extent overflow"))?;
    data.get(sig_start..sig_end)
        .ok_or_else(|| anyhow!("PKCS#7 extent out of range"))
}

/// PKCS#7 indirect digest vs osslsigncode-style CAB hash (`cab_verify_digests`).
pub fn verify_cab_digest_consistency(path: &Path) -> Result<()> {
    let data = std::fs::read(path)?;
    let ctx = parse_cab_context(&data)?;

    if ctx.header_size != SIGNED_HEADER_EXTRA || ctx.sigpos == 0 || ctx.siglen == 0 {
        return Err(anyhow!(
            "CAB has no embedded Authenticode signature (expected 20-byte reserve header + PKCS#7)"
        ));
    }
    let pkcs7 = cab_signature_pkcs7_der(&data)?;

    let sig = AuthenticodeSignature::from_bytes(pkcs7)
        .map_err(|e| anyhow!("CAB PKCS#7 parse failed: {e}"))?;
    let embedded = sig.digest();
    let kind = PeAuthenticodeHashKind::from_digest_byte_len(embedded.len())?;

    let computed = compute_cab_authenticode_digest(&data, &ctx, kind)?;
    if computed.as_slice() != embedded {
        return Err(anyhow!(
            "CAB Authenticode digest mismatch (Rust SIP vs PKCS#7 indirect digest)"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_mscf() {
        let buf = vec![0u8; 64];
        assert!(parse_cab_context(&buf).is_err());
    }

    #[test]
    fn unsigned_minimal_digest_stable() {
        let mut data = vec![0u8; 48];
        data[0..4].copy_from_slice(b"MSCF");
        data[8..12].copy_from_slice(&100u32.to_le_bytes());
        let ctx = parse_cab_context(&data).expect("parse");
        assert_eq!(ctx.sigpos, 0);
        let h =
            compute_cab_authenticode_digest(&data, &ctx, PeAuthenticodeHashKind::Sha256).unwrap();
        assert_eq!(h.len(), 32);
    }

    #[test]
    fn cab_rsa_sha256_signer_prehash_digest_errors_when_unsigned() {
        let mut data = vec![0u8; 48];
        data[0..4].copy_from_slice(b"MSCF");
        data[8..12].copy_from_slice(&100u32.to_le_bytes());
        assert!(cab_rsa_sha256_signer_prehash_digest(&data, 0).is_err());
    }

    #[test]
    fn cab_rsa_sha256_signer_prehash_matches_direct_signer_on_tiny_signed_fixture() {
        let bytes =
            include_bytes!("../../../tests/fixtures/cab-authenticode-upstream/tiny-signed.cab");
        let pkcs7 = cab_signature_pkcs7_der(bytes).expect("cab pkcs7");
        let sd = crate::pkcs7::parse_pkcs7_signed_data_der(pkcs7).expect("SignedData");
        let si = sd.signer_infos.0.as_slice().first().expect("SignerInfo");
        let direct = crate::pkcs7::signer_info_sha256_digest_over_signed_attrs(si).expect("direct");
        let via_cab = cab_rsa_sha256_signer_prehash_digest(bytes, 0).expect("cab helper");
        assert_eq!(direct, via_cab);
    }

    #[test]
    fn tiny_signed_cab_signed_data_embedded_certificate_count() {
        let bytes =
            include_bytes!("../../../tests/fixtures/cab-authenticode-upstream/tiny-signed.cab");
        let pkcs7 = cab_signature_pkcs7_der(bytes).expect("cab pkcs7");
        let sd = crate::pkcs7::parse_pkcs7_signed_data_der(pkcs7).expect("SignedData");
        let n = sd.certificates.as_ref().map(|s| s.0.len()).unwrap_or(0);
        assert_eq!(
            n, 1,
            "fixture embeds signer cert only (CAB chain completes via anchors)"
        );
    }

    #[test]
    fn tiny_signed_cab_spc_indirect_digest_matches_authenticode_rs_digest() {
        let bytes =
            include_bytes!("../../../tests/fixtures/cab-authenticode-upstream/tiny-signed.cab");
        let pkcs7 = cab_signature_pkcs7_der(bytes).expect("cab pkcs7");
        let sig = AuthenticodeSignature::from_bytes(pkcs7).expect("authenticode-rs");
        let sd = crate::pkcs7::parse_pkcs7_signed_data_der(pkcs7).expect("SignedData");
        let indirect = crate::pkcs7::signed_data_spc_indirect_message_digest_octets(&sd)
            .expect("SpcIndirectData digest");
        assert_eq!(indirect.as_slice(), sig.digest());
    }
}
