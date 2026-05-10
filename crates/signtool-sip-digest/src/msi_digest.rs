//! Windows Installer Authenticode digest (`MSISIP.DLL`) vs PKCS#7 `SpcIndirectData`.
//!
//! The traversal matches **Signify** `SignedMsiFile` (`signify/authenticode/signed_file/msi.py`,
//! Apache-2.0): sorted UTF-16 code-unit order on sibling names, skip `\u{5}DigitalSignature` and
//! `\u{5}MsiDigitalSignatureEx`, optional metadata **pre-hash** when `MsiDigitalSignatureEx` exists,
//! then recursive stream hashing plus per-storage CLSID little-endian bytes at each storage close.
//! **MSISIP.DLL** uses **`DigestStorageMetadataHelper`** / **`DigestStorageContentHelper`** for storage traversal;
//! see **`docs/windows-signing-components.md`**.

use super::pe_digest::PeAuthenticodeHashKind;
use anyhow::{Result, anyhow};
use authenticode::AuthenticodeSignature;
use cfb::{CompoundFile, Entry};
use digest::Digest;
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use std::cmp::Ordering;
use std::fs::File;
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// OLE stream names use a leading VT_LPWSTR length marker `\x05` (SIGNIFY / olefile convention).
const DIGITAL_SIGNATURE_ENTRY: &str = "\u{5}DigitalSignature";
const EXTENDED_SIGNATURE_ENTRY: &str = "\u{5}MsiDigitalSignatureEx";

/// FILETIME ticks between 1601-01-01 UTC and 1970-01-01 UTC (100 ns units).
const FILETIME_UNIX_EPOCH: u64 = 11_644_473_600_000_000;

fn root_stream(name: &str) -> PathBuf {
    Path::new("/").join(name)
}

fn cmp_utf16_name(a: &str, b: &str) -> Ordering {
    let ae: Vec<u16> = a.encode_utf16().collect();
    let be: Vec<u16> = b.encode_utf16().collect();
    ae.cmp(&be)
}

fn hash_utf16_name<H: Digest>(name: &str, hasher: &mut H) {
    for u in name.encode_utf16() {
        hasher.update(u.to_le_bytes());
    }
}

fn system_time_to_filetime_le(st: SystemTime) -> [u8; 8] {
    let ticks = match st.duration_since(UNIX_EPOCH) {
        Ok(d) => {
            let t = d.as_secs().saturating_mul(10_000_000) + u64::from(d.subsec_nanos()) / 100;
            t.saturating_add(FILETIME_UNIX_EPOCH)
        }
        Err(_) => 0,
    };
    ticks.to_le_bytes()
}

fn prehash_entry<H: Digest>(entry: &Entry, hasher: &mut H) {
    if !entry.is_root() {
        hash_utf16_name(entry.name(), hasher);
    }
    if entry.is_root() || entry.is_storage() {
        hasher.update(entry.clsid().to_bytes_le());
    }
    if entry.is_stream() {
        let sz = u32::try_from(entry.len()).unwrap_or(0xffff_ffff);
        hasher.update(sz.to_le_bytes());
    }
    hasher.update(entry.state_bits().to_le_bytes());
    if !entry.is_root() {
        hasher.update(system_time_to_filetime_le(entry.created()));
        hasher.update(system_time_to_filetime_le(entry.modified()));
    }
}

fn prehash_storage_recursive<F: Read + Seek, H: Digest>(
    cfb: &CompoundFile<F>,
    storage_path: &Path,
    hasher: &mut H,
) -> Result<()> {
    let meta = cfb.entry(storage_path)?;
    prehash_entry(&meta, hasher);

    let mut entries: Vec<Entry> = cfb.read_storage(storage_path)?.collect();
    entries.sort_by(|a, b| cmp_utf16_name(a.name(), b.name()));

    for e in entries {
        if e.name() == DIGITAL_SIGNATURE_ENTRY || e.name() == EXTENDED_SIGNATURE_ENTRY {
            continue;
        }
        if e.is_storage() {
            prehash_storage_recursive(cfb, e.path(), hasher)?;
        } else {
            prehash_entry(&e, hasher);
        }
    }
    Ok(())
}

fn hash_storage_content_recursive<F: Read + Seek, H: Digest>(
    cfb: &mut CompoundFile<F>,
    storage_path: &Path,
    hasher: &mut H,
) -> Result<()> {
    let mut entries: Vec<Entry> = cfb.read_storage(storage_path)?.collect();
    entries.sort_by(|a, b| cmp_utf16_name(a.name(), b.name()));

    for e in entries {
        if e.name() == DIGITAL_SIGNATURE_ENTRY || e.name() == EXTENDED_SIGNATURE_ENTRY {
            continue;
        }
        if e.is_storage() {
            hash_storage_content_recursive(cfb, e.path(), hasher)?;
        } else if e.is_stream() {
            let mut stream = cfb.open_stream(e.path())?;
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf)?;
            hasher.update(&buf);
        }
    }

    let st = cfb.entry(storage_path)?;
    hasher.update(st.clsid().to_bytes_le());
    Ok(())
}

fn msi_has_extended<F: Read + Seek>(cfb: &CompoundFile<F>) -> bool {
    cfb.exists(root_stream(EXTENDED_SIGNATURE_ENTRY))
}

fn compute_prehash<F: Read + Seek>(
    cfb: &CompoundFile<F>,
    kind: PeAuthenticodeHashKind,
) -> Result<Vec<u8>> {
    Ok(match kind {
        PeAuthenticodeHashKind::Sha1 => {
            let mut h = Sha1::new();
            prehash_storage_recursive(cfb, Path::new("/"), &mut h)?;
            h.finalize().to_vec()
        }
        PeAuthenticodeHashKind::Sha256 => {
            let mut h = Sha256::new();
            prehash_storage_recursive(cfb, Path::new("/"), &mut h)?;
            h.finalize().to_vec()
        }
        PeAuthenticodeHashKind::Sha384 => {
            let mut h = Sha384::new();
            prehash_storage_recursive(cfb, Path::new("/"), &mut h)?;
            h.finalize().to_vec()
        }
        PeAuthenticodeHashKind::Sha512 => {
            let mut h = Sha512::new();
            prehash_storage_recursive(cfb, Path::new("/"), &mut h)?;
            h.finalize().to_vec()
        }
    })
}

fn compute_msi_fingerprint<F: Read + Seek>(
    cfb: &mut CompoundFile<F>,
    kind: PeAuthenticodeHashKind,
) -> Result<Vec<u8>> {
    Ok(match kind {
        PeAuthenticodeHashKind::Sha1 => {
            let mut h = Sha1::new();
            if msi_has_extended(cfb) {
                let pre = compute_prehash(cfb, kind)?;
                h.update(&pre);
            }
            hash_storage_content_recursive(cfb, Path::new("/"), &mut h)?;
            h.finalize().to_vec()
        }
        PeAuthenticodeHashKind::Sha256 => {
            let mut h = Sha256::new();
            if msi_has_extended(cfb) {
                let pre = compute_prehash(cfb, kind)?;
                h.update(&pre);
            }
            hash_storage_content_recursive(cfb, Path::new("/"), &mut h)?;
            h.finalize().to_vec()
        }
        PeAuthenticodeHashKind::Sha384 => {
            let mut h = Sha384::new();
            if msi_has_extended(cfb) {
                let pre = compute_prehash(cfb, kind)?;
                h.update(&pre);
            }
            hash_storage_content_recursive(cfb, Path::new("/"), &mut h)?;
            h.finalize().to_vec()
        }
        PeAuthenticodeHashKind::Sha512 => {
            let mut h = Sha512::new();
            if msi_has_extended(cfb) {
                let pre = compute_prehash(cfb, kind)?;
                h.update(&pre);
            }
            hash_storage_content_recursive(cfb, Path::new("/"), &mut h)?;
            h.finalize().to_vec()
        }
    })
}

fn read_stream_all<F: Read + Seek>(cfb: &mut CompoundFile<F>, path: &Path) -> Result<Vec<u8>> {
    let mut s = cfb.open_stream(path)?;
    let mut v = Vec::new();
    s.read_to_end(&mut v)?;
    Ok(v)
}

/// Compare PKCS#7 indirect digest with a Rust MSI SIP fingerprint (Signify-compatible).
pub fn verify_msi_digest_consistency(path: &Path) -> Result<()> {
    let mut cfb = CompoundFile::open(File::open(path)?)?;

    let sig_path = root_stream(DIGITAL_SIGNATURE_ENTRY);
    if !cfb.exists(&sig_path) {
        return Err(anyhow!(
            "MSI is missing {} stream",
            DIGITAL_SIGNATURE_ENTRY.escape_debug()
        ));
    }

    let pkcs7 = read_stream_all(&mut cfb, &sig_path)?;
    let sig = AuthenticodeSignature::from_bytes(&pkcs7)
        .map_err(|e| anyhow!("MSI Authenticode PKCS#7 parse failed: {e}"))?;
    let embedded = sig.digest();
    let kind = PeAuthenticodeHashKind::from_digest_byte_len(embedded.len())?;

    let computed = compute_msi_fingerprint(&mut cfb, kind)?;
    if computed.as_slice() != embedded {
        return Err(anyhow!(
            "MSI Authenticode digest mismatch (Rust SIP fingerprint vs PKCS#7 indirect digest)"
        ));
    }

    if msi_has_extended(&cfb) {
        let expected = read_stream_all(&mut cfb, &root_stream(EXTENDED_SIGNATURE_ENTRY))?;
        let pre = compute_prehash(&cfb, kind)?;
        if pre != expected {
            return Err(anyhow!(
                "MSI extended metadata digest mismatch (MsiDigitalSignatureEx stream vs Rust pre-hash)"
            ));
        }
    }

    Ok(())
}
