//! MSIX / APPX **flat package** and **bundle** digest (`AppxSip.dll`) vs PKCS#7 `SpcIndirectData` APPX blob.
//!
//! Digest layout follows **osslsigncode** [`appx.c`](https://github.com/mtrojnar/osslsigncode/blob/master/appx.c):
//! strip **PKCX** from `AppxSignature.p7x`, parse Authenticode `SpcIndirectData`, then compare the
//! **APPX + AXPC + AXCD + AXCT + AXBM [+ AXCI]** blob with hashes recomputed from the ZIP layout.
//!
//! **Bundles** (`.msixbundle` / `.appxbundle`, or any ZIP that contains `AppxMetadata/AppxBundleManifest.xml`)
//! use the **same** ZIP hash pipeline as flat packages in `appx.c` (`appx_calculate_hashes`); only the
//! **SpcSipInfo** UUID embedded at **sign** time differs (`APPXBUNDLE_UUID` vs `APPX_UUID`). Windows may route
//! verification through **`AppxBundleSip*`** COM helpers, but the recomputed PKCS#7 indirect digest matches this
//! implementation (aligned with **`AppxSip.dll`** behavior; see **`docs/windows-signing-components.md`**).

use crate::pe_digest::PeAuthenticodeHashKind;
use anyhow::{Result, anyhow};
use authenticode::AuthenticodeSignature;
use digest::Digest;
use std::io::{Cursor, Read};
use std::path::Path;
use zip::CompressionMethod;
use zip::read::ZipArchive;
use zip::read::ZipFile;

const APP_SIGNATURE: &[u8] = b"AppxSignature.p7x";
const CONTENT_TYPES: &[u8] = b"[Content_Types].xml";
const BLOCK_MAP: &[u8] = b"AppxBlockMap.xml";
const BUNDLE_MANIFEST: &[u8] = b"AppxMetadata/AppxBundleManifest.xml";
const CODE_INTEGRITY: &[u8] = b"AppxMetadata/CodeIntegrity.cat";

const SIG_APPX: &[u8] = b"APPX";
const TAG_AXPC: &[u8] = b"AXPC";
const TAG_AXCD: &[u8] = b"AXCD";
const TAG_AXCT: &[u8] = b"AXCT";
const TAG_AXBM: &[u8] = b"AXBM";
const TAG_AXCI: &[u8] = b"AXCI";

const HASH_SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
const HASH_SHA384: &str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
const HASH_SHA512: &str = "http://www.w3.org/2001/04/xmlenc#sha512";

const ZIP64_EXTRA_ID: u16 = 0x0001;

const LH_SIG: u32 = 0x0403_4b50;
const CD_SIG: u32 = 0x0201_4b50;
const EOCD_SIG: u32 = 0x0605_4b50;
const ZIP64_EOCD_SIG: u32 = 0x0606_4b50;
const ZIP64_LOC_SIG: u32 = 0x0706_4b50;

const DATA_DESCRIPTOR_BIT: u16 = 1 << 3;
const DD_SIG: u32 = 0x0807_4b50;

#[derive(Clone, Debug)]
struct AppxDigestParts {
    axpc: Vec<u8>,
    axcd: Vec<u8>,
    axct: Vec<u8>,
    axbm: Vec<u8>,
    axci: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct ClassicEocd {
    number_of_files_on_this_disk: u16,
    number_of_files: u16,
    central_directory_size: u32,
    central_directory_offset: u32,
    zip_file_comment: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Zip64Locator {
    disk_with_central_directory: u32,
    end_of_central_directory_offset: u64,
    number_of_disks: u32,
}

#[derive(Clone, Debug)]
struct Zip64Eocd {
    record_size: u64,
    version_made_by: u16,
    version_needed_to_extract: u16,
    disk_number: u32,
    disk_with_central_directory: u32,
    tail_after_fixed: Vec<u8>,
}

#[derive(Clone, Debug)]
struct ZipTail {
    classic: ClassicEocd,
    zip64_eocd: Option<Zip64Eocd>,
    locator: Option<Zip64Locator>,
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
            Self::Sha1(h) => digest::Digest::update(h, bytes),
            Self::Sha256(h) => digest::Digest::update(h, bytes),
            Self::Sha384(h) => digest::Digest::update(h, bytes),
            Self::Sha512(h) => digest::Digest::update(h, bytes),
        }
    }

    fn finalize(self) -> Vec<u8> {
        match self {
            Self::Sha1(h) => digest::Digest::finalize(h).to_vec(),
            Self::Sha256(h) => digest::Digest::finalize(h).to_vec(),
            Self::Sha384(h) => digest::Digest::finalize(h).to_vec(),
            Self::Sha512(h) => digest::Digest::finalize(h).to_vec(),
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

fn read_u64_le(buf: &[u8], off: usize) -> Result<u64> {
    buf.get(off..off + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| anyhow!("read past end at {off}"))
}

fn strip_pkcx(data: &[u8]) -> Result<&[u8]> {
    if data.len() < 4 || &data[..4] != b"PKCX" {
        return Err(anyhow!(
            "AppxSignature.p7x did not start with PKCX (Windows P7X wrapper)"
        ));
    }
    Ok(&data[4..])
}

fn hash_kind_from_block_map_xml(xml: &[u8]) -> Result<PeAuthenticodeHashKind> {
    let s = std::str::from_utf8(xml).map_err(|_| anyhow!("AppxBlockMap.xml is not valid UTF-8"))?;
    let needle = "HashMethod";
    let Some(pos) = s.find(needle) else {
        return Err(anyhow!("AppxBlockMap.xml missing HashMethod"));
    };
    let tail = &s[pos + needle.len()..];
    let (qi, q) = tail
        .char_indices()
        .find(|(_, c)| *c == '"' || *c == '\'')
        .ok_or_else(|| anyhow!("AppxBlockMap.xml HashMethod has no quoted value"))?;
    let open = qi + q.len_utf8();
    let close_rel = tail[open..]
        .find(q)
        .ok_or_else(|| anyhow!("AppxBlockMap.xml HashMethod value not terminated"))?;
    let uri = tail[open..open + close_rel].trim();
    if uri == HASH_SHA256 {
        Ok(PeAuthenticodeHashKind::Sha256)
    } else if uri == HASH_SHA384 {
        Ok(PeAuthenticodeHashKind::Sha384)
    } else if uri == HASH_SHA512 {
        Ok(PeAuthenticodeHashKind::Sha512)
    } else {
        Err(anyhow!(
            "unsupported AppxBlockMap HashMethod URI `{uri}` (expected SHA256/384/512 URIs)"
        ))
    }
}

fn parse_signed_appx_blob(data: &[u8]) -> Result<(usize, AppxDigestParts)> {
    if data.len() < 4 || &data[..4] != SIG_APPX {
        return Err(anyhow!(
            "PKCS#7 indirect digest is not an APPX blob (missing APPX prefix)"
        ));
    }
    let mut md_len_opt = None;
    for &candidate in &[20usize, 32, 48, 64] {
        let mut pos = 4usize;
        let mut ok = true;
        let tags = [TAG_AXPC, TAG_AXCD, TAG_AXCT, TAG_AXBM];
        for t in tags {
            if pos + 4 + candidate > data.len() || &data[pos..pos + 4] != t {
                ok = false;
                break;
            }
            pos += 4 + candidate;
        }
        if !ok {
            continue;
        }
        if pos == data.len() {
            md_len_opt = Some((candidate, false));
            break;
        }
        if pos + 4 + candidate <= data.len() && &data[pos..pos + 4] == TAG_AXCI {
            pos += 4 + candidate;
            if pos == data.len() {
                md_len_opt = Some((candidate, true));
                break;
            }
        }
    }
    let (md_len, has_ci) = md_len_opt.ok_or_else(|| {
        anyhow!("could not parse APPX indirect digest blob (expected AXPC..AXBM [+ AXCI])")
    })?;

    let mut pos = 4usize;
    let mut take = |tag: &[u8]| -> Result<Vec<u8>> {
        if pos + 4 + md_len > data.len() || &data[pos..pos + 4] != tag {
            return Err(anyhow!("unexpected APPX digest tag"));
        }
        pos += 4;
        let d = data[pos..pos + md_len].to_vec();
        pos += md_len;
        Ok(d)
    };

    let axpc = take(TAG_AXPC)?;
    let axcd = take(TAG_AXCD)?;
    let axct = take(TAG_AXCT)?;
    let axbm = take(TAG_AXBM)?;
    let axci = if has_ci { Some(take(TAG_AXCI)?) } else { None };
    if pos != data.len() {
        return Err(anyhow!("trailing bytes in APPX indirect digest blob"));
    }
    Ok((
        md_len,
        AppxDigestParts {
            axpc,
            axcd,
            axct,
            axbm,
            axci,
        },
    ))
}

fn find_classic_eocd(buf: &[u8]) -> Result<(usize, ClassicEocd)> {
    const HEADER_SIZE: u64 = 22;
    let file_length = buf.len() as u64;
    if file_length < HEADER_SIZE {
        return Err(anyhow!("buffer too small for EOCD"));
    }
    let search_upper_bound = file_length.saturating_sub(HEADER_SIZE + u16::MAX as u64);
    let mut pos = file_length - HEADER_SIZE;
    while pos >= search_upper_bound {
        let p = pos as usize;
        if read_u32_le(buf, p)? == EOCD_SIG {
            let _disk_number = read_u16_le(buf, p + 4)?;
            let _disk_with_central_directory = read_u16_le(buf, p + 6)?;
            let number_of_files_on_this_disk = read_u16_le(buf, p + 8)?;
            let number_of_files = read_u16_le(buf, p + 10)?;
            let central_directory_size = read_u32_le(buf, p + 12)?;
            let central_directory_offset = read_u32_le(buf, p + 16)?;
            let zip_file_comment_length = read_u16_le(buf, p + 20)? as usize;
            let cstart = p + 22;
            let cend = cstart
                .checked_add(zip_file_comment_length)
                .ok_or_else(|| anyhow!("EOCD comment overflow"))?;
            let zip_file_comment = buf
                .get(cstart..cend)
                .ok_or_else(|| anyhow!("EOCD comment out of range"))?
                .to_vec();
            return Ok((
                p,
                ClassicEocd {
                    number_of_files_on_this_disk,
                    number_of_files,
                    central_directory_size,
                    central_directory_offset,
                    zip_file_comment,
                },
            ));
        }
        pos = match pos.checked_sub(1) {
            Some(p) => p,
            None => break,
        };
    }
    Err(anyhow!("could not find ZIP end-of-central-directory"))
}

fn parse_zip64_locator(buf: &[u8], off: usize) -> Result<Zip64Locator> {
    if read_u32_le(buf, off)? != ZIP64_LOC_SIG {
        return Err(anyhow!("invalid ZIP64 locator signature"));
    }
    Ok(Zip64Locator {
        disk_with_central_directory: read_u32_le(buf, off + 4)?,
        end_of_central_directory_offset: read_u64_le(buf, off + 8)?,
        number_of_disks: read_u32_le(buf, off + 16)?,
    })
}

fn find_zip64_eocd(
    buf: &[u8],
    nominal_offset: usize,
    search_upper_bound: usize,
) -> Result<(usize, Zip64Eocd, u64)> {
    let mut pos = nominal_offset;
    while pos <= search_upper_bound {
        if read_u32_le(buf, pos)? == ZIP64_EOCD_SIG {
            let archive_offset_u64 = (pos as u64).saturating_sub(
                u64::try_from(nominal_offset).map_err(|_| anyhow!("nominal offset"))?,
            );
            let record_size = read_u64_le(buf, pos + 4)?;
            let version_made_by = read_u16_le(buf, pos + 12)?;
            let version_needed_to_extract = read_u16_le(buf, pos + 14)?;
            let disk_number = read_u32_le(buf, pos + 16)?;
            let disk_with_central_directory = read_u32_le(buf, pos + 20)?;
            let fixed_after_record_size = 44usize;
            let total_record_content =
                usize::try_from(record_size).map_err(|_| anyhow!("zip64"))?;
            let tail_len = total_record_content.saturating_sub(fixed_after_record_size);
            let tail_start = pos + 12 + fixed_after_record_size;
            let tail_end = tail_start
                .checked_add(tail_len)
                .ok_or_else(|| anyhow!("zip64 tail overflow"))?;
            let tail_after_fixed = buf
                .get(tail_start..tail_end)
                .ok_or_else(|| anyhow!("zip64 tail out of range"))?
                .to_vec();
            return Ok((
                pos,
                Zip64Eocd {
                    record_size,
                    version_made_by,
                    version_needed_to_extract,
                    disk_number,
                    disk_with_central_directory,
                    tail_after_fixed,
                },
                archive_offset_u64,
            ));
        }
        pos += 1;
    }
    Err(anyhow!("could not find ZIP64 end-of-central-directory"))
}

fn parse_zip_tail(buf: &[u8]) -> Result<ZipTail> {
    let (cde_pos, classic) = find_classic_eocd(buf)?;
    let cde_pos_u64 = u64::try_from(cde_pos).map_err(|_| anyhow!("cde position"))?;
    cde_pos_u64
        .checked_sub(classic.central_directory_size as u64)
        .and_then(|x| x.checked_sub(classic.central_directory_offset as u64))
        .ok_or_else(|| anyhow!("invalid EOCD central directory size/offset"))?;

    let file_len = buf.len();
    let comment_len = classic.zip_file_comment.len();
    let mut locator = None;
    let mut zip64_eocd = None;

    let locator_seek = file_len
        .checked_sub(20 + 22 + comment_len)
        .filter(|&x| x <= file_len);
    if let Some(off) = locator_seek
        && off + 20 <= buf.len()
        && read_u32_le(buf, off)? == ZIP64_LOC_SIG
    {
        let loc = parse_zip64_locator(buf, off)?;
        locator = Some(loc.clone());
        let nominal = usize::try_from(loc.end_of_central_directory_offset)
            .map_err(|_| anyhow!("zip64 nominal offset"))?;
        let search_upper = cde_pos.saturating_sub(60);
        let (_zpos, z64, _ao) = find_zip64_eocd(buf, nominal, search_upper)?;
        zip64_eocd = Some(z64);
    }

    Ok(ZipTail {
        classic,
        zip64_eocd,
        locator,
    })
}

fn parse_zip64_cd_extra(
    extra: &[u8],
    fixed_comp: u32,
    fixed_uncomp: u32,
    fixed_off: u32,
    fixed_disk: u16,
) -> (bool, bool, bool, bool, u32) {
    let mut needs_uncomp = fixed_uncomp == u32::MAX;
    let mut needs_comp = fixed_comp == u32::MAX;
    let mut needs_off = fixed_off == u32::MAX;
    let mut needs_disk = fixed_disk == u16::MAX;
    let mut disk = fixed_disk as u32;

    let mut i = 0usize;
    while i + 4 <= extra.len() {
        let id = u16::from_le_bytes(extra[i..i + 2].try_into().unwrap());
        let sz = u16::from_le_bytes(extra[i + 2..i + 4].try_into().unwrap()) as usize;
        i += 4;
        if i + sz > extra.len() {
            break;
        }
        let chunk = &extra[i..i + sz];
        if id == ZIP64_EXTRA_ID {
            let mut r = 0usize;
            if needs_uncomp && r + 8 <= chunk.len() {
                r += 8;
                needs_uncomp = false;
            }
            if needs_comp && r + 8 <= chunk.len() {
                r += 8;
                needs_comp = false;
            }
            if needs_off && r + 8 <= chunk.len() {
                r += 8;
                needs_off = false;
            }
            if needs_disk && r + 4 <= chunk.len() {
                disk = u32::from_le_bytes(chunk[r..r + 4].try_into().unwrap());
                needs_disk = false;
            }
        }
        i += sz;
    }

    (
        fixed_uncomp == u32::MAX,
        fixed_comp == u32::MAX,
        fixed_off == u32::MAX,
        fixed_disk == u16::MAX,
        disk,
    )
}

fn write_local_header_normalized(
    hasher: &mut RunningHasher,
    buf: &[u8],
    zf: &ZipFile<'_>,
) -> Result<()> {
    let hs = usize::try_from(zf.header_start()).map_err(|_| anyhow!("header_start"))?;
    if read_u32_le(buf, hs)? != LH_SIG {
        return Err(anyhow!("bad local file header signature"));
    }
    let version = read_u16_le(buf, hs + 4)?;
    let flags = read_u16_le(buf, hs + 6)?;
    let compression = read_u16_le(buf, hs + 8)?;
    let mod_time = read_u16_le(buf, hs + 10)?;
    let mod_date = read_u16_le(buf, hs + 12)?;

    let crc32 = zf.crc32();
    let compressed_size = zf.compressed_size();
    let uncompressed_size = zf.size();
    let name = zf.name_raw();
    let extra = zf.extra_data();

    hasher.update(&LH_SIG.to_le_bytes());
    hasher.update(&version.to_le_bytes());
    hasher.update(&flags.to_le_bytes());
    hasher.update(&compression.to_le_bytes());
    hasher.update(&mod_time.to_le_bytes());
    hasher.update(&mod_date.to_le_bytes());

    if flags & DATA_DESCRIPTOR_BIT != 0 {
        hasher.update(&[0u8; 12]);
    } else {
        let comp_zip64 = compressed_size > u64::from(u32::MAX);
        let uncomp_zip64 = uncompressed_size > u64::from(u32::MAX);
        hasher.update(&crc32.to_le_bytes());
        hasher.update(
            &(if comp_zip64 {
                u32::MAX
            } else {
                compressed_size as u32
            })
            .to_le_bytes(),
        );
        hasher.update(
            &(if uncomp_zip64 {
                u32::MAX
            } else {
                uncompressed_size as u32
            })
            .to_le_bytes(),
        );
    }

    hasher.update(&(name.len() as u16).to_le_bytes());
    hasher.update(&(extra.len() as u16).to_le_bytes());
    hasher.update(name);
    hasher.update(extra);
    Ok(())
}

fn append_data_descriptor(
    hasher: &mut RunningHasher,
    buf: &[u8],
    zf: &ZipFile<'_>,
    package_zip64: bool,
) -> Result<()> {
    let hs = usize::try_from(zf.header_start()).map_err(|_| anyhow!("header_start"))?;
    let flags = read_u16_le(buf, hs + 6)?;
    if flags & DATA_DESCRIPTOR_BIT == 0 {
        return Ok(());
    }
    hasher.update(&DD_SIG.to_le_bytes());
    hasher.update(&zf.crc32().to_le_bytes());
    if package_zip64 {
        hasher.update(&zf.compressed_size().to_le_bytes());
        hasher.update(&zf.size().to_le_bytes());
    } else {
        let cs = u32::try_from(zf.compressed_size())
            .map_err(|_| anyhow!("ZIP64 package flag required for large data descriptor"))?;
        let us = u32::try_from(zf.size()).map_err(|_| anyhow!("ZIP64 package flag required"))?;
        hasher.update(&cs.to_le_bytes());
        hasher.update(&us.to_le_bytes());
    }
    Ok(())
}

fn payload_and_descriptor_len(buf: &[u8], zf: &ZipFile<'_>, package_zip64: bool) -> Result<u64> {
    let hs = usize::try_from(zf.header_start()).map_err(|_| anyhow!("header_start"))?;
    let flags = read_u16_le(buf, hs + 6)?;
    let cs = zf.compressed_size();
    let dd_extra = if flags & DATA_DESCRIPTOR_BIT != 0 {
        if package_zip64 { 24u64 } else { 16u64 }
    } else {
        0u64
    };
    Ok(cs.saturating_add(dd_extra))
}

fn hash_zip_file_data(
    buf: &[u8],
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    tail: &ZipTail,
    kind: PeAuthenticodeHashKind,
) -> Result<(Vec<u8>, u64)> {
    let package_zip64 = tail.locator.is_some();
    let mut hasher = RunningHasher::new(kind);
    let mut cd_cursor: u64 = 0;
    let n = archive.len();
    for i in 0..n {
        let zf = archive.by_index(i)?;
        if zf.name_raw() == APP_SIGNATURE {
            continue;
        }
        let name = zf.name();
        if name.ends_with('/') || name.ends_with('\\') {
            continue;
        }
        match zf.compression() {
            CompressionMethod::Stored | CompressionMethod::Deflated => {}
            other => {
                return Err(anyhow!(
                    "unsupported ZIP compression {other:?} for MSIX digest (need Stored/Deflated)"
                ));
            }
        }
        write_local_header_normalized(&mut hasher, buf, &zf)?;
        let hl = u64::try_from(30 + zf.name_raw().len() + zf.extra_data().len())
            .map_err(|_| anyhow!("local header length"))?;
        cd_cursor = cd_cursor
            .checked_add(hl)
            .ok_or_else(|| anyhow!("cursor overflow"))?;

        let ds = usize::try_from(zf.data_start()).map_err(|_| anyhow!("data_start"))?;
        let cs = usize::try_from(zf.compressed_size()).map_err(|_| anyhow!("compressed_size"))?;
        let end = ds
            .checked_add(cs)
            .ok_or_else(|| anyhow!("payload overflow"))?;
        let slice = buf
            .get(ds..end)
            .ok_or_else(|| anyhow!("compressed payload out of range"))?;
        hasher.update(slice);
        append_data_descriptor(&mut hasher, buf, &zf, package_zip64)?;

        let inc = payload_and_descriptor_len(buf, &zf, package_zip64)?;
        cd_cursor = cd_cursor
            .checked_add(inc)
            .ok_or_else(|| anyhow!("cursor overflow"))?;
    }
    Ok((hasher.finalize(), cd_cursor))
}

fn hash_cd_and_eocd(
    buf: &[u8],
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    tail: &ZipTail,
    kind: PeAuthenticodeHashKind,
    cd_offset_virtual: u64,
) -> Result<Vec<u8>> {
    let mut hasher = RunningHasher::new(kind);
    let mut cd_size: u64 = 0;
    let mut no_entries: u16 = 0;

    let n = archive.len();
    for i in 0..n {
        let zf = archive.by_index(i)?;
        if zf.name_raw() == APP_SIGNATURE {
            continue;
        }
        let name = zf.name();
        if name.ends_with('/') || name.ends_with('\\') {
            continue;
        }

        let central_off = usize::try_from(zf.central_header_start())
            .map_err(|_| anyhow!("central_header_start"))?;
        if read_u32_le(buf, central_off)? != CD_SIG {
            return Err(anyhow!("bad central directory signature"));
        }

        let version_made_by = read_u16_le(buf, central_off + 4)?;
        let version_needed = read_u16_le(buf, central_off + 6)?;
        let flags = read_u16_le(buf, central_off + 8)?;
        let compression = read_u16_le(buf, central_off + 10)?;
        let mod_time = read_u16_le(buf, central_off + 12)?;
        let mod_date = read_u16_le(buf, central_off + 14)?;
        let crc32 = read_u32_le(buf, central_off + 16)?;
        let comp32 = read_u32_le(buf, central_off + 20)?;
        let uncomp32 = read_u32_le(buf, central_off + 24)?;
        let file_name_length = read_u16_le(buf, central_off + 28)? as usize;
        let extra_field_length = read_u16_le(buf, central_off + 30)? as usize;
        let file_comment_length = read_u16_le(buf, central_off + 32)? as usize;
        let disk_start = read_u16_le(buf, central_off + 34)?;
        let internal_attr = read_u16_le(buf, central_off + 36)?;
        let external_attr = read_u32_le(buf, central_off + 38)?;
        let local_off32 = read_u32_le(buf, central_off + 42)?;

        let base = central_off + 46;
        let name_end = base
            .checked_add(file_name_length)
            .ok_or_else(|| anyhow!("name"))?;
        let extra_end = name_end
            .checked_add(extra_field_length)
            .ok_or_else(|| anyhow!("extra"))?;
        let record_end = extra_end
            .checked_add(file_comment_length)
            .ok_or_else(|| anyhow!("comment"))?;
        if record_end > buf.len() {
            return Err(anyhow!("central directory entry out of range"));
        }
        let fname = &buf[base..name_end];
        let extra = &buf[name_end..extra_end];
        let fcomment = &buf[extra_end..record_end];

        let (uncomp_z64, comp_z64, off_z64, disk_z64, disk_u32) =
            parse_zip64_cd_extra(extra, comp32, uncomp32, local_off32, disk_start);

        let uncomp_u64 = zf.size();
        let comp_u64 = zf.compressed_size();
        let off_u64 = zf.header_start();

        let uncomp_z64 = uncomp_z64 || uncomp_u64 > u64::from(u32::MAX);
        let comp_z64 = comp_z64 || comp_u64 > u64::from(u32::MAX);
        let off_z64 = off_z64 || off_u64 > u64::from(u32::MAX);

        let mut syn = Vec::new();
        let mut pay = Vec::new();
        if uncomp_z64 {
            pay.extend_from_slice(&uncomp_u64.to_le_bytes());
        }
        if comp_z64 {
            pay.extend_from_slice(&comp_u64.to_le_bytes());
        }
        if off_z64 {
            pay.extend_from_slice(&off_u64.to_le_bytes());
        }
        if disk_z64 {
            pay.extend_from_slice(&disk_u32.to_le_bytes());
        }
        if !pay.is_empty() {
            syn.extend_from_slice(&ZIP64_EXTRA_ID.to_le_bytes());
            syn.extend_from_slice(&(pay.len() as u16).to_le_bytes());
            syn.extend_from_slice(&pay);
        }

        hasher.update(&CD_SIG.to_le_bytes());
        hasher.update(&version_made_by.to_le_bytes());
        hasher.update(&version_needed.to_le_bytes());
        hasher.update(&flags.to_le_bytes());
        hasher.update(&compression.to_le_bytes());
        hasher.update(&mod_time.to_le_bytes());
        hasher.update(&mod_date.to_le_bytes());
        hasher.update(&crc32.to_le_bytes());
        hasher.update(
            &(if comp_z64 {
                u32::MAX
            } else {
                u32::try_from(comp_u64).map_err(|_| anyhow!("compressed size overflow"))?
            })
            .to_le_bytes(),
        );
        hasher.update(
            &(if uncomp_z64 {
                u32::MAX
            } else {
                u32::try_from(uncomp_u64).map_err(|_| anyhow!("uncompressed size overflow"))?
            })
            .to_le_bytes(),
        );
        hasher.update(&(fname.len() as u16).to_le_bytes());
        let syn_len_u16 =
            u16::try_from(syn.len()).map_err(|_| anyhow!("synthetic extra too large"))?;
        hasher.update(&syn_len_u16.to_le_bytes());
        hasher.update(&(fcomment.len() as u16).to_le_bytes());
        hasher.update(&(if disk_z64 { u16::MAX } else { disk_start }).to_le_bytes());
        hasher.update(&internal_attr.to_le_bytes());
        hasher.update(&external_attr.to_le_bytes());
        hasher.update(
            &(if off_z64 {
                u32::MAX
            } else {
                u32::try_from(off_u64).map_err(|_| anyhow!("local header offset overflow"))?
            })
            .to_le_bytes(),
        );
        hasher.update(fname);
        hasher.update(&syn);
        hasher.update(fcomment);

        let written = 46u64
            .saturating_add(fname.len() as u64)
            .saturating_add(u64::from(syn_len_u16))
            .saturating_add(fcomment.len() as u64);
        cd_size = cd_size
            .checked_add(written)
            .ok_or_else(|| anyhow!("cd_size overflow"))?;
        no_entries = no_entries
            .checked_add(1)
            .ok_or_else(|| anyhow!("too many entries"))?;
    }

    let no_entries_u64 = u64::from(no_entries);

    if let Some(z) = &tail.zip64_eocd {
        let loc = tail
            .locator
            .as_ref()
            .ok_or_else(|| anyhow!("ZIP64 EOCD without locator"))?;
        hasher.update(&ZIP64_EOCD_SIG.to_le_bytes());
        hasher.update(&z.record_size.to_le_bytes());
        hasher.update(&z.version_made_by.to_le_bytes());
        hasher.update(&z.version_needed_to_extract.to_le_bytes());
        hasher.update(&z.disk_number.to_le_bytes());
        hasher.update(&z.disk_with_central_directory.to_le_bytes());
        hasher.update(&no_entries_u64.to_le_bytes());
        hasher.update(&no_entries_u64.to_le_bytes());
        hasher.update(&cd_size.to_le_bytes());
        hasher.update(&cd_offset_virtual.to_le_bytes());
        hasher.update(&z.tail_after_fixed);

        hasher.update(&ZIP64_LOC_SIG.to_le_bytes());
        hasher.update(&loc.disk_with_central_directory.to_le_bytes());
        hasher.update(&(cd_offset_virtual.saturating_add(cd_size)).to_le_bytes());
        hasher.update(&loc.number_of_disks.to_le_bytes());
    }

    let c = &tail.classic;
    hasher.update(&EOCD_SIG.to_le_bytes());
    hasher.update(&0u16.to_le_bytes());
    hasher.update(&0u16.to_le_bytes());
    hasher.update(
        &(if c.number_of_files_on_this_disk != u16::MAX {
            no_entries
        } else {
            u16::MAX
        })
        .to_le_bytes(),
    );
    hasher.update(
        &(if c.number_of_files != u16::MAX {
            no_entries
        } else {
            u16::MAX
        })
        .to_le_bytes(),
    );
    hasher.update(
        &(if c.central_directory_size != u32::MAX {
            u32::try_from(cd_size).map_err(|_| anyhow!("cd_size does not fit u32"))?
        } else {
            u32::MAX
        })
        .to_le_bytes(),
    );
    hasher.update(
        &(if c.central_directory_offset != u32::MAX {
            u32::try_from(cd_offset_virtual).map_err(|_| anyhow!("cd_offset does not fit u32"))?
        } else {
            u32::MAX
        })
        .to_le_bytes(),
    );
    hasher.update(&(c.zip_file_comment.len() as u16).to_le_bytes());
    hasher.update(&c.zip_file_comment);

    Ok(hasher.finalize())
}

fn read_zip_entry_raw(archive: &mut ZipArchive<Cursor<&[u8]>>, name: &str) -> Result<Vec<u8>> {
    let mut f = archive.by_name(name)?;
    let mut v = Vec::new();
    f.read_to_end(&mut v)?;
    Ok(v)
}

fn hash_bytes(kind: PeAuthenticodeHashKind, bytes: &[u8]) -> Vec<u8> {
    let mut h = RunningHasher::new(kind);
    h.update(bytes);
    h.finalize()
}

fn zip_has_bundle_manifest(archive: &ZipArchive<Cursor<&[u8]>>) -> bool {
    let name = std::str::from_utf8(BUNDLE_MANIFEST).expect("ASCII path");
    archive.file_names().any(|n| n == name)
}

/// Encrypted package extensions (`CryptSIPDll*` **`EappxSip*`** / **`EappxBundleSip*`** rows). Cleartext ZIP hash parity ([`verify_msix_digest_consistency`]) does **not** apply.
///
/// `ext` should be the path extension in ASCII lowercase (no dot).
#[inline]
pub fn is_encrypted_msix_extension(ext: &str) -> bool {
    matches!(ext, "eappx" | "eappxbundle" | "emsix" | "emsixbundle")
}

/// Compare PKCS#7 APPX indirect blob with osslsigncode-style MSIX / APPX bundle ZIP hashes (`AppxSip.dll` semantics).
pub fn verify_msix_digest_consistency(path: &Path) -> Result<()> {
    let ext = path
        .extension()
        .and_then(|x| x.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if is_encrypted_msix_extension(&ext) {
        return Err(anyhow!(
            "Rust MSIX SIP digest parity applies only to cleartext OPC/ZIP packages (.msix, .appx, bundles); \
             encrypted packages (.eappx, .emsix, …) use AppxSip `EappxSip*` / Windows crypto — rely on WinVerifyTrust"
        ));
    }
    if !matches!(ext.as_str(), "msix" | "appx" | "msixbundle" | "appxbundle") {
        return Err(anyhow!(
            "Rust MSIX SIP digest check applies only to `.msix` / `.appx` / `.msixbundle` / `.appxbundle` files"
        ));
    }

    let buf = std::fs::read(path)?;
    let tail = parse_zip_tail(&buf)?;
    let mut archive = ZipArchive::new(Cursor::new(buf.as_slice()))?;
    if matches!(ext.as_str(), "msixbundle" | "appxbundle") && !zip_has_bundle_manifest(&archive) {
        return Err(anyhow!(
            "missing `{}` — not a valid {} bundle ZIP",
            std::str::from_utf8(BUNDLE_MANIFEST).expect("ASCII"),
            ext
        ));
    }

    let p7x = read_zip_entry_raw(&mut archive, std::str::from_utf8(APP_SIGNATURE)?)?;
    let pkcs7 = strip_pkcx(&p7x)?;
    let sig = AuthenticodeSignature::from_bytes(pkcs7)
        .map_err(|e| anyhow!("MSIX PKCS#7 parse failed: {e}"))?;
    let embedded = sig.digest();

    let (piece_len, parts) = parse_signed_appx_blob(embedded)?;

    let block_map_bytes = read_zip_entry_raw(&mut archive, std::str::from_utf8(BLOCK_MAP)?)?;
    let kind = hash_kind_from_block_map_xml(&block_map_bytes)?;
    let expected_piece = kind.digest_output_len();
    if piece_len != expected_piece {
        return Err(anyhow!(
            "PKCS#7 APPX digest width {piece_len} does not match AppxBlockMap HashMethod ({expected_piece})"
        ));
    }

    let ct_raw = read_zip_entry_raw(&mut archive, std::str::from_utf8(CONTENT_TYPES)?)?;
    let bm_raw = read_zip_entry_raw(&mut archive, std::str::from_utf8(BLOCK_MAP)?)?;

    let code_integrity_name = std::str::from_utf8(CODE_INTEGRITY).expect("ASCII path");
    let ci_expected = archive.file_names().any(|n| n == code_integrity_name);
    let ci_raw = if ci_expected {
        Some(read_zip_entry_raw(
            &mut archive,
            std::str::from_utf8(CODE_INTEGRITY)?,
        )?)
    } else {
        None
    };

    if ci_expected != parts.axci.is_some() {
        return Err(anyhow!(
            "CodeIntegrity.cat presence does not match PKCS#7 AXCI block"
        ));
    }

    let ct_hash = hash_bytes(kind, &ct_raw);
    let bm_hash = hash_bytes(kind, &bm_raw);
    let ci_hash = match (&ci_raw, &parts.axci) {
        (Some(data), Some(_)) => Some(hash_bytes(kind, data)),
        (None, None) => None,
        _ => unreachable!(),
    };

    let mut archive2 = ZipArchive::new(Cursor::new(buf.as_slice()))?;
    let (data_hash, cd_off_virt) = hash_zip_file_data(&buf, &mut archive2, &tail, kind)?;
    let mut archive3 = ZipArchive::new(Cursor::new(buf.as_slice()))?;
    let cd_hash = hash_cd_and_eocd(&buf, &mut archive3, &tail, kind, cd_off_virt)?;

    let check = |label: &str, a: &[u8], b: &[u8]| -> Result<()> {
        if a != b {
            return Err(anyhow!(
                "MSIX Authenticode {label} mismatch (Rust SIP vs PKCS#7 APPX blob)"
            ));
        }
        Ok(())
    };

    check("AXPC (payload)", &data_hash, &parts.axpc)?;
    check("AXCD (central directory)", &cd_hash, &parts.axcd)?;
    check("AXCT ([Content_Types].xml)", &ct_hash, &parts.axct)?;
    check("AXBM (AppxBlockMap.xml)", &bm_hash, &parts.axbm)?;
    if let (Some(ch), Some(sig_ci)) = (&ci_hash, &parts.axci) {
        check("AXCI (CodeIntegrity.cat)", ch, sig_ci)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_appx_blob_roundtrip_widths() {
        let mut blob = Vec::from(SIG_APPX);
        let z = [7u8; 32];
        for t in [TAG_AXPC, TAG_AXCD, TAG_AXCT, TAG_AXBM] {
            blob.extend_from_slice(t);
            blob.extend_from_slice(&z);
        }
        let (ml, p) = parse_signed_appx_blob(&blob).unwrap();
        assert_eq!(ml, 32);
        assert!(p.axci.is_none());

        blob.extend_from_slice(TAG_AXCI);
        blob.extend_from_slice(&z);
        let (ml2, p2) = parse_signed_appx_blob(&blob).unwrap();
        assert_eq!(ml2, 32);
        assert!(p2.axci.is_some());
    }

    #[test]
    fn hash_method_parses_sha256_uri() {
        let xml = br#"<?xml version="1.0"?><BlockMap HashMethod="http://www.w3.org/2001/04/xmlenc#sha256" />"#;
        assert_eq!(
            hash_kind_from_block_map_xml(xml).unwrap(),
            PeAuthenticodeHashKind::Sha256
        );
    }

    #[test]
    fn encrypted_msix_extension_is_detected() {
        assert!(is_encrypted_msix_extension("emsix"));
        assert!(is_encrypted_msix_extension("eappxbundle"));
        assert!(!is_encrypted_msix_extension("msix"));
    }

    #[test]
    fn verify_rejects_encrypted_msix_by_extension() {
        let dir = std::env::temp_dir();
        let p = dir.join("signtool_rs_fake_encrypted.emsix");
        std::fs::write(&p, b"not-a-real-package").expect("write temp");
        let err = verify_msix_digest_consistency(&p).unwrap_err();
        let _ = std::fs::remove_file(&p);
        let msg = format!("{err:#}");
        assert!(
            msg.contains("encrypted") && msg.contains("Eappx"),
            "unexpected message: {msg}"
        );
    }
}
