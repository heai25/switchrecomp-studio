//! NSZ / XCZ: NSP and XCI files whose NCAs were compressed into NCZ files (zstd).
//!
//! An NCZ keeps the NCA's first 0x4000 bytes as they are (the encrypted header), then:
//!   "NCZSECTN", u64 section count, and per section: u64 offset, u64 size, u64 crypto type, u64 padding,
//!   16-byte key, 16-byte counter;
//!   then either "NCZBLOCK" (u8 version, u8 type, u8 unused, u8 block size exponent, u32 block count,
//!   u64 decompressed size, u32 compressed size per block; a block is stored raw when compression did not
//!   shrink it), or one zstd stream.
//! The decompressed bytes are the NCA from 0x4000 on, with the listed sections in plaintext. We re-encrypt
//! them (AES-CTR with the section key and counter, block offset from the NCA start) to get the original NCA
//! back, so the normal decrypt path runs on it and checks its hashes.

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::aes::{ctr_apply, Aes128, Xts};
use super::keys::Keys;
use super::{container_entries, read_at, Entry, NCA_HEADER};

const PREFIX: u64 = 0x4000;

struct Section {
    offset: u64,
    size: u64,
    crypto: u64,
    aes: Aes128,
    iv_high: u64,
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// The NCA's full size, from its (decrypted) header.
fn nca_size(prefix: &[u8], keys: &Keys) -> Result<u64, String> {
    let mut h = prefix[..NCA_HEADER].to_vec();
    if !matches!(&h[0x200..0x204], b"NCA3" | b"NCA2") {
        let key = keys.key32("header_key").ok_or("prod.keys has no header_key")?;
        Xts::new(&key).decrypt(&mut h, 0, 0x200);
    }
    if !matches!(&h[0x200..0x204], b"NCA3" | b"NCA2") {
        return Err("the NCZ's NCA header did not decrypt".into());
    }
    Ok(u64_at(&h, 0x208))
}

/// Re-encrypts plaintext NCA bytes that start at absolute NCA offset `at`.
fn encrypt(sections: &[Section], at: u64, buf: &mut [u8]) {
    for s in sections.iter().filter(|s| s.crypto == 3 || s.crypto == 4) {
        let start = s.offset.max(at);
        let end = (s.offset + s.size).min(at + buf.len() as u64);
        if start < end {
            let range = &mut buf[(start - at) as usize..(end - at) as usize];
            ctr_apply(&s.aes, s.iv_high, start, range);
        }
    }
}

/// Converts the NCZ at `base..base+len` of `r` back into its NCA, written to `w`; returns the NCA size.
pub fn ncz_to_nca<R: Read + Seek, W: Write>(r: &mut R, base: u64, len: u64, keys: &Keys, w: &mut W) -> Result<u64, String> {
    let prefix = read_at(r, base, PREFIX as usize).map_err(|e| e.to_string())?;
    let total = nca_size(&prefix, keys)?;
    w.write_all(&prefix).map_err(|e| e.to_string())?;
    let head = read_at(r, base + PREFIX, 16).map_err(|e| e.to_string())?;
    if &head[..8] != b"NCZSECTN" {
        return Err("not an NCZ (no NCZSECTN header)".into());
    }
    let count = u64_at(&head, 8) as usize;
    // updates split their patch sections into one entry per AesCtrEx generation range: often 100+
    if count > 1 << 16 {
        return Err("NCZ section count is implausible".into());
    }
    let table = read_at(r, base + PREFIX + 16, count * 0x40).map_err(|e| e.to_string())?;
    let sections: Vec<Section> = (0..count)
        .map(|i| {
            let e = &table[i * 0x40..(i + 1) * 0x40];
            Section {
                offset: u64_at(e, 0),
                size: u64_at(e, 8),
                crypto: u64_at(e, 16),
                aes: Aes128::new(e[0x20..0x30].try_into().unwrap()),
                iv_high: u64::from_be_bytes(e[0x30..0x38].try_into().unwrap()),
            }
        })
        .collect();
    let mut at = base + PREFIX + 16 + table.len() as u64;
    let end = base + len;
    let want = total.saturating_sub(PREFIX);
    let mut produced = 0u64;
    let mut out = |plain: &mut [u8], produced: &mut u64| -> Result<(), String> {
        let n = (plain.len() as u64).min(want - *produced) as usize;
        let chunk = &mut plain[..n];
        encrypt(&sections, PREFIX + *produced, chunk);
        w.write_all(chunk).map_err(|e| e.to_string())?;
        *produced += n as u64;
        Ok(())
    };
    let magic = read_at(r, at, 8).map_err(|e| e.to_string())?;
    if &magic == b"NCZBLOCK" {
        let bh = read_at(r, at, 0x18).map_err(|e| e.to_string())?;
        let exponent = bh[11] as u32;
        let blocks = u32_at(&bh, 12) as usize;
        let size = u64_at(&bh, 16);
        if !(14..=32).contains(&exponent) || blocks > 1 << 24 {
            return Err("NCZ block header is implausible".into());
        }
        let block = 1u64 << exponent;
        let sizes = read_at(r, at + 0x18, blocks * 4).map_err(|e| e.to_string())?;
        at += 0x18 + sizes.len() as u64;
        r.seek(SeekFrom::Start(at)).map_err(|e| e.to_string())?;
        let mut raw = Vec::new();
        for b in 0..blocks {
            let csize = u32_at(&sizes, b * 4) as usize;
            let dsize = block.min(size - b as u64 * block) as usize;
            raw.resize(csize, 0);
            r.read_exact(&mut raw).map_err(|e| format!("NCZ block {b}: {e}"))?;
            let mut plain = if csize < dsize {
                let mut d = Vec::with_capacity(dsize);
                ruzstd::decoding::StreamingDecoder::new(&raw[..])
                    .map_err(|e| format!("NCZ block {b}: {e}"))?
                    .read_to_end(&mut d)
                    .map_err(|e| format!("NCZ block {b}: {e}"))?;
                d
            } else {
                raw.clone()
            };
            if plain.len() != dsize {
                return Err(format!("NCZ block {b} decompressed to {} bytes, expected {dsize}", plain.len()));
            }
            out(&mut plain, &mut produced)?;
        }
    } else {
        r.seek(SeekFrom::Start(at)).map_err(|e| e.to_string())?;
        let mut limited = BufReader::with_capacity(1 << 20, (&mut *r).take(end - at));
        let mut buf = vec![0u8; 4 << 20];
        // a stream can hold several zstd frames back to back
        while produced < want {
            let mut dec = match ruzstd::decoding::StreamingDecoder::new(&mut limited) {
                Ok(d) => d,
                Err(e) => return Err(format!("NCZ zstd stream: {e}")),
            };
            loop {
                let n = dec.read(&mut buf).map_err(|e| format!("NCZ zstd stream: {e}"))?;
                if n == 0 {
                    break;
                }
                out(&mut buf[..n], &mut produced)?;
                if produced >= want {
                    break;
                }
            }
            if produced < want && limited.fill_buf().map_err(|e| e.to_string())?.is_empty() {
                break;
            }
        }
    }
    if produced != want {
        return Err(format!("NCZ decompressed to {} bytes, the NCA header says {}", produced + PREFIX, total));
    }
    Ok(total)
}

use std::io::BufRead;

/// Writes an NSP holding the container's files with every .ncz turned back into its .nca.
pub fn uncompress_to_nsp(input: &Path, out: &Path, keys: &Keys) -> Result<(), String> {
    let mut r = BufReader::with_capacity(1 << 20, File::open(input).map_err(|e| format!("{}: {e}", input.display()))?);
    let (_, entries) = container_entries(&mut r, input)?;
    // sizes first: an NCA's size is in its header
    let mut plan: Vec<(String, Entry, Option<u64>)> = Vec::new();
    for e in entries {
        if let Some(stem) = e.name.strip_suffix(".ncz") {
            let prefix = read_at(&mut r, e.offset, PREFIX as usize).map_err(|err| format!("{}: {err}", e.name))?;
            let size = nca_size(&prefix, keys).map_err(|err| format!("{}: {err}", e.name))?;
            plan.push((format!("{stem}.nca"), e, Some(size)));
        } else {
            plan.push((e.name.clone(), e, None));
        }
    }
    let mut strings = Vec::new();
    let mut table = Vec::new();
    let mut data_at = 0u64;
    for (name, e, size) in &plan {
        let size = size.unwrap_or(e.size);
        table.extend(data_at.to_le_bytes());
        table.extend(size.to_le_bytes());
        table.extend((strings.len() as u32).to_le_bytes());
        table.extend(0u32.to_le_bytes());
        strings.extend(name.as_bytes());
        strings.push(0);
        data_at += size;
    }
    while (16 + table.len() + strings.len()) % 0x20 != 0 {
        strings.push(0);
    }
    let mut w = BufWriter::with_capacity(8 << 20, File::create(out).map_err(|e| format!("{}: {e}", out.display()))?);
    let mut header = b"PFS0".to_vec();
    header.extend((plan.len() as u32).to_le_bytes());
    header.extend((strings.len() as u32).to_le_bytes());
    header.extend(0u32.to_le_bytes());
    for part in [&header, &table, &strings] {
        w.write_all(part).map_err(|e| e.to_string())?;
    }
    for (name, e, size) in &plan {
        match size {
            Some(expected) => {
                eprintln!("switchrecomp: uncompressing {} ({:.1} MiB)", e.name, *expected as f64 / (1u64 << 20) as f64);
                let n = ncz_to_nca(&mut r, e.offset, e.size, keys, &mut w).map_err(|err| format!("{}: {err}", e.name))?;
                if n != *expected {
                    return Err(format!("{name}: size changed while uncompressing"));
                }
            }
            None => {
                r.seek(SeekFrom::Start(e.offset)).map_err(|err| err.to_string())?;
                let n = io::copy(&mut (&mut r).take(e.size), &mut w).map_err(|err| err.to_string())?;
                if n != e.size {
                    return Err(format!("{name}: short read"));
                }
            }
        }
    }
    w.flush().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn ncz(prefix: &[u8], key: [u8; 16], counter: u64, body_plain: &[u8], block: bool) -> Vec<u8> {
        let mut out = prefix.to_vec();
        out.extend(b"NCZSECTN");
        out.extend(1u64.to_le_bytes());
        out.extend(PREFIX.to_le_bytes());
        out.extend((body_plain.len() as u64).to_le_bytes());
        out.extend(3u64.to_le_bytes());
        out.extend(0u64.to_le_bytes());
        out.extend(key);
        out.extend(counter.to_be_bytes());
        out.extend(0u64.to_be_bytes());
        if block {
            let exp = 14u8;
            let bs = 1usize << exp;
            let chunks: Vec<&[u8]> = body_plain.chunks(bs).collect();
            let comp: Vec<Vec<u8>> = chunks.iter().map(|c| ruzstd::encoding::compress_to_vec(*c, ruzstd::encoding::CompressionLevel::Fastest)).collect();
            out.extend(b"NCZBLOCK");
            out.extend([2u8, 1, 0, exp]);
            out.extend((chunks.len() as u32).to_le_bytes());
            out.extend((body_plain.len() as u64).to_le_bytes());
            for (c, raw) in comp.iter().zip(&chunks) {
                let stored = c.len() >= raw.len();
                out.extend((if stored { raw.len() } else { c.len() } as u32).to_le_bytes());
            }
            for (c, raw) in comp.iter().zip(&chunks) {
                if c.len() >= raw.len() { out.extend(*raw) } else { out.extend(c) }
            }
        } else {
            out.extend(ruzstd::encoding::compress_to_vec(body_plain, ruzstd::encoding::CompressionLevel::Fastest));
        }
        out
    }

    #[test]
    fn ncz_round_trips_to_the_encrypted_nca() {
        let header_key = [0x42u8; 32];
        let keys = Keys::from_parts(&[("header_key", &header_key)], &[]);
        let body: Vec<u8> = (0..0x9000u32).map(|i| (i % 251) as u8).chain(std::iter::repeat_n(0u8, 0x8000)).collect();
        let total = PREFIX + body.len() as u64;
        let mut h = vec![0u8; PREFIX as usize];
        h[0x200..0x204].copy_from_slice(b"NCA3");
        h[0x208..0x210].copy_from_slice(&total.to_le_bytes());
        let mut enc_head = h[..0xc00].to_vec();
        Xts::new(&header_key).encrypt(&mut enc_head, 0, 0x200);
        h[..0xc00].copy_from_slice(&enc_head);
        let key = [9u8; 16];
        let counter = 0x0102030405060708u64;
        let mut expected_body = body.clone();
        ctr_apply(&Aes128::new(&key), counter, PREFIX, &mut expected_body);
        for block in [false, true] {
            let file = ncz(&h, key, counter, &body, block);
            let mut nca = Vec::new();
            let n = ncz_to_nca(&mut Cursor::new(&file), 0, file.len() as u64, &keys, &mut nca).expect("uncompresses");
            assert_eq!(n, total);
            assert_eq!(&nca[..PREFIX as usize], &h[..]);
            assert_eq!(&nca[PREFIX as usize..], &expected_body[..], "block mode {block}");
        }
    }
}

/// Whether a container holds NCZ files.
pub fn has_ncz(path: &Path) -> Result<bool, String> {
    let mut r = BufReader::new(File::open(path).map_err(|e| format!("{}: {e}", path.display()))?);
    let (_, entries) = container_entries(&mut r, path)?;
    Ok(entries.iter().any(|e| e.name.ends_with(".ncz")))
}

/// For an NSZ/XCZ, an uncompressed temporary NSP next to `out` (Some(path), delete it when done); else None.
pub fn uncompressed_copy(path: &Path, out: &Path, keys: &Keys) -> Result<Option<PathBuf>, String> {
    if !has_ncz(path)? {
        return Ok(None);
    }
    let mut name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(".uncompressed.nsp");
    let dir = out.parent().map(Path::to_path_buf).unwrap_or_default();
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let tmp = dir.join(name);
    uncompress_to_nsp(path, &tmp, keys)?;
    Ok(Some(tmp))
}
