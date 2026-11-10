//! switchrecomp-studio's own decryption: turns an encrypted NSP, XCI or NCA dumped from your own
//! console into the extracted folder layout the recompiler reads (exefs/, romfs.bin, control.nacp,
//! content.cnmt), using your prod.keys / title.keys.
//!
//! Accuracy rules: every ExeFS block is checked against the NCA's SHA-256 hash table, so a wrong
//! key or a damaged dump stops with an exact reason instead of producing garbage code.

pub mod aes;
pub mod keys;
pub mod ncz;
pub mod patch;
pub mod rsa;
pub mod sha256;

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use aes::{ctr_apply, Aes128, Xts};
use keys::Keys;
use kirikae_loader::{cnmt, nca as knca, pfs0};

pub const NCA_HEADER: usize = 0xc00;

#[derive(Clone, Debug)]
pub struct Entry {
    pub name: String,
    pub offset: u64,
    pub size: u64,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

fn read_at<R: Read + Seek>(r: &mut R, at: u64, len: usize) -> io::Result<Vec<u8>> {
    r.seek(SeekFrom::Start(at))?;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

// ---------------------------------------------------------------- containers

fn hfs0<R: Read + Seek>(r: &mut R, base: u64) -> Result<Vec<Entry>, String> {
    let head = read_at(r, base, 0x10).map_err(|e| e.to_string())?;
    if &head[..4] != b"HFS0" {
        return Err(format!("expected an HFS0 partition at {base:#x}"));
    }
    let count = u32_at(&head, 4) as usize;
    let strings = u32_at(&head, 8) as usize;
    if count > 0x10000 || strings > 0x100_0000 {
        return Err("HFS0 header is implausible".into());
    }
    let table = read_at(r, base + 0x10, count * 0x40 + strings).map_err(|e| e.to_string())?;
    let names = &table[count * 0x40..];
    let data = base + 0x10 + table.len() as u64;
    (0..count)
        .map(|i| {
            let e = &table[i * 0x40..i * 0x40 + 0x40];
            let at = u32_at(e, 0x10) as usize;
            let tail = names.get(at..).ok_or("HFS0 name offset")?;
            let len = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
            Ok(Entry { name: String::from_utf8_lossy(&tail[..len]).into_owned(), offset: data + u64_at(e, 0), size: u64_at(e, 8) })
        })
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Container {
    Nsp,
    Xci,
    Nca,
}

/// The NCAs (and tickets) inside an NSP, an XCI's secure partition, or a lone NCA file.
pub fn container_entries<R: Read + Seek>(r: &mut R, path: &Path) -> Result<(Container, Vec<Entry>), String> {
    let len = r.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
    let head = read_at(r, 0, 0x200.min(len as usize)).map_err(|e| e.to_string())?;
    if head.starts_with(b"PFS0") {
        let entries = pfs0::parse(r, 0).map_err(|e| e.to_string())?;
        return Ok((Container::Nsp, entries.into_iter().map(|e| Entry { name: e.name, offset: e.offset, size: e.size }).collect()));
    }
    if head.len() >= 0x140 && &head[0x100..0x104] == b"HEAD" {
        let root = hfs0(r, u64_at(&head, 0x130))?;
        let secure = root.iter().find(|e| e.name == "secure").ok_or("the XCI has no secure partition")?;
        return Ok((Container::Xci, hfs0(r, secure.offset)?));
    }
    if path.extension().is_some_and(|x| x.eq_ignore_ascii_case("nca")) || len >= NCA_HEADER as u64 {
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "content.nca".into());
        return Ok((Container::Nca, vec![Entry { name, offset: 0, size: len }]));
    }
    Err("not an NSP, XCI or NCA".into())
}

/// Common-ticket title keys carried in the dump itself (rights ID -> encrypted title key).
pub fn ticket_key(t: &[u8]) -> Option<([u8; 16], [u8; 16])> {
    if t.len() < 4 {
        return None;
    }
    let (size, pad) = match u32_at(t, 0) {
        0x10000 | 0x10003 => (0x200, 0x3c),
        0x10001 | 0x10004 => (0x100, 0x3c),
        0x10002 | 0x10005 => (0x3c, 0x40),
        _ => return None,
    };
    let body = 4 + size + pad;
    if t.len() < body + 0x180 || t[body + 0x141] != 0 {
        return None; // personalised: see resolve_ticket
    }
    Some((t[body + 0x160..body + 0x170].try_into().unwrap(), t[body + 0x40..body + 0x50].try_into().unwrap()))
}

/// A ticket's (rights ID, encrypted title key): common tickets directly, personalized ones unwrapped with
/// the console's eTicket RSA key when PRODINFO and eticket_rsa_kek are available. Personalized tickets that
/// cannot be unwrapped return None (title.keys may still have the key).
pub fn resolve_ticket(t: &[u8], keys: &Keys) -> Option<([u8; 16], [u8; 16])> {
    if let Some(k) = ticket_key(t) {
        return Some(k);
    }
    let (size, pad) = match u32_at(t, 0) {
        0x10000 | 0x10003 => (0x200, 0x3c),
        0x10001 | 0x10004 => (0x100, 0x3c),
        0x10002 | 0x10005 => (0x3c, 0x40),
        _ => return None,
    };
    let body = 4 + size + pad;
    if t.len() < body + 0x180 || t[body + 0x141] != 1 {
        return None;
    }
    let rights: [u8; 16] = t[body + 0x160..body + 0x170].try_into().unwrap();
    let key = keys.eticket()?.unwrap_title_key(&t[body + 0x40..body + 0x140]).ok()?;
    Some((rights, key))
}

// ---------------------------------------------------------------- NCA

#[derive(Clone, Debug)]
pub enum KeySource {
    KeyArea(String),
    Ticket,
    TitleKeys,
}

pub struct DecNca {
    pub name: String,
    pub base: u64,
    pub header: Vec<u8>,
    pub info: knca::Nca,
    pub was_encrypted: bool,
    pub master_key: u8,
    #[allow(dead_code)]
    pub rights_id: [u8; 16],
    key: Result<([u8; 16], KeySource), String>,
}

fn key_for(h: &[u8], keys: &Keys, tickets: &HashMap<[u8; 16], [u8; 16]>, master: u8) -> Result<([u8; 16], KeySource), String> {
    let newest = keys.newest_generation().map_or("none".to_string(), |g| format!("{g:02x}"));
    let rights: [u8; 16] = h[0x230..0x240].try_into().unwrap();
    if rights != [0; 16] {
        let (mut tk, src) = match tickets.get(&rights) {
            Some(k) => (*k, KeySource::Ticket),
            None => (
                keys.title_key(&rights).ok_or_else(|| format!("no title key for rights ID {} (not in the dump's ticket nor in title.keys)", hex(&rights)))?,
                KeySource::TitleKeys,
            ),
        };
        let name = format!("titlekek_{master:02x}");
        let kek = keys.key16(&name).ok_or_else(|| format!("prod.keys lacks {name}: this content needs master key {master:02x}, your keys go up to {newest}; dump keys from a console on newer firmware"))?;
        Aes128::new(&kek).decrypt_block(&mut tk);
        return Ok((tk, src));
    }
    let kind = match h[0x207] {
        0 => "application",
        1 => "ocean",
        2 => "system",
        other => return Err(format!("unknown key area index {other}")),
    };
    let name = format!("key_area_key_{kind}_{master:02x}");
    let kak = keys.key16(&name).ok_or_else(|| format!("prod.keys lacks {name}: this content needs master key {master:02x}, your keys go up to {newest}; dump keys from a console on newer firmware"))?;
    let mut area = h[0x300..0x340].to_vec();
    Aes128::new(&kak).ecb_decrypt(&mut area);
    Ok((area[0x20..0x30].try_into().unwrap(), KeySource::KeyArea(name)))
}

pub fn open_nca<R: Read + Seek>(r: &mut R, e: &Entry, keys: &Keys, tickets: &HashMap<[u8; 16], [u8; 16]>) -> Result<DecNca, String> {
    let raw = read_at(r, e.offset, NCA_HEADER).map_err(|err| format!("{}: {err}", e.name))?;
    let mut h = raw.clone();
    let plain = |m: &[u8]| matches!(m, b"NCA3" | b"NCA2" | b"DNCA");
    let was_encrypted = !plain(&raw[0x200..0x204]);
    if was_encrypted {
        let header_key = keys.key32("header_key").ok_or("prod.keys has no header_key")?;
        let xts = Xts::new(&header_key);
        xts.decrypt(&mut h, 0, 0x200);
        match &h[0x200..0x204] {
            b"NCA3" => {}
            b"NCA2" => {
                for i in 0..4 {
                    let at = 0x400 + i * 0x200;
                    let mut fs = raw[at..at + 0x200].to_vec();
                    xts.decrypt(&mut fs, 0, 0x200);
                    h[at..at + 0x200].copy_from_slice(&fs);
                }
            }
            b"NCA0" => return Err(format!("{}: NCA0 (pre-release format) is not supported", e.name)),
            _ => return Err(format!("{}: the header did not decrypt with your header_key (wrong key file, or not an NCA)", e.name)),
        }
    }
    let master = h[0x206].max(h[0x220]).saturating_sub(1);
    let mut patched = h.clone();
    patched[0x200..0x204].copy_from_slice(b"DNCA");
    let mut info = knca::parse(&mut Cursor::new(&patched), 0).map_err(|err| format!("{}: {err}", e.name))?;
    info.base = e.offset;
    for s in &mut info.sections {
        s.start += e.offset;
        s.end += e.offset;
        s.data_offset += e.offset;
    }
    let key = if was_encrypted { key_for(&h, keys, tickets, master) } else { Err("plaintext".into()) };
    Ok(DecNca { name: e.name.clone(), base: e.offset, rights_id: h[0x230..0x240].try_into().unwrap(), header: h, info, was_encrypted, master_key: master, key })
}

/// Reads an NCA section as plaintext. Positions are absolute offsets in the container file.
pub struct SectionReader<'a, R> {
    r: &'a mut R,
    nca_base: u64,
    end: u64,
    aes: Option<Aes128>,
    iv: u64,
    pos: u64,
}

impl<R: Read + Seek> Read for SectionReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.end {
            return Ok(0);
        }
        let n = buf.len().min((self.end - self.pos) as usize);
        self.r.seek(SeekFrom::Start(self.pos))?;
        self.r.read_exact(&mut buf[..n])?;
        if let Some(aes) = &self.aes {
            ctr_apply(aes, self.iv, self.pos - self.nca_base, &mut buf[..n]);
        }
        self.pos += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for SectionReader<'_, R> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        self.pos = match to {
            SeekFrom::Start(x) => x,
            SeekFrom::Current(d) => self.pos.checked_add_signed(d).ok_or(io::ErrorKind::InvalidInput)?,
            SeekFrom::End(d) => self.end.checked_add_signed(d).ok_or(io::ErrorKind::InvalidInput)?,
        };
        Ok(self.pos)
    }
}

impl DecNca {
    pub fn content_key(&self) -> Option<[u8; 16]> {
        self.key.as_ref().ok().map(|(k, _)| *k)
    }

    pub fn key_source(&self) -> Option<&KeySource> {
        self.key.as_ref().ok().map(|(_, s)| s)
    }

    pub fn fs_header(&self, s: &knca::Section) -> &[u8] {
        &self.header[0x400 + s.index * 0x200..0x600 + s.index * 0x200]
    }

    pub fn reader<'a, R: Read + Seek>(&self, r: &'a mut R, s: &knca::Section) -> Result<SectionReader<'a, R>, String> {
        let aes = if !self.was_encrypted || s.crypto == knca::CRYPTO_NONE {
            None
        } else {
            match s.crypto {
                knca::CRYPTO_CTR | knca::CRYPTO_CTR_SKIP_HASH => {
                    let (key, _) = self.key.as_ref().map_err(|e| format!("{}: {e}", self.name))?;
                    Some(Aes128::new(key))
                }
                knca::CRYPTO_BKTR | knca::CRYPTO_BKTR_SKIP_HASH => {
                    return Err(format!("{}: section {} is an update patch (BKTR) and needs the base game; not supported yet", self.name, s.index));
                }
                knca::CRYPTO_XTS => return Err(format!("{}: section {} uses AES-XTS, which game content never does", self.name, s.index)),
                other => return Err(format!("{}: section {} has unknown encryption type {other}", self.name, s.index)),
            }
        };
        Ok(SectionReader { r, nca_base: self.base, end: s.end, aes, iv: s.nonce, pos: s.start })
    }

    /// Checks a PFS0 section against its SHA-256 hash tree; returns the number of blocks verified.
    pub fn verify_pfs0<R: Read + Seek>(&self, r: &mut R, s: &knca::Section) -> Result<usize, String> {
        let fs = self.fs_header(s).to_vec();
        if s.hash_type != 2 || u32_at(&fs, 0x2c) != 2 {
            return Ok(0);
        }
        let master: [u8; 32] = fs[0x8..0x28].try_into().unwrap();
        let block = u32_at(&fs, 0x28) as u64;
        let (table_off, table_size) = (u64_at(&fs, 0x30), u64_at(&fs, 0x38));
        let (data_off, data_size) = (u64_at(&fs, 0x40), u64_at(&fs, 0x48));
        if block == 0 || table_size > 64 << 20 {
            return Err(format!("{}: implausible hash layout", self.name));
        }
        let mut rd = self.reader(r, s)?;
        let table = read_at(&mut rd, s.start + table_off, table_size as usize).map_err(|e| e.to_string())?;
        let why = |what: &str| {
            let src = match self.key_source() {
                Some(KeySource::KeyArea(n)) => format!("key area decrypted with {n}"),
                Some(KeySource::Ticket) => "title key from the dump's ticket".into(),
                Some(KeySource::TitleKeys) => "title key from title.keys".into(),
                None => "plaintext".into(),
            };
            format!("{}: {what} does not match its SHA-256 hash ({src}, master key {:02x}). The key is wrong for this game or the dump is damaged.", self.name, self.master_key)
        };
        if sha256::sha256(&table) != master {
            return Err(why("the ExeFS hash table"));
        }
        let blocks = data_size.div_ceil(block) as usize;
        if table.len() < blocks * 32 {
            return Err(why("the ExeFS hash table size"));
        }
        let mut buf = vec![0u8; block as usize];
        for i in 0..blocks {
            let at = i as u64 * block;
            let n = block.min(data_size - at) as usize;
            rd.seek(SeekFrom::Start(s.start + data_off + at)).map_err(|e| e.to_string())?;
            rd.read_exact(&mut buf[..n]).map_err(|e| e.to_string())?;
            if sha256::sha256(&buf[..n])[..] != table[i * 32..i * 32 + 32] {
                return Err(why(&format!("ExeFS block {i} of {blocks}")));
            }
        }
        Ok(blocks)
    }

    pub fn pfs0_files<R: Read + Seek>(&self, r: &mut R, s: &knca::Section) -> Result<Vec<(String, Vec<u8>)>, String> {
        let mut rd = self.reader(r, s)?;
        let entries = pfs0::parse(&mut rd, s.data_offset).map_err(|_| {
            format!("{}: section {} did not decrypt to a PFS0 (wrong key for master key {:02x}?)", self.name, s.index, self.master_key)
        })?;
        entries.iter().map(|e| Ok((e.name.clone(), pfs0::read_entry(&mut rd, e).map_err(|err| err.to_string())?))).collect()
    }

    /// One file from the root of a RomFS section (used for control.nacp).
    pub fn romfs_root_file<R: Read + Seek>(&self, r: &mut R, s: &knca::Section, want: &str) -> Result<Option<Vec<u8>>, String> {
        let mut rd = self.reader(r, s)?;
        let head = read_at(&mut rd, s.data_offset, 0x50).map_err(|e| e.to_string())?;
        if u64_at(&head, 0) != 0x50 {
            return Err(format!("{}: section {} did not decrypt to a RomFS", self.name, s.index));
        }
        let (meta_off, meta_size, data_off) = (u64_at(&head, 0x38), u64_at(&head, 0x40), u64_at(&head, 0x48));
        if meta_size > 64 << 20 {
            return Err("RomFS file table is implausible".into());
        }
        let meta = read_at(&mut rd, s.data_offset + meta_off, meta_size as usize).map_err(|e| e.to_string())?;
        let mut at = 0usize;
        while at + 0x20 <= meta.len() {
            let parent = u32_at(&meta, at);
            let (off, size) = (u64_at(&meta, at + 8), u64_at(&meta, at + 0x10));
            let name_len = u32_at(&meta, at + 0x1c) as usize;
            let name = meta.get(at + 0x20..at + 0x20 + name_len).unwrap_or_default();
            if parent == 0 && name == want.as_bytes() {
                return Ok(Some(read_at(&mut rd, s.data_offset + data_off + off, size as usize).map_err(|e| e.to_string())?));
            }
            at += 0x20 + name_len.next_multiple_of(4);
        }
        Ok(None)
    }
}

// ---------------------------------------------------------------- whole packages

pub struct Report {
    pub container: Container,
    pub title_id: u64,
    pub version: u32,
    pub master_key: u8,
    pub key_source: String,
    pub exefs_files: usize,
    pub verified_blocks: usize,
    pub romfs_bytes: u64,
    /// LZ4 blocks decompressed (0 when the RomFS was stored uncompressed)
    pub romfs_lz4_blocks: usize,
    pub warnings: Vec<String>,
}

const BKTR_NODE: usize = 0x4000;
const BKTR_ENTRY: usize = 0x18;
const BKTR_PER_SET: usize = (BKTR_NODE - 0x10) / BKTR_ENTRY;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompressedBlock {
    pub virt: u64,
    pub phys: u64,
    pub kind: u8,
    pub psize: u32,
}

/// Parses a RomFS compression table (a BucketTree). The entry sets are the last nodes of the table,
/// after the L1 and any L2 offset nodes, so tables of any size (L2 included) are read the same way.
pub fn compression_blocks(table: &[u8], entry_count: usize) -> Result<(Vec<CompressedBlock>, u64), String> {
    let bad = |why: &str| format!("RomFS compression table: {why}");
    if entry_count == 0 {
        return Err(bad("no entries"));
    }
    let sets = entry_count.div_ceil(BKTR_PER_SET);
    let nodes = table.len() / BKTR_NODE;
    if nodes < 1 + sets {
        return Err(bad("table is smaller than its entry count needs"));
    }
    let first = nodes - sets;
    let mut blocks = Vec::with_capacity(entry_count);
    let mut end = 0;
    for k in 0..sets {
        let node = &table[(first + k) * BKTR_NODE..(first + k + 1) * BKTR_NODE];
        let (index, count) = (u32_at(node, 0) as usize, u32_at(node, 4) as usize);
        if index != k || count == 0 || count > BKTR_PER_SET {
            return Err(bad(&format!("entry set {k} has an unexpected header (index {index}, {count} entries)")));
        }
        end = u64_at(node, 8);
        for i in 0..count {
            let e = &node[0x10 + i * BKTR_ENTRY..0x10 + (i + 1) * BKTR_ENTRY];
            blocks.push(CompressedBlock { virt: u64_at(e, 0), phys: u64_at(e, 8), kind: e[0x10], psize: u32_at(e, 0x14) });
        }
    }
    if blocks.len() != entry_count {
        return Err(bad(&format!("{} entries found, header says {entry_count}", blocks.len())));
    }
    if blocks[0].virt != 0 || !blocks.windows(2).all(|w| w[0].virt < w[1].virt) || end <= blocks[blocks.len() - 1].virt {
        return Err(bad("block offsets are not in order"));
    }
    Ok((blocks, end))
}

/// Writes the decompressed RomFS of an LZ4-compressed section; returns (bytes written, LZ4 blocks).
fn decompress_romfs<R: Read + Seek>(rd: &mut SectionReader<'_, R>, base: u64, table_off: u64, table_size: u64, entry_count: usize, out: &Path) -> Result<(u64, usize), String> {
    if table_size > 256 << 20 {
        return Err("RomFS compression table is implausibly large".into());
    }
    let table = read_at(rd, base + table_off, table_size as usize).map_err(|e| e.to_string())?;
    let (blocks, total) = compression_blocks(&table, entry_count)?;
    let mut f = io::BufWriter::with_capacity(4 << 20, File::create(out).map_err(|e| format!("{}: {e}", out.display()))?);
    let mut raw = Vec::new();
    let mut lz4_blocks = 0;
    let mut written = 0u64;
    let mut next_note = 512u64 << 20;
    for (i, b) in blocks.iter().enumerate() {
        let vsize = (blocks.get(i + 1).map_or(total, |n| n.virt) - b.virt) as usize;
        if vsize > 1 << 30 {
            return Err(format!("RomFS block {i} is implausibly large"));
        }
        match b.kind {
            0 => {
                raw.resize(vsize, 0);
                rd.seek(SeekFrom::Start(base + b.phys)).map_err(|e| e.to_string())?;
                rd.read_exact(&mut raw).map_err(|e| e.to_string())?;
                f.write_all(&raw).map_err(|e| e.to_string())?;
            }
            1 => {
                raw.clear();
                raw.resize(vsize, 0);
                f.write_all(&raw).map_err(|e| e.to_string())?;
            }
            3 => {
                raw.resize(b.psize as usize, 0);
                rd.seek(SeekFrom::Start(base + b.phys)).map_err(|e| e.to_string())?;
                rd.read_exact(&mut raw).map_err(|e| e.to_string())?;
                let plain = kirikae_loader::lz4::decompress(&raw, vsize).map_err(|e| format!("RomFS LZ4 block {i} at {:#x}: {e}", b.phys))?;
                f.write_all(&plain).map_err(|e| e.to_string())?;
                lz4_blocks += 1;
            }
            other => return Err(format!("RomFS block {i} uses compression type {other}, which is not LZ4 (unsupported)")),
        }
        written += vsize as u64;
        if written >= next_note {
            eprintln!("switchrecomp: RomFS {} / {} MiB (decompressing LZ4)", written >> 20, total >> 20);
            next_note += 512 << 20;
        }
    }
    f.flush().map_err(|e| e.to_string())?;
    Ok((written, lz4_blocks))
}

pub struct Options {
    pub romfs: bool,
}

fn copy_section<R: Read + Seek>(rd: &mut SectionReader<'_, R>, from: u64, len: u64, out: &Path) -> Result<(), String> {
    let mut f = io::BufWriter::new(File::create(out).map_err(|e| format!("{}: {e}", out.display()))?);
    rd.seek(SeekFrom::Start(from)).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 4 << 20];
    let mut left = len;
    let mut next_note = 512u64 << 20;
    while left > 0 {
        let n = (buf.len() as u64).min(left) as usize;
        rd.read_exact(&mut buf[..n]).map_err(|e| e.to_string())?;
        f.write_all(&buf[..n]).map_err(|e| e.to_string())?;
        left -= n as u64;
        if len - left >= next_note {
            eprintln!("switchrecomp: RomFS {} / {} MiB", (len - left) >> 20, len >> 20);
            next_note += 512 << 20;
        }
    }
    f.flush().map_err(|e| e.to_string())
}

/// Decrypts `input` (NSP, XCI or NCA) into `out` as exefs/ + romfs.bin + control.nacp + content.cnmt.
pub fn decrypt_package(input: &Path, out: &Path, keys: &Keys, opts: &Options) -> Result<Report, String> {
    let mut r = BufReader::with_capacity(1 << 20, File::open(input).map_err(|e| format!("{}: {e}", input.display()))?);
    let (container, entries) = container_entries(&mut r, input)?;
    let file_len = r.seek(SeekFrom::End(0)).map_err(|e| e.to_string())?;
    let needed = entries.iter().map(|e| e.offset + e.size).max().unwrap_or(0);
    if needed > file_len {
        let gib = |b: u64| b as f64 / (1u64 << 30) as f64;
        let cut: Vec<&str> = entries.iter().filter(|e| e.offset + e.size > file_len).map(|e| e.name.as_str()).collect();
        return Err(format!(
            "the dump is truncated: its contents need {:.2} GiB but the file is {:.2} GiB, so {} cannot be read. Re-dump or re-copy it.",
            gib(needed),
            gib(file_len),
            cut.join(", ")
        ));
    }
    if entries.iter().any(|e| e.name.ends_with(".ncz")) {
        // NSZ / XCZ: rebuild the original NCAs into a temporary NSP, decrypt that, then delete it
        drop(r);
        let tmp = ncz::uncompressed_copy(input, out, keys)?.ok_or("NCZ files disappeared")?;
        let result = decrypt_package(&tmp, out, keys, opts);
        let _ = std::fs::remove_file(&tmp);
        return result.map(|mut rep| {
            rep.warnings.insert(0, format!("uncompressed from NSZ/XCZ ({})", input.display()));
            rep
        });
    }
    let mut warnings = Vec::new();
    let mut tickets = HashMap::new();
    for e in entries.iter().filter(|e| e.name.ends_with(".tik")) {
        if let Ok(t) = read_at(&mut r, e.offset, e.size.min(0x1000) as usize)
            && let Some((rid, key)) = resolve_ticket(&t, keys)
        {
            tickets.insert(rid, key);
        }
    }
    let mut ncas = Vec::new();
    for e in entries.iter().filter(|e| e.name.ends_with(".nca") || container == Container::Nca) {
        match open_nca(&mut r, e, keys, &tickets) {
            Ok(n) => ncas.push(n),
            Err(err) => warnings.push(err),
        }
    }
    if ncas.is_empty() {
        return Err(format!("no readable NCA in {}{}", input.display(), warnings.first().map(|w| format!(": {w}")).unwrap_or_default()));
    }

    // content metadata, newest first
    let mut metas = Vec::new();
    for n in ncas.iter().filter(|n| n.info.content_type == knca::CONTENT_META) {
        for s in n.info.sections.iter().filter(|s| s.fs_type == knca::FS_PFS0) {
            match n.pfs0_files(&mut r, s) {
                Ok(files) => {
                    if let Some((_, bytes)) = files.into_iter().find(|(name, _)| name.ends_with(".cnmt"))
                        && let Ok(meta) = cnmt::Cnmt::parse(&bytes)
                    {
                        metas.push((meta, bytes));
                    }
                }
                Err(err) => warnings.push(err),
            }
        }
    }
    metas.sort_by(|a, b| b.0.version.cmp(&a.0.version).then(a.0.meta_type.cmp(&b.0.meta_type)));
    let by_id = |id: &[u8; 16]| {
        let name = format!("{}.nca", cnmt::content_id_hex(id));
        ncas.iter().position(|n| n.name.eq_ignore_ascii_case(&name))
    };

    // program candidates: listed by metadata first, then any program NCA
    let mut candidates: Vec<(usize, Option<usize>)> = Vec::new();
    for (mi, (meta, _)) in metas.iter().enumerate() {
        if let Some(i) = meta.content(cnmt::CONTENT_PROGRAM).and_then(|c| by_id(&c.id)) {
            candidates.push((i, Some(mi)));
        }
    }
    for (i, n) in ncas.iter().enumerate() {
        if n.info.content_type == knca::CONTENT_PROGRAM && !candidates.iter().any(|c| c.0 == i) {
            candidates.push((i, None));
        }
    }
    let is_bktr = |n: &DecNca| n.info.sections.iter().any(|s| matches!(s.crypto, knca::CRYPTO_BKTR | knca::CRYPTO_BKTR_SKIP_HASH));
    if candidates.len() > 1 && candidates.iter().any(|c| !is_bktr(&ncas[c.0])) {
        let before = candidates.len();
        candidates.retain(|c| !is_bktr(&ncas[c.0]));
        if candidates.len() < before {
            warnings.push("the dump also holds an update (BKTR patch); it is not applied yet, the base game is used".into());
        }
    }

    let mut chosen = None;
    for (i, mi) in candidates {
        let n = &ncas[i];
        for s in n.info.sections.iter().filter(|s| s.fs_type == knca::FS_PFS0) {
            match n.pfs0_files(&mut r, s) {
                Ok(files) if files.iter().any(|(name, _)| name == "main") => {
                    chosen = Some((i, mi, s.clone(), files));
                    break;
                }
                Ok(_) => {}
                Err(err) => warnings.push(err),
            }
        }
        if chosen.is_some() {
            break;
        }
    }
    let Some((pi, mi, exefs_section, files)) = chosen else {
        return Err(format!("no program NCA with an ExeFS could be decrypted{}", warnings.first().map(|w| format!(": {w}")).unwrap_or_default()));
    };
    let program = &ncas[pi];
    let verified_blocks = program.verify_pfs0(&mut r, &exefs_section)?;

    std::fs::create_dir_all(out.join("exefs")).map_err(|e| format!("{}: {e}", out.display()))?;
    for (name, bytes) in &files {
        std::fs::write(out.join("exefs").join(name), bytes).map_err(|e| e.to_string())?;
    }
    let meta = mi.map(|m| &metas[m]);
    if let Some((_, bytes)) = meta {
        std::fs::write(out.join("content.cnmt"), bytes).map_err(|e| e.to_string())?;
    }

    // control.nacp from the control NCA's RomFS
    let control = meta.and_then(|(m, _)| m.content(cnmt::CONTENT_CONTROL)).and_then(|c| by_id(&c.id)).or_else(|| ncas.iter().position(|n| n.info.content_type == knca::CONTENT_CONTROL));
    if let Some(ci) = control {
        let c = &ncas[ci];
        let mut found = false;
        for s in &c.info.sections {
            let got = if s.fs_type == knca::FS_ROMFS {
                c.romfs_root_file(&mut r, s, "control.nacp")
            } else {
                c.pfs0_files(&mut r, s).map(|f| f.into_iter().find(|(n, _)| n == "control.nacp").map(|(_, b)| b))
            };
            match got {
                Ok(Some(bytes)) => {
                    std::fs::write(out.join("control.nacp"), bytes).map_err(|e| e.to_string())?;
                    found = true;
                    break;
                }
                Ok(None) => {}
                Err(err) => warnings.push(err),
            }
        }
        if !found {
            warnings.push("control.nacp was not found in the control NCA (no title name / save settings)".into());
        }
    }

    // RomFS
    let mut romfs_bytes = 0;
    let mut romfs_lz4_blocks = 0;
    let romfs_path = out.join("romfs.bin");
    let compression_path = out.join("romfs.compression");
    let _ = std::fs::remove_file(&compression_path);
    if let Some(s) = program.info.sections.iter().find(|s| s.fs_type == knca::FS_ROMFS) {
        if !opts.romfs && s.compression.is_some() {
            warnings.push(format!("the RomFS is LZ4-compressed ({} blocks); it was skipped (--no-romfs)", u32_at(program.fs_header(s), 0x190)));
        }
        let is_patch = matches!(s.crypto, knca::CRYPTO_BKTR | knca::CRYPTO_BKTR_SKIP_HASH);
        if opts.romfs && is_patch {
            warnings.push("this is an update: its RomFS is a patch over the base game's; decrypt the base game with --update <this file> to get the patched RomFS".into());
        }
        if opts.romfs && !is_patch {
            let mut rd = program.reader(&mut r, s)?;
            if let Some((off, size)) = s.compression {
                // newer games: the RomFS is stored in LZ4-compressed blocks; write it out decompressed
                let entry_count = u32_at(program.fs_header(s), 0x190) as usize;
                let (len, lz4_blocks) = decompress_romfs(&mut rd, s.data_offset, off, size, entry_count, &romfs_path)?;
                romfs_bytes = len;
                romfs_lz4_blocks = lz4_blocks;
            } else {
                let len = s.data_size.min(s.end.saturating_sub(s.data_offset));
                copy_section(&mut rd, s.data_offset, len, &romfs_path)?;
                romfs_bytes = len;
            }
            let mut magic = [0u8; 8];
            File::open(&romfs_path).and_then(|mut f| f.read_exact(&mut magic)).map_err(|e| e.to_string())?;
            if u64::from_le_bytes(magic) != 0x50 {
                return Err(format!("{}: the RomFS did not decrypt (header check failed, master key {:02x})", program.name, program.master_key));
            }
        }
    } else {
        warnings.push("the program has no RomFS".into());
    }

    let key_source = match program.key_source() {
        Some(KeySource::KeyArea(n)) => format!("key area ({n})"),
        Some(KeySource::Ticket) => "title key from the dump's ticket".into(),
        Some(KeySource::TitleKeys) => "title key from title.keys".into(),
        None => "none (plaintext dump)".into(),
    };
    let title_id = meta.and_then(|(m, _)| m.application_id).unwrap_or(program.info.title_id & !0x800);
    let report = Report {
        container,
        title_id,
        version: meta.map_or(0, |(m, _)| m.version),
        master_key: program.master_key,
        key_source,
        exefs_files: files.len(),
        verified_blocks,
        romfs_bytes,
        romfs_lz4_blocks,
        warnings,
    };
    let mut text = format!(
        "input: {}\ncontainer: {:?}\ntitle: {:016x} v{}\nprogram NCA: {}\nmaster key: {:02x}\nkey: {}\nexefs files: {}\nexefs blocks verified (SHA-256): {}\nromfs bytes: {} (LZ4 blocks decompressed: {})\n",
        input.display(),
        report.container,
        report.title_id,
        report.version,
        program.name,
        report.master_key,
        report.key_source,
        report.exefs_files,
        report.verified_blocks,
        report.romfs_bytes,
        report.romfs_lz4_blocks
    );
    for w in &report.warnings {
        text.push_str(&format!("warning: {w}\n"));
    }
    std::fs::write(out.join("decrypt-report.txt"), text).map_err(|e| e.to_string())?;
    Ok(report)
}

/// Where the decrypted copy of an encrypted dump lives (next to it).
pub fn decrypted_dir_for(input: &Path) -> PathBuf {
    let mut name = input.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    name.push(".decrypted");
    input.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an encrypted NCA3 with one CTR-encrypted, hash-verified PFS0 section, then decrypts it.
    #[test]
    fn decrypts_a_synthetic_encrypted_nca() {
        let header_key = [0x42u8; 32];
        let kak = [0x24u8; 16];
        let content_key = [0x77u8; 16];
        let keys = Keys::from_parts(&[("header_key", &header_key), ("key_area_key_application_00", &kak)], &[]);

        let nso: Vec<u8> = (0..0x300u32).map(|i| i as u8).collect();
        let mut pfs = b"PFS0".to_vec();
        pfs.extend(1u32.to_le_bytes());
        pfs.extend(8u32.to_le_bytes());
        pfs.extend(0u32.to_le_bytes());
        pfs.extend(0u64.to_le_bytes());
        pfs.extend((nso.len() as u64).to_le_bytes());
        pfs.extend(0u32.to_le_bytes());
        pfs.extend(0u32.to_le_bytes());
        pfs.extend(b"main\0\0\0\0");
        pfs.extend(&nso);

        let block = 0x200usize;
        let table: Vec<u8> = pfs.chunks(block).flat_map(|c| sha256::sha256(c)).collect();
        let start = 0xc00usize;
        let data_off = 0x200usize;
        let mut section = vec![0u8; data_off + pfs.len()];
        section[..table.len()].copy_from_slice(&table);
        section[data_off..].copy_from_slice(&pfs);
        let end = (start + section.len()).next_multiple_of(0x200);
        let mut nca = vec![0u8; end];
        nca[start..start + section.len()].copy_from_slice(&section);

        let mut h = vec![0u8; 0xc00];
        h[0x200..0x204].copy_from_slice(b"NCA3");
        h[0x205] = knca::CONTENT_PROGRAM;
        h[0x206] = 0;
        h[0x207] = 0;
        h[0x210..0x218].copy_from_slice(&0x0100_1234_5678_0000u64.to_le_bytes());
        h[0x240..0x244].copy_from_slice(&((start / 0x200) as u32).to_le_bytes());
        h[0x244..0x248].copy_from_slice(&((end / 0x200) as u32).to_le_bytes());
        // key area: encrypt the content key into slot 2 (ECB encrypt with kak)
        let mut slot = content_key;
        Aes128::new(&kak).encrypt_block(&mut slot);
        h[0x320..0x330].copy_from_slice(&slot);
        let fs = 0x400;
        h[fs + 2] = knca::FS_PFS0;
        h[fs + 3] = 2;
        h[fs + 4] = knca::CRYPTO_CTR;
        h[fs + 0x8..fs + 0x28].copy_from_slice(&sha256::sha256(&table));
        h[fs + 0x28..fs + 0x2c].copy_from_slice(&(block as u32).to_le_bytes());
        h[fs + 0x2c..fs + 0x30].copy_from_slice(&2u32.to_le_bytes());
        h[fs + 0x38..fs + 0x40].copy_from_slice(&(table.len() as u64).to_le_bytes());
        h[fs + 0x40..fs + 0x48].copy_from_slice(&(data_off as u64).to_le_bytes());
        h[fs + 0x48..fs + 0x50].copy_from_slice(&(pfs.len() as u64).to_le_bytes());
        h[fs + 0x140..fs + 0x148].copy_from_slice(&0x0102030405060708u64.to_le_bytes());
        // encrypt the section body with CTR, then the header with XTS
        let iv = 0x0102030405060708u64;
        ctr_apply(&Aes128::new(&content_key), iv, start as u64, &mut nca[start..end]);
        Xts::new(&header_key).encrypt(&mut h, 0, 0x200);
        nca[..0xc00].copy_from_slice(&h);

        let mut r = Cursor::new(nca.clone());
        let e = Entry { name: "x.nca".into(), offset: 0, size: nca.len() as u64 };
        let dec = open_nca(&mut r, &e, &keys, &HashMap::new()).expect("header decrypts");
        assert_eq!(dec.info.title_id, 0x0100_1234_5678_0000);
        let s = dec.info.sections[0].clone();
        let blocks = dec.verify_pfs0(&mut r, &s).expect("hashes match");
        assert_eq!(blocks, pfs.len().div_ceil(block));
        let files = dec.pfs0_files(&mut r, &s).expect("pfs0 decrypts");
        assert_eq!(files[0].0, "main");
        assert_eq!(files[0].1, nso);

        // a wrong key area key must fail the hash check, not produce garbage
        let bad = Keys::from_parts(&[("header_key", &header_key), ("key_area_key_application_00", &[0u8; 16])], &[]);
        let dec = open_nca(&mut r, &e, &bad, &HashMap::new()).unwrap();
        assert!(dec.verify_pfs0(&mut r, &s).is_err());
    }

    fn bktr_node(index: u32, end: u64, entries: &[(u64, u64, u8, u32)]) -> Vec<u8> {
        let mut n = vec![0u8; BKTR_NODE];
        n[0..4].copy_from_slice(&index.to_le_bytes());
        n[4..8].copy_from_slice(&(entries.len() as u32).to_le_bytes());
        n[8..16].copy_from_slice(&end.to_le_bytes());
        for (i, (v, p, k, s)) in entries.iter().enumerate() {
            let at = 0x10 + i * BKTR_ENTRY;
            n[at..at + 8].copy_from_slice(&v.to_le_bytes());
            n[at + 8..at + 16].copy_from_slice(&p.to_le_bytes());
            n[at + 16] = *k;
            n[at + 20..at + 24].copy_from_slice(&s.to_le_bytes());
        }
        n
    }

    #[test]
    fn compression_table_with_and_without_l2_nodes() {
        let set0: Vec<_> = (0..BKTR_PER_SET as u64).map(|i| (i * 0x10000, i * 0x100, 3u8, 0x100u32)).collect();
        let set1 = vec![(BKTR_PER_SET as u64 * 0x10000, 0x9_0000, 0u8, 0u32)];
        let end = BKTR_PER_SET as u64 * 0x10000 + 0x10000;
        let sets = [bktr_node(0, end, &set0), bktr_node(1, end, &set1)].concat();
        let count = BKTR_PER_SET + 1;
        for offset_nodes in [1usize, 2] {
            let table = [vec![0u8; offset_nodes * BKTR_NODE], sets.clone()].concat();
            let (blocks, total) = compression_blocks(&table, count).expect("table parses");
            assert_eq!(blocks.len(), count);
            assert_eq!(total, end);
            assert_eq!(blocks[1].phys, 0x100);
            assert_eq!(blocks[count - 1].kind, 0);
        }
        assert!(compression_blocks(&sets, count).is_err(), "no room for the offset node");
    }

    #[test]
    fn decompresses_an_lz4_romfs_section() {
        // two blocks: one LZ4 ("abcabcabcabc" + "!" padded to 0x50... use a real RomFS header first)
        let mut header = vec![0u8; 0x50];
        header[..8].copy_from_slice(&0x50u64.to_le_bytes());
        // LZ4 block encoding the 0x50-byte header: literal token with all bytes as literals
        let mut lz = vec![0xF0u8, (0x50 - 15) as u8];
        lz.extend_from_slice(&header);
        let stored = b"stored!!".to_vec();
        let mut data = lz.clone();
        let stored_at = data.len() as u64;
        data.extend_from_slice(&stored);
        let table_off = data.len().next_multiple_of(16) as u64;
        data.resize(table_off as usize, 0);
        let entries = [(0u64, 0u64, 3u8, lz.len() as u32), (0x50, stored_at, 0, 0), (0x58, 0, 1, 0)];
        let table = [vec![0u8; BKTR_NODE], bktr_node(0, 0x60, &entries)].concat();
        data.extend_from_slice(&table);
        let mut file = Cursor::new(data);
        let mut rd = SectionReader { r: &mut file, nca_base: 0, end: u64::MAX, aes: None, iv: 0, pos: 0 };
        let out = std::env::temp_dir().join(format!("srs-lz4-{}.bin", std::process::id()));
        let (len, lz4) = decompress_romfs(&mut rd, 0, table_off, table.len() as u64, 3, &out).expect("decompresses");
        let bytes = std::fs::read(&out).unwrap();
        let _ = std::fs::remove_file(&out);
        assert_eq!((len, lz4), (0x60, 1));
        assert_eq!(&bytes[..0x50], &header[..]);
        assert_eq!(&bytes[0x50..0x58], b"stored!!");
        assert_eq!(&bytes[0x58..], &[0u8; 8]);
    }

    #[test]
    fn reads_common_ticket() {
        let mut t = vec![0u8; 0x2c0];
        t[..4].copy_from_slice(&0x10004u32.to_le_bytes());
        let body = 4 + 0x100 + 0x3c;
        t[body + 0x40..body + 0x50].fill(0xab);
        t[body + 0x160..body + 0x170].fill(0x01);
        let (rid, key) = ticket_key(&t).unwrap();
        assert_eq!(rid, [1u8; 16]);
        assert_eq!(key, [0xab; 16]);
        t[body + 0x141] = 1;
        assert!(ticket_key(&t).is_none());
    }
}
