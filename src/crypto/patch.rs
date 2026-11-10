//! Updates: an update's program NCA carries its RomFS as a patch (BKTR) over the base game's RomFS.
//!
//! The patch section holds two bucket trees (described by the patch info at fs header 0x100):
//!   * an indirect table: the patched section is a list of ranges, each read from the base game's RomFS section
//!     (storage 0) or from the patch's own data (storage 1);
//!   * an AesCtrEx table: the patch data is AES-CTR encrypted with a per-range generation in the counter
//!     (counter = section nonce high 32 bits | generation, then the block offset).
//! The patched RomFS is the IVFC data level of the virtual section, at the patch fs header's data offset.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

use super::aes::{ctr_apply, Aes128};
use super::keys::Keys;
use super::{container_entries, open_nca, read_at, resolve_ticket, DecNca, Entry, BKTR_NODE};
use kirikae_loader::nca as knca;

const INDIRECT_ENTRY: usize = 0x14;
const AESCTREX_ENTRY: usize = 0x10;

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// Entries of a bucket tree whose entry sets are the last nodes of `table`; returns (entries, end offset).
pub fn bucket_tree(table: &[u8], entry_count: usize, entry_size: usize, what: &str) -> Result<(Vec<Vec<u8>>, u64), String> {
    let bad = |why: String| format!("{what} table: {why}");
    if entry_count == 0 {
        return Err(bad("no entries".into()));
    }
    let per = (BKTR_NODE - 0x10) / entry_size;
    let sets = entry_count.div_ceil(per);
    let nodes = table.len() / BKTR_NODE;
    if nodes < 1 + sets {
        return Err(bad(format!("{} bytes cannot hold {entry_count} entries", table.len())));
    }
    let first = nodes - sets;
    let mut out = Vec::with_capacity(entry_count);
    let mut end = 0;
    for k in 0..sets {
        let node = &table[(first + k) * BKTR_NODE..(first + k + 1) * BKTR_NODE];
        let (index, count) = (u32_at(node, 0) as usize, u32_at(node, 4) as usize);
        if index != k || count == 0 || count > per {
            return Err(bad(format!("entry set {k} has an unexpected header (index {index}, {count} entries); wrong key?")));
        }
        end = u64_at(node, 8);
        for i in 0..count {
            out.push(node[0x10 + i * entry_size..0x10 + (i + 1) * entry_size].to_vec());
        }
    }
    if out.len() != entry_count {
        return Err(bad(format!("{} entries found, header says {entry_count}", out.len())));
    }
    Ok((out, end))
}

struct Indirect {
    virt: u64,
    phys: u64,
    storage: u32,
}

struct Ctr {
    offset: u64,
    generation: u32,
}

/// The patch section's own data (storage 1): AES-CTR with the generation of the AesCtrEx range it falls in.
struct PatchData<'a> {
    section_start: u64,
    nca_base: u64,
    nonce: u64,
    aes: Aes128,
    ranges: &'a [Ctr],
}

impl PatchData<'_> {
    fn read<R: Read + Seek>(&self, r: &mut R, mut rel: u64, mut buf: &mut [u8]) -> io::Result<()> {
        while !buf.is_empty() {
            let i = self.ranges.partition_point(|c| c.offset <= rel).saturating_sub(1);
            let generation = self.ranges.get(i).map_or(0, |c| c.generation);
            let next = self.ranges.get(i + 1).map_or(u64::MAX, |c| c.offset);
            let n = (buf.len() as u64).min(next - rel) as usize;
            let (chunk, rest) = buf.split_at_mut(n);
            r.seek(SeekFrom::Start(self.section_start + rel))?;
            r.read_exact(chunk)?;
            let iv = (self.nonce & 0xffff_ffff_0000_0000) | generation as u64;
            ctr_apply(&self.aes, iv, self.section_start - self.nca_base + rel, chunk);
            rel += n as u64;
            buf = rest;
        }
        Ok(())
    }
}

fn open_container(path: &Path, keys: &Keys) -> Result<(BufReader<File>, Vec<Entry>, HashMap<[u8; 16], [u8; 16]>), String> {
    let mut r = BufReader::with_capacity(1 << 20, File::open(path).map_err(|e| format!("{}: {e}", path.display()))?);
    let (_, entries) = container_entries(&mut r, path)?;
    let mut tickets = HashMap::new();
    for e in entries.iter().filter(|e| e.name.ends_with(".tik")) {
        if let Ok(t) = read_at(&mut r, e.offset, e.size.min(0x1000) as usize)
            && let Some((rid, key)) = resolve_ticket(&t, keys)
        {
            tickets.insert(rid, key);
        }
    }
    Ok((r, entries, tickets))
}

fn program_with_romfs<R: Read + Seek>(r: &mut R, entries: &[Entry], keys: &Keys, tickets: &HashMap<[u8; 16], [u8; 16]>, patch: bool) -> Result<(DecNca, knca::Section), String> {
    let mut why = Vec::new();
    for e in entries.iter().filter(|e| e.name.ends_with(".nca") && !e.name.ends_with(".cnmt.nca")) {
        let nca = match open_nca(r, e, keys, tickets) {
            Ok(n) => n,
            Err(err) => {
                why.push(err);
                continue;
            }
        };
        if nca.info.content_type != knca::CONTENT_PROGRAM {
            continue;
        }
        let found = nca.info.sections.iter().find(|s| {
            s.fs_type == knca::FS_ROMFS && matches!(s.crypto, knca::CRYPTO_BKTR | knca::CRYPTO_BKTR_SKIP_HASH) == patch
        });
        if let Some(s) = found.cloned() {
            return Ok((nca, s));
        }
    }
    Err(format!(
        "no program NCA with a {} RomFS{}",
        if patch { "patch (BKTR)" } else { "base" },
        why.first().map(|w| format!(" ({w})")).unwrap_or_default()
    ))
}

pub struct PatchReport {
    pub bytes: u64,
    pub ranges: usize,
    pub from_patch: u64,
}

/// Writes the patched RomFS (base game + update) to `out`.
pub fn write_patched_romfs(base: &Path, update: &Path, keys: &Keys, out: &Path) -> Result<PatchReport, String> {
    let (mut br, bentries, btickets) = open_container(base, keys)?;
    let (mut ur, uentries, utickets) = open_container(update, keys)?;
    let (bnca, bsec) = program_with_romfs(&mut br, &bentries, keys, &btickets, false).map_err(|e| format!("base game: {e}"))?;
    let (unca, usec) = program_with_romfs(&mut ur, &uentries, keys, &utickets, true).map_err(|e| format!("update: {e}"))?;
    if bnca.info.title_id & !0xfff != unca.info.title_id & !0xfff {
        return Err(format!("the update ({:016x}) is not for this game ({:016x})", unca.info.title_id, bnca.info.title_id));
    }
    let fs = unca.fs_header(&usec).to_vec();
    let (ind_off, ind_size, ind_count) = (u64_at(&fs, 0x100), u64_at(&fs, 0x108), u32_at(&fs, 0x118) as usize);
    let (ctr_off, ctr_size, ctr_count) = (u64_at(&fs, 0x120), u64_at(&fs, 0x128), u32_at(&fs, 0x138) as usize);
    if &fs[0x110..0x114] != b"BKTR" || &fs[0x130..0x134] != b"BKTR" {
        return Err("update: the patch info has no BKTR headers".into());
    }
    if ind_size > 256 << 20 || ctr_size > 256 << 20 {
        return Err("update: implausible patch table sizes".into());
    }
    let key = unca.content_key().ok_or("update: no content key")?;
    let aes = Aes128::new(&key);
    // the tables are encrypted with the section's plain counter
    let table = |r: &mut BufReader<File>, off: u64, size: u64| -> Result<Vec<u8>, String> {
        let mut t = read_at(r, usec.start + off, size as usize).map_err(|e| e.to_string())?;
        ctr_apply(&aes, usec.nonce, usec.start - unca.base + off, &mut t);
        Ok(t)
    };
    let ind_table = table(&mut ur, ind_off, ind_size)?;
    let ctr_table = table(&mut ur, ctr_off, ctr_size)?;
    let (ind_raw, virt_end) = bucket_tree(&ind_table, ind_count, INDIRECT_ENTRY, "indirect")?;
    let (ctr_raw, _) = bucket_tree(&ctr_table, ctr_count, AESCTREX_ENTRY, "AesCtrEx")?;
    let ind: Vec<Indirect> = ind_raw.iter().map(|e| Indirect { virt: u64_at(e, 0), phys: u64_at(e, 8), storage: u32_at(e, 0x10) }).collect();
    let ctr: Vec<Ctr> = ctr_raw.iter().map(|e| Ctr { offset: u64_at(e, 0), generation: u32_at(e, 0xc) }).collect();
    if ind.first().map(|e| e.virt) != Some(0) || !ind.windows(2).all(|w| w[0].virt < w[1].virt) || ind.iter().any(|e| e.storage > 1) {
        return Err("update: the indirect table is not well formed".into());
    }
    let patch = PatchData { section_start: usec.start, nca_base: unca.base, nonce: usec.nonce, aes: aes.clone(), ranges: &ctr };
    let mut base_rd = bnca.reader(&mut br, &bsec)?;

    // the patched RomFS: the IVFC data level of the virtual section
    let romfs_start = usec.data_offset - usec.start;
    let romfs_len = usec.data_size;
    if romfs_start + romfs_len > virt_end {
        return Err("update: the RomFS lies outside the patched section".into());
    }
    let mut w = io::BufWriter::with_capacity(8 << 20, File::create(out).map_err(|e| format!("{}: {e}", out.display()))?);
    let mut buf = vec![0u8; 4 << 20];
    let mut at = romfs_start;
    let end = romfs_start + romfs_len;
    let mut from_patch = 0u64;
    let mut next_note = 1u64 << 30;
    while at < end {
        let i = ind.partition_point(|e| e.virt <= at) - 1;
        let e = &ind[i];
        let range_end = ind.get(i + 1).map_or(virt_end, |n| n.virt).min(end);
        let n = ((range_end - at) as usize).min(buf.len());
        let phys = e.phys + (at - e.virt);
        let chunk = &mut buf[..n];
        if e.storage == 0 {
            base_rd.seek(SeekFrom::Start(bsec.start + phys)).map_err(|err| err.to_string())?;
            base_rd.read_exact(chunk).map_err(|err| format!("base game RomFS: {err}"))?;
        } else {
            patch.read(&mut ur, phys, chunk).map_err(|err| format!("update data: {err}"))?;
            from_patch += n as u64;
        }
        w.write_all(chunk).map_err(|err| err.to_string())?;
        at += n as u64;
        if at - romfs_start >= next_note {
            eprintln!("switchrecomp: patched RomFS {} / {} MiB", (at - romfs_start) >> 20, romfs_len >> 20);
            next_note += 1 << 30;
        }
    }
    w.flush().map_err(|e| e.to_string())?;
    drop(w);
    let mut magic = [0u8; 8];
    File::open(out).and_then(|mut f| f.read_exact(&mut magic)).map_err(|e| e.to_string())?;
    if u64::from_le_bytes(magic) != 0x50 {
        return Err("the patched RomFS has no valid header (wrong base game version, or a key problem)".into());
    }
    Ok(PatchReport { bytes: romfs_len, ranges: ind.len(), from_patch })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_tree_reads_entry_sets_after_offset_nodes() {
        let per = (BKTR_NODE - 0x10) / INDIRECT_ENTRY;
        let mut set = vec![0u8; BKTR_NODE];
        set[4..8].copy_from_slice(&2u32.to_le_bytes());
        set[8..16].copy_from_slice(&0x3000u64.to_le_bytes());
        set[0x10..0x18].copy_from_slice(&0u64.to_le_bytes());
        set[0x24..0x2c].copy_from_slice(&0x1000u64.to_le_bytes());
        set[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());
        let table = [vec![0u8; BKTR_NODE], set].concat();
        let (e, end) = bucket_tree(&table, 2, INDIRECT_ENTRY, "t").unwrap();
        assert_eq!(end, 0x3000);
        assert_eq!(u64_at(&e[1], 0), 0x1000);
        assert_eq!(u32_at(&e[1], 0x10), 1);
        assert!(per > 2);
        assert!(bucket_tree(&table, 3, INDIRECT_ENTRY, "t").is_err());
    }
}
