//! Extra function entry points for Kirikae, so more of a game runs as native code from the first build.
//!
//! Kirikae starts from each module's entry point and every code pointer in its relocations, follows calls, branches
//! and jump tables, and compiles what it reaches. What it cannot see (code reached only through pointers computed at
//! run time) runs in the interpreter until a play profile names it. This module adds two kinds of static seeds first:
//!
//! * exported function symbols (a module's dynamic symbol table names functions nothing else may point at);
//! * function prologues in the gaps Kirikae did not reach: `stp ..., [sp, #-n]!`, `sub sp, sp, #n`, `paciasp` or
//!   `bti c`, standing right after the end of other code (a return, an unconditional branch, or padding).
//!
//! Only unreached code is seeded, so the functions Kirikae already found are compiled exactly as before. A wrong
//! guess costs a little compile time for code that never runs; it cannot change what reached code does, because any
//! address may be an entry in Kirikae's design (the play profile adds entries the same way).

use std::path::Path;

use kirikae_a64::{lift, Control};
use kirikae_loader::{dynamic, Executable, Image};
use kirikae_recomp::discover::{build_function, find_entries, CodeSpace};
use kirikae_recomp::project;

const HEADER: &str = "# kirikae: switchrecomp seeds (play profile + exported symbols + prologues in unreached code)\n";

#[derive(Default, Debug, Clone)]
pub struct Analysis {
    /// instructions in all modules' .text
    pub total: u64,
    /// instructions reachable from Kirikae's own seeds (and the play profile)
    pub reachable_before: u64,
    /// instructions reachable once the extra seeds are added
    pub reachable_after: u64,
    pub functions_before: usize,
    pub functions_after: usize,
    /// exported function symbols that were not already entries
    pub from_symbols: usize,
    /// prologues found in unreached code
    pub from_prologues: usize,
    /// every extra address, sorted (play profile addresses not included)
    pub extra: Vec<u64>,
}

impl Analysis {
    pub fn pct(n: u64, total: u64) -> f64 {
        100.0 * n as f64 / total.max(1) as f64
    }
}

/// Does this word open a function? Stack frame set-ups compilers emit first.
pub fn is_prologue(w: u32) -> bool {
    w & 0xFFC0_03E0 == 0xA980_03E0 // stp xA, xB, [sp, #-n]!
        || w & 0xFFC0_03E0 == 0x6D80_03E0 // stp dA, dB, [sp, #-n]!
        || w & 0xFF80_03FF == 0xD100_03FF // sub sp, sp, #n
        || w == 0xD503_233F // paciasp
        || w == 0xD503_237F // pacibsp (Switch 2 toolchains sign return addresses with the B key)
        || w & 0xFFE0_0FFF == 0xF800_0FFE // str x30, [sp, #-n]!
        || w == 0xD503_245F // bti c
        || w == 0xD503_24DF // bti jc
}

/// Does this word end the code before it, so the next word may start a function?
fn ends_code(w: u32, addr: u64) -> bool {
    if w == 0 || w == 0xD503_201F {
        return true; // zero padding or nop padding
    }
    matches!(lift(addr, w).control(), Control::Return | Control::Jump(_) | Control::JumpIndirect | Control::Undefined)
}

/// Straight-line scan from `addr`: valid instructions until a return, branch or indirect jump within 256 words,
/// with no undefined words and no zero words on the way (data islands and literal pools fail this).
fn reads_as_function(m: &Image, addr: u64) -> bool {
    for j in 0..1024u64 {
        let at = addr + 4 * j;
        let Some(w) = m.word(at) else { return false };
        if !is_allocated_encoding(w) {
            return false;
        }
        match lift(at, w).control() {
            Control::Return | Control::Jump(_) | Control::JumpIndirect => return true,
            // instructions the static lifter leaves to the runtime still read as code
            _ => {}
        }
    }
    false
}

/// A64 top-level encoding groups (bits 28:25): 0000 is reserved (UDF and data), 0001 and 0011 are unallocated.
fn is_allocated_encoding(w: u32) -> bool {
    w != 0 && !matches!((w >> 25) & 0xf, 0b0000 | 0b0001 | 0b0011)
}

/// Covered-instruction bitmaps, one per module, in CodeSpace order (sorted by base)
struct Covered<'a> {
    images: Vec<&'a Image>,
    bits: Vec<Vec<u64>>,
}

impl<'a> Covered<'a> {
    fn new(exe: &'a Executable) -> Covered<'a> {
        let mut images: Vec<&Image> = exe.modules.iter().map(|m| &m.image).collect();
        images.sort_by_key(|i| i.base);
        let bits = images.iter().map(|m| vec![0u64; ((m.text.end - m.text.start) / 4).div_ceil(64) as usize]).collect();
        Covered { images, bits }
    }

    fn slot(&self, addr: u64) -> Option<(usize, usize)> {
        let i = self.images.partition_point(|m| m.base <= addr).checked_sub(1)?;
        let m = self.images[i];
        m.text.contains(&addr).then(|| (i, ((addr - m.text.start) / 4) as usize))
    }

    fn set(&mut self, addr: u64) {
        if let Some((i, k)) = self.slot(addr) {
            self.bits[i][k / 64] |= 1 << (k % 64);
        }
    }

    fn get(&self, i: usize, k: usize) -> bool {
        self.bits[i][k / 64] & (1 << (k % 64)) != 0
    }
}

/// Marks every instruction of every function Kirikae would compile, lifting the functions on all cores
fn cover<'a>(exe: &'a Executable, space: &CodeSpace, entries: &std::collections::BTreeSet<u64>) -> Covered<'a> {
    let mut cov = Covered::new(exe);
    let list: Vec<u64> = entries.iter().copied().collect();
    cover_more(&mut cov, space, &list, entries);
    cov
}

/// Adds the instructions of the functions starting at `list` (more entries only ever add coverage: code a new
/// entry splits off is covered by that entry's own function).
fn cover_more(cov: &mut Covered, space: &CodeSpace, list: &[u64], entries: &std::collections::BTreeSet<u64>) {
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get()).max(1);
    let chunk = list.len().div_ceil(threads).max(1);
    let spans: Vec<Vec<(u64, usize)>> = std::thread::scope(|s| {
        let handles: Vec<_> = list
            .chunks(chunk)
            .map(|part| {
                s.spawn(move || {
                    let mut out = Vec::new();
                    for &e in part {
                        let f = build_function(space, e, entries);
                        for b in &f.blocks {
                            out.push((b.start, b.insns.len()));
                        }
                    }
                    out
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap_or_default()).collect()
    });
    for (start, n) in spans.into_iter().flatten() {
        for j in 0..n as u64 {
            cov.set(start + 4 * j);
        }
    }
}

/// Works out the extra seeds for a game. `profile` holds the play-profile addresses already chosen as roots.
pub fn analyse(exe: &Executable, profile: &[u64], heuristics: bool) -> Analysis {
    let space = CodeSpace::new(exe.modules.iter().map(|m| &m.image).collect());
    let mut roots = project::seeds(exe);
    roots.extend_from_slice(profile);
    let total = space.words();
    let (entries, reachable_before) = find_entries(&space, &roots);
    let mut a = Analysis { total, reachable_before, reachable_after: reachable_before, functions_before: entries.len(), functions_after: entries.len(), ..Default::default() };
    if !heuristics {
        return a;
    }

    let mut extra: Vec<u64> = Vec::new();
    for m in &exe.modules {
        for (addr, _) in dynamic::function_symbols(&m.image) {
            if space.is_code(addr) && !entries.contains(&addr) {
                extra.push(addr);
            }
        }
    }
    extra.sort_unstable();
    extra.dedup();
    a.from_symbols = extra.len();

    // Seeds reveal more code, whose ends reveal more function starts: repeat until nothing new turns up.
    let mut current = entries.clone();
    if !extra.is_empty() {
        let mut r = roots.clone();
        r.extend_from_slice(&extra);
        current = find_entries(&space, &r).0;
    }
    let mut found_total = 0usize;
    let mut cov = cover(exe, &space, &current);
    for round in 0..32 {
        let found = boundary_seeds(&mut cov, &space, &current);
        let fresh: Vec<u64> = found.into_iter().filter(|e| !current.contains(e)).collect();
        if std::env::var_os("SWITCHRECOMP_SEED_TRACE").is_some() {
            eprintln!("switchrecomp: seed round {round}: {} new function starts", fresh.len());
        }
        if fresh.is_empty() {
            break;
        }
        found_total += fresh.len();
        let last = fresh.len() < 64; // the tail of the fixpoint: take these and stop
        extra.extend(fresh);
        if last {
            break;
        }
        let mut r = roots.clone();
        r.extend_from_slice(&extra);
        let next = find_entries(&space, &r).0;
        let added: Vec<u64> = next.difference(&current).copied().collect();
        cover_more(&mut cov, &space, &added, &next);
        current = next;
    }
    a.from_prologues = found_total;
    extra.sort_unstable();
    extra.dedup();
    extra.retain(|e| !entries.contains(e));

    if !extra.is_empty() {
        roots.extend_from_slice(&extra);
        let (after, reach) = find_entries(&space, &roots);
        a.functions_after = after.len();
        a.reachable_after = reach;
    }
    a.extra = extra;
    a
}

/// Function starts at the edges of the code `entries` reach: frame set-ups after a terminator or padding, and
/// leaf functions right after the end of reached code.
///
/// Scans each module front to back and marks each new function's own instructions as it goes, so a run of
/// back-to-back unreached functions is picked up in one pass instead of one function per round.
fn boundary_seeds(cov: &mut Covered, space: &CodeSpace, entries: &std::collections::BTreeSet<u64>) -> Vec<u64> {
    let mut found = Vec::new();
    for i in 0..cov.images.len() {
        let m = cov.images[i];
        let words = ((m.text.end - m.text.start) / 4) as usize;
        for k in 0..words {
            if cov.get(i, k) {
                continue;
            }
            let addr = m.text.start + 4 * k as u64;
            let Some(w) = m.word(addr) else { continue };
            if w == 0 || w == 0xD503_201F {
                continue;
            }
            let prev = if k == 0 { None } else { m.word(addr - 4) };
            let seed = if is_prologue(w) {
                // a frame set-up at the start of .text, or after padding / a terminator
                (k == 0 || prev.is_some_and(|p| ends_code(p, addr - 4))) && lift(addr, w).control() != Control::Undefined
            } else {
                // a leaf function (no frame set-up) right after the end of reached code
                k > 0
                    && cov.get(i, k - 1)
                    && prev.is_some_and(|p| matches!(lift(addr - 4, p).control(), Control::Return | Control::Jump(_) | Control::JumpIndirect))
                    && reads_as_function(m, addr)
            };
            if !seed {
                continue;
            }
            found.push(addr);
            let f = build_function(space, addr, entries);
            for b in &f.blocks {
                for j in 0..b.insns.len() as u64 {
                    cov.set(b.start + 4 * j);
                }
            }
        }
    }
    found
}

/// Writes a Kirikae profile holding the play-profile addresses and the extra seeds
pub fn write_profile(path: &Path, profile: &[u64], extra: &[u64]) -> Result<(), String> {
    let mut all: Vec<u64> = profile.iter().chain(extra).copied().collect();
    all.sort_unstable();
    all.dedup();
    let mut text = String::with_capacity(HEADER.len() + all.len() * 10);
    text.push_str(HEADER);
    for a in all {
        text.push_str(&format!("{a:x}\n"));
    }
    std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))?;
    // the guest tag is rewritten by Kirikae for this dump; a stale one from another dump would refuse the build
    let _ = std::fs::remove_file(project::guest_tag_path(path));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kirikae_loader::package::{from_source, Source};

    #[test]
    fn prologues() {
        assert!(is_prologue(0xA9BF_7BFD)); // stp x29, x30, [sp, #-16]!
        assert!(is_prologue(0xA9BA_7BFD)); // stp x29, x30, [sp, #-96]!
        assert!(is_prologue(0xD101_03FF)); // sub sp, sp, #0x40
        assert!(is_prologue(0xD503_233F)); // paciasp
        assert!(is_prologue(0xD503_237F)); // pacibsp
        assert!(is_prologue(0xF81F_0FFE)); // str x30, [sp, #-16]!
        assert!(!is_prologue(0xF81F_0FE0)); // str x0, [sp, #-16]! (not the link register)
        assert!(!is_prologue(0xD65F_03C0)); // ret
        assert!(!is_prologue(0xA9017BFD)); // stp x29, x30, [sp, #16] (no writeback: mid-function)
        assert!(!is_prologue(0xD100_0400)); // sub x0, x0, #1
    }

    #[test]
    fn terminators() {
        assert!(ends_code(0xD65F_03C0, 0x1000)); // ret
        assert!(ends_code(0x1400_0004, 0x1000)); // b
        assert!(ends_code(0, 0x1000));
        assert!(!ends_code(0x9400_0004, 0x1000)); // bl returns here
        assert!(!ends_code(0x8B01_0000, 0x1000)); // add
    }

    fn exe_of(image: Image) -> Executable {
        Executable {
            entry: image.entry,
            modules: vec![kirikae_loader::Module { name: "main".into(), image }],
            title_id: None,
            main_stack_size: None,
            system_resource_size: 0,
            romfs: None,
            nacp: None,
            title_version: 0,
        }
    }

    fn hello() -> Executable {
        let path = std::env::temp_dir().join(format!("srseeds-hello-{}.nro", std::process::id()));
        std::fs::write(&path, kirikae_testkit::hello_nro()).unwrap();
        let src: Source = kirikae_loader::package::read_source(&path).unwrap();
        let exe = from_source(&src).unwrap();
        let _ = std::fs::remove_file(&path);
        exe
    }

    #[test]
    fn analysis_keeps_what_kirikae_found() {
        let exe = hello();
        let plain = analyse(&exe, &[], false);
        let seeded = analyse(&exe, &[], true);
        assert!(plain.reachable_before > 0);
        assert_eq!(plain.reachable_before, seeded.reachable_before);
        assert!(seeded.reachable_after >= seeded.reachable_before);
        assert!(seeded.functions_after >= seeded.functions_before);
        assert!(seeded.reachable_after <= seeded.total);
    }

    #[test]
    fn unreached_function_is_found() {
        // entry: stp; ldp; ret.  then a function nothing calls: stp; ldp; ret
        let words: [u32; 6] = [0xA9BF_7BFD, 0xA8C1_7BFD, 0xD65F_03C0, 0xA9BF_7BFD, 0xA8C1_7BFD, 0xD65F_03C0];
        let base = 0x0800_0000u64;
        let memory: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let end = base + memory.len() as u64;
        let image = Image { base, memory, text: base..end, ro: end..end, data: end..end, bss: end..end, entry: base };
        let a = analyse(&exe_of(image), &[], true);
        assert_eq!(a.reachable_before, 3);
        assert_eq!(a.extra, vec![base + 12]);
        assert_eq!(a.reachable_after, 6);
        assert_eq!(a.functions_after, 2);
    }

    /// `cargo test write_test_nros -- --ignored` with SR_TESTKIT_OUT set: writes Kirikae's synthetic homebrew programs
    /// as .nro files, to try a whole build without any game files
    #[test]
    #[ignore]
    fn write_test_nros() {
        let out = std::path::PathBuf::from(std::env::var_os("SR_TESTKIT_OUT").expect("set SR_TESTKIT_OUT"));
        std::fs::create_dir_all(&out).unwrap();
        for (name, bytes) in [("hello", kirikae_testkit::hello_nro()), ("threads", kirikae_testkit::threads_nro()), ("parallel-threads", kirikae_testkit::parallel_threads_nro())] {
            std::fs::write(out.join(format!("{name}.nro")), bytes).unwrap();
        }
    }

    #[test]
    fn mid_function_frames_are_not_seeded() {
        // entry: b +8 over an unreached `stp ... !` that follows a non-terminator, then ret
        let words: [u32; 4] = [0x8B01_0000, 0x1400_0002, 0x9100_0400, 0xD65F_03C0];
        let base = 0x0800_0000u64;
        let mut memory: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        // word 2 (unreached, after a `b`) becomes a frame set-up: seeded. Put one after an `add` instead: not seeded
        memory[8..12].copy_from_slice(&0xA9BF_7BFDu32.to_le_bytes());
        let end = base + memory.len() as u64;
        let image = Image { base, memory: memory.clone(), text: base..end, ro: end..end, data: end..end, bss: end..end, entry: base };
        assert_eq!(analyse(&exe_of(image), &[], true).extra, vec![base + 8]);
        // now the unreached frame set-up follows reached straight-line code that is not a terminator
        let words: [u32; 4] = [0x1400_0003, 0x8B01_0000, 0xA9BF_7BFD, 0xD65F_03C0];
        let memory: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let image = Image { base, memory, text: base..end, ro: end..end, data: end..end, bss: end..end, entry: base };
        // the frame set-up itself is not a start; the code after the reached `b` is (a leaf-function start),
        // and it covers the frame set-up
        assert_eq!(analyse(&exe_of(image), &[], true).extra, vec![base + 4]);
    }
}

/// Diagnostic: what the unreached code looks like (`switchrecomp gaps <dump>`).
pub fn gap_report(exe: &Executable, profile: &[u64]) -> String {
    use std::collections::{BTreeMap, HashSet};
    use std::fmt::Write as _;
    let space = CodeSpace::new(exe.modules.iter().map(|m| &m.image).collect());
    let a = analyse(exe, profile, true);
    let mut roots = project::seeds(exe);
    roots.extend_from_slice(profile);
    roots.extend_from_slice(&a.extra);
    let (entries, _) = find_entries(&space, &roots);
    let cov = cover(exe, &space, &entries);

    // raw pointer-looking values anywhere in each module's data (absolute or base-relative)
    let mut data_values: HashSet<u64> = HashSet::new();
    for m in &exe.modules {
        let img = &m.image;
        for at in (0..img.memory.len().saturating_sub(7)).step_by(8) {
            let addr = img.base + at as u64;
            if img.text.contains(&addr) {
                continue;
            }
            let v = u64::from_le_bytes(img.memory[at..at + 8].try_into().unwrap());
            data_values.insert(v);
            data_values.insert(img.base.wrapping_add(v));
        }
    }

    let mut out = String::new();
    let mut total_unreached = 0u64;
    let mut padding = 0u64;
    let mut runs: Vec<(u64, u64, String)> = Vec::new(); // (start, words, module)
    let mut first_class: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut prev_class: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut in_data = 0u64;
    let mut in_data_words = 0u64;
    for (i, img) in cov.images.iter().enumerate() {
        let name = exe.modules.iter().find(|m| m.image.base == img.base).map_or("?", |m| m.name.as_str()).to_string();
        let words = ((img.text.end - img.text.start) / 4) as usize;
        let mut k = 0;
        while k < words {
            if cov.get(i, k) {
                k += 1;
                continue;
            }
            let start = k;
            while k < words && !cov.get(i, k) {
                k += 1;
            }
            // trim padding words from both ends
            let addr_of = |j: usize| img.text.start + 4 * j as u64;
            let mut s = start;
            while s < k && matches!(img.word(addr_of(s)), Some(0) | Some(0xD503_201F)) {
                s += 1;
            }
            let mut e = k;
            while e > s && matches!(img.word(addr_of(e - 1)), Some(0) | Some(0xD503_201F)) {
                e -= 1;
            }
            padding += ((s - start) + (k - e)) as u64;
            if s == e {
                continue;
            }
            let n = (e - s) as u64;
            total_unreached += n;
            let at = addr_of(s);
            let w = img.word(at).unwrap_or(0);
            let class = if is_prologue(w) {
                "prologue".to_string()
            } else {
                match lift(at, w).control() {
                    Control::Undefined => format!("undefined/data ({:02x}xxxxxx)", w >> 24),
                    Control::Return => "ret".into(),
                    Control::Jump(_) => "b".into(),
                    Control::JumpIndirect => "br".into(),
                    _ => format!("other ({:02x}xxxxxx)", w >> 24),
                }
            };
            let ent = first_class.entry(class).or_default();
            ent.0 += 1;
            ent.1 += n;
            let pc = if s == 0 {
                "start of .text".to_string()
            } else {
                let pw = img.word(addr_of(s - 1)).unwrap_or(0);
                let covered = cov.get(i, s - 1);
                let kind = match lift(addr_of(s - 1), pw).control() {
                    Control::Return => "ret",
                    Control::Jump(_) => "b",
                    Control::JumpIndirect => "br",
                    Control::Call(_) => "bl",
                    Control::CallIndirect => "blr",
                    Control::JumpIf(_) => "b.cond/cbz/tbz",
                    Control::Undefined => "undefined/data",
                    Control::Fallthrough => if pw == 0 || pw == 0xD503_201F { "padding" } else { "straight-line" },
                };
                format!("{} {}", if covered { "reached" } else { "unreached" }, kind)
            };
            let ent = prev_class.entry(pc).or_default();
            ent.0 += 1;
            ent.1 += n;
            if data_values.contains(&at) {
                in_data += 1;
                in_data_words += n;
            }
            runs.push((at, n, name.clone()));
        }
    }
    let total = space.words();
    let _ = writeln!(out, "unreached: {} of {} instructions ({:.2}%), {} runs; padding skipped: {}", total_unreached, total, Analysis::pct(total_unreached, total), runs.len(), padding);
    let _ = writeln!(out, "runs whose start address appears as a raw value in data: {in_data} ({in_data_words} insns)");
    let _ = writeln!(out, "\nfirst instruction of each run (runs, insns):");
    let mut v: Vec<_> = first_class.into_iter().collect();
    v.sort_by(|a, b| b.1 .1.cmp(&a.1 .1));
    for (c, (r, n)) in v.iter().take(20) {
        let _ = writeln!(out, "  {r:>7} {n:>9}  {c}");
    }
    let _ = writeln!(out, "\nwhat precedes each run (runs, insns):");
    let mut v: Vec<_> = prev_class.into_iter().collect();
    v.sort_by(|a, b| b.1 .1.cmp(&a.1 .1));
    for (c, (r, n)) in v.iter() {
        let _ = writeln!(out, "  {r:>7} {n:>9}  {c}");
    }
    let mut buckets = [0u64; 6];
    let mut bucket_words = [0u64; 6];
    for (_, n, _) in &runs {
        let b = match n { 0..=3 => 0, 4..=15 => 1, 16..=63 => 2, 64..=255 => 3, 256..=4095 => 4, _ => 5 };
        buckets[b] += 1;
        bucket_words[b] += n;
    }
    let _ = writeln!(out, "\nrun sizes:");
    for (label, (r, n)) in ["1-3", "4-15", "16-63", "64-255", "256-4095", "4096+"].iter().zip(buckets.iter().zip(bucket_words)) {
        let _ = writeln!(out, "  {label:>9}: {r:>7} runs {n:>9} insns");
    }
    runs.sort_by(|a, b| b.1.cmp(&a.1));
    let _ = writeln!(out, "\nlargest runs:");
    for (at, n, name) in runs.iter().take(25) {
        let base = exe.modules.iter().find(|m| &m.name == name).map_or(0, |m| m.image.base);
        let words: Vec<String> = (0..6).filter_map(|j| space.word(at + 4 * j)).map(|w| format!("{w:08x}")).collect();
        let _ = writeln!(out, "  {name}+{:#x}  {n} insns  {}", at - base, words.join(" "));
    }
    out
}
