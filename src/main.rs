//! switchrecomp: decomp/recomp front end for Nintendo Switch dumps, built on Kirikae.
//!
//! inspect -> extract -> build (AArch64 -> Cranelift -> native .exe) -> play -> refine (profile-guided rebuild)

mod crypto;
mod doctor;
mod input;
mod library;
mod linker;
mod seeds;
mod sudachi;
mod toolchain;

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use kirikae_a64::{lift, Control};
use kirikae_recomp::discover::CodeSpace;
use kirikae_recomp::project::{self, build as kirikae_build, default_profile, Backend, BuildOptions};

use library::{Game, Library};

const USAGE: &str = "\
switchrecomp: turn your own Switch game dumps into native PC executables (powered by Kirikae)

usage:
  switchrecomp                               interactive menu
  switchrecomp <dump>                        same as `build <dump>` (drag a dump onto the exe)
  switchrecomp doctor                        check Rust, MSVC, Vulkan and build paths
  switchrecomp inspect <dump>                what the dump is, its title, modules and code coverage
  switchrecomp extract <dump> <dir>          write <dir>/exefs and <dir>/romfs
  switchrecomp build <dump> [--name <n>] [-o <dir>] [-j <jobs>] [--fresh] [--fast-regs]
                     [--no-seed] [--linker auto|lld|msvc]
                                             recompile into games/<name>/<name>.exe
                                             --fresh      ignore the saved play profile
                                             --fast-regs  keep guest registers in host registers
                                                          (faster game code; experimental in Kirikae)
                                             --no-seed    only Kirikae's own entry points (no extra
                                                          seeds from symbols and prologues)
                                             --linker     LLD links several times faster (default:
                                                          auto = LLD when it works, else link.exe)
  switchrecomp refine <game> [--linker ...]  rebuild using what the last play session had to
                                             interpret, so more code runs natively
  switchrecomp remove <game>                 take a game off the list (its files stay)
  switchrecomp play <game> [--stats] [--vsync] [--handheld]
  switchrecomp coverage <game>               summary of the services/SVCs/shaders the game used
  switchrecomp list                          games you have built
  switchrecomp syms <dump> [pattern]         exported function symbols
  switchrecomp scan <folder>... [--json]     list the dumps in folders: what each is and whether it can be built
  switchrecomp sudachi                       where Sudachi puts its ExeFS / RomFS dumps (they can be built from there)
  switchrecomp decrypt <nsp|xci|nca> [-o <dir>] [--keys <dir|prod.keys>] [--update <update.nsp>] [--no-romfs] [--force]
                                             --update: apply an update (code from the update, RomFS patched)
                                             decrypt your own dump with your prod.keys/title.keys into
                                             <dump>.decrypted (exefs, romfs.bin, control.nacp); every
                                             ExeFS block is checked against its SHA-256 hash
  switchrecomp keys [--keys <dir|prod.keys>]  which key files are used and what they cover (no key values)

<dump> is an NSP or XCI (encrypted ones are decrypted with your keys first), a folder with
exefs/ (+ romfs/), an NSO or an NRO. Only use games and keys dumped from your own console,
and the executables it produces must not be shared.";

fn main() -> ExitCode {
    toolchain::prepare();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        None => menu(),
        Some("doctor") => cmd_doctor(),
        Some("inspect" | "info") => cmd_inspect(&args[1..]),
        Some("extract") => cmd_extract(&args[1..]),
        Some("build") => cmd_build(&args[1..]),
        Some("refine") => cmd_refine(&args[1..]),
        Some("play" | "run") => cmd_play(&args[1..]),
        Some("coverage") => cmd_coverage(&args[1..]),
        Some("list" | "ls") => cmd_list(),
        Some("remove" | "rm") => cmd_remove(&args[1..]),
        Some("syms") => cmd_syms(&args[1..]),
        Some("scan") => cmd_scan(&args[1..]),
        Some("sudachi") => cmd_sudachi(),
        Some("decrypt") => cmd_decrypt(&args[1..]),
        Some("keys") => cmd_keys(&args[1..]),
        Some("dumpmods") => {
            // research aid: each module's loaded image (NSOs decompressed) as <dir>/<name>.bin, plus their bases
            parse(&args[1..]).and_then(|a| {
                let loaded = input::load(Path::new(a.arg(0, "dump")?))?;
                let dir = PathBuf::from(a.arg(1, "dir")?);
                std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
                let mut index = String::new();
                for m in &loaded.exe.modules {
                    std::fs::write(dir.join(format!("{}.bin", m.name)), &m.image.memory).map_err(|e| e.to_string())?;
                    index.push_str(&format!("{} {:#x} text {:#x}-{:#x}\n", m.name, m.image.base, m.image.text.start, m.image.text.end));
                }
                std::fs::write(dir.join("modules.txt"), &index).map_err(|e| e.to_string())?;
                print!("{index}");
                Ok(())
            })
        }
        Some("gaps") => {
            let r = parse(&args[1..]).and_then(|a| {
                let loaded = input::load(Path::new(a.arg(0, "dump")?))?;
                println!("{}", seeds::gap_report(&loaded.exe, &[]));
                Ok(())
            });
            r
        }
        Some("-h" | "--help" | "help") => {
            println!("{USAGE}");
            Ok(())
        }
        Some(path) if Path::new(path).exists() => {
            let r = cmd_build(&args);
            pause_if_double_clicked();
            r
        }
        Some(other) => Err(format!("unknown command `{other}`\n\n{USAGE}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("\nswitchrecomp: {e}");
            if args.len() == 1 && Path::new(&args[0]).exists() {
                pause_if_double_clicked();
            }
            ExitCode::FAILURE
        }
    }
}

// ---------------------------------------------------------------- argument parsing

const SWITCHES: &[&str] = &["--fresh", "--stats", "--vsync", "--handheld", "--headless", "--json", "--fast-regs", "--no-seed", "--no-romfs", "--force"];

struct Args {
    positional: Vec<String>,
    options: Vec<(String, String)>,
}

fn parse(args: &[String]) -> Result<Args, String> {
    let mut out = Args { positional: Vec::new(), options: Vec::new() };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if SWITCHES.contains(&a.as_str()) {
            out.options.push((a.clone(), String::new()));
        } else if a.starts_with('-') && a.len() > 1 {
            let v = it.next().ok_or_else(|| format!("{a} needs a value"))?;
            out.options.push((a.clone(), v.clone()));
        } else {
            out.positional.push(a.clone());
        }
    }
    Ok(out)
}

impl Args {
    fn arg(&self, i: usize, what: &str) -> Result<&str, String> {
        self.positional.get(i).map(String::as_str).ok_or_else(|| format!("missing {what}\n\n{USAGE}"))
    }
    fn opt(&self, names: &[&str]) -> Option<&str> {
        self.options.iter().find(|(k, _)| names.contains(&k.as_str())).map(|(_, v)| v.as_str())
    }
    fn flag(&self, name: &str) -> bool {
        self.options.iter().any(|(k, _)| k == name)
    }
}

// ---------------------------------------------------------------- shared helpers

/// Short Cargo target folder so the MSVC linker stays under 260 characters.
pub fn build_target_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("CARGO_TARGET_DIR") {
        return PathBuf::from(dir).join("kirikae-games");
    }
    if cfg!(windows)
        && let Some(local) = std::env::var_os("LOCALAPPDATA")
    {
        return PathBuf::from(local).join("srt");
    }
    library::home().join("target-games")
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn pause_if_double_clicked() {
    if cfg!(windows) && std::env::var_os("PROMPT").is_none() {
        print!("\nPress Enter to close...");
        let _ = std::io::stdout().flush();
        let _ = std::io::stdin().lock().read_line(&mut String::new());
    }
}

fn game<'a>(lib: &'a Library, name: &str) -> Result<&'a Game, String> {
    lib.find(name).ok_or_else(|| {
        let names: Vec<&str> = lib.games.iter().map(|g| g.name.as_str()).collect();
        if names.is_empty() {
            format!("no game `{name}` (nothing built yet; run `switchrecomp build <dump>`)")
        } else {
            format!("no game `{name}` (built: {})", names.join(", "))
        }
    })
}

// ---------------------------------------------------------------- commands

fn cmd_doctor() -> Result<(), String> {
    println!("switchrecomp doctor\n");
    if doctor::report() {
        println!("\nEverything needed to recompile and play is in place.");
        Ok(())
    } else {
        Err("fix the items marked FAIL, then run `switchrecomp doctor` again".into())
    }
}

#[derive(Default)]
struct Coverage {
    words: u64,
    lifted: u64,
}

fn decoder_coverage(image: &kirikae_loader::Image) -> Coverage {
    let mut c = Coverage::default();
    let mut addr = image.text.start;
    while addr < image.text.end {
        let w = image.word(addr).unwrap_or(0);
        c.words += 1;
        if lift(addr, w).control() != Control::Undefined {
            c.lifted += 1;
        }
        addr += 4;
    }
    c
}

fn cmd_inspect(args: &[String]) -> Result<(), String> {
    let a = parse(args)?;
    let path = Path::new(a.arg(0, "dump")?);
    let kind = input::classify(path);
    println!("input    {}", path.display());
    println!("kind     {}", kind.label());
    if !kind.recompilable() {
        if let Some(fix) = kind.fix() {
            println!("\n{fix}");
        }
        return Ok(());
    }
    let loaded = input::load(path)?;
    let exe = &loaded.exe;
    if let Some(t) = input::title_name(exe) {
        println!("title    {t}");
    }
    if let Some(id) = exe.title_id {
        println!("title id {id:016X}");
    }
    if let Some(n) = &exe.nacp {
        if !n.display_version.is_empty() {
            println!("version  {}", n.display_version);
        }
    }
    if let Some(r) = &exe.romfs {
        match kirikae_loader::romfs::Reader::open(r) {
            Ok(rd) => println!("romfs    {:.1} MiB", rd.size() as f64 / (1u64 << 20) as f64),
            Err(e) => println!("romfs    unreadable: {e}"),
        }
    } else {
        println!("romfs    none (the game may need it: dump it alongside exefs/)");
    }
    println!("entry    {:#x}\n", exe.entry);
    println!("{:<10} {:>18} {:>12} {:>10}", "module", "base", "code", "lifted");
    let mut total = Coverage::default();
    for m in &exe.modules {
        let c = decoder_coverage(&m.image);
        println!(
            "{:<10} {:>#18x} {:>9} KiB {:>9.2}%",
            m.name,
            m.image.base,
            (m.image.text.end - m.image.text.start) / 1024,
            100.0 * c.lifted as f64 / c.words.max(1) as f64
        );
        total.words += c.words;
        total.lifted += c.lifted;
    }
    println!(
        "\n{} instructions, {:.2}% handled by the static lifter (the rest runs through the runtime's SIMD helpers/interpreter)",
        total.words,
        100.0 * total.lifted as f64 / total.words.max(1) as f64
    );
    let t = Instant::now();
    let a = seeds::analyse(exe, &[], true);
    println!(
        "\nreachable from entry points    {:>6.2}% of instructions  ({} functions)",
        seeds::Analysis::pct(a.reachable_before, a.total),
        a.functions_before
    );
    println!(
        "with switchrecomp's seeds      {:>6.2}% of instructions  ({} functions: +{} exported symbols, +{} prologues in unreached code)  [{:.1}s]",
        seeds::Analysis::pct(a.reachable_after, a.total),
        a.functions_after,
        a.from_symbols,
        a.from_prologues,
        t.elapsed().as_secs_f64()
    );
    println!("what is left runs in the interpreter until a play session finds it (`refine`).");
    println!("\nready: `switchrecomp build \"{}\"`", path.display());
    Ok(())
}

fn cmd_extract(args: &[String]) -> Result<(), String> {
    let a = parse(args)?;
    let path = Path::new(a.arg(0, "dump")?);
    let out = PathBuf::from(a.arg(1, "output folder")?);
    let loaded = input::load(path)?;
    let kirikae_loader::Source::ExeFs(files, _, romfs) = &loaded.source else {
        return Err("this is a single executable, not a game dump with an ExeFS".into());
    };
    let exefs = out.join("exefs");
    std::fs::create_dir_all(&exefs).map_err(|e| format!("{}: {e}", exefs.display()))?;
    for (name, bytes) in files {
        std::fs::write(exefs.join(name), bytes).map_err(|e| format!("{name}: {e}"))?;
    }
    let mut count = 0usize;
    if let Some(romfs) = romfs {
        let mut r = kirikae_loader::romfs::Reader::open(romfs).map_err(|e| e.to_string())?;
        let all = kirikae_loader::romfs::list(&mut r, usize::MAX).map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; 1 << 20];
        for (i, f) in all.iter().enumerate() {
            let dest = out.join("romfs").join(f.path.trim_start_matches('/'));
            std::fs::create_dir_all(dest.parent().unwrap()).map_err(|e| e.to_string())?;
            let mut w = std::io::BufWriter::new(std::fs::File::create(&dest).map_err(|e| format!("{}: {e}", dest.display()))?);
            let mut done = 0u64;
            while done < f.size {
                let n = (f.size - done).min(buf.len() as u64) as usize;
                r.read_at(f.offset + done, &mut buf[..n]).map_err(|e| e.to_string())?;
                w.write_all(&buf[..n]).map_err(|e| e.to_string())?;
                done += n as u64;
            }
            count += 1;
            if i % 500 == 0 {
                eprint!("\rswitchrecomp: romfs {}/{}", i + 1, all.len());
            }
        }
        eprintln!();
    }
    println!("switchrecomp: wrote {} ExeFS files and {count} RomFS files to {}", files.len(), out.display());
    Ok(())
}

/// How to build a game
#[derive(Clone)]
struct BuildCfg {
    name: Option<String>,
    out: Option<PathBuf>,
    jobs: Option<usize>,
    /// ignore the play profile
    fresh: bool,
    /// add switchrecomp's extra seeds (exported symbols, prologues in unreached code)
    seed: bool,
    /// Kirikae's register cache in generated code
    fast_regs: bool,
    linker: linker::Choice,
}

impl Default for BuildCfg {
    fn default() -> BuildCfg {
        BuildCfg { name: None, out: None, jobs: None, fresh: false, seed: true, fast_regs: false, linker: linker::Choice::Auto }
    }
}

impl BuildCfg {
    fn from_args(a: &Args) -> Result<BuildCfg, String> {
        Ok(BuildCfg {
            name: a.opt(&["--name"]).map(String::from),
            out: a.opt(&["-o", "--out"]).map(PathBuf::from),
            jobs: a.opt(&["-j", "--jobs"]).map(|j| j.parse().map_err(|_| format!("bad job count `{j}`"))).transpose()?,
            fresh: a.flag("--fresh"),
            seed: !a.flag("--no-seed"),
            fast_regs: a.flag("--fast-regs"),
            linker: a.opt(&["--linker"]).map(linker::Choice::parse).transpose()?.unwrap_or(linker::Choice::Auto),
        })
    }
}

fn build_game(path: &Path, cfg: &BuildCfg) -> Result<Game, String> {
    let started = Instant::now();
    eprintln!("switchrecomp: reading {}", path.display());
    let loaded = input::load(path)?;
    let title = input::title_name(&loaded.exe);
    let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "game".into());
    let name = input::slug(cfg.name.clone().or_else(|| title.clone()).as_deref().unwrap_or(&stem));
    let out_dir = cfg.out.clone().unwrap_or_else(|| library::home().join("games").join(&name));
    std::fs::create_dir_all(&out_dir).map_err(|e| format!("{}: {e}", out_dir.display()))?;
    let out_dir = std::path::absolute(&out_dir).unwrap_or(out_dir);
    let package = project::package_name(&name);

    // the play profile, with Kirikae's own checks (well formed, made by this dump)
    let play_path = default_profile(&out_dir, &package);
    let play: Vec<u64> = if !cfg.fresh && play_path.is_file() {
        let space = CodeSpace::new(loaded.exe.modules.iter().map(|m| &m.image).collect());
        let p = project::load_profile(&play_path, &space, &project::guest_identity(&loaded.exe.modules))?;
        eprintln!("switchrecomp: play profile {}: {} interpreted addresses become functions", play_path.display(), p.len());
        p
    } else {
        if cfg.fresh && play_path.is_file() {
            eprintln!("switchrecomp: --fresh: ignoring the play profile {}", play_path.display());
        }
        Vec::new()
    };

    eprintln!("switchrecomp: analysing {} ({} modules)", title.as_deref().unwrap_or(&name), loaded.exe.modules.len());
    let t = Instant::now();
    let analysis = seeds::analyse(&loaded.exe, &play, cfg.seed);
    eprintln!(
        "switchrecomp: {} functions, {:.2}% of {} instructions reachable from entry points",
        analysis.functions_before,
        seeds::Analysis::pct(analysis.reachable_before, analysis.total),
        analysis.total
    );
    if cfg.seed {
        eprintln!(
            "switchrecomp: seeded unreached code with {} exported symbols and {} prologues: {} functions, {:.2}% reachable ({:.1}s)",
            analysis.from_symbols,
            analysis.from_prologues,
            analysis.functions_after,
            seeds::Analysis::pct(analysis.reachable_after, analysis.total),
            t.elapsed().as_secs_f64()
        );
    }

    let mut opts = BuildOptions::new(&out_dir, &name);
    opts.backend = Backend::Cranelift;
    opts.target_dir = Some(build_target_dir());
    if let Some(j) = cfg.jobs {
        opts.jobs = j;
    }
    opts.fast_regs = cfg.fast_regs;
    if analysis.extra.is_empty() {
        opts.no_profile = cfg.fresh;
    } else {
        let seeds_path = out_dir.join(format!("{package}.seeds.profile"));
        seeds::write_profile(&seeds_path, &play, &analysis.extra)?;
        opts.profile = Some(seeds_path);
    }
    if cfg.fast_regs {
        eprintln!("switchrecomp: --fast-regs: guest registers are cached in host registers (experimental in Kirikae)");
    }
    let (picked, desc) = linker::select(cfg.linker);
    eprintln!("switchrecomp: linking with {desc}");

    eprintln!("switchrecomp: recompiling into {}", out_dir.display());
    let (executable, functions, reachable, total, linker_used) = match kirikae_build(&loaded.source, &opts) {
        Ok(r) => (r.executable, r.functions, r.reachable, r.total, if picked == linker::Choice::Lld { "lld" } else { "link.exe" }),
        Err(e) if picked == linker::Choice::Lld && e.starts_with("cargo build failed") => {
            let project_dir = out_dir.join(format!("{package}-build"));
            let exe = linker::relink_msvc(&project_dir, &build_target_dir(), &package, &out_dir)?;
            (exe, analysis.functions_after, analysis.reachable_after, analysis.total, "link.exe")
        }
        Err(e) => return Err(e),
    };
    let secs = started.elapsed().as_secs_f64();
    println!(
        "\nswitchrecomp: {} functions ({} of {} instructions reachable, {:.2}%) -> {} in {:.0}s ({})",
        functions,
        reachable,
        total,
        seeds::Analysis::pct(reachable, total),
        executable.display(),
        secs,
        linker_used
    );

    let mut lib = Library::load();
    let builds = lib.games.iter().find(|g| g.name == name).map_or(0, |g| g.builds) + 1;
    let game = Game {
        name: name.clone(),
        title,
        title_id: loaded.exe.title_id.map(|t| format!("{t:016X}")),
        version: loaded.exe.nacp.as_ref().map(|n| n.display_version.clone()).filter(|v| !v.is_empty()),
        source: std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf()),
        out_dir,
        executable,
        functions,
        reachable,
        total,
        builds,
        last_built_unix: now(),
        fast_regs: cfg.fast_regs,
        seeded: cfg.seed,
        build_secs: secs,
        linker: linker_used.to_string(),
        seeded_functions: analysis.functions_after.saturating_sub(analysis.functions_before),
    };
    lib.upsert(game.clone());
    lib.save()?;
    println!("switchrecomp: play it with `switchrecomp play {name}`; after a session, `switchrecomp refine {name}`");
    Ok(game)
}

fn cmd_build(args: &[String]) -> Result<(), String> {
    let a = parse(args)?;
    let path = PathBuf::from(a.arg(0, "dump")?);
    build_game(&path, &BuildCfg::from_args(&a)?).map(|_| ())
}

fn cmd_remove(args: &[String]) -> Result<(), String> {
    let a = parse(args)?;
    let mut lib = Library::load();
    let g = game(&lib, a.arg(0, "game name")?)?.clone();
    lib.remove(&g.name);
    lib.save()?;
    println!("switchrecomp: removed {} from the library; its files are still in {}", g.name, g.out_dir.display());
    Ok(())
}

fn cmd_refine(args: &[String]) -> Result<(), String> {
    let a = parse(args)?;
    let lib = Library::load();
    let g = game(&lib, a.arg(0, "game name")?)?.clone();
    let profile = default_profile(&g.out_dir, &kirikae_recomp::project::package_name(&g.name));
    if !profile.is_file() {
        return Err(format!(
            "no play profile yet at {}: play the game first (`switchrecomp play {}`), the exe writes it every 10 s",
            profile.display(),
            g.name
        ));
    }
    if !g.source.exists() {
        return Err(format!("the original dump is gone: {}", g.source.display()));
    }
    let before = g.functions;
    let cfg = BuildCfg {
        name: Some(g.name.clone()),
        out: Some(g.out_dir.clone()),
        seed: g.seeded,
        fast_regs: g.fast_regs,
        linker: a.opt(&["--linker"]).map(linker::Choice::parse).transpose()?.unwrap_or(linker::Choice::Auto),
        ..BuildCfg::default()
    };
    let after = build_game(&g.source, &cfg)?;
    println!("switchrecomp: {} -> {} natively compiled functions", before, after.functions);
    Ok(())
}

fn cmd_play(args: &[String]) -> Result<(), String> {
    let a = parse(args)?;
    let lib = Library::load();
    let g = game(&lib, a.arg(0, "game name")?)?;
    if !g.executable.is_file() {
        return Err(format!("{} is missing; rebuild with `switchrecomp build \"{}\"`", g.executable.display(), g.source.display()));
    }
    let mut cmd = Command::new(&g.executable);
    cmd.current_dir(&g.out_dir);
    if a.flag("--stats") {
        cmd.env("KIRIKAE_STATS", "1");
    }
    if a.flag("--vsync") {
        cmd.env("KIRIKAE_VSYNC", "1");
    }
    if a.flag("--handheld") {
        cmd.env("KIRIKAE_NPAD", "handheld");
    }
    if a.flag("--headless") {
        cmd.env("KIRIKAE_HEADLESS", "1");
    }
    println!("switchrecomp: starting {}", g.title.as_deref().unwrap_or(&g.name));
    let status = cmd.status().map_err(|e| format!("{}: {e}", g.executable.display()))?;
    let profile = default_profile(&g.out_dir, &kirikae_recomp::project::package_name(&g.name));
    if profile.is_file() {
        println!("switchrecomp: play profile saved; `switchrecomp refine {}` compiles what was interpreted", g.name);
    }
    if status.success() { Ok(()) } else { Err(format!("the game exited with {status}; see the log above, and `switchrecomp coverage {}`", g.name)) }
}

fn cmd_coverage(args: &[String]) -> Result<(), String> {
    let a = parse(args)?;
    let lib = Library::load();
    let g = game(&lib, a.arg(0, "game name")?)?;
    let file = g.out_dir.join(format!("{}.coverage.json", kirikae_recomp::project::package_name(&g.name)));
    let text = std::fs::read_to_string(&file).map_err(|_| format!("no coverage report yet at {} (play the game first)", file.display()))?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", file.display()))?;

    // Count statuses per top-level section without depending on the exact schema.
    fn walk(v: &serde_json::Value, counts: &mut [usize; 3], missing: &mut Vec<String>, path: &str) {
        match v {
            serde_json::Value::Object(m) => {
                if let Some(serde_json::Value::String(s)) = m.get("status") {
                    match s.as_str() {
                        "implemented" => counts[0] += 1,
                        "stub" => counts[1] += 1,
                        "missing" => {
                            counts[2] += 1;
                            let label = m.get("name").and_then(|n| n.as_str()).map_or(path.to_string(), |n| format!("{path} {n}"));
                            missing.push(label);
                        }
                        _ => {}
                    }
                }
                for (k, child) in m {
                    walk(child, counts, missing, if path.is_empty() { k.as_str() } else { path });
                }
            }
            serde_json::Value::Array(a) => a.iter().for_each(|c| walk(c, counts, missing, path)),
            serde_json::Value::String(s) if matches!(s.as_str(), "implemented" | "stub" | "missing") => match s.as_str() {
                "implemented" => counts[0] += 1,
                "stub" => counts[1] += 1,
                _ => {
                    counts[2] += 1;
                    missing.push(path.to_string());
                }
            },
            _ => {}
        }
    }

    println!("{}  ({})\n", g.title.as_deref().unwrap_or(&g.name), file.display());
    let sections: Vec<(String, &serde_json::Value)> = match &v {
        serde_json::Value::Object(m) => m.iter().map(|(k, v)| (k.clone(), v)).collect(),
        other => vec![("all".into(), other)],
    };
    let mut any_missing = Vec::new();
    for (name, section) in sections {
        let mut c = [0usize; 3];
        let mut missing = Vec::new();
        walk(section, &mut c, &mut missing, &name);
        if c.iter().sum::<usize>() == 0 {
            continue;
        }
        println!("  {name:<14} {:>5} implemented  {:>5} stubbed  {:>5} missing", c[0], c[1], c[2]);
        any_missing.extend(missing);
    }
    if !any_missing.is_empty() {
        any_missing.sort();
        any_missing.dedup();
        println!("\nmissing (first {}):", any_missing.len().min(25));
        for m in any_missing.iter().take(25) {
            println!("  {m}");
        }
        println!("\nThese are what Kirikae's runtime still lacks for this game; report them upstream with the coverage file.");
    }
    Ok(())
}

fn cmd_list() -> Result<(), String> {
    let lib = Library::load();
    if lib.games.is_empty() {
        println!("no games built yet: `switchrecomp build <dump>`");
        return Ok(());
    }
    println!("{:<28} {:<18} {:>8} {:>7}  {}", "name", "title id", "funcs", "builds", "executable");
    for g in &lib.games {
        let present = if g.executable.is_file() { "" } else { "  (missing)" };
        println!(
            "{:<28} {:<18} {:>8} {:>7}  {}{present}",
            g.name,
            g.title_id.as_deref().unwrap_or("-"),
            g.functions,
            g.builds,
            g.executable.display()
        );
    }
    Ok(())
}

fn cmd_syms(args: &[String]) -> Result<(), String> {
    let a = parse(args)?;
    let loaded = input::load(Path::new(a.arg(0, "dump")?))?;
    let pattern = a.positional.get(1).map_or("", String::as_str);
    for m in &loaded.exe.modules {
        for (addr, name) in kirikae_loader::dynamic::function_symbols(&m.image) {
            if name.contains(pattern) {
                println!("{}+{:#x}  {name}", m.name, addr - m.image.base);
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------- scan

const DUMP_EXTS: &[&str] = &["nsp", "nsz", "xci", "xcz", "nso", "nro"];

/// The title ID and version in the usual dump names: "Game [0100...000][v131072].nsp", "Game.0100...800.v131072.nsp"
fn name_tags(name: &str) -> (Option<String>, Option<u64>) {
    let up = name.to_ascii_uppercase();
    let b = up.as_bytes();
    let mut tid = None;
    for i in 0..b.len().saturating_sub(15) {
        // Switch title IDs start 01 (Switch 2: 04) and are 16 hex digits standing on their own
        if b[i] == b'0' && (b[i + 1] == b'1' || b[i + 1] == b'4') && b[i..i + 16].iter().all(u8::is_ascii_hexdigit) {
            let before = i == 0 || !b[i - 1].is_ascii_alphanumeric();
            let after = i + 16 == b.len() || !b[i + 16].is_ascii_alphanumeric();
            if before && after {
                tid = Some(up[i..i + 16].to_string());
                break;
            }
        }
    }
    let lower = name.to_ascii_lowercase();
    let mut ver = None;
    for (i, _) in lower.match_indices('v') {
        let prev_ok = i == 0 || !lower.as_bytes()[i - 1].is_ascii_alphanumeric();
        let digits: String = lower[i + 1..].chars().take_while(char::is_ascii_digit).collect();
        if prev_ok && !digits.is_empty() && lower[i + 1 + digits.len()..].chars().next().is_none_or(|c| !c.is_ascii_alphanumeric()) {
            ver = digits.parse().ok();
            break;
        }
    }
    (tid, ver)
}

/// Base game, update or DLC from a title ID: base ...000, update ...800, add-on content otherwise
fn role(tid: Option<&str>) -> &'static str {
    match tid {
        Some(t) if t.ends_with("800") => "update",
        Some(t) if t.ends_with("000") => "base",
        Some(_) => "dlc",
        None => "unknown",
    }
}

fn scan_candidates(dir: &Path, depth: u32, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut entries: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            if p.join("main").is_file() || p.join("exefs").join("main").is_file() {
                out.push(p);
            } else if depth > 0 && !p.file_name().is_some_and(|n| n.eq_ignore_ascii_case("exefs") || n.eq_ignore_ascii_case("romfs")) {
                scan_candidates(&p, depth - 1, out);
            }
        } else if p.extension().is_some_and(|e| DUMP_EXTS.iter().any(|x| e.eq_ignore_ascii_case(x))) {
            out.push(p);
        }
    }
}

/// "Super Mario Odyssey [0100000000010000][v0].nsp" -> "Super Mario Odyssey"
fn pretty_name(file: &str) -> String {
    let stem = file.rsplit_once('.').filter(|(_, e)| DUMP_EXTS.iter().any(|x| e.eq_ignore_ascii_case(x))).map_or(file, |(s, _)| s);
    let cut = stem.find(['[', '(']).unwrap_or(stem.len());
    let mut n = stem[..cut].trim().to_string();
    // "Mario.Party.Superstars.01006FE013472800.v131072" style
    if let Some(i) = n.find(".01").or_else(|| n.find(".04")) {
        n.truncate(i);
    }
    let n = n.replace('.', " ").trim().to_string();
    if n.is_empty() { stem.to_string() } else { n }
}

fn cmd_scan(args: &[String]) -> Result<(), String> {
    let a = parse(args)?;
    if a.positional.is_empty() {
        return Err(format!("missing folder\n\n{USAGE}"));
    }
    let sudachi = sudachi::dump_dir(None).map(|d| std::path::absolute(&d).unwrap_or(d));
    let lib = Library::load();
    let mut rows = Vec::new();
    let mut count = 0usize;
    for (fi, folder) in a.positional.iter().enumerate() {
        let dir = PathBuf::from(folder);
        if !dir.is_dir() {
            eprintln!("switchrecomp: {} is not a folder (skipped)", dir.display());
            continue;
        }
        let from_sudachi = sudachi.as_ref().is_some_and(|s| std::path::absolute(&dir).is_ok_and(|d| &d == s));
        let mut found = Vec::new();
        scan_candidates(&dir, 2, &mut found);
        count += found.len();
        for p in &found {
            let kind = input::classify(p);
            let file = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let (tid, ver) = name_tags(&file);
            let size = if p.is_dir() { 0 } else { std::fs::metadata(p).map_or(0, |m| m.len()) };
            let abs = std::path::absolute(p).unwrap_or_else(|_| p.clone());
            let built = lib.games.iter().find(|g| g.source == abs).map(|g| g.name.clone());
            let role = role(tid.as_deref());
            // a folder dump: does it carry the RomFS (most games need their data)
            let romfs = !p.is_dir() || p.join("romfs").is_dir() || p.parent().is_some_and(|q| q.join("romfs").is_dir() && p.ends_with("exefs"));
            let mut note = if role == "update" || role == "dlc" {
                Some("Kirikae builds base games only: updates and DLC are not supported yet.".to_string())
            } else {
                None
            };
            if p.is_dir() && !romfs {
                note = Some(if from_sudachi {
                    "ExeFS only: also right-click the game in Sudachi -> Dump RomFS, most games need their data.".into()
                } else {
                    "No romfs\\ folder beside exefs\\: most games need their data.".into()
                });
            }
            let name = if p.is_dir() && tid.as_deref() == Some(file.to_ascii_uppercase().as_str()) { file.to_ascii_uppercase() } else { pretty_name(&file) };
            if !a.flag("--json") {
                println!(
                    "{:<9} {:<30} {:>9.2} GB  {}{}{}",
                    if kind.recompilable() && role != "update" && role != "dlc" { "ready" } else { "not ready" },
                    kind.label(),
                    size as f64 / 1e9,
                    file,
                    if from_sudachi { "  (Sudachi dump)" } else { "" },
                    built.as_deref().map(|b| format!("  (built: {b})")).unwrap_or_default()
                );
            }
            rows.push(serde_json::json!({
                "path": abs, "file": file, "name": name, "kind": kind.label(), "recompilable": kind.recompilable(),
                "fix": kind.fix(), "size": size, "title_id": tid, "version": ver, "role": role, "note": note, "built": built,
                "folder": fi, "sudachi": from_sudachi, "romfs": romfs,
            }));
        }
    }
    if a.flag("--json") {
        // one line, so the app can tell it from the log
        println!("SCAN_JSON {}", serde_json::Value::Array(rows));
    } else {
        println!("\n{count} dump(s) in {} folder(s)", a.positional.len());
    }
    Ok(())
}

fn cmd_sudachi() -> Result<(), String> {
    match sudachi::dump_dir(None) {
        Some(d) => {
            println!("{}", d.display());
            Ok(())
        }
        None => Err("no Sudachi dump folder found (%APPDATA%\\sudachi\\dump): turn on Dump ExeFS in Sudachi's settings and start a game once".into()),
    }
}

// ---------------------------------------------------------------- interactive menu

fn prompt(q: &str) -> String {
    print!("{q}");
    let _ = std::io::stdout().flush();
    let mut s = String::new();
    let _ = std::io::stdin().lock().read_line(&mut s);
    s.trim().trim_matches('"').to_string()
}

fn menu() -> Result<(), String> {
    loop {
        let lib = Library::load();
        println!("\n=== switchrecomp (Kirikae) ===");
        if lib.games.is_empty() {
            println!("  no games built yet");
        }
        for (i, g) in lib.games.iter().enumerate() {
            println!("  {}. {}  [{} functions, build {}]", i + 1, g.title.as_deref().unwrap_or(&g.name), g.functions, g.builds);
        }
        println!("\n  b) build a dump     p) play     r) refine     c) coverage");
        println!("  i) inspect a dump   x) extract   d) doctor     q) quit");
        let choice = prompt("> ");
        let pick_game = |lib: &Library| -> Option<String> {
            if lib.games.len() == 1 {
                return Some(lib.games[0].name.clone());
            }
            let s = prompt("game number or name: ");
            match s.parse::<usize>() {
                Ok(n) if n >= 1 && n <= lib.games.len() => Some(lib.games[n - 1].name.clone()),
                _ if !s.is_empty() => Some(s),
                _ => None,
            }
        };
        let r = match choice.as_str() {
            "b" => {
                let p = prompt("path to NSP / exefs folder / NSO (drag it here): ");
                if p.is_empty() { Ok(()) } else { build_game(Path::new(&p), &BuildCfg::default()).map(|_| ()) }
            }
            "i" => {
                let p = prompt("path: ");
                cmd_inspect(&[p])
            }
            "x" => {
                let p = prompt("dump path: ");
                let o = prompt("output folder: ");
                cmd_extract(&[p, o])
            }
            "p" | "r" | "c" => match pick_game(&lib) {
                Some(n) => match choice.as_str() {
                    "p" => cmd_play(&[n]),
                    "r" => cmd_refine(&[n]),
                    _ => cmd_coverage(&[n]),
                },
                None => Ok(()),
            },
            "d" => cmd_doctor(),
            "q" | "" => return Ok(()),
            other => Err(format!("unknown choice `{other}`")),
        };
        if let Err(e) = r {
            eprintln!("\nswitchrecomp: {e}");
        }
    }
}

// ---------------------------------------------------------------- decryption (switchrecomp-studio)

fn cmd_decrypt(args: &[String]) -> Result<(), String> {
    let a = parse(args)?;
    let input = Path::new(a.arg(0, "dump")?);
    let keys = crypto::keys::Keys::load(a.opt(&["--keys"]).map(Path::new))?;
    let out = a.opt(&["-o", "--out"]).map(PathBuf::from).unwrap_or_else(|| crypto::decrypted_dir_for(input));
    if out.join("exefs").join("main").is_file() && !a.flag("--force") {
        println!("already decrypted: {} (pass --force to decrypt again)", out.display());
        return Ok(());
    }
    let started = Instant::now();
    eprintln!("switchrecomp: decrypting {} with {}", input.display(), keys.prod_path.as_deref().map_or("?".into(), |p| p.display().to_string()));
    if let Some(update) = a.opt(&["--update"]) {
        // code, control data and metadata from the update; RomFS = base game RomFS with the update's patch applied
        let update = Path::new(update);
        let r = crypto::decrypt_package(update, &out, &keys, &crypto::Options { romfs: false })?;
        // the patch reader needs plain NSPs: uncompress NSZ/XCZ inputs to temporary copies first
        let base_tmp = crypto::ncz::uncompressed_copy(input, &out, &keys)?;
        let update_tmp = crypto::ncz::uncompressed_copy(update, &out, &keys)?;
        let (input, update) = (base_tmp.as_deref().unwrap_or(input), update_tmp.as_deref().unwrap_or(update));
        let cleanup = || {
            for t in [&base_tmp, &update_tmp].into_iter().flatten() {
                let _ = std::fs::remove_file(t);
            }
        };
        println!("update     {:016X} v{} ({}), exefs {} files, {} blocks verified", r.title_id, r.version, r.key_source, r.exefs_files, r.verified_blocks);
        if !a.flag("--no-romfs") {
            let p = crypto::patch::write_patched_romfs(input, update, &keys, &out.join("romfs.bin"));
            cleanup();
            let p = p?;
            println!(
                "romfs      {:.1} MiB patched ({} ranges, {:.1} MiB from the update)",
                p.bytes as f64 / (1u64 << 20) as f64,
                p.ranges,
                p.from_patch as f64 / (1u64 << 20) as f64
            );
        }
        cleanup();
        println!("took       {:.1}s; build it with `switchrecomp build \"{}\"`", started.elapsed().as_secs_f64(), out.display());
        return Ok(());
    }
    let r = crypto::decrypt_package(input, &out, &keys, &crypto::Options { romfs: !a.flag("--no-romfs") })?;
    println!("decrypted  {} -> {}", input.display(), out.display());
    println!("title      {:016X} v{}", r.title_id, r.version);
    println!("container  {:?}, master key {:02x}, {}", r.container, r.master_key, r.key_source);
    println!("exefs      {} files, {} blocks verified against SHA-256", r.exefs_files, r.verified_blocks);
    if r.romfs_lz4_blocks > 0 {
        println!("romfs      {:.1} MiB (decompressed from {} LZ4 blocks)", r.romfs_bytes as f64 / (1u64 << 20) as f64, r.romfs_lz4_blocks);
    } else {
        println!("romfs      {:.1} MiB", r.romfs_bytes as f64 / (1u64 << 20) as f64);
    }
    for w in &r.warnings {
        println!("warning    {w}");
    }
    println!("took       {:.1}s; build it with `switchrecomp build \"{}\"`", started.elapsed().as_secs_f64(), out.display());
    Ok(())
}

fn cmd_keys(args: &[String]) -> Result<(), String> {
    let a = parse(args)?;
    let keys = crypto::keys::Keys::load(a.opt(&["--keys"]).map(Path::new))?;
    println!("prod.keys   {}", keys.prod_path.as_deref().map_or("-".into(), |p| p.display().to_string()));
    println!("title.keys  {} ({} title keys)", keys.title_path.as_deref().map_or("-".into(), |p| p.display().to_string()), keys.title_key_count());
    println!("eTicket     {}", keys.eticket_status);
    let Some(newest) = keys.newest_generation() else {
        return Err("prod.keys has no key_area_key_application_XX keys".into());
    };
    println!("master keys 00..{newest:02x} (content needing a newer master key will not decrypt)");
    let mut missing = Vec::new();
    for g in 0..=newest {
        for kind in ["key_area_key_application", "titlekek"] {
            let name = format!("{kind}_{g:02x}");
            if keys.key16(&name).is_none() {
                missing.push(name);
            }
        }
    }
    if missing.is_empty() {
        println!("complete    every generation has its key area and title key keys");
    } else {
        println!("missing     {}", missing.join(", "));
    }
    Ok(())
}
