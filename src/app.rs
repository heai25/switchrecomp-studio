//! SwitchRecomp: the desktop app over switchrecomp.exe.
//!
//! A window with your game library, drag-and-drop for dumps, and buttons for what the command line does (inspect, build,
//! play, refine, coverage, extract, doctor). Every action runs switchrecomp.exe as a child process and streams its output
//! into the log, so a recompile that takes many minutes, or crashes, never freezes or takes down the window.
#![windows_subsystem = "windows"]

#[path = "library.rs"]
#[allow(dead_code)]
mod library;
#[path = "sudachi.rs"]
mod sudachi;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use eframe::egui::{self, Color32, RichText};
use library::{Game, Library};
use serde::{Deserialize, Serialize};

/// lines kept in the log (older ones drop off the top)
const LOG_CAP: usize = 30_000;
const DUMP_EXTS: &[&str] = &["nsp", "nso", "nro", "nsz", "xci", "xcz"];

/// One dump found by `switchrecomp scan --json`
#[derive(Deserialize, Clone)]
struct DumpRow {
    path: PathBuf,
    name: String,
    kind: String,
    recompilable: bool,
    fix: Option<String>,
    size: u64,
    title_id: Option<String>,
    version: Option<u64>,
    role: String,
    note: Option<String>,
    #[serde(default)]
    sudachi: bool,
    #[serde(default = "yes")]
    romfs: bool,
}

fn yes() -> bool {
    true
}

impl DumpRow {
    fn ready(&self) -> bool {
        self.recompilable && self.role != "update" && self.role != "dlc"
    }
    fn status(&self) -> (&'static str, Color32) {
        if self.ready() {
            ("ready to build", Color32::from_rgb(80, 170, 95))
        } else if self.role == "update" {
            ("update: base games only", Color32::from_rgb(140, 140, 150))
        } else if self.role == "dlc" {
            ("DLC: base games only", Color32::from_rgb(140, 140, 150))
        } else {
            ("needs a decrypted dump", Color32::from_rgb(215, 130, 50))
        }
    }
}

/// The app's own settings, beside library.json
#[derive(Serialize, Deserialize)]
struct Settings {
    dumps_dir: Option<PathBuf>,
    /// don't list or watch Sudachi's dump folder
    #[serde(default)]
    sudachi_off: bool,
    // play options
    #[serde(default = "yes")]
    vsync: bool,
    #[serde(default)]
    stats: bool,
    #[serde(default)]
    handheld: bool,
    // build options
    #[serde(default = "yes")]
    seed: bool,
    #[serde(default)]
    fast_regs: bool,
    /// auto, lld or msvc
    #[serde(default = "auto")]
    linker: String,
}

fn auto() -> String {
    "auto".into()
}

impl Default for Settings {
    fn default() -> Settings {
        Settings { dumps_dir: None, sudachi_off: false, vsync: true, stats: false, handheld: false, seed: true, fast_regs: false, linker: auto() }
    }
}

/// How a log line is shown
#[derive(Clone, Copy, PartialEq)]
enum Tone {
    Plain,
    Command,
    Good,
    Bad,
    Warn,
    Quiet,
}

impl Tone {
    fn of(s: &str) -> Tone {
        let t = s.trim_start();
        let lower = t.to_ascii_lowercase();
        if t.starts_with("> ") {
            Tone::Command
        } else if lower.starts_with("error") || lower.contains("error:") || lower.contains(" failed") || t.contains("[FAIL]") || lower.starts_with("thread '") {
            Tone::Bad
        } else if lower.starts_with("warning") || lower.contains("warning:") {
            Tone::Warn
        } else if t.starts_with("== ") || t.contains("[ ok ]") || t.starts_with("Finished `release`") {
            Tone::Good
        } else if ["Compiling ", "Updating ", "Locking ", "Adding ", "Downloaded ", "Downloading ", "Fresh "].iter().any(|p| t.starts_with(p)) {
            Tone::Quiet
        } else {
            Tone::Plain
        }
    }

    fn color(self, ui: &egui::Ui) -> Color32 {
        match self {
            Tone::Plain => ui.visuals().text_color(),
            Tone::Command => Color32::from_rgb(110, 165, 240),
            Tone::Good => Color32::from_rgb(110, 200, 120),
            Tone::Bad => Color32::from_rgb(235, 100, 90),
            Tone::Warn => Color32::from_rgb(220, 180, 80),
            Tone::Quiet => ui.visuals().weak_text_color(),
        }
    }
}

struct LogLine {
    text: String,
    tone: Tone,
}

fn settings_path() -> PathBuf {
    library::home().join("switchrecomp-app.json")
}

impl Settings {
    fn load() -> Settings {
        std::fs::read_to_string(settings_path()).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
    }
    fn save(&self) {
        if let Ok(t) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(settings_path(), t);
        }
    }
}

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Library,
    Dumps,
}

enum Msg {
    Line(String),
    Eof,
}

struct Job {
    label: String,
    child: Child,
    rx: Receiver<Msg>,
    eofs: u8,
    started: Instant,
    /// what the job is doing now, read from its output
    phase: String,
    /// 0..1 when the output says how far along it is
    progress: Option<f32>,
    crates: usize,
}

impl Job {
    /// Follows a build (or extract) through the lines switchrecomp, Kirikae and cargo print
    fn track(&mut self, line: &str) {
        let t = line.trim();
        let frac = |s: &str| -> Option<(f32, f32)> {
            let (a, b) = s.split_whitespace().next()?.split_once('/')?;
            Some((a.parse().ok()?, b.parse::<f32>().ok()?.max(1.0)))
        };
        if t.starts_with("switchrecomp: reading") {
            self.phase = "Reading the dump".into();
            self.progress = Some(0.01);
        } else if t.starts_with("switchrecomp: analysing") {
            self.phase = "Finding functions".into();
            self.progress = Some(0.03);
        } else if t.starts_with("switchrecomp: seeded") || t.starts_with("switchrecomp: linking with") {
            self.phase = "Finding functions".into();
            self.progress = Some(0.10);
        } else if let Some(rest) = t.strip_prefix("kirikae: code generation ") {
            if let Some((d, n)) = frac(rest) {
                self.phase = format!("Generating native code  {d}/{n} objects");
                self.progress = Some(0.12 + 0.58 * d / n);
            }
        } else if let Some(rest) = t.strip_prefix("Compiling ") {
            self.crates += 1;
            let krate = rest.split_whitespace().next().unwrap_or("");
            if rest.trim_end().ends_with("-build)") {
                self.phase = "Compiling and linking the game".into();
                self.progress = Some(0.93);
            } else {
                self.phase = format!("Compiling the runtime ({krate})");
                self.progress = Some((0.72 + 0.003 * self.crates as f32).min(0.9));
            }
        } else if t.starts_with("Finished `release`") {
            self.phase = "Copying the executable".into();
            self.progress = Some(0.98);
        } else if let Some(rest) = t.strip_prefix("switchrecomp: romfs ") {
            if let Some((d, n)) = frac(rest) {
                self.phase = format!("Extracting RomFS  {d}/{n} files");
                self.progress = Some(d / n);
            }
        }
    }
}

struct App {
    tool: PathBuf,
    lib: Library,
    selected: Option<String>,
    dump: Option<PathBuf>,
    build_name: String,
    fresh: bool,
    filter: String,
    log: Vec<LogLine>,
    job: Option<Job>,
    status: Option<(String, bool)>,
    tab: Tab,
    settings: Settings,
    dumps: Vec<DumpRow>,
    scan_pending: bool,
    sudachi_dir: Option<PathBuf>,
    watch_sig: String,
    watch_at: Instant,
}

fn tool_path() -> PathBuf {
    let dir = std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf)).unwrap_or_else(|| PathBuf::from("."));
    dir.join("switchrecomp.exe")
}

fn quote(a: &str) -> String {
    if a.contains(' ') { format!("\"{a}\"") } else { a.to_string() }
}

fn ago(unix: u64) -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let s = now.saturating_sub(unix);
    match s {
        0..=59 => "just now".into(),
        60..=3599 => format!("{} min ago", s / 60),
        3600..=86399 => format!("{} h ago", s / 3600),
        _ => format!("{} days ago", s / 86400),
    }
}

/// Reads a child's pipe and sends it on line by line; a carriage return (progress counters) ends a line too
fn reader(mut pipe: impl Read + Send + 'static, tx: Sender<Msg>, ctx: egui::Context) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 8192];
        let mut line = Vec::new();
        loop {
            match pipe.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    for &b in &buf[..n] {
                        if b == b'\n' || b == b'\r' {
                            if !line.is_empty() || b == b'\n' {
                                let _ = tx.send(Msg::Line(String::from_utf8_lossy(&line).into_owned()));
                            }
                            line.clear();
                        } else {
                            line.push(b);
                        }
                    }
                    ctx.request_repaint();
                }
            }
        }
        if !line.is_empty() {
            let _ = tx.send(Msg::Line(String::from_utf8_lossy(&line).into_owned()));
        }
        let _ = tx.send(Msg::Eof);
        ctx.request_repaint();
    });
}

impl App {
    fn new() -> App {
        let mut app = App {
            tool: tool_path(),
            lib: Library::load(),
            selected: None,
            dump: None,
            build_name: String::new(),
            fresh: false,
            filter: String::new(),
            log: Vec::new(),
            job: None,
            status: None,
            tab: Tab::Library,
            settings: Settings::load(),
            dumps: Vec::new(),
            scan_pending: false,
            sudachi_dir: sudachi::dump_dir(None),
            watch_sig: String::new(),
            watch_at: Instant::now(),
        };
        if let Some(d) = &app.sudachi_dir {
            let msg = format!("Sudachi dump folder: {} (watched: new dumps appear in the Dumps list)", d.display());
            app.line(&msg);
        }
        // the dumps folder chosen last time, and Sudachi's dumps, are scanned again at start
        if app.settings.dumps_dir.as_ref().is_some_and(|d| d.is_dir()) || app.sudachi_dir.is_some() {
            app.scan_pending = true;
            app.tab = Tab::Dumps;
        }
        app.selected = app.lib.games.first().map(|g| g.name.clone());
        // a dump given on the command line: dropping a file on the app's icon in Explorer opens it
        if let Some(p) = std::env::args_os().nth(1).map(PathBuf::from).filter(|p| p.exists()) {
            app.dump = Some(p);
        }
        if !app.tool.is_file() {
            app.line(&format!("switchrecomp.exe was not found next to this app ({}). Run setup.bat.", app.tool.display()));
        } else {
            app.line("Drop an NSP, a dump folder (exefs/ + romfs/), an NSO or an NRO on this window, or use Open dump.");
        }
        app
    }

    fn line(&mut self, s: &str) {
        for part in s.split('\n') {
            self.log.push(LogLine { text: part.to_string(), tone: Tone::of(part) });
        }
        if self.log.len() > LOG_CAP {
            let cut = self.log.len() - LOG_CAP;
            self.log.drain(..cut);
        }
    }

    fn log_text(&self) -> String {
        self.log.iter().map(|l| l.text.as_str()).collect::<Vec<_>>().join("\n")
    }

    /// --no-seed / --fast-regs / --linker from the saved build options
    fn build_flags(&self, seed: bool, fast_regs: bool) -> Vec<String> {
        let mut v = Vec::new();
        if !seed {
            v.push("--no-seed".into());
        }
        if fast_regs {
            v.push("--fast-regs".into());
        }
        if self.settings.linker != "auto" {
            v.push("--linker".into());
            v.push(self.settings.linker.clone());
        }
        v
    }

    fn matches(&self, texts: &[&str]) -> bool {
        let f = self.filter.trim().to_ascii_lowercase();
        f.is_empty() || texts.iter().any(|t| t.to_ascii_lowercase().contains(&f))
    }

    fn game(&self) -> Option<&Game> {
        self.selected.as_deref().and_then(|n| self.lib.games.iter().find(|g| g.name == n))
    }

    fn run(&mut self, ctx: &egui::Context, label: &str, args: Vec<String>) {
        if self.job.is_some() {
            return;
        }
        if !self.tool.is_file() {
            self.line(&format!("switchrecomp.exe is missing: {}", self.tool.display()));
            return;
        }
        let mut cmd = Command::new(&self.tool);
        cmd.args(&args)
            .current_dir(library::home())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("PROMPT", "$P$G"); // tells switchrecomp it is not double-clicked: never wait for Enter
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW: no console flashes up
        }
        self.line(&format!("\n> switchrecomp {}", args.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" ")));
        match cmd.spawn() {
            Ok(mut child) => {
                let (tx, rx) = channel();
                if let Some(o) = child.stdout.take() {
                    reader(o, tx.clone(), ctx.clone());
                }
                if let Some(e) = child.stderr.take() {
                    reader(e, tx, ctx.clone());
                }
                self.status = None;
                self.job = Some(Job { label: label.to_string(), child, rx, eofs: 0, started: Instant::now(), phase: String::new(), progress: None, crates: 0 });
            }
            Err(e) => self.line(&format!("could not start switchrecomp.exe: {e}")),
        }
    }

    fn cancel(&mut self) {
        if let Some(job) = &mut self.job {
            // the whole tree: switchrecomp, the cargo build or the game it started
            let pid = job.child.id().to_string();
            let mut kill = Command::new("taskkill");
            kill.args(["/T", "/F", "/PID", &pid]);
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                kill.creation_flags(0x0800_0000);
            }
            if kill.status().is_err() {
                let _ = job.child.kill();
            }
            self.line("(cancelled)");
        }
    }

    fn poll(&mut self) {
        let Some(job) = &mut self.job else { return };
        let mut lines = Vec::new();
        while let Ok(m) = job.rx.try_recv() {
            match m {
                Msg::Line(l) => lines.push(l),
                Msg::Eof => job.eofs += 1,
            }
        }
        let finished = if job.eofs >= 2 { job.child.wait().ok() } else { None };
        for l in &lines {
            job.track(l);
        }
        for l in lines {
            if let Some(json) = l.strip_prefix("SCAN_JSON ") {
                match serde_json::from_str::<Vec<DumpRow>>(json) {
                    Ok(rows) => {
                        let ready = rows.iter().filter(|r| r.ready()).count();
                        self.line(&format!("{} dump(s) found, {} ready to build", rows.len(), ready));
                        self.dumps = rows;
                    }
                    Err(e) => self.line(&format!("could not read the scan: {e}")),
                }
            } else {
                self.line(&l);
            }
        }
        if let Some(status) = finished {
            let job = self.job.take().unwrap();
            let secs = job.started.elapsed().as_secs_f64();
            let ok = status.success();
            let text = if ok { format!("{} finished in {:.0}s", job.label, secs) } else { format!("{} failed ({status}) after {:.0}s: see the log", job.label, secs) };
            self.line(&format!("== {text}"));
            self.status = Some((text, ok));
            self.reload();
        }
    }

    fn reload(&mut self) {
        self.lib = Library::load();
        // a build of the open dump selects the game it made
        if let Some(d) = &self.dump {
            let abs = std::path::absolute(d).unwrap_or_else(|_| d.clone());
            if let Some(g) = self.lib.games.iter().find(|g| g.source == abs) {
                self.selected = Some(g.name.clone());
            }
        }
        if self.game().is_none() {
            self.selected = self.lib.games.first().map(|g| g.name.clone());
        }
    }

    fn watched(&self) -> Vec<PathBuf> {
        let mut v = Vec::new();
        if let Some(d) = &self.settings.dumps_dir {
            v.push(d.clone());
        }
        if !self.settings.sudachi_off
            && let Some(d) = &self.sudachi_dir
            && !v.contains(d)
        {
            v.push(d.clone());
        }
        v
    }

    fn scan(&mut self, ctx: &egui::Context) {
        let dirs = self.watched();
        if dirs.is_empty() {
            return;
        }
        self.watch_sig = self.signature();
        let mut args = vec!["scan".to_string()];
        args.extend(dirs.iter().map(|d| d.display().to_string()));
        args.push("--json".into());
        self.run(ctx, "scan", args);
    }

    /// A cheap fingerprint of the watched folders: their entries, sizes and times, and for dump folders whether exefs\ and
    /// romfs\ exist. Sudachi writing a new dump changes it; the files a long RomFS dump keeps adding inside romfs\ do not
    fn signature(&self) -> String {
        let mut sig = String::new();
        for d in self.watched() {
            let Ok(rd) = std::fs::read_dir(&d) else { continue };
            let mut items: Vec<String> = rd
                .filter_map(|e| e.ok())
                .map(|e| {
                    let p = e.path();
                    let m = e.metadata().ok();
                    let len = m.as_ref().map_or(0, |m| if m.is_file() { m.len() } else { 0 });
                    let main = p.join("exefs").join("main");
                    let t = std::fs::metadata(&main).and_then(|m| m.modified()).ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs());
                    format!("{}|{len}|{}|{t}|{}", e.file_name().to_string_lossy(), main.is_file(), p.join("romfs").is_dir())
                })
                .collect();
            items.sort();
            sig.push_str(&d.display().to_string());
            sig.push('\n');
            sig.push_str(&items.join("\n"));
            sig.push('\n');
        }
        sig
    }

    fn watch(&mut self, ctx: &egui::Context) {
        if self.watch_at.elapsed().as_secs() < 3 {
            return;
        }
        self.watch_at = Instant::now();
        if self.sudachi_dir.is_none() {
            self.sudachi_dir = sudachi::dump_dir(None);   // Sudachi made its dump folder after the app started
        }
        if self.job.is_some() || self.watch_sig.is_empty() {
            return;
        }
        if self.signature() != self.watch_sig {
            self.line("a dump folder changed: scanning again");
            self.scan(ctx);
        }
    }

    /// The game's name for a title-ID folder (a Sudachi dump): from a file of the same title in the list
    fn display_name(&self, r: &DumpRow) -> String {
        if r.sudachi
            && let Some(t) = &r.title_id
        {
            if let Some(o) = self.dumps.iter().find(|o| !o.sudachi && o.title_id.as_deref() == Some(t)) {
                return o.name.clone();
            }
            return format!("Title {t}");
        }
        r.name.clone()
    }

    fn choose_dumps_dir(&mut self, ctx: &egui::Context) {
        let mut dlg = rfd::FileDialog::new().set_title("Folder with your dumps (NSP, XCI, NSO, NRO, exefs folders)");
        if let Some(d) = &self.settings.dumps_dir {
            dlg = dlg.set_directory(d);
        }
        if let Some(d) = dlg.pick_folder() {
            self.settings.dumps_dir = Some(d);
            self.settings.save();
            self.dumps.clear();
            self.tab = Tab::Dumps;
            self.scan(ctx);
        }
    }

    fn row_for(&self, p: &Path) -> Option<&DumpRow> {
        let abs = std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
        self.dumps.iter().find(|r| r.path == abs)
    }

    fn built_from(&self, p: &Path) -> Option<&Game> {
        self.lib.games.iter().find(|g| g.source == p)
    }

    fn set_dump(&mut self, p: PathBuf) {
        self.line(&format!("dump: {}", p.display()));
        self.build_name.clear();
        self.dump = Some(p);
    }

    // ------------------------------------------------------------ panels

    fn top(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let idle = self.job.is_none();
        ui.horizontal(|ui| {
            ui.heading(RichText::new("SwitchRecomp").strong());
            ui.label(RichText::new("your own Switch dumps into native Windows games, powered by Kirikae").weak());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.add_enabled(idle, egui::Button::new("Doctor")).on_hover_text("Check Rust, the MSVC linker, Vulkan and build paths").clicked() {
                    self.run(ctx, "doctor", vec!["doctor".into()]);
                }
                if ui.add_enabled(idle, egui::Button::new("Dumps folder...")).on_hover_text("Load every dump in a folder into the Dumps list").clicked() {
                    self.choose_dumps_dir(ctx);
                }
                if ui.button("Open folder").on_hover_text("Where library.json and games\\ live").clicked() {
                    let _ = Command::new("explorer").arg(library::home()).spawn();
                }
                if ui.add_enabled(idle, egui::Button::new("Open dump folder...")).on_hover_text("A folder with exefs\\ (and romfs\\)").clicked()
                    && let Some(p) = rfd::FileDialog::new().set_title("Dump folder (exefs + romfs)").pick_folder()
                {
                    self.set_dump(p);
                }
                if ui.add_enabled(idle, egui::Button::new("Open dump...")).on_hover_text("An NSP, NSO or NRO").clicked()
                    && let Some(p) = rfd::FileDialog::new().set_title("Switch dump").add_filter("Switch dumps", DUMP_EXTS).add_filter("All files", &["*"]).pick_file()
                {
                    self.set_dump(p);
                }
            });
        });
    }

    fn side(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.tab, Tab::Library, RichText::new(format!("Library ({})", self.lib.games.len())).strong());
            ui.selectable_value(&mut self.tab, Tab::Dumps, RichText::new(format!("Dumps ({})", self.dumps.len())).strong());
        });
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("Filter by name or title ID").desired_width(f32::INFINITY));
        });
        ui.separator();
        match self.tab {
            Tab::Library => self.library(ui),
            Tab::Dumps => self.dump_list(ui, ctx),
        }
    }

    fn dump_rows(&self, ui: &mut egui::Ui, sudachi: bool, pick: &mut Option<PathBuf>) {
        for r in self.dumps.iter().filter(|r| r.sudachi == sudachi) {
            let sel = self.dump.as_ref().is_some_and(|d| std::path::absolute(d).unwrap_or_else(|_| d.clone()) == r.path);
            let title = self.display_name(r);
            if !self.matches(&[&title, r.title_id.as_deref().unwrap_or(""), &r.path.to_string_lossy()]) {
                continue;
            }
            if ui.selectable_label(sel, RichText::new(title).strong()).on_hover_text(r.path.display().to_string()).clicked() {
                *pick = Some(r.path.clone());
            }
            let (st, col) = r.status();
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                ui.label(RichText::new(st).small().color(col));
                let mut meta = if sudachi { r.title_id.clone().unwrap_or_else(|| r.kind.clone()) } else { r.kind.clone() };
                if r.size > 0 {
                    meta.push_str(&format!("  ·  {:.1} GB", r.size as f64 / 1e9));
                }
                ui.label(RichText::new(meta).small().weak());
                if r.ready() && !r.romfs {
                    ui.label(RichText::new("no RomFS yet").small().color(Color32::from_rgb(215, 130, 50)));
                }
                if self.lib.games.iter().any(|g| g.source == r.path) {
                    ui.label(RichText::new("built").small().color(Color32::from_rgb(80, 140, 230)));
                }
            });
            ui.add_space(6.0);
        }
    }

    fn dump_list(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let idle = self.job.is_none();
        ui.horizontal(|ui| {
            if ui.add_enabled(idle, egui::Button::new("Rescan")).clicked() {
                self.scan(ctx);
            }
            if self.job.as_ref().is_some_and(|j| j.label == "scan") {
                ui.spinner();
            } else if !self.dumps.is_empty() {
                let ready = self.dumps.iter().filter(|r| r.ready()).count();
                ui.label(RichText::new(format!("{ready} of {} ready to build", self.dumps.len())).small().weak());
            }
        });
        ui.separator();
        let mut pick = None;
        egui::ScrollArea::vertical().id_salt("dumps").auto_shrink([false, false]).show(ui, |ui| {
            // your game folder
            ui.horizontal(|ui| {
                ui.label(RichText::new("Game folder").strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some(d) = self.settings.dumps_dir.clone()
                        && ui.small_button("Show").clicked()
                    {
                        let _ = Command::new("explorer").arg(d).spawn();
                    }
                    if ui.add_enabled(idle, egui::Button::new("Change...").small()).clicked() {
                        self.choose_dumps_dir(ctx);
                    }
                });
            });
            match &self.settings.dumps_dir {
                Some(d) => {
                    ui.label(RichText::new(d.display().to_string()).small().monospace().weak());
                }
                None => {
                    ui.label(RichText::new("Choose the folder that holds your dumps: every NSP, NSZ, XCI, NSO, NRO and exefs folder in it is listed.").small().weak());
                }
            }
            ui.add_space(4.0);
            self.dump_rows(ui, false, &mut pick);
            ui.add_space(8.0);
            ui.separator();
            // Sudachi's dump folder, watched
            ui.horizontal(|ui| {
                ui.label(RichText::new("Sudachi dumps").strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some(d) = self.sudachi_dir.clone()
                        && ui.small_button("Show").clicked()
                    {
                        let _ = Command::new("explorer").arg(d).spawn();
                    }
                    let mut on = !self.settings.sudachi_off;
                    if ui.checkbox(&mut on, "watch").on_hover_text("List Sudachi's dump folder and pick up new dumps as Sudachi writes them").changed() {
                        self.settings.sudachi_off = !on;
                        self.settings.save();
                        self.scan(ctx);
                    }
                });
            });
            match &self.sudachi_dir {
                Some(d) => {
                    ui.label(RichText::new(d.display().to_string()).small().monospace().weak());
                }
                None => {
                    ui.label(RichText::new("Sudachi's dump folder was not found (%APPDATA%\\sudachi).").small().weak());
                }
            }
            if !self.settings.sudachi_off && !self.dumps.iter().any(|r| r.sudachi) {
                ui.add_space(4.0);
                ui.label(
                    RichText::new(
                        "No dumps yet. In Sudachi, turn on Dump ExeFS in its settings and start the game once; then right-click the game and choose Dump RomFS. Each dump appears here by itself. Use keys from your own console.",
                    )
                    .small()
                    .weak(),
                );
            }
            ui.add_space(4.0);
            self.dump_rows(ui, true, &mut pick);
        });
        if let Some(p) = pick {
            self.set_dump(p);
        }
    }

    fn library(&mut self, ui: &mut egui::Ui) {
        if self.lib.games.is_empty() {
            ui.label(RichText::new("No games built yet.\nOpen or drop a dump, then Build.").weak());
        }
        let mut pick = None;
        egui::ScrollArea::vertical().id_salt("library").auto_shrink([false, false]).show(ui, |ui| {
            for g in &self.lib.games {
                let sel = self.selected.as_deref() == Some(g.name.as_str()) && self.dump.is_none();
                let title = g.title.clone().unwrap_or_else(|| g.name.clone());
                if !self.matches(&[&title, &g.name, g.title_id.as_deref().unwrap_or("")]) {
                    continue;
                }
                let mut sub = format!("{}  ·  {} functions", g.title_id.as_deref().unwrap_or("no title id"), g.functions);
                if !g.executable.is_file() {
                    sub.push_str("  ·  exe missing");
                }
                let r = ui.selectable_label(sel, RichText::new(title).strong());
                ui.label(RichText::new(sub).small().weak());
                ui.add_space(6.0);
                if r.clicked() {
                    pick = Some(g.name.clone());
                }
            }
        });
        if let Some(n) = pick {
            self.selected = Some(n);
            self.dump = None;
        }
    }

    fn dump_view(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, dump: PathBuf) {
        let idle = self.job.is_none();
        let d = dump.display().to_string();
        let row = self.row_for(&dump).cloned();
        ui.heading(row.as_ref().map_or("Dump".to_string(), |r| self.display_name(r)));
        ui.label(RichText::new(&d).monospace());
        let mut buildable = true;
        if let Some(r) = &row {
            ui.add_space(6.0);
            egui::Grid::new("dumpfacts").num_columns(2).spacing([16.0, 4.0]).show(ui, |ui| {
                ui.label(RichText::new("kind").weak());
                ui.label(&r.kind);
                ui.end_row();
                ui.label(RichText::new("contents").weak());
                ui.label(match r.role.as_str() { "base" => "base game", "update" => "update", "dlc" => "add-on content (DLC)", _ => "unknown" });
                ui.end_row();
                if let Some(t) = &r.title_id {
                    ui.label(RichText::new("title id").weak());
                    ui.label(format!("{t}{}", r.version.map(|v| format!("  (v{v})")).unwrap_or_default()));
                    ui.end_row();
                }
                if r.sudachi {
                    ui.label(RichText::new("from").weak());
                    ui.label("Sudachi's dump folder");
                    ui.end_row();
                }
                if r.size > 0 {
                    ui.label(RichText::new("size").weak());
                    ui.label(format!("{:.2} GB", r.size as f64 / 1e9));
                    ui.end_row();
                }
            });
            if r.ready() && !r.romfs
                && let Some(n) = &r.note
            {
                ui.add_space(8.0);
                ui.colored_label(Color32::from_rgb(215, 130, 50), n);
            }
            if !r.ready() {
                buildable = false;
                ui.add_space(8.0);
                let (st, col) = r.status();
                egui::Frame::group(ui.style()).stroke(egui::Stroke::new(1.0_f32, col)).show(ui, |ui| {
                    ui.label(RichText::new(format!("Not buildable as it is: {st}")).color(col).strong());
                    if let Some(n) = &r.note {
                        ui.label(n);
                    }
                    if let Some(f) = &r.fix {
                        ui.label(f);
                    }
                });
            }
        }
        if let Some(g) = self.built_from(&std::path::absolute(&dump).unwrap_or_else(|_| dump.clone())).cloned() {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new(format!("Built as {}", g.name)).color(Color32::from_rgb(80, 140, 230)));
                if ui.button("Open in library").clicked() {
                    self.selected = Some(g.name.clone());
                    self.dump = None;
                    self.tab = Tab::Library;
                }
            });
        }
        ui.add_space(8.0);
        ui.label("Inspect first: it says what this is (decrypted NSP, exefs folder, NSO, NRO, or something that needs your own console's keys) and how much of its code the lifter handles.");
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui.add_enabled(idle, egui::Button::new("Inspect")).clicked() {
                self.run(ctx, "inspect", vec!["inspect".into(), d.clone()]);
            }
            if ui.add_enabled(idle, egui::Button::new("Extract...")).on_hover_text("Write exefs\\ and romfs\\ to a folder").clicked()
                && let Some(out) = rfd::FileDialog::new().set_title("Extract to").pick_folder()
            {
                self.run(ctx, "extract", vec!["extract".into(), d.clone(), out.display().to_string()]);
            }
            if ui.button("Close").clicked() {
                self.dump = None;
            }
        });
        ui.add_space(14.0);
        ui.group(|ui| {
            ui.label(RichText::new("Build a native executable").strong());
            ui.label(RichText::new("AArch64 to Kirikae IR to Cranelift to games\\<name>\\<name>.exe. The first build of a game takes a while.").weak());
            ui.horizontal(|ui| {
                ui.label("Name");
                ui.add(egui::TextEdit::singleline(&mut self.build_name).hint_text("from the game's title").desired_width(220.0));
                ui.checkbox(&mut self.fresh, "Fresh").on_hover_text("Ignore a saved play profile");
            });
            if self.build_options(ui) {
                self.settings.save();
            }
            if ui.add_enabled(idle && buildable, egui::Button::new(RichText::new("Build").strong()).min_size(egui::vec2(120.0, 28.0))).clicked() {
                let mut args = vec!["build".to_string(), d.clone()];
                if !self.build_name.trim().is_empty() {
                    args.push("--name".into());
                    args.push(self.build_name.trim().into());
                }
                if self.fresh {
                    args.push("--fresh".into());
                }
                args.extend(self.build_flags(self.settings.seed, self.settings.fast_regs));
                self.run(ctx, "build", args);
            }
        });
    }

    /// Seeding, fast registers and the linker; true when one changed
    fn build_options(&mut self, ui: &mut egui::Ui) -> bool {
        let mut changed = false;
        ui.horizontal_wrapped(|ui| {
            changed |= ui
                .checkbox(&mut self.settings.seed, "Seed unreached code")
                .on_hover_text("Also compile exported functions and function prologues Kirikae's analysis did not reach, so less runs in the interpreter")
                .changed();
            changed |= ui
                .checkbox(&mut self.settings.fast_regs, "Fast registers (experimental)")
                .on_hover_text("Kirikae keeps guest registers in host registers: faster game code, less tested")
                .changed();
            ui.label("Linker");
            let label = match self.settings.linker.as_str() {
                "lld" => "LLD",
                "msvc" => "link.exe",
                _ => "Auto",
            };
            egui::ComboBox::from_id_salt("linker").selected_text(label).show_ui(ui, |ui| {
                for (v, l) in [("auto", "Auto (LLD when it works)"), ("lld", "LLD"), ("msvc", "link.exe")] {
                    changed |= ui.selectable_value(&mut self.settings.linker, v.to_string(), l).changed();
                }
            })
            .response
            .on_hover_text("LLD links a game several times faster than Microsoft's link.exe. Switching linker rebuilds the runtime once.");
        });
        changed
    }

    fn game_view(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, g: Game) {
        let idle = self.job.is_none();
        ui.heading(g.title.clone().unwrap_or_else(|| g.name.clone()));
        egui::Grid::new("facts").num_columns(2).spacing([16.0, 4.0]).show(ui, |ui| {
            let row = |ui: &mut egui::Ui, k: &str, v: String| {
                ui.label(RichText::new(k).weak());
                ui.label(v);
                ui.end_row();
            };
            row(ui, "name", g.name.clone());
            row(ui, "title id", g.title_id.clone().unwrap_or_else(|| "-".into()));
            if let Some(v) = &g.version {
                row(ui, "version", v.clone());
            }
            row(
                ui,
                "native functions",
                format!("{}  ({} of {} instructions reachable, {:.2}%)", g.functions, g.reachable, g.total, 100.0 * g.reachable as f64 / g.total.max(1) as f64),
            );
            if g.seeded_functions > 0 {
                row(ui, "from seeding", format!("+{} functions (exported symbols and prologues)", g.seeded_functions));
            }
            let mut last = format!("{}  (last {})", g.builds, ago(g.last_built_unix));
            if g.build_secs > 0.0 {
                last.push_str(&format!(", took {:.0}s with {}", g.build_secs, if g.linker.is_empty() { "link.exe" } else { &g.linker }));
            }
            if g.fast_regs {
                last.push_str(", fast registers");
            }
            row(ui, "builds", last);
            row(ui, "executable", g.executable.display().to_string());
            row(ui, "dump", format!("{}{}", g.source.display(), if g.source.exists() { "" } else { "  (missing: refine needs it)" }));
        });
        ui.add_space(12.0);
        let exe = g.executable.is_file();
        ui.horizontal(|ui| {
            let play = egui::Button::new(RichText::new("▶  Play").strong().size(16.0)).min_size(egui::vec2(120.0, 32.0));
            if ui.add_enabled(idle && exe, play).clicked() {
                let mut args = vec!["play".to_string(), g.name.clone()];
                if self.settings.stats {
                    args.push("--stats".into());
                }
                if self.settings.vsync {
                    args.push("--vsync".into());
                }
                if self.settings.handheld {
                    args.push("--handheld".into());
                }
                self.run(ctx, "play", args);
            }
            let mut changed = ui.checkbox(&mut self.settings.vsync, "VSync").changed();
            changed |= ui.checkbox(&mut self.settings.stats, "Stats").on_hover_text("Frame times and how much runs natively").changed();
            changed |= ui.checkbox(&mut self.settings.handheld, "Handheld").changed();
            if changed {
                self.settings.save();
            }
        });
        if !exe {
            ui.colored_label(Color32::from_rgb(230, 120, 90), "The executable is missing: rebuild it from the dump.");
        }
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui.add_enabled(idle, egui::Button::new("Refine")).on_hover_text("Rebuild with what the last play session had to interpret, so more runs natively").clicked() {
                let mut args = vec!["refine".to_string(), g.name.clone()];
                if self.settings.linker != "auto" {
                    args.extend(["--linker".to_string(), self.settings.linker.clone()]);
                }
                self.run(ctx, "refine", args);
            }
            if ui.add_enabled(idle, egui::Button::new("Coverage")).on_hover_text("Services, SVCs and shaders the game used that the runtime lacks").clicked() {
                self.run(ctx, "coverage", vec!["coverage".into(), g.name.clone()]);
            }
            if ui.add_enabled(idle && g.source.exists(), egui::Button::new("Rebuild fresh")).on_hover_text("Build again from the dump with the options below, ignoring the play profile").clicked() {
                let mut args = vec!["build".into(), g.source.display().to_string(), "--name".into(), g.name.clone(), "--out".into(), g.out_dir.display().to_string(), "--fresh".into()];
                args.extend(self.build_flags(self.settings.seed, self.settings.fast_regs));
                self.run(ctx, "build", args);
            }
            if ui.button("Show files").clicked() {
                let _ = Command::new("explorer").arg(&g.out_dir).spawn();
            }
            if ui.add_enabled(idle, egui::Button::new("Remove from list")).on_hover_text("Take this game off the list. Its files stay where they are.").clicked() {
                self.run(ctx, "remove", vec!["remove".into(), g.name.clone()]);
            }
        });
        ui.add_space(6.0);
        ui.label(RichText::new("Build options for new builds and Rebuild fresh (Refine keeps the ones this game was built with):").small().weak());
        if self.build_options(ui) {
            self.settings.save();
        }
        ui.add_space(10.0);
        ui.label(RichText::new("Keyboard: left stick WASD / arrows, right stick IJKL, A/B/X/Y = Z or Space / X / C / V, L/R/ZL/ZR = E/U/Q/O, + / - = Enter / Backspace, D-pad TFGH. The first XInput pad works too.").small().weak());
    }

    fn log_panel(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if let Some(job) = &self.job {
                ui.spinner();
                ui.label(RichText::new(format!("{}  ·  {:.0}s", job.label, job.started.elapsed().as_secs_f64())).strong());
                if let Some(p) = job.progress {
                    ui.add(egui::ProgressBar::new(p).desired_width(300.0).text(format!("{}  {:.0}%", job.phase, p * 100.0)));
                } else if !job.phase.is_empty() {
                    ui.label(RichText::new(&job.phase).weak());
                }
            } else if let Some((s, ok)) = &self.status {
                let c = if *ok { Color32::from_rgb(110, 200, 120) } else { Color32::from_rgb(235, 100, 90) };
                ui.label(RichText::new(if *ok { format!("✔ {s}") } else { format!("✖ {s}") }).color(c));
            } else {
                ui.label(RichText::new("Log").strong());
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.job.is_some() && ui.button("Cancel").clicked() {
                    self.cancel();
                }
                if ui.button("Clear").clicked() {
                    self.log.clear();
                }
                if ui.button("Copy").clicked() {
                    ui.ctx().copy_text(self.log_text());
                }
            });
        });
        ui.separator();
        // only the visible rows are laid out, so a long build log stays smooth
        let row_h = ui.text_style_height(&egui::TextStyle::Monospace);
        egui::ScrollArea::both().stick_to_bottom(true).auto_shrink([false, false]).show_rows(ui, row_h, self.log.len(), |ui, rows| {
            for l in &self.log[rows] {
                let c = l.tone.color(ui);
                let text = RichText::new(if l.text.is_empty() { " " } else { &l.text }).monospace().color(c);
                ui.add(egui::Label::new(if l.tone == Tone::Bad { text.strong() } else { text }).extend());
            }
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        self.watch(ctx);
        ctx.request_repaint_after(std::time::Duration::from_secs(3));
        if self.scan_pending && self.job.is_none() {
            self.scan_pending = false;
            self.scan(ctx);
        }
        if self.job.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(250)); // the elapsed time ticks
        }
        // drag and drop: a file or a folder
        let dropped: Vec<PathBuf> = ctx.input(|i| i.raw.dropped_files.iter().filter_map(|f| f.path.clone()).collect());
        if let Some(p) = dropped.into_iter().next() {
            self.set_dump(p);
        }
        let hovering = ctx.input(|i| !i.raw.hovered_files.is_empty());

        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(6.0);
            self.top(ui, ctx);
            ui.add_space(4.0);
        });
        egui::TopBottomPanel::bottom("log").resizable(true).default_height(260.0).min_height(120.0).show(ctx, |ui| {
            ui.add_space(4.0);
            self.log_panel(ui);
        });
        egui::SidePanel::left("library").resizable(true).default_width(320.0).show(ctx, |ui| self.side(ui, ctx));
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(6.0);
            if let Some(d) = self.dump.clone() {
                self.dump_view(ui, ctx, d);
            } else if let Some(g) = self.game().cloned() {
                self.game_view(ui, ctx, g);
            } else {
                ui.add_space(60.0);
                ui.vertical_centered(|ui| {
                    ui.heading("Drop a dump here");
                    ui.label("An NSP whose NCAs are not encrypted, a folder with exefs\\ (+ romfs\\), an NSO or an NRO.");
                    ui.label(RichText::new("Only games dumped from your own console. switchrecomp never decrypts anything, and the executables it makes must not be shared.").weak());
                });
            }
        });

        if hovering {
            let screen = ctx.screen_rect();
            let painter = ctx.layer_painter(egui::LayerId::new(egui::Order::Foreground, egui::Id::new("drop")));
            painter.rect_filled(screen, 0.0, Color32::from_black_alpha(170));
            painter.text(screen.center(), egui::Align2::CENTER_CENTER, "Drop to open this dump", egui::FontId::proportional(28.0), Color32::WHITE);
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.cancel();
    }
}

/// A plain 64x64 icon drawn here (no image files): a rounded dark tile with a white arrow between two chips
fn icon() -> egui::IconData {
    let n = 64usize;
    let mut rgba = vec![0u8; n * n * 4];
    for y in 0..n {
        for x in 0..n {
            let (fx, fy) = (x as f32 + 0.5, y as f32 + 0.5);
            let r = 12.0;
            let cx = fx.clamp(r, n as f32 - r);
            let cy = fy.clamp(r, n as f32 - r);
            let inside = (fx - cx).powi(2) + (fy - cy).powi(2) <= r * r;
            let i = (y * n + x) * 4;
            if !inside {
                continue;
            }
            let mut c = [28u8, 34, 52, 255];
            let chip = |x0: usize, y0: usize| x >= x0 && x < x0 + 14 && y >= y0 && y < y0 + 22;
            if chip(8, 21) {
                c = [230, 80, 70, 255];
            }
            if chip(42, 21) {
                c = [80, 170, 240, 255];
            }
            let shaft = (25..=37).contains(&x) && (30..=33).contains(&y);
            let head = x >= 33 && x <= 40 && (y as i32 - 32).unsigned_abs() as usize <= 40 - x;
            if shaft || head {
                c = [245, 245, 245, 255];
            }
            rgba[i..i + 4].copy_from_slice(&c);
        }
    }
    egui::IconData { rgba, width: n as u32, height: n as u32 }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("SwitchRecomp")
            .with_inner_size([1100.0, 720.0])
            .with_min_inner_size([760.0, 480.0])
            .with_drag_and_drop(true)
            .with_icon(Arc::new(icon())),
        ..Default::default()
    };
    eframe::run_native("SwitchRecomp", options, Box::new(|_cc| Ok(Box::new(App::new()))))
}
