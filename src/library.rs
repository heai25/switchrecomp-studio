//! The list of games switchrecomp has built, kept in `library.json` next to the tool.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Game {
    pub name: String,
    pub title: Option<String>,
    pub title_id: Option<String>,
    pub version: Option<String>,
    /// The dump it was built from (NSP, folder, NSO or NRO).
    pub source: PathBuf,
    pub out_dir: PathBuf,
    pub executable: PathBuf,
    pub functions: usize,
    pub reachable: u64,
    pub total: u64,
    pub builds: u32,
    pub last_built_unix: u64,
    /// how the last build was made (kept so `refine` builds the same way)
    #[serde(default)]
    pub fast_regs: bool,
    #[serde(default = "yes")]
    pub seeded: bool,
    /// seconds the last build took, and with which linker
    #[serde(default)]
    pub build_secs: f64,
    #[serde(default)]
    pub linker: String,
    /// extra native functions from switchrecomp's static seeding in the last build
    #[serde(default)]
    pub seeded_functions: usize,
}

fn yes() -> bool {
    true
}

#[derive(Serialize, Deserialize, Default)]
pub struct Library {
    pub games: Vec<Game>,
}

/// Where switchrecomp keeps library.json and games/: SWITCHRECOMP_HOME, else the folder of the exe
/// (or the project root when run through `cargo run`).
pub fn home() -> PathBuf {
    if let Some(h) = std::env::var_os("SWITCHRECOMP_HOME") {
        return PathBuf::from(h);
    }
    let exe_dir = std::env::current_exe().ok().and_then(|e| e.parent().map(Path::to_path_buf)).unwrap_or_else(|| PathBuf::from("."));
    // target/release/switchrecomp.exe -> project root
    if exe_dir.ends_with("target/release") || exe_dir.ends_with("target\\release") || exe_dir.ends_with("target/debug") {
        if let Some(root) = exe_dir.parent().and_then(Path::parent) {
            return root.to_path_buf();
        }
    }
    exe_dir
}

fn path() -> PathBuf {
    home().join("library.json")
}

impl Library {
    pub fn load() -> Library {
        match std::fs::read_to_string(path()) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_else(|e| {
                eprintln!("switchrecomp: library.json is unreadable ({e}); starting a new one");
                Library::default()
            }),
            Err(_) => Library::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let p = path();
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        let tmp = p.with_extension("json.tmp");
        std::fs::write(&tmp, text).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, &p).map_err(|e| format!("{}: {e}", p.display()))
    }

    pub fn find(&self, name: &str) -> Option<&Game> {
        let n = name.to_ascii_lowercase();
        self.games
            .iter()
            .find(|g| g.name == n)
            .or_else(|| self.games.iter().find(|g| g.title_id.as_deref().is_some_and(|t| t.eq_ignore_ascii_case(name))))
            .or_else(|| self.games.iter().find(|g| g.name.starts_with(&n)))
    }

    /// Takes a game out of the list (its files stay where they are); true when it was there
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.games.len();
        self.games.retain(|g| g.name != name);
        self.games.len() != before
    }

    pub fn upsert(&mut self, game: Game) {
        match self.games.iter_mut().find(|g| g.name == game.name) {
            Some(existing) => *existing = game,
            None => self.games.push(game),
        }
        self.games.sort_by(|a, b| a.name.cmp(&b.name));
    }
}
