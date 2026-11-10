//! Where Sudachi (and the yuzu family it comes from) writes its dumps, so its ExeFS / RomFS dumps show up in switchrecomp.
//!
//! In Sudachi, turn on "Dump ExeFS" in the settings and start the game once (the ExeFS is written as it boots), then
//! right-click the game -> Dump RomFS: they land in <dump>\<title id>\exefs and \romfs, the folder layout switchrecomp
//! builds from. Sudachi uses the keys it is given; use keys dumped from your own console. The dump folder is Sudachi's `dump_directory` setting (qt-config.ini), by
//! default <user>\dump, where <user> is a `user` folder beside sudachi.exe (portable) or %APPDATA%\sudachi.

use std::path::{Path, PathBuf};

/// `key=value` from an ini file; the last one wins, as Qt reads them
fn ini_value(text: &str, key: &str) -> Option<String> {
    text.lines().filter_map(|l| l.trim().strip_prefix(key)?.strip_prefix('=').map(|v| v.trim().to_string())).filter(|v| !v.is_empty()).last()
}

/// The dump folder of a Sudachi user folder (`...\sudachi` or a portable `user` folder)
pub fn dump_dir_of(user: &Path) -> Option<PathBuf> {
    if let Ok(ini) = std::fs::read_to_string(user.join("config").join("qt-config.ini"))
        && let Some(v) = ini_value(&ini, "dump_directory")
    {
        let p = PathBuf::from(v.replace('/', "\\"));
        if p.is_dir() {
            return Some(p);
        }
    }
    let d = user.join("dump");
    d.is_dir().then_some(d)
}

/// Sudachi's dump folder: a portable install beside `sudachi_exe_dir` when given, else %APPDATA%\sudachi
pub fn dump_dir(sudachi_exe_dir: Option<&Path>) -> Option<PathBuf> {
    if let Some(dir) = sudachi_exe_dir {
        let portable = dir.join("user");
        if portable.is_dir()
            && let Some(d) = dump_dir_of(&portable)
        {
            return Some(d);
        }
    }
    let appdata = PathBuf::from(std::env::var_os("APPDATA")?);
    dump_dir_of(&appdata.join("sudachi"))
}
