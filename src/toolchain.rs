//! Makes the Rust toolchain usable no matter how the user's PATH is set up, before anything runs cargo.
//!
//! Two things break recompiling on real machines:
//! * cargo is installed (rustup puts it in %USERPROFILE%\.cargo\bin) but that folder is not on PATH;
//! * another `link.exe` comes before Microsoft's on PATH: devkitPro, MSYS2, Git for Windows and Cygwin all ship
//!   the Unix `link` command as `link.exe`, and rustc then calls it as the MSVC linker ("extra operand ...").
//!
//! Kirikae runs cargo for every game it recompiles, as a child of this process, so fixing the environment here
//! fixes those builds too: CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER names Microsoft's linker explicitly.

use std::path::{Path, PathBuf};
use std::process::Command;

pub const LINKER_VAR: &str = "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER";

/// Microsoft's x64 link.exe from the newest Visual Studio (or Build Tools) with the C++ tools, if any.
pub fn msvc_link() -> Option<PathBuf> {
    let vswhere = Path::new(r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe");
    let out = Command::new(vswhere)
        .args(["-latest", "-products", "*", "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"])
        .output()
        .ok()?;
    let vs = PathBuf::from(String::from_utf8_lossy(&out.stdout).lines().next()?.trim());
    let version = std::fs::read_to_string(vs.join(r"VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt")).ok()?;
    let link = vs.join(r"VC\Tools\MSVC").join(version.trim()).join(r"bin\Hostx64\x64\link.exe");
    link.is_file().then_some(link)
}

/// The first link.exe on PATH, when it is not Microsoft's (the one that would break the build).
pub fn shadowing_link() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let first = std::env::split_paths(&path).map(|d| d.join("link.exe")).find(|p| p.is_file())?;
    let s = first.to_string_lossy().to_ascii_lowercase();
    (!s.contains("microsoft visual studio")).then_some(first)
}

fn rustup_bin() -> Option<PathBuf> {
    let dir = std::env::var_os("CARGO_HOME").map(PathBuf::from).or_else(|| std::env::var_os("USERPROFILE").map(|h| PathBuf::from(h).join(".cargo")))?;
    let bin = dir.join("bin");
    bin.join("cargo.exe").is_file().then_some(bin)
}

fn cargo_on_path() -> bool {
    std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join("cargo.exe").is_file() || d.join("cargo").is_file()))
}

/// Call once at start-up, before any thread exists.
pub fn prepare() {
    if !cfg!(windows) {
        return;
    }
    if !cargo_on_path()
        && let Some(bin) = rustup_bin()
    {
        let mut dirs = vec![bin];
        if let Some(p) = std::env::var_os("PATH") {
            dirs.extend(std::env::split_paths(&p));
        }
        if let Ok(joined) = std::env::join_paths(dirs) {
            // SAFETY: called first thing in main, while the process is single-threaded
            unsafe { std::env::set_var("PATH", joined) };
        }
    }
    // unset, blank or pointing at nothing (a stale setting): pin it; a working value the user set is kept
    let set_ok = std::env::var_os(LINKER_VAR).is_some_and(|v| Path::new(v.to_string_lossy().trim()).is_file());
    if !set_ok
        && let Some(link) = msvc_link()
    {
        // SAFETY: as above
        unsafe { std::env::set_var(LINKER_VAR, link) };
    }
}
