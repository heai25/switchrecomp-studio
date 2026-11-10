//! Which linker builds a game: LLD (rust-lld, shipped with every Rust toolchain) or Microsoft's link.exe.
//!
//! A recompiled game is one executable made from a hundred-odd large objects of generated code, and the final link is a
//! big part of every rebuild. LLD links those several times faster than link.exe. It is checked once with a tiny probe
//! project (the result is cached per Rust version), and if a game link with LLD ever fails, switchrecomp links that game
//! again with link.exe, without generating the code again.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::toolchain::{msvc_link, LINKER_VAR};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice {
    Auto,
    Lld,
    Msvc,
}

impl Choice {
    pub fn parse(s: &str) -> Result<Choice, String> {
        match s.to_ascii_lowercase().as_str() {
            "auto" => Ok(Choice::Auto),
            "lld" | "rust-lld" => Ok(Choice::Lld),
            "msvc" | "link" | "link.exe" => Ok(Choice::Msvc),
            _ => Err(format!("unknown linker `{s}` (auto, lld or msvc)")),
        }
    }
}

fn rustc_output(args: &[&str]) -> Option<String> {
    let out = Command::new("rustc").args(args).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// rust-lld.exe in the active toolchain
pub fn rust_lld() -> Option<PathBuf> {
    let sysroot = PathBuf::from(rustc_output(&["--print", "sysroot"])?);
    let host = rustc_output(&["-vV"])?.lines().find_map(|l| l.strip_prefix("host: ").map(str::to_string))?;
    let exe = if cfg!(windows) { "rust-lld.exe" } else { "rust-lld" };
    let p = sysroot.join("lib").join("rustlib").join(host).join("bin").join(exe);
    p.is_file().then_some(p)
}

fn probe_dir() -> PathBuf {
    crate::build_target_dir().join("lld-probe")
}

fn probe_key(lld: &Path) -> String {
    format!("{}\n{}\n", rustc_output(&["--version"]).unwrap_or_default(), lld.display())
}

/// Builds and runs a hello-world with LLD; the answer is cached for this Rust version and LLD path
pub fn lld_works(lld: &Path) -> Result<(), String> {
    let dir = probe_dir();
    let stamp = dir.join("ok.txt");
    let key = probe_key(lld);
    match std::fs::read_to_string(&stamp) {
        Ok(s) if s == key => return Ok(()),
        Ok(s) if s == format!("failed\n{key}") => return Err("a game link with LLD failed earlier with this Rust version".into()),
        _ => {}
    }
    std::fs::create_dir_all(dir.join("src")).map_err(|e| format!("{}: {e}", dir.display()))?;
    std::fs::write(dir.join("Cargo.toml"), "[package]\nname = \"lld-probe\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[workspace]\n").map_err(|e| e.to_string())?;
    std::fs::write(dir.join("src").join("main.rs"), "fn main() { println!(\"lld-ok\"); }\n").map_err(|e| e.to_string())?;
    let target = dir.join("target");
    let out = Command::new("cargo")
        .args(["build", "--release", "--quiet", "--manifest-path"])
        .arg(dir.join("Cargo.toml"))
        .arg("--target-dir")
        .arg(&target)
        .env(LINKER_VAR, lld)
        .output()
        .map_err(|e| format!("cargo: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).lines().rev().take(4).collect::<Vec<_>>().join(" / "));
    }
    let exe = target.join("release").join(format!("lld-probe{}", std::env::consts::EXE_SUFFIX));
    let ran = Command::new(&exe).output().map_err(|e| format!("{}: {e}", exe.display()))?;
    if !String::from_utf8_lossy(&ran.stdout).contains("lld-ok") {
        return Err("the probe linked but did not run".into());
    }
    let _ = std::fs::write(&stamp, key);
    Ok(())
}

fn set_linker(p: &Path) {
    // SAFETY: switchrecomp sets this between its own phases, while no other thread reads the environment
    unsafe { std::env::set_var(LINKER_VAR, p) };
}

/// Points game builds at the chosen linker; returns what was picked, for the log
pub fn select(choice: Choice) -> (Choice, String) {
    if choice == Choice::Msvc || !cfg!(windows) {
        return (Choice::Msvc, use_msvc());
    }
    match rust_lld() {
        Some(lld) if choice == Choice::Lld => {
            set_linker(&lld);
            (Choice::Lld, format!("LLD, as asked ({})", lld.display()))
        }
        Some(lld) => match lld_works(&lld) {
            Ok(()) => {
                set_linker(&lld);
                (Choice::Lld, format!("LLD ({})", lld.display()))
            }
            Err(e) => {
                let why = format!("LLD did not work here ({e}); using link.exe");
                let _ = use_msvc();
                (Choice::Msvc, why)
            }
        },
        None => {
            let _ = use_msvc();
            (Choice::Msvc, "rust-lld not found in the Rust toolchain; using link.exe".into())
        }
    }
}

/// Points game builds at Microsoft's link.exe (what toolchain::prepare pinned)
pub fn use_msvc() -> String {
    match msvc_link() {
        Some(link) => {
            set_linker(&link);
            format!("link.exe ({})", link.display())
        }
        None => "link.exe".into(),
    }
}

/// Re-runs only the final cargo build of a game's project (code already generated) with link.exe
pub fn relink_msvc(project: &Path, target_dir: &Path, package: &str, out_dir: &Path) -> Result<PathBuf, String> {
    eprintln!("switchrecomp: the LLD link failed; linking again with link.exe ({})", use_msvc());
    let mut cmd = Command::new("cargo");
    if std::env::var_os("RUST_MIN_STACK").is_none() {
        cmd.env("RUST_MIN_STACK", (256u64 << 20).to_string());
    }
    let status = cmd
        .args(["build", "--release", "--manifest-path"])
        .arg(project.join("Cargo.toml"))
        .arg("--target-dir")
        .arg(target_dir)
        .status()
        .map_err(|e| format!("could not run cargo: {e}"))?;
    if !status.success() {
        return Err(format!("cargo build failed with link.exe too ({status})"));
    }
    let name = format!("{package}{}", std::env::consts::EXE_SUFFIX);
    let built = target_dir.join("release").join(&name);
    let exe = out_dir.join(&name);
    std::fs::copy(&built, &exe).map_err(|e| format!("copying {}: {e}", built.display()))?;
    // later builds go straight to link.exe until the Rust toolchain changes (`--linker lld` still forces LLD)
    if let Some(lld) = rust_lld() {
        let _ = std::fs::write(probe_dir().join("ok.txt"), format!("failed\n{}", probe_key(&lld)));
    }
    Ok(exe)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn choices() {
        assert_eq!(Choice::parse("LLD").unwrap(), Choice::Lld);
        assert_eq!(Choice::parse("msvc").unwrap(), Choice::Msvc);
        assert_eq!(Choice::parse("auto").unwrap(), Choice::Auto);
        assert!(Choice::parse("gold").is_err());
    }
}
