//! Checks the machine has what recompiling needs: Rust, the MSVC linker, Vulkan, short build paths.

use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Check {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
    pub fix: &'static str,
}

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn rustc_minor(version: &str) -> Option<u32> {
    // "rustc 1.97.0 (...)"
    version.split_whitespace().nth(1)?.split('.').nth(1)?.parse().ok()
}

pub fn checks() -> Vec<Check> {
    let mut out = Vec::new();

    let cargo = run("cargo", &["--version"]);
    out.push(Check {
        name: "cargo",
        ok: cargo.is_some(),
        detail: cargo.unwrap_or_else(|| "not found on PATH".into()),
        fix: "Install Rust from https://rustup.rs and reopen the terminal.",
    });

    let rustc = run("rustc", &["--version"]);
    let minor = rustc.as_deref().and_then(rustc_minor);
    out.push(Check {
        name: "rustc >= 1.88",
        ok: minor.is_some_and(|m| m >= 88),
        detail: rustc.unwrap_or_else(|| "not found".into()),
        fix: "Run `rustup update stable`.",
    });

    if cfg!(windows) {
        let vswhere = PathBuf::from(r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe");
        let msvc = vswhere.is_file().then(|| {
            run(
                vswhere.to_str().unwrap(),
                &["-latest", "-products", "*", "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"],
            )
        });
        let msvc = msvc.flatten().filter(|s| !s.is_empty());
        out.push(Check {
            name: "MSVC linker (C++ build tools)",
            ok: msvc.is_some(),
            detail: msvc.unwrap_or_else(|| "Visual Studio C++ build tools not found".into()),
            fix: "Install Visual Studio Build Tools with the \"Desktop development with C++\" workload.",
        });

        // Another link.exe ahead of Microsoft's on PATH (devkitPro, MSYS2, Git, Cygwin ship the Unix `link`) breaks every
        // build unless the linker is pinned; switchrecomp pins it at start-up (toolchain::prepare), so this only reports
        let pinned = std::env::var_os(crate::toolchain::LINKER_VAR).map(PathBuf::from);
        let shadow = crate::toolchain::shadowing_link();
        out.push(Check {
            name: "linker pinned to MSVC",
            ok: pinned.as_ref().is_some_and(|p| p.is_file()),
            detail: match (&pinned, &shadow) {
                (Some(p), Some(s)) => format!("{} (PATH's first link.exe is {}, bypassed)", p.display(), s.display()),
                (Some(p), None) => p.display().to_string(),
                (None, Some(s)) => format!("not pinned, and PATH's first link.exe is {}", s.display()),
                (None, None) => "not pinned".into(),
            },
            fix: "Install the Visual Studio C++ build tools; switchrecomp then pins their link.exe automatically.",
        });

        // optional: LLD links games several times faster; without it link.exe is used
        let lld = crate::linker::rust_lld();
        let lld_state = lld.as_ref().map(|p| crate::linker::lld_works(p));
        out.push(Check {
            name: "fast linker (LLD, optional)",
            ok: true,
            detail: match (&lld, &lld_state) {
                (Some(p), Some(Ok(()))) => format!("{} works: game builds link with it", p.display()),
                (Some(_), Some(Err(e))) => format!("not used ({e}); game builds link with link.exe"),
                _ => "rust-lld not in the toolchain; game builds link with link.exe".into(),
            },
            fix: "",
        });

        let vulkan = Path::new(r"C:\Windows\System32\vulkan-1.dll").is_file();
        out.push(Check {
            name: "Vulkan loader",
            ok: vulkan,
            detail: if vulkan { "vulkan-1.dll present".into() } else { "vulkan-1.dll missing".into() },
            fix: "Update your GPU driver (Vulkan 1.3 is required to play recompiled games).",
        });

        let long = run("reg", &["query", r"HKLM\SYSTEM\CurrentControlSet\Control\FileSystem", "/v", "LongPathsEnabled"])
            .is_some_and(|s| s.contains("0x1"));
        let target = crate::build_target_dir();
        let short = target.as_os_str().len() < 60;
        out.push(Check {
            name: "short build path",
            ok: long || short,
            detail: format!(
                "builds go to {} ({} chars){}",
                target.display(),
                target.as_os_str().len(),
                if long { "; long paths enabled" } else { "" }
            ),
            fix: "Set CARGO_TARGET_DIR to a short folder such as D:\\srt (the MSVC linker fails past 260 characters).",
        });
    }
    out
}

pub fn report() -> bool {
    let mut all = true;
    for c in checks() {
        println!("  [{}] {:<32} {}", if c.ok { " ok " } else { "FAIL" }, c.name, c.detail);
        if !c.ok {
            println!("         -> {}", c.fix);
            all = false;
        }
    }
    all
}
