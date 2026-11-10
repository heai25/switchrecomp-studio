//! Works out what kind of Switch dump the user handed us, and whether Kirikae can take it as-is.

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use kirikae_loader::package::{from_source, read_source, Source};
use kirikae_loader::{pfs0, Error, Executable};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A folder holding `exefs/` (+ optional `romfs/`), or an ExeFS folder itself.
    ExeFsFolder,
    /// An NSP (PFS0) whose program NCA is plaintext: Kirikae reads it directly.
    PlainNsp,
    /// An NSP whose NCAs are still encrypted.
    EncryptedNsp,
    /// An NSZ (NSP with compressed .ncz content).
    CompressedNsp,
    /// A cartridge image (XCI / HFS0).
    Xci,
    Nso,
    Nro,
    Unknown,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::ExeFsFolder => "extracted ExeFS/RomFS folder",
            Kind::PlainNsp => "NSP (not encrypted)",
            Kind::EncryptedNsp => "NSP (encrypted)",
            Kind::CompressedNsp => "NSZ (compressed NSP)",
            Kind::Xci => "XCI cartridge image",
            Kind::Nso => "NSO executable",
            Kind::Nro => "NRO homebrew executable",
            Kind::Unknown => "unknown",
        }
    }

    pub fn recompilable(self) -> bool {
        matches!(self, Kind::ExeFsFolder | Kind::PlainNsp | Kind::Nso | Kind::Nro | Kind::EncryptedNsp | Kind::Xci | Kind::CompressedNsp)
    }

    /// Encrypted or compressed inputs that switchrecomp-studio decrypts itself (with the user's own keys) first.
    pub fn needs_decryption(self) -> bool {
        matches!(self, Kind::EncryptedNsp | Kind::Xci | Kind::CompressedNsp)
    }

    /// What the user has to do before this input can be recompiled.
    pub fn fix(self) -> Option<&'static str> {
        match self {
            Kind::EncryptedNsp | Kind::Xci => Some(
                "This dump is encrypted. switchrecomp decrypts it with your own console's keys: put\n\
                 prod.keys and title.keys (from Lockpick_RCM) next to switchrecomp.exe, in a keys\\ folder\n\
                 there, or in %USERPROFILE%\\.switch, or run `switchrecomp decrypt <dump> --keys <folder>`.",
            ),
            Kind::CompressedNsp => Some(
                "This is a compressed NSZ. switchrecomp uncompresses and decrypts it with your own console's\n\
                 keys: put prod.keys and title.keys next to switchrecomp.exe (or in a keys\\ folder there).",
            ),
            Kind::Unknown => Some("Not a recognised Switch dump (expected an NSP, an exefs/romfs folder, an NSO or an NRO)."),
            _ => None,
        }
    }
}

fn read_magic(path: &Path) -> std::io::Result<[u8; 0x110]> {
    let mut buf = [0u8; 0x110];
    let mut f = File::open(path)?;
    let mut filled = 0;
    while filled < buf.len() {
        let n = f.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(buf)
}

pub fn classify(path: &Path) -> Kind {
    if path.is_dir() {
        let has_main = path.join("main").is_file() || path.join("exefs").join("main").is_file();
        return if has_main { Kind::ExeFsFolder } else { Kind::Unknown };
    }
    let Ok(magic) = read_magic(path) else { return Kind::Unknown };
    if &magic[..4] == b"PFS0" {
        if let Ok(f) = File::open(path) {
            let mut r = BufReader::new(f);
            if r.seek(SeekFrom::Start(0)).is_ok()
                && let Ok(entries) = pfs0::parse(&mut r, 0)
                && entries.iter().any(|e| e.name.ends_with(".ncz"))
            {
                return Kind::CompressedNsp;
            }
        }
        return match read_source(path) {
            Ok(_) => Kind::PlainNsp,
            Err(Error::Encrypted) => Kind::EncryptedNsp,
            // Any other problem: let `load` surface Kirikae's own error message.
            Err(_) => Kind::PlainNsp,
        };
    }
    if &magic[0x100..0x104] == b"HEAD" {
        return Kind::Xci;
    }
    if &magic[..4] == b"NSO0" {
        return Kind::Nso;
    }
    if &magic[0x10..0x14] == b"NRO0" {
        return Kind::Nro;
    }
    Kind::Unknown
}

pub struct Loaded {
    pub source: Source,
    pub exe: Executable,
}

pub fn load(path: &Path) -> Result<Loaded, String> {
    let kind = classify(path);
    if !kind.recompilable() {
        let mut msg = format!("{}: {}", path.display(), kind.label());
        if let Some(fix) = kind.fix() {
            msg.push_str("\n\n");
            msg.push_str(fix);
        }
        return Err(msg);
    }
    if kind.needs_decryption() {
        let dir = crate::crypto::decrypted_dir_for(path);
        if !dir.join("exefs").join("main").is_file() {
            let keys = crate::crypto::keys::Keys::load(None).map_err(|e| {
                format!("{}: {}\n\n{e}\n\n{}", path.display(), kind.label(), kind.fix().unwrap_or_default())
            })?;
            eprintln!("switchrecomp: decrypting {} into {}", path.display(), dir.display());
            let report = crate::crypto::decrypt_package(path, &dir, &keys, &crate::crypto::Options { romfs: true })
                .map_err(|e| format!("{}: {e}", path.display()))?;
            eprintln!(
                "switchrecomp: decrypted title {:016X} v{} (master key {:02x}, {}); {} ExeFS blocks verified",
                report.title_id, report.version, report.master_key, report.key_source, report.verified_blocks
            );
            for w in &report.warnings {
                eprintln!("switchrecomp: warning: {w}");
            }
        }
        return load(&dir);
    }
    let source = read_source(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let exe = from_source(&source).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Loaded { source, exe })
}

/// The game's display name (American English first, then the first non-empty language).
pub fn title_name(exe: &Executable) -> Option<String> {
    let nacp = exe.nacp.as_ref()?;
    (0..kirikae_loader::nacp::LANGUAGE_COUNT).map(|i| nacp.name(i)).find(|n| !n.trim().is_empty())
}

/// A file-system- and Cargo-safe short name.
pub fn slug(s: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            dash = false;
        } else if !dash && !out.is_empty() {
            out.push('-');
            dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() { "game".into() } else { out.chars().take(40).collect::<String>().trim_end_matches('-').to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs() {
        assert_eq!(slug("The Legend of Zelda: Link's Awakening"), "the-legend-of-zelda-link-s-awakening");
        assert_eq!(slug("  !!"), "game");
        assert_eq!(slug("Pokémon™ Let's Go"), "pok-mon-let-s-go");
    }
}
