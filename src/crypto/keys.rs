//! Loads the user's own console keys (prod.keys / title.keys, as dumped by Lockpick_RCM).
//! Key values are never printed: only names and whether they were found.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Default, Clone)]
pub struct Keys {
    named: HashMap<String, Vec<u8>>,
    titles: HashMap<[u8; 16], [u8; 16]>,
    pub prod_path: Option<PathBuf>,
    pub title_path: Option<PathBuf>,
    /// The console's eTicket RSA key (for personalized tickets), from PRODINFO + eticket_rsa_kek.
    eticket: Option<super::rsa::EticketKey>,
    /// What happened when looking for it (shown by `switchrecomp keys`).
    pub eticket_status: String,
}

/// File names a PRODINFO (decrypted calibration partition) dump goes by, looked for next to prod.keys.
const PRODINFO_NAMES: [&str; 6] = ["PRODINFO", "PRODINFO.bin", "prodinfo.bin", "PRODINFO.dec", "prodinfo.dec", "PRODINFO.img"];

fn parse_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some((0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect())
}

fn parse_lines(text: &str) -> impl Iterator<Item = (String, Vec<u8>)> + '_ {
    text.lines().filter_map(|line| {
        let line = line.split(['#', ';']).next()?.trim();
        let (name, value) = line.split_once(['=', ','])?;
        Some((name.trim().to_ascii_lowercase(), parse_hex(value)?))
    })
}

/// Folders searched for prod.keys / title.keys, most specific first.
pub fn search_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(v) = std::env::var("SWITCHRECOMP_KEYS") {
        let p = PathBuf::from(v);
        dirs.push(if p.is_file() { p.parent().map(Path::to_path_buf).unwrap_or(p) } else { p });
    }
    if let Some(exe_dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)) {
        dirs.push(exe_dir.join("keys"));
        dirs.push(exe_dir);
    }
    if let Ok(cwd) = std::env::current_dir() {
        dirs.push(cwd.join("keys"));
        dirs.push(cwd);
    }
    if let Some(home) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")) {
        dirs.push(PathBuf::from(home).join(".switch"));
    }
    if let Some(appdata) = std::env::var_os("APPDATA") {
        let a = PathBuf::from(appdata);
        for emu in ["eden", "citron", "suyu", "sudachi", "yuzu"] {
            dirs.push(a.join(emu).join("keys"));
        }
        dirs.push(a.join("Ryujinx").join("system"));
    }
    dirs
}

impl Keys {
    /// Load from an explicit folder or prod.keys file, or search the usual places.
    pub fn load(explicit: Option<&Path>) -> Result<Keys, String> {
        let dirs = match explicit {
            Some(p) if p.is_file() => vec![p.parent().map(Path::to_path_buf).unwrap_or_default()],
            Some(p) => vec![p.to_path_buf()],
            None => search_dirs(),
        };
        let mut keys = Keys::default();
        let prod = match explicit.filter(|p| p.is_file()) {
            Some(p) => Some(p.to_path_buf()),
            None => dirs.iter().map(|d| d.join("prod.keys")).find(|p| p.is_file()),
        };
        let Some(prod) = prod else {
            let looked: Vec<String> = dirs.iter().map(|d| format!("  {}", d.display())).collect();
            return Err(format!("no prod.keys found (dumped from your own console). Looked in:\n{}", looked.join("\n")));
        };
        let text = std::fs::read_to_string(&prod).map_err(|e| format!("{}: {e}", prod.display()))?;
        keys.named.extend(parse_lines(&text));
        keys.prod_path = Some(prod.clone());
        let title = std::iter::once(prod.with_file_name("title.keys")).chain(dirs.iter().map(|d| d.join("title.keys"))).find(|p| p.is_file());
        if let Some(title) = title {
            if let Ok(text) = std::fs::read_to_string(&title) {
                for (name, value) in parse_lines(&text) {
                    if let (Some(rid), Ok(key)) = (parse_hex(&name), <[u8; 16]>::try_from(value.as_slice()))
                        && let Ok(rid) = <[u8; 16]>::try_from(rid.as_slice())
                    {
                        keys.titles.insert(rid, key);
                    }
                }
                keys.title_path = Some(title);
            }
        }
        if keys.key32("header_key").is_none() {
            return Err(format!("{} has no header_key", prod.display()));
        }
        keys.load_eticket(&prod, &dirs);
        Ok(keys)
    }

    fn load_eticket(&mut self, prod: &Path, dirs: &[PathBuf]) {
        let keks: Vec<[u8; 16]> = ["eticket_rsa_kek", "eticket_rsa_kek_personalized"].iter().filter_map(|n| self.key16(n)).collect();
        let found = std::iter::once(prod.parent().map(Path::to_path_buf).unwrap_or_default())
            .chain(dirs.iter().cloned())
            .flat_map(|d| PRODINFO_NAMES.iter().map(move |n| d.join(n)))
            .find(|p| p.is_file());
        self.eticket_status = match (found, keks.is_empty()) {
            (None, _) => "no PRODINFO dump next to prod.keys: personalized tickets rely on title.keys".into(),
            (Some(p), true) => format!("{} found, but prod.keys has no eticket_rsa_kek", p.display()),
            (Some(p), false) => match std::fs::read(&p) {
                Err(e) => format!("{}: {e}", p.display()),
                Ok(data) => {
                    let mut last = String::new();
                    for kek in &keks {
                        match super::rsa::EticketKey::from_prodinfo(&data, kek) {
                            Ok(k) => {
                                self.eticket = Some(k);
                                last.clear();
                                break;
                            }
                            Err(e) => last = e,
                        }
                    }
                    if self.eticket.is_some() { format!("eTicket key loaded from {}", p.display()) } else { format!("{}: {last}", p.display()) }
                }
            },
        };
    }

    pub fn eticket(&self) -> Option<&super::rsa::EticketKey> {
        self.eticket.as_ref()
    }

    pub fn key16(&self, name: &str) -> Option<[u8; 16]> {
        self.named.get(name).and_then(|v| v.as_slice().try_into().ok())
    }

    pub fn key32(&self, name: &str) -> Option<[u8; 32]> {
        self.named.get(name).and_then(|v| v.as_slice().try_into().ok())
    }

    pub fn title_key(&self, rights_id: &[u8; 16]) -> Option<[u8; 16]> {
        self.titles.get(rights_id).copied()
    }

    pub fn title_key_count(&self) -> usize {
        self.titles.len()
    }

    /// Highest master key generation the key set can serve (key_area_key_application_XX present).
    pub fn newest_generation(&self) -> Option<u8> {
        (0..=0x3fu8).rev().find(|g| self.key16(&format!("key_area_key_application_{g:02x}")).is_some())
    }

    #[cfg(test)]
    pub fn from_parts(named: &[(&str, &[u8])], titles: &[([u8; 16], [u8; 16])]) -> Keys {
        Keys {
            named: named.iter().map(|(n, v)| (n.to_string(), v.to_vec())).collect(),
            titles: titles.iter().copied().collect(),
            prod_path: None,
            title_path: None,
            eticket: None,
            eticket_status: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_lockpick_format() {
        let text = "header_key = 00112233445566778899AABBCCDDEEFF00112233445566778899aabbccddeeff\n; comment\nkey_area_key_application_00=000102030405060708090a0b0c0d0e0f\nbad = xyz\n";
        let named: HashMap<_, _> = parse_lines(text).collect();
        assert_eq!(named.len(), 2);
        assert_eq!(named["header_key"].len(), 32);
        assert_eq!(named["key_area_key_application_00"][15], 0x0f);
    }
}
