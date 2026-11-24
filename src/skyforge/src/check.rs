//! Static validation: SKSE plugin runtime compatibility, plugin masters and slot
//! limits, and the file-conflict map. These are *static* checks; they never
//! replace evidence from an actual launch (skse64.log) or gameplay.

use crate::config::Config;
use crate::install::State;
use crate::manifest::Manifest;
use crate::mo2;
use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// RUNTIME_VERSION / MAKE_EXE_VERSION encoding used by SKSE.
pub fn exe_version(major: u32, minor: u32, build: u32, sub: u32) -> u32 {
    ((major & 0xFF) << 24) | ((minor & 0xFF) << 16) | ((build & 0xFFF) << 4) | (sub & 0xF)
}

pub fn parse_runtime(s: &str) -> Result<u32> {
    let p: Vec<u32> = s.split('.').map(|x| x.parse().unwrap_or(0)).collect();
    if p.len() < 3 {
        bail!("runtime must look like 1.6.1170");
    }
    Ok(exe_version(p[0], p[1], p[2], *p.get(3).unwrap_or(&0)))
}

fn fmt_ver(v: u32) -> String {
    format!("{}.{}.{}.{}", v >> 24, (v >> 16) & 0xFF, (v >> 4) & 0xFFF, v & 0xF)
}

#[derive(Debug, Serialize)]
pub struct DllReport {
    pub mod_name: String,
    pub file: String,
    pub verdict: String,
    pub detail: String,
}

struct Pe<'a> {
    b: &'a [u8],
    sections: Vec<(u32, u32, u32, u32)>, // va, vsize, raw_ptr, raw_size
    export_rva: u32,
}

fn rd16(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o + 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}
fn rd32(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

impl<'a> Pe<'a> {
    fn parse(b: &'a [u8]) -> Option<Self> {
        if b.get(0..2)? != b"MZ" {
            return None;
        }
        let pe = rd32(b, 0x3C)? as usize;
        if b.get(pe..pe + 4)? != b"PE\0\0" {
            return None;
        }
        let coff = pe + 4;
        let nsec = rd16(b, coff + 2)? as usize;
        let opt_size = rd16(b, coff + 16)? as usize;
        let opt = coff + 20;
        let magic = rd16(b, opt)?;
        let dd = match magic {
            0x20B => opt + 112,
            0x10B => opt + 96,
            _ => return None,
        };
        let export_rva = rd32(b, dd)?;
        let st = opt + opt_size;
        let mut sections = Vec::new();
        for i in 0..nsec {
            let s = st + i * 40;
            sections.push((rd32(b, s + 12)?, rd32(b, s + 8)?, rd32(b, s + 20)?, rd32(b, s + 16)?));
        }
        Some(Pe { b, sections, export_rva })
    }
    fn off(&self, rva: u32) -> Option<usize> {
        for &(va, vs, rp, rs) in &self.sections {
            if rva >= va && rva < va + vs.max(rs) {
                return Some((rva - va + rp) as usize);
            }
        }
        None
    }
    fn cstr(&self, rva: u32) -> Option<String> {
        let o = self.off(rva)?;
        let end = self.b[o..].iter().position(|c| *c == 0)? + o;
        Some(String::from_utf8_lossy(&self.b[o..end]).into_owned())
    }
    fn exports(&self) -> Vec<(String, u32)> {
        let mut v = Vec::new();
        if self.export_rva == 0 {
            return v;
        }
        let Some(e) = self.off(self.export_rva) else { return v };
        let (Some(nnames), Some(funcs), Some(names), Some(ords)) =
            (rd32(self.b, e + 24), rd32(self.b, e + 28), rd32(self.b, e + 32), rd32(self.b, e + 36))
        else {
            return v;
        };
        let (Some(fo), Some(no), Some(oo)) = (self.off(funcs), self.off(names), self.off(ords)) else { return v };
        for i in 0..nnames as usize {
            let (Some(nrva), Some(ord)) = (rd32(self.b, no + 4 * i), rd16(self.b, oo + 2 * i)) else { continue };
            let (Some(name), Some(frva)) = (self.cstr(nrva), rd32(self.b, fo + 4 * ord as usize)) else { continue };
            v.push((name, frva));
        }
        v
    }
}

fn addr_independent(indep: u32) -> bool {
    indep & 0b011 != 0 // AddressLibraryPostAE | Signatures
}
fn struct_independent(indep: u32, indep_ex: u32) -> bool {
    indep & 0b100 != 0 || indep_ex & 1 != 0 // StructsPost629 | NoStructUse
}

/// Mirror of SKSE 2.2.x PluginManager::checkPluginCompatibility.
pub fn check_dll(bytes: &[u8], runtime: u32, skse_packed: u32) -> (String, String) {
    let Some(pe) = Pe::parse(bytes) else { return ("NOT-PE".into(), "not a PE image".into()) };
    let ex = pe.exports();
    let Some(&(_, rva)) = ex.iter().find(|(n, _)| n == "SKSEPlugin_Version") else {
        if ex.iter().any(|(n, _)| n == "SKSEPlugin_Query") {
            return ("INCOMPATIBLE".into(), "SE-only plugin (SKSEPlugin_Query without SKSEPlugin_Version)".into());
        }
        return ("NOT-SKSE".into(), "no SKSE plugin exports (helper library?)".into());
    };
    let Some(o) = pe.off(rva) else { return ("INCOMPATIBLE".into(), "SKSEPlugin_Version not mapped".into()) };
    let Some(d) = bytes.get(o..o + 848) else { return ("INCOMPATIBLE".into(), "truncated version data".into()) };
    let data_version = rd32(d, 0).unwrap();
    let name_end = d[8..264].iter().position(|c| *c == 0).unwrap_or(256);
    let name = String::from_utf8_lossy(&d[8..8 + name_end]).into_owned();
    let indep_ex = rd32(d, 772).unwrap();
    let indep = rd32(d, 776).unwrap();
    let compat: Vec<u32> = (0..16).map(|i| rd32(d, 780 + 4 * i).unwrap()).take_while(|v| *v != 0).collect();
    let se_req = rd32(d, 844).unwrap();
    if data_version == 0 {
        return ("INCOMPATIBLE".into(), "bad version data".into());
    }
    if name.is_empty() {
        return ("INCOMPATIBLE".into(), "no plugin name".into());
    }
    let addr = addr_independent(indep);
    let structs = struct_independent(indep, indep_ex);
    let compat_s = if addr_independent(indep) && struct_independent(indep, indep_ex) {
        "ignored (version-independent)".to_string()
    } else {
        format!("[{}]", compat.iter().map(|v| fmt_ver(*v)).collect::<Vec<_>>().join(","))
    };
    let detail = format!(
        "'{name}' indep={indep:#x} indepEx={indep_ex:#x} compat={compat_s} skseReq={}",
        if se_req == 0 { "-".into() } else { fmt_ver(se_req) }
    );
    if !(addr && structs) && !compat.contains(&runtime) {
        return ("INCOMPATIBLE".into(), format!("not version-independent and does not list {}; {detail}", fmt_ver(runtime)));
    }
    if se_req > skse_packed {
        return ("INCOMPATIBLE".into(), format!("requires newer SKSE; {detail}"));
    }
    let how = if addr && structs { "version-independent (Address Library + struct independence)" } else { "lists runtime explicitly" };
    ("COMPATIBLE".into(), format!("{how}; {detail}"))
}

#[derive(Debug, Serialize, Default)]
pub struct Report {
    pub runtime: String,
    pub dlls: Vec<DllReport>,
    pub address_library_present: bool,
    pub plugins_full: usize,
    pub plugins_light: usize,
    pub missing_masters: Vec<String>,
    pub master_order_errors: Vec<String>,
    pub conflicts: BTreeMap<String, usize>,
    pub conflict_files: usize,
}

#[derive(Debug)]
struct FileProvider {
    owner: String,
    relative: String,
    path: PathBuf,
}

/// The game consumes a Windows path namespace, even when the backing files live
/// on Linux. Resolve original paths through explicit ASCII-insensitive keys;
/// never guess which of two aliases in the same provider should win.
fn windows_key(name: &str) -> String {
    name.replace('\\', "/").to_ascii_lowercase()
}

fn optional_text(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Preserve planning before a profile exists, while observing actual activation
/// when it does. The caller decides whether a missing profile is valid.
fn profile_layers(cfg: &Config, required: bool) -> Result<Vec<(String, PathBuf)>> {
    let mut layers = Vec::new();
    let data = cfg.stock_game.join("Data");
    if required || data.exists() { layers.push(("Stock Game".into(), data)); }
    let modlist_path = cfg.profile_dir().join("modlist.txt");
    let modlist = optional_text(&modlist_path)?;
    if required && modlist.is_none() { bail!("missing profile modlist {}", modlist_path.display()); }
    let mut enabled = Vec::new();
    let mut names = HashMap::new();
    for line in modlist.as_deref().unwrap_or("").lines().map(str::trim) {
        if let Some(name) = line.strip_prefix('+') {
            if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\']) { bail!("invalid enabled mod directory {name:?}"); }
            if let Some(other) = names.insert(windows_key(name), name) { bail!("duplicate enabled mod directory {other:?} / {name:?}"); }
            enabled.push(name);
        }
    }
    for name in enabled.into_iter().rev() { layers.push((name.into(), cfg.mods_dir().join(name))); }
    let overwrite = cfg.mo2_instance.join("overwrite");
    if overwrite.exists() { layers.push(("Overwrite".into(), overwrite)); }
    Ok(layers)
}

/// Existing physical active plugin names for FOMOD context. Uninstalled selected
/// manifest entries are projected separately by main::fomod_active_set.
pub fn existing_active_plugins(cfg: &Config) -> Result<std::collections::HashSet<String>> {
    let mut available = std::collections::HashSet::new();
    for (owner, dir) in profile_layers(cfg, false)? {
        if std::fs::symlink_metadata(&dir)?.file_type().is_symlink() { bail!("unsupported symlink provider: {}", dir.display()); }
        let mut layer = HashMap::new();
        for entry in std::fs::read_dir(&dir).with_context(|| format!("reading provider {owner}: {}", dir.display()))? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            let key = windows_key(&name);
            if ![".esm", ".esp", ".esl"].iter().any(|ext| key.ends_with(ext)) { continue; }
            let kind = entry.file_type()?;
            if kind.is_symlink() { bail!("unsupported symlink provider: {}", entry.path().display()); }
            if !kind.is_file() { continue; }
            if let Some(other) = layer.insert(key.clone(), name) { bail!("ambiguous Windows path {key} in provider {owner}: {other}"); }
            available.insert(key);
        }
    }
    let mut active = std::collections::HashSet::new();
    for name in mo2::BASE_MASTERS { if available.contains(&windows_key(name)) { active.insert(windows_key(name)); } }
    let ccc = optional_text(&cfg.stock_game.join("Skyrim.ccc"))?.unwrap_or_default();
    let plugins = optional_text(&cfg.profile_dir().join("plugins.txt"))?.unwrap_or_default();
    for name in ccc.lines().map(str::trim).filter(|l| !l.is_empty()).chain(plugins.lines().map(str::trim).filter_map(|l| l.strip_prefix('*'))) {
        let key = windows_key(name);
        if available.contains(&key) { active.insert(key); }
    }
    Ok(active)
}

fn scan_layer(dir: &Path, owner: &str, files: &mut BTreeMap<String, Vec<FileProvider>>) -> Result<()> {
    if !dir.is_dir() {
        bail!("enabled provider {owner} has no directory: {}", dir.display());
    }
    let mut layer = HashMap::new();
    for entry in WalkDir::new(dir).sort_by_file_name() {
        let entry = entry.with_context(|| format!("reading provider {owner}"))?;
        let relative = entry.path().strip_prefix(dir)?.to_string_lossy().replace('\\', "/");
        if entry.file_type().is_symlink() { bail!("unsupported symlink provider: {}", entry.path().display()); }
        if relative.is_empty() { continue; }
        let key = windows_key(&relative);
        if key == "meta.ini" {
            continue;
        }
        if let Some(other) = layer.insert(key.clone(), entry.path().to_path_buf()) {
            bail!("ambiguous Windows path {key} in provider {owner}: {} and {}", other.display(), entry.path().display());
        }
        if !entry.file_type().is_file() { continue; }
        files.entry(key).or_default().push(FileProvider { owner: owner.into(), relative, path: entry.into_path() });
    }
    Ok(())
}

pub fn run(cfg: &Config, m: &Manifest, _state: &State, skse_packed: u32) -> Result<Report> {
    let runtime = parse_runtime(&m.meta.runtime)?;
    let mut r = Report { runtime: m.meta.runtime.clone(), ..Default::default() };
    let al_name = format!("versionlib-{}.bin", m.meta.runtime.replace('.', "-") + "-0");

    // Effective MO2 layers, lowest priority first. The selected profile is the
    // authority for activation; manifest defaults are installation intentions.
    let mut files = BTreeMap::new();
    for (owner, dir) in profile_layers(cfg, true)? { scan_layer(&dir, &owner, &mut files)?; }

    // 1. Only winning native DLLs and the complete file-conflict map.
    for (key, providers) in &files {
        let winner = providers.last().unwrap();
        if key.starts_with("skse/plugins/") && key.ends_with(".dll") && key.matches('/').count() == 2 {
            let (verdict, detail) = check_dll(&std::fs::read(&winner.path)?, runtime, skse_packed);
            r.dlls.push(DllReport { mod_name: winner.owner.clone(), file: winner.relative.clone(), verdict, detail });
        }
        if key == &format!("skse/plugins/{}", windows_key(&al_name)) {
            r.address_library_present = true;
        }
    }
    for providers in files.values().filter(|v| v.len() > 1) {
        r.conflict_files += 1;
        let winner = providers.last().unwrap();
        for loser in &providers[..providers.len() - 1] {
            *r.conflicts.entry(format!("{} > {}", winner.owner, loser.owner)).or_default() += 1;
        }
    }

    // 2. Plugins: masters present and loaded earlier; slot usage.
    let plugins_path = cfg.profile_dir().join("plugins.txt");
    let order = read_plugins_txt(&plugins_path)?;
    let mut index: HashMap<String, usize> = HashMap::new();
    let mut active = Vec::new();
    let mut add = |name: &str| {
        let key = windows_key(name);
        if !index.contains_key(&key) {
            index.insert(key, active.len());
            active.push(name.to_string());
        }
    };
    for name in mo2::BASE_MASTERS { add(name); }
    // Skyrim.ccc entries load implicitly only when physically available in the
    // effective Data namespace, including downloaded creations in Overwrite.
    let ccc = optional_text(&cfg.stock_game.join("Skyrim.ccc"))?.unwrap_or_default();
    for l in ccc.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if files.contains_key(&windows_key(l)) {
            add(l);
        }
    }
    for name in &order { add(name); }
    for name in active {
        let key = windows_key(&name);
        let Some(provider) = files.get(&key).and_then(|v| v.last()) else {
            r.missing_masters.push(format!("{name}: active plugin has no physical provider"));
            continue;
        };
        let mut pl = esplugin::Plugin::new(esplugin::GameId::SkyrimSE, &provider.path);
        if let Err(e) = pl.parse_file(esplugin::ParseOptions::header_only()) {
            r.missing_masters.push(format!("{name}: unreadable header: {e}"));
            continue;
        }
        if pl.is_light_plugin() {
            r.plugins_light += 1;
        } else {
            r.plugins_full += 1;
        }
        let me = index.get(&key).copied();
        let masters = pl.masters().with_context(|| format!("reading {name} master list"))?;
        for master in masters {
            match (index.get(&windows_key(&master)), me) {
                (None, _) => r.missing_masters.push(format!("{name} needs {master}")),
                (Some(mi), Some(pi)) if *mi > pi => r.master_order_errors.push(format!("{name} loads before its master {master}")),
                _ => {}
            }
        }
    }
    Ok(r)
}

pub fn read_plugins_txt(p: &Path) -> Result<Vec<String>> {
    Ok(std::fs::read_to_string(p)
        .with_context(|| format!("reading {}", p.display()))?
        .lines()
        .map(str::trim)
        .filter_map(|l| l.strip_prefix('*'))
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Fixture { root: PathBuf, cfg: Config, manifest: Manifest }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("skyforge-check-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            std::fs::create_dir_all(root.join("stock/Data")).unwrap();
            std::fs::create_dir_all(root.join("mo2/profiles/Test")).unwrap();
            std::fs::create_dir_all(root.join("mo2/overwrite")).unwrap();
            let cfg = Config {
                workspace: root.clone(), manifest: root.join("manifest.toml"), lockfile: root.join("lock.json"), state: root.join("state.json"),
                downloads: root.join("downloads"), mo2_instance: root.join("mo2"), stock_game: root.join("stock"), profile: "Test".into(),
                staging: root.join("staging"), nexus_key_file: root.join("unused-key"), tools_bin: root.join("tools"), downloads_overflow: None, downloads_reserve_gb: None, admission: Default::default(), checkpoint: Default::default(),
            };
            let manifest = toml::from_str("[meta]\ngame_domain='skyrimspecialedition'\ngame_id=1704\nruntime='1.6.1170'\n").unwrap();
            let f = Self { root, cfg, manifest };
            f.text("mo2/profiles/Test/modlist.txt", "# MO2\n");
            f.text("mo2/profiles/Test/plugins.txt", "# MO2\n");
            f.text("stock/Skyrim.ccc", "");
            for name in mo2::BASE_MASTERS { f.plugin(&format!("stock/Data/{name}"), false, &[]); }
            f
        }
        fn text(&self, rel: &str, text: &str) { self.bytes(rel, text.as_bytes()); }
        fn bytes(&self, rel: &str, bytes: &[u8]) { let p=self.root.join(rel);std::fs::create_dir_all(p.parent().unwrap()).unwrap();std::fs::write(p,bytes).unwrap(); }
        fn plugin(&self, rel: &str, light: bool, masters: &[&str]) {
            let mut body = Vec::new();
            body.extend_from_slice(b"HEDR");body.extend_from_slice(&12u16.to_le_bytes());
            body.extend_from_slice(&1.7f32.to_le_bytes());body.extend_from_slice(&0u32.to_le_bytes());body.extend_from_slice(&0x800u32.to_le_bytes());
            for name in masters {
                body.extend_from_slice(b"MAST");body.extend_from_slice(&((name.len()+1) as u16).to_le_bytes());body.extend_from_slice(name.as_bytes());body.push(0);
                body.extend_from_slice(b"DATA");body.extend_from_slice(&8u16.to_le_bytes());body.extend_from_slice(&[0;8]);
            }
            let mut header=Vec::from(&b"TES4"[..]);header.extend_from_slice(&(body.len() as u32).to_le_bytes());header.extend_from_slice(&(if light {0x200u32}else{0}).to_le_bytes());header.extend_from_slice(&[0;8]);header.extend_from_slice(&44u16.to_le_bytes());header.extend_from_slice(&0u16.to_le_bytes());header.extend(body);self.bytes(rel,&header);
        }
        fn run(&self) -> Result<Report> { run(&self.cfg, &self.manifest, &State::default(), exe_version(2,2,6,0)) }
    }
    impl Drop for Fixture { fn drop(&mut self) { let _=std::fs::remove_dir_all(&self.root); } }

    #[test]
    fn active_windows_namespace_includes_lowercase_cc_and_overwrite() {
        let f=Fixture::new();
        f.text("stock/Skyrim.ccc", "ccExample.esl\nOverwriteCreation.esm\nUnavailableOptional.esl\n");
        f.plugin("stock/Data/ccexample.esl",true,&["Skyrim.esm"]);
        f.plugin("mo2/overwrite/overwritecreation.esm",false,&["ccEXAMPLE.esl"]);
        f.text("mo2/profiles/Test/modlist.txt", "+Active\n-Disabled\n");
        f.plugin("mo2/mods/Active/Actual.esp",false,&["overwritecreation.esm"]);
        f.plugin("mo2/mods/Active/Inactive.esp",false,&["Absent.esm"]);
        f.plugin("mo2/mods/Disabled/Disabled.esp",false,&["Absent.esm"]);
        f.text("mo2/profiles/Test/plugins.txt", "# MO2\n*ACTUAL.ESP\nInactive.esp\n");
        let r=f.run().unwrap();
        assert_eq!((r.plugins_full,r.plugins_light),(7,1));
        assert!(r.missing_masters.is_empty(),"{:?}",r.missing_masters);
        assert!(r.master_order_errors.is_empty(),"{:?}",r.master_order_errors);
    }
    #[test]
    fn only_winning_copy_and_active_plugins_supply_master_headers() {
        let f=Fixture::new();
        f.text("mo2/profiles/Test/modlist.txt", "+High\n+Low\n");
        f.plugin("mo2/mods/Low/Active.esp",false,&["Absent.esm"]);
        f.plugin("mo2/mods/High/aCTIVE.esp",true,&["Skyrim.esm"]);
        f.plugin("mo2/overwrite/ACTIVE.esp",false,&["Update.esm"]);
        f.text("mo2/profiles/Test/plugins.txt", "*active.esp\n");
        f.bytes("mo2/mods/Low/SKSE/Plugins/Test.dll", b"old invalid helper");
        f.bytes("mo2/overwrite/skse/plugins/test.DLL", b"winning helper");
        let r=f.run().unwrap();assert_eq!((r.plugins_full,r.plugins_light),(6,0));assert!(r.missing_masters.is_empty());
        assert_eq!(r.dlls.len(),1);assert_eq!(r.dlls[0].mod_name,"Overwrite");
    }
    #[test]
    fn missing_active_provider_and_disabled_master_are_errors() {
        let f=Fixture::new();f.text("mo2/profiles/Test/modlist.txt", "+Active\n");
        f.plugin("mo2/mods/Active/A.esp",false,&["Inactive.esm"]);
        f.plugin("mo2/mods/Active/Inactive.esm",false,&[]);
        f.text("mo2/profiles/Test/plugins.txt", "*A.esp\nInactive.esm\n*Missing.esp\n");
        let r=f.run().unwrap();assert!(r.missing_masters.iter().any(|x|x.contains("A.esp needs Inactive.esm")));assert!(r.missing_masters.iter().any(|x|x.contains("Missing.esp")));
    }
    #[test]
    fn missing_master_and_master_order_remain_strict() {
        let f=Fixture::new();f.text("mo2/profiles/Test/modlist.txt", "+Active\n");
        f.plugin("mo2/mods/Active/A.esp",false,&["B.esm","Absent.esm"]);f.plugin("mo2/mods/Active/B.esm",false,&[]);
        f.text("mo2/profiles/Test/plugins.txt", "*A.esp\n*B.esm\n");
        let r=f.run().unwrap();assert_eq!(r.missing_masters,vec!["A.esp needs Absent.esm"]);assert_eq!(r.master_order_errors,vec!["A.esp loads before its master B.esm"]);
    }
    #[test]
    fn same_provider_case_aliases_are_rejected() {
        let f=Fixture::new();f.text("mo2/profiles/Test/modlist.txt", "+Active\n");
        f.plugin("mo2/mods/Active/A.esp",false,&[]);f.plugin("mo2/mods/Active/a.esp",false,&[]);
        assert!(f.run().unwrap_err().to_string().contains("ambiguous Windows path"));
    }
    #[test]
    fn missing_enabled_mod_directory_is_rejected() {
        let f=Fixture::new();f.text("mo2/profiles/Test/modlist.txt", "+Missing\n");
        assert!(f.run().unwrap_err().to_string().contains("Missing"));
    }

    #[test]
    fn directory_component_aliases_are_rejected_even_with_different_files() {
        for (a,b) in [("Foo/a.txt","foo/b.txt"), ("interface/infinityui/HUDMenu/Foo/a.swf","interface/infinityui/HUDMenu/foo/b.swf")] {
            let f=Fixture::new();f.text("mo2/profiles/Test/modlist.txt", "+Active\n");
            f.text(&format!("mo2/mods/Active/{a}"), "a");f.text(&format!("mo2/mods/Active/{b}"), "b");
            assert!(f.run().unwrap_err().to_string().contains("ambiguous Windows path"));
        }
    }
    #[test]
    fn original_scaleform_component_names_are_preserved() {
        let f=Fixture::new();let rel="interface/infinityui/HUDMenu/HUDMovieBaseInstance/QuestItemList.swf";
        f.text(&format!("mo2/mods/Active/{rel}"), "swf");
        let mut files=BTreeMap::new();scan_layer(&f.cfg.mods_dir().join("Active"),"Active",&mut files).unwrap();
        assert_eq!(files[&windows_key(rel)][0].relative,rel);
        assert_eq!(files[&windows_key(rel)][0].path,f.cfg.mods_dir().join("Active").join(rel));
    }
    #[cfg(unix)]
    #[test]
    fn symlink_providers_are_reported_instead_of_ignored() {
        let f=Fixture::new();f.text("mo2/profiles/Test/modlist.txt", "+Active\n");f.text("mo2/mods/Active/real.txt","a");
        std::os::unix::fs::symlink("real.txt",f.cfg.mods_dir().join("Active/link.txt")).unwrap();
        assert!(f.run().unwrap_err().to_string().contains("unsupported symlink provider"));
    }
    #[test]
    fn missing_ccc_is_optional_but_unreadable_ccc_is_an_error() {
        let f=Fixture::new();let path=f.cfg.stock_game.join("Skyrim.ccc");std::fs::remove_file(&path).unwrap();
        assert!(f.run().is_ok());std::fs::create_dir(&path).unwrap();
        assert!(f.run().unwrap_err().to_string().contains("Skyrim.ccc"));
        assert!(existing_active_plugins(&f.cfg).unwrap_err().to_string().contains("Skyrim.ccc"));
    }
    #[test]
    fn fomod_context_unions_actual_profile_without_inactive_overwrite_plugins() {
        let f=Fixture::new();f.text("stock/Skyrim.ccc","ccDownloaded.esl\n");f.plugin("mo2/overwrite/ccdownloaded.esl",true,&[]);
        f.plugin("mo2/overwrite/Inactive.esp",false,&[]);f.plugin("mo2/overwrite/User.esp",false,&[]);
        f.text("mo2/profiles/Test/plugins.txt","*USER.ESP\nInactive.esp\n");
        let active=crate::fomod_active_set(&f.cfg,&f.manifest,&State::default()).unwrap();
        assert!(active.contains("ccdownloaded.esl"));assert!(active.contains("user.esp"));assert!(!active.contains("inactive.esp"));
    }
    #[test]
    fn fomod_context_preserves_uninstalled_plan_before_profile_and_stock_exist() {
        let f=Fixture::new();std::fs::remove_dir_all(f.cfg.stock_game.join("Data")).unwrap();std::fs::remove_dir_all(f.cfg.profile_dir()).unwrap();
        let manifest:Manifest=toml::from_str("[meta]\ngame_domain='skyrimspecialedition'\ngame_id=1704\nruntime='1.6.1170'\n[[mod]]\nkey='future'\nname='Future'\nstatus='SELECTED'\nplugins=['Future.esp']\n[[mod]]\nkey='installed'\nname='Installed'\nstatus='SELECTED'\nplugins=['WrongDeclaration.esp']\n").unwrap();
        let mut state=State::default();state.installs.insert("installed".into(),crate::install::InstallRecord{files:vec!["ActualInstalled.esp".into()],..Default::default()});
        let active=crate::fomod_active_set(&f.cfg,&manifest,&state).unwrap();
        assert!(active.contains("skyrim.esm"));assert!(active.contains("future.esp"));assert!(active.contains("actualinstalled.esp"));assert!(!active.contains("wrongdeclaration.esp"));
    }
}
