//! Installing locked, verified archives into MO2 mod folders or the Stock Game root.
//!
//! Idempotent: an entry whose sources, rules and FOMOD choices are unchanged is skipped.
//! MO2 mod folders are owned by skyforge and replaced atomically on reinstall.
//! Game-root installs back up any file they overwrite and record every path they touch.

use crate::config::Config;
use crate::fomod;
use crate::lock::LockedFile;
use crate::manifest::{ModEntry, Source, Target};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use walkdir::WalkDir;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InstallRecord {
    pub key: String,
    pub target: String,
    pub dir: PathBuf,
    /// Hash over (sources, rules, choices): unchanged => skip.
    pub fingerprint: String,
    pub files: Vec<String>,
    pub fomod_chosen: BTreeMap<String, Vec<String>>,
    pub fomod_defaulted: Vec<String>,
    pub installed_at: String,
    #[serde(default)]
    pub backups: Vec<String>,
    /// None means a legacy record still needs one read-only plan qualification.
    /// Some(empty) proves an archive has no FOMOD-dependent installation rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fomod_contexts: Option<Vec<fomod::ContextWatch>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct State {
    pub installs: BTreeMap<String, InstallRecord>,
}

impl State {
    pub fn load(p: &Path) -> Result<Self> {
        if !p.exists() {
            return Ok(State::default());
        }
        Ok(serde_json::from_str(&std::fs::read_to_string(p)?)?)
    }
    pub fn save(&self, p: &Path) -> Result<()> {
        let tmp = p.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(self)? + "\n")?;
        std::fs::rename(tmp, p)?;
        Ok(())
    }
}

const DATA_DIRS: &[&str] = &[
    "meshes", "textures", "scripts", "interface", "sound", "music", "skse", "strings", "video",
    "grass", "lodsettings", "shadersfx", "seq", "source", "dyndolod", "nemesis_engine", "pandora_engine",
    "calientetools", "netscriptframework", "shaders", "facegen", "dialogueviews", "materials",
    "lightplacer", "pbrnifpatcher", "pbrtexturesets", "trees", "terrain", "prismaui", "mcm", "oar",
    "platform", "distantlod", "lod", "vis", "config",
];
const DATA_EXT: &[&str] = &["esp", "esm", "esl", "bsa", "ini", "toml"];

fn is_data_root(dir: &Path) -> bool {
    let Ok(rd) = std::fs::read_dir(dir) else { return false };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_lowercase();
        let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if is_dir && DATA_DIRS.contains(&name.as_str()) {
            return true;
        }
        if !is_dir {
            if let Some(ext) = name.rsplit('.').next() {
                if DATA_EXT.contains(&ext) && name != "meta.ini" {
                    return true;
                }
            }
        }
    }
    false
}

/// Descend through wrapper folders ("ModName/", "Data/") to the real Data root.
fn detect_root(extracted: &Path) -> PathBuf {
    let mut cur = extracted.to_path_buf();
    for _ in 0..4 {
        if is_data_root(&cur) {
            return cur;
        }
        let entries: Vec<_> = std::fs::read_dir(&cur).map(|r| r.flatten().collect()).unwrap_or_default();
        let dirs: Vec<_> = entries.iter().filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false)).collect();
        if let Some(d) = dirs.iter().find(|e| e.file_name().to_string_lossy().eq_ignore_ascii_case("data")) {
            cur = d.path();
            continue;
        }
        let meaningful_files = entries.iter().any(|e| {
            e.file_type().map(|t| t.is_file()).unwrap_or(false) && {
                let n = e.file_name().to_string_lossy().to_lowercase();
                !(n.ends_with(".txt") || n.ends_with(".md") || n.ends_with(".pdf") || n.ends_with(".url") || n.ends_with(".png") || n.ends_with(".jpg") || n.ends_with(".html"))
            }
        });
        if dirs.len() == 1 && !meaningful_files {
            cur = dirs[0].path();
            continue;
        }
        break;
    }
    cur
}

fn find_ci(base: &Path, rel: &str) -> Option<PathBuf> {
    if rel.is_empty() {
        return Some(base.to_path_buf());
    }
    let mut cur = base.to_path_buf();
    for comp in rel.split('/') {
        let direct = cur.join(comp);
        if direct.exists() {
            cur = direct;
            continue;
        }
        let rd = std::fs::read_dir(&cur).ok()?;
        let hit = rd.flatten().find(|e| e.file_name().to_string_lossy().eq_ignore_ascii_case(comp))?;
        cur = hit.path();
    }
    Some(cur)
}

/// Normalize ordinary asset directories to avoid duplicate case variants on Linux.
/// Infinity UI's menu subtree instead encodes case-sensitive Scaleform instance names:
/// its directory enumeration becomes a GetVariable path, not just a file lookup.
fn norm_dest(rel: &str, keep_case: bool) -> String {
    let rel = rel.replace('\\', "/");
    let parts: Vec<&str> = rel.split('/').filter(|c| !c.is_empty() && *c != ".").collect();
    if keep_case {
        return parts.join("/");
    }
    let infinity_ui = parts.len() >= 2
        && parts[0].eq_ignore_ascii_case("interface")
        && parts[1].eq_ignore_ascii_case("infinityui");
    let n = parts.len();
    parts
        .iter()
        .enumerate()
        .map(|(i, c)| if i + 1 < n && !(infinity_ui && i >= 2) { c.to_lowercase() } else { c.to_string() })
        .collect::<Vec<_>>()
        .join("/")
}

fn glob_match(pat: &str, s: &str) -> bool {
    // Minimal case-insensitive glob: '*' (any run incl. '/'), '?' (one char).
    fn rec(p: &[char], s: &[char]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some('*'), _) => rec(&p[1..], s) || (!s.is_empty() && rec(p, &s[1..])),
            (Some('?'), Some(_)) => rec(&p[1..], &s[1..]),
            (Some(a), Some(b)) => a == b && rec(&p[1..], &s[1..]),
            _ => false,
        }
    }
    let p: Vec<char> = pat.to_lowercase().replace('\\', "/").chars().collect();
    let s: Vec<char> = s.to_lowercase().chars().collect();
    rec(&p, &s)
}

pub fn extract(cfg: &Config, archive: &Path, dest: &Path) -> Result<()> {
    std::fs::create_dir_all(dest)?;
    let ext = archive.extension().and_then(|e| e.to_str()).unwrap_or("").to_lowercase();
    let run_unar = || -> Result<bool> {
        Ok(Command::new(cfg.tool("unar"))
            .args(["-q", "-f", "-D", "-o"])
            .arg(dest)
            .arg(archive)
            .stdout(Stdio::null())
            .status()?
            .success())
    };
    let ok = if ext == "rar" {
        run_unar()?
    } else {
        let st = Command::new(cfg.tool("7zz"))
            .arg("x")
            .arg("-y")
            .arg("-bso0")
            .arg("-bsp0")
            .arg(format!("-o{}", dest.display()))
            .arg(archive)
            .status()?;
        st.success() || run_unar()?
    };
    if !ok {
        bail!("extraction failed for {}", archive.display());
    }
    Ok(())
}

fn fingerprint(e: &ModEntry, files: &[LockedFile]) -> String {
    let mut h = Sha256::new();
    h.update(format!("{:?}|{:?}|{:?}|{:?}|{:?}|v3", e.target, e.root, e.fomod, e.include, e.exclude));
    for f in files {
        h.update(f.sha256.as_deref().unwrap_or("?"));
    }
    hex::encode(h.finalize())
}

/// Build destination -> source mapping for one extracted archive.
fn plan_archive(
    e: &ModEntry,
    extracted: &Path,
    ctx: &fomod::Context,
    rec: &mut InstallRecord,
) -> Result<Vec<(String, PathBuf, i64, usize)>> {
    let keep_case = e.target == Target::GameRoot;
    let mut plan = Vec::new();
    // FOMOD present and not overridden by an explicit root?
    let fomod_xml = if e.root.is_none() {
        WalkDir::new(extracted)
            .max_depth(4)
            .into_iter()
            .flatten()
            .find(|d| d.file_name().to_string_lossy().eq_ignore_ascii_case("ModuleConfig.xml")
                && d.path().parent().and_then(|p| p.file_name()).map_or(false, |n| n.to_string_lossy().eq_ignore_ascii_case("fomod")))
            .map(|d| d.into_path())
    } else {
        None
    };
    if let Some(xml_path) = fomod_xml {
        let fomod_root = xml_path.parent().and_then(|p| p.parent()).unwrap().to_path_buf();
        let xml = fomod::decode_xml(&std::fs::read(&xml_path)?)?;
        let mc = fomod::ModuleConfig::parse(&xml).with_context(|| format!("parsing {}", xml_path.display()))?;
        rec.fomod_contexts.get_or_insert_with(Vec::new).push(mc.watch_context(ctx));
        let empty = BTreeMap::new();
        let res = mc.resolve(e.fomod.as_ref().unwrap_or(&empty), ctx)?;
        rec.fomod_chosen.extend(res.chosen);
        rec.fomod_defaulted.extend(res.defaulted);
        for fi in res.files {
            let src = find_ci(&fomod_root, &fi.source)
                .ok_or_else(|| anyhow!("FOMOD source '{}' not found in archive", fi.source))?;
            if fi.folder || src.is_dir() {
                for w in WalkDir::new(&src).into_iter().flatten().filter(|w| w.file_type().is_file()) {
                    let rel = w.path().strip_prefix(&src)?.to_string_lossy().replace('\\', "/");
                    let dest = if fi.destination.is_empty() { rel } else { format!("{}/{}", fi.destination, rel) };
                    plan.push((norm_dest(&dest, keep_case), w.into_path(), fi.priority, fi.seq));
                }
            } else {
                plan.push((norm_dest(&fi.destination, keep_case), src, fi.priority, fi.seq));
            }
        }
        return Ok(plan);
    }
    let root = match &e.root {
        Some(r) => find_ci(extracted, &r.replace('\\', "/")).ok_or_else(|| anyhow!("root '{r}' not in archive"))?,
        None => {
            if e.target == Target::GameRoot { extracted.to_path_buf() } else { detect_root(extracted) }
        }
    };
    for (i, w) in WalkDir::new(&root).into_iter().flatten().filter(|w| w.file_type().is_file()).enumerate() {
        let rel = w.path().strip_prefix(&root)?.to_string_lossy().replace('\\', "/");
        let lower = rel.to_lowercase();
        if e.target == Target::Mods && (lower.starts_with("fomod/") || lower == "meta.ini") {
            continue;
        }
        plan.push((norm_dest(&rel, keep_case), w.into_path(), 0, i));
    }
    Ok(plan)
}

fn write_meta_ini(dir: &Path, e: &ModEntry, files: &[LockedFile]) -> Result<()> {
    let (mod_id, version) = match &e.source {
        Some(Source::Nexus { mod_id, .. }) => (*mod_id, files.first().and_then(|f| f.version.clone()).unwrap_or_default()),
        _ => (0, files.first().and_then(|f| f.version.clone()).unwrap_or_default()),
    };
    let mut s = String::from("[General]\ngameName=SkyrimSE\n");
    s += &format!("modid={mod_id}\nversion={version}\nnewestVersion={version}\ncategory=\"\"\n");
    s += &format!("installationFile={}\n", files.first().and_then(|f| f.file_name.clone()).unwrap_or_default());
    s += if mod_id > 0 { "repository=Nexus\n" } else { "repository=\n" };
    s += &format!("url={}\nhasCustomURL={}\n", e.url.clone().unwrap_or_default(), e.url.is_some());
    s += &format!("notes=\"skyforge key {} | status {:?} | phase {}\"\n", e.key, e.status, e.phase);
    s += "converted=false\nvalidated=false\nendorsed=0\ntracked=0\n\n[installedFiles]\n";
    let mut i = 0;
    for f in files {
        if let (Some(m), Some(fid)) = (f.mod_id, f.file_id) {
            i += 1;
            s += &format!("{i}\\modid={m}\n{i}\\fileid={fid}\n");
        }
    }
    s += &format!("size={i}\n");
    std::fs::write(dir.join("meta.ini"), s)?;
    Ok(())
}

pub enum InstallOutcome {
    Unchanged,
    Installed(usize),
    /// Not installed yet, with the reason (e.g. the Stock Game it targets is not built).
    Deferred(String),
}

fn same_file_bytes(source: &Path, destination: &Path) -> Result<bool> {
    use std::fs::OpenOptions;
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let open = |path: &Path| OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path);
    let mut source_file = open(source)?;
    let mut destination_file = match open(destination) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let before_source = source_file.metadata()?;
    let before_destination = destination_file.metadata()?;
    if !before_source.is_file() || !before_destination.is_file() { bail!("non-regular installation member"); }
    if before_source.len() != before_destination.len() { return Ok(false); }
    let mut left = [0u8; 65536];
    let mut right = [0u8; 65536];
    let mut remaining = before_source.len();
    while remaining > 0 {
        let count = remaining.min(left.len() as u64) as usize;
        source_file.read_exact(&mut left[..count])?;
        destination_file.read_exact(&mut right[..count])?;
        if left[..count] != right[..count] { return Ok(false); }
        remaining -= count as u64;
    }
    if source_file.read(&mut left[..1])? != 0 || destination_file.read(&mut right[..1])? != 0 {
        bail!("installation member grew during qualification");
    }
    let after_source = source_file.metadata()?;
    let after_destination = destination_file.metadata()?;
    if before_source.len() != after_source.len() || before_source.modified()? != after_source.modified()?
        || before_destination.len() != after_destination.len() || before_destination.modified()? != after_destination.modified()? {
        bail!("installation member changed during qualification");
    }
    Ok(true)
}

pub fn install_one(
    cfg: &Config,
    e: &ModEntry,
    files: &[LockedFile],
    state: &mut State,
    active_files: &HashSet<String>,
    game_version: &str,
) -> Result<InstallOutcome> {
    if e.target == Target::None {
        return Ok(InstallOutcome::Unchanged);
    }
    // Writing into a not-yet-built Stock Game would create the folder and make stock-build
    // refuse to merge the depots into it.
    if e.target == Target::GameRoot && !cfg.stock_game.join("SkyrimSE.exe").is_file() {
        return Ok(InstallOutcome::Deferred("Stock Game not built yet (run stock-build first)".into()));
    }
    for f in files {
        if f.verified_by.is_none() {
            bail!("{}: source {} is not verified; run fetch first", e.key, f.display_name);
        }
    }
    let fp = fingerprint(e, files);
    let ctx = fomod::Context { active_files, game_version };
    let dest_dir = match e.target {
        Target::Mods => cfg.mods_dir().join(&e.name),
        Target::GameRoot => cfg.stock_game.clone(),
        Target::None => unreachable!(),
    };
    if let Some(r) = state.installs.get(&e.key) {
        if r.fingerprint == fp && r.dir == dest_dir && (e.target == Target::GameRoot || dest_dir.exists()) {
            if r.fomod_contexts.as_ref().is_some_and(|watches| watches.iter().all(|watch| watch.matches(&ctx))) {
                return Ok(InstallOutcome::Unchanged);
            }
        }
    }
    let staging = cfg.staging.join(&e.key);
    if staging.exists() {
        std::fs::remove_dir_all(&staging)?;
    }
    let mut rec = InstallRecord { key: e.key.clone(), target: format!("{:?}", e.target), dir: dest_dir.clone(), fingerprint: fp, installed_at: chrono::Local::now().to_rfc3339(), fomod_contexts: Some(Vec::new()), ..Default::default() };
    // dest -> (src, priority, seq, archive index)
    let mut merged: HashMap<String, (PathBuf, i64, usize, usize)> = HashMap::new();
    let mut display: HashMap<String, String> = HashMap::new();
    for (ai, f) in files.iter().enumerate() {
        let archive = f.archive_path(&cfg.downloads).ok_or_else(|| anyhow!("no file name"))?;
        let x = staging.join(format!("a{ai}"));
        extract(cfg, &archive, &x).with_context(|| format!("{}: extracting {}", e.key, archive.display()))?;
        for (dest, src, prio, seq) in plan_archive(e, &x, &ctx, &mut rec)? {
            if dest.is_empty() {
                continue;
            }
            if !e.include.is_empty() && !e.include.iter().any(|p| glob_match(p, &dest)) {
                continue;
            }
            if e.exclude.iter().any(|p| glob_match(p, &dest)) {
                continue;
            }
            let k = dest.to_lowercase();
            let better = match merged.get(&k) {
                None => true,
                Some((_, p, s, a)) => (ai, prio, seq) >= (*a, *p, *s),
            };
            if better {
                merged.insert(k.clone(), (src, prio, seq, ai));
                display.insert(k, dest);
            }
        }
    }
    if merged.is_empty() {
        bail!("{}: nothing to install after applying rules", e.key);
    }
    // Requalify old records and relevant predicate changes without replacing
    // packages whose resolved choices, output paths and actual bytes agree.
    if let Some(previous) = state.installs.get(&e.key) {
        let mut planned: Vec<_> = display.values().cloned().collect();
        planned.sort();
        if previous.fingerprint == rec.fingerprint && previous.dir == dest_dir
            && previous.files == planned && previous.fomod_chosen == rec.fomod_chosen {
            let mut equal = true;
            for (key, (source, ..)) in &merged {
                if !same_file_bytes(source, &dest_dir.join(&display[key]))? { equal = false; break; }
            }
            if equal {
                rec.files = previous.files.clone();
                rec.installed_at = previous.installed_at.clone();
                rec.backups = previous.backups.clone();
                state.installs.insert(e.key.clone(), rec);
                std::fs::remove_dir_all(&staging)?;
                return Ok(InstallOutcome::Unchanged);
            }
            // A context metadata migration is not authority to overwrite an
            // unrecorded local edit when source rules and selected outputs agree.
            bail!("{}: installed bytes differ from the unchanged source plan; preserving files", e.key);
        }
    }
    match e.target {
        Target::Mods => {
            let tmp = cfg.mods_dir().join(format!(".{}.skyforge-new", e.name));
            if tmp.exists() {
                std::fs::remove_dir_all(&tmp)?;
            }
            std::fs::create_dir_all(&tmp)?;
            for (k, (src, ..)) in &merged {
                let d = tmp.join(&display[k]);
                std::fs::create_dir_all(d.parent().unwrap())?;
                std::fs::rename(src, &d).or_else(|_| std::fs::copy(src, &d).map(|_| ()))?;
                rec.files.push(display[k].clone());
            }
            write_meta_ini(&tmp, e, files)?;
            if dest_dir.exists() {
                // Only ever remove a folder skyforge itself installed.
                let owned = state.installs.get(&e.key).map_or(false, |r| r.dir == dest_dir);
                if !owned {
                    bail!("{} exists but is not managed by skyforge; refusing to replace it", dest_dir.display());
                }
                std::fs::remove_dir_all(&dest_dir)?;
            }
            std::fs::rename(&tmp, &dest_dir)?;
        }
        Target::GameRoot => {
            let bdir = cfg.workspace.join("backups/game-root").join(&e.key).join(chrono::Local::now().format("%Y%m%d-%H%M%S").to_string());
            for (k, (src, ..)) in &merged {
                let d = dest_dir.join(&display[k]);
                if d.exists() {
                    let b = bdir.join(&display[k]);
                    std::fs::create_dir_all(b.parent().unwrap())?;
                    std::fs::copy(&d, &b)?;
                    rec.backups.push(display[k].clone());
                }
                std::fs::create_dir_all(d.parent().unwrap())?;
                std::fs::copy(src, &d)?;
                rec.files.push(display[k].clone());
            }
        }
        Target::None => {}
    }
    rec.files.sort();
    let n = rec.files.len();
    state.installs.insert(e.key.clone(), rec);
    std::fs::remove_dir_all(&staging).ok();
    Ok(InstallOutcome::Installed(n))
}

#[cfg(test)]
mod tests {
    use super::norm_dest;
    use sha2::Digest;

    fn dependency_fixture(condition: &str) -> (super::Config, super::ModEntry, Vec<super::LockedFile>, super::State) {
        use std::{fs, process::Command, time::{SystemTime, UNIX_EPOCH}};
        let id=SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let root=std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("test-output/{}-{id}",std::process::id()));
        let source=root.join("source");fs::create_dir_all(source.join("fomod")).unwrap();
        fs::create_dir_all(root.join("downloads")).unwrap();fs::create_dir_all(root.join("mo2/mods")).unwrap();
        fs::write(source.join("Base.ini"),b"base\n").unwrap();fs::write(source.join("Dependency.ini"),b"dependency\n").unwrap();
        let xml=format!(r#"<config><moduleName>Context test</moduleName><requiredInstallFiles><file source="Base.ini" destination="Base.ini"/></requiredInstallFiles><conditionalFileInstalls><patterns><pattern><dependencies>{condition}</dependencies><files><file source="Dependency.ini" destination="Dependency.ini"/></files></pattern></patterns></conditionalFileInstalls></config>"#);
        fs::write(source.join("fomod/ModuleConfig.xml"),xml).unwrap();
        let archive=root.join("downloads/fixture.7z");
        assert!(Command::new("7zz").args(["a","-t7z","-mx0","-bd","-bso0","-bsp0"]).arg(&archive).arg(".").current_dir(&source).status().unwrap().success());
        // Resolve extraction tools on PATH, just as fixture creation does.
        let cfg = super::Config {
            workspace: root.clone(),
            manifest: root.join("mods.toml"),
            lockfile: root.join("lock.json"),
            state: root.join("state.json"),
            downloads: root.join("downloads"),
            mo2_instance: root.join("mo2"),
            stock_game: root.join("stock"),
            profile: "Test".into(),
            staging: root.join("staging"),
            nexus_key_file: root.join("unused"),
            tools_bin: std::path::PathBuf::new(),
            downloads_overflow: None,
            downloads_reserve_gb: None,
        };
        let entry=serde_json::from_value(serde_json::json!({"key":"dependency-fixture","name":"Dependency fixture","status":"SELECTED"})).unwrap();
        let bytes=fs::read(&archive).unwrap();
        let locked=super::LockedFile{source:"local".into(),file_name:Some("fixture.7z".into()),display_name:"fixture".into(),sha256:Some(format!("{:x}",super::Sha256::digest(&bytes))),verified_by:Some("local-test-fixture".into()),..Default::default()};
        (cfg,entry,vec![locked],super::State::default())
    }

    #[test]
    fn conditional_dependency_change_is_not_unchanged() {
        let(cfg,e,files,mut state)=dependency_fixture(r#"<fileDependency file="ccFixture.esl" state="Active"/>"#);
        let mut active=std::collections::HashSet::new();
        assert!(matches!(super::install_one(&cfg,&e,&files,&mut state,&active,"1.6.1170.0").unwrap(),super::InstallOutcome::Installed(1)));
        active.insert("ccfixture.esl".into());
        assert!(matches!(super::install_one(&cfg,&e,&files,&mut state,&active,"1.6.1170.0").unwrap(),super::InstallOutcome::Installed(2)));
        assert_eq!(std::fs::read(cfg.mods_dir().join(&e.name).join("Dependency.ini")).unwrap(),b"dependency\n");
    }

    #[test]
    fn game_dependency_change_is_not_unchanged() {
        let(cfg,e,files,mut state)=dependency_fixture(r#"<gameDependency version="1.6.1170.0"/>"#);
        let active=std::collections::HashSet::new();
        assert!(matches!(super::install_one(&cfg,&e,&files,&mut state,&active,"1.5.97.0").unwrap(),super::InstallOutcome::Installed(1)));
        assert!(matches!(super::install_one(&cfg,&e,&files,&mut state,&active,"1.6.1170.0").unwrap(),super::InstallOutcome::Installed(2)));
    }

    #[test]
    fn unrelated_activation_reuses_qualified_plan_without_extraction() {
        let(cfg,e,files,mut state)=dependency_fixture(r#"<fileDependency file="ccFixture.esl" state="Active"/>"#);
        let mut active=std::collections::HashSet::new();
        super::install_one(&cfg,&e,&files,&mut state,&active,"1.6.1170.0").unwrap();
        std::fs::remove_file(files[0].archive_path(&cfg.downloads).unwrap()).unwrap();
        active.insert("unrelated.esp".into());
        assert!(matches!(super::install_one(&cfg,&e,&files,&mut state,&active,"1.6.1170.0").unwrap(),super::InstallOutcome::Unchanged));
    }

    #[test]
    fn legacy_record_requalifies_without_rewriting_identical_files() {
        use std::os::unix::fs::MetadataExt;
        let(cfg,e,files,mut state)=dependency_fixture(r#"<fileDependency file="ccFixture.esl" state="Active"/>"#);
        let active=std::collections::HashSet::new();
        super::install_one(&cfg,&e,&files,&mut state,&active,"1.6.1170.0").unwrap();
        let installed=cfg.mods_dir().join(&e.name).join("Base.ini");let before=std::fs::metadata(&installed).unwrap();
        let mut json=serde_json::to_value(&state).unwrap();json["installs"][&e.key].as_object_mut().unwrap().remove("fomod_contexts");
        state=serde_json::from_value(json).unwrap();
        assert!(matches!(super::install_one(&cfg,&e,&files,&mut state,&active,"1.6.1170.0").unwrap(),super::InstallOutcome::Unchanged));
        let after=std::fs::metadata(&installed).unwrap();assert_eq!(before.ino(),after.ino());assert_eq!(before.modified().unwrap(),after.modified().unwrap());
        assert!(state.installs[&e.key].fomod_contexts.is_some());
    }

    #[test]
    fn legacy_record_still_detects_conditional_only_plan_change() {
        let(cfg,e,files,mut state)=dependency_fixture(r#"<fileDependency file="ccFixture.esl" state="Active"/>"#);
        let mut active=std::collections::HashSet::new();
        super::install_one(&cfg,&e,&files,&mut state,&active,"1.6.1170.0").unwrap();
        let prior=state.installs.get_mut(&e.key).unwrap();assert!(prior.fomod_chosen.is_empty()&&prior.fomod_defaulted.is_empty());prior.fomod_contexts=None;
        active.insert("ccfixture.esl".into());
        assert!(matches!(super::install_one(&cfg,&e,&files,&mut state,&active,"1.6.1170.0").unwrap(),super::InstallOutcome::Installed(2)));
    }

    #[test]
    fn relevant_change_with_same_filtered_output_preserves_files() {
        use std::os::unix::fs::MetadataExt;
        let(cfg,mut e,files,mut state)=dependency_fixture(r#"<fileDependency file="ccFixture.esl" state="Active"/>"#);
        e.include=vec!["Base.ini".into()];let mut active=std::collections::HashSet::new();
        super::install_one(&cfg,&e,&files,&mut state,&active,"1.6.1170.0").unwrap();
        let installed=cfg.mods_dir().join(&e.name).join("Base.ini");let inode=std::fs::metadata(&installed).unwrap().ino();
        active.insert("ccfixture.esl".into());
        assert!(matches!(super::install_one(&cfg,&e,&files,&mut state,&active,"1.6.1170.0").unwrap(),super::InstallOutcome::Unchanged));
        assert_eq!(inode,std::fs::metadata(installed).unwrap().ino());
    }

    #[test]
    fn legacy_context_migration_preserves_unrecorded_local_edits() {
        let(cfg,e,files,mut state)=dependency_fixture(r#"<fileDependency file="ccFixture.esl" state="Active"/>"#);
        let active=std::collections::HashSet::new();super::install_one(&cfg,&e,&files,&mut state,&active,"1.6.1170.0").unwrap();
        state.installs.get_mut(&e.key).unwrap().fomod_contexts=None;
        let installed=cfg.mods_dir().join(&e.name).join("Base.ini");std::fs::write(&installed,b"owner modification\n").unwrap();
        assert!(super::install_one(&cfg,&e,&files,&mut state,&active,"1.6.1170.0").err().unwrap().to_string().contains("preserving files"));
        assert_eq!(std::fs::read(installed).unwrap(),b"owner modification\n");
    }

    #[test]
    fn same_satisfied_game_predicate_keeps_qualified_plan() {
        let(cfg,e,files,mut state)=dependency_fixture(r#"<gameDependency version="1.6.1170.0"/>"#);
        let active=std::collections::HashSet::new();super::install_one(&cfg,&e,&files,&mut state,&active,"1.6.1170.0").unwrap();
        std::fs::remove_file(files[0].archive_path(&cfg.downloads).unwrap()).unwrap();
        assert!(matches!(super::install_one(&cfg,&e,&files,&mut state,&active,"1.7.104.0").unwrap(),super::InstallOutcome::Unchanged));
    }

    #[test]
    fn infinity_ui_paths_preserve_scaleform_member_names() {
        // Infinity UI turns these directory names into case-sensitive GetVariable paths.
        assert_eq!(
            norm_dest("Interface/InfinityUI/HUDMenu/HUDMovieBaseInstance/CompassShoutMeterHolder/Compass.swf", false),
            "interface/infinityui/HUDMenu/HUDMovieBaseInstance/CompassShoutMeterHolder/Compass.swf"
        );
        assert_eq!(
            norm_dest(r"INTERFACE\InfinityUI\HUDMenu\HUDMovieBaseInstance\QuestItemList.swf", false),
            "interface/infinityui/HUDMenu/HUDMovieBaseInstance/QuestItemList.swf"
        );
        assert_eq!(
            norm_dest("interface/infinityui/OtherMenu/SomeContainer/MyWidget/child.swf", false),
            "interface/infinityui/OtherMenu/SomeContainer/MyWidget/child.swf"
        );
    }

    #[test]
    fn ordinary_asset_paths_and_game_root_keep_their_existing_contract() {
        assert_eq!(norm_dest("Textures/Actors/Character/Face.DDS", false), "textures/actors/character/Face.DDS");
        assert_eq!(norm_dest("Interface/Exported/Widgets/Widget.swf", false), "interface/exported/widgets/Widget.swf");
        assert_eq!(norm_dest("Other/InfinityUI/SomeFolder/file.swf", false), "other/infinityui/somefolder/file.swf");
        assert_eq!(norm_dest("SKSE/Plugins/Plugin.dll", true), "SKSE/Plugins/Plugin.dll");
    }
}
