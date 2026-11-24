//! Installing locked, verified archives into MO2 mod folders or the Stock Game root.
//!
//! Idempotent: an entry whose sources, rules and FOMOD choices are unchanged is skipped.
//! Every archive passes admission first: its bytes are checked against the lockfile, it is
//! extracted under confinement and limits, and the staged tree is inspected.
//! MO2 mod folders are owned by skyforge and exchanged atomically on reinstall.
//! Game-root installs back up any file they overwrite and record every path they touch.

use crate::admission;
use crate::config::Config;
use crate::fomod;
use crate::lock::LockedFile;
use crate::manifest::{ModEntry, Source, Target};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
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
    /// One digest over every installed destination and the SHA-256 of its bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_sha256: Option<String>,
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
        if comp == ".." {
            return None;
        }
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
            admission::check_source(&fi.source)?;
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
        Some(r) => {
            admission::check_source(r)?;
            find_ci(extracted, &r.replace('\\', "/")).ok_or_else(|| anyhow!("root '{r}' not in archive"))?
        }
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

/// Whether the newest game-root journal of this key has no end: the run that wrote it was
/// cut off between its first and last file.
fn game_root_interrupted(cfg: &Config, key: &str) -> bool {
    let Ok(runs) = std::fs::read_dir(cfg.workspace.join("backups/game-root").join(key)) else { return false };
    let Some(latest) = runs.flatten().map(|run| run.path()).max() else { return false };
    let Ok(text) = std::fs::read_to_string(latest.join("journal.json")) else { return false };
    serde_json::from_str::<serde_json::Value>(&text).is_ok_and(|journal| journal.get("completed_at").is_none() && journal.get("rolled_back_at").is_none())
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
    let mut receipt = admission::Receipt::begin(&e.key, &format!("{:?}", e.target), files, &e.executables, &e.extra_types, &cfg.admission);
    // A receipt can be shared for review, so it names local directories by role, not by path.
    for (path, label) in [(&cfg.staging, "<staging>"), (&cfg.downloads, "<downloads>"), (&cfg.mods_dir(), "<mods>"), (&cfg.mo2_instance, "<mo2>"), (&cfg.stock_game, "<game-root>"), (&cfg.workspace, "<workspace>")] {
        receipt.hide(path, label);
    }
    if let Some(overflow) = &cfg.downloads_overflow {
        receipt.hide(overflow, "<downloads>");
    }
    if let Some(home) = std::env::var_os("HOME") {
        receipt.hide(std::path::Path::new(&home), "<home>");
    }
    let result = install_checked(cfg, e, files, state, active_files, game_version, &mut receipt);
    match receipt.finish(&cfg.state, &result) {
        Ok(_) => result,
        // The original failure matters more than a receipt that could not be written.
        Err(_) if result.is_err() => result,
        Err(error) => Err(error.context(format!("{}: recording the admission receipt", e.key))),
    }
}

fn install_checked(
    cfg: &Config,
    e: &ModEntry,
    files: &[LockedFile],
    state: &mut State,
    active_files: &HashSet<String>,
    game_version: &str,
    receipt: &mut admission::Receipt,
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
    if e.target == Target::Mods {
        if !admission::safe_mod_name(&e.name) {
            bail!("{}: mod name {:?} cannot name an MO2 mod folder", e.key, e.name);
        }
        admission::recover_dir(&cfg.mods_dir(), &e.name)?;
        // Only ever replace a folder skyforge itself installed.
        let owned = state.installs.get(&e.key).is_some_and(|r| r.dir == dest_dir);
        if !owned && std::fs::symlink_metadata(&dest_dir).is_ok() {
            bail!("{} exists but is not managed by skyforge; refusing to replace it", dest_dir.display());
        }
    }
    // A game-root activation that was cut off left a journal without an end. Until a run
    // completes, the files on disk are not known to match any record.
    let interrupted = e.target == Target::GameRoot && game_root_interrupted(cfg, &e.key);
    if let Some(r) = state.installs.get(&e.key) {
        if !interrupted && r.fingerprint == fp && r.dir == dest_dir && (e.target == Target::GameRoot || dest_dir.exists()) {
            if r.fomod_contexts.as_ref().is_some_and(|watches| watches.iter().all(|watch| watch.matches(&ctx))) {
                return Ok(InstallOutcome::Unchanged);
            }
        }
    }
    // The key names the receipt directory, so it is checked before a receipt is promised.
    if !admission::safe_key(&e.key) {
        return Err(admission::Refusal { code: admission::RefusalCode::UnapprovedIdentity, detail: format!("manifest key {:?} cannot name a staging directory", e.key) }.into());
    }
    receipt.started = true;
    let staging = admission::owned_staging(&cfg.staging, &e.key)?;
    receipt.staging = Some(staging.clone());
    let mut staged = admission::Staged::default();
    let mut rec = InstallRecord { key: e.key.clone(), target: format!("{:?}", e.target), dir: dest_dir.clone(), fingerprint: fp, installed_at: chrono::Local::now().to_rfc3339(), fomod_contexts: Some(Vec::new()), ..Default::default() };
    // dest -> (src, priority, seq, archive index)
    let mut merged: HashMap<String, (PathBuf, i64, usize, usize)> = HashMap::new();
    let mut display: HashMap<String, String> = HashMap::new();
    for (ai, f) in files.iter().enumerate() {
        let path = admission::approved_path(&cfg.downloads, cfg.downloads_overflow.as_deref(), f)?;
        let archive = admission::BoundArchive::read(&path)?;
        receipt.archives[ai].observed_sha256 = Some(archive.sha256.clone());
        receipt.archives[ai].size = Some(archive.size);
        archive.approve(f)?;
        let x = staging.join(format!("a{ai}"));
        receipt.confinement = admission::extract(|tool| cfg.tool(tool), &archive, &receipt.archives[ai].file_name, &x, &cfg.admission)
            .with_context(|| format!("{}: extracting {}", e.key, receipt.archives[ai].file_name))?;
        let tree = admission::inspect_tree(&x, &cfg.admission.limits).with_context(|| format!("{}: inspecting {}", e.key, receipt.archives[ai].file_name))?;
        staged.entries += tree.entries;
        staged.bytes += tree.bytes;
        receipt.staged = Some(staged);
        for (dest, src, prio, seq) in plan_archive(e, &x, &ctx, &mut rec)? {
            if dest.is_empty() {
                continue;
            }
            // FOMOD and manifest rules name these paths; neither may leave its tree.
            admission::check_contained(&x, &src)?;
            admission::check_destination(&dest)?;
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
        if !interrupted && previous.fingerprint == rec.fingerprint && previous.dir == dest_dir
            && previous.files == planned && previous.fomod_chosen == rec.fomod_chosen {
            let mut equal = true;
            for (key, (source, ..)) in &merged {
                if !same_file_bytes(source, &dest_dir.join(&display[key]))? { equal = false; break; }
            }
            if equal {
                rec.files = previous.files.clone();
                rec.installed_at = previous.installed_at.clone();
                rec.backups = previous.backups.clone();
                rec.plan_sha256 = previous.plan_sha256.clone();
                state.installs.insert(e.key.clone(), rec);
                receipt.decision = admission::Decision::Unchanged;
                return Ok(InstallOutcome::Unchanged);
            }
            // A context metadata migration is not authority to overwrite an
            // unrecorded local edit when source rules and selected outputs agree.
            bail!("{}: installed bytes differ from the unchanged source plan; preserving files", e.key);
        }
    }
    // Hash every planned output once. Activation below accepts only these exact files.
    let mut proofs: HashMap<&String, admission::Proof> = HashMap::new();
    for (k, (src, ..)) in &merged {
        let proof = admission::prove(src).with_context(|| format!("{}: inspecting {}", e.key, display[k]))?;
        if let Some(class) = admission::classify(&display[k], &proof.head) {
            receipt.executables.push(admission::ExecRecord { path: display[k].clone(), class, sha256: proof.sha256.clone() });
        }
        proofs.insert(k, proof);
    }
    receipt.executables.sort_by(|a, b| a.path.cmp(&b.path));
    admission::enforce_executables(&receipt.executables, &e.executables)?;
    // Everything that is not an executable class must be a known data type or one this entry names.
    let classed: HashSet<&String> = receipt.executables.iter().map(|r| &r.path).collect();
    admission::enforce_known_types(display.values().filter(|d| !classed.contains(d)), &e.extra_types)?;
    let planned: Vec<(String, &admission::Proof)> = merged.keys().map(|k| (display[k].clone(), &proofs[k])).collect();
    let plan = admission::PlanRecord { files: planned.len(), bytes: planned.iter().map(|(_, p)| p.size).sum(), sha256: admission::plan_digest(&planned) };
    rec.plan_sha256 = Some(plan.sha256.clone());
    receipt.plan = Some(plan);
    match e.target {
        Target::Mods => {
            let tmp = admission::assembly_dir(&cfg.mods_dir(), &e.name);
            let assemble = || -> Result<()> {
                std::fs::create_dir_all(&tmp)?;
                for (k, (src, ..)) in &merged {
                    let d = tmp.join(&display[k]);
                    std::fs::create_dir_all(d.parent().unwrap())?;
                    admission::place_verified(src, &d, &proofs[k], false)?;
                }
                write_meta_ini(&tmp, e, files)
            };
            if let Err(error) = assemble() {
                admission::remove_tree(&tmp).ok();
                return Err(error);
            }
            rec.files.extend(display.values().cloned());
            let replaced = std::fs::symlink_metadata(&dest_dir).is_ok();
            let method = admission::activate_dir(&cfg.mods_dir(), &e.name)?;
            receipt.activation = Some(admission::ActivationRecord { method, replaced_existing: replaced });
        }
        Target::GameRoot => {
            let bdir = cfg.workspace.join("backups/game-root").join(&e.key).join(chrono::Local::now().format("%Y%m%d-%H%M%S").to_string());
            // Refuse before the first write: no planned path may pass through a link or
            // replace anything but a regular file.
            for k in merged.keys() {
                let mut at = dest_dir.clone();
                let parts: Vec<&str> = display[k].split('/').collect();
                for (i, part) in parts.iter().enumerate() {
                    at.push(part);
                    let last = i + 1 == parts.len();
                    match std::fs::symlink_metadata(&at) {
                        Ok(m) if (last && m.is_file()) || (!last && m.is_dir()) => {}
                        Ok(_) => bail!("{}: {} passes through or replaces something in the game root that is not a plain file or directory", e.key, display[k]),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                        Err(error) => return Err(error.into()),
                    }
                }
            }
            // The journal names every path this activation may touch. It gains an end only
            // when the run completes or is rolled back, so a run that was cut off is visible.
            std::fs::create_dir_all(&bdir)?;
            let journal = bdir.join("journal.json");
            let mut planned_paths: Vec<&String> = merged.keys().map(|k| &display[k]).collect();
            planned_paths.sort();
            let mut entry = serde_json::json!({"version": 1, "key": e.key, "plan_sha256": rec.plan_sha256, "started_at": chrono::Local::now().to_rfc3339(), "files": planned_paths});
            let write_journal = |entry: &serde_json::Value| -> Result<()> { Ok(std::fs::write(&journal, serde_json::to_string_pretty(entry)? + "\n")?) };
            write_journal(&entry)?;
            // Phase 1: write every new file beside its destination under a temporary name and
            // confirm its bytes. Nothing the game reads has changed, so a failure here removes
            // the temporaries and leaves the game root as it was.
            let mut written: Vec<(PathBuf, PathBuf, &String)> = Vec::new();
            let mut failure = None;
            for (k, (src, ..)) in &merged {
                let d = dest_dir.join(&display[k]);
                let name = d.file_name().unwrap().to_string_lossy().into_owned();
                let tmp = d.with_file_name(format!(".{name}.skyforge-new"));
                let step = (|| -> Result<()> {
                    std::fs::create_dir_all(d.parent().unwrap())?;
                    admission::remove_tree(&tmp)?;
                    admission::place_verified(src, &tmp, &proofs[k], true)
                })();
                match step {
                    Ok(()) => written.push((tmp, d, &display[k])),
                    Err(error) => {
                        admission::remove_tree(&tmp).ok();
                        failure = Some(error);
                        break;
                    }
                }
            }
            // Phase 2: back up and rename, one file at a time. A failure undoes the files
            // already switched, so the game root is the old set or the new one.
            enum Undo { Restore(PathBuf), Remove, Keep }
            let mut done: Vec<(&PathBuf, Undo)> = Vec::new();
            if failure.is_none() {
                for (tmp, d, shown) in &written {
                    let step = (|| -> Result<Undo> {
                        #[cfg(test)]
                        tests::injected_failure(done.len())?;
                        let undo = if std::fs::symlink_metadata(d).is_err() {
                            Undo::Remove
                        } else if same_file_bytes(tmp, d)? {
                            // Written by a run that was cut off. Its original is in that
                            // run's backup, so it is not backed up again.
                            Undo::Keep
                        } else {
                            let b = bdir.join(shown);
                            std::fs::create_dir_all(b.parent().unwrap())?;
                            std::fs::copy(d, &b)?;
                            Undo::Restore(b)
                        };
                        std::fs::rename(tmp, d)?;
                        Ok(undo)
                    })();
                    match step {
                        Ok(undo) => done.push((d, undo)),
                        Err(error) => {
                            failure = Some(error);
                            break;
                        }
                    }
                }
            }
            if let Some(error) = failure {
                for (d, undo) in done.iter().rev() {
                    match undo {
                        Undo::Restore(b) => {
                            let back = d.with_file_name(format!(".{}.skyforge-undo", d.file_name().unwrap().to_string_lossy()));
                            std::fs::copy(b, &back).and_then(|_| std::fs::rename(&back, d)).with_context(|| format!("{}: restoring a replaced game-root file from its backup", e.key))?;
                        }
                        Undo::Remove => std::fs::remove_file(d)?,
                        Undo::Keep => {}
                    }
                }
                for (tmp, ..) in &written {
                    admission::remove_tree(tmp).ok();
                }
                entry["rolled_back_at"] = chrono::Local::now().to_rfc3339().into();
                write_journal(&entry)?;
                return Err(error);
            }
            let mut replaced = false;
            for ((_, _, shown), (_, undo)) in written.iter().zip(&done) {
                if matches!(undo, Undo::Restore(_)) {
                    rec.backups.push((*shown).clone());
                    replaced = true;
                }
                rec.files.push((*shown).clone());
            }
            entry["completed_at"] = chrono::Local::now().to_rfc3339().into();
            write_journal(&entry)?;
            receipt.activation = Some(admission::ActivationRecord { method: "game-root", replaced_existing: replaced });
        }
        Target::None => {}
    }
    rec.files.sort();
    let n = rec.files.len();
    state.installs.insert(e.key.clone(), rec);
    receipt.decision = admission::Decision::Admitted;
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
            // These fixtures must not depend on how full the host filesystem is.
            admission: super::admission::Policy { limits: super::admission::Limits { reserve_bytes: 0, ..Default::default() }, ..Default::default() },
            checkpoint: Default::default(),
        };
        let entry=serde_json::from_value(serde_json::json!({"key":"dependency-fixture","name":"Dependency fixture","status":"SELECTED"})).unwrap();
        let bytes=fs::read(&archive).unwrap();
        let locked=super::LockedFile{source:"local".into(),file_name:Some("fixture.7z".into()),display_name:"fixture".into(),sha256:Some(hex::encode(super::Sha256::digest(&bytes))),verified_by:Some("local-test-fixture".into()),..Default::default()};
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

    // ---- Archive admission, end to end through install_one with synthetic archives ----

    thread_local! {
        /// The number of game-root files after which the next switch fails, for one test.
        static FAIL_AT: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    }

    pub(super) fn injected_failure(switched: usize) -> anyhow::Result<()> {
        if FAIL_AT.with(|at| at.get()) == Some(switched) {
            anyhow::bail!("injected failure after {switched} switched files");
        }
        Ok(())
    }

    use super::admission::testkit::{conforms, scratch, tar, Entry};
    use super::admission::{ExecClass, Refusal, RefusalCode};

    struct Fixture {
        cfg: super::Config,
        entry: super::ModEntry,
        files: Vec<super::LockedFile>,
        state: super::State,
        active: std::collections::HashSet<String>,
    }

    impl Fixture {
        fn new(archive: &[u8]) -> Self {
            let root = scratch("admit");
            for dir in ["downloads", "mo2/mods"] {
                std::fs::create_dir_all(root.join(dir)).unwrap();
            }
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
                admission: super::admission::Policy { limits: super::admission::Limits { reserve_bytes: 0, ..Default::default() }, ..Default::default() },
            checkpoint: Default::default(),
            };
            let entry = serde_json::from_value(serde_json::json!({"key": "fixture", "name": "Fixture mod", "status": "SELECTED"})).unwrap();
            let mut fixture = Fixture { cfg, entry, files: Vec::new(), state: super::State::default(), active: Default::default() };
            fixture.approve(archive);
            fixture
        }

        /// Place archive bytes in the download directory without touching the lock.
        fn place(&self, archive: &[u8]) {
            std::fs::write(self.cfg.downloads.join("fixture.tar"), archive).unwrap();
        }

        /// Place archive bytes and approve exactly those bytes in the lock.
        fn approve(&mut self, archive: &[u8]) {
            self.place(archive);
            self.files = vec![super::LockedFile {
                source: "url".into(),
                file_name: Some("fixture.tar".into()),
                display_name: "fixture".into(),
                sha256: Some(hex::encode(super::Sha256::digest(archive))),
                size: Some(archive.len() as u64),
                url: Some("https://downloads.invalid/fixture.tar?token=signed-secret".into()),
                verified_by: Some("sha256-pinned".into()),
                ..Default::default()
            }];
        }

        fn install(&mut self) -> anyhow::Result<super::InstallOutcome> {
            super::install_one(&self.cfg, &self.entry, &self.files, &mut self.state, &self.active, "1.6.1170.0")
        }

        fn refused(&mut self) -> RefusalCode {
            let error = self.install().err().expect("the install must be refused");
            error.chain().find_map(|e| e.downcast_ref::<Refusal>()).unwrap_or_else(|| panic!("not a refusal: {error:#}")).code
        }

        fn mod_dir(&self) -> std::path::PathBuf {
            self.cfg.mods_dir().join(&self.entry.name)
        }

        fn receipts(&self) -> Vec<serde_json::Value> {
            let dir = self.cfg.workspace.join("admission").join(&self.entry.key);
            let mut paths: Vec<_> = std::fs::read_dir(dir).map(|d| d.flatten().map(|e| e.path()).collect()).unwrap_or_default();
            paths.sort();
            paths.iter().map(|p| serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()).collect()
        }

        /// Nothing is left in staging, and the mods directory holds only finished mod folders.
        fn assert_clean(&self) {
            assert!(!self.cfg.staging.join(&self.entry.key).exists(), "staging must be cleared");
            for e in std::fs::read_dir(self.cfg.mods_dir()).unwrap().flatten() {
                assert!(!e.file_name().to_string_lossy().starts_with('.'), "leftover {:?}", e.file_name());
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            super::admission::remove_tree(&self.cfg.workspace).ok();
        }
    }

    #[test]
    fn an_ordinary_archive_is_admitted_with_a_receipt() {
        let mut f = Fixture::new(&tar(&[Entry::File("Textures/Armor/Plate.dds", b"DDS texture"), Entry::File("Fixture.esp", b"TES4 plugin")]));
        assert!(matches!(f.install().unwrap(), super::InstallOutcome::Installed(2)));
        assert_eq!(std::fs::read(f.mod_dir().join("textures/armor/Plate.dds")).unwrap(), b"DDS texture");
        assert_eq!(std::fs::read(f.mod_dir().join("Fixture.esp")).unwrap(), b"TES4 plugin");
        f.assert_clean();
        let receipts = f.receipts();
        assert_eq!(receipts.len(), 1);
        let r = &receipts[0];
        assert_eq!((r["version"].as_u64(), r["decision"].as_str(), r["key"].as_str()), (Some(1), Some("admitted"), Some("fixture")));
        assert!(r["confinement"].as_str().unwrap().starts_with("landlock-abi-"));
        assert_eq!(r["archives"][0]["approved_sha256"], r["archives"][0]["observed_sha256"]);
        assert_eq!((r["archives"][0]["provenance"].as_str(), r["archives"][0]["confidence"].as_str()), (Some("sha256-pinned"), Some("publisher-digest")));
        assert_eq!((r["plan"]["files"].as_u64(), r["plan"]["bytes"].as_u64()), (Some(2), Some(22)));
        assert_eq!(r["plan"]["sha256"].as_str(), f.state.installs["fixture"].plan_sha256.as_deref());
        assert_eq!((r["activation"]["method"].as_str(), r["activation"]["replaced_existing"].as_bool()), (Some("rename"), Some(false)));
        assert!(r.get("refusal").is_none() && r["executables"].as_array().unwrap().is_empty());
        // A receipt never carries the download location or anything signed into it.
        let text = serde_json::to_string(r).unwrap();
        assert!(!text.contains("token") && !text.contains("https://"), "{text}");
        // An unchanged entry is skipped before admission and leaves no further receipt.
        assert!(matches!(f.install().unwrap(), super::InstallOutcome::Unchanged));
        assert_eq!(f.receipts().len(), 1);
    }

    #[test]
    fn changed_archive_bytes_are_refused_and_the_installed_mod_is_kept() {
        use std::os::unix::fs::MetadataExt;
        let mut f = Fixture::new(&tar(&[Entry::File("Fixture.esp", b"approved")]));
        f.install().unwrap();
        let installed = f.mod_dir().join("Fixture.esp");
        let inode = std::fs::metadata(&installed).unwrap().ino();
        // Different bytes appear under the approved name. The lock still approves the old ones.
        f.place(&tar(&[Entry::File("Fixture.esp", b"substituted")]));
        f.entry.exclude = vec!["nothing".into()];
        assert_eq!(f.refused(), RefusalCode::DigestMismatch);
        assert_eq!(std::fs::read(&installed).unwrap(), b"approved");
        assert_eq!(std::fs::metadata(&installed).unwrap().ino(), inode);
        f.assert_clean();
        let receipts = f.receipts();
        let r = receipts.last().unwrap();
        assert_eq!((r["decision"].as_str(), r["refusal"]["code"].as_str()), (Some("refused"), Some("digest-mismatch")));
        let substituted = hex::encode(super::Sha256::digest(tar(&[Entry::File("Fixture.esp", b"substituted")])));
        assert_eq!(r["archives"][0]["observed_sha256"].as_str(), Some(substituted.as_str()));
        assert_ne!(r["archives"][0]["approved_sha256"].as_str(), Some(substituted.as_str()));
        assert!(r.get("plan").is_none() && r.get("activation").is_none());
        // Approving the new bytes in the lock is what lets them in.
        f.approve(&tar(&[Entry::File("Fixture.esp", b"substituted")]));
        assert!(matches!(f.install().unwrap(), super::InstallOutcome::Installed(1)));
        assert_eq!(std::fs::read(&installed).unwrap(), b"substituted");
        assert_eq!(f.receipts().last().unwrap()["activation"]["method"].as_str(), Some("exchange"));
        f.assert_clean();
    }

    #[test]
    fn links_and_special_entries_are_refused() {
        // A directory next to staging that the last archive tries to write through a link:
        // staging is <workspace>/staging/<key>/a0, so three levels up is the workspace.
        let target = "../../../victim";
        // With the pinned tools: 7zz restores the first link and the hard link; it refuses the
        // upward link, and unar then creates it. Inspection refuses all three. Neither tool
        // will write through the last link, so that archive is unreadable.
        let cases: Vec<(Vec<Entry>, RefusalCode)> = vec![
            (vec![Entry::File("Fixture.esp", b"x"), Entry::Symlink("link", "/etc/hostname")], RefusalCode::UnsupportedEntry),
            (vec![Entry::File("Fixture.esp", b"x"), Entry::Symlink("up", "../../../outside")], RefusalCode::UnsupportedEntry),
            (vec![Entry::File("Fixture.esp", b"x"), Entry::Hardlink("Copy.esp", "Fixture.esp")], RefusalCode::UnsupportedEntry),
            (vec![Entry::Symlink("d", target), Entry::File("d/pwned.txt", b"pwned")], RefusalCode::ExtractionFailed),
        ];
        for (entries, expected) in &cases {
            let mut f = Fixture::new(&tar(entries));
            let victim = f.cfg.workspace.join("victim");
            std::fs::create_dir(&victim).unwrap();
            assert_eq!(f.refused(), *expected);
            assert!(!f.mod_dir().exists());
            f.assert_clean();
            assert_eq!(f.receipts()[0]["decision"].as_str(), Some("refused"));
            assert_eq!(std::fs::read_dir(&victim).unwrap().count(), 0, "an archive link must not carry a write outside staging");
        }
    }

    #[test]
    fn traversal_and_absolute_names_stay_inside_the_mod_folder() {
        let absolute = format!("/tmp/skyforge-absolute-{}.txt", std::process::id());
        let mut f = Fixture::new(&tar(&[Entry::File("../../../../traversal.txt", b"x"), Entry::File(&absolute, b"x"), Entry::File("Fixture.esp", b"x")]));
        let workspace = f.cfg.workspace.clone();
        // The pinned 7zz strips the upward and leading parts of these names, so the archive
        // installs and everything it produced is below the mod folder.
        assert!(matches!(f.install().unwrap(), super::InstallOutcome::Installed(3)));
        assert!(f.mod_dir().join("traversal.txt").is_file() && f.mod_dir().join("Fixture.esp").is_file());
        for entry in walkdir::WalkDir::new(f.cfg.mods_dir()).into_iter().flatten() {
            assert!(entry.path().starts_with(f.mod_dir()) || entry.path() == f.cfg.mods_dir());
        }
        f.assert_clean();
        assert!(!std::path::Path::new(&absolute).exists(), "the absolute name was written to");
        for up in workspace.ancestors().skip(1).take(4) {
            assert!(!up.join("traversal.txt").exists(), "escaped to {}", up.display());
        }
    }

    fn fomod(file_rule: &str) -> String {
        format!(r#"<config><moduleName>Fixture</moduleName><requiredInstallFiles>{file_rule}</requiredInstallFiles></config>"#)
    }

    #[test]
    fn fomod_rules_cannot_reach_outside_the_archive_or_the_mod_folder() {
        // A file the installer could read and move if a rule were followed out of staging.
        let outside = scratch("fomod-victim");
        let victim = outside.join("save.ess");
        let up = "..\\".repeat(12);
        let cases = [
            // The source climbs out of the archive to an owner file.
            format!(r#"<file source="{up}{}" destination="stolen.ess"/>"#, victim.display().to_string().trim_start_matches('/').replace('/', "\\")),
            r#"<folder source="..\..\..\..\mo2" destination="copied"/>"#.to_string(),
            // The destination climbs out of the mod folder.
            r#"<file source="Fixture.esp" destination="..\..\..\escaped.esp"/>"#.to_string(),
            r#"<file source="Fixture.esp" destination="textures\..\..\..\escaped.esp"/>"#.to_string(),
            // Names that Windows resolves differently.
            r#"<file source="Fixture.esp" destination="Fixture.esp:stream"/>"#.to_string(),
            r#"<file source="Fixture.esp" destination="NUL.esp"/>"#.to_string(),
        ];
        for rule in &cases {
            std::fs::write(&victim, b"owner save").unwrap();
            let xml = fomod(rule);
            let mut f = Fixture::new(&tar(&[Entry::File("Fixture.esp", b"x"), Entry::File("fomod/ModuleConfig.xml", xml.as_bytes())]));
            assert_eq!(f.refused(), RefusalCode::UnsafePath, "{rule}");
            assert!(!f.mod_dir().exists(), "{rule}");
            f.assert_clean();
            assert_eq!(std::fs::read(&victim).unwrap(), b"owner save", "{rule}");
            assert!(!f.cfg.workspace.join("escaped.esp").exists() && !f.cfg.mo2_instance.join("escaped.esp").exists(), "{rule}");
            assert_eq!(f.receipts()[0]["refusal"]["code"].as_str(), Some("unsafe-path"));
        }
        // An ordinary rule still installs, with the rename it asks for.
        let xml = fomod(r#"<file source="Fixture.esp" destination="Renamed.esp"/>"#);
        let mut f = Fixture::new(&tar(&[Entry::File("Fixture.esp", b"x"), Entry::File("fomod/ModuleConfig.xml", xml.as_bytes())]));
        assert!(matches!(f.install().unwrap(), super::InstallOutcome::Installed(1)));
        assert!(f.mod_dir().join("Renamed.esp").is_file());
        // A manifest root may not climb out either.
        let mut f = Fixture::new(&tar(&[Entry::File("Fixture.esp", b"x")]));
        f.entry.root = Some("../../..".into());
        assert_eq!(f.refused(), RefusalCode::UnsafePath);
        std::fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn unrecognized_content_needs_the_entry_to_name_its_type() {
        let archive = tar(&[Entry::File("Fixture.esp", b"x"), Entry::File("SKSE/Plugins/signing.pem", b"-----BEGIN"), Entry::File("docs/README", b"read me")]);
        let mut f = Fixture::new(&archive);
        assert_eq!(f.refused(), RefusalCode::UnrecognizedContent);
        assert!(!f.mod_dir().exists());
        f.assert_clean();
        assert_eq!(f.receipts()[0]["refusal"]["code"].as_str(), Some("unrecognized-content"));
        // The owner can drop the file or accept its type for this entry.
        f.entry.exclude = vec!["*.pem".into()];
        assert!(matches!(f.install().unwrap(), super::InstallOutcome::Installed(2)));
        let mut f = Fixture::new(&archive);
        f.entry.extra_types = vec!["pem".into()];
        assert!(matches!(f.install().unwrap(), super::InstallOutcome::Installed(3)));
        assert_eq!(f.receipts()[0]["allowed_extra_types"][0].as_str(), Some("pem"));
    }

    #[test]
    fn a_fomod_rename_cannot_hide_an_executable_class() {
        // The destination name decides the class, so a rule cannot rename code into place unseen.
        let xml = fomod(r#"<file source="readme.txt" destination="SKSE\Plugins\Loader.dll"/>"#);
        let mut f = Fixture::new(&tar(&[Entry::File("readme.txt", b"MZ\x90\0 code"), Entry::File("fomod/ModuleConfig.xml", xml.as_bytes())]));
        assert_eq!(f.refused(), RefusalCode::UnexpectedExecutable);
        assert_eq!(f.receipts()[0]["executables"][0]["class"].as_str(), Some("skse-plugin"));
    }

    #[test]
    fn a_pipe_entry_never_reaches_the_mod_folder_as_a_pipe() {
        let mut f = Fixture::new(&tar(&[Entry::File("Fixture.esp", b"x"), Entry::Fifo("textures/pipe.dds")]));
        // The pinned 7zz writes a pipe entry as an empty regular file; the sandbox would
        // refuse a real one and inspection would refuse it again.
        assert!(matches!(f.install().unwrap(), super::InstallOutcome::Installed(2)));
        for entry in walkdir::WalkDir::new(f.mod_dir()).into_iter().flatten() {
            let kind = std::fs::symlink_metadata(entry.path()).unwrap().file_type();
            assert!(kind.is_dir() || kind.is_file(), "{}", entry.path().display());
        }
        assert_eq!(std::fs::metadata(f.mod_dir().join("textures/pipe.dds")).unwrap().len(), 0);
        f.assert_clean();
    }

    #[test]
    fn two_different_files_behind_one_caseless_path_are_refused() {
        let mut f = Fixture::new(&tar(&[Entry::File("Meshes/Thing.nif", b"one"), Entry::File("meshes/thing.nif", b"two")]));
        assert_eq!(f.refused(), RefusalCode::AmbiguousPath);
        assert!(!f.mod_dir().exists());
        f.assert_clean();
        // Directory case variants holding the same bytes are one file, as on Windows.
        let mut f = Fixture::new(&tar(&[Entry::File("Meshes/Thing.nif", b"same"), Entry::File("meshes/thing.nif", b"same"), Entry::File("Meshes/Other.nif", b"other")]));
        assert!(matches!(f.install().unwrap(), super::InstallOutcome::Installed(2)));
    }

    #[test]
    fn archives_beyond_the_limits_are_refused() {
        let big = vec![0u8; 300_000];
        let many: Vec<String> = (0..6).map(|i| format!("textures/{i}.dds")).collect();
        let many: Vec<Entry> = many.iter().map(|n| Entry::File(n, b"x")).collect();
        type Tighten = fn(&mut super::admission::Limits);
        let cases: Vec<(Vec<u8>, Tighten)> = vec![
            (tar(&many), |l| l.max_entries = 4),
            (tar(&[Entry::File("a.bsa", &big), Entry::File("b.bsa", &big)]), |l| l.max_total_bytes = 500_000),
            (tar(&[Entry::File("a.bsa", &big)]), |l| l.max_file_bytes = 100_000),
            (tar(&[Entry::File("a/b/c/d/e/f.txt", b"x")]), |l| l.max_depth = 3),
            (tar(&[Entry::File("Fixture.esp", b"x")]), |l| l.reserve_bytes = u64::MAX),
        ];
        for (archive, tighten) in cases {
            let mut f = Fixture::new(&archive);
            tighten(&mut f.cfg.admission.limits);
            assert_eq!(f.refused(), RefusalCode::LimitExceeded);
            assert!(!f.mod_dir().exists());
            f.assert_clean();
            assert_eq!(f.receipts()[0]["refusal"]["code"].as_str(), Some("limit-exceeded"));
        }
    }

    #[test]
    fn executables_need_the_entry_to_allow_their_class() {
        let archive = tar(&[Entry::File("SKSE/Plugins/Thing.dll", b"MZ\x90\0 native code"), Entry::File("Fixture.esp", b"x")]);
        let mut f = Fixture::new(&archive);
        assert_eq!(f.refused(), RefusalCode::UnexpectedExecutable);
        assert!(!f.mod_dir().exists());
        f.assert_clean();
        let refused = f.receipts();
        assert_eq!(refused[0]["executables"][0]["class"].as_str(), Some("skse-plugin"));
        f.entry.executables = vec![ExecClass::SksePlugin];
        assert!(matches!(f.install().unwrap(), super::InstallOutcome::Installed(2)));
        let receipts = f.receipts();
        let r = receipts.last().unwrap();
        assert_eq!(r["executables"][0]["path"].as_str(), Some("skse/plugins/Thing.dll"));
        assert_eq!(r["executables"][0]["sha256"].as_str().unwrap(), hex::encode(super::Sha256::digest(b"MZ\x90\0 native code")));
        assert_eq!(r["allowed_executables"][0].as_str(), Some("skse-plugin"));
        // Executable bytes behind a data extension are refused whatever the entry allows.
        let mut f = Fixture::new(&tar(&[Entry::File("textures/Plate.dds", b"MZ\x90\0 not a texture")]));
        f.entry.executables = vec![ExecClass::SksePlugin, ExecClass::NativeLibrary, ExecClass::Program, ExecClass::Script];
        assert_eq!(f.refused(), RefusalCode::UnexpectedExecutable);
        assert!(!f.mod_dir().exists());
    }

    #[test]
    fn an_interrupted_extraction_is_cleared_and_the_installed_mod_is_kept() {
        use std::os::unix::fs::PermissionsExt;
        let mut f = Fixture::new(&tar(&[Entry::File("Fixture.esp", b"known good")]));
        f.install().unwrap();
        // An extractor that writes part of its output and then never finishes.
        let tools = f.cfg.workspace.join("tools");
        std::fs::create_dir_all(&tools).unwrap();
        let script = "#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in -o*) out=\"${a#-o}\";; esac; done\necho partial > \"$out/partial.bin\"\nexec sleep 30\n";
        std::fs::write(tools.join("7zz"), script).unwrap();
        std::fs::set_permissions(tools.join("7zz"), std::fs::Permissions::from_mode(0o755)).unwrap();
        f.cfg.tools_bin = tools;
        f.cfg.admission.limits.wall_seconds = 1;
        f.approve(&tar(&[Entry::File("Fixture.esp", b"next version")]));
        assert_eq!(f.refused(), RefusalCode::LimitExceeded);
        assert_eq!(std::fs::read(f.mod_dir().join("Fixture.esp")).unwrap(), b"known good");
        f.assert_clean();
        assert_eq!(f.receipts().last().unwrap()["refusal"]["code"].as_str(), Some("limit-exceeded"));
    }

    #[test]
    fn leftovers_of_an_interrupted_run_are_recovered_before_installing() {
        use std::os::unix::fs::PermissionsExt;
        let mut f = Fixture::new(&tar(&[Entry::File("Fixture.esp", b"one")]));
        f.install().unwrap();
        // The process died mid-extraction and mid-replacement: partial staging the owner
        // cannot enter, an incomplete new folder, and the old folder moved aside.
        let staging = f.cfg.staging.join("fixture/a0/locked");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("partial.bin"), b"partial").unwrap();
        std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o000)).unwrap();
        let mods = f.cfg.mods_dir();
        std::fs::create_dir_all(mods.join(".Fixture mod.skyforge-new")).unwrap();
        std::fs::write(mods.join(".Fixture mod.skyforge-new/Fixture.esp"), b"incomplete").unwrap();
        std::fs::rename(f.mod_dir(), mods.join(".Fixture mod.skyforge-old")).unwrap();
        // The unchanged entry gets its known-good folder back without reinstalling.
        assert!(matches!(f.install().unwrap(), super::InstallOutcome::Unchanged));
        assert_eq!(std::fs::read(f.mod_dir().join("Fixture.esp")).unwrap(), b"one");
        // The next real install clears the stale staging and completes.
        f.approve(&tar(&[Entry::File("Fixture.esp", b"two")]));
        assert!(matches!(f.install().unwrap(), super::InstallOutcome::Installed(1)));
        assert_eq!(std::fs::read(f.mod_dir().join("Fixture.esp")).unwrap(), b"two");
        f.assert_clean();
    }

    #[test]
    fn unsafe_keys_names_and_archive_locations_are_refused_before_any_write() {
        let archive = tar(&[Entry::File("Fixture.esp", b"x")]);
        let mut f = Fixture::new(&archive);
        f.entry.key = "../escape".into();
        assert_eq!(f.refused(), RefusalCode::UnapprovedIdentity);
        assert!(!f.cfg.workspace.join("escape").exists() && !f.cfg.workspace.join("admission").exists());
        let mut f = Fixture::new(&archive);
        f.entry.name = ".hidden".into();
        assert!(f.install().is_err() && std::fs::read_dir(f.cfg.mods_dir()).unwrap().count() == 0);
        let mut f = Fixture::new(&archive);
        f.files[0].file_name = Some("../downloads/fixture.tar".into());
        assert_eq!(f.refused(), RefusalCode::UnapprovedIdentity);
        let mut f = Fixture::new(&archive);
        f.files[0].sha256 = None;
        assert_eq!(f.refused(), RefusalCode::UnapprovedIdentity);
        assert!(!f.mod_dir().exists());
    }

    #[test]
    fn a_receipt_names_local_directories_by_role_only() {
        use std::os::unix::fs::PermissionsExt;
        // An owner-placed local source: its lock entry carries the full path.
        let archive = tar(&[Entry::File("Fixture.esp", b"x")]);
        let mut f = Fixture::new(&archive);
        let local = f.cfg.workspace.join("generated/output.tar");
        std::fs::create_dir_all(local.parent().unwrap()).unwrap();
        std::fs::write(&local, &archive).unwrap();
        let path = local.to_string_lossy().into_owned();
        f.files[0] = super::LockedFile { source: "local".into(), display_name: path.clone(), file_name: Some(path), verified_by: Some("local-hash-recorded".into()), ..f.files[0].clone() };
        f.install().unwrap();
        // A refusal whose detail would name the staging root.
        std::fs::set_permissions(&f.cfg.staging, std::fs::Permissions::from_mode(0o777)).unwrap();
        f.approve(&tar(&[Entry::File("Fixture.esp", b"y")]));
        assert_eq!(f.refused(), RefusalCode::StagingNotOwned);
        let receipts = f.receipts();
        assert_eq!(receipts.len(), 2, "a refusal before staging exists still leaves a receipt");
        assert_eq!((receipts[0]["archives"][0]["name"].as_str(), receipts[0]["archives"][0]["file_name"].as_str()), (Some("output.tar"), Some("output.tar")));
        assert_eq!(receipts[1]["refusal"]["code"].as_str(), Some("staging-not-owned"));
        assert!(receipts[1]["refusal"]["detail"].as_str().unwrap().contains("<staging>"));
        let workspace = f.cfg.workspace.to_string_lossy().into_owned();
        for receipt in &receipts {
            let text = serde_json::to_string(receipt).unwrap();
            assert!(!text.contains(&workspace) && !text.contains("/test-output/"), "{text}");
        }
    }

    #[test]
    fn a_folder_skyforge_did_not_install_is_not_replaced() {
        let mut f = Fixture::new(&tar(&[Entry::File("Fixture.esp", b"from the archive")]));
        std::fs::create_dir_all(f.mod_dir()).unwrap();
        std::fs::write(f.mod_dir().join("Fixture.esp"), b"owner's own folder").unwrap();
        assert!(f.install().err().unwrap().to_string().contains("not managed by skyforge"));
        assert_eq!(std::fs::read(f.mod_dir().join("Fixture.esp")).unwrap(), b"owner's own folder");
        f.assert_clean();
    }

    #[test]
    fn a_game_root_install_is_verified_backed_up_and_journaled() {
        let mut f = Fixture::new(&tar(&[Entry::File("d3dx9_42.dll", b"MZ\x90\0 new loader"), Entry::File("Data/SKSE/Plugins/Thing.dll", b"MZ\x90\0 plugin")]));
        f.entry = serde_json::from_value(serde_json::json!({"key": "fixture", "name": "Fixture root", "status": "SELECTED", "target": "game-root"})).unwrap();
        std::fs::create_dir_all(&f.cfg.stock_game).unwrap();
        std::fs::write(f.cfg.stock_game.join("SkyrimSE.exe"), b"game").unwrap();
        std::fs::write(f.cfg.stock_game.join("d3dx9_42.dll"), b"old loader").unwrap();
        // Undeclared executables never reach the game root.
        assert_eq!(f.refused(), RefusalCode::UnexpectedExecutable);
        assert_eq!(std::fs::read(f.cfg.stock_game.join("d3dx9_42.dll")).unwrap(), b"old loader");
        assert!(!f.cfg.workspace.join("backups").exists());
        f.entry.executables = vec![ExecClass::NativeLibrary, ExecClass::SksePlugin];
        assert!(matches!(f.install().unwrap(), super::InstallOutcome::Installed(2)));
        assert_eq!(std::fs::read(f.cfg.stock_game.join("d3dx9_42.dll")).unwrap(), b"MZ\x90\0 new loader");
        assert_eq!(std::fs::read(f.cfg.stock_game.join("Data/SKSE/Plugins/Thing.dll")).unwrap(), b"MZ\x90\0 plugin");
        let runs: Vec<_> = std::fs::read_dir(f.cfg.workspace.join("backups/game-root/fixture")).unwrap().flatten().map(|e| e.path()).collect();
        assert_eq!(runs.len(), 1);
        assert_eq!(std::fs::read(runs[0].join("d3dx9_42.dll")).unwrap(), b"old loader");
        let journal: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(runs[0].join("journal.json")).unwrap()).unwrap();
        assert!(journal["completed_at"].is_string() && journal["files"].as_array().unwrap().len() == 2);
        assert_eq!(f.state.installs["fixture"].backups, vec!["d3dx9_42.dll".to_string()]);
        let receipts = f.receipts();
        let r = receipts.last().unwrap();
        assert_eq!((r["activation"]["method"].as_str(), r["activation"]["replaced_existing"].as_bool()), (Some("game-root"), Some(true)));
        assert_eq!(r["executables"].as_array().unwrap().len(), 2);
        assert!(!f.cfg.stock_game.join(".d3dx9_42.dll.skyforge-new").exists());
        f.assert_clean();
    }

    fn root_names(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = walkdir::WalkDir::new(dir).min_depth(1).into_iter().flatten().filter(|e| e.file_type().is_file()).map(|e| e.path().strip_prefix(dir).unwrap().to_string_lossy().into_owned()).collect();
        names.sort();
        names
    }

    fn game_root_fixture() -> Fixture {
        let mut f = Fixture::new(&tar(&[Entry::File("a_first.dll", b"MZ\x90\0 new a"), Entry::File("b_second.dll", b"MZ\x90\0 new b"), Entry::File("c_third.dll", b"MZ\x90\0 new c")]));
        f.entry = serde_json::from_value(serde_json::json!({"key": "fixture", "name": "Fixture root", "status": "SELECTED", "target": "game-root", "executables": ["native-library"]})).unwrap();
        std::fs::create_dir_all(&f.cfg.stock_game).unwrap();
        for (name, bytes) in [("SkyrimSE.exe", "game"), ("a_first.dll", "old a"), ("b_second.dll", "old b")] {
            std::fs::write(f.cfg.stock_game.join(name), bytes).unwrap();
        }
        f
    }

    #[test]
    fn a_game_root_install_that_fails_midway_leaves_the_old_files() {
        // Every position: before the first switch, between files, before the last.
        for at in 0..3 {
            let mut f = game_root_fixture();
            let before = root_names(&f.cfg.stock_game);
            FAIL_AT.with(|cell| cell.set(Some(at)));
            let error = f.install().err().unwrap().to_string();
            FAIL_AT.with(|cell| cell.set(None));
            assert!(error.contains("injected failure"), "{error}");
            assert_eq!(root_names(&f.cfg.stock_game), before, "failure after {at} files");
            assert_eq!(std::fs::read(f.cfg.stock_game.join("a_first.dll")).unwrap(), b"old a");
            assert_eq!(std::fs::read(f.cfg.stock_game.join("b_second.dll")).unwrap(), b"old b");
            assert!(!f.cfg.stock_game.join("c_third.dll").exists());
            assert!(f.state.installs.is_empty());
            let receipts = f.receipts();
            let r = receipts.last().unwrap();
            assert_eq!((r["decision"].as_str(), r["refusal"]["code"].as_str()), (Some("refused"), Some("error")));
            let run = std::fs::read_dir(f.cfg.workspace.join("backups/game-root/fixture")).unwrap().flatten().next().unwrap().path();
            let journal: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(run.join("journal.json")).unwrap()).unwrap();
            assert!(journal["rolled_back_at"].is_string() && journal.get("completed_at").is_none());
            // The same install then completes normally.
            std::thread::sleep(std::time::Duration::from_millis(1100));
            assert!(matches!(f.install().unwrap(), super::InstallOutcome::Installed(3)));
            assert_eq!(std::fs::read(f.cfg.stock_game.join("c_third.dll")).unwrap(), b"MZ\x90\0 new c");
        }
    }

    #[test]
    fn a_cut_off_game_root_install_is_never_reported_unchanged() {
        let mut f = game_root_fixture();
        f.install().unwrap();
        assert!(matches!(f.install().unwrap(), super::InstallOutcome::Unchanged));
        // A later run was cut off after its first file: its journal has no end and one
        // file holds bytes no record describes.
        let cut = f.cfg.workspace.join("backups/game-root/fixture/99991231-235959");
        std::fs::create_dir_all(&cut).unwrap();
        std::fs::write(cut.join("journal.json"), r#"{"version":1,"key":"fixture","started_at":"x","files":["a_first.dll"]}"#).unwrap();
        std::fs::write(f.cfg.stock_game.join("a_first.dll"), b"MZ half written by the cut-off run").unwrap();
        // The unchanged entry is not skipped: the planned bytes are installed again.
        assert!(matches!(f.install().unwrap(), super::InstallOutcome::Installed(3)));
        assert_eq!(std::fs::read(f.cfg.stock_game.join("a_first.dll")).unwrap(), b"MZ\x90\0 new a");
    }

    #[test]
    fn a_game_root_path_through_a_link_is_refused_before_any_write() {
        let outside = scratch("root-link");
        let mut f = Fixture::new(&tar(&[Entry::File("Data/SKSE/Plugins/Thing.dll", b"MZ\x90\0 plugin")]));
        f.entry = serde_json::from_value(serde_json::json!({"key": "fixture", "name": "Fixture root", "status": "SELECTED", "target": "game-root", "executables": ["skse-plugin"]})).unwrap();
        std::fs::create_dir_all(&f.cfg.stock_game).unwrap();
        std::fs::write(f.cfg.stock_game.join("SkyrimSE.exe"), b"game").unwrap();
        std::os::unix::fs::symlink(&outside, f.cfg.stock_game.join("Data")).unwrap();
        assert!(f.install().err().unwrap().to_string().contains("not a plain file or directory"));
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
        assert!(!f.cfg.workspace.join("backups").exists());
        std::fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn written_receipts_follow_the_published_contract() {
        let schema: serde_json::Value = serde_json::from_str(include_str!("../../../contracts/admission-receipt-v1.schema.json")).unwrap();
        let fixtures: serde_json::Value = serde_json::from_str(include_str!("../../../contracts/fixtures/admission-receipts.json")).unwrap();
        for (name, fixture) in fixtures.as_object().unwrap() {
            conforms(&schema, &schema, fixture).unwrap_or_else(|e| panic!("fixture {name}: {e}"));
        }
        let mut unknown = fixtures["admitted"].clone();
        unknown["archives"][0]["url"] = "https://downloads.invalid/a".into();
        assert!(conforms(&schema, &schema, &unknown).is_err());
        let mut silent = fixtures["refused"].clone();
        silent.as_object_mut().unwrap().remove("refusal");
        assert!(conforms(&schema, &schema, &silent).is_err());

        // Admitted with an executable, refused for other bytes, and requalified unchanged.
        let mut f = Fixture::new(&tar(&[Entry::File("SKSE/Plugins/Thing.dll", b"MZ\x90\0 code"), Entry::File("Fixture.esp", b"x")]));
        f.entry.executables = vec![ExecClass::SksePlugin];
        f.install().unwrap();
        f.state.installs.get_mut("fixture").unwrap().fomod_contexts = None;
        assert!(matches!(f.install().unwrap(), super::InstallOutcome::Unchanged));
        f.place(&tar(&[Entry::File("Fixture.esp", b"other bytes")]));
        f.entry.exclude = vec!["nothing".into()];
        assert_eq!(f.refused(), RefusalCode::DigestMismatch);
        let receipts = f.receipts();
        let decisions: Vec<_> = receipts.iter().map(|r| r["decision"].as_str().unwrap().to_owned()).collect();
        assert_eq!(decisions, ["admitted", "unchanged", "refused"]);
        for receipt in &receipts {
            conforms(&schema, &schema, receipt).unwrap_or_else(|e| panic!("{}: {e}\n{receipt:#}", receipt["decision"]));
        }
    }
}
