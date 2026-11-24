//! Lockfile: exact, resolved sources for every installable manifest entry,
//! plus integrity data recorded when a download is verified.

use crate::manifest::{Manifest, Source};
use crate::nexus::{FileInfo, Nexus};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LockedFile {
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mod_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_id: Option<u64>,
    /// Display name of the file on its source page.
    pub display_name: String,
    /// Local archive file name inside the downloads directory (set at fetch time for Nexus).
    #[serde(default)]
    pub file_name: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub uploaded: Option<i64>,
    #[serde(default)]
    pub size: Option<u64>,
    #[serde(default)]
    pub md5: Option<String>,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    /// How integrity was established ("nexus-md5+size", "sha256-pinned", ...).
    #[serde(default)]
    pub verified_by: Option<String>,
    #[serde(default)]
    pub verified_at: Option<String>,
    /// Directory holding the archive when it is not the primary downloads directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dir: Option<std::path::PathBuf>,
}

impl LockedFile {
    pub fn archive_path(&self, primary: &std::path::Path) -> Option<std::path::PathBuf> {
        let name = self.file_name.as_ref()?;
        Some(self.dir.clone().unwrap_or_else(|| primary.to_path_buf()).join(name))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Lockfile {
    pub generated: String,
    pub runtime: String,
    pub entries: BTreeMap<String, Vec<LockedFile>>,
}

impl Lockfile {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Lockfile::default());
        }
        let t = std::fs::read_to_string(path)?;
        serde_json::from_str(&t).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(self)? + "\n")?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

/// Resolve every installable entry's sources against live metadata.
/// Integrity fields from a previous lock are kept when the file identity is unchanged.
pub fn lock(nx: &Nexus, manifest: &Manifest, prev: &Lockfile, keys: &[String]) -> Result<(Lockfile, Vec<String>)> {
    let mut out = prev.clone();
    out.generated = chrono::Local::now().to_rfc3339();
    out.runtime = manifest.meta.runtime.clone();
    let mut problems = Vec::new();
    let mut cache: HashMap<u64, Vec<FileInfo>> = HashMap::new();

    for e in manifest.select(keys, None) {
        if !e.status.installs() {
            out.entries.remove(&e.key);
            continue;
        }
        let Some(src) = &e.source else { continue };
        let old: HashMap<(u64, u64), LockedFile> = prev
            .entries
            .get(&e.key)
            .map(|v| {
                v.iter()
                    .filter_map(|f| Some(((f.mod_id?, f.file_id?), f.clone())))
                    .collect()
            })
            .unwrap_or_default();
        let mut files = Vec::new();
        match src {
            Source::Nexus { mod_id, files: ids } => {
                if !cache.contains_key(mod_id) {
                    let list = nx
                        .mod_files(manifest.meta.game_id, *mod_id)
                        .with_context(|| format!("files of mod {mod_id} ({})", e.key))?;
                    cache.insert(*mod_id, list);
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
                let list = &cache[mod_id];
                if ids.is_empty() {
                    problems.push(format!("{}: no file ids pinned for mod {mod_id}", e.key));
                }
                for fid in ids {
                    match list.iter().find(|f| f.file_id == *fid) {
                        None => problems.push(format!(
                            "{}: file {fid} not listed on mod {mod_id} (removed or hidden)",
                            e.key
                        )),
                        Some(f) => {
                            if matches!(f.category.as_str(), "REMOVED" | "DELETED") {
                                problems.push(format!("{}: file {fid} is {}", e.key, f.category));
                            }
                            let mut lf = old.get(&(*mod_id, *fid)).cloned().unwrap_or_default();
                            lf.source = "nexus".into();
                            lf.mod_id = Some(*mod_id);
                            lf.file_id = Some(*fid);
                            lf.display_name = f.name.clone();
                            lf.version = f.version.clone();
                            lf.category = Some(f.category.clone());
                            lf.uploaded = Some(f.date);
                            if lf.size.is_some() && lf.size != f.size_in_bytes {
                                // Remote size changed under the same id: drop stale integrity data.
                                lf.md5 = None;
                                lf.sha256 = None;
                                lf.verified_by = None;
                                lf.verified_at = None;
                            }
                            lf.size = f.size_in_bytes;
                            files.push(lf);
                        }
                    }
                }
            }
            Source::Url { url, sha256, file_name } => {
                if sha256.len() != 64 {
                    bail!("{}: url source needs a pinned sha256", e.key);
                }
                let mut lf = prev
                    .entries
                    .get(&e.key)
                    .and_then(|v| v.first().cloned())
                    .unwrap_or_default();
                lf.source = "url".into();
                lf.display_name = file_name.clone();
                lf.file_name = Some(file_name.clone());
                lf.url = Some(url.clone());
                if lf.sha256.as_deref() != Some(sha256.as_str()) {
                    lf.verified_by = None;
                    lf.verified_at = None;
                }
                lf.sha256 = Some(sha256.to_lowercase());
                files.push(lf);
            }
            Source::Github { repo, tag, asset, sha256 } => {
                let mut lf = prev.entries.get(&e.key).and_then(|v| v.first().cloned()).unwrap_or_default();
                let (url, size, digest) = github_asset(nx, repo, tag, asset)
                    .with_context(|| format!("{}: resolving GitHub asset {repo}@{tag}/{asset}", e.key))?;
                let pinned = sha256.clone().map(|s| s.to_lowercase()).or(digest);
                if lf.url.as_deref() != Some(url.as_str()) || (pinned.is_some() && lf.sha256 != pinned) {
                    lf.verified_by = None;
                    lf.verified_at = None;
                    lf.sha256 = pinned.clone();
                }
                lf.source = "github".into();
                lf.display_name = format!("{repo}@{tag}/{asset}");
                lf.file_name = Some(asset.clone());
                lf.version = Some(tag.clone());
                lf.url = Some(url);
                lf.size = Some(size);
                if pinned.is_none() {
                    problems.push(format!("{}: GitHub publishes no digest for {asset}; will trust-on-first-use", e.key));
                }
                files.push(lf);
            }
            Source::Local { path } => {
                // The recorded hash of an owner-placed file is its approval; keep it while
                // the manifest still names the same path.
                let mut lf = prev
                    .entries
                    .get(&e.key)
                    .and_then(|v| v.first().cloned())
                    .filter(|f| f.source == "local" && f.file_name.as_deref() == Some(path.as_str()))
                    .unwrap_or_default();
                lf.source = "local".into();
                lf.display_name = path.clone();
                lf.file_name = Some(path.clone());
                files.push(lf);
            }
        }
        out.entries.insert(e.key.clone(), files);
    }
    Ok((out, problems))
}

/// Resolve a GitHub release asset: (download URL, size, sha256 from the published digest if any).
fn github_asset(nx: &Nexus, repo: &str, tag: &str, asset: &str) -> Result<(String, u64, Option<String>)> {
    let url = format!("https://api.github.com/repos/{repo}/releases/tags/{tag}");
    let resp = nx.http().get(&url).header("Accept", "application/vnd.github+json").send()?;
    if !resp.status().is_success() {
        bail!("GitHub API {} for {url}", resp.status());
    }
    let v: serde_json::Value = resp.json()?;
    let a = v["assets"]
        .as_array()
        .and_then(|arr| arr.iter().find(|a| a["name"].as_str() == Some(asset)))
        .ok_or_else(|| anyhow::anyhow!("asset {asset} not in release {tag}"))?;
    let dl = a["browser_download_url"].as_str().unwrap_or_default().to_string();
    let size = a["size"].as_u64().unwrap_or(0);
    let digest = a["digest"].as_str().and_then(|d| d.strip_prefix("sha256:")).map(|d| d.to_lowercase());
    Ok((dl, size, digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(path: &str) -> Manifest {
        toml::from_str(&format!(
            "[meta]\ngame_domain='skyrimspecialedition'\ngame_id=1704\nruntime='1.6.1170'\n\n[[mod]]\nkey='generated'\nname='Generated output'\nstatus='SELECTED'\nsource={{kind='local',path='{path}'}}\n"
        ))
        .unwrap()
    }

    #[test]
    fn relocking_keeps_the_approval_of_an_unchanged_local_path() {
        let nx = Nexus::new(None).unwrap();
        let mut prev = Lockfile::default();
        let approved = LockedFile { source: "local".into(), display_name: "out/a.7z".into(), file_name: Some("out/a.7z".into()), sha256: Some("ab".repeat(32)), verified_by: Some("local-hash-recorded".into()), ..Default::default() };
        prev.entries.insert("generated".into(), vec![approved]);
        let (same, _) = lock(&nx, &manifest("out/a.7z"), &prev, &[]).unwrap();
        assert_eq!(same.entries["generated"][0].sha256.as_deref(), Some("ab".repeat(32).as_str()));
        assert_eq!(same.entries["generated"][0].verified_by.as_deref(), Some("local-hash-recorded"));
        // A different path is a different file and starts unapproved.
        let (moved, _) = lock(&nx, &manifest("out/b.7z"), &prev, &[]).unwrap();
        assert_eq!((moved.entries["generated"][0].sha256.clone(), moved.entries["generated"][0].verified_by.clone()), (None, None));
    }
}
