//! The mod manifest: every approved candidate, its decision, source and install rules.
//!
//! Manifest order is MO2 priority order: the first entry has the lowest priority
//! (its files lose conflicts), the last entry wins.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    /// Mandatory for the build (framework, dependency, core AI).
    Required,
    /// Chosen for the build.
    Selected,
    /// Installable but disabled by default.
    Optional,
    /// Documented alternative to a selected entry; not installed.
    Alternative,
    /// Functionality already provided by another entry; not installed.
    Superseded,
    /// Conflicts with the selected build; not installed.
    Incompatible,
    /// Cannot be obtained or installed for an external reason.
    Blocked,
    /// Attempted and failed; kept for evidence.
    Failed,
}

impl Status {
    pub fn installs(self) -> bool {
        matches!(self, Status::Required | Status::Selected | Status::Optional)
    }
    pub fn enabled_by_default(self) -> bool {
        matches!(self, Status::Required | Status::Selected)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Source {
    /// A Nexus Mods file (or several) of one mod page.
    Nexus { mod_id: u64, files: Vec<u64> },
    /// A direct HTTPS download with a pinned SHA-256.
    Url { url: String, sha256: String, file_name: String },
    /// A GitHub release asset; sha256 comes from GitHub's published asset digest when available.
    Github {
        repo: String,
        tag: String,
        asset: String,
        #[serde(default)]
        sha256: Option<String>,
    },
    /// A file the owner placed manually (e.g. generated output, depot content).
    Local { path: String },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Target {
    /// Installed as an MO2 mod folder (the default).
    #[default]
    Mods,
    /// Installed into the Stock Game root (SKSE loader, preloader DLLs).
    GameRoot,
    /// Not installed by skyforge (tools, server-side components, notes).
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModEntry {
    /// Stable unique slug.
    pub key: String,
    /// MO2 mod folder / display name.
    pub name: String,
    #[serde(default)]
    pub section: String,
    pub status: Status,
    /// Implementation phase (1 foundation ... 7 final generation).
    #[serde(default)]
    pub phase: u8,
    #[serde(default)]
    pub source: Option<Source>,
    #[serde(default)]
    pub target: Target,
    /// Sub-directory inside the archive to treat as the Data root (non-FOMOD archives).
    #[serde(default)]
    pub root: Option<String>,
    /// FOMOD choices: "Step name/Group name" (or just "Group name") -> option names.
    #[serde(default)]
    pub fomod: Option<BTreeMap<String, Vec<String>>>,
    /// Only install paths matching one of these (case-insensitive glob, relative to the Data root).
    #[serde(default)]
    pub include: Vec<String>,
    /// Drop paths matching one of these.
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Plugins this entry is expected to provide (validated after install).
    #[serde(default)]
    pub plugins: Vec<String>,
    /// Keys of entries this one depends on.
    #[serde(default)]
    pub requires: Vec<String>,
    /// MO2 separator placed above this entry.
    #[serde(default)]
    pub separator: Option<String>,
    /// Upstream URL (authoritative page) for provenance.
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
    /// Decision rationale / evidence notes.
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub game_domain: String,
    pub game_id: u64,
    pub runtime: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub meta: Meta,
    #[serde(default, rename = "mod")]
    pub mods: Vec<ModEntry>,
}

impl Manifest {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading manifest {}", path.display()))?;
        let m: Manifest = toml::from_str(&text).context("parsing manifest")?;
        m.validate()?;
        Ok(m)
    }

    fn validate(&self) -> Result<()> {
        let mut keys = HashSet::new();
        let mut names = HashSet::new();
        for e in &self.mods {
            if !keys.insert(e.key.as_str()) {
                bail!("duplicate manifest key {}", e.key);
            }
            if e.target == Target::Mods && e.status.installs() && !names.insert(e.name.to_lowercase()) {
                bail!("duplicate MO2 mod name {}", e.name);
            }
            if e.name.contains(['/', '\\', ':', '*', '?', '"', '<', '>', '|']) {
                bail!("mod name {} contains characters MO2 cannot use", e.name);
            }
        }
        for e in &self.mods {
            for r in &e.requires {
                if !keys.contains(r.as_str()) {
                    bail!("{} requires unknown key {}", e.key, r);
                }
            }
            if e.status.installs() {
                for r in &e.requires {
                    let dep = self.get(r).unwrap();
                    if !dep.status.installs() {
                        bail!("{} ({:?}) requires {} which is {:?}", e.key, e.status, r, dep.status);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn get(&self, key: &str) -> Option<&ModEntry> {
        self.mods.iter().find(|e| e.key == key)
    }

    /// Entries filtered by an optional key list and maximum phase.
    pub fn select<'a>(&'a self, keys: &[String], max_phase: Option<u8>) -> Vec<&'a ModEntry> {
        self.mods
            .iter()
            .filter(|e| keys.is_empty() || keys.iter().any(|k| k == &e.key))
            .filter(|e| max_phase.map_or(true, |p| e.phase <= p))
            .collect()
    }
}
