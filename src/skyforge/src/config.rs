//! Workspace configuration (`skyforge.toml` at the workspace root).

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Root of the installation workspace (ledger, manifest, logs, ...).
    pub workspace: PathBuf,
    /// Mod manifest, relative to `workspace` unless absolute.
    pub manifest: PathBuf,
    /// Lockfile with resolved and verified file metadata.
    pub lockfile: PathBuf,
    /// Install-state file (what was installed where, with content hashes).
    pub state: PathBuf,
    /// Download directory (also MO2's download directory).
    pub downloads: PathBuf,
    /// Portable MO2 instance directory.
    pub mo2_instance: PathBuf,
    /// Stock Game folder the modded profile runs against.
    pub stock_game: PathBuf,
    /// MO2 profile name managed by skyforge.
    pub profile: String,
    /// Scratch space for extraction; must be on the same filesystem as `mo2_instance`.
    pub staging: PathBuf,
    /// File holding the Nexus personal API key (never logged).
    pub nexus_key_file: PathBuf,
    /// Directory containing 7zz/unar (the Nix tool environment).
    pub tools_bin: PathBuf,
    /// Second download location used when the primary would drop below `downloads_reserve_gb` free.
    #[serde(default)]
    pub downloads_overflow: Option<PathBuf>,
    /// Free space (GB) to keep on the primary download filesystem (e.g. for container storage).
    #[serde(default)]
    pub downloads_reserve_gb: Option<f64>,
    /// Archive admission limits and extractor confinement (`[admission]`).
    #[serde(default)]
    pub admission: crate::admission::Policy,
}

fn expand_home(p: &Path) -> PathBuf {
    if let Ok(rest) = p.strip_prefix("~") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    p.to_path_buf()
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let mut c: Config = toml::from_str(&text).context("parsing skyforge.toml")?;
        let ws = expand_home(&c.workspace);
        let rel = |p: &Path| -> PathBuf {
            let p = expand_home(p);
            if p.is_absolute() { p } else { ws.join(p) }
        };
        c.manifest = rel(&c.manifest);
        c.lockfile = rel(&c.lockfile);
        c.state = rel(&c.state);
        c.downloads = rel(&c.downloads);
        c.mo2_instance = rel(&c.mo2_instance);
        c.stock_game = rel(&c.stock_game);
        c.staging = rel(&c.staging);
        c.nexus_key_file = rel(&c.nexus_key_file);
        c.tools_bin = rel(&c.tools_bin);
        c.downloads_overflow = c.downloads_overflow.as_deref().map(rel);
        c.workspace = ws;
        Ok(c)
    }

    pub fn mods_dir(&self) -> PathBuf {
        self.mo2_instance.join("mods")
    }

    pub fn profile_dir(&self) -> PathBuf {
        self.mo2_instance.join("profiles").join(&self.profile)
    }

    pub fn tool(&self, name: &str) -> PathBuf {
        self.tools_bin.join(name)
    }
}

/// Free bytes on the filesystem containing `p` (statvfs via `df`, avoiding an extra crate).
pub fn free_bytes(p: &Path) -> Option<u64> {
    let out = std::process::Command::new("df").arg("--output=avail").arg("-B1").arg(p).output().ok()?;
    String::from_utf8_lossy(&out.stdout).lines().nth(1)?.trim().parse().ok()
}
