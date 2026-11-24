//! Archive admission.
//!
//! Invariant: the bytes approved in the lockfile are the bytes the extractor reads, the
//! extractor can write only inside a staging directory skyforge owns, and activation consumes
//! only staging output that passed inspection. Every decision leaves a receipt, and a refusal
//! leaves the installed mod as it was.

use crate::lock::LockedFile;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Bounds on what one archive may expand to and how long its extractor may run.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    /// Files and directories one archive may expand to.
    pub max_entries: u64,
    /// Bytes one archive may expand to.
    pub max_total_bytes: u64,
    /// Bytes of the largest single file.
    pub max_file_bytes: u64,
    /// Bytes of the longest path below the staging directory.
    pub max_path_bytes: usize,
    /// Directory depth below the staging directory.
    pub max_depth: usize,
    /// Wall-clock seconds one extractor run may take.
    pub wall_seconds: u64,
    /// Processor seconds one extractor run may use.
    pub cpu_seconds: u64,
    /// Free bytes that must remain on the staging filesystem.
    pub reserve_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_entries: 250_000,
            max_total_bytes: 64 << 30,
            max_file_bytes: 16 << 30,
            max_path_bytes: 1024,
            max_depth: 48,
            wall_seconds: 3600,
            cpu_seconds: 3600,
            reserve_bytes: 1 << 30,
        }
    }
}

/// How the extractor process is kept away from everything except its staging directory.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confinement {
    /// Linux Landlock: the extractor can write only below the staging directory.
    #[default]
    Landlock,
    /// No kernel confinement. Inspection and limits still apply.
    None,
}

/// The `[admission]` table of `skyforge.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub limits: Limits,
    pub confinement: Confinement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RefusalCode {
    /// The lockfile or manifest does not identify one approved archive.
    UnapprovedIdentity,
    /// The archive bytes differ from the approved SHA-256.
    DigestMismatch,
    /// The archive changed between verification and the end of extraction.
    ArchiveChanged,
    /// The staging root is not a directory this user alone can write.
    StagingNotOwned,
    /// The configured confinement is not available on this kernel.
    ConfinementUnavailable,
    /// No supported extractor could read the archive.
    ExtractionFailed,
    /// A count, size, time or free-space limit was reached.
    LimitExceeded,
    /// A link, device, pipe or socket, which skyforge never installs.
    UnsupportedEntry,
    /// A name that Windows and Linux read differently.
    UnsafePath,
    /// Two different files that become one path without case.
    AmbiguousPath,
    /// Executable content the manifest entry does not allow.
    UnexpectedExecutable,
    /// A file type that is neither known game data nor allowed by the manifest entry.
    UnrecognizedContent,
    /// A staged file changed between inspection and activation.
    ActivationMismatch,
    /// An operating error, not a policy decision. The detail says what failed.
    Error,
}

/// A decision not to install. It is an ordinary error with a stable code for the receipt.
#[derive(Debug)]
pub struct Refusal {
    pub code: RefusalCode,
    pub detail: String,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = serde_json::to_value(self.code)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default();
        write!(f, "admission refused ({code}): {}", self.detail)
    }
}

impl std::error::Error for Refusal {}

fn refuse<T>(code: RefusalCode, detail: impl Into<String>) -> Result<T> {
    Err(Refusal {
        code,
        detail: detail.into(),
    }
    .into())
}

/// Executable content classes a manifest entry can allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecClass {
    /// A DLL directly inside `SKSE/Plugins`, which SKSE loads into the game.
    SksePlugin,
    /// Any other native library.
    NativeLibrary,
    /// A program or installer.
    Program,
    /// A host script, shortcut or registry file.
    Script,
    /// Executable bytes behind a data extension. Never allowed.
    Disguised,
}

/// Classify one planned output by its destination name and first bytes.
pub fn classify(dest: &str, head: &[u8]) -> Option<ExecClass> {
    let lower = dest.to_lowercase().replace('\\', "/");
    let name = lower.rsplit('/').next().unwrap_or("");
    let ext = name.rsplit_once('.').map_or("", |(_, e)| e);
    let skse = ["skse/plugins/", "data/skse/plugins/"].iter().any(|p| {
        lower
            .strip_prefix(p)
            .is_some_and(|rest| !rest.contains('/'))
    });
    match ext {
        "dll" | "asi" | "ocx" | "sys" | "so" | "cpl" | "drv" | "ax" | "xll" => {
            Some(if skse && ext == "dll" {
                ExecClass::SksePlugin
            } else {
                ExecClass::NativeLibrary
            })
        }
        "exe" | "com" | "scr" | "pif" | "msi" | "msp" | "mst" | "msu" | "appx" | "msix" => {
            Some(ExecClass::Program)
        }
        // Everything a Windows or Linux desktop runs or resolves on open. A new host script
        // type belongs here; first bytes catch native code and `#!` behind other names.
        "bat" | "cmd" | "ps1" | "psm1" | "psd1" | "ps1xml" | "psc1" | "vbs" | "vbe" | "vb"
        | "js" | "jse" | "wsf" | "wsh" | "wsc" | "sct" | "hta" | "lnk" | "url" | "scf" | "reg"
        | "inf" | "jar" | "sh" | "py" | "pyw" | "msc" | "chm" | "msh" | "msh1" | "msh2"
        | "mshxml" | "settingcontent-ms" | "appref-ms" | "application" | "gadget" | "desktop"
        | "pyc" | "pyo" | "pyz" | "pyzw" | "ws" | "library-ms" | "search-ms" | "ps2" | "lua"
        | "ts" => Some(ExecClass::Script),
        _ if head.starts_with(b"MZ") || head.starts_with(b"\x7fELF") => Some(ExecClass::Disguised),
        _ if head.starts_with(b"#!") => Some(ExecClass::Script),
        _ => None,
    }
}

/// File types a Skyrim mod installs as data or documentation. Anything outside this list and
/// outside the executable classes is refused until the manifest entry names its extension,
/// so a type nobody reviewed cannot pass by being unknown.
const GAME_DATA: &[&str] = &[
    "bak",
    "bik",
    "bin",
    "bk2",
    "bmp",
    "bsa",
    "bto",
    "btr",
    "btt",
    "cfg",
    "conf",
    "css",
    "csv",
    "dat",
    "db",
    "dds",
    "dlstrings",
    "docx",
    "egm",
    "egt",
    "esl",
    "esm",
    "esp",
    "example",
    "exr",
    "fbx",
    "flac",
    "fnt",
    "fuz",
    "fx",
    "fxh",
    "gfx",
    "gif",
    "glsl",
    "h",
    "hdr",
    "hkb",
    "hkt",
    "hkx",
    "hlsl",
    "hlsli",
    "htm",
    "html",
    "ico",
    "ilstrings",
    "ini",
    "jpeg",
    "jpg",
    "json",
    "jsonc",
    "kf",
    "lip",
    "lod",
    "log",
    "lst",
    "md",
    "modgroups",
    "mp3",
    "nif",
    "obj",
    "ogg",
    "osp",
    "otf",
    "pdb",
    "pdf",
    "pdn",
    "pex",
    "placeholder",
    "png",
    "psc",
    "psd",
    "rtf",
    "seq",
    "strings",
    "svg",
    "swf",
    "tga",
    "toml",
    "tri",
    "tsv",
    "ttf",
    "txt",
    "wav",
    "webp",
    "woff",
    "woff2",
    "xcf",
    "xml",
    "xsd",
    "xwm",
    "yaml",
    "yml",
];

/// Documentation files that conventionally have no extension.
const PLAIN_NAMES: &[&str] = &[
    "authors",
    "changelog",
    "copying",
    "credits",
    "licence",
    "license",
    "notice",
    "readme",
];

fn extension(dest: &str) -> (String, String) {
    let lower = dest.to_lowercase().replace('\\', "/");
    let name = lower.rsplit('/').next().unwrap_or("").to_owned();
    let ext = name.rsplit_once('.').map_or("", |(_, e)| e).to_owned();
    (name, ext)
}

/// An extension a manifest entry may name in `extra_types`: a plain lower-case extension that
/// is not one of the executable classes, which have their own rule.
pub fn safe_type(ext: &str) -> bool {
    !ext.is_empty()
        && ext.len() <= 32
        && ext
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
        && classify(&format!("x.{ext}"), b"").is_none()
}

/// Refuse planned outputs whose type is not known game data, not an executable class and not
/// named by the manifest entry.
pub fn enforce_known_types<'a>(
    dests: impl Iterator<Item = &'a String>,
    extra: &[String],
) -> Result<()> {
    let mut unknown: Vec<(&String, String)> = dests
        .filter_map(|dest| {
            let (name, ext) = extension(dest);
            let known = if ext.is_empty() {
                PLAIN_NAMES.contains(&name.as_str())
            } else {
                GAME_DATA.contains(&ext.as_str()) || extra.contains(&ext)
            };
            (!known).then_some((dest, ext))
        })
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    unknown.sort();
    let mut shown: Vec<String> = unknown.iter().take(5).map(|(d, _)| (*d).clone()).collect();
    if unknown.len() > shown.len() {
        shown.push(format!("and {} more", unknown.len() - shown.len()));
    }
    let mut need: Vec<&str> = unknown
        .iter()
        .map(|(_, e)| e.as_str())
        .filter(|e| safe_type(e))
        .collect();
    need.sort();
    need.dedup();
    let advice = if need.is_empty() {
        "; exclude them on the manifest entry".to_owned()
    } else {
        format!("; after review, exclude them or add extra_types = {need:?} to the manifest entry")
    };
    refuse(
        RefusalCode::UnrecognizedContent,
        format!("{}{advice}", shown.join(", ")),
    )
}

#[derive(Debug, Clone, Serialize)]
pub struct ExecRecord {
    pub path: String,
    pub class: ExecClass,
    pub sha256: String,
}

/// Refuse executable outputs the manifest entry does not allow.
pub fn enforce_executables(found: &[ExecRecord], allowed: &[ExecClass]) -> Result<()> {
    let bad: Vec<&ExecRecord> = found
        .iter()
        .filter(|r| r.class == ExecClass::Disguised || !allowed.contains(&r.class))
        .collect();
    if bad.is_empty() {
        return Ok(());
    }
    let label = |c: ExecClass| {
        serde_json::to_value(c)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_default()
    };
    let mut shown: Vec<String> = bad
        .iter()
        .take(5)
        .map(|r| format!("{} ({})", r.path, label(r.class)))
        .collect();
    if bad.len() > shown.len() {
        shown.push(format!("and {} more", bad.len() - shown.len()));
    }
    let mut need: Vec<String> = bad
        .iter()
        .filter(|r| r.class != ExecClass::Disguised)
        .map(|r| label(r.class))
        .collect();
    need.sort();
    need.dedup();
    let advice = if need.is_empty() {
        String::new()
    } else {
        format!("; after review, allow them with executables = {need:?} on the manifest entry")
    };
    refuse(
        RefusalCode::UnexpectedExecutable,
        format!("{}{advice}", shown.join(", ")),
    )
}

/// A manifest key or archive file name that is exactly one ordinary path component.
pub fn single_component(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\', '\0'])
}

/// A manifest key: it names the staging and receipt directories.
pub fn safe_key(key: &str) -> bool {
    let mut chars = key.chars();
    key.len() <= 128
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// An MO2 mod folder name: one component that cannot collide with skyforge's own temporaries.
pub fn safe_mod_name(name: &str) -> bool {
    single_component(name)
        && !name.starts_with('.')
        && !name.ends_with([' ', '.'])
        && !name.chars().any(char::is_control)
}

/// A FOMOD or manifest path inside an archive: it may not climb out of the archive.
pub fn check_source(rel: &str) -> Result<()> {
    if rel.replace('\\', "/").split('/').any(|c| c == "..") {
        return refuse(
            RefusalCode::UnsafePath,
            format!("{rel:?} names a source outside the archive"),
        );
    }
    Ok(())
}

/// A planned destination below the mod folder or game root: every component an ordinary
/// name, so it cannot climb out and means the same on Windows and Linux.
pub fn check_destination(dest: &str) -> Result<()> {
    for component in dest.split('/') {
        let why = match component {
            "" | "." | ".." => Some("a component that is not a name"),
            name => unsafe_component(name),
        };
        if let Some(why) = why {
            return refuse(
                RefusalCode::UnsafePath,
                format!("destination {dest:?}: {why}"),
            );
        }
    }
    Ok(())
}

/// A planned source must be a file below the extraction root it was planned from.
pub fn check_contained(root: &Path, src: &Path) -> Result<()> {
    let inside = src.strip_prefix(root).is_ok_and(|rest| {
        rest.components()
            .all(|c| matches!(c, std::path::Component::Normal(_)))
    });
    if !inside {
        return refuse(
            RefusalCode::UnsafePath,
            "the plan names a file outside the extracted archive",
        );
    }
    Ok(())
}

/// Where an approved archive may be read from: a download root named by the configuration,
/// or the owner-placed path of a local source, which the manifest names itself.
pub fn approved_path(
    downloads: &Path,
    overflow: Option<&Path>,
    locked: &LockedFile,
) -> Result<PathBuf> {
    let Some(name) = locked.file_name.as_deref() else {
        return refuse(
            RefusalCode::UnapprovedIdentity,
            format!(
                "{}: the lockfile names no archive file",
                locked.display_name
            ),
        );
    };
    if locked.source == "local" {
        return Ok(locked.dir.as_deref().unwrap_or(downloads).join(name));
    }
    if !single_component(name) {
        return refuse(
            RefusalCode::UnapprovedIdentity,
            format!("archive name {name:?} is not a single file name"),
        );
    }
    match locked.dir.as_deref() {
        None => Ok(downloads.join(name)),
        Some(dir) if dir == downloads || Some(dir) == overflow => Ok(dir.join(name)),
        Some(dir) => refuse(
            RefusalCode::UnapprovedIdentity,
            format!(
                "archive directory {} is not a configured download root",
                dir.display()
            ),
        ),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Stamp {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

fn stamp(file: &File) -> std::io::Result<(Stamp, bool)> {
    let m = file.metadata()?;
    Ok((
        Stamp {
            dev: m.dev(),
            ino: m.ino(),
            size: m.size(),
            mtime: (m.mtime(), m.mtime_nsec()),
            ctime: (m.ctime(), m.ctime_nsec()),
        },
        m.is_file(),
    ))
}

/// An approved archive held open. The extractor reads this exact file through the descriptor,
/// so replacing the path cannot change what is extracted, and a write to the file is detected.
pub struct BoundArchive {
    file: File,
    stamp: Stamp,
    shown: String,
    pub sha256: String,
    pub size: u64,
}

impl BoundArchive {
    /// Open and hash the archive. Nothing is approved yet.
    pub fn read(path: &Path) -> Result<Self> {
        let shown = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        // Non-blocking, so a pipe at the archive path is refused instead of waited on.
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
        {
            Ok(file) => file,
            Err(error) => {
                return refuse(
                    RefusalCode::UnapprovedIdentity,
                    format!("{shown}: cannot open the approved archive: {error}"),
                )
            }
        };
        let (before, regular) = stamp(&file)?;
        if !regular {
            return refuse(
                RefusalCode::UnapprovedIdentity,
                format!("{shown}: not a regular file"),
            );
        }
        let mut hash = Sha256::new();
        let mut buf = vec![0u8; 4 << 20];
        let mut offset = 0u64;
        loop {
            let n = file.read_at(&mut buf, offset)?;
            if n == 0 {
                break;
            }
            hash.update(&buf[..n]);
            offset += n as u64;
        }
        let sha256 = hex::encode(hash.finalize());
        if stamp(&file)?.0 != before || offset != before.size {
            return refuse(
                RefusalCode::ArchiveChanged,
                format!("{shown}: changed while it was being verified"),
            );
        }
        Ok(BoundArchive {
            file,
            stamp: before,
            shown,
            sha256,
            size: offset,
        })
    }

    /// The bytes that were read are the bytes the lockfile approves.
    pub fn approve(&self, approved: &LockedFile) -> Result<()> {
        let shown = &self.shown;
        let hex =
            |d: &&str| d.len() == 64 && d.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        let Some(want) = approved.sha256.as_deref().filter(hex) else {
            return refuse(
                RefusalCode::UnapprovedIdentity,
                format!("{shown}: the lockfile holds no SHA-256 for this archive"),
            );
        };
        if self.sha256 != want {
            return refuse(
                RefusalCode::DigestMismatch,
                format!("{shown}: approved SHA-256 {want}, found {}", self.sha256),
            );
        }
        if approved.size.is_some_and(|size| size != self.size) {
            return refuse(
                RefusalCode::UnapprovedIdentity,
                format!("{shown}: the lockfile size disagrees with its own SHA-256"),
            );
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn open(path: &Path, approved: &LockedFile) -> Result<Self> {
        let archive = Self::read(path)?;
        archive.approve(approved)?;
        Ok(archive)
    }

    /// The archive is still the file that was verified, with no write since.
    pub fn confirm_unchanged(&self) -> Result<()> {
        if stamp(&self.file)?.0 != self.stamp {
            return refuse(
                RefusalCode::ArchiveChanged,
                "the archive was written to, replaced or relinked after it was verified",
            );
        }
        Ok(())
    }
}

/// Remove a tree even when an archive left directories without owner permissions.
pub fn remove_tree(path: &Path) -> std::io::Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !meta.is_dir() {
        return std::fs::remove_file(path);
    }
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                stack.push(entry.path());
            }
        }
    }
    std::fs::remove_dir_all(path)
}

fn private_dir(path: &Path) -> std::io::Result<()> {
    std::fs::DirBuilder::new().mode(0o700).create(path)
}

/// A fresh staging directory for one manifest key, below a root only this user can write.
pub fn owned_staging(root: &Path, key: &str) -> Result<PathBuf> {
    if !safe_key(key) {
        return refuse(
            RefusalCode::UnapprovedIdentity,
            format!("manifest key {key:?} cannot name a staging directory"),
        );
    }
    std::fs::create_dir_all(root)?;
    let meta = std::fs::symlink_metadata(root)?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o022 != 0 {
        return refuse(
            RefusalCode::StagingNotOwned,
            format!(
                "{} must be a real directory that only its owner can write",
                root.display()
            ),
        );
    }
    let dir = root.join(key);
    remove_tree(&dir).with_context(|| format!("clearing interrupted staging {}", dir.display()))?;
    private_dir(&dir)?;
    Ok(dir)
}

const FS_EXECUTE: u64 = 1;
const FS_WRITE_FILE: u64 = 1 << 1;
const FS_READ_FILE: u64 = 1 << 2;
const FS_READ_DIR: u64 = 1 << 3;
const FS_MAKE_CHAR: u64 = 1 << 6;
const FS_MAKE_SOCK: u64 = 1 << 9;
const FS_MAKE_FIFO: u64 = 1 << 10;
const FS_MAKE_BLOCK: u64 = 1 << 11;
const FS_REFER: u64 = 1 << 13;
const FS_TRUNCATE: u64 = 1 << 14;
const RULE_PATH_BENEATH: u32 = 1;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

#[repr(C, packed)]
struct PathBeneath {
    allowed_access: u64,
    parent_fd: i32,
}

/// Where extractors and the libraries they load live. Nothing of the user's is below these.
const SYSTEM_ROOTS: &[&str] = &[
    "/nix",
    "/usr",
    "/lib",
    "/lib32",
    "/lib64",
    "/bin",
    "/sbin",
    "/etc",
    "/run/current-system",
];

/// The only device files an extractor may read. `/dev/shm` and terminals stay out of reach.
const DEVICES: &[&str] = &["/dev/zero", "/dev/urandom", "/dev/random"];

/// A Landlock ruleset for one extractor run: write only below `writable`; read the system
/// roots, `readable` (the archive and the tool directories) and nothing else. The extractor
/// cannot read credentials, saves or any other user file, whatever the archive makes it do.
fn landlock(writable: &Path, readable: &[&Path]) -> std::io::Result<(OwnedFd, i64)> {
    let last = std::io::Error::last_os_error;
    // SAFETY: a null attribute with the version flag only queries the supported ABI.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            1u32,
        )
    };
    if abi < 1 {
        return Err(last());
    }
    let mut handled = (1u64 << 13) - 1;
    if abi >= 2 {
        handled |= FS_REFER;
    }
    if abi >= 3 {
        handled |= FS_TRUNCATE;
    }
    let attr = RulesetAttr {
        handled_access_fs: handled,
    };
    // SAFETY: `attr` outlives the call and its size is passed with it.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const RulesetAttr,
            std::mem::size_of::<RulesetAttr>(),
            0u32,
        )
    };
    if fd < 0 {
        return Err(last());
    }
    // SAFETY: the kernel returned a new descriptor that nothing else owns.
    let ruleset = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
    let allow = |path: &Path, access: u64| -> std::io::Result<()> {
        let parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH)
            .open(path)?;
        // A rule on a file may carry only the rights that apply to a file.
        let access = if parent.metadata()?.is_dir() {
            access
        } else {
            access & (FS_EXECUTE | FS_READ_FILE | FS_WRITE_FILE | FS_TRUNCATE)
        };
        let rule = PathBeneath {
            allowed_access: access & handled,
            parent_fd: parent.as_raw_fd(),
        };
        // SAFETY: `rule` and both descriptors are valid for the duration of the call.
        if unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset.as_raw_fd(),
                RULE_PATH_BENEATH,
                &rule as *const PathBeneath,
                0u32,
            )
        } != 0
        {
            return Err(last());
        }
        Ok(())
    };
    let read = FS_EXECUTE | FS_READ_FILE | FS_READ_DIR;
    for root in SYSTEM_ROOTS
        .iter()
        .map(Path::new)
        .filter(|root| root.exists())
    {
        allow(root, read)?;
    }
    for path in DEVICES.iter().map(Path::new).filter(|p| p.exists()) {
        allow(path, FS_READ_FILE)?;
    }
    for path in readable {
        allow(path, read)?;
    }
    allow(
        Path::new("/dev/null"),
        FS_READ_FILE | FS_WRITE_FILE | FS_TRUNCATE,
    )?;
    allow(
        writable,
        handled & !(FS_EXECUTE | FS_MAKE_CHAR | FS_MAKE_BLOCK | FS_MAKE_SOCK | FS_MAKE_FIFO),
    )?;
    Ok((ruleset, abi))
}

/// A seccomp filter for the extractor. Landlock governs files; this refuses what Landlock
/// does not reach: starting another process, opening any socket (network or the desktop
/// session bus), signalling or tracing other processes, the kernel keyring, and new
/// namespaces. Mode and owner changes report success and do nothing, because Landlock cannot
/// confine them to staging and inspection resets modes afterwards. Threads stay available.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn syscall_filter() -> Vec<libc::sock_filter> {
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64
    let refuse: &[libc::c_long] = &[
        #[cfg(target_arch = "x86_64")]
        libc::SYS_fork,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_vfork,
        libc::SYS_clone3,
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_io_uring_setup,
        libc::SYS_kill,
        libc::SYS_tkill,
        libc::SYS_tgkill,
        libc::SYS_rt_sigqueueinfo,
        libc::SYS_rt_tgsigqueueinfo,
        libc::SYS_pidfd_send_signal,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_userfaultfd,
    ];
    let ignore: &[libc::c_long] = &[
        #[cfg(target_arch = "x86_64")]
        libc::SYS_chmod,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_chown,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_lchown,
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        452, // fchmodat2
        libc::SYS_fchown,
        libc::SYS_fchownat,
    ];
    let stmt = |code: u32, k: u32| libc::sock_filter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k,
    };
    let jump = |code: u32, k: u32, jt: u8, jf: u8| libc::sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    };
    let (load, test, ret) = (
        libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
        libc::BPF_JMP | libc::BPF_K,
        libc::BPF_RET | libc::BPF_K,
    );
    let errno = |e: i32| libc::SECCOMP_RET_ERRNO | (e as u32 & libc::SECCOMP_RET_DATA);
    // Offsets into seccomp_data: nr at 0, arch at 4, the low half of args[0] at 16.
    let mut filter = vec![
        stmt(load, 4),
        jump(test | libc::BPF_JEQ, ARCH, 1, 0),
        stmt(ret, libc::SECCOMP_RET_KILL_PROCESS),
        stmt(load, 0),
    ];
    // The x32 numbering would slip past the checks below.
    #[cfg(target_arch = "x86_64")]
    filter.extend([
        jump(test | libc::BPF_JGE, 0x4000_0000, 0, 1),
        stmt(ret, libc::SECCOMP_RET_KILL_PROCESS),
    ]);
    for nr in refuse {
        filter.push(jump(test | libc::BPF_JEQ, *nr as u32, 0, 1));
        filter.push(stmt(ret, errno(libc::EPERM)));
    }
    for nr in ignore {
        filter.push(jump(test | libc::BPF_JEQ, *nr as u32, 0, 1));
        filter.push(stmt(ret, errno(0)));
    }
    // clone is allowed only for a new thread of the same process.
    filter.extend([
        jump(test | libc::BPF_JEQ, libc::SYS_clone as u32, 0, 4),
        stmt(load, 16),
        jump(test | libc::BPF_JSET, libc::CLONE_THREAD as u32, 1, 0),
        stmt(ret, errno(libc::EPERM)),
        stmt(ret, libc::SECCOMP_RET_ALLOW),
        stmt(ret, libc::SECCOMP_RET_ALLOW),
    ]);
    filter
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
fn syscall_filter() -> Vec<libc::sock_filter> {
    Vec::new()
}

struct Sandbox {
    ruleset: Option<OwnedFd>,
    label: String,
}

impl Sandbox {
    fn new(mode: Confinement, writable: &Path, readable: &[&Path]) -> Result<Self> {
        match mode {
            Confinement::None => Ok(Sandbox { ruleset: None, label: "none".into() }),
            Confinement::Landlock => match landlock(writable, readable) {
                Ok((ruleset, abi)) => Ok(Sandbox { ruleset: Some(ruleset), label: format!("landlock-abi-{abi}") }),
                Err(error) => refuse(
                    RefusalCode::ConfinementUnavailable,
                    format!("Landlock is not available ({error}); extraction is refused unless [admission] confinement = \"none\" is set deliberately"),
                ),
            },
        }
    }
}

fn free_bytes(path: &Path) -> Option<u64> {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).ok()?;
    let mut s = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `c` is a valid C string and `s` is writable for one statvfs record.
    if unsafe { libc::statvfs(c.as_ptr(), s.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: statvfs returned success, so the record is initialized.
    let s = unsafe { s.assume_init() };
    // The field widths differ between C libraries, so the casts stay explicit.
    #[allow(clippy::unnecessary_cast)]
    let free = s.f_bavail as u64 * s.f_frsize as u64;
    Some(free)
}

/// Which limit the staged tree has passed, if any. Stops counting once a limit is passed.
fn over_budget(dir: &Path, limits: &Limits) -> Option<String> {
    if free_bytes(dir).is_some_and(|free| free < limits.reserve_bytes) {
        return Some(format!(
            "free space fell below the {}-byte reserve",
            limits.reserve_bytes
        ));
    }
    let (mut entries, mut bytes) = (0u64, 0u64);
    let mut stack = vec![dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(read) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in read.flatten() {
            entries += 1;
            if let Ok(meta) = entry.metadata() {
                if meta.is_dir() {
                    stack.push(entry.path());
                } else {
                    bytes += meta.size();
                }
            }
            if entries > limits.max_entries {
                return Some(format!("more than {} entries", limits.max_entries));
            }
            if bytes > limits.max_total_bytes {
                return Some(format!("more than {} bytes", limits.max_total_bytes));
            }
        }
    }
    None
}

/// Arrange for `cmd` to start with only `keep` of our descriptors, with the size and
/// processor limits, and under the Landlock ruleset when there is one.
fn restrict(cmd: &mut Command, keep: RawFd, limits: &Limits, ruleset: Option<RawFd>) {
    let (file_bytes, cpu) = (limits.max_file_bytes, limits.cpu_seconds);
    // The extractor gets no variable that could carry a credential.
    let kept: Vec<_> = ["PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TZ"]
        .iter()
        .filter_map(|k| std::env::var_os(k).map(|v| (*k, v)))
        .collect();
    cmd.env_clear().envs(kept);
    // Built before the fork: the child only passes the finished program to the kernel.
    let filter = if ruleset.is_some() {
        syscall_filter()
    } else {
        Vec::new()
    };
    // SAFETY: the closure runs between fork and exec and makes only async-signal-safe calls.
    unsafe {
        cmd.pre_exec(move || {
            let check = |ok: bool| {
                if ok {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            };
            // Every descriptor this process holds closes at exec, then the archive alone is
            // kept. A kernel without close_range leaves the standard library's own
            // close-on-exec flags in force.
            libc::syscall(
                libc::SYS_close_range,
                3u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            );
            check(libc::fcntl(keep, libc::F_SETFD, 0) == 0)?;
            for (resource, value) in [
                (libc::RLIMIT_FSIZE, file_bytes),
                (libc::RLIMIT_CPU, cpu),
                (libc::RLIMIT_CORE, 0),
            ] {
                check(
                    libc::setrlimit(
                        resource,
                        &libc::rlimit {
                            rlim_cur: value,
                            rlim_max: value,
                        },
                    ) == 0,
                )?;
            }
            if let Some(ruleset) = ruleset {
                check(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0)?;
                check(libc::syscall(libc::SYS_landlock_restrict_self, ruleset, 0u32) == 0)?;
                if !filter.is_empty() {
                    let program = libc::sock_fprog {
                        len: filter.len() as libc::c_ushort,
                        filter: filter.as_ptr() as *mut libc::sock_filter,
                    };
                    check(
                        libc::prctl(
                            libc::PR_SET_SECCOMP,
                            libc::SECCOMP_MODE_FILTER,
                            &program as *const libc::sock_fprog,
                        ) == 0,
                    )?;
                }
            }
            Ok(())
        });
    }
}

/// Run one extractor on the bound archive. `Ok(false)` means the tool could not read it.
fn run_extractor(
    mut cmd: Command,
    archive: &BoundArchive,
    dest: &Path,
    limits: &Limits,
    sandbox: &Sandbox,
) -> Result<(bool, String)> {
    let fd = archive.file.as_raw_fd();
    cmd.arg(format!("/proc/self/fd/{fd}"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    restrict(
        &mut cmd,
        fd,
        limits,
        sandbox.ruleset.as_ref().map(AsRawFd::as_raw_fd),
    );
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        // A tool that is not installed cannot read the archive; the caller tries the next one.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok((
                false,
                format!("{} is not installed", cmd.get_program().to_string_lossy()),
            ));
        }
        Err(error) => return Err(error).context("starting the extractor"),
    };
    let mut stderr = child.stderr.take();
    let drain = std::thread::spawn(move || {
        let mut tail = Vec::new();
        let mut buf = [0u8; 4096];
        while let Some(n) = stderr
            .as_mut()
            .and_then(|s| s.read(&mut buf).ok())
            .filter(|n| *n > 0)
        {
            tail.extend_from_slice(&buf[..n]);
            let excess = tail.len().saturating_sub(2048);
            tail.drain(..excess);
        }
        String::from_utf8_lossy(&tail)
            .chars()
            .filter(|c| !c.is_control() || *c == '\n')
            .collect::<String>()
            .trim()
            .replace('\n', "; ")
    });
    let started = Instant::now();
    let mut next_usage = started + Duration::from_millis(250);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        let now = Instant::now();
        let over = if now.duration_since(started).as_secs() >= limits.wall_seconds {
            Some(format!(
                "the extractor ran longer than {} seconds",
                limits.wall_seconds
            ))
        } else if now >= next_usage {
            next_usage = now + Duration::from_secs(1);
            over_budget(dest, limits)
        } else {
            None
        };
        if let Some(what) = over {
            child.kill().ok();
            child.wait().ok();
            drain.join().ok();
            return refuse(RefusalCode::LimitExceeded, what);
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let said = drain.join().unwrap_or_default();
    match status.signal() {
        Some(libc::SIGXFSZ) => refuse(
            RefusalCode::LimitExceeded,
            format!("a file larger than {} bytes", limits.max_file_bytes),
        ),
        Some(libc::SIGXCPU) | Some(libc::SIGKILL) => refuse(
            RefusalCode::LimitExceeded,
            format!(
                "the extractor was killed, by the limit of {} processor seconds or by the kernel",
                limits.cpu_seconds
            ),
        ),
        _ => Ok((status.success(), said)),
    }
}

fn clear_dir(dir: &Path) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        remove_tree(&entry?.path())?;
    }
    Ok(())
}

/// The absolute program a tool name runs, so its directory can be made readable to it.
fn resolve_tool(tool: PathBuf) -> PathBuf {
    let found = if tool.components().count() > 1 {
        Some(tool.clone())
    } else {
        std::env::var_os("PATH").and_then(|paths| {
            std::env::split_paths(&paths)
                .map(|dir| dir.join(&tool))
                .find(|p| p.is_file())
        })
    };
    found.and_then(|p| p.canonicalize().ok()).unwrap_or(tool)
}

/// Extract the bound archive into `dest`, an empty directory inside owned staging.
/// Tool precedence is unchanged: RAR goes to unar, everything else to 7zz and then unar.
/// Returns the confinement that was in force.
pub fn extract(
    tool: impl Fn(&str) -> PathBuf,
    archive: &BoundArchive,
    file_name: &str,
    dest: &Path,
    policy: &Policy,
) -> Result<String> {
    private_dir(dest)?;
    if let Some(what) = over_budget(dest, &policy.limits) {
        return refuse(
            RefusalCode::LimitExceeded,
            format!("before extraction: {what}"),
        );
    }
    let (seven_tool, unar_tool) = (resolve_tool(tool("7zz")), resolve_tool(tool("unar")));
    let archive_path = PathBuf::from(format!("/proc/self/fd/{}", archive.file.as_raw_fd()));
    let mut readable: Vec<&Path> = vec![&archive_path];
    // Only a tool that exists has a directory to make readable.
    readable.extend(
        [&seven_tool, &unar_tool]
            .into_iter()
            .filter(|t| t.is_absolute() && t.is_file())
            .filter_map(|t| t.parent()),
    );
    let sandbox = Sandbox::new(policy.confinement, dest, &readable)?;
    let seven = || {
        let mut c = Command::new(&seven_tool);
        c.args(["x", "-y", "-bso0", "-bsp0"])
            .arg(format!("-o{}", dest.display()));
        c
    };
    let unar = || {
        let mut c = Command::new(&unar_tool);
        c.args(["-q", "-f", "-D", "-o"]).arg(dest);
        c
    };
    let rar = Path::new(file_name)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("rar"));
    let (ok, said) = if rar {
        run_extractor(unar(), archive, dest, &policy.limits, &sandbox)?
    } else {
        match run_extractor(seven(), archive, dest, &policy.limits, &sandbox)? {
            (true, said) => (true, said),
            (false, first) => {
                clear_dir(dest)?;
                let (ok, second) = run_extractor(unar(), archive, dest, &policy.limits, &sandbox)?;
                (ok, format!("{first}; {second}"))
            }
        }
    };
    if !ok {
        return refuse(
            RefusalCode::ExtractionFailed,
            format!("no supported extractor could read {file_name}: {said}"),
        );
    }
    archive.confirm_unchanged()?;
    if let Some(what) = over_budget(dest, &policy.limits) {
        return refuse(RefusalCode::LimitExceeded, what);
    }
    Ok(sandbox.label)
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Staged {
    pub entries: u64,
    pub bytes: u64,
}

const RESERVED: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// Why Windows and Linux would not agree on this file name, if they would not.
fn unsafe_component(name: &str) -> Option<&'static str> {
    if name.len() > 255 {
        Some("a name longer than 255 bytes")
    } else if name
        .chars()
        .any(|c| c.is_control() || matches!(c, '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|'))
    {
        Some("a character Windows does not allow in a name")
    } else if name.ends_with([' ', '.']) {
        Some("a trailing space or dot, which Windows drops")
    } else if RESERVED.contains(&name.split('.').next().unwrap_or("").to_lowercase().as_str()) {
        Some("a Windows device name")
    } else {
        None
    }
}

fn same_bytes(a: &Path, b: &Path) -> std::io::Result<bool> {
    let (mut a, mut b) = (File::open(a)?, File::open(b)?);
    if a.metadata()?.len() != b.metadata()?.len() {
        return Ok(false);
    }
    let (mut x, mut y) = (vec![0u8; 1 << 16], vec![0u8; 1 << 16]);
    loop {
        let n = a.read(&mut x)?;
        if n == 0 {
            return Ok(b.read(&mut y)? == 0);
        }
        b.read_exact(&mut y[..n])?;
        if x[..n] != y[..n] {
            return Ok(false);
        }
    }
}

/// Inspect everything an extractor left: only directories and unshared regular files, names
/// that mean the same on Windows and Linux, no two different files behind one caseless path,
/// and totals inside the limits. Permissions are reset so the tree can always be removed.
pub fn inspect_tree(root: &Path, limits: &Limits) -> Result<Staged> {
    let mut staged = Staged::default();
    let mut seen: HashMap<String, (PathBuf, bool)> = HashMap::new();
    let mut stack = vec![(root.to_path_buf(), String::new(), 0usize)];
    while let Some((dir, rel, depth)) = stack.pop() {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))?;
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&dir)? {
            names.push(entry?.file_name());
        }
        names.sort();
        for name in names {
            let path = dir.join(&name);
            let shown = format!("{rel}{}", name.to_string_lossy());
            let Some(name) = name.to_str() else {
                return refuse(
                    RefusalCode::UnsafePath,
                    format!("{shown}: a name that is not UTF-8"),
                );
            };
            if let Some(why) = unsafe_component(name) {
                return refuse(RefusalCode::UnsafePath, format!("{shown}: {why}"));
            }
            if shown.len() > limits.max_path_bytes || depth >= limits.max_depth {
                return refuse(
                    RefusalCode::LimitExceeded,
                    format!("{shown}: deeper or longer than the path limits"),
                );
            }
            staged.entries += 1;
            if staged.entries > limits.max_entries {
                return refuse(
                    RefusalCode::LimitExceeded,
                    format!("more than {} entries", limits.max_entries),
                );
            }
            let meta = std::fs::symlink_metadata(&path)?;
            let kind = meta.file_type();
            let folded = shown.to_lowercase();
            if kind.is_dir() {
                if seen.get(&folded).is_some_and(|(_, is_dir)| !is_dir) {
                    return refuse(
                        RefusalCode::AmbiguousPath,
                        format!("{shown} is a file and a directory when case is ignored"),
                    );
                }
                seen.entry(folded).or_insert((path.clone(), true));
                stack.push((path, format!("{shown}/"), depth + 1));
                continue;
            }
            if !kind.is_file() {
                let what = if kind.is_symlink() {
                    "a symbolic link"
                } else {
                    "a device, pipe or socket"
                };
                return refuse(RefusalCode::UnsupportedEntry, format!("{shown}: {what}"));
            }
            if meta.nlink() != 1 {
                return refuse(
                    RefusalCode::UnsupportedEntry,
                    format!("{shown}: a hard link"),
                );
            }
            if meta.size() > limits.max_file_bytes {
                return refuse(
                    RefusalCode::LimitExceeded,
                    format!("{shown}: larger than {} bytes", limits.max_file_bytes),
                );
            }
            staged.bytes += meta.size();
            if staged.bytes > limits.max_total_bytes {
                return refuse(
                    RefusalCode::LimitExceeded,
                    format!("more than {} bytes", limits.max_total_bytes),
                );
            }
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
            match seen.get(&folded) {
                None => {
                    seen.insert(folded, (path, false));
                }
                Some((_, true)) => {
                    return refuse(
                        RefusalCode::AmbiguousPath,
                        format!("{shown} is a file and a directory when case is ignored"),
                    )
                }
                Some((other, false)) if !same_bytes(other, &path)? => {
                    return refuse(
                        RefusalCode::AmbiguousPath,
                        format!(
                            "{shown} and another file differ only by case and hold different bytes"
                        ),
                    );
                }
                Some(_) => {}
            }
        }
    }
    Ok(staged)
}

/// What inspection established about one planned output.
#[derive(Debug, Clone)]
pub struct Proof {
    dev: u64,
    ino: u64,
    pub size: u64,
    pub sha256: String,
    pub head: [u8; 4],
}

fn open_plain(path: &Path) -> Result<(File, std::fs::Metadata)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.nlink() != 1 {
        return refuse(
            RefusalCode::UnsupportedEntry,
            format!("{}: not an unshared regular file", path.display()),
        );
    }
    Ok((file, meta))
}

fn hash_into(file: &mut File, mut sink: Option<&mut File>) -> Result<(String, [u8; 4], u64)> {
    use std::io::Write;
    let mut hash = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let (mut head, mut total) = ([0u8; 4], 0u64);
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        for (i, b) in buf[..n]
            .iter()
            .enumerate()
            .take(4usize.saturating_sub(total as usize))
        {
            head[total as usize + i] = *b;
        }
        hash.update(&buf[..n]);
        if let Some(sink) = sink.as_deref_mut() {
            sink.write_all(&buf[..n])?;
        }
        total += n as u64;
    }
    Ok((hex::encode(hash.finalize()), head, total))
}

/// Hash one planned output and remember which file it was.
pub fn prove(src: &Path) -> Result<Proof> {
    let (mut file, meta) = open_plain(src)?;
    let (sha256, head, size) = hash_into(&mut file, None)?;
    Ok(Proof {
        dev: meta.dev(),
        ino: meta.ino(),
        size,
        sha256,
        head,
    })
}

/// One digest for a whole plan: every destination with the SHA-256 of its bytes.
pub fn plan_digest(files: &[(String, &Proof)]) -> String {
    let mut lines: Vec<String> = files
        .iter()
        .map(|(dest, proof)| format!("{dest}\0{}\n", proof.sha256))
        .collect();
    lines.sort();
    let mut hash = Sha256::new();
    for line in lines {
        hash.update(line);
    }
    hex::encode(hash.finalize())
}

/// Move a proven file to `dest`, or copy it when a move is impossible, and confirm that the
/// file now at `dest` is the one that was proven.
pub fn place_verified(src: &Path, dest: &Path, proof: &Proof, keep_source: bool) -> Result<()> {
    let changed = || {
        refuse(
            RefusalCode::ActivationMismatch,
            format!("{} changed after it was inspected", dest.display()),
        )
    };
    if !keep_source && std::fs::rename(src, dest).is_ok() {
        let meta = std::fs::symlink_metadata(dest)?;
        if !meta.is_file()
            || meta.nlink() != 1
            || (meta.dev(), meta.ino(), meta.size()) != (proof.dev, proof.ino, proof.size)
        {
            return changed();
        }
        return Ok(());
    }
    let (mut from, _) = open_plain(src)?;
    let mut to = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(dest)?;
    let (sha256, _, _) = hash_into(&mut from, Some(&mut to))?;
    if sha256 != proof.sha256 {
        drop(to);
        std::fs::remove_file(dest).ok();
        return changed();
    }
    Ok(())
}

fn temporary(parent: &Path, name: &str, suffix: &str) -> PathBuf {
    parent.join(format!(".{name}.skyforge-{suffix}"))
}

/// The directory a new version of a mod folder is assembled in before it replaces the old one.
pub fn assembly_dir(parent: &Path, name: &str) -> PathBuf {
    temporary(parent, name, "new")
}

/// Undo or finish an interrupted replacement, so the mod folder is either the old version
/// or the new one and never missing.
pub fn recover_dir(parent: &Path, name: &str) -> Result<()> {
    let (old, dest) = (temporary(parent, name, "old"), parent.join(name));
    if std::fs::symlink_metadata(&old).is_ok() {
        if std::fs::symlink_metadata(&dest).is_ok() {
            remove_tree(&old)?;
        } else {
            std::fs::rename(&old, &dest)?;
        }
    }
    remove_tree(&assembly_dir(parent, name))?;
    Ok(())
}

/// Put the assembled directory in place. An existing folder is exchanged atomically, so there
/// is no moment without a usable mod folder. Returns the method used.
pub fn activate_dir(parent: &Path, name: &str) -> Result<&'static str> {
    activate_dir_with(parent, name, true)
}

fn activate_dir_with(parent: &Path, name: &str, exchange: bool) -> Result<&'static str> {
    let (new, old, dest) = (
        assembly_dir(parent, name),
        temporary(parent, name, "old"),
        parent.join(name),
    );
    if std::fs::symlink_metadata(&dest).is_err() {
        std::fs::rename(&new, &dest)?;
        return Ok("rename");
    }
    let c = |p: &Path| std::ffi::CString::new(p.as_os_str().as_encoded_bytes());
    let (from, to) = (c(&new)?, c(&dest)?);
    // SAFETY: both paths are valid C strings for the duration of the call.
    let exchanged = exchange
        && unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                from.as_ptr(),
                libc::AT_FDCWD,
                to.as_ptr(),
                libc::RENAME_EXCHANGE,
            )
        } == 0;
    // Once the new folder is in place the install has happened. A leftover old folder is
    // cleared by `recover_dir` on the next run and never turns the result into a failure.
    if exchanged {
        remove_tree(&new).ok();
        return Ok("exchange");
    }
    // Filesystems without an atomic exchange: keep the old folder until the new one is in place.
    std::fs::rename(&dest, &old)?;
    if let Err(error) = std::fs::rename(&new, &dest) {
        std::fs::rename(&old, &dest)?;
        return Err(error.into());
    }
    remove_tree(&old).ok();
    Ok("replace")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    /// The archives passed and their plan was activated.
    Admitted,
    /// The archives passed and the installed files already hold the planned bytes.
    Unchanged,
    /// Nothing was activated.
    Refused,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveRecord {
    pub index: usize,
    /// The file's name on its source page.
    pub name: String,
    pub file_name: String,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mod_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_id: Option<u64>,
    /// How the lockfile says integrity was established.
    pub provenance: String,
    /// How much that method proves about where the bytes came from.
    pub confidence: &'static str,
    pub approved_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
}

/// How strongly a lockfile verification method ties bytes to their source.
pub fn confidence(verified_by: &str) -> &'static str {
    match verified_by {
        "sha256-pinned" | "github-digest-sha256" => "publisher-digest",
        v if v.starts_with("nexus-md5") => "source-index",
        v if v.starts_with("nexus-size") => "size-and-archive-check",
        "github-size+tofu-sha256" => "first-use",
        "local-hash-recorded" => "owner-local",
        _ => "unclassified",
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RefusalRecord {
    pub code: RefusalCode,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlanRecord {
    pub files: usize,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActivationRecord {
    pub method: &'static str,
    pub replaced_existing: bool,
}

/// The record of one admission decision. It never holds a download URL or a credential.
#[derive(Debug, Clone, Serialize)]
pub struct Receipt {
    pub version: u32,
    pub tool: String,
    pub key: String,
    pub target: String,
    pub decided_at: String,
    pub decision: Decision,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal: Option<RefusalRecord>,
    pub archives: Vec<ArchiveRecord>,
    pub limits: Limits,
    pub confinement: String,
    pub allowed_executables: Vec<ExecClass>,
    pub allowed_extra_types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub staged: Option<Staged>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<PlanRecord>,
    pub executables: Vec<ExecRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activation: Option<ActivationRecord>,
    /// Set once admission has begun; a receipt is written only then.
    #[serde(skip)]
    pub started: bool,
    /// The staging directory to clear when the decision is recorded.
    #[serde(skip)]
    pub staging: Option<PathBuf>,
    /// Local directories and the labels that replace them in recorded text.
    #[serde(skip)]
    hidden: Vec<(String, &'static str)>,
}

impl Receipt {
    pub fn begin(
        key: &str,
        target: &str,
        files: &[LockedFile],
        allowed: &[ExecClass],
        extra_types: &[String],
        policy: &Policy,
    ) -> Self {
        let archives = files
            .iter()
            .enumerate()
            .map(|(index, f)| ArchiveRecord {
                index,
                // A local source is displayed by its path; the receipt keeps the file name only.
                name: if f.source == "local" {
                    Path::new(&f.display_name)
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default()
                } else {
                    f.display_name.clone()
                },
                file_name: Path::new(f.file_name.as_deref().unwrap_or(""))
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
                source: f.source.clone(),
                mod_id: f.mod_id,
                file_id: f.file_id,
                provenance: f.verified_by.clone().unwrap_or_default(),
                confidence: confidence(f.verified_by.as_deref().unwrap_or("")),
                approved_sha256: f.sha256.clone(),
                observed_sha256: None,
                size: None,
            })
            .collect();
        Receipt {
            version: 1,
            tool: format!("skyforge {}", env!("CARGO_PKG_VERSION")),
            key: key.to_owned(),
            target: target.to_owned(),
            decided_at: String::new(),
            decision: Decision::Refused,
            refusal: None,
            archives,
            limits: policy.limits.clone(),
            confinement: "not-started".into(),
            allowed_executables: allowed.to_vec(),
            allowed_extra_types: extra_types.to_vec(),
            staged: None,
            plan: None,
            executables: Vec::new(),
            activation: None,
            started: false,
            staging: None,
            hidden: Vec::new(),
        }
    }

    /// Replace a local directory with a label wherever it would appear in the receipt.
    pub fn hide(&mut self, path: &Path, label: &'static str) {
        let text = path.to_string_lossy().into_owned();
        if text.len() > 1 {
            self.hidden.push((text, label));
            self.hidden
                .sort_by_key(|(text, _)| std::cmp::Reverse(text.len()));
        }
    }

    fn scrub(&self, text: &str) -> String {
        self.hidden
            .iter()
            .fold(text.to_owned(), |text, (path, label)| {
                text.replace(path, label)
            })
    }

    /// Record the outcome, write the receipt beside the install state and clear staging.
    /// Returns the receipt path when admission had begun.
    pub fn finish<T>(&mut self, state_file: &Path, result: &Result<T>) -> Result<Option<PathBuf>> {
        if !self.started {
            return Ok(None);
        }
        let cleared = match self.staging.take() {
            Some(staging) => remove_tree(&staging)
                .with_context(|| format!("clearing staging {}", staging.display())),
            None => Ok(()),
        };
        if let Err(error) = result {
            self.decision = Decision::Refused;
            self.activation = None;
            let (code, detail) = match error.chain().find_map(|e| e.downcast_ref::<Refusal>()) {
                Some(refusal) => (refusal.code, refusal.detail.clone()),
                None => (RefusalCode::Error, format!("{error:#}")),
            };
            self.refusal = Some(RefusalRecord {
                code,
                detail: self.scrub(&detail),
            });
        }
        let now = chrono::Utc::now();
        self.decided_at = now.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let label = serde_json::to_value(self.decision)?
            .as_str()
            .unwrap_or("decision")
            .to_owned();
        let dir = state_file
            .parent()
            .unwrap_or(Path::new("."))
            .join("admission")
            .join(&self.key);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{}-{label}.json", now.format("%Y%m%dT%H%M%S%.3fZ")));
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(self)? + "\n")?;
        std::fs::rename(&tmp, &path)?;
        cleared?;
        Ok(Some(path))
    }
}

/// Synthetic archives for tests: a minimal tar writer, so hostile entries need no external tool.
#[cfg(test)]
pub(crate) mod testkit {
    pub enum Entry<'a> {
        File(&'a str, &'a [u8]),
        Symlink(&'a str, &'a str),
        Hardlink(&'a str, &'a str),
        Fifo(&'a str),
    }

    pub fn tar(entries: &[Entry]) -> Vec<u8> {
        let mut out = Vec::new();
        for entry in entries {
            let (name, kind, link, data): (&str, u8, &str, &[u8]) = match entry {
                Entry::File(name, data) => (name, b'0', "", data),
                Entry::Hardlink(name, target) => (name, b'1', target, &[]),
                Entry::Symlink(name, target) => (name, b'2', target, &[]),
                Entry::Fifo(name) => (name, b'6', "", &[]),
            };
            assert!(
                name.len() <= 100 && link.len() <= 100,
                "this writer has no long names"
            );
            let mut header = [0u8; 512];
            header[..name.len()].copy_from_slice(name.as_bytes());
            header[100..108].copy_from_slice(b"0000644\0");
            header[108..116].copy_from_slice(b"0000000\0");
            header[116..124].copy_from_slice(b"0000000\0");
            header[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
            header[136..148].copy_from_slice(b"00000000000\0");
            header[148..156].copy_from_slice(b"        ");
            header[156] = kind;
            header[157..157 + link.len()].copy_from_slice(link.as_bytes());
            header[257..265].copy_from_slice(b"ustar\x0000");
            let sum: u32 = header.iter().map(|b| *b as u32).sum();
            header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
            out.extend_from_slice(&header);
            out.extend_from_slice(data);
            out.resize(out.len().div_ceil(512) * 512, 0);
        }
        out.resize(out.len() + 1024, 0);
        out
    }

    /// A unique scratch directory below the crate's ignored test output.
    pub fn scratch(label: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
            "test-output/{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }
}

#[cfg(test)]
mod tests {
    use super::testkit::{scratch, tar, Entry};
    use super::*;

    fn code(error: &anyhow::Error) -> RefusalCode {
        error
            .chain()
            .find_map(|e| e.downcast_ref::<Refusal>())
            .unwrap_or_else(|| panic!("not a refusal: {error:#}"))
            .code
    }

    fn locked(bytes: &[u8]) -> LockedFile {
        LockedFile {
            source: "url".into(),
            file_name: Some("fixture.tar".into()),
            sha256: Some(hex::encode(Sha256::digest(bytes))),
            ..Default::default()
        }
    }

    fn tool(name: &str) -> PathBuf {
        PathBuf::from(name)
    }

    #[test]
    fn classes_follow_destination_and_first_bytes() {
        assert_eq!(
            classify("skse/plugins/Thing.dll", b"MZ\x90\0"),
            Some(ExecClass::SksePlugin)
        );
        assert_eq!(
            classify("Data/SKSE/Plugins/Thing.dll", b"MZ\x90\0"),
            Some(ExecClass::SksePlugin)
        );
        assert_eq!(
            classify("skse/plugins/helper/Lib.dll", b"MZ\x90\0"),
            Some(ExecClass::NativeLibrary)
        );
        assert_eq!(
            classify("d3dx9_42.dll", b"MZ\x90\0"),
            Some(ExecClass::NativeLibrary)
        );
        assert_eq!(
            classify("tools/Patcher.EXE", b"MZ\x90\0"),
            Some(ExecClass::Program)
        );
        assert_eq!(classify("tools/run.bat", b"@ech"), Some(ExecClass::Script));
        assert_eq!(classify("tools/run", b"#!/b"), Some(ExecClass::Script));
        assert_eq!(
            classify("textures/a.dds", b"MZ\x90\0"),
            Some(ExecClass::Disguised)
        );
        assert_eq!(
            classify("meshes/a.nif", b"\x7fELF"),
            Some(ExecClass::Disguised)
        );
        for script in [
            "a.js",
            "a.JSE",
            "a.wsc",
            "a.url",
            "a.scf",
            "a.inf",
            "a.py",
            "a.psd1",
            "a.settingcontent-ms",
        ] {
            assert_eq!(
                classify(script, b"text"),
                Some(ExecClass::Script),
                "{script}"
            );
        }
        assert_eq!(
            classify("panel.cpl", b"MZ\x90\0"),
            Some(ExecClass::NativeLibrary)
        );
        assert_eq!(
            classify("setup.msix", b"PK\x03\x04"),
            Some(ExecClass::Program)
        );
        for script in ["a.lua", "a.pyc", "a.desktop", "a.library-ms", "a.ws"] {
            assert_eq!(
                classify(script, b"text"),
                Some(ExecClass::Script),
                "{script}"
            );
        }
        assert_eq!(
            classify("addin.xll", b"MZ\x90\0"),
            Some(ExecClass::NativeLibrary)
        );
        assert_eq!(classify("textures/a.dds", b"DDS "), None);
        assert_eq!(classify("scripts/a.pex", b"\xfa\x57\xc0\xde"), None);
    }

    #[test]
    fn a_type_nobody_reviewed_is_refused_until_the_entry_names_it() {
        let files = |names: &[&str]| names.iter().map(|n| n.to_string()).collect::<Vec<_>>();
        let known = files(&[
            "Fixture.esp",
            "meshes/a.NIF",
            "textures/a.dds",
            "scripts/a.pex",
            "docs/README",
            "LICENSE",
            "interface/a.swf",
        ]);
        assert!(enforce_known_types(known.iter(), &[]).is_ok());
        for odd in [
            "data/key.pem",
            "tools/archive.7z",
            "notes",
            "meshes/a.nif_",
            "a.unknowntype",
        ] {
            let planned = files(&["Fixture.esp", odd]);
            let error = enforce_known_types(planned.iter(), &[]).unwrap_err();
            assert_eq!(code(&error), RefusalCode::UnrecognizedContent, "{odd}");
            assert!(error.to_string().contains(odd), "{error}");
        }
        let planned = files(&["Fixture.esp", "data/key.pem"]);
        let error = enforce_known_types(planned.iter(), &[])
            .unwrap_err()
            .to_string();
        assert!(error.contains(r#"extra_types = ["pem"]"#), "{error}");
        assert!(enforce_known_types(planned.iter(), &["pem".to_string()]).is_ok());
        // An extra type cannot smuggle an executable class past its own rule.
        for ext in ["exe", "dll", "js", "bat", "lnk", "PEM", "a b", "", "../x"] {
            assert!(!safe_type(ext), "{ext:?}");
        }
        assert!(safe_type("pem") && safe_type("7z") && safe_type("nif_"));
    }

    #[test]
    fn names_that_leave_their_directory_are_not_keys_or_mod_names() {
        for key in [
            "", ".", "..", "../x", "a/b", "a\\b", ".hidden", "a b", "a\0b",
        ] {
            assert!(!safe_key(key), "{key:?}");
        }
        assert!(
            safe_key("unofficial-patch_1.2") && safe_mod_name("Unofficial Skyrim Patch (USSEP)")
        );
        for name in [
            "",
            "..",
            "a/b",
            ".hidden",
            "trailing.",
            "trailing ",
            "tab\there",
        ] {
            assert!(!safe_mod_name(name), "{name:?}");
        }
        let downloads = Path::new("/downloads");
        let mut f = locked(b"x");
        assert_eq!(
            approved_path(downloads, None, &f).unwrap(),
            downloads.join("fixture.tar")
        );
        f.file_name = Some("../fixture.tar".into());
        assert_eq!(
            code(&approved_path(downloads, None, &f).unwrap_err()),
            RefusalCode::UnapprovedIdentity
        );
        f.file_name = Some("fixture.tar".into());
        f.dir = Some("/elsewhere".into());
        assert_eq!(
            code(&approved_path(downloads, Some(Path::new("/overflow")), &f).unwrap_err()),
            RefusalCode::UnapprovedIdentity
        );
        f.dir = Some("/overflow".into());
        assert_eq!(
            approved_path(downloads, Some(Path::new("/overflow")), &f).unwrap(),
            Path::new("/overflow/fixture.tar")
        );
    }

    #[test]
    fn a_bound_archive_refuses_other_bytes_and_ignores_a_replaced_path() {
        let root = scratch("bind");
        let path = root.join("fixture.tar");
        let approved = tar(&[Entry::File("approved.txt", b"approved")]);
        std::fs::write(&path, &approved).unwrap();
        let lock = locked(&approved);

        let mut missing = lock.clone();
        missing.sha256 = None;
        assert_eq!(
            code(&BoundArchive::open(&path, &missing).err().unwrap()),
            RefusalCode::UnapprovedIdentity
        );
        let mut wrong_size = lock.clone();
        wrong_size.size = Some(1);
        assert_eq!(
            code(&BoundArchive::open(&path, &wrong_size).err().unwrap()),
            RefusalCode::UnapprovedIdentity
        );

        let policy = Policy {
            limits: Limits {
                reserve_bytes: 0,
                ..Default::default()
            },
            ..Default::default()
        };
        let bound = BoundArchive::open(&path, &lock).unwrap();
        let label = extract(tool, &bound, "fixture.tar", &root.join("plain"), &policy).unwrap();
        assert!(label.starts_with("landlock-abi-"), "{label}");
        assert_eq!(
            std::fs::read(root.join("plain/approved.txt")).unwrap(),
            b"approved"
        );

        // The path is replaced after verification. The extractor still reads the approved
        // bytes, never the substitute, and the replacement itself is reported.
        let bound = BoundArchive::open(&path, &lock).unwrap();
        let other = root.join("other.tar");
        std::fs::write(
            &other,
            tar(&[Entry::File("substituted.txt", b"substituted")]),
        )
        .unwrap();
        std::fs::rename(&other, &path).unwrap();
        assert_eq!(
            code(&extract(tool, &bound, "fixture.tar", &root.join("out"), &policy).unwrap_err()),
            RefusalCode::ArchiveChanged
        );
        assert_eq!(
            std::fs::read(root.join("out/approved.txt")).unwrap(),
            b"approved"
        );
        assert!(!root.join("out/substituted.txt").exists());

        // The replacement no longer matches the approved digest.
        assert_eq!(
            code(&BoundArchive::open(&path, &lock).err().unwrap()),
            RefusalCode::DigestMismatch
        );

        // A write to the verified file itself is detected before anything is activated.
        std::fs::write(&path, &approved).unwrap();
        let bound = BoundArchive::open(&path, &lock).unwrap();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all_at(b"x", approved.len() as u64)
            .unwrap();
        assert_eq!(
            code(&bound.confirm_unchanged().unwrap_err()),
            RefusalCode::ArchiveChanged
        );

        // A pipe at the archive path is refused at once instead of being waited on.
        let pipe = root.join("pipe.tar");
        let c = std::ffi::CString::new(pipe.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        assert_eq!(
            code(&BoundArchive::open(&pipe, &lock).err().unwrap()),
            RefusalCode::UnapprovedIdentity
        );

        // A symbolic link is not an approved archive, whatever it points to.
        std::fs::write(&path, &approved).unwrap();
        let link = root.join("link.tar");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(
            code(&BoundArchive::open(&link, &lock).err().unwrap()),
            RefusalCode::UnapprovedIdentity
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unar_takes_rar_names_and_what_7zz_cannot_read() {
        let root = scratch("unar");
        let bytes = tar(&[Entry::File("Data/Fixture.esp", b"through unar")]);
        let policy = Policy {
            limits: Limits {
                reserve_bytes: 0,
                ..Default::default()
            },
            ..Default::default()
        };
        // No 7zz exists for these runs, so only unar can have produced the output.
        let only_unar = |name: &str| match name {
            "7zz" => PathBuf::from("/nonexistent/7zz"),
            other => PathBuf::from(other),
        };
        for (file_name, out) in [("fixture.rar", "rar"), ("fixture.7z", "fallback")] {
            let path = root.join(file_name);
            std::fs::write(&path, &bytes).unwrap();
            let mut lock = locked(&bytes);
            lock.file_name = Some(file_name.into());
            let bound = BoundArchive::open(&path, &lock).unwrap();
            let label = extract(only_unar, &bound, file_name, &root.join(out), &policy).unwrap();
            assert!(label.starts_with("landlock-abi-"), "{label}");
            assert_eq!(
                std::fs::read(root.join(out).join("Data/Fixture.esp")).unwrap(),
                b"through unar"
            );
        }
        // With neither tool the archive is unreadable, which is a refusal and not a crash.
        let none = |name: &str| PathBuf::from(format!("/nonexistent/{name}"));
        let bound = BoundArchive::open(&root.join("fixture.7z"), &locked(&bytes)).unwrap();
        let error = extract(none, &bound, "fixture.7z", &root.join("none"), &policy).unwrap_err();
        assert_eq!(code(&error), RefusalCode::ExtractionFailed);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_confined_process_is_held_to_its_directory_its_limits_and_itself() {
        let root = scratch("confine");
        let (inside, outside) = (root.join("inside"), root.join("outside"));
        std::fs::create_dir_all(&inside).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let keep = File::open(&root).unwrap();
        let limits = Limits {
            max_file_bytes: 64 << 10,
            ..Default::default()
        };
        let credential = outside.join("credential.txt");
        std::fs::write(&credential, b"secret").unwrap();
        let (ruleset, abi) =
            landlock(&inside, &[]).expect("Landlock must be available where these tests run");
        assert!(abi >= 1);
        // Each command is itself the confined process; a shell runs only its own builtins.
        let run = |program: &str, args: &[&std::ffi::OsStr]| {
            let mut cmd = Command::new(program);
            cmd.args(args).stdout(Stdio::null()).stderr(Stdio::null());
            restrict(
                &mut cmd,
                keep.as_raw_fd(),
                &limits,
                Some(ruleset.as_raw_fd()),
            );
            cmd.status().unwrap().success()
        };
        let sh = |script: &str| {
            run(
                "sh",
                &[
                    "-c".as_ref(),
                    script.as_ref(),
                    "sh".as_ref(),
                    inside.as_os_str(),
                    outside.as_os_str(),
                ],
            )
        };
        let (os, at) = (std::ffi::OsStr::new, |p: &Path, n: &str| {
            p.join(n).into_os_string()
        });

        // Files: write only below its own directory.
        assert!(sh(r#"echo in > "$1/in.txt""#));
        assert_eq!(std::fs::read(inside.join("in.txt")).unwrap(), b"in\n");
        assert!(!sh(r#"echo out > "$2/out.txt""#));
        assert!(!run("mkdir", &[&at(&outside, "dir")]));
        assert!(run(
            "ln",
            &[os("-s"), outside.as_os_str(), &at(&inside, "link")]
        ));
        assert!(!sh(r#"echo out > "$1/link/through.txt""#));
        assert!(!run(
            "mv",
            &[&at(&inside, "in.txt"), &at(&outside, "moved.txt")]
        ));
        assert!(!run("mkfifo", &[&at(&inside, "pipe")]));
        assert_eq!(
            std::fs::read_dir(&outside).unwrap().count(),
            1,
            "nothing may appear outside the confined directory"
        );

        // Files: read its own directory and the system, never the user's files, other
        // processes or shared memory.
        assert!(run("cat", &[&at(&inside, "in.txt")]) && run("ls", &[inside.as_os_str()]));
        assert!(run("ls", &[os("/etc")]));
        assert!(!run("cat", &[credential.as_os_str()]));
        assert!(!run("ls", &[outside.as_os_str()]));
        assert!(!run("ls", &[os("/proc/self")]) && !run("ls", &[os("/dev/shm")]));
        std::env::set_var("SKYFORGE_TEST_CREDENTIAL", "secret");
        assert!(
            sh(r#"test -z "$SKYFORGE_TEST_CREDENTIAL""#),
            "the environment must not be inherited"
        );
        std::env::remove_var("SKYFORGE_TEST_CREDENTIAL");

        // Limits: a file larger than the limit ends the process.
        assert!(!sh(r#"exec head -c 200000 /dev/zero > "$1/big.bin""#));
        assert!(std::fs::metadata(inside.join("big.bin")).unwrap().len() <= 64 << 10);

        // Itself: no second process, no socket, no signal to another process, and a mode
        // change outside its directory does nothing.
        assert!(sh(r#"exec ls "$1""#), "one program may replace the shell");
        assert!(
            !sh(r#"ls "$1" || exit 7; exit 0"#),
            "a second process must not start"
        );
        assert!(run("python3", &[os("-c"), os("pass")]));
        assert!(!run(
            "python3",
            &[os("-c"), os("import socket; socket.socket()")]
        ));
        assert!(!run(
            "python3",
            &[os("-c"), os("import socket; socket.socket(socket.AF_UNIX)")]
        ));
        assert!(!sh(r#"kill -0 "$PPID""#));
        let mode = std::fs::metadata(&credential).unwrap().mode();
        run("chmod", &[os("777"), credential.as_os_str()]);
        assert_eq!(std::fs::metadata(&credential).unwrap().mode(), mode);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inspection_refuses_links_special_files_unsafe_names_and_caseless_conflicts() {
        let limits = Limits::default();
        let case = |build: &dyn Fn(&Path)| {
            let root = scratch("inspect");
            build(&root);
            let result = inspect_tree(&root, &limits);
            remove_tree(&root).unwrap();
            result
        };
        let write = |root: &Path, rel: &str, bytes: &[u8]| {
            let path = root.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        };
        let staged = case(&|r| {
            write(r, "Meshes/a.nif", b"same");
            write(r, "meshes/A.nif", b"same");
            write(r, "Textures/b.dds", b"other");
        })
        .unwrap();
        assert_eq!((staged.entries, staged.bytes), (6, 13));

        let refused = |build: &dyn Fn(&Path)| code(&case(build).unwrap_err());
        assert_eq!(
            refused(&|r| std::os::unix::fs::symlink("/etc/hostname", r.join("link")).unwrap()),
            RefusalCode::UnsupportedEntry
        );
        assert_eq!(
            refused(&|r| {
                write(r, "a.txt", b"x");
                std::fs::hard_link(r.join("a.txt"), r.join("b.txt")).unwrap();
            }),
            RefusalCode::UnsupportedEntry
        );
        assert_eq!(
            refused(&|r| {
                let c =
                    std::ffi::CString::new(r.join("pipe").as_os_str().as_encoded_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
            }),
            RefusalCode::UnsupportedEntry
        );
        for name in [
            "back\\slash.txt",
            "colon:stream.txt",
            "trailing.",
            "trailing ",
            "NUL.txt",
            "com1",
            "new\nline",
        ] {
            assert_eq!(
                refused(&|r| write(r, name, b"x")),
                RefusalCode::UnsafePath,
                "{name:?}"
            );
        }
        assert_eq!(
            refused(&|r| {
                write(r, "Meshes/a.nif", b"one");
                write(r, "meshes/A.nif", b"two");
            }),
            RefusalCode::AmbiguousPath
        );
        assert_eq!(
            refused(&|r| {
                write(r, "Data/thing", b"file");
                write(r, "data/Thing/inner.txt", b"x");
            }),
            RefusalCode::AmbiguousPath
        );
        // A directory the owner cannot enter is opened up, inspected and still removable.
        let staged = case(&|r| {
            write(r, "locked/inner.txt", b"x");
            std::fs::set_permissions(r.join("locked"), std::fs::Permissions::from_mode(0o000))
                .unwrap();
        })
        .unwrap();
        assert_eq!(staged.entries, 2);
    }

    #[test]
    fn inspection_enforces_count_size_depth_and_path_limits() {
        let case = |limits: Limits, files: &[(&str, usize)]| {
            let root = scratch("limits");
            for (rel, size) in files {
                let path = root.join(rel);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, vec![0u8; *size]).unwrap();
            }
            let result = inspect_tree(&root, &limits).map_err(|e| code(&e));
            remove_tree(&root).unwrap();
            result.err()
        };
        let four = [("a", 10), ("b", 10), ("c", 10), ("d", 10)];
        assert_eq!(case(Limits::default(), &four), None);
        assert_eq!(
            case(
                Limits {
                    max_entries: 3,
                    ..Default::default()
                },
                &four
            ),
            Some(RefusalCode::LimitExceeded)
        );
        assert_eq!(
            case(
                Limits {
                    max_total_bytes: 39,
                    ..Default::default()
                },
                &four
            ),
            Some(RefusalCode::LimitExceeded)
        );
        assert_eq!(
            case(
                Limits {
                    max_file_bytes: 9,
                    ..Default::default()
                },
                &four
            ),
            Some(RefusalCode::LimitExceeded)
        );
        assert_eq!(
            case(
                Limits {
                    max_depth: 2,
                    ..Default::default()
                },
                &[("one/two/three.txt", 1)]
            ),
            Some(RefusalCode::LimitExceeded)
        );
        assert_eq!(
            case(
                Limits {
                    max_depth: 3,
                    ..Default::default()
                },
                &[("one/two/three.txt", 1)]
            ),
            None
        );
        assert_eq!(
            case(
                Limits {
                    max_path_bytes: 10,
                    ..Default::default()
                },
                &[("long-directory/file.txt", 1)]
            ),
            Some(RefusalCode::LimitExceeded)
        );
    }

    #[test]
    fn staging_must_be_a_real_directory_only_its_owner_can_write() {
        let root = scratch("staging");
        let good = root.join("good");
        let dir = owned_staging(&good, "key").unwrap();
        assert_eq!(std::fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        // An interrupted run left a tree the owner cannot enter and a link. Both are cleared.
        std::fs::create_dir_all(dir.join("a0/locked")).unwrap();
        std::fs::write(dir.join("a0/locked/partial.bin"), b"partial").unwrap();
        std::os::unix::fs::symlink(&root, dir.join("a0/link")).unwrap();
        std::fs::set_permissions(
            dir.join("a0/locked"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
        let dir = owned_staging(&good, "key").unwrap();
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        assert!(
            root.is_dir(),
            "clearing staging must not follow the link out of it"
        );

        assert_eq!(
            code(&owned_staging(&good, "../escape").unwrap_err()),
            RefusalCode::UnapprovedIdentity
        );
        assert!(!root.join("escape").exists());
        let shared = root.join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            code(&owned_staging(&shared, "key").unwrap_err()),
            RefusalCode::StagingNotOwned
        );
        let linked = root.join("linked");
        std::os::unix::fs::symlink(&good, &linked).unwrap();
        assert_eq!(
            code(&owned_staging(&linked, "key").unwrap_err()),
            RefusalCode::StagingNotOwned
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_replaced_folder_is_never_missing_and_an_interrupted_replacement_recovers() {
        let root = scratch("activate");
        let write = |dir: &Path, text: &str| {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(dir.join("version.txt"), text).unwrap();
        };
        let read = || std::fs::read_to_string(root.join("Mod/version.txt")).unwrap();
        write(&assembly_dir(&root, "Mod"), "one");
        assert_eq!(activate_dir(&root, "Mod").unwrap(), "rename");
        write(&assembly_dir(&root, "Mod"), "two");
        assert_eq!(activate_dir(&root, "Mod").unwrap(), "exchange");
        assert_eq!(read(), "two");
        assert_eq!(
            std::fs::read_dir(&root).unwrap().count(),
            1,
            "the old version and the assembly directory are gone"
        );

        // A filesystem without an atomic exchange keeps the old folder until the new one is in.
        write(&assembly_dir(&root, "Mod"), "two, replaced");
        assert_eq!(activate_dir_with(&root, "Mod", false).unwrap(), "replace");
        assert_eq!(read(), "two, replaced");
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        write(&assembly_dir(&root, "Mod"), "two");
        activate_dir(&root, "Mod").unwrap();

        // Interrupted before the new folder was in place: the old one is restored.
        std::fs::rename(root.join("Mod"), root.join(".Mod.skyforge-old")).unwrap();
        write(&assembly_dir(&root, "Mod"), "three, incomplete");
        recover_dir(&root, "Mod").unwrap();
        assert_eq!(read(), "two");
        // Interrupted after the new folder was in place: only the leftovers are removed.
        write(&root.join(".Mod.skyforge-old"), "one");
        recover_dir(&root, "Mod").unwrap();
        assert_eq!(read(), "two");
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn executables_are_refused_unless_the_entry_allows_their_class() {
        let record = |path: &str, class| ExecRecord {
            path: path.into(),
            class,
            sha256: String::new(),
        };
        let plugin = record("skse/plugins/Thing.dll", ExecClass::SksePlugin);
        assert!(enforce_executables(&[], &[]).is_ok());
        let error = enforce_executables(std::slice::from_ref(&plugin), &[]).unwrap_err();
        assert_eq!(code(&error), RefusalCode::UnexpectedExecutable);
        assert!(
            error
                .to_string()
                .contains(r#"executables = ["skse-plugin"]"#),
            "{error}"
        );
        assert!(
            enforce_executables(std::slice::from_ref(&plugin), &[ExecClass::SksePlugin]).is_ok()
        );
        assert_eq!(
            code(
                &enforce_executables(
                    &[plugin, record("tool.exe", ExecClass::Program)],
                    &[ExecClass::SksePlugin]
                )
                .unwrap_err()
            ),
            RefusalCode::UnexpectedExecutable
        );
        let all = [
            ExecClass::SksePlugin,
            ExecClass::NativeLibrary,
            ExecClass::Program,
            ExecClass::Script,
            ExecClass::Disguised,
        ];
        assert_eq!(
            code(
                &enforce_executables(&[record("textures/a.dds", ExecClass::Disguised)], &all)
                    .unwrap_err()
            ),
            RefusalCode::UnexpectedExecutable
        );
    }
}
