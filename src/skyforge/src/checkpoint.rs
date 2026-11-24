//! Coherent playthrough checkpoints.
//!
//! A checkpoint is one save pair and one database dump that belong to the same playthrough
//! and the same moment, with the identities needed to judge whether it can be restored. It is
//! captured and restored as a unit: a pair that does not match, a database that moved while it
//! was read, or a target that belongs to another playthrough is refused, and a refusal leaves
//! every earlier checkpoint and every target as it was.

use crate::admission::{free_bytes, remove_tree};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

/// How to reach one database. Skyforge runs these commands and reads their output; it holds
/// no connection, credential or table name of its own.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Lane {
    /// Runs one SQL text, appended as the last argument, and prints the result.
    pub query: Vec<String>,
    /// Writes a complete dump of the database to its standard output.
    pub dump: Vec<String>,
    /// Replaces the database with the dump on its standard input.
    pub restore: Vec<String>,
    /// SQL that prints the playthrough the database is bound to, or nothing when it has none.
    pub playthrough_sql: String,
    /// SQL that prints a value that changes whenever the playthrough's state is written.
    pub watermark_sql: String,
    /// SQL that prints the Unix time of the newest event, or nothing.
    pub last_event_sql: String,
    /// SQL that prints the schema version.
    pub schema_sql: String,
    /// SQL that prints one line per table with its row count, for the restore readback.
    pub tables_sql: String,
    /// Schema versions this lane can receive. Empty accepts only an exact readback match.
    pub accepts_schema: Vec<String>,
}

/// The `[checkpoint]` table of `skyforge.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    /// Directory that holds the checkpoints, relative to the workspace unless absolute.
    pub store: PathBuf,
    /// Save directory of the playthrough. Defaults to the managed profile's `saves`.
    pub saves: Option<PathBuf>,
    /// Free bytes that must remain on the store's filesystem after a capture.
    pub reserve_bytes: u64,
    /// Seconds by which the newest database event may follow the save and still belong to it.
    pub ahead_tolerance_seconds: i64,
    /// Process name of the running game. A capture is refused while it runs.
    pub game_process: String,
    /// Co-save plugin and record that hold the playthrough ID.
    pub cosave_plugin: String,
    pub cosave_record: String,
    /// Files whose digests identify the game, client and load order of this playthrough.
    pub identity: BTreeMap<String, PathBuf>,
    /// Further identities recorded as given, such as a model or policy revision.
    pub labels: BTreeMap<String, String>,
    pub lanes: BTreeMap<String, Lane>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            store: PathBuf::from("checkpoints/playthrough"),
            saves: None,
            reserve_bytes: 256 << 20,
            ahead_tolerance_seconds: 5,
            game_process: "SkyrimSE.exe".into(),
            cosave_plugin: "AIAG".into(),
            cosave_record: "AIPT".into(),
            identity: BTreeMap::new(),
            labels: BTreeMap::new(),
            lanes: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RefusalCode {
    /// A save without its co-save, or a co-save without its save.
    IncompletePair,
    /// The co-save holds no playthrough record, so nothing binds it to a database.
    NoPlaythroughRecord,
    /// The save, the database or the target belong to different playthroughs.
    MixedOwner,
    /// The game was running, or the save or the database changed during capture.
    NotQuiescent,
    /// The database holds events newer than the save.
    DatabaseAhead,
    /// Not enough free space for the capture and the reserve.
    InsufficientSpace,
    /// The checkpoint or one of its files does not exist.
    Missing,
    /// A file does not match its recorded digest, or the record is not valid.
    Corrupt,
    /// The restored database is not the state the record describes.
    WrongEpoch,
    /// The target cannot receive this schema version.
    IncompatibleSchema,
    /// The target already holds other state, or is the source itself.
    WouldOverwrite,
    /// A database command failed.
    LaneFailed,
}

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
        write!(f, "checkpoint refused ({code}): {}", self.detail)
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileProof {
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavePair {
    /// File name without extension, shared by the save and its co-save.
    pub name: String,
    pub save: FileProof,
    pub cosave: FileProof,
    /// Unix time the save was last written.
    pub modified_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Database {
    pub lane: String,
    pub dump: FileProof,
    pub watermark: String,
    pub last_event_at: Option<i64>,
    pub schema: String,
    /// Digest of the per-table row counts, compared again after a restore.
    pub tables_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coherence {
    /// `coherent`, or `database-ahead` when the owner accepted events newer than the save.
    pub state: String,
    /// Seconds by which the newest database event follows the save. This is the play that a
    /// restore of this checkpoint cannot bring back in the game.
    pub database_ahead_seconds: i64,
}

/// The record of one checkpoint, `checkpoint.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub id: String,
    pub created_at: String,
    pub playthrough: String,
    pub note: String,
    pub save: SavePair,
    pub database: Database,
    pub coherence: Coherence,
    pub identity: BTreeMap<String, FileProof>,
    pub labels: BTreeMap<String, String>,
    pub capture_seconds: f64,
}

/// What a restore did, printed for the operator and kept beside the restored saves.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreReport {
    pub checkpoint: String,
    pub playthrough: String,
    pub lane: String,
    pub started_at: String,
    #[serde(default)]
    pub completed_at: Option<String>,
    #[serde(default)]
    pub restore_seconds: f64,
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

/// The playthrough ID a client stored in an SKSE co-save: the first 32 bytes of `record` in
/// the block of `plugin`. `Ok(None)` means a well-formed co-save without that record.
pub fn cosave_playthrough(bytes: &[u8], plugin: &str, record: &str) -> Result<Option<String>> {
    let malformed = || {
        refuse(
            RefusalCode::Corrupt,
            "the co-save is not a well-formed SKSE co-save",
        )
    };
    if bytes.get(..4) != Some(b"SKSE".as_slice()) {
        return malformed();
    }
    let Some(plugins) = u32_at(bytes, 16) else {
        return malformed();
    };
    let mut at = 20usize;
    for _ in 0..plugins {
        let (Some(tag), Some(chunks), Some(length)) = (
            bytes.get(at..at + 4),
            u32_at(bytes, at + 4),
            u32_at(bytes, at + 8),
        ) else {
            return malformed();
        };
        let end = at + 12 + length as usize;
        if end > bytes.len() {
            return malformed();
        }
        let mut chunk = at + 12;
        for _ in 0..chunks {
            let (Some(kind), Some(size)) = (bytes.get(chunk..chunk + 4), u32_at(bytes, chunk + 8))
            else {
                return malformed();
            };
            let data = chunk + 12;
            if data + size as usize > end {
                return malformed();
            }
            if tag == plugin.as_bytes() && kind == record.as_bytes() {
                let id = bytes
                    .get(data..data + 32)
                    .filter(|_| size >= 32)
                    .and_then(|id| std::str::from_utf8(id).ok());
                return match id
                    .filter(|id| id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
                {
                    Some(id) => Ok(Some(id.to_owned())),
                    None => malformed(),
                };
            }
            chunk = data + size as usize;
        }
        at = end;
    }
    Ok(None)
}

fn proof(path: &Path) -> Result<FileProof> {
    let mut file = std::fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut size = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
        size += n as u64;
    }
    Ok(FileProof {
        sha256: hex::encode(hash.finalize()),
        size,
    })
}

/// Copy a file and return the digest of the bytes that were written.
fn copy_proved(from: &Path, to: &Path) -> Result<FileProof> {
    let mut source = std::fs::File::open(from)?;
    let mut target = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(to)?;
    let mut hash = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut size = 0u64;
    loop {
        let n = source.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
        target.write_all(&buf[..n])?;
        size += n as u64;
    }
    target.sync_all()?;
    Ok(FileProof {
        sha256: hex::encode(hash.finalize()),
        size,
    })
}

fn tail(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let clean: String = text
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .collect();
    let clean = clean.trim().replace('\n', "; ");
    clean
        .chars()
        .rev()
        .take(400)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect()
}

impl Lane {
    fn command(&self, argv: &[String], what: &str) -> Result<Command> {
        let Some((program, args)) = argv.split_first() else {
            return refuse(
                RefusalCode::LaneFailed,
                format!("the lane has no {what} command"),
            );
        };
        let mut command = Command::new(program);
        command.args(args);
        Ok(command)
    }

    /// Run one SQL text and return what it printed, trimmed.
    fn ask(&self, sql: &str, what: &str) -> Result<String> {
        if sql.is_empty() {
            return Ok(String::new());
        }
        let output = self
            .command(&self.query, "query")?
            .arg(sql)
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("running the {what} query"))?;
        if !output.status.success() {
            return refuse(
                RefusalCode::LaneFailed,
                format!("the {what} query failed: {}", tail(&output.stderr)),
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    /// Write the database dump to `to` and return its digest.
    fn dump_to(&self, to: &Path) -> Result<FileProof> {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(to)?;
        let output = self
            .command(&self.dump, "dump")?
            .stdin(Stdio::null())
            .stdout(file)
            .stderr(Stdio::piped())
            .output()
            .context("running the dump")?;
        if !output.status.success() {
            return refuse(
                RefusalCode::LaneFailed,
                format!("the dump failed: {}", tail(&output.stderr)),
            );
        }
        let proof = proof(to)?;
        if proof.size == 0 {
            return refuse(RefusalCode::LaneFailed, "the dump is empty");
        }
        Ok(proof)
    }

    fn restore_from(&self, from: &Path) -> Result<()> {
        let file = std::fs::File::open(from)?;
        let output = self
            .command(&self.restore, "restore")?
            .stdin(file)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .context("running the restore")?;
        if !output.status.success() {
            return refuse(
                RefusalCode::LaneFailed,
                format!("the restore failed: {}", tail(&output.stderr)),
            );
        }
        Ok(())
    }

    fn tables_digest(&self) -> Result<Option<String>> {
        let tables = self.ask(&self.tables_sql, "table count")?;
        Ok((!tables.is_empty()).then(|| hex::encode(Sha256::digest(tables.as_bytes()))))
    }
}

/// Whether a process with this name is running.
fn process_runs(name: &str) -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    entries.flatten().any(|entry| {
        entry
            .file_name()
            .to_string_lossy()
            .bytes()
            .all(|b| b.is_ascii_digit())
            && std::fs::read_to_string(entry.path().join("comm"))
                .is_ok_and(|comm| comm.trim_end() == name.chars().take(15).collect::<String>())
    })
}

/// One capture or restore at a time on a store. The lock is released when this is dropped.
struct StoreLock {
    _file: std::fs::File,
}

impl StoreLock {
    fn take(store: &Path) -> Result<Self> {
        std::fs::create_dir_all(store)?;
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(store.join(".lock"))?;
        // A process that is being started briefly shares every open descriptor, so a lock
        // that was just released can still read as held. Wait a moment before giving up.
        let deadline = Instant::now() + std::time::Duration::from_secs(3);
        // SAFETY: the descriptor is open for the duration of each call.
        while unsafe {
            libc::flock(
                std::os::fd::AsRawFd::as_raw_fd(&file),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        } != 0
        {
            if Instant::now() >= deadline {
                bail!(
                    "another checkpoint operation holds {}",
                    store.join(".lock").display()
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        Ok(StoreLock { _file: file })
    }
}

impl Settings {
    pub fn store_dir(&self, workspace: &Path) -> PathBuf {
        if self.store.is_absolute() {
            self.store.clone()
        } else {
            workspace.join(&self.store)
        }
    }

    fn lane(&self, name: &str) -> Result<&Lane> {
        match self.lanes.get(name) {
            Some(lane) => Ok(lane),
            None => refuse(
                RefusalCode::Missing,
                format!("no database lane named {name:?} is configured"),
            ),
        }
    }
}

fn stamp(path: &Path) -> Result<(u64, u64, i64, i64)> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_file() {
        return refuse(
            RefusalCode::IncompletePair,
            format!(
                "{} is not a regular file",
                path.file_name().unwrap_or_default().to_string_lossy()
            ),
        );
    }
    Ok((meta.ino(), meta.size(), meta.mtime(), meta.mtime_nsec()))
}

/// The save to capture: the named one, or the newest save in the directory.
fn choose_save(saves: &Path, name: Option<&str>) -> Result<String> {
    if let Some(name) = name {
        if name.contains(['/', '\\']) || name.is_empty() {
            return refuse(
                RefusalCode::Missing,
                "a save is named by its file name without extension",
            );
        }
        return Ok(name.to_owned());
    }
    let mut newest: Option<(i64, String)> = None;
    for entry in std::fs::read_dir(saves)
        .with_context(|| format!("reading {}", saves.display()))?
        .flatten()
    {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("ess") {
            continue;
        }
        let (Ok(meta), Some(stem)) = (entry.metadata(), path.file_stem().and_then(|s| s.to_str()))
        else {
            continue;
        };
        if newest.as_ref().is_none_or(|(time, _)| meta.mtime() > *time) {
            newest = Some((meta.mtime(), stem.to_owned()));
        }
    }
    match newest {
        Some((_, name)) => Ok(name),
        None => refuse(RefusalCode::Missing, "the save directory holds no save"),
    }
}

/// Capture a checkpoint of the newest (or named) save pair and the database of `lane_name`.
pub fn capture(
    workspace: &Path,
    settings: &Settings,
    saves: &Path,
    lane_name: &str,
    save: Option<&str>,
    accept_ahead: bool,
    note: &str,
) -> Result<Manifest> {
    let started = Instant::now();
    let lane = settings.lane(lane_name)?;
    let store = settings.store_dir(workspace);
    let _lock = StoreLock::take(&store)?;
    // A capture that was cut off left only a partial directory. It was never a checkpoint.
    for entry in std::fs::read_dir(&store)?.flatten() {
        if entry.file_name().to_string_lossy().starts_with(".partial-") {
            remove_tree(&entry.path())?;
        }
    }
    if process_runs(&settings.game_process) {
        return refuse(
            RefusalCode::NotQuiescent,
            format!(
                "{} is running; capture after the game has closed",
                settings.game_process
            ),
        );
    }

    let name = choose_save(saves, save)?;
    let (ess, skse) = (
        saves.join(format!("{name}.ess")),
        saves.join(format!("{name}.skse")),
    );
    for (path, what) in [(&ess, "save"), (&skse, "co-save")] {
        if std::fs::symlink_metadata(path).is_err() {
            return refuse(
                RefusalCode::IncompletePair,
                format!("{name}: the {what} is missing"),
            );
        }
    }
    let before = (stamp(&ess)?, stamp(&skse)?);
    let playthrough = match cosave_playthrough(
        &std::fs::read(&skse)?,
        &settings.cosave_plugin,
        &settings.cosave_record,
    )? {
        Some(id) => id,
        None => {
            return refuse(
                RefusalCode::NoPlaythroughRecord,
                format!("{name}: the co-save holds no playthrough record"),
            )
        }
    };

    let bound = lane.ask(&lane.playthrough_sql, "playthrough")?;
    if bound != playthrough {
        return refuse(
            RefusalCode::MixedOwner,
            format!(
                "the save belongs to playthrough {playthrough} and the database is bound to {}",
                if bound.is_empty() {
                    "none"
                } else {
                    bound.as_str()
                }
            ),
        );
    }
    let watermark = lane.ask(&lane.watermark_sql, "watermark")?;
    let last_event_at = lane
        .ask(&lane.last_event_sql, "newest event")?
        .parse::<i64>()
        .ok();
    let ahead = last_event_at.map_or(0, |at| at - before.0 .2);
    if ahead > settings.ahead_tolerance_seconds && !accept_ahead {
        return refuse(RefusalCode::DatabaseAhead, format!("the database holds events {ahead} seconds newer than the save; a restore would lose that play in the game"));
    }

    let needed = before.0 .1 + before.1 .1 + settings.reserve_bytes;
    if free_bytes(&store).is_some_and(|free| free < needed) {
        return refuse(
            RefusalCode::InsufficientSpace,
            format!("the store needs {needed} free bytes for the save pair and its reserve"),
        );
    }

    let created = chrono::Utc::now();
    let id = format!("{}-{}", created.format("%Y%m%dT%H%M%SZ"), &playthrough[..8]);
    if store.join(&id).exists() {
        return refuse(
            RefusalCode::WouldOverwrite,
            format!("checkpoint {id} already exists"),
        );
    }
    let partial = store.join(format!(".partial-{id}"));
    std::fs::create_dir_all(partial.join("save"))?;
    let outcome = (|| -> Result<Manifest> {
        let dump = lane.dump_to(&partial.join("database.dump"))?;
        if free_bytes(&store).is_some_and(|free| free < settings.reserve_bytes) {
            return refuse(
                RefusalCode::InsufficientSpace,
                "the dump left less than the reserve free",
            );
        }
        let schema = lane.ask(&lane.schema_sql, "schema")?;
        let tables_sha256 = lane.tables_digest()?;
        // The fence: nothing the checkpoint describes may have moved while it was read.
        if lane.ask(&lane.watermark_sql, "watermark")? != watermark
            || lane.ask(&lane.playthrough_sql, "playthrough")? != playthrough
        {
            return refuse(
                RefusalCode::NotQuiescent,
                "the database changed while it was being captured",
            );
        }
        let save_proof = copy_proved(&ess, &partial.join("save").join(format!("{name}.ess")))?;
        let cosave_proof = copy_proved(&skse, &partial.join("save").join(format!("{name}.skse")))?;
        if (stamp(&ess)?, stamp(&skse)?) != before || process_runs(&settings.game_process) {
            return refuse(
                RefusalCode::NotQuiescent,
                "the save changed or the game started during capture",
            );
        }
        let mut identity = BTreeMap::new();
        for (label, path) in &settings.identity {
            let path = if path.is_absolute() {
                path.clone()
            } else {
                workspace.join(path)
            };
            identity.insert(
                label.clone(),
                proof(&path).with_context(|| format!("reading the identity file {label}"))?,
            );
        }
        let manifest = Manifest {
            version: 1,
            id: id.clone(),
            created_at: created.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            playthrough: playthrough.clone(),
            note: note.to_owned(),
            save: SavePair {
                name: name.clone(),
                save: save_proof,
                cosave: cosave_proof,
                modified_at: before.0 .2,
            },
            database: Database {
                lane: lane_name.to_owned(),
                dump,
                watermark: watermark.clone(),
                last_event_at,
                schema,
                tables_sha256,
            },
            coherence: Coherence {
                state: if ahead > settings.ahead_tolerance_seconds {
                    "database-ahead"
                } else {
                    "coherent"
                }
                .into(),
                database_ahead_seconds: ahead.max(0),
            },
            identity,
            labels: settings.labels.clone(),
            capture_seconds: started.elapsed().as_secs_f64(),
        };
        std::fs::write(
            partial.join("checkpoint.json"),
            serde_json::to_string_pretty(&manifest)? + "\n",
        )?;
        Ok(manifest)
    })();
    match outcome {
        Ok(manifest) => {
            // The checkpoint exists from this rename on, complete or not at all.
            std::fs::rename(&partial, store.join(&id))?;
            Ok(manifest)
        }
        Err(error) => {
            remove_tree(&partial).ok();
            Err(error)
        }
    }
}

/// Read a checkpoint and confirm every file against its record.
pub fn verify(store: &Path, id: &str, settings: &Settings) -> Result<Manifest> {
    if id.contains(['/', '\\']) || id.starts_with('.') || id.is_empty() {
        return refuse(RefusalCode::Missing, "a checkpoint is named by its ID");
    }
    let dir = store.join(id);
    let text = match std::fs::read_to_string(dir.join("checkpoint.json")) {
        Ok(text) => text,
        Err(_) => {
            return refuse(
                RefusalCode::Missing,
                format!("checkpoint {id} does not exist or has no record"),
            )
        }
    };
    let manifest: Manifest = match serde_json::from_str(&text) {
        Ok(manifest) => manifest,
        Err(error) => {
            return refuse(
                RefusalCode::Corrupt,
                format!("the record of {id} is not valid: {error}"),
            )
        }
    };
    if manifest.version != 1 || manifest.id != id {
        return refuse(
            RefusalCode::Corrupt,
            format!("the record of {id} names another version or checkpoint"),
        );
    }
    let name = &manifest.save.name;
    if name.contains(['/', '\\']) || name.is_empty() {
        return refuse(
            RefusalCode::Corrupt,
            "the record names a save outside the checkpoint",
        );
    }
    let files = [
        (
            dir.join("save").join(format!("{name}.ess")),
            &manifest.save.save,
            "save",
        ),
        (
            dir.join("save").join(format!("{name}.skse")),
            &manifest.save.cosave,
            "co-save",
        ),
        (
            dir.join("database.dump"),
            &manifest.database.dump,
            "database dump",
        ),
    ];
    for (path, recorded, what) in &files {
        if std::fs::symlink_metadata(path).is_err() {
            return refuse(
                RefusalCode::Missing,
                format!("checkpoint {id} has no {what}"),
            );
        }
        if proof(path)? != **recorded {
            return refuse(
                RefusalCode::Corrupt,
                format!("the {what} of {id} does not match its recorded digest"),
            );
        }
    }
    let cosave = std::fs::read(&files[1].0)?;
    if cosave_playthrough(&cosave, &settings.cosave_plugin, &settings.cosave_record)?.as_deref()
        != Some(manifest.playthrough.as_str())
    {
        return refuse(
            RefusalCode::MixedOwner,
            format!("the co-save of {id} belongs to another playthrough than its record"),
        );
    }
    Ok(manifest)
}

/// Every complete checkpoint in the store, oldest first. Unreadable records are skipped.
pub fn list(store: &Path) -> Vec<Manifest> {
    let mut found: Vec<Manifest> = std::fs::read_dir(store)
        .map(|entries| {
            entries
                .flatten()
                .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
                .filter_map(|e| std::fs::read_to_string(e.path().join("checkpoint.json")).ok())
                .filter_map(|text| serde_json::from_str(&text).ok())
                .collect()
        })
        .unwrap_or_default();
    found.sort_by(|a, b| a.id.cmp(&b.id));
    found
}

/// Checkpoints that retention would remove: everything older than the newest `keep` that
/// still verify. A checkpoint that fails verification is never counted as kept and never
/// removed here, so damage stays visible. With `apply` the listed ones are deleted.
pub fn prune(store: &Path, settings: &Settings, keep: usize, apply: bool) -> Result<Vec<String>> {
    let _lock = StoreLock::take(store)?;
    let verified: Vec<String> = list(store)
        .into_iter()
        .filter(|m| verify(store, &m.id, settings).is_ok())
        .map(|m| m.id)
        .collect();
    // The newest verified checkpoint is the recovery point. It is kept whatever `keep` says.
    let surplus = verified.len().saturating_sub(keep.max(1));
    let remove: Vec<String> = verified.into_iter().take(surplus).collect();
    if apply {
        for id in &remove {
            remove_tree(&store.join(id))?;
        }
    }
    Ok(remove)
}

fn same_place(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// Restore a checkpoint into an independent save directory and database lane. The checkpoint
/// itself is only read. The live save directory and the lane it was captured from are refused.
pub fn restore(
    workspace: &Path,
    settings: &Settings,
    live_saves: &Path,
    id: &str,
    target_saves: &Path,
    lane_name: &str,
) -> Result<RestoreReport> {
    let started = Instant::now();
    let store = settings.store_dir(workspace);
    let _lock = StoreLock::take(&store)?;
    let manifest = verify(&store, id, settings)?;
    let lane = settings.lane(lane_name)?;
    if lane_name == manifest.database.lane || same_place(target_saves, live_saves) {
        return refuse(RefusalCode::WouldOverwrite, "this command restores only into an independent save directory and database lane, never over the source");
    }
    if !lane.accepts_schema.is_empty() && !lane.accepts_schema.contains(&manifest.database.schema) {
        return refuse(
            RefusalCode::IncompatibleSchema,
            format!(
                "lane {lane_name} accepts schema {:?} and the checkpoint holds {:?}",
                lane.accepts_schema, manifest.database.schema
            ),
        );
    }

    std::fs::create_dir_all(target_saves)?;
    let journal_path = target_saves.join(".skyforge-restore.json");
    let earlier: Option<RestoreReport> = std::fs::read_to_string(&journal_path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok());
    let resuming = earlier
        .as_ref()
        .is_some_and(|j| j.checkpoint == manifest.id && j.lane == lane_name);
    if let Some(other) = earlier
        .as_ref()
        .filter(|j| !resuming && j.completed_at.is_none())
    {
        return refuse(
            RefusalCode::WouldOverwrite,
            format!(
                "an unfinished restore of checkpoint {} owns this save directory",
                other.checkpoint
            ),
        );
    }
    // The target must be empty or already this playthrough's; nothing in it is overwritten.
    let name = &manifest.save.name;
    let source = store.join(id).join("save");
    for entry in std::fs::read_dir(target_saves)?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("skse") {
            continue;
        }
        let owner = cosave_playthrough(
            &std::fs::read(&path)?,
            &settings.cosave_plugin,
            &settings.cosave_record,
        )
        .unwrap_or(None);
        if owner
            .as_deref()
            .is_some_and(|owner| owner != manifest.playthrough)
        {
            return refuse(
                RefusalCode::MixedOwner,
                "the target save directory holds saves of another playthrough",
            );
        }
    }
    for (file, recorded) in [
        (format!("{name}.ess"), &manifest.save.save),
        (format!("{name}.skse"), &manifest.save.cosave),
    ] {
        let target = target_saves.join(&file);
        if std::fs::symlink_metadata(&target).is_ok() && proof(&target)? != *recorded {
            return refuse(
                RefusalCode::WouldOverwrite,
                format!("the target already holds a different {file}"),
            );
        }
    }
    let bound = lane.ask(&lane.playthrough_sql, "playthrough")?;
    if !bound.is_empty() && !resuming {
        let (code, what) = if bound == manifest.playthrough {
            (RefusalCode::WouldOverwrite, "this playthrough already")
        } else {
            (RefusalCode::MixedOwner, "another playthrough")
        };
        return refuse(
            code,
            format!("lane {lane_name} holds {what}; restore into an empty lane"),
        );
    }

    let mut report = RestoreReport {
        checkpoint: manifest.id.clone(),
        playthrough: manifest.playthrough.clone(),
        lane: lane_name.to_owned(),
        started_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        completed_at: None,
        restore_seconds: 0.0,
    };
    let write_journal = |report: &RestoreReport| -> Result<()> {
        Ok(std::fs::write(
            &journal_path,
            serde_json::to_string_pretty(report)? + "\n",
        )?)
    };
    write_journal(&report)?;

    // Database first: the saves appear only beside a database that was read back as theirs.
    lane.restore_from(&store.join(id).join("database.dump"))?;
    let readback = (
        lane.ask(&lane.playthrough_sql, "playthrough")?,
        lane.ask(&lane.watermark_sql, "watermark")?,
        lane.ask(&lane.schema_sql, "schema")?,
        lane.tables_digest()?,
    );
    if readback.0 != manifest.playthrough {
        return refuse(
            RefusalCode::MixedOwner,
            "the restored database is bound to another playthrough than the record",
        );
    }
    if readback.1 != manifest.database.watermark || readback.3 != manifest.database.tables_sha256 {
        return refuse(
            RefusalCode::WrongEpoch,
            "the restored database is not the state the record describes",
        );
    }
    if readback.2 != manifest.database.schema {
        return refuse(
            RefusalCode::IncompatibleSchema,
            format!(
                "the restored database reports schema {:?}, the record {:?}",
                readback.2, manifest.database.schema
            ),
        );
    }
    for (file, recorded) in [
        (format!("{name}.ess"), &manifest.save.save),
        (format!("{name}.skse"), &manifest.save.cosave),
    ] {
        let target = target_saves.join(&file);
        if std::fs::symlink_metadata(&target).is_ok() {
            continue;
        }
        let temporary = target_saves.join(format!(".{file}.skyforge-restore"));
        remove_tree(&temporary)?;
        if copy_proved(&source.join(&file), &temporary)? != *recorded {
            remove_tree(&temporary).ok();
            return refuse(
                RefusalCode::Corrupt,
                format!("{file} changed while it was being restored"),
            );
        }
        std::fs::rename(&temporary, &target)?;
    }
    report.completed_at =
        Some(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    report.restore_seconds = started.elapsed().as_secs_f64();
    write_journal(&report)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::testkit::scratch;
    use std::os::unix::fs::PermissionsExt;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2";

    /// A synthetic SKSE co-save: one unrelated plugin block, then optionally the client's
    /// block with a playthrough record.
    fn cosave(playthrough: Option<&str>) -> Vec<u8> {
        let block = |tag: &[u8; 4], chunks: &[(&[u8; 4], u32, Vec<u8>)]| {
            let mut body = Vec::new();
            for (kind, version, data) in chunks {
                body.extend_from_slice(*kind);
                body.extend_from_slice(&version.to_le_bytes());
                body.extend_from_slice(&(data.len() as u32).to_le_bytes());
                body.extend_from_slice(data);
            }
            let mut out = tag.to_vec();
            out.extend_from_slice(&(chunks.len() as u32).to_le_bytes());
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&body);
            out
        };
        let mut blocks = vec![block(b"OTHR", &[(b"DATA", 1, vec![7; 9])])];
        if let Some(id) = playthrough {
            let mut record = id.as_bytes().to_vec();
            record.push(0);
            blocks.push(block(
                b"AIAG",
                &[(b"AIPT", 2, record), (b"AIAC", 0, vec![0; 8])],
            ));
        }
        let mut out = b"SKSE".to_vec();
        for word in [1u32, 0x0202_0080, 0x0106_4920, blocks.len() as u32] {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out.extend(blocks.concat());
        out
    }

    /// A stand-in database: a directory with one file per fact, reached through a shell
    /// script the way a real lane is reached through its commands.
    struct World {
        root: PathBuf,
        saves: PathBuf,
        settings: Settings,
    }

    impl World {
        fn new() -> Self {
            let root = scratch("checkpoint");
            let saves = root.join("live-saves");
            std::fs::create_dir_all(&saves).unwrap();
            let script = root.join("lane.sh");
            std::fs::write(
                &script,
                r#"#!/bin/sh
# usage: lane.sh <database directory> query <sql> | dump | restore
db=$1; action=$2
case "$action" in
query)
    [ -e "$db/broken" ] && { echo "connection refused" >&2; exit 2; }
    case "$3" in
    playthrough|watermark|last_event|schema|tables) cat "$db/$3" 2>/dev/null; exit 0 ;;
    *) echo "unknown query" >&2; exit 2 ;;
    esac ;;
dump)
    [ -e "$db/dump-fails" ] && { printf 'partial'; echo "dump interrupted" >&2; exit 1; }
    for f in playthrough watermark last_event schema tables rows; do
        printf '%s=%s\n' "$f" "$(cat "$db/$f" 2>/dev/null)"
    done
    [ -e "$db/moves-during-dump" ] && echo moved > "$db/watermark"
    exit 0 ;;
restore)
    [ -e "$db/restore-fails-once" ] && { rm "$db/restore-fails-once"; echo "restore interrupted" >&2; exit 1; }
    mkdir -p "$db"
    while IFS='=' read -r key value; do printf '%s' "$value" > "$db/$key"; done
    exit 0 ;;
esac
exit 2
"#,
            )
            .unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
            let lane = |name: &str| {
                let base = [
                    "sh".to_string(),
                    script.to_string_lossy().into_owned(),
                    root.join(name).to_string_lossy().into_owned(),
                ];
                let with = |action: &str| {
                    base.iter()
                        .cloned()
                        .chain([action.to_string()])
                        .collect::<Vec<_>>()
                };
                Lane {
                    query: with("query"),
                    dump: with("dump"),
                    restore: with("restore"),
                    playthrough_sql: "playthrough".into(),
                    watermark_sql: "watermark".into(),
                    last_event_sql: "last_event".into(),
                    schema_sql: "schema".into(),
                    tables_sql: "tables".into(),
                    accepts_schema: Vec::new(),
                }
            };
            let mut settings = Settings {
                store: root.join("store"),
                reserve_bytes: 0,
                // No process has this name, so the game never appears to be running.
                game_process: "no-such-game".into(),
                ..Default::default()
            };
            for name in ["play", "spare", "other"] {
                settings.lanes.insert(name.into(), lane(name));
            }
            let world = World {
                root,
                saves,
                settings,
            };
            world.database("play", A, "41|12", 1_000);
            world.save("Save1", A, 1_000);
            world
        }

        fn database(&self, lane: &str, playthrough: &str, watermark: &str, last_event: i64) {
            let db = self.root.join(lane);
            std::fs::create_dir_all(&db).unwrap();
            for (file, value) in [
                ("playthrough", playthrough),
                ("watermark", watermark),
                ("last_event", &last_event.to_string()),
                ("schema", "2026101319"),
                ("tables", "eventlog|12;speech|3"),
                ("rows", "synthetic rows"),
            ] {
                std::fs::write(db.join(file), value).unwrap();
            }
        }

        fn save(&self, name: &str, playthrough: &str, modified_at: i64) {
            let time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(modified_at as u64);
            for (ext, bytes) in [
                ("ess", format!("save {name}").into_bytes()),
                ("skse", cosave(Some(playthrough))),
            ] {
                let path = self.saves.join(format!("{name}.{ext}"));
                std::fs::write(&path, bytes).unwrap();
                std::fs::File::options()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_modified(time)
                    .unwrap();
            }
        }

        fn capture(&self) -> Result<Manifest> {
            capture(
                &self.root,
                &self.settings,
                &self.saves,
                "play",
                None,
                false,
                "test",
            )
        }

        fn store(&self) -> PathBuf {
            self.settings.store_dir(&self.root)
        }

        fn restore(&self, id: &str, target: &str, lane: &str) -> Result<RestoreReport> {
            restore(
                &self.root,
                &self.settings,
                &self.saves,
                id,
                &self.root.join(target),
                lane,
            )
        }

        fn entries(&self) -> Vec<String> {
            let mut names: Vec<String> = std::fs::read_dir(self.store())
                .map(|d| {
                    d.flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .filter(|n| n != ".lock")
                        .collect()
                })
                .unwrap_or_default();
            names.sort();
            names
        }
    }

    impl Drop for World {
        fn drop(&mut self) {
            remove_tree(&self.root).ok();
        }
    }

    fn code<T>(result: Result<T>) -> RefusalCode {
        let error = result.err().expect("must be refused");
        error
            .chain()
            .find_map(|e| e.downcast_ref::<Refusal>())
            .unwrap_or_else(|| panic!("not a refusal: {error:#}"))
            .code
    }

    #[test]
    fn the_playthrough_record_is_read_from_a_cosave() {
        assert_eq!(
            cosave_playthrough(&cosave(Some(A)), "AIAG", "AIPT")
                .unwrap()
                .as_deref(),
            Some(A)
        );
        assert_eq!(
            cosave_playthrough(&cosave(None), "AIAG", "AIPT").unwrap(),
            None
        );
        for broken in [
            b"NOPE".to_vec(),
            cosave(Some(A))[..40].to_vec(),
            cosave(Some("not hex, not an identifier!!!!!!")),
        ] {
            assert_eq!(
                code(cosave_playthrough(&broken, "AIAG", "AIPT")),
                RefusalCode::Corrupt
            );
        }
    }

    #[test]
    fn a_coherent_pair_is_captured_verified_and_listed() {
        let w = World::new();
        w.save("Older", A, 500);
        let m = w.capture().unwrap();
        assert_eq!(
            (m.version, m.playthrough.as_str(), m.save.name.as_str()),
            (1, A, "Save1"),
            "the newest save is chosen"
        );
        assert_eq!(
            (
                m.coherence.state.as_str(),
                m.coherence.database_ahead_seconds
            ),
            ("coherent", 0)
        );
        assert_eq!(
            (
                m.database.lane.as_str(),
                m.database.watermark.as_str(),
                m.database.schema.as_str()
            ),
            ("play", "41|12", "2026101319")
        );
        assert!(m.database.tables_sha256.is_some() && m.id.ends_with(&A[..8]));
        let verified = verify(&w.store(), &m.id, &w.settings).unwrap();
        assert_eq!(verified.save.save, m.save.save);
        assert_eq!(list(&w.store()).len(), 1);
        assert_eq!(
            w.entries(),
            vec![m.id.clone()],
            "no partial directory remains"
        );
        // The live saves and the database are only read.
        assert_eq!(
            std::fs::read(w.saves.join("Save1.ess")).unwrap(),
            b"save Save1"
        );
        assert_eq!(
            std::fs::read_to_string(w.root.join("play/watermark")).unwrap(),
            "41|12"
        );
    }

    #[test]
    fn a_pair_that_is_not_one_playthrough_at_rest_is_refused() {
        // Each case starts from a coherent world and breaks one thing.
        type Break = Box<dyn Fn(&mut World)>;
        let cases: Vec<(&str, RefusalCode, Break)> = vec![
            (
                "no co-save",
                RefusalCode::IncompletePair,
                Box::new(|w| std::fs::remove_file(w.saves.join("Save1.skse")).unwrap()),
            ),
            (
                "co-save without a playthrough record",
                RefusalCode::NoPlaythroughRecord,
                Box::new(|w| std::fs::write(w.saves.join("Save1.skse"), cosave(None)).unwrap()),
            ),
            (
                "database of another playthrough",
                RefusalCode::MixedOwner,
                Box::new(|w| w.database("play", B, "41|12", 1_000)),
            ),
            (
                "database bound to no playthrough",
                RefusalCode::MixedOwner,
                Box::new(|w| w.database("play", "", "41|12", 1_000)),
            ),
            (
                "database newer than the save",
                RefusalCode::DatabaseAhead,
                Box::new(|w| w.database("play", A, "58|19", 1_400)),
            ),
            (
                "database written during the dump",
                RefusalCode::NotQuiescent,
                Box::new(|w| std::fs::write(w.root.join("play/moves-during-dump"), "").unwrap()),
            ),
            (
                "game running",
                RefusalCode::NotQuiescent,
                Box::new(|w| {
                    w.settings.game_process = std::fs::read_to_string("/proc/self/comm")
                        .unwrap()
                        .trim()
                        .to_owned()
                }),
            ),
            (
                "no room for the reserve",
                RefusalCode::InsufficientSpace,
                Box::new(|w| w.settings.reserve_bytes = u64::MAX / 2),
            ),
            (
                "dump cut off",
                RefusalCode::LaneFailed,
                Box::new(|w| std::fs::write(w.root.join("play/dump-fails"), "").unwrap()),
            ),
            (
                "database unreachable",
                RefusalCode::LaneFailed,
                Box::new(|w| std::fs::write(w.root.join("play/broken"), "").unwrap()),
            ),
        ];
        for (name, expected, break_it) in cases {
            let mut w = World::new();
            // An earlier good checkpoint must survive every refused capture untouched.
            let earlier = w.capture().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(1100));
            break_it(&mut w);
            assert_eq!(code(w.capture()), expected, "{name}");
            assert_eq!(
                w.entries(),
                vec![earlier.id.clone()],
                "{name}: nothing partial is left"
            );
            if !w.root.join("play/broken").exists() {
                verify(&w.store(), &earlier.id, &w.settings)
                    .unwrap_or_else(|e| panic!("{name}: {e:#}"));
            }
        }
    }

    #[test]
    fn events_newer_than_the_save_are_recorded_only_when_accepted() {
        let w = World::new();
        w.database("play", A, "58|19", 1_400);
        assert_eq!(code(w.capture()), RefusalCode::DatabaseAhead);
        let m = capture(
            &w.root,
            &w.settings,
            &w.saves,
            "play",
            Some("Save1"),
            true,
            "after a crash",
        )
        .unwrap();
        assert_eq!(
            (
                m.coherence.state.as_str(),
                m.coherence.database_ahead_seconds
            ),
            ("database-ahead", 400)
        );
        assert_eq!(m.note, "after a crash");
    }

    #[test]
    fn a_cut_off_capture_leaves_nothing_that_looks_like_a_checkpoint() {
        let w = World::new();
        let partial = w.store().join(".partial-20261124T000000Z-aaaaaaaa");
        std::fs::create_dir_all(partial.join("save")).unwrap();
        std::fs::write(partial.join("database.dump"), "half").unwrap();
        assert!(list(&w.store()).is_empty());
        assert_eq!(
            code(verify(
                &w.store(),
                ".partial-20261124T000000Z-aaaaaaaa",
                &w.settings
            )),
            RefusalCode::Missing
        );
        let m = w.capture().unwrap();
        assert_eq!(
            w.entries(),
            vec![m.id],
            "the next capture clears the leftover"
        );
    }

    #[test]
    fn a_checkpoint_restores_into_an_independent_profile_and_database() {
        let w = World::new();
        let m = w.capture().unwrap();
        let report = w.restore(&m.id, "restored-saves", "spare").unwrap();
        assert_eq!(
            (
                report.checkpoint.as_str(),
                report.playthrough.as_str(),
                report.lane.as_str()
            ),
            (m.id.as_str(), A, "spare")
        );
        assert!(report.completed_at.is_some());
        // Exact save pair, exact owner, exact watermark, and every fact of the source database.
        for ext in ["ess", "skse"] {
            assert_eq!(
                std::fs::read(w.root.join(format!("restored-saves/Save1.{ext}"))).unwrap(),
                std::fs::read(w.saves.join(format!("Save1.{ext}"))).unwrap()
            );
        }
        for fact in [
            "playthrough",
            "watermark",
            "last_event",
            "schema",
            "tables",
            "rows",
        ] {
            assert_eq!(
                std::fs::read_to_string(w.root.join("spare").join(fact)).unwrap(),
                std::fs::read_to_string(w.root.join("play").join(fact)).unwrap(),
                "{fact}"
            );
        }
        // The checkpoint and the live playthrough are untouched, and a repeat is harmless.
        verify(&w.store(), &m.id, &w.settings).unwrap();
        assert_eq!(
            std::fs::read_to_string(w.root.join("play/watermark")).unwrap(),
            "41|12"
        );
        assert!(w.restore(&m.id, "restored-saves", "spare").is_ok());
    }

    #[test]
    fn a_restore_refuses_material_or_targets_that_do_not_fit() {
        let checkpoint_file = |w: &World, id: &str, rel: &str| w.store().join(id).join(rel);
        type Break = Box<dyn Fn(&mut World, &str)>;
        let cases: Vec<(&str, RefusalCode, Break)> = vec![
            (
                "missing dump",
                RefusalCode::Missing,
                Box::new(move |w, id| {
                    std::fs::remove_file(checkpoint_file(w, id, "database.dump")).unwrap()
                }),
            ),
            (
                "missing co-save",
                RefusalCode::Missing,
                Box::new(move |w, id| {
                    std::fs::remove_file(checkpoint_file(w, id, "save/Save1.skse")).unwrap()
                }),
            ),
            (
                "changed dump",
                RefusalCode::Corrupt,
                Box::new(move |w, id| {
                    std::fs::write(checkpoint_file(w, id, "database.dump"), "other bytes").unwrap()
                }),
            ),
            (
                "changed save",
                RefusalCode::Corrupt,
                Box::new(move |w, id| {
                    std::fs::write(checkpoint_file(w, id, "save/Save1.ess"), "other save").unwrap()
                }),
            ),
            (
                "record of another version",
                RefusalCode::Corrupt,
                Box::new(move |w, id| {
                    let path = checkpoint_file(w, id, "checkpoint.json");
                    std::fs::write(
                        &path,
                        std::fs::read_to_string(&path)
                            .unwrap()
                            .replace("\"version\": 1", "\"version\": 2"),
                    )
                    .unwrap();
                }),
            ),
            (
                "co-save of another playthrough with a matching digest",
                RefusalCode::MixedOwner,
                Box::new(move |w, id| {
                    // Someone swaps in another playthrough's co-save and edits the record to match its digest.
                    let other = cosave(Some(B));
                    std::fs::write(checkpoint_file(w, id, "save/Save1.skse"), &other).unwrap();
                    let path = checkpoint_file(w, id, "checkpoint.json");
                    let mut m: Manifest =
                        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
                    m.save.cosave = FileProof {
                        sha256: hex::encode(Sha256::digest(&other)),
                        size: other.len() as u64,
                    };
                    std::fs::write(&path, serde_json::to_string_pretty(&m).unwrap()).unwrap();
                }),
            ),
            (
                "record that claims another moment",
                RefusalCode::WrongEpoch,
                Box::new(move |w, id| {
                    let path = checkpoint_file(w, id, "checkpoint.json");
                    std::fs::write(
                        &path,
                        std::fs::read_to_string(&path)
                            .unwrap()
                            .replace("41|12", "99|99"),
                    )
                    .unwrap();
                }),
            ),
            (
                "schema the lane does not accept",
                RefusalCode::IncompatibleSchema,
                Box::new(|w, _| {
                    w.settings.lanes.get_mut("spare").unwrap().accepts_schema =
                        vec!["2027010100".into()]
                }),
            ),
            (
                "target saves of another playthrough",
                RefusalCode::MixedOwner,
                Box::new(|w, _| {
                    std::fs::create_dir_all(w.root.join("restored-saves")).unwrap();
                    std::fs::write(w.root.join("restored-saves/Other.skse"), cosave(Some(B)))
                        .unwrap();
                }),
            ),
            (
                "target holds a different file of that name",
                RefusalCode::WouldOverwrite,
                Box::new(|w, _| {
                    std::fs::create_dir_all(w.root.join("restored-saves")).unwrap();
                    std::fs::write(w.root.join("restored-saves/Save1.ess"), "a different save")
                        .unwrap();
                }),
            ),
            (
                "target lane of another playthrough",
                RefusalCode::MixedOwner,
                Box::new(|w, _| w.database("spare", B, "7|7", 10)),
            ),
            (
                "target lane already holds this playthrough",
                RefusalCode::WouldOverwrite,
                Box::new(|w, _| w.database("spare", A, "90|40", 5_000)),
            ),
        ];
        for (name, expected, break_it) in cases {
            let mut w = World::new();
            let m = w.capture().unwrap();
            break_it(&mut w, &m.id);
            assert_eq!(
                code(w.restore(&m.id, "restored-saves", "spare")),
                expected,
                "{name}"
            );
            assert!(
                !w.root.join("restored-saves/Save1.skse").exists(),
                "{name}: no save appears beside a refused database"
            );
            assert_eq!(
                std::fs::read_to_string(w.root.join("play/watermark")).unwrap(),
                "41|12",
                "{name}: the source is untouched"
            );
        }
        // The source itself is never a restore target, and an unknown checkpoint is missing.
        let w = World::new();
        let m = w.capture().unwrap();
        assert_eq!(
            code(w.restore(&m.id, "restored-saves", "play")),
            RefusalCode::WouldOverwrite
        );
        assert_eq!(
            code(w.restore(&m.id, "live-saves", "spare")),
            RefusalCode::WouldOverwrite
        );
        assert_eq!(
            code(w.restore("20200101T000000Z-aaaaaaaa", "restored-saves", "spare")),
            RefusalCode::Missing
        );
        assert_eq!(
            code(w.restore("../store", "restored-saves", "spare")),
            RefusalCode::Missing
        );
    }

    #[test]
    fn an_interrupted_restore_is_retried_from_the_untouched_checkpoint() {
        let w = World::new();
        let m = w.capture().unwrap();
        std::fs::create_dir_all(w.root.join("spare")).unwrap();
        std::fs::write(w.root.join("spare/restore-fails-once"), "").unwrap();
        assert_eq!(
            code(w.restore(&m.id, "restored-saves", "spare")),
            RefusalCode::LaneFailed
        );
        // Cut off after the journal and before the database: no save has appeared.
        let journal: RestoreReport = serde_json::from_str(
            &std::fs::read_to_string(w.root.join("restored-saves/.skyforge-restore.json")).unwrap(),
        )
        .unwrap();
        assert!(
            journal.completed_at.is_none() && !w.root.join("restored-saves/Save1.ess").exists()
        );
        verify(&w.store(), &m.id, &w.settings).unwrap();
        // Another checkpoint may not take over the half-restored target.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let second = w.capture().unwrap();
        assert_eq!(
            code(w.restore(&second.id, "restored-saves", "other")),
            RefusalCode::WouldOverwrite
        );
        // The same restore completes.
        let report = w.restore(&m.id, "restored-saves", "spare").unwrap();
        assert!(report.completed_at.is_some());
        assert_eq!(
            std::fs::read_to_string(w.root.join("spare/watermark")).unwrap(),
            "41|12"
        );
        assert_eq!(
            std::fs::read(w.root.join("restored-saves/Save1.ess")).unwrap(),
            b"save Save1"
        );
    }

    #[test]
    fn retention_keeps_the_newest_verified_checkpoints_and_never_the_last_one() {
        let w = World::new();
        let mut ids = Vec::new();
        for _ in 0..3 {
            ids.push(w.capture().unwrap().id);
            std::thread::sleep(std::time::Duration::from_millis(1100));
        }
        // A damaged checkpoint is neither counted as kept nor removed.
        std::fs::write(w.store().join(&ids[2]).join("database.dump"), "damaged").unwrap();
        assert_eq!(
            prune(&w.store(), &w.settings, 1, false).unwrap(),
            vec![ids[0].clone()],
            "a dry run lists and removes nothing"
        );
        assert_eq!(w.entries().len(), 3);
        assert_eq!(
            prune(&w.store(), &w.settings, 1, true).unwrap(),
            vec![ids[0].clone()]
        );
        assert_eq!(w.entries(), vec![ids[1].clone(), ids[2].clone()]);
        // Asking to keep none still keeps the one verified recovery point.
        assert!(prune(&w.store(), &w.settings, 0, true).unwrap().is_empty());
        verify(&w.store(), &ids[1], &w.settings).unwrap();
    }

    #[test]
    fn a_written_record_follows_the_published_contract() {
        use crate::admission::testkit::conforms;
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../../../contracts/checkpoint-v1.schema.json"))
                .unwrap();
        let fixtures: serde_json::Value =
            serde_json::from_str(include_str!("../../../contracts/fixtures/checkpoints.json"))
                .unwrap();
        for (name, fixture) in fixtures.as_object().unwrap() {
            conforms(&schema, &schema, fixture).unwrap_or_else(|e| panic!("fixture {name}: {e}"));
            // The fixtures are records this code can read back.
            serde_json::from_value::<Manifest>(fixture.clone())
                .unwrap_or_else(|e| panic!("fixture {name}: {e}"));
        }
        let mut w = World::new();
        std::fs::write(w.root.join("Game.exe"), "game binary").unwrap();
        w.settings
            .identity
            .insert("game".into(), PathBuf::from("Game.exe"));
        w.database("play", A, "58|19", 1_400);
        let m = capture(&w.root, &w.settings, &w.saves, "play", None, true, "").unwrap();
        let written: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(w.store().join(&m.id).join("checkpoint.json")).unwrap(),
        )
        .unwrap();
        conforms(&schema, &schema, &written).unwrap_or_else(|e| panic!("{e}\n{written:#}"));
        let mut extra = written.clone();
        extra["database"]["rows"] = "content".into();
        assert!(conforms(&schema, &schema, &extra).is_err());
    }

    #[test]
    fn the_configuration_names_lanes_and_identity_files() {
        let text = r#"
store = "checkpoints"
identity = { game = "stock/Game.exe" }
labels = { model = "fixture-model" }
[lanes.play]
query = ["psql", "-AtXc"]
dump = ["pg_dump", "-Fc"]
restore = ["pg_restore", "--clean"]
playthrough_sql = "select 1"
"#;
        let settings: Settings = toml::from_str(text).unwrap();
        assert_eq!(settings.lanes["play"].query, ["psql", "-AtXc"]);
        assert_eq!(
            (
                settings.game_process.as_str(),
                settings.cosave_record.as_str()
            ),
            ("SkyrimSE.exe", "AIPT")
        );
        assert!(toml::from_str::<Settings>("unknown_key = 1").is_err());
        // A capture hashes the configured identity files into the record.
        let mut w = World::new();
        std::fs::write(w.root.join("Game.exe"), "game binary").unwrap();
        w.settings
            .identity
            .insert("game".into(), PathBuf::from("Game.exe"));
        w.settings
            .labels
            .insert("model".into(), "fixture-model".into());
        let m = w.capture().unwrap();
        assert_eq!(
            m.identity["game"].sha256,
            hex::encode(Sha256::digest(b"game binary"))
        );
        assert_eq!(m.labels["model"], "fixture-model");
    }
}
