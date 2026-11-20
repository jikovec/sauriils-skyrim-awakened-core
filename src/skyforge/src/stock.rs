//! Build the isolated Stock Game from Steam `download_depot` output.
//!
//! The Steam-managed installation is never modified. Depot folders are verified
//! (expected depots present, SkyrimSE.exe PE version), merged into the Stock Game
//! directory, and an inventory with SHA-256 for every file is written so the
//! folder can be re-verified at any time.

use crate::fetch::hash_file;
use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub const DEPOTS: &[&str] = &["489831", "489832", "489833"];

/// Read the fixed file version from a PE's VS_FIXEDFILEINFO.
pub fn pe_file_version(path: &Path) -> Result<(u16, u16, u16, u16)> {
    let b = std::fs::read(path)?;
    let sig = 0xFEEF04BDu32.to_le_bytes();
    let i = b
        .windows(4)
        .position(|w| w == sig)
        .ok_or_else(|| anyhow::anyhow!("no VS_FIXEDFILEINFO in {}", path.display()))?;
    let ms = u32::from_le_bytes(b[i + 8..i + 12].try_into()?);
    let ls = u32::from_le_bytes(b[i + 12..i + 16].try_into()?);
    Ok(((ms >> 16) as u16, ms as u16, (ls >> 16) as u16, ls as u16))
}

pub fn build(content_root: &Path, stock: &Path, expect: (u16, u16, u16, u16), steam_game: &Path) -> Result<BTreeMap<String, (u64, String)>> {
    if stock.canonicalize().ok() == steam_game.canonicalize().ok() {
        bail!("refusing to build the Stock Game inside the Steam installation");
    }
    let mut depot_dirs: Vec<PathBuf> = Vec::new();
    for d in DEPOTS {
        let p = content_root.join(format!("depot_{d}"));
        if !p.is_dir() {
            bail!("missing depot folder {}", p.display());
        }
        depot_dirs.push(p);
    }
    let exe = depot_dirs[2].join("SkyrimSE.exe");
    let v = pe_file_version(&exe).context("reading SkyrimSE.exe version from depot 489833")?;
    if v != expect {
        bail!("depot SkyrimSE.exe is {}.{}.{}.{}, expected {}.{}.{}.{}", v.0, v.1, v.2, v.3, expect.0, expect.1, expect.2, expect.3);
    }
    if stock.exists() && std::fs::read_dir(stock)?.next().is_some() {
        bail!("{} is not empty; refusing to merge into an existing folder", stock.display());
    }
    std::fs::create_dir_all(stock)?;
    // Merge depots in order; a later depot may only add files, never silently replace one.
    let mut origin: BTreeMap<String, String> = BTreeMap::new();
    for (i, dd) in depot_dirs.iter().enumerate() {
        for w in WalkDir::new(dd).into_iter().flatten().filter(|w| w.file_type().is_file()) {
            let rel = w.path().strip_prefix(dd)?.to_string_lossy().to_string();
            if rel.starts_with(".DepotDownloader") || rel.ends_with(".steam_manifest") {
                continue;
            }
            if let Some(prev) = origin.get(&rel.to_lowercase()) {
                bail!("{rel} provided by depot {prev} and depot {}", DEPOTS[i]);
            }
            let dest = stock.join(&rel);
            std::fs::create_dir_all(dest.parent().unwrap())?;
            std::fs::copy(w.path(), &dest).with_context(|| format!("copying {rel}"))?;
            origin.insert(rel.to_lowercase(), DEPOTS[i].to_string());
        }
    }
    // Lets SkyrimSE.exe initialise the Steam API directly instead of relaunching via Steam.
    std::fs::write(stock.join("steam_appid.txt"), "489830")?;
    let mut inv = BTreeMap::new();
    for w in WalkDir::new(stock).into_iter().flatten().filter(|w| w.file_type().is_file()) {
        let rel = w.path().strip_prefix(stock)?.to_string_lossy().to_string();
        let (_, sha, n) = hash_file(w.path())?;
        inv.insert(rel, (n, sha));
    }
    Ok(inv)
}

pub fn verify(stock: &Path, inventory: &BTreeMap<String, (u64, String)>) -> Result<Vec<String>> {
    let mut problems = Vec::new();
    for (rel, (n, sha)) in inventory {
        let p = stock.join(rel);
        if !p.exists() {
            problems.push(format!("missing {rel}"));
            continue;
        }
        let (_, s, len) = hash_file(&p)?;
        if len != *n || &s != sha {
            problems.push(format!("changed {rel}"));
        }
    }
    Ok(problems)
}

/// Let `dest` share `src`'s disk extents wherever their bytes are identical (FIDEDUPERANGE on
/// btrfs/XFS). The kernel compares each range before sharing it and refuses differing data, so
/// neither file's content can change; `src` is only opened for reading. Returns shared bytes.
pub fn dedupe_file(src: &Path, dest: &Path) -> Result<u64> {
    use std::os::fd::AsRawFd;
    #[repr(C)]
    struct RangeInfo {
        dest_fd: i64,
        dest_offset: u64,
        bytes_deduped: u64,
        status: i32,
        reserved: u32,
    }
    #[repr(C)]
    struct Range {
        src_offset: u64,
        src_length: u64,
        dest_count: u16,
        reserved1: u16,
        reserved2: u32,
        info: RangeInfo,
    }
    // _IOWR(0x94, 54, struct file_dedupe_range) with the 24-byte header.
    const FIDEDUPERANGE: libc::c_ulong = 0xC018_9436;
    // btrfs shares at most 16 MiB per call.
    const CHUNK: u64 = 16 << 20;

    let s = std::fs::File::open(src).with_context(|| format!("opening {}", src.display()))?;
    let d = std::fs::OpenOptions::new().read(true).write(true).open(dest).with_context(|| format!("opening {}", dest.display()))?;
    let len = s.metadata()?.len();
    if len != d.metadata()?.len() {
        return Ok(0);
    }
    let (mut off, mut shared) = (0u64, 0u64);
    while off < len {
        let mut r = Range {
            src_offset: off,
            src_length: CHUNK.min(len - off),
            dest_count: 1,
            reserved1: 0,
            reserved2: 0,
            info: RangeInfo { dest_fd: d.as_raw_fd() as i64, dest_offset: off, bytes_deduped: 0, status: 0, reserved: 0 },
        };
        // SAFETY: `r` is a correctly laid out file_dedupe_range with one info entry; both fds are open.
        let rc = unsafe { libc::ioctl(s.as_raw_fd(), FIDEDUPERANGE, &mut r as *mut Range) };
        if rc != 0 {
            bail!("FIDEDUPERANGE {}: {}", dest.display(), std::io::Error::last_os_error());
        }
        match r.info.status {
            0 if r.info.bytes_deduped > 0 => {
                shared += r.info.bytes_deduped;
                off += r.info.bytes_deduped;
            }
            // Nothing more can be shared (e.g. an unaligned tail).
            0 => break,
            // FILE_DEDUPE_RANGE_DIFFERS: this chunk differs; later chunks may still match.
            1 => off += r.src_length,
            e => bail!("FIDEDUPERANGE {}: {}", dest.display(), std::io::Error::from_raw_os_error(-e)),
        }
    }
    Ok(shared)
}

/// Deduplicate every inventoried Stock Game file against the same path (case-insensitive) in the
/// Steam installation. Returns (files fully shared, files partly shared, shared bytes).
pub fn dedupe(stock: &Path, steam_game: &Path, inventory: &BTreeMap<String, (u64, String)>) -> Result<(usize, usize, u64)> {
    let mut steam: BTreeMap<String, PathBuf> = BTreeMap::new();
    for w in WalkDir::new(steam_game).into_iter().flatten().filter(|w| w.file_type().is_file()) {
        let rel = w.path().strip_prefix(steam_game)?.to_string_lossy().to_lowercase();
        steam.insert(rel, w.path().to_path_buf());
    }
    let (mut full, mut partial, mut bytes) = (0, 0, 0u64);
    for (rel, (n, _)) in inventory {
        let Some(src) = steam.get(&rel.to_lowercase()) else { continue };
        let shared = dedupe_file(src, &stock.join(rel))?;
        if shared == 0 {
            continue;
        }
        bytes += shared;
        if shared >= *n { full += 1 } else { partial += 1 }
    }
    Ok((full, partial, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedupe_shares_identical_ranges_only() {
        let dir = std::env::temp_dir().join(format!("skyforge-dedupe-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let (a, b, c) = (dir.join("a"), dir.join("b"), dir.join("c"));
        let data: Vec<u8> = (0..(40u32 << 20)).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        std::fs::write(&a, &data).unwrap();
        std::fs::write(&b, &data).unwrap(); // an independent copy, not a reflink
        let mut other = data.clone();
        other[0] ^= 1;
        std::fs::write(&c, &other).unwrap();
        match dedupe_file(&a, &b) {
            Ok(n) => {
                assert_eq!(n, data.len() as u64);
                assert_eq!(std::fs::read(&b).unwrap(), data);
                // Only the first 16 MiB chunk differs; the rest is shared, content unchanged.
                assert_eq!(dedupe_file(&a, &c).unwrap(), data.len() as u64 - (16 << 20));
                assert_eq!(std::fs::read(&c).unwrap(), other);
                assert_eq!(std::fs::read(&a).unwrap(), data);
            }
            Err(e) => eprintln!("skipping: no dedupe support on this filesystem ({e:#})"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
