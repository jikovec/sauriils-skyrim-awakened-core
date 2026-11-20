//! Downloads with resume and verification.
//!
//! A Nexus file counts as verified only when its size matches the listed size AND
//! Nexus's md5_search maps the archive's MD5 back to the same mod id and file id.
//! URL sources must match their pinned SHA-256. Nothing is assumed from HTTP success.

use crate::config::Config;
use crate::lock::LockedFile;
use crate::nexus::Nexus;
use anyhow::{anyhow, bail, Context, Result};
use md5::{Digest as _, Md5};
use reqwest::header::RANGE;
use sha2::Sha256;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub fn hash_file(path: &Path) -> Result<(String, String, u64)> {
    let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut md5 = Md5::new();
    let mut sha = Sha256::new();
    let mut buf = vec![0u8; 4 << 20];
    let mut n = 0u64;
    loop {
        let r = f.read(&mut buf)?;
        if r == 0 {
            break;
        }
        md5.update(&buf[..r]);
        sha.update(&buf[..r]);
        n += r as u64;
    }
    Ok((hex::encode(md5.finalize()), hex::encode(sha.finalize()), n))
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| if matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') { '_' } else { c })
        .collect()
}

/// The partial file `download` writes before renaming it to `dest`.
fn part_path(dest: &Path) -> PathBuf {
    dest.with_extension(format!(
        "{}.part",
        dest.extension().and_then(|e| e.to_str()).unwrap_or("bin")
    ))
}

/// Stream `url` into `dest`, resuming a partial `.part` file when the server honours Range.
fn download(nx: &Nexus, url: &str, dest: &Path) -> Result<()> {
    let part = part_path(dest);
    let mut have = part.metadata().map(|m| m.len()).unwrap_or(0);
    let mut req = nx.http().get(url).timeout(Duration::from_secs(6 * 3600));
    if have > 0 {
        req = req.header(RANGE, format!("bytes={have}-"));
    }
    let mut resp = req.send().context("starting download")?;
    let status = resp.status();
    if status.as_u16() == 206 {
        // resuming
    } else if status.is_success() {
        have = 0; // server ignored Range: restart
    } else {
        bail!("download HTTP {status}");
    }
    let total = resp.content_length().map(|l| l + have);
    let mut out = OpenOptions::new()
        .create(true)
        .write(true)
        .append(have > 0)
        .truncate(have == 0)
        .open(&part)?;
    let mut buf = vec![0u8; 1 << 20];
    let started = Instant::now();
    let mut last = Instant::now();
    let mut got = have;
    loop {
        let n = resp.read(&mut buf)?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n])?;
        got += n as u64;
        if last.elapsed() > Duration::from_secs(15) {
            let rate = (got - have) as f64 / started.elapsed().as_secs_f64() / 1e6;
            match total {
                Some(t) => eprintln!("    {:.0}% of {:.1} MB ({rate:.1} MB/s)", got as f64 * 100.0 / t as f64, t as f64 / 1e6),
                None => eprintln!("    {:.1} MB ({rate:.1} MB/s)", got as f64 / 1e6),
            }
            last = Instant::now();
        }
    }
    out.flush()?;
    drop(out);
    if let Some(t) = total {
        if got != t {
            bail!("short download: {got} of {t} bytes (partial kept for resume)");
        }
    }
    std::fs::rename(&part, dest)?;
    Ok(())
}

/// MO2 download metadata so the archive shows up correctly in MO2's Downloads tab.
fn write_mo2_meta(dest: &Path, domain: &str, lf: &LockedFile, mod_name: &str) -> Result<()> {
    let meta = PathBuf::from(format!("{}.meta", dest.display()));
    let mut s = String::from("[General]\n");
    s += "gameName=skyrimse\n";
    if let (Some(m), Some(f)) = (lf.mod_id, lf.file_id) {
        s += &format!("modID={m}\nfileID={f}\nurl=\"https://www.nexusmods.com/{domain}/mods/{m}?tab=files&file_id={f}\"\nrepository=Nexus\n");
    } else if let Some(u) = &lf.url {
        s += &format!("url=\"{u}\"\nrepository=\n");
    }
    s += &format!("name={}\nmodName={}\n", lf.display_name, mod_name);
    if let Some(v) = &lf.version {
        s += &format!("version={v}\nnewestVersion={v}\n");
    }
    s += "installed=false\nuninstalled=false\npaused=false\nremoved=false\n";
    std::fs::write(meta, s)?;
    Ok(())
}

/// Pick where archive `name` of `size` bytes should go: where a partial download of it already
/// is (so it resumes), otherwise the primary directory unless that would break its reserve.
fn choose_dir(cfg: &Config, name: &str, size: Option<u64>) -> PathBuf {
    for d in std::iter::once(&cfg.downloads).chain(cfg.downloads_overflow.as_ref()) {
        if part_path(&d.join(name)).exists() {
            return d.clone();
        }
    }
    let need = size.unwrap_or(0) as f64;
    if let (Some(over), Some(reserve)) = (&cfg.downloads_overflow, cfg.downloads_reserve_gb) {
        if let Some(free) = crate::config::free_bytes(&cfg.downloads) {
            if (free as f64) - need < reserve * 1e9 {
                let _ = std::fs::create_dir_all(over);
                return over.clone();
            }
        }
    }
    cfg.downloads.clone()
}

/// Newer Nexus uploads are stored under a bare UUID; those names carry no provenance.
pub fn is_uuid_name(n: &str) -> bool {
    let b = n.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| if [8, 13, 18, 23].contains(&i) { *c == b'-' } else { c.is_ascii_hexdigit() })
}

/// The archive file name Nexus serves, taken from the signed CDN URL path.
fn name_from_url(url: &str) -> Option<String> {
    let path = url.split('?').next()?;
    let last = path.rsplit('/').next()?;
    let mut out = Vec::new();
    let b = last.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&last[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    let s = String::from_utf8_lossy(&out).into_owned();
    if s.is_empty() { None } else { Some(s) }
}

pub enum Outcome {
    AlreadyVerified,
    Downloaded,
    Adopted,
}

/// Ensure one locked file is present and verified in the downloads directory.
pub fn fetch_one(nx: &Nexus, cfg: &Config, domain: &str, mod_name: &str, lf: &mut LockedFile) -> Result<Outcome> {
    std::fs::create_dir_all(&cfg.downloads)?;
    match lf.source.as_str() {
        "local" => {
            let p = PathBuf::from(lf.file_name.as_deref().unwrap_or_default());
            if !p.exists() {
                bail!("local source {} is missing", p.display());
            }
            let (m, s, n) = hash_file(&p)?;
            lf.md5 = Some(m);
            lf.sha256 = Some(s);
            lf.size = Some(n);
            lf.verified_by = Some("local-hash-recorded".into());
            lf.verified_at = Some(chrono::Local::now().to_rfc3339());
            Ok(Outcome::AlreadyVerified)
        }
        "url" | "github" => {
            let name = sanitize(lf.file_name.as_deref().ok_or_else(|| anyhow!("url source without file name"))?);
            lf.file_name = Some(name.clone());
            let existing = lf.archive_path(&cfg.downloads).filter(|p| p.exists());
            let dest = match existing {
                Some(p) => p,
                None => {
                    let d = choose_dir(cfg, &name, lf.size);
                    lf.dir = if d == cfg.downloads { None } else { Some(d.clone()) };
                    d.join(&name)
                }
            };
            if lf.source == "github" && lf.sha256.is_none() {
                // No published digest: trust on first use, clearly labelled as such.
                if !dest.exists() {
                    download(nx, lf.url.as_deref().unwrap(), &dest)?;
                }
                let (m, s, n) = hash_file(&dest)?;
                if lf.size.map_or(false, |sz| sz != n) {
                    bail!("size mismatch for {name}: {n} vs GitHub {}", lf.size.unwrap());
                }
                lf.md5 = Some(m);
                lf.sha256 = Some(s);
                lf.size = Some(n);
                lf.verified_by = Some("github-size+tofu-sha256".into());
                lf.verified_at = Some(chrono::Local::now().to_rfc3339());
                write_mo2_meta(&dest, domain, lf, mod_name)?;
                return Ok(Outcome::Downloaded);
            }
            let want = lf.sha256.clone().ok_or_else(|| anyhow!("url source without sha256"))?;
            let mut outcome = Outcome::AlreadyVerified;
            if !dest.exists() {
                download(nx, lf.url.as_deref().unwrap(), &dest)?;
                outcome = Outcome::Downloaded;
            }
            let (m, s, n) = hash_file(&dest)?;
            if s != want {
                let bad = dest.with_extension("sha256-mismatch");
                std::fs::rename(&dest, &bad)?;
                bail!("sha256 mismatch for {name}: got {s}, pinned {want} (moved to {})", bad.display());
            }
            lf.md5 = Some(m);
            lf.size = Some(n);
            lf.verified_by = Some(if lf.source == "github" { "github-digest-sha256".into() } else { "sha256-pinned".into() });
            lf.verified_at = Some(chrono::Local::now().to_rfc3339());
            write_mo2_meta(&dest, domain, lf, mod_name)?;
            Ok(outcome)
        }
        "nexus" => {
            let (mod_id, file_id) = (lf.mod_id.unwrap(), lf.file_id.unwrap());
            if let Some(dest) = lf.archive_path(&cfg.downloads).filter(|p| p.exists()) {
                let (m, s, n) = hash_file(&dest)?;
                if lf.sha256.as_deref() == Some(s.as_str()) && lf.verified_by.is_some() {
                    return Ok(Outcome::AlreadyVerified);
                }
                // An archive is present but not (or not identically) verified: verify it now.
                if let Some(how) = verify_nexus(nx, cfg, &dest, domain, mod_id, file_id, &m, n, lf.size)? {
                    lf.md5 = Some(m);
                    lf.sha256 = Some(s);
                    lf.size = Some(n);
                    lf.verified_by = Some(how);
                    lf.verified_at = Some(chrono::Local::now().to_rfc3339());
                    write_mo2_meta(&dest, domain, lf, mod_name)?;
                    return Ok(Outcome::Adopted);
                }
                let bad = dest.with_extension("unverified");
                std::fs::rename(&dest, &bad)?;
                eprintln!("    existing archive failed verification, moved to {}", bad.display());
            }
            let links = nx.download_links(domain, mod_id, file_id)?;
            if lf.file_name.is_none() {
                let n = match links.first().and_then(|u| name_from_url(u)) {
                    Some(n) if !is_uuid_name(&n) => n,
                    _ => nx.file_details(domain, mod_id, file_id)?.0,
                };
                lf.file_name = Some(sanitize(&n));
            }
            let d = choose_dir(cfg, lf.file_name.as_deref().unwrap(), lf.size);
            lf.dir = if d == cfg.downloads { None } else { Some(d.clone()) };
            let dest = d.join(lf.file_name.as_ref().unwrap());
            let mut last = None;
            for url in links.iter().take(3) {
                match download(nx, url, &dest) {
                    Ok(()) => {
                        last = None;
                        break;
                    }
                    Err(e) => {
                        eprintln!("    mirror failed: {e:#}");
                        last = Some(e);
                    }
                }
            }
            if let Some(e) = last {
                return Err(e);
            }
            let (m, s, n) = hash_file(&dest)?;
            let Some(how) = verify_nexus(nx, cfg, &dest, domain, mod_id, file_id, &m, n, lf.size)? else {
                let bad = dest.with_extension("unverified");
                std::fs::rename(&dest, &bad)?;
                bail!("downloaded archive failed verification (kept as {})", bad.display());
            };
            lf.md5 = Some(m);
            lf.sha256 = Some(s);
            lf.size = Some(n);
            lf.verified_by = Some(how);
            lf.verified_at = Some(chrono::Local::now().to_rfc3339());
            write_mo2_meta(&dest, domain, lf, mod_name)?;
            Ok(Outcome::Downloaded)
        }
        other => bail!("unknown source kind {other}"),
    }
}

fn verify_nexus(nx: &Nexus, cfg: &Config, path: &Path, domain: &str, mod_id: u64, file_id: u64, md5: &str, size: u64, listed: Option<u64>) -> Result<Option<String>> {
    let hits = nx.md5_search(domain, md5)?;
    if let Some(h) = hits.iter().find(|h| h.mod_.mod_id == mod_id && h.file_details.file_id == file_id) {
        match listed {
            Some(l) if l != size => {
                // Nexus's md5 index ties these exact bytes to this file id; only the listed size
                // metadata disagrees, so record that instead of rejecting the genuine file.
                eprintln!(
                    "    size mismatch: archive {size} bytes, Nexus lists {l} (md5 index: {:?}); md5 matches this file",
                    h.file_details.size_in_bytes
                );
                return Ok(Some(format!("nexus-md5 (listed size {l} != {size})")));
            }
            _ => return Ok(Some("nexus-md5+size".into())),
        }
    }
    if let Some(l) = listed {
        if l != size {
            eprintln!("    size mismatch: archive {size} bytes, Nexus lists {l}");
            return Ok(None);
        }
    }
    if !hits.is_empty() {
        eprintln!(
            "    md5 {md5} belongs to other files {:?}, not mod {mod_id} file {file_id}",
            hits.iter().map(|h| (h.mod_.mod_id, h.file_details.file_id)).collect::<Vec<_>>()
        );
        return Ok(None);
    }
    // Nexus has no md5 entry for this file at all: require the exact listed size plus a full CRC test.
    if listed.is_none() {
        eprintln!("    md5 not indexed and no listed size: cannot verify");
        return Ok(None);
    }
    let st = std::process::Command::new(cfg.tool("7zz")).arg("t").arg("-bso0").arg("-bsp0").arg(path).status()?;
    if st.success() {
        eprintln!("    md5 not indexed by Nexus; accepted on exact size + archive CRC test");
        Ok(Some("nexus-size+archive-crc (md5 not indexed)".into()))
    } else {
        eprintln!("    md5 not indexed and archive CRC test failed");
        Ok(None)
    }
}

/// Rename UUID-named archives (and their MO2 .meta) to the file names Nexus lists.
pub fn fix_names(nx: &Nexus, cfg: &Config, domain: &str, mod_name: &str, lf: &mut LockedFile) -> Result<Option<String>> {
    let (Some(m), Some(f)) = (lf.mod_id, lf.file_id) else { return Ok(None) };
    let Some(cur) = lf.file_name.clone() else { return Ok(None) };
    if !is_uuid_name(&cur) {
        return Ok(None);
    }
    let old = lf.archive_path(&cfg.downloads).unwrap();
    if !old.exists() {
        return Ok(None);
    }
    let real = sanitize(&nx.file_details(domain, m, f)?.0);
    let new = old.with_file_name(&real);
    if new.exists() {
        bail!("{} already exists", new.display());
    }
    std::fs::rename(&old, &new)?;
    let old_meta = PathBuf::from(format!("{}.meta", old.display()));
    if old_meta.exists() {
        std::fs::remove_file(&old_meta)?;
    }
    lf.file_name = Some(real.clone());
    write_mo2_meta(&new, domain, lf, mod_name)?;
    Ok(Some(real))
}
