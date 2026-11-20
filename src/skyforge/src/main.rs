//! skyforge - reproducible, verifiable Skyrim SE mod installation for MO2 on Linux.

mod check;
mod config;
mod fetch;
mod fomod;
mod install;
mod lock;
mod manifest;
mod mo2;
mod nexus;
mod pex;
mod stock;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use std::collections::HashSet;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "skyforge", version, about)]
struct Cli {
    /// Workspace configuration file.
    #[arg(long, default_value = "./skyforge.toml")]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Validate the Nexus API key (prints account name and premium status only).
    KeyCheck,
    /// List the files of a Nexus mod (public metadata).
    Files { mod_id: u64, #[arg(long)] all: bool },
    /// Resolve manifest sources into the lockfile.
    Lock { #[arg(long, value_delimiter = ',')] keys: Vec<String> },
    /// Download and verify locked files.
    Fetch { #[arg(long, value_delimiter = ',')] keys: Vec<String>, #[arg(long)] phase: Option<u8> },
    /// Rename UUID-named archives to the real Nexus file names (keeps verification).
    FixNames,
    /// Install verified archives into MO2 mod folders / the Stock Game.
    Install { #[arg(long, value_delimiter = ',')] keys: Vec<String>, #[arg(long)] phase: Option<u8> },
    /// Write the MO2 profile's modlist.txt from manifest order.
    Modlist,
    /// Sort plugins with libloot and write plugins.txt / loadorder.txt.
    Sort {
        #[arg(long, default_value = "./manifest/loot/masterlist.yaml")] masterlist: PathBuf,
        #[arg(long, default_value = "./manifest/loot/prelude.yaml")] prelude: PathBuf,
        #[arg(long, default_value = "./manifest/loot/userlist.yaml")] userlist: PathBuf,
    },
    /// Static validation report (DLL runtime compatibility, masters, conflicts).
    Check { #[arg(long)] json: Option<PathBuf>, #[arg(long, default_value = "2.2.6")] skse: String },
    /// Inspect one SKSE DLL against a runtime.
    Dll { path: PathBuf, #[arg(long, default_value = "1.6.1170")] runtime: String, #[arg(long, default_value = "2.2.6")] skse: String },
    /// Summary of manifest decisions and install state.
    Status,
    /// Build the isolated Stock Game from Steam download_depot output.
    StockBuild {
        /// Steam writes download_depot output to steamapps/content (or ubuntu12_32/steamapps/content);
        /// both are symlinked to this /games folder so the Stock Game can be reflinked, not copied.
        #[arg(long, default_value = "./depots/content/app_489830")]
        content: String,
        #[arg(long, default_value = "./SteamLibrary/steamapps/common/Skyrim Special Edition")]
        steam_game: PathBuf,
        #[arg(long, default_value = "1.6.1170.0")]
        expect: String,
    },
    /// Re-verify the Stock Game against its recorded inventory.
    StockVerify,
    /// Share identical disk extents between the Stock Game and the Steam installation (btrfs dedupe;
    /// file contents never change), then re-verify the Stock Game inventory.
    StockDedupe {
        #[arg(long, default_value = "./SteamLibrary/steamapps/common/Skyrim Special Edition")]
        steam_game: PathBuf,
    },
    /// Verify exact round-trip of a compiled Papyrus script and disassemble one function.
    PexDump { path: PathBuf, #[arg(long)] function: Option<String> },
    /// Apply the CHIM quest-safety patch (EndDialogueClearScene: no scene/quest restarts).
    PexPatchChim { input: PathBuf, output: PathBuf },
    /// Apply the CHIM schedule guard (no travel/teleport for essential actors or actors in a scene).
    PexPatchChimSchedule { input: PathBuf, output: PathBuf },
    /// Point the MO2 instance at the Stock Game and create the managed profile (idempotent).
    Mo2Setup { #[arg(long, default_value = "./configs/ini")] ini_templates: PathBuf },
}

fn skse_packed(v: &str) -> Result<u32> {
    let p: Vec<u32> = v.split('.').map(|x| x.parse().unwrap_or(0)).collect();
    if p.len() != 3 {
        bail!("SKSE version must look like 2.2.6");
    }
    Ok(check::exe_version(p[0], p[1], p[2], 0))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Cmd::PexDump { path, function } = &cli.cmd {
        let b = std::fs::read(path)?;
        let p = pex::roundtrip_check(&b)?;
        println!("{}: round-trip exact ({} bytes, {} strings, {} objects, debug info: {})", path.display(), b.len(), p.strings.len(), p.objects.len(), p.debug.is_some());
        if let Some(f) = function {
            print!("{}", p.disassemble(f)?);
        }
        return Ok(());
    }
    if let Cmd::PexPatchChim { input, output } = &cli.cmd {
        let b = std::fs::read(input)?;
        let mut p = pex::roundtrip_check(&b)?;
        println!("BEFORE\n{}", p.disassemble("EndDialogueClearScene")?);
        let msg = pex::patch_chim_scene_restart(&mut p)?;
        let out = p.write();
        let p2 = pex::Pex::parse(&out).context("re-parsing patched pex")?;
        println!("AFTER\n{}", p2.disassemble("EndDialogueClearScene")?);
        std::fs::write(output, &out)?;
        println!("{msg}\nwrote {} ({} bytes)", output.display(), out.len());
        return Ok(());
    }
    if let Cmd::PexPatchChimSchedule { input, output } = &cli.cmd {
        let b = std::fs::read(input)?;
        let mut p = pex::roundtrip_check(&b)?;
        println!("BEFORE\n{}", p.disassemble("Execute")?);
        let msg = pex::patch_chim_schedule_guard(&mut p)?;
        let out = p.write();
        let p2 = pex::Pex::parse(&out).context("re-parsing patched pex")?;
        p2.check_jumps()?;
        println!("AFTER\n{}", p2.disassemble("Execute")?);
        std::fs::write(output, &out)?;
        println!("{msg}\nwrote {} ({} bytes)", output.display(), out.len());
        return Ok(());
    }
    if let Cmd::Dll { path, runtime, skse } = &cli.cmd {
        let (v, d) = check::check_dll(&std::fs::read(path)?, check::parse_runtime(runtime)?, skse_packed(skse)?);
        println!("{v}: {d}");
        return Ok(());
    }
    let cfg = config::Config::load(&cli.config)?;
    let nx = nexus::Nexus::new(Some(&cfg.nexus_key_file))?;
    match cli.cmd {
        Cmd::KeyCheck => {
            if !nx.has_key() {
                bail!("no API key at {}", cfg.nexus_key_file.display());
            }
            let u = nx.validate()?;
            println!("Nexus account: {} | premium: {} | supporter: {}", u.name, u.is_premium, u.is_supporter);
        }
        Cmd::Files { mod_id, all } => {
            let man = manifest::Manifest::load(&cfg.manifest)?;
            for f in nx.mod_files(man.meta.game_id, mod_id)? {
                if !all && matches!(f.category.as_str(), "ARCHIVED" | "REMOVED" | "DELETED") {
                    continue;
                }
                let d = chrono::DateTime::from_timestamp(f.date, 0).map(|d| d.date_naive().to_string()).unwrap_or_default();
                println!(
                    "{:>7} {:<13} {:<60} v{:<14} {} {:>9.1} MB",
                    f.file_id,
                    f.category,
                    f.name.chars().take(60).collect::<String>(),
                    f.version.unwrap_or_default(),
                    d,
                    f.size_in_bytes.unwrap_or(0) as f64 / 1e6
                );
            }
        }
        Cmd::Lock { keys } => {
            let man = manifest::Manifest::load(&cfg.manifest)?;
            let prev = lock::Lockfile::load(&cfg.lockfile)?;
            let (lf, problems) = lock::lock(&nx, &man, &prev, &keys)?;
            lf.save(&cfg.lockfile)?;
            let n: usize = lf.entries.values().map(|v| v.len()).sum();
            println!("locked {} entries / {n} files -> {}", lf.entries.len(), cfg.lockfile.display());
            for p in &problems {
                println!("PROBLEM: {p}");
            }
            if !problems.is_empty() {
                std::process::exit(2);
            }
        }
        Cmd::Fetch { keys, phase } => {
            let man = manifest::Manifest::load(&cfg.manifest)?;
            let mut lf = lock::Lockfile::load(&cfg.lockfile)?;
            let mut failed = Vec::new();
            for e in man.select(&keys, phase) {
                if !e.status.installs() || e.source.is_none() {
                    continue;
                }
                let Some(n) = lf.entries.get(&e.key).map(|v| v.len()) else {
                    failed.push(format!("{}: not locked", e.key));
                    continue;
                };
                for i in 0..n {
                    let f = &mut lf.entries.get_mut(&e.key).unwrap()[i];
                    eprintln!("[{}] {} ({})", e.key, f.display_name, f.version.clone().unwrap_or_default());
                    match fetch::fetch_one(&nx, &cfg, &man.meta.game_domain, &e.name, f) {
                        Ok(fetch::Outcome::AlreadyVerified) => eprintln!("    verified (cached)"),
                        Ok(fetch::Outcome::Downloaded) => eprintln!("    downloaded + verified ({})", f.verified_by.clone().unwrap_or_default()),
                        Ok(fetch::Outcome::Adopted) => eprintln!("    existing archive verified ({})", f.verified_by.clone().unwrap_or_default()),
                        Err(err) => {
                            eprintln!("    FAILED: {err:#}");
                            failed.push(format!("{}: {}: {err:#}", e.key, f.display_name));
                        }
                    }
                    // Persist progress after every file so interruptions lose nothing.
                    lf.save(&cfg.lockfile)?;
                }
            }
            for f in &failed {
                println!("FAILED: {f}");
            }
            if !failed.is_empty() {
                std::process::exit(2);
            }
        }
        Cmd::FixNames => {
            let man = manifest::Manifest::load(&cfg.manifest)?;
            let mut lf = lock::Lockfile::load(&cfg.lockfile)?;
            let mut n = 0;
            for e in &man.mods {
                let Some(files) = lf.entries.get_mut(&e.key) else { continue };
                for f in files.iter_mut() {
                    if let Some(real) = fetch::fix_names(&nx, &cfg, &man.meta.game_domain, &e.name, f)? {
                        println!("[{}] -> {real}", e.key);
                        n += 1;
                    }
                }
            }
            lf.save(&cfg.lockfile)?;
            println!("renamed {n} archive(s)");
        }
        Cmd::Install { keys, phase } => {
            let man = manifest::Manifest::load(&cfg.manifest)?;
            let lf = lock::Lockfile::load(&cfg.lockfile)?;
            let mut st = install::State::load(&cfg.state)?;
            std::fs::create_dir_all(cfg.mods_dir())?;
            std::fs::create_dir_all(&cfg.staging)?;
            let mut active = fomod_active_set(&cfg, &man, &st)?;
            let gv = format!("{}.0", man.meta.runtime);
            let mut failed = Vec::new();
            for e in man.select(&keys, phase) {
                if !e.status.installs() || e.source.is_none() || e.target == manifest::Target::None {
                    continue;
                }
                let Some(files) = lf.entries.get(&e.key) else {
                    failed.push(format!("{}: not locked", e.key));
                    continue;
                };
                match install::install_one(&cfg, e, files, &mut st, &active, &gv) {
                    Ok(install::InstallOutcome::Unchanged) => eprintln!("[{}] unchanged", e.key),
                    Ok(install::InstallOutcome::Deferred(why)) => eprintln!("[{}] deferred: {why}", e.key),
                    Ok(install::InstallOutcome::Installed(n)) => {
                        let r = &st.installs[&e.key];
                        eprintln!("[{}] installed {n} files -> {}", e.key, r.dir.display());
                        for d in &r.fomod_defaulted {
                            eprintln!("    FOMOD default used: {d}");
                        }
                        active = fomod_active_set(&cfg, &man, &st)?;
                    }
                    Err(err) => {
                        eprintln!("[{}] FAILED: {err:#}", e.key);
                        failed.push(format!("{}: {err:#}", e.key));
                    }
                }
                st.save(&cfg.state)?;
            }
            for f in &failed {
                println!("FAILED: {f}");
            }
            if !failed.is_empty() {
                std::process::exit(2);
            }
        }
        Cmd::Modlist => {
            let man = manifest::Manifest::load(&cfg.manifest)?;
            let st = install::State::load(&cfg.state)?;
            let n = mo2::write_modlist(&cfg, &man, &st)?;
            println!("modlist.txt: {n} lines -> {}", cfg.profile_dir().display());
        }
        Cmd::Sort { masterlist, prelude, userlist } => {
            let man = manifest::Manifest::load(&cfg.manifest)?;
            let st = install::State::load(&cfg.state)?;
            let r = mo2::sort_and_write(&cfg, &man, &st, Some(&masterlist), Some(&prelude), Some(&userlist))?;
            println!("sorted {} plugins (masterlist: {})", r.order.len(), r.masterlist.map(|p| p.display().to_string()).unwrap_or("none".into()));
            for (i, p) in r.order.iter().enumerate() {
                println!("{i:>4} {p}");
            }
        }
        Cmd::Check { json, skse } => {
            let man = manifest::Manifest::load(&cfg.manifest)?;
            let st = install::State::load(&cfg.state)?;
            let r = check::run(&cfg, &man, &st, skse_packed(&skse)?)?;
            for d in &r.dlls {
                println!("DLL {:<12} {:<40} {}", d.verdict, format!("{} :: {}", d.mod_name, d.file.rsplit('/').next().unwrap_or("")), d.detail);
            }
            println!("Address Library for {} present: {}", r.runtime, r.address_library_present);
            println!("plugins: {} full, {} light", r.plugins_full, r.plugins_light);
            for x in &r.missing_masters {
                println!("MISSING MASTER: {x}");
            }
            for x in &r.master_order_errors {
                println!("ORDER ERROR: {x}");
            }
            println!("files provided by more than one mod: {}", r.conflict_files);
            if let Some(p) = json {
                std::fs::write(&p, serde_json::to_string_pretty(&r)?).with_context(|| format!("writing {}", p.display()))?;
            }
            let bad = r.dlls.iter().filter(|d| d.verdict == "INCOMPATIBLE").count()
                + r.missing_masters.len()
                + r.master_order_errors.len()
                + usize::from(r.plugins_full > 254);
            if bad > 0 {
                std::process::exit(2);
            }
        }
        Cmd::Status => {
            let man = manifest::Manifest::load(&cfg.manifest)?;
            let lf = lock::Lockfile::load(&cfg.lockfile)?;
            let st = install::State::load(&cfg.state)?;
            let mut counts = std::collections::BTreeMap::<String, usize>::new();
            for e in &man.mods {
                *counts.entry(format!("{:?}", e.status)).or_default() += 1;
                let locked = lf.entries.get(&e.key).map_or(0, |v| v.len());
                let verified = lf.entries.get(&e.key).map_or(0, |v| v.iter().filter(|f| f.verified_by.is_some()).count());
                let inst = st.installs.contains_key(&e.key);
                println!("{:<4} {:<34} {:<13} p{} locked {locked} verified {verified} installed {}", e.section, e.key, format!("{:?}", e.status), e.phase, if inst { "yes" } else { "no" });
            }
            println!("{counts:?}");
        }
        Cmd::StockBuild { content, steam_game, expect } => {
            let content = if let Some(rest) = content.strip_prefix("~/") {
                PathBuf::from(std::env::var("HOME")?).join(rest)
            } else {
                PathBuf::from(content)
            };
            let p: Vec<u16> = expect.split('.').map(|x| x.parse().unwrap_or(0)).collect();
            if p.len() != 4 {
                bail!("--expect must look like 1.6.1170.0");
            }
            let inv = stock::build(&content, &cfg.stock_game, (p[0], p[1], p[2], p[3]), &steam_game)?;
            let out = cfg.workspace.join("state/stock-game-inventory.json");
            std::fs::write(&out, serde_json::to_string_pretty(&inv)?)?;
            let bytes: u64 = inv.values().map(|(n, _)| n).sum();
            println!("Stock Game built at {} ({} files, {:.2} GB); inventory -> {}", cfg.stock_game.display(), inv.len(), bytes as f64 / 1e9, out.display());
        }
        Cmd::StockVerify => {
            let out = cfg.workspace.join("state/stock-game-inventory.json");
            let inv: std::collections::BTreeMap<String, (u64, String)> = serde_json::from_str(&std::fs::read_to_string(&out)?)?;
            let v = stock::pe_file_version(&cfg.stock_game.join("SkyrimSE.exe"))?;
            let problems = stock::verify(&cfg.stock_game, &inv)?;
            println!("SkyrimSE.exe {}.{}.{}.{}; {} inventoried files; {} problem(s)", v.0, v.1, v.2, v.3, inv.len(), problems.len());
            for p in &problems {
                println!("  {p}");
            }
            if !problems.is_empty() {
                std::process::exit(2);
            }
        }
        Cmd::StockDedupe { steam_game } => {
            let out = cfg.workspace.join("state/stock-game-inventory.json");
            let inv: std::collections::BTreeMap<String, (u64, String)> = serde_json::from_str(&std::fs::read_to_string(&out)?)?;
            let (full, partial, bytes) = stock::dedupe(&cfg.stock_game, &steam_game, &inv)?;
            println!("shared with the Steam installation: {full} files fully, {partial} partly, {:.2} GB", bytes as f64 / 1e9);
            let problems = stock::verify(&cfg.stock_game, &inv)?;
            println!("Stock Game re-verified: {} inventoried files, {} problem(s)", inv.len(), problems.len());
            for p in &problems {
                println!("  {p}");
            }
            if !problems.is_empty() {
                std::process::exit(2);
            }
        }
        Cmd::Mo2Setup { ini_templates } => {
            for d in mo2::setup_instance(&cfg, &ini_templates)? {
                println!("{d}");
            }
        }
        Cmd::Dll { .. } | Cmd::PexDump { .. } | Cmd::PexPatchChim { .. } | Cmd::PexPatchChimSchedule { .. } => unreachable!(),
    }
    Ok(())
}

/// The plugins FOMOD auto-detection treats as active: base masters, the Creation Club / resource
/// plugins that load implicitly from Skyrim.ccc, the installed top-level plugins of every enabled
/// entry (the manifest's `plugins` list is only the researcher's expectation and misses FOMOD-chosen
/// patches), and the expected plugins of enabled entries that are not installed yet.
fn fomod_active_set(cfg: &config::Config, man: &manifest::Manifest, st: &install::State) -> Result<HashSet<String>> {
    let mut active: HashSet<String> = mo2::BASE_MASTERS.iter().map(|b| b.to_lowercase()).collect();
    // Existing profiles can activate unmanaged/Overwrite providers. Union that
    // observed namespace with the installation plan below: replacing the plan
    // would break dependency detection before phased packages are installed.
    active.extend(check::existing_active_plugins(cfg)?);
    for e in man.mods.iter().filter(|e| e.status.enabled_by_default()) {
        match st.installs.get(&e.key) {
            Some(r) => {
                for f in &r.files {
                    let l = f.to_lowercase();
                    if !l.contains('/') && (l.ends_with(".esp") || l.ends_with(".esm") || l.ends_with(".esl")) {
                        active.insert(l);
                    }
                }
            }
            None => active.extend(e.plugins.iter().map(|p| p.to_lowercase())),
        }
    }
    Ok(active)
}
