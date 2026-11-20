# Sauriil's Skyrim Awakened — Core

**Development preview.** The custom engineering side of [Sauriil's Skyrim Awakened — Complete Collection](https://github.com/jikovec/sauriils-skyrim-awakened). Both use a matching release identifier; the documented local baseline is **v0.0.3**.

The complete intended game combines a curated third-party modlist with a local AI/CHIM integration layer, NPC dialogue and memory enhancements, patch-generation workflows and Skyforge tooling. **This repository is not yet a complete downloadable Core release.** It publishes only the cleared source inventory below; upstream/derivative native game plugins, backend patches, modified game records, generated voice files, models and user data are deliberately withheld pending their own rights/provenance reviews.

## Included source

- `src/skyforge/` — Rust Skyforge installer source and Cargo lockfile, as currently maintained for the Linux/Proton/MO2 workflow. Its `Cargo.toml` declares `GPL-3.0-or-later` because of libloot. It is a public-source snapshot whose local absolute CLI defaults were converted to relative defaults. **This edited public snapshot has not been independently built or tested as a portable installer**; the tested v0.0.3 playable profile remains in the separate private workspace.
- `docs/` — the Core architecture, rights boundaries, integration inventory and v0.0.3 verification status.

See [licensing](LICENSING.md) before reusing code or proposing derivative patches. Original code under `src/skyforge` is GPL-3.0-or-later; original documentation is CC BY 4.0. Neither license grants rights in separate third-party mods.

## Not distributed here

No Skyrim game assets, Bethesda files, external mod archives, MO2 installation, personal saves, NPC voices/voice models, local CHIM databases, private conversations, credentials, or uncleared CHIM/HerikaServer derivative code. Source-only publication does **not** mean the full v0.0.3 runtime is publicly released or gameplay-qualified.

The exact complete list of third-party references and integration package names is in the [Collection repository](https://github.com/jikovec/sauriils-skyrim-awakened). Contributions of original code or documentation are welcome through pull requests after reading [CONTRIBUTING.md](CONTRIBUTING.md).
