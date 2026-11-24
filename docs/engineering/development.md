# Development, verification and compatibility

The source shell pins the same nixpkgs revision as the private tool environment. From the Core repository root:

```bash
nix develop --no-update-lock-file --command bash scripts/check doctor
nix develop --no-update-lock-file --command bash scripts/check build
nix develop --no-update-lock-file --command bash scripts/check test
nix develop --no-update-lock-file --command bash scripts/check lint origin/main
nix develop --no-update-lock-file --command bash scripts/check verify origin/main
```

The commands run inside an x86_64 Linux shell using the checked-in Cargo lockfile, Rust 1.95.0, LLVM 21, libloot 0.29.7 and 7-Zip for synthetic archive tests. The first invocation can obtain pinned Nix packages and crates. Set `CARGO_NET_OFFLINE=true` with an independently prepared cache and use an isolated `CARGO_TARGET_DIR` to bound disk use or compare clean builds. Source checks need no Nexus account, licensed game, local model, save or live database. The formatter gates new and previously formatted changed files. Whole-file output for legacy formatting and existing Clippy warnings remains advisory. A source build and synthetic tests do not prove a portable installed modlist.

| Environment | Supported verification and evidence |
| --- | --- |
| Public source and fixtures | Workflow runs the same entrypoint with locked dependencies, bounded job time and read-only repository token. Review code, inventory and formats before attributing a hosted result to a PR head. |
| Disposable integration | Use a component-owned prefix/profile, distinct backend binding/database and licensed fixtures only where required. Test fresh and migrated schemas, recovery, queue pressure and cancellation. |
| Licensed candidate | Record exact Skyrim/SKSE/Address Library/Proton/MO2, plugin hashes, Profile/load order, backend/schema, model and measurement settings. Verify load, start/save/reload, quests, speech/perception, NPC state and sustained gameplay independently. |
| Owner gameplay | Owner acceptance is its own observation. Hosting, source merge and runtime promotion require distinct authority and proof. |

The public preview documents the local v0.0.3 target (Skyrim SE 1.6.1170, SKSE 2.2.8 and the paired Collection references) and does not ship that profile. Newer private configurations may share the executable and differ in runtime content. For paired releases record one release identifier with Core/Collection source commits, exact approved dependencies and hashes, schema compatibility range and migrations, runtime/profile identity, verification verdicts and rollback targets. Version source automation independently through commits and protected PRs. Keep release notes/changelog entries tied to their evidence. Use signed or owner-approved protected release tags only under separate release authority. Rehearse restoration of the exact profile, backend and schema in an isolated environment and preserve prior manifests even after promotion.

For the private native C++ Windows/SKSE toolchain, Papyrus compatibility, PHP/PostgreSQL, Lua, Podman, MO2, Proton and asset inspection, request authorized owner-workspace access. Reproduce the owning component's pinned recipe; do not infer proof from a tool being present. Escalate missing pins or an unreproducible dependency through its owning Issue.
