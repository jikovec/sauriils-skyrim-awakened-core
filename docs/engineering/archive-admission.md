# Archive admission

Skyforge installs an archive only after it passes admission. The invariant: the bytes the lockfile approves are the bytes the extractor reads, the extractor can write only inside a staging directory Skyforge owns, and activation consumes only staged files that passed inspection. A refusal leaves the installed mod as it was and writes a receipt that says why.

The code is in `src/skyforge/src/admission.rs`. `install.rs` calls it for every archive, with the same extractor order and FOMOD rules as before.

## What happens to one archive

1. **Identity.** The lockfile must hold a SHA-256 for the archive. The file name must be one name inside a configured download root. A manifest key must be letters, digits, `.`, `_` or `-`, because it names the staging and receipt directories.
2. **Binding.** Skyforge opens the archive without following a link, hashes it through that descriptor and compares the digest with the lockfile. The extractor then reads the same open file through `/proc/self/fd`, so replacing the path cannot change what is extracted. Skyforge compares the file's identity and change time again after extraction, and a write, replacement or relink in between refuses the install.
3. **Confinement.** The extractor runs under a Linux Landlock ruleset and a seccomp filter. Landlock lets it write only below its staging directory and read only the system directories its own program and libraries live in, three device files and the archive. It cannot read a credential file, a save, a database, another process's entry under `/proc` or shared memory. The filter refuses what Landlock does not reach: starting another process, opening any socket (so no network and no desktop session bus), signalling or tracing other processes, the kernel keyring and new namespaces. Mode and owner changes report success and do nothing. The extractor starts with a minimal environment and with only the archive descriptor. Because it cannot start a second process, nothing of it survives the wait that ends its run.
4. **Limits.** The extractor has a per-file size limit and a processor-time limit from the kernel. Skyforge stops it when it passes the wall-clock limit, the entry count, the expanded size or the free-space reserve. A stopped extractor is not retried with the next tool.
5. **Inspection.** Skyforge walks everything the extractor left. Only directories and unshared regular files pass. A symbolic link, a hard link, a device, a pipe or a socket refuses the install. So does a name Windows and Linux read differently (a backslash, a colon, a trailing dot or space, a device name such as `NUL`), and so do two different files that become one path when case is ignored. Directories that differ only by case merge, as they do on Windows.
6. **Plan.** The existing FOMOD and include/exclude rules select the outputs. A FOMOD rule or a manifest `root` is input from the archive or its configuration, so every planned source must be a file below the extraction root and every planned destination must be made of ordinary names. A rule with `..`, a drive or stream separator, or a Windows device name refuses the install. Skyforge then hashes each selected file once and records one digest for the whole plan.
7. **Content.** Each selected output is classified by its destination name and first bytes, after any FOMOD rename. Executable classes need the manifest entry to allow them, and executable bytes behind a data extension are always refused. Every other output must be a file type Skyrim mods install as data or documentation, or a type the entry names. An unknown type is refused, so a type nobody reviewed cannot pass by being unknown.
8. **Activation.** A mod folder is assembled beside its destination, each file is confirmed to be the one that was hashed, and the finished folder is exchanged with the old one in a single atomic step. A game-root install refuses any path that passes through a link, then writes and confirms every new file under a temporary name before it changes anything the game reads. Only then does it back up and rename, one file at a time. If a rename fails it restores the files it already switched, so the game root holds the old set or the new one. Its journal gains an end when the run completes or is rolled back.

Extraction uses `unar` for `.rar` and `7zz` then `unar` for everything else. Either tool may be missing; a missing tool counts as unable to read the archive.

## Refusal codes

| Code | Meaning |
| --- | --- |
| `unapproved-identity` | The lockfile or manifest does not identify one approved archive. |
| `digest-mismatch` | The archive bytes differ from the approved SHA-256. |
| `archive-changed` | The archive changed between verification and the end of extraction. |
| `staging-not-owned` | The staging root is a link, belongs to another user, or others can write it. |
| `confinement-unavailable` | Landlock is not available and the configuration requires it. |
| `extraction-failed` | No supported extractor could read the archive. |
| `limit-exceeded` | A count, size, depth, time or free-space limit was reached. |
| `unsupported-entry` | A link, device, pipe or socket. |
| `unsafe-path` | A name that Windows and Linux read differently. |
| `ambiguous-path` | Two different files behind one caseless path. |
| `unexpected-executable` | Executable content the manifest entry does not allow. |
| `unrecognized-content` | A file type that is neither known game data nor named by the manifest entry. |
| `activation-mismatch` | A staged file changed between inspection and activation. |
| `error` | An operating error that is not a policy decision. The detail says what failed. |

## Receipts

Every decision writes one JSON file to `admission/<key>/<time>-<decision>.json` beside the install state file. The [receipt schema](../../contracts/admission-receipt-v1.schema.json) is versioned, and the installer's own tests validate the receipts it writes against it. A receipt records the approved and observed digests, the provenance method from the lockfile and how much that method proves, the limits and confinement in force, the staged totals, the plan digest, every executable with its class and digest, and how activation happened. It never records a download URL or a credential. A local source is named by its file name, and local directories appear by role (`<staging>`, `<mods>`, `<workspace>`), so a receipt can be shared for review. A digest mismatch records both digests.

The install state gains `plan_sha256`, the digest of what was installed. An entry whose sources and rules are unchanged is still skipped before admission, so it leaves no new receipt.

## Configuration

Defaults apply when `skyforge.toml` has no `[admission]` table.

```toml
[admission]
confinement = "landlock"   # "none" turns kernel confinement off; inspection and limits remain

[admission.limits]
max_entries = 250000
max_total_bytes = 68719476736
max_file_bytes = 17179869184
max_path_bytes = 1024
max_depth = 48
wall_seconds = 3600
cpu_seconds = 3600
reserve_bytes = 1073741824
```

A manifest entry allows executable content by class and names any further file type it installs:

```toml
[[mod]]
key = "example-plugin"
executables = ["skse-plugin"]
extra_types = ["pem"]
```

| Class | What it covers |
| --- | --- |
| `skse-plugin` | A `.dll` directly inside `SKSE/Plugins`. |
| `native-library` | Any other `.dll`, and `.asi`, `.ocx`, `.sys`, `.so`, `.cpl`, `.drv`, `.ax`. |
| `program` | `.exe`, `.com`, `.scr`, `.pif`, `.msi`, `.msp`, `.mst`, `.msu`, `.appx`, `.msix`. |
| `script` | Host scripts, shortcuts and files a desktop resolves on open: `.bat`, `.cmd`, the PowerShell and Windows Script Host types (`.ps1`, `.vbs`, `.js`, `.wsf` and their variants), `.hta`, `.lnk`, `.url`, `.scf`, `.reg`, `.inf`, `.jar`, `.sh`, `.py`, `.msc`, `.chm` and similar, or a file that starts with `#!`. `classify` in `admission.rs` holds the exact list. |

The executable lists name known host-executable types and can never be complete. Two rules cover what they miss. Native code and `#!` are recognised by their first bytes whatever the name. And a file whose extension is not in `GAME_DATA` in `admission.rs` is refused as `unrecognized-content` until the entry excludes it or names the extension in `extra_types`. `extra_types` accepts lower-case extensions only and never an executable type. Web and Lua sources inside an interface mod count as `script`; exclude them or allow the class after review.

A survey of one installed list of 621 mod folders found 72 distinct extensions across 60,692 files, so the known-data list is short and the declarations are few. A game archive (`.bsa`) is admitted as one file. Its contents are not inspected.

An existing manifest needs these declarations before an entry with executable or unrecognized content can be installed again. Entries that are already installed and unchanged are not affected.

## Local sources

The recorded hash of an owner-placed file is its approval. `skyforge lock` keeps it while the manifest names the same path. `skyforge fetch` refuses different bytes until the owner reruns it with `--accept-changed-local` and the exact `--keys`.

## Interruption and recovery

Staging for a key is cleared at the start of every install and after every decision, including trees with permissions an archive set to lock the owner out. A mod folder replacement that was interrupted leaves either the old folder or the new one. The next install of that entry restores a folder that was moved aside and removes leftovers. A game-root install that was cut off by a crash leaves a journal without an end. Until a run completes, that entry is never reported as unchanged: the next install writes the planned files again and does not back up files that already hold the planned bytes.

## What admission does not do

- It does not defend against another process of the same user that races Skyforge inside its own staging directory.
- It does not stop the extractor from changing the timestamps of files outside staging, which Landlock and the filter do not cover.
- It supports the confinement on x86-64 and AArch64 Linux. On another architecture the syscall filter is absent and Landlock alone applies.
- It does not verify publisher signatures. The lockfile digest and its recorded provenance method are the approval.
- It does not judge what an allowed executable does. Reviewing a plugin remains the owner's decision; the receipt records exactly which bytes were allowed.
- It does not keep the previous version of a replaced mod folder. The previous lockfile reinstalls it.

## Verification

`bash scripts/check test` runs the admission tests inside the pinned shell. They build their archives in memory, so no third-party file is needed. They need a kernel with Landlock and seccomp; without them they fail and are not skipped. The expectations for hostile archives are pinned to the 7-Zip and unar versions of the shell, and a tool update that changes how a link or an upward name is handled shows up as a test failure.
