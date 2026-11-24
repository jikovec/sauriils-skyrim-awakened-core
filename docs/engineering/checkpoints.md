# Playthrough checkpoints

A playthrough lives in two places: the Skyrim save with its SKSE co-save, and the PostgreSQL state the NPC minds are built from. A backup of one without the other restores files that are each valid and do not belong together. `skyforge checkpoint` captures and restores both as one unit, and refuses a pair that is not one playthrough at one moment.

The code is in `src/skyforge/src/checkpoint.rs`. Skyforge holds no database connection, credential or table name. A *lane* in `skyforge.toml` names the commands that reach one database and the SQL that reads its facts.

## What a checkpoint holds

`<store>/<id>/` contains `checkpoint.json`, `save/<name>.ess`, `save/<name>.skse` and `database.dump`. The [record schema](../../contracts/checkpoint-v1.schema.json) is versioned, and Skyforge's tests validate the records it writes against it.

| Field | Meaning |
| --- | --- |
| `playthrough` | The ID the client stored in the co-save. It is read from the co-save, never from a name. |
| `save` | The save pair by name, each file with its SHA-256 and size, and when the save was written. |
| `database.dump` | SHA-256 and size of the dump. |
| `database.watermark` | A value that changes whenever the playthrough's state is written. It is the event boundary of this checkpoint. |
| `database.schema` | The schema version the dump was taken from. |
| `database.tables_sha256` | Digest of the per-table row counts, compared again after a restore. |
| `coherence` | `coherent`, or `database-ahead` with the number of seconds of play the save does not hold. |
| `identity` | Digests of the files that identify the game, the native client and the load order. |
| `labels` | Further identities recorded as configured, such as a model or policy revision. |

A logical dump carries rows, not indexes. Every index, including a vector index, is rebuilt from the restored rows by the restore itself, so derived search structures always come from the restored source.

## Capture

`skyforge checkpoint capture --lane <name> [--save <name>]`

1. The store takes a lock. Leftovers of a capture that was cut off are removed; they were never checkpoints.
2. The game must not be running.
3. The newest save, or the named one, must have its co-save, and the co-save must hold a playthrough record.
4. The database must be bound to the same playthrough.
5. The newest database event must not follow the save by more than the tolerance. Otherwise the capture is refused as `database-ahead`, because a restore would give NPCs memories of play the save does not contain. `--accept-database-ahead` records the checkpoint with that loss window stated, for the case where the newer play is already lost, for example after a crash.
6. Free space must cover the save pair and the configured reserve, before and after the dump.
7. The dump is written. Then the fence is checked: the watermark and the bound playthrough must read exactly as before the dump, the save pair must be unchanged, and the game must still be closed.
8. The record is written and the directory is renamed into place. The checkpoint exists from that rename on, complete or not at all.

Any refusal removes the partial directory and leaves every earlier checkpoint as it was.

## Restore

`skyforge checkpoint restore <id> --saves <directory> --lane <name>`

A restore goes only into an independent save directory and database lane. The live save directory and the lane the checkpoint was captured from are refused, so this command cannot overwrite the playthrough it protects. Restoring over a live playthrough is a separate, owner-authorized procedure.

1. Every file of the checkpoint is confirmed against its record, and the co-save must still name the recorded playthrough.
2. The lane must accept the recorded schema version.
3. The target save directory must be empty or hold only this playthrough's saves, and no file of the same name with other bytes. The target lane must be bound to no playthrough.
4. A journal is written into the target directory.
5. The database is restored first. The lane is read back: playthrough, watermark, schema and table counts must equal the record. A dump that is not the state the record describes is refused as `wrong-epoch`.
6. Only then is the save pair copied in, each file under a temporary name, confirmed and renamed.
7. The journal is completed with the measured restore time.

A restore that was cut off leaves its journal without an end. Repeating the same restore completes it. Another checkpoint cannot take over that directory. The checkpoint itself is only ever read.

## Refusal codes

| Code | Meaning |
| --- | --- |
| `incomplete-pair` | A save without its co-save. |
| `no-playthrough-record` | The co-save holds no playthrough ID, so nothing binds it to a database. |
| `mixed-owner` | The save, the database or the target belong to different playthroughs. |
| `not-quiescent` | The game was running, or the save or the database changed during capture. |
| `database-ahead` | The database holds events newer than the save. |
| `insufficient-space` | Not enough free space for the capture and the reserve. |
| `missing` | The checkpoint or one of its files does not exist. |
| `corrupt` | A file does not match its recorded digest, or the record is not valid. |
| `wrong-epoch` | The restored database is not the state the record describes. |
| `incompatible-schema` | The target cannot receive this schema version. |
| `would-overwrite` | The target already holds other state, or is the source itself. |
| `lane-failed` | A database command failed. |

## Recovery objectives

- **Recovery point.** One checkpoint per play session, taken after the game has closed. The objective is to lose at most the session in progress. Inside a checkpoint the loss is exact and recorded: zero for `coherent`, and `database_ahead_seconds` otherwise.
- **Recovery time.** The record of each restore states its measured duration. The objective for a restore into an independent profile is minutes, bounded by the database restore.
- **Capacity.** One checkpoint is one save pair plus one compressed dump. `reserve_bytes` keeps the store from filling its filesystem.

Measured values for one installation belong in that installation's own records.

## Retention

`skyforge checkpoint prune --keep <n>` lists the checkpoints older than the newest `n` that still verify, and deletes them only with `--yes`. The newest verified checkpoint is always kept. A checkpoint that fails verification is never removed by retention, so damage stays visible.

## Configuration

```toml
[checkpoint]
store = "checkpoints/playthrough"
reserve_bytes = 268435456
ahead_tolerance_seconds = 5
identity = { game = "stock-game/SkyrimSE.exe" }
labels = { model = "model-name and digest" }

[checkpoint.lanes.play]
query = ["<command that runs one SQL text given as its last argument>"]
dump = ["<command that writes a dump to standard output>"]
restore = ["<command that replaces the database from standard input>"]
playthrough_sql = "<prints the bound playthrough ID>"
watermark_sql = "<prints a value that changes with every write of playthrough state>"
last_event_sql = "<prints the Unix time of the newest event>"
schema_sql = "<prints the schema version>"
tables_sql = "<prints one line per table with its row count>"
accepts_schema = []
```

The dump and restore commands should run as a database role that can read everything and restore only into databases it creates. [Core #170](https://github.com/jikovec/sauriils-skyrim-awakened-core/issues/170) defines that role.

## What a checkpoint does not do

- It does not capture while the game runs. A consistent capture during play needs the client and the server to agree on a save boundary.
- It does not judge whether a save loads. It binds identities and bytes.
- It does not copy unmatched co-saves, other saves of the directory, models, voices or mod files.
- It does not restore over a live playthrough.

## Verification

`bash scripts/check test` runs the checkpoint tests with a stand-in lane: a shell script over a directory, reached exactly the way a real lane is reached. They cover capture, every refusal, a cut-off capture, restore into an independent directory and lane, every refused restore, and a restore that is interrupted and retried. A qualification against a real PostgreSQL belongs to the installation that owns it.
