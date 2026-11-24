# Synthetic interface contracts

Run `nix develop --no-update-lock-file --command bash scripts/check static`. The fixtures contain invented IDs, no text payload and no game or service dependency. Refer to [data ownership](../docs/architecture/data.md) and [diagnostics](../docs/architecture/operations.md) before adopting a schema with any producer.

- [event-v1.schema.json](event-v1.schema.json) defines metadata-only correlation, parentage, producer, time and scoped identifiers.
- [receipt-v1.schema.json](receipt-v1.schema.json) defines action and speech lifecycle receipts. Completion requires an owning engine or playback evidence identifier.
- [fixtures/trace.json](fixtures/trace.json) connects native, CHIM, inference, speech and playback events. The validator exercises the positive trace, structural negatives and correlation failures.
- [admission-receipt-v1.schema.json](admission-receipt-v1.schema.json) defines the receipt Skyforge writes for every [archive admission](../docs/engineering/archive-admission.md) decision. [fixtures/admission-receipts.json](fixtures/admission-receipts.json) holds an admitted and a refused example. The validator rejects receipts that carry a download location, omit a refusal reason or admit bytes other than the approved digest. Skyforge's own tests validate the receipts it writes against the same schema.
- [checkpoint-v1.schema.json](checkpoint-v1.schema.json) defines the record of a [playthrough checkpoint](../docs/engineering/checkpoints.md): one save pair and one database dump of the same playthrough and moment. [fixtures/checkpoints.json](fixtures/checkpoints.json) holds a coherent example and one whose database is ahead of its save. The validator rejects a record that hides its loss window, names a playthrough by anything but its ID, or carries database content.
- [identity-v1.schema.json](identity-v1.schema.json) defines actor, quest, playthrough, save, load and event identity, and the request that resolves a target to one identity. [Identity version 1](#identity-version-1) states its rules.
- [fixtures/identity.json](fixtures/identity.json) holds one synthetic world, resolution cases with their expected identity or refusal, and records that must be rejected. The validator checks every expected reason, not only that a case fails.

The event, interface receipt and identity schemas are version 1 engineering fixture contracts. The admission receipt and the checkpoint record are produced by Skyforge today. Production action execution, actor and playthrough persistence, event admission, payload schemas and SQL migrations retain their existing owners until separate adoption and qualification.

## Identity version 1

The native resolver produces identity records from engine state. Service ingress and the SQL binding consume them. A record is an object with `version` 1 and a `type`. A reader rejects any other version and any property the schema does not name. Records carry no dialogue, save content or engine handle.

A display name is never an identity. Memories, events, relationships and generated actions are scoped to one actor identity in one playthrough.

### Forms and plugins

A form is identified by the plugin that defines it and by its form ID inside that plugin.

| Field | Meaning | Role |
| --- | --- | --- |
| `origin` | `plugin` for a form a plugin defines, `dynamic` for a form the engine created at run time. | Authoritative |
| `plugin.file` | Plugin file name. Compared after ASCII lower-casing; all other bytes are compared exactly. | Authoritative |
| `plugin.kind` | `full` or `light`. A light plugin's local form IDs are `000000` to `000FFF`. | Authoritative for the range check, not part of equality |
| `plugin.content` | Optional SHA-256 of the plugin file. A changed digest tells the binding owner that the plugin was replaced. | Descriptive |
| `plugin.load_index` | Position in one session's load order: two hex digits for a full plugin, `FE` and three hex digits for a light plugin. | Descriptive |
| `local_form_id` | Six uppercase hex digits: the form ID with its load-order part removed. | Authoritative |
| `runtime_form_id` | Eight uppercase hex digits: the form ID as one session sees it. | Descriptive for `plugin`, a load-time handle for `dynamic` |
| `incarnation` | 32 lowercase hex digits. The resolver assigns it when the engine creates or replaces the actor behind a reference and carries it in the save. | Authoritative when present |

The runtime form ID of a plugin form is its load index followed by its local form ID: `2A` and `000D62` give `2A000D62`. For a light plugin the index is followed by the last three digits: `FE013` and `000801` give `FE013801`. A stated runtime form ID must be the one the session's load order produces. It never enters a key, so the same form keeps its identity when the load order changes.

A dynamic form has the runtime form ID `FF......` and no plugin identity. It exists only in the saves that descend from the load that created it, and the engine can give the same ID to another object later. An actor with a dynamic reference, a dynamic base or an incarnation has `portable` false. A dynamic reference without an incarnation is valid only in the session and load generation that observed it.

### Records

| Type | Identity | Other fields |
| --- | --- | --- |
| `playthrough` | `id`: 128 random bits as 32 lowercase hex digits, created with the character and carried in its saves. Never derived from the character name. | `name` is descriptive. Two playthroughs can share it. |
| `load-order` | `session` | `plugins` with their load indexes. |
| `save` | `id` | `playthrough`, `parent` save or null, and the load in which it was written. A parent belongs to the same playthrough. |
| `load` | `session` and `load_generation` | `playthrough` and the loaded `save`, or null for a new game. |
| `actor` | `playthrough`, `reference` and its `incarnation` | `base` is authoritative and must agree. `name` and `observed` are descriptive, except that `observed` is part of the key of a dynamic reference without an incarnation. |
| `quest` | `form` | `editor_id` must agree, ignoring ASCII case. It never selects a quest. |
| `event` | `session` and `sequence` | `playthrough`, `load_generation`, `digest` of the producer's payload, optional `subject` actor key. |
| `request` | none | `playthrough`, `session`, `load_generation`, `target` and, for a name, `candidates`. |

A session is one run of the game process and has a random ID. The load generation starts at 1 in each session and increases on every load and every new game. The newest accepted load is the current load. An earlier session is a replaced session.

### Keys

```text
form      <plugin file, ASCII lower case>|<local form ID>          skyrim.esm|0A0001
actor     actor:<playthrough>:<form>                               plugin reference
          actor:<playthrough>:<form>#<incarnation>                 plugin reference that was replaced
          actor:<playthrough>:dynamic|<incarnation>                dynamic reference carried in the save
          actor:<playthrough>:dynamic|<session>.<load generation>.<runtime form ID>
quest     quest:<form>
event     event:<session>:<sequence>
```

Two identities are equal when their keys are equal byte for byte. Nothing else makes them equal: not the name, the base, the runtime form ID or the load index.

### Resolution

A request resolves to exactly one key or to one refusal. Every request first names the playthrough, session and load generation of the current load. Otherwise it is refused as `cross-playthrough`, `stale-session`, `unknown-session`, `stale-load-generation` or `unknown-load-generation`. The target then decides the path.

A target `by: "identity"` carries a reference and a base. The checks run in this order.

1. A stated runtime form ID that the session's load order does not produce is `runtime-form-id-mismatch`, `plugin-kind-mismatch`, `unknown-plugin` or `unknown-load-order`.
2. The key of the reference is looked up. The name is ignored, so a renamed actor keeps its identity. A key that is not bound is `unknown-actor`, also when another actor holds the same name. A dynamic reference without an incarnation whose runtime form ID belongs to a dynamic actor of another load is `dynamic-reference-stale`.
3. An incarnation presented under another runtime form ID is `incarnation-conflict`.
4. A bound actor whose base differs is `base-mismatch`: the engine replaced the actor behind the reference.

A target `by: "name"` selects among the request's own candidates, which are identities with the names the engine reports now. Names are compared after trimming and ASCII lower-casing. No matching candidate is `unknown-name`. More than one matching identity is `ambiguous-name`. One matching identity continues as a target `by: "identity"`. A name never reaches an actor outside the candidates.

A target `by: "key"` is a stored key. A key that is not bound is `unknown-actor`. A key of another playthrough is `cross-playthrough`. A key of a dynamic reference without an incarnation from another load is `dynamic-reference-stale`.

A target `by: "quest"` is resolved by its form after the runtime form ID check. An unbound form is `unknown-quest`, also when the editor ID is known. A different editor ID is `quest-editor-id-mismatch`.

An unload and reload inside one load generation changes handles and nothing else, so the actor resolves to the same key.

### Admission

Records are admitted in arrival order. Each record names a known playthrough (`unknown-playthrough`). A playthrough ID equal to a hash of its name is `playthrough-derived-from-name`, and a repeated ID is `duplicate-playthrough`. A load order that lists one plugin or one load index twice is `load-order-conflict`. A save's parent and a load's save exist in the same playthrough (`unknown-save`, `cross-playthrough`), and a repeated save ID is `duplicate-save`. A load generation that does not increase within its session is `load-generation-not-monotonic`. A save, an event and an actor's `observed` name a load that was accepted for their playthrough (`unknown-load-generation`, `cross-playthrough`). A second actor or quest under one key is `duplicate-actor` or `duplicate-quest`. A `portable` value that contradicts the reference, base and incarnation is `portable-flag-mismatch`.

An event that repeats an admitted event exactly changes nothing, at any later time. The same event key with other content is `event-id-conflict`. Events can arrive out of sequence order. Within a session the sequence orders them, so an event's load generation is never lower than that of an event with a smaller sequence (`event-order-violation`). Its subject is an actor of the same playthrough.

### Use with event-v1 and receipt-v1

The event and receipt schemas are unchanged. A trace can opt in by putting identity-v1 identifiers in their existing fields:

```text
playthrough   p-<playthrough>
actor         a-<first 40 hex digits of SHA-256 over the actor key>
event         e-<session>-<sequence>       events produced by "native"
```

The validator then requires each of them to belong to an admitted identity record of the stated playthrough.
