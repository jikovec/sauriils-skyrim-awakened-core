# Synthetic interface contracts

Run `nix develop --no-update-lock-file --command bash scripts/check static`. The fixtures contain invented IDs, no text payload and no game or service dependency. Refer to [data ownership](../docs/architecture/data.md) and [diagnostics](../docs/architecture/operations.md) before adopting a schema with any producer.

- [event-v1.schema.json](event-v1.schema.json) defines metadata-only correlation, parentage, producer, time and scoped identifiers.
- [receipt-v1.schema.json](receipt-v1.schema.json) defines action and speech lifecycle receipts. Completion requires an owning engine or playback evidence identifier.
- [fixtures/trace.json](fixtures/trace.json) connects native, CHIM, inference, speech and playback events. The validator exercises the positive trace, structural negatives and correlation failures.
- [admission-receipt-v1.schema.json](admission-receipt-v1.schema.json) defines the receipt Skyforge writes for every [archive admission](../docs/engineering/archive-admission.md) decision. [fixtures/admission-receipts.json](fixtures/admission-receipts.json) holds an admitted and a refused example. The validator rejects receipts that carry a download location, omit a refusal reason or admit bytes other than the approved digest. Skyforge's own tests validate the receipts it writes against the same schema.

The event and interface receipt schemas are version 1 engineering fixture contracts. The admission receipt is produced by Skyforge today. Production action execution, actor and playthrough persistence, event admission, payload schemas and SQL migrations retain their existing owners until separate adoption and qualification.
