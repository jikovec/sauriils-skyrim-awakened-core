# Synthetic interface contracts

Run `nix develop --no-update-lock-file --command bash scripts/check static`. The fixtures contain invented IDs, no text payload and no game or service dependency. Refer to [data ownership](../docs/architecture/data.md) and [diagnostics](../docs/architecture/operations.md) before adopting a schema with any producer.

- [event-v1.schema.json](event-v1.schema.json) defines metadata-only correlation, parentage, producer, time and scoped identifiers.
- [receipt-v1.schema.json](receipt-v1.schema.json) defines action and speech lifecycle receipts. Completion requires an owning engine or playback evidence identifier.
- [fixtures/trace.json](fixtures/trace.json) connects native, CHIM, inference, speech and playback events. The validator exercises the positive trace, structural negatives and correlation failures.

Version 1 is an engineering fixture contract. Production action execution, actor and playthrough persistence, event admission, payload schemas and SQL migrations retain their existing owners until separate adoption and qualification.
