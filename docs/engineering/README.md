# Engineering orientation

Confirm the Git root and remote, identify the assigned Issue, and read its current state and native blockers. An unassigned agent can identify eligible work and return it to the coordinator. It may implement only work that the applicable task authorizes. Read the nearest scoped AGENTS.md and use the row below to load only the relevant architecture and checks. Fresh sessions may have public context only. If a path, authority or evidence is owner-private, report that dependency and continue in the public lane.

| Area | Owner and starting point | Verification |
| --- | --- | --- |
| Skyforge, manifests and install mechanics | Core [source](../../src/skyforge), [archive admission](archive-admission.md), [playthrough checkpoints](checkpoints.md), [portability](https://github.com/jikovec/sauriils-skyrim-awakened-core/issues/7) | [Locked build and tests](development.md) |
| Native SKSE, world actions and quest eligibility | Core [runtime](../architecture/runtime.md); private native maintainer or [Collection](https://github.com/jikovec/sauriils-skyrim-awakened) compatibility owner | Isolated native/quest scenarios and monitored receipts |
| AI/CHIM, speech, lore and memories | Core [runtime](../architecture/runtime.md) and [data](../architecture/data.md); owner-authorized component checkout | Synthetic schema, disposable SQL, request/delivery trace and audience controls |
| Simulation, stability and profiling | Core [operations](../architecture/operations.md) | Bounded concurrency, failure/recovery fixtures and an exact private runtime candidate |
| Publication, rollback and coordinated release | [Promotion](promotion.md), [development](development.md), [coordination](coordination.md) | Rights checks, source CI, version-bound private qualification and rollback |
| Hosted checks, workflows and repository rules | [Hosted controls](hosted-controls.md) | Workflow policy verifier and the required check on each pull request |

The [architecture index](../architecture/README.md) is the canonical system entry. The private owner workspace routes investigation, research, build/fix, review and verification to its existing toolkit and has separate CHIM diagnosis and Skyrim qualification workflows. Use the public commands when private context is absent. Codex and OpenCode can read this repository’s AGENTS.md directly. Claude Code imports it through the thin CLAUDE.md. Humans and other agents use the same files. No provider requires a separately maintained technical policy.
