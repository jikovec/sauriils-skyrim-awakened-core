# Resource budgets and observability

## Admission and load shedding

The foreground game owns render, audio, and main-thread headroom. Engine-critical event handling gets bounded priority, followed by active player turns, nearby eligible NPC work and deferred background activity. Keep each class bounded and record expiry, backpressure, cancellation and fair service. Defer or coalesce optional background work first, then constrain context, temporary residency and concurrency according to the measured profile. Preserve authored gameplay and persistence when inference is unavailable. Never promise an action or delivered line that expired or failed.

| Budget | Record and verify |
| --- | --- |
| CPU | Record game and service CPU load, frame-time distribution, runnable queues, thread and inference worker counts under comparable gameplay and model scenarios. Bound background CPU against foreground requirements. |
| GPU and VRAM | Record GPU-wide and per-process residency, allocation failures and render performance with co-running services. Leave measured game headroom; use profile-specific pressure/clear thresholds with hysteresis and a tested recovery path. |
| RAM and storage | Bound working sets, file caches, background indexing, logs, archives and temporary build footprint. Measure peak and recovery, including fragmentation or resource exhaustion where observable. |
| Model and context | Record model digest, quantization, offload, runtime, contexts, cache and concurrency. Admit work using measured cold/warm memory plus latency and cap in-flight work and reserved slots. |
| Queues and deadlines | Bound by count and cost. Record age, depth, wait, service time, deadlines, drops and cancel reason. Decline or degrade work that cannot meet an applicable deadline. |
| Simulation | Budget updates by tier and game-clock progression. Preserve necessary deferred intent and reconcile on load without runaway catch-up. |

The first deployment profile is an owner Desktop with i7-11700K, about 31 GiB RAM and RTX 4070 12 GiB. The v0.0.5 investigation observed GPU allocation failure. The reported input stall boundary was not instrumented directly. A fixed-request 24-layer offload trial reduced GPU-wide allocation from 5,234–5,312 MiB to 4,396–4,465 MiB but sharply degraded inference latency and was rolled back. An in-world peak was unavailable. Separate Havok and AIAgent exceptions have their own incident evidence; a shared cause is unproven. Establish workload and measurement conditions before choosing numerical admission targets. [Allocation](https://github.com/jikovec/sauriils-skyrim-awakened-core/issues/9), [Havok](https://github.com/jikovec/sauriils-skyrim-awakened-core/issues/10), [AIAgent](https://github.com/jikovec/sauriils-skyrim-awakened-core/issues/11).

## Correlation and retention

Emit structured event metadata at native ingress, SQL admission, context retrieval, scheduling, provider request, TTS, ordered playback, effect execution and terminal receipt. Correlate a scoped request ID across hops, parent event IDs for causality, opaque actor/playthrough IDs where needed, and segment/utterance IDs for speech. Record producer and binary/schema identity, wall and monotonic timing or declared clock domain, game time where applicable, and outcome. Classification distinguishes unavailable dependency, malformed input, overloaded, expired, canceled, failed and observed completion. A process health probe is liveness evidence. Queue depth, saturation, latency, allocation and crash evidence measure different boundaries.

Default to metadata-only logs with sensitive fields disallowed. Keep raw transcripts, audio, private prompts, secrets and save details out of shared logs. Use local access controls, bounded retention and explicit review for exceptional diagnostic capture. Retention belongs to the owner-approved environment profile and must be exercised under pressure. Configure component health separately from semantic acceptance and capture the specific failing transition. Bind a diagnostic to exact commands and binary/config identities, preserve source evidence locally and publish only sanitized findings. Use the [synthetic correlation fixtures](../../contracts/README.md) before wiring new runtime producers.
