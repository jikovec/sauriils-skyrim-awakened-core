# Core architecture and publication state (v0.0.3)

Our working local project combines:
- **Skyforge** — Rust installer, pinned archive verification, MO2 configuration and Wine/Proton launch integration.
- **CHIM native client integration** — hands-free dialogue, proper-name correction, authored dialogue option selection, per-spoken-segment line skipping, audio lifecycle, focus and continuity.
- **CHIM/HerikaServer backend changes** — NPC identity/knowledge context, memories, belief/disclosure controls, per-character playthrough separation and Helgen-lore gating.
- **Speech stack** — local Whisper STT, PocketTTS TTS, language model, embeddings and voice caches. Models/weights/voices are NOT included.
- **Background Life** — schedule protocol and activity/return tracking. The reporting feature remains disabled while owner gameplay validation is outstanding.
- **Compatibility work** — custom patches for Alternate Start, quests, Icerunner/TCIY, C.O.I.N., Skyforge's installed authored integration and numerous repair/FOMOD overlays.

**Only the Skyforge Rust source is actually included in this public repository.** The native client and backend are upstream-derived works pending license/provenance review; local mod override folders may contain copyrighted source content and cannot be uploaded without permission or clean rebuild recipes.

The current **v0.0.3 local profile** has 618 enabled mod folders, of which 39 are local or derivative packaging and 579 are third-party references. Real new-game and conversation gameplay acceptance has not been established; DynDOLOD output is not generated. See the Collection reference catalog for precise source and mod version mapping.

## Publication work remaining

1. Audit derivative source and original copyright holders before migrating CHIM and server changes.
2. Convert modified author patch folders into permitted patches or source-only build recipes.
3. Validate runtime installation from independently downloaded mods and document supported hardware/platform.
4. Integrate security and privacy checks; keep character save/recording data outside public source.
5. Qualify the gameplay and install paths before advertising a full Core binary release.
