# Meterless H-MEM provenance

- Upstream: https://github.com/Meterless/Meterless/tree/1742dec56a66e58eef9dda2d2b865823758ca8cd/engines/hmem
- Pinned commit: `1742dec56a66e58eef9dda2d2b865823758ca8cd`
- Retrieved: 2026-10-25
- Author/copyright notice: Copyright 2026 Meterless
- License: Apache License 2.0; original complete license retained in `LICENSE`.
- No upstream NOTICE file was present in the repository tree at this commit.

`reference/src/*.ts`, `reference/README.md`, `reference/package.json`,
`conformance/runner.ts`, `conformance/vectors/vectors.json`,
`conformance/README.md`, `AGENTS.md`, and `LICENSE` are unmodified upstream files.
`bridge.mjs` is a separate SafeGuard adapter, not an upstream file.

No npm dependency install is needed at runtime. Node.js 24 executes the original
TypeScript with `--experimental-transform-types`. We deliberately use the
official deterministic hash embedder and disclose its limits instead of
presenting it as a learned semantic embedding service.

The upstream conformance suite tests the engine. SafeGuard Python integration
tests separately exercise persistence, actual recall, provenance, expiry,
supersession, related graph edges, concurrent access and unavailable runtime.
