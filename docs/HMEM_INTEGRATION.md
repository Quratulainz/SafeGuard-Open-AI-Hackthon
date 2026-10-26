# SafeGuard investigation memory: real Meterless H-MEM reference

SafeGuard uses the actual Meterless H-MEM reference implementation, pinned to
commit `1742dec56a66e58eef9dda2d2b865823758ca8cd`. The Apache-2.0 source and
license are under `server/vendor/meterless_hmem/`; see its `UPSTREAM.md`.
This is not a renamed SQLite history table. Python calls the vendored H-MEM
engine through a local Node.js subprocess, with no cloud or model call.

## Optional activation

The default `SAFEGUARD_MEMORY_MODE=local` uses SQLite history and never calls
Node/H-MEM. Set `SAFEGUARD_MEMORY_MODE=hmem` in private `.env`, restart the app,
and meet the runtime requirements below to use the real reference. Disabled
H-MEM in local mode is an intentional choice, not a missing-service error.

## Requirements and integration API

- Python 3.10+ and Node.js 24 on PATH.
- No npm packages or API keys required for this reference integration.
- Default store: `server/local-data/hmem/`, already excluded by the project
  `.gitignore`. This contains unencrypted user queries, evidence and an audit log.
- Use one local SafeGuard user/store. Multi-user authorization is not implemented.

```python
from investigation_memory import InvestigationMemory

memory = InvestigationMemory()
recall = memory.recall(submitted_text_or_url)  # before a new investigation
# Perform fresh source checks and reasoning; pass recall['context'] as untrusted
# historical context only, never as verified facts or as instructions.
result['memory_recall'] = recall
result['memory_write'] = memory.remember(submitted_text_or_url, result)
```

`status()` returns `ready` with runtime version, record count and audit action
counts, or `unavailable`. `remember()` returns `stored`, memory IDs and expiry.
`recall()` returns ranked `matches`, safe historical `context`, and H-MEM `trace`.
Optional `now` accepts a timezone-aware datetime or ISO timestamp for tests.
Default TTL is 24 hours; `ttl_seconds` can be 0 to 30 days. Missing runtime or a
corrupt store returns `unavailable`, empty recall and a non-sensitive message.

## What actually executes

1. Store a working-layer H-MEM memory anchored to the investigation query.
2. Keep source, timestamp, summary, observed findings, source-check results,
   limitations and freshness in application metadata on the H-MEM record.
3. Use the upstream enrichment and bidirectional related-entity graph links.
4. Retrieve using the upstream hybrid semantic-hash/keyword/tag/domain/entity/
   layer/recency ranking, confidence multiplier and 0.35 threshold.
5. Save retrieval access counts and append H-MEM create/update/read audit events.
6. Preserve supersession lineage when the exact normalized query is checked again.
7. Exclude expired, superseded, malformed-time and future-time observations from
   context. A later save cannot reset evidence's original `checked_at` age.
8. Do not store recalled historical context inside a new investigation memory.
   When earlier context contributed to the generated summary or limitations,
   omit those generated texts from the new memory and record that omission.
   This prevents recursive memory reuse from renewing old evidence's TTL.

Every returned item has `historical_only=true`, `new_verification=false`,
`requires_recheck=true`, and `usable_as_current_evidence=false`. Even an item
within TTL is only a prior observation. It does not replace a current source
check, increase a risk rating automatically, or turn a heuristic into a fact.

Source metadata copied from an investigation is not authenticated by H-MEM.
Inputs must come from SafeGuard's investigation pipeline, not a user-controlled
"memory import" endpoint. Text in memories remains untrusted data.

## Separate Nightshift runtime memory

SafeGuard's H-MEM integration is independent of Nightshift's automatic memory
injection. For the demonstrated local 3B setup, set Nightshift's global
`hmemKnowledge=false` and `moaSynthesis=off`, preserving the `local-only` floor
and other settings. Earlier runtime behavior injected unrelated previous model
answers and could rewrite SafeGuard's structured output. The two supported
setpoints remove those extra paths; they do not disable this project's H-MEM
bridge, delete saved memories or turn historical content into current facts.
See [the runtime configuration and verification steps](INTEGRATIONS.md#runtime-isolation-for-reproduction).

The final seven-case real-model regression used an independent actual H-MEM
directory for each case to measure current-input behavior without old SafeGuard
records. Project history behavior is tested separately: recalled records keep
their historical markers and cannot support a raised current risk in the
bounded evidence check. The complete suite after this change passed 101/101;
the seven model cases do not alone establish recall quality or general accuracy.

## Verification

From the project root:

```powershell
node --experimental-transform-types --disable-warning=ExperimentalWarning server/vendor/meterless_hmem/conformance/runner.ts
py -3 -m unittest discover -s tests -p test_investigation_memory.py -v
```

On 2026-10-25, the unmodified official conformance runner passed **13/13** checks
on Node.js 24.19.0. This validates the reference engine's tested contracts;
it does not certify a production deployment or the rest of SafeGuard.
The separate Python integration suite passed **11/11** tests against the real
engine, including persistence, provenance, freshness, graph links, supersession,
concurrent instances and unavailable/corrupt runtime behavior.

## Honest limits

- Upstream explicitly describes this as a reference, not a production library.
  Its embedding is a deterministic hash mock, not a trained semantic model.
  Similar-word recall is demonstrated; semantic paraphrase and multilingual
  retrieval quality are not guaranteed.
- SafeGuard actively uses storage, retrieval, graph links, provenance and audit.
  Dreaming, sleep consolidation, human approval UI and conflict-resolution UI
  exist in the vendored engine but are not invoked by this product adapter.
- JSON persistence is synchronous and not crash-transactional. The wrapper adds
  per-store thread/process locking, but this is not a high-volume database.
- Memory is local, unencrypted, unbounded in size, and has no user-facing delete
  interface yet. Only non-sensitive demo data should be used.
- Reusing an old result is never independent fraud/identity verification.
- This H-MEM integration alone does not provide Meterless Nightshift, an LLM,
  Zetaris or the complete sponsor integration required by the hackathon.

## Quick two-run demo

Investigate `Acme registration fee job offer`, then investigate
`Acme job offer registration fee`. The second run should show a real memory ID,
source URL (if present), original checked time, ranking score and audit entry.
Use a short TTL in a test: after expiry the record remains inspectable, but
`context` is empty and `freshness` is `expired`.
