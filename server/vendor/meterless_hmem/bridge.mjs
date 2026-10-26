// SafeGuard adapter; separate from the unmodified Apache-2.0 Meterless reference.
import fs from 'node:fs';
import { HMEM, tokenize } from './reference/src/index.ts';

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const request = JSON.parse(Buffer.concat(chunks).toString('utf8'));
fs.mkdirSync(request.persist_dir, { recursive: true });
const hmem = new HMEM({
  persistDir: request.persist_dir,
  clock: () => request.now_ms,
  actor: 'safeguard-investigation',
});
let response;
if (request.operation === 'status') {
  response = { records: hmem.store.all().length, ledger_actions: hmem.ledger.stats(), node_version: process.version };
} else if (request.operation === 'remember') {
  const sameSubject = hmem.store.all().filter(m =>
    m.safeguard?.subject_key === request.observation.subject_key && !m.supersededBy);
  const previous = sameSubject.sort((a, b) => b.timestamp - a.timestamp)[0];
  const record = hmem.add({
    // The original query is the retrieval anchor; structured observations are
    // attached below, preserved by the reference store and audit snapshots.
    content: request.query,
    type: 'general',
    layer: 'working',
    source: request.observation.source,
    confidence: 0.85,
    tags: [...new Set(['safeguard-investigation', ...tokenize(request.query).slice(0, 8)])],
    provenance: {
      origin: 'plan_completion',
      learnedAt: request.now_ms,
      label: 'Recorded investigation observations; not an independent verification',
      refs: request.observation.source_refs,
    },
    supersedes: previous?.id,
  });
  // Extended application metadata. Core H-MEM shape and algorithm are unchanged.
  hmem.store.update(record.id, { safeguard: request.observation });
  for (const old of sameSubject) hmem.store.update(old.id, { supersededBy: record.id });
  response = { memory_ids: [record.id], supersedes: sameSubject.map(m => m.id), layer: record.layer };
} else if (request.operation === 'recall') {
  const result = hmem.query(request.query, { topN: request.limit, threshold: 0.35 });
  // Upstream query mutates access counters in memory. Persist them explicitly.
  hmem.store.persist();
  response = {
    memories: result.memories.map(({ memory, relevance }) => ({
      id: memory.id,
      content: memory.content,
      relevance,
      layer: memory.layer,
      confidence: memory.confidence,
      source: memory.source,
      provenance: memory.provenance,
      entities: memory.entities,
      related_to: memory.relatedTo,
      superseded_by: memory.supersededBy || null,
      access_count: memory.accessCount,
      observation: memory.safeguard || null,
    })),
    trace: result.trace,
  };
} else {
  throw new Error('Unknown SafeGuard H-MEM operation');
}
process.stdout.write(JSON.stringify(response));
