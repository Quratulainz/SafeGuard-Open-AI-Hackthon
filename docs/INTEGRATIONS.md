# SafeGuard sponsor service adapters

`server/integrations.py` contains real HTTP adapters for Zetaris and Meterless
Nightshift. They use Python's standard library. Mock tests validate contracts
and failure handling; they do not prove that a live account or runtime works.
No cloud resources, accounts, API keys or model downloads are created here.

## Default and optional execution

The app defaults to `SAFEGUARD_ANALYSIS_MODE=rules`,
`SAFEGUARD_MEMORY_MODE=local`, and `SAFEGUARD_DOMAIN_PROVIDER=none`. Thus startup
and ordinary message checks do not call these adapters. Set analysis `model`
for Nightshift and domain provider `zetaris` for domain SQL. A failed model
request falls back visibly to rules; missing services never count as successful
verification. H-MEM is separately enabled with memory mode `hmem`.

The adapter functions below still perform real requests when called directly.
Historical live evidence describes the connected evaluation, not a promise
that optional services are online in the default configuration. See
[reproduction](OPTIONAL_SERVICES.md) for setup and [competition evidence](HACKATHON_REQUIREMENTS.md)
for the limits of a credential-free mode.

## Website-result scope

The v0.3.2 webpage check is separate from the model's three-value risk schema.
A green webpage result means the current scoped page check found no warning
signs, not that Zetaris, TLS, a model or a feed certified an official company.
Incomplete fetch/context stays explicitly incomplete; a missing optional adapter
does not by itself imply that a site is suspicious. See [website checks](WEBSITE_CHECKS.md).
The recorded model-regression table below remains historical and is not rewritten
to pretend the newer website policy existed in that run.

## Configuration

The adapters read the process environment on every call. The app may load a
local, gitignored `.env` using its existing loader before calling them. These
values must never appear in source, screenshots, logs or a public repository.

### Zetaris deployed Query API with UI login

The official hackathon bundle deployed on 2026-10-25 was verified through an
SSH tunnel using this explicit configuration:

```dotenv
ZETARIS_QUERY_ROUTE=ui_query
ZETARIS_BASE_URL=http://127.0.0.1:3000
ZETARIS_REST_URL=
ZETARIS_API_KEY=
ZETARIS_USERNAME=YOUR_INSTANCE_USER
ZETARIS_PASSWORD=YOUR_PRIVATE_PASSWORD
ZETARIS_ORG_ID=YOUR_ACTUAL_NUMERIC_ORG_ID
ZETARIS_QUERY_LIMIT=100
ZETARIS_TIMEOUT_SECONDS=60
ZETARIS_EVIDENCE_TABLE=security.domain_evidence
```

This route logs in at `POST /api/auth/login` with `username` and `password`.
The observed response contains `idToken`, `refreshToken`, and numeric `orgId`.
The adapter uses the returned organization ID, and rejects a configured ID
that differs. It keeps only the access JWT in process memory, with expiry based
on its `exp` claim minus 30 seconds and a maximum one-hour cache lifetime.
Decoding `exp` is a cache hint, not local verification of the token's signature;
the service authenticates every request. A query receiving HTTP 401 can log in
again once. HTTP 403, repeated 401 and network failures do not cause a login
loop. Refresh tokens are not retained; this is re-login, not an implementation
of the separate refresh-token API. An explicitly supplied API key takes
precedence and is never replaced by a login after an authorization failure.

Queries use `POST /api/proxy/query/sql/start` with `select` and `pageLimit`.
This API accepts SELECT queries and page sizes from 1 to 100. The adapter
normalizes the verified `records` array of named objects and retains
`total_count`, `page_number`, and `total_pages`. It reads only the first page;
additional records/pages set `truncated=true`. Empty results remain empty.
The returned `queryToken` is used only to close the server-side query cache with
`DELETE /api/proxy/query/sql/close/{queryToken}`. It is never returned to the
application. Closing also happens when row parsing fails; a close failure is
reported rather than claiming full success. Successful results include
`query_closed=true`.

The deployed `/redoc/docs.yaml`, accessed with the instance user's Basic
authentication, confirmed these Query API contracts. Real checks passed for
authenticated `SELECT 1`, an `example.com` row, and an absent-domain lookup.
The registered `security.domain_evidence` dataset currently has exactly one
CSV row: an attributed IANA documentation-domain fact with
`record_kind=curated_demo_observation`. It includes `source_url`, `observed_at`,
`indicator`, `observation` and `notes`. It is a demonstration dataset, not a
threat feed or a website safety certification. Its registration used the
administrator SQL Editor API once; the application adapter remains read-only.
The existing sample datasets were preserved.

For a fresh bundle installation, generate a private administrator password
that meets the vendor's lowercase/uppercase/digit/special-character rule.
The live initialization rejected a URL-safe random string without an allowed
special character. A 44-character random value including `!` was used for the
successful initialization; it is stored only in private configuration. Do not
reuse a published bundle default or place credentials in documentation.

### Zetaris direct REST (legacy SQL Editor route)

```dotenv
ZETARIS_REST_URL=https://YOUR-INSTANCE/api/v1.0
ZETARIS_ORG_ID=YOUR_NUMERIC_ORG_ID
ZETARIS_API_KEY=YOUR_PRIVATE_KEY
ZETARIS_QUERY_LIMIT=100
ZETARIS_TIMEOUT_SECONDS=30
ZETARIS_EVIDENCE_TABLE=security.domain_evidence
```

Use the real instance API address, not the Zetaris Cloud account-management
dashboard. Local instances can use `http://localhost:8888/api/v1.0`. The
organization ID must be the numeric ID from the instance's Management page.
This direct route requires an existing bearer key. The adapter does not create
keys or accounts. A read-only service account is recommended for ongoing use;
the current isolated evaluation uses its private initial administrator login.

Direct SQL follows the upstream `RestChannel.run` contract:

- `POST {ZETARIS_REST_URL}/sql-editor/sqls/run`.
- Headers: `Authorization: Bearer ...`, `X-Org-ID`, fresh UUID `X-Request-ID`.
- Body: `queryId` UUID, `sql`, `source: "SqlEditor"`, `limit`.
- Rows are read from the JSON response's `data` array. If column names are
  absent, array positions are preserved as `c1`, `c2`, etc.; semantic column
  names are never guessed. Named object rows, explicit `columns`, and the
  deployed SQL Editor's `headers` labels are kept.

### Zetaris UI proxy (legacy SQL Editor route)

For the older SQL Editor helper route, leave `ZETARIS_REST_URL` unset
and set `ZETARIS_BASE_URL` to the web UI origin (no path). Keep the same API key
and organization ID, or use the UI login settings described above. Set
`ZETARIS_QUERY_ROUTE=ui_proxy`. Optional `ZETARIS_ENGINE_ID` is passed to this
route only.

The adapter sends `POST /api/proxy/sql-editor/sqls/run-query` with `sql`,
`limit`, and optional `engineId`, as in the official `query_zetaris.py` helper.
Without `ZETARIS_QUERY_ROUTE`, a REST URL selects `rest`; otherwise the default
is `ui_proxy` for compatibility. `ui_query` must be selected explicitly.
There is no silent retry against a different endpoint, protocol or provider.

### Evidence dataset

`query_domain_evidence(domain)` queries the configured table's `domain` column
by exact hostname. The table name must have two or three simple identifier
segments, e.g. `security.domain_evidence`. Domain input is IDNA-normalized and
strictly validated. This function never accepts SQL from a browser or model.
The table should contain named columns such as `domain`, `source_url`,
`observed_at`, `indicator`, and `notes`; the adapter does not create the table
or fabricate rows. Preserve licenses, timestamps and provenance when preparing
data. If the instance only returns positional columns, the integration layer
must map a verified table schema explicitly before presenting semantic claims.

`query_zetaris(sql, limit=...)` is a lower-level interface for trusted server
code. It permits only a deliberately limited single SELECT/SHOW/DESCRIBE
statement, rejects comments and write keywords, and caps returned rows at
1,000. Do not expose this general function as an arbitrary browser SQL API.
The SQL guard is a supplementary check, not a replacement for database access
controls.

### Meterless Nightshift

```dotenv
METERLESS_BASE_URL=http://127.0.0.1:8088/v1
METERLESS_RUNTIME_TOKEN=YOUR_PRIVATE_RUNTIME_TOKEN
METERLESS_MODEL=meterless/auto
```

Aliases supported: `NIGHTSHIFT_BASE_URL`, `NIGHTSHIFT_TOKEN` or
`METERLESS_API_KEY`, and `NIGHTSHIFT_MODEL`. Canonical settings take precedence.
The token is Nightshift's actual runtime token; `rt-local` is not accepted.
URLs ending in `/v1`, `/v1/models`, `/v1/chat/completions` or `/healthz` are
normalized to a single `/v1`. A missing scheme means HTTP, allowed only for
localhost/loopback. Remote endpoints require HTTPS. URLs with embedded
credentials, queries, fragments or unexpected paths are rejected. Redirects
are not followed, so bearer credentials cannot cross to another destination.

Every request includes the bearer token and `meterless-app: safeguard-ai`.
Chat also includes `meterless-scope: user`. Models are routing modes, not
necessarily the actual backend model: `/v1/models` must return at least one
`meterless/*` ID for a successful status check. Unknown future Meterless modes
are retained. `/healthz` alone is not treated as an integration test.

`analyze_evidence(evidence, subject="...")` posts a non-streaming chat request
with a 180-second timeout. Input may be one dictionary or a list of dictionaries.
Existing unique `id` values are preserved; otherwise records receive E1, E2,
etc. The model sees a JSON-encoded string of evidence, preceded by instructions
that the evidence is untrusted data. The adapter validates this response:

```json
{
  "summary": "Evidence is incomplete.",
  "risk_level": "unknown",
  "claims": [{"text": "A lookup returned no matching record.", "evidence_ids": ["E1"]}],
  "uncertainties": ["A miss does not prove safety."],
  "next_steps": ["Check another independent source."]
}
```

Risk values are `elevated`, `caution`, or `unknown`. Every claim must cite an
existing input ID. Invalid JSON/schema/references produce `invalid_response`;
raw model text is not returned to the UI. Schema validation does not prove a
claim is factually supported: the caller must check evidence sufficiency and
keep analysis separate from independently verified facts. No model output
modifies the existing keyword score or executes an action.

After schema/reference validation, `server/evidence_validation.py` applies a
bounded support check to the complete current text evidence (up to the recorded
8,000-character input limit), accessible page excerpts and attributed adverse
records. It checks requests in their local clause context, including English
and Chinese negation and a separate request after protective wording. It does
not treat keyword matches, missing lookups or historical memory as current risk
facts. If a raised risk has no recognized support, it returns `unknown`, removes
unsupported claims and supplies a neutral explanation. An adverse listing alone
can support at most `caution`. It never promotes `unknown` or certifies safety.

`semantic_validation` records the original `model_risk_level`, review status,
reason and supporting evidence IDs/quotes. In model mode, the dashboard, popup and floating
assistant identify the reviewed model basis and visibly explain
`abstained` or `limited` corrections. `supported` means the bounded check found
a relevant current behavior; it does not verify every model claim or every kind
of fraud. Unrecognized risks can remain `unknown` and require further checks.

The result separates `requested_model` (routing mode) from `model` (the name
reported by the service). `model_identity_reported` is false if the latter is
missing or still a `meterless/*` route. A reported name alone is not independent
proof of NVIDIA award eligibility; retain the actual Nightshift request trace.

### Runtime isolation for reproduction

The recorded Windows Nightshift 1.2.3 setup used Llama 3.2 3B Instruct Q4_K_M,
8,192 context, one slot, the `safeguard-ai` app bound to `local`, and global
privacy floor `local-only`. It also requires these two global setpoints:

```json
{"hmemKnowledge": false, "moaSynthesis": "off"}
```

These are Nightshift runtime settings, not SafeGuard environment variables or
guessed HTTP headers. Earlier live runs showed Nightshift's independent memory
inserting prior answers and its synthesis rewriting structured output. Disabling
those two paths isolates this app's evidence and JSON contract. SafeGuard's own
official H-MEM engine still stores and recalls history with provenance and TTL;
no memory is deleted. These runtime settings also affect other apps sharing that
runtime, so preserve its other settings and record the previous values.

The supported write contract in the installed official package is the local
control socket's `POST /admin/setpoints`; it is **not** an endpoint under the
public `/v1` API. `engine/IPC_SPEC.md` lines 96-109 documents the state write and
immediate next-request notification. `engine/js/data.js` defines
`hmemKnowledge` and the `moaSynthesis` enum (`off`, `auto`, `always`);
`engine/js/engine/dgx-client.js` uses `rt_setpoints_set` for desktop updates.
These references describe the inspected 1.2.3 package; check your installed
version's contract before adapting them.

For that Windows package, this Node command uses the package's official path
helpers and preserves the complete existing setpoint document. First set
`NIGHTSHIFT_ENGINE_DIR` to the installed package's actual `engine` folder. Keep
Nightshift running, and configure the local-only floor in its UI before running:

```powershell
$env:NIGHTSHIFT_ENGINE_DIR = 'C:\path\to\nightshift\engine'
@'
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import {pathToFileURL} from 'node:url';
const engine = process.env.NIGHTSHIFT_ENGINE_DIR;
const {defaultControlSocket, defaultStateDir} = await import(
  pathToFileURL(path.join(engine, 'win-compat.mjs')).href);
const file = path.join(defaultStateDir(), 'state', 'setpoints.json');
const before = JSON.parse(fs.readFileSync(file, 'utf8'));
if (before.privacyMin !== 'local-only') throw Error('Set the local-only floor first.');
const backup = file + '.safeguard-before-isolation.json';
if (!fs.existsSync(backup)) fs.copyFileSync(file, backup);
const body = JSON.stringify({...before, hmemKnowledge: false, moaSynthesis: 'off'});
await new Promise((resolve, reject) => {
  const req = http.request({socketPath: defaultControlSocket(),
    path: '/admin/setpoints', method: 'POST',
    headers: {host: 'meterlessd', 'content-type': 'application/json',
      'content-length': Buffer.byteLength(body)}}, res => {
    res.resume();
    res.on('end', () => res.statusCode >= 200 && res.statusCode < 300
      ? resolve() : reject(Error('Setpoints write failed: ' + res.statusCode)));
  });
  req.setTimeout(10000, () => req.destroy(Error('Setpoints write timed out.')));
  req.on('error', reject);
  req.end(body);
});
const after = JSON.parse(fs.readFileSync(file, 'utf8'));
if (after.hmemKnowledge !== false || after.moaSynthesis !== 'off')
  throw Error('Runtime did not persist both requested settings.');
for (const [key, value] of Object.entries(before)) {
  if (!['hmemKnowledge', 'moaSynthesis'].includes(key) &&
      JSON.stringify(after[key]) !== JSON.stringify(value))
    throw Error('An unrelated setting changed: ' + key);
}
console.log('Memory injection disabled; synthesis off; other settings preserved.');
'@ | node --input-type=module -
```

Verify both the persisted settings and a new request receipt: actual model
`local-runtime/llama-3.2-3b-instruct`, local routing with local-only floor, no
runtime H-MEM injection, and no synthesis adoption. A requested `meterless/local`
route alone is insufficient because an app binding can override a requested
mode. The adapter also sends `meterless-tier-split=off`, strict JSON Schema and
`max_tokens=1024`; it does not change runtime setpoints automatically.

### Recorded live regression

On 2026-10-25, the final seven-case run used the actual local 3B model and an
independent real SafeGuard H-MEM directory per case. Optional Zetaris and
BlackIPS services were disabled for this model evaluation; the public example
page used a real HTML request. These results do not establish those services'
connection status. All final responses passed JSON/reference validation.

| Case | Raw model risk | Final reviewed risk | Elapsed seconds |
|---|---|---|---|
| Public `https://example.com` | unknown | unknown | 4.282 |
| English request to send an OTP | elevated | elevated | 2.532 |
| English reminder not to share an OTP | elevated | unknown; review abstained | 2.462 |
| English protective wording followed by a request to send the OTP | elevated | elevated | 7.553 |
| Chinese request to send a verification code | elevated | elevated | 1.920 |
| Chinese reminder not to share a verification code | unknown | unknown | 1.966 |
| Chinese protective wording followed by a request to send the code | elevated | elevated | 1.752 |

All seven final outcomes matched the expected regression result. The English
reminder is a correction by the evidence check, not a correct raw model answer.
This small, deliberately selected regression set is not an accuracy benchmark.
`unknown` means no supported conclusion was established, never "safe".
Receipts reported local-only execution, no runtime memory injection, no
synthesis adoption and $0 cloud inference cost. Cost excludes electricity,
licensing and unrelated services. Receipt signatures were present but not
independently verified. The private evaluation record is
`nightshift-eval-20261025T103423325632Z` (full results, readable summary and
sanitized receipt proof); do not publish local tokens or runtime state.

After these changes, the full Python suite passed **101/101** in 11.490 seconds,
including 30 adapter, 10 coordinator and eight semantic-support test methods
(with English/Chinese subcases). The latter tests are deterministic/local and
are separate from the seven real model cases above.

## Public Python interfaces

- `query_zetaris(sql, *, limit=None)`: normalized rows, column labels, query ID,
  source, transport and timestamp on successful execution.
- `query_domain_evidence(domain)`: fixed domain lookup plus dataset provenance.
- `zetaris_status()`: authenticated `SELECT 1`; requires the expected result.
- `get_nightshift_models()` / `nightshift_status()`: authenticated model-list check.
- `analyze_evidence(evidence, *, subject='', feedback='')`: validated analysis and
  model metadata. Optional retry feedback accepts only the fixed codes
  `invalid_analysis_schema`, `invalid_analysis_response`,
  `invalid_analysis_evidence_reference`, or `unsupported_claim`. It never copies
  free-form feedback into the trusted prompt. The caller controls retry count.
- `integration_status()`: both status checks, performed sequentially.

Statuses are `unconfigured`, `unauthorized`, `unavailable`, `online`, and (for
invalid model output) `invalid_response`. `online` means that particular
request succeeded; a model-list success does not prove that generation works.
Error results contain a stable error code, never provider response bodies,
exception strings, credentials or submitted SQL. Known configured secrets and
secret-named fields are redacted from evidence sent to the model and results.

## Verification

Run `python -m unittest discover -s tests -p test_integrations.py -v` for mocked
contract, parsing, timeout, authorization, evidence-reference and redaction
tests. Separately verify a live authenticated query and live Nightshift chat
with authorized sample data. Missing credentials or a failed live test block that optional integration;
there is no fake success or other-model-provider fallback. The app may continue
with explicitly identified local rules.

This module does not implement a Meterless Engine. H-MEM/Markovian/etc. must
also power a real feature and pass its own tests to satisfy the event's full
Meterless requirement.

## Upstream contracts checked on 2026-10-25

- [Zetaris client setup](https://github.com/zetaris/getting-started/blob/main/docs/connections/client-setup.md)
- [Zetaris direct REST implementation](https://github.com/zetaris/getting-started/blob/main/scripts/zetaris_sql.py)
- [Zetaris UI proxy helper](https://github.com/zetaris/getting-started/blob/main/scripts/query_zetaris.py)
- [Zetaris authentication helper](https://github.com/zetaris/getting-started/blob/main/scripts/zetaris_api.py)
- [Nightshift provider contract](https://github.com/Meterless/Meterless/blob/main/docs/agent-ready/add-meterless-provider.md)
- [Nightshift hotspot](https://github.com/Meterless/Meterless/blob/main/docs/products/nightshift/hotspot.md)
