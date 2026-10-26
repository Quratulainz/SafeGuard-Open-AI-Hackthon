# SafeGuard modification diary

This file is append-only. Do not overwrite earlier entries.

---

## 2026-10-22 — Phase P1: provider-neutral IP reputation layer

### Files changed

Created:

- `server/ip_reputation.py` — public-IP validation, hostname resolution, provider interface, BlackIPS adapter, normalized evidence helpers
- `tests/test_ip_reputation.py` — unit tests with mocked HTTP (no live BlackIPS server)
- `MODIFICATION_DIARY.md` — this diary (no prior file existed in the tree)

Modified:

- `server/engine.py` — `inspect_url()` attaches `ip_reputation` after `safe_url()`; keyword scoring unchanged
- `server/app.py` — `POST /api/ip-check` with existing `X-Pairing-Key` auth

Not modified (by design):

- Chrome extension UI, keyword `PATTERNS`, `assess()` risk levels, Zetaris/Meterless/Nemotron paths

### Architecture decisions

- URL inspection pipeline: validate URL (`safe_url`) → extract hostname → resolve public IPs (`socket.getaddrinfo`) → optional provider → normalized evidence → SafeGuard result.
- SafeGuard result schema is vendor-neutral (`provider`, `ip`, `status`, `listed`, `source`, `checked_at`, `details`). BlackIPS `code`/`message` are mapped in the adapter only; `message` is treated as a feed/source id, not an attack category.
- `IpReputationProvider` is the extension point for BlackIPS, another TI feed, or later Zetaris-backed IP intelligence without rewriting `engine.py`.
- `BLACKIPS_BASE_URL` enables the HTTP adapter (`GET {base}/check?ip=`). Missing env → `status=unavailable`, inspection still succeeds.
- Only globally routable IPs are checked (IPv4 and IPv6 at the SafeGuard interface). Loopback, RFC1918/private, link-local, multicast, reserved, and unspecified addresses are skipped (`unsupported` / omitted from resolution).
- At most 4 public IPs are queried per URL. Existing `safe_url()` SSRF checks were not relaxed.
- A blacklist hit may add a cautious `verified_facts` line. A miss does not prove safety and does not change `risk_level`.
- Provider URL and credentials stay on the local server; they are not sent to the extension.

### Tests run

```
py -3 -m unittest discover -s tests -v
```

### Tests passed/failed

Passed: 21 tests (4 existing `test_engine` + 17 new `test_ip_reputation`).

Failed: none (after tightening multicast/reserved rejection; Python's `ipaddress.is_global` treated `224.0.0.1` as global on this interpreter).

### Limitations

- No real BlackIPS process is configured in this phase; unit tests mock `urlopen` / isolate JSON normalization.
- IP reputation is not used to raise or lower keyword `risk_level`.
- If HTML fetch fails, `app.py` still falls back to URL-text `assess()` without `ip_reputation` (existing fetch-failure contract).
- DNS rebinding between `safe_url()` and the reputation resolver remains a known prototype concern.
- The popup/dashboard do not specially render `ip_reputation` (UI redesign deferred).

### Rollback notes

1. Delete `server/ip_reputation.py` and `tests/test_ip_reputation.py`.
2. Revert `server/engine.py` (`ip_reputation` import, `inspect_url` merge).
3. Revert `server/app.py` (`check_ip` import and `/api/ip-check`).
4. Leave this diary entry in place or restore the previous diary snapshot.

Unset `BLACKIPS_BASE_URL` to disable the adapter without code rollback.

---

## 2026-10-22 — Phase P2: live BlackIPS as an optional external service

### Files created

- `docs/BLACKIPS_LOCAL_SETUP.md` — clone/run BlackIPS outside this repo; SafeGuard only uses `BLACKIPS_BASE_URL`
- `.env.example` — `BLACKIPS_BASE_URL=http://127.0.0.1:9091` (no secrets)
- `scripts/test_blackips_live.py` — manual live check; not collected by `unittest discover`

### Files modified

- `server/ip_reputation.py` — optional `.env` loader, `blackips_status()`; P1 adapter/normalization/risk merge left in place
- `server/app.py` — load project-root `.env`; `GET /api/integrations/blackips/status` (pairing-key auth)
- `tests/test_ip_reputation.py` — mocked status/env tests; live script private-IP refusal
- `MODIFICATION_DIARY.md` — this entry (P1 text not overwritten)

Not modified: keyword scoring, `risk_level` fusion, Chrome UI, Zetaris/Meterless/Nemotron. BlackIPS source was not vendored.

### Architecture decision

BlackIPS stays an optional local process:

SafeGuard → BlackIPS HTTP `GET /check?ip=` (default `http://127.0.0.1:9091`) → Redis → threat feeds.

SafeGuard does not talk to Redis. Missing or down BlackIPS cannot crash `inspect_url()`. Private/non-global IPs are still never sent. Provenance remains `provider=blackips`, `source=<feed id>`, `checked_at`; feed names are not attack categories; hits are not proof a website is malicious.

P1 review: no adapter defects required a redesign. Additions are status, docs, env example, and a live script.

### Environment variables

- `BLACKIPS_BASE_URL` — optional; example `http://127.0.0.1:9091`
- Loaded from the process environment, or from a gitignored project-root `.env` if the key is not already set
- `.env` was already listed in `.gitignore`

### Tests

```
py -3 -m unittest discover -s tests -v
```

Passed: 26 tests (previous 21 plus status/env/live-script-guard tests). None require a running BlackIPS instance.

Manual (not in unittest): `py -3 scripts/test_blackips_live.py <PUBLIC_IP>`

### Known limitations

- Operator must clone, configure Redis, load feeds, and run `blackapi` using upstream docs.
- Status probe uses public IP `1.1.1.1` against the local API; a miss still means reachable.
- `risk_level` is still keyword-only.
- HTML fetch failure still omits `ip_reputation` via the existing `app.py` fallback.

### Licensing / provenance note

BlackIPS (https://github.com/njcx/BlackIPS) and its aggregated feeds are external resources and are not bundled with SafeGuard. Operators must comply with upstream licensing and feed terms. SafeGuard only stores normalized check results from an API the operator chooses to run.

### Rollback notes

1. Remove `docs/BLACKIPS_LOCAL_SETUP.md`, `.env.example`, and `scripts/test_blackips_live.py`.
2. Revert P2 edits in `server/ip_reputation.py`, `server/app.py`, and `tests/test_ip_reputation.py`.
3. Leave the P1 diary entry and P1 adapter in place if rolling back only P2.

---

## 2026-10-25 - Phase P3: local investigation workflow and sponsor adapters

### Implementation at this revision

- Repaired the backend entry point and organized local server creation so an
  import does not create listeners or user data. Added local API tests, input
  checks and authenticated dashboard pairing using a separate HttpOnly session.
- URL retrieval failures retain already collected IP evidence; blocked/private
  destinations remain rejected. This does not remove the known DNS-rebinding
  limitation.
- Added `server/investigation.py`: an input-based plan, collection, historical
  recall, optional Nightshift analysis, schema/reference validation, at most one
  correction attempt, and operational traces. Tool gaps are explicitly partial.
- Added `server/integrations.py`, `tests/test_integrations.py` and
  `docs/INTEGRATIONS.md`. Zetaris uses the documented direct REST or UI-proxy
  route. Nightshift uses real bearer authentication and the compatible model
  list/chat endpoints. No successful service result is synthesized when an
  integration is absent. Errors do not expose provider response bodies or keys.
- Added `server/investigation_memory.py` and the pinned official Meterless
  H-MEM reference under `server/vendor/meterless_hmem/`, with its Apache-2.0
  license and upstream provenance. Python calls the actual engine through a
  local Node.js 24 bridge. Storage, ranking, graph links, audit and supersession
  are used; old observations are never fresh verification.
- Added H-MEM and investigation tests plus `docs/HMEM_INTEGRATION.md`.
  Investigation contract tests use local fixture HTTP services, not sponsor
  production endpoints.
- Updated the dashboard to show real service states, evidence records,
  separate keyword and AI indicators, citation links, historical recall and
  execution traces. The extension's compact controls remain in place.
- Added `scripts/run_local.ps1` and updated `.env.example` for local launch,
  the Node executable override and optional services.
- Rewrote `README.md` to describe current behavior, Node.js 24, dashboard and
  extension pairing, three safe demo inputs and service setup. Removed the
  obsolete claim that Cursor is mandatory. Current requirements include both
  a working Meterless Engine and Nightshift as the primary AI provider.

### Verification and evidence boundaries

- Sponsor-adapter suite: 26 tests passed on 2026-10-25. HTTP is mocked in this
  suite; it validates request contracts, failure states, parsing, redaction,
  evidence references and bounded response handling, not live connectivity.
- The H-MEM integration guide records 13/13 upstream conformance checks and
  10/10 Python integration tests against the actual vendored engine on
  Node.js 24.19.0. These are local engine checks, not proof of Nightshift or
  Zetaris operation.
- API and investigation tests cover local requests and fixture-backed flows.
  A full-suite result must include its skipped count; Node-dependent cases can
  skip when Node is absent from PATH.
- No live Zetaris query, Nightshift generation or NVIDIA model use has yet
  been demonstrated against the team's actual configured services at the time
  of this entry. Cloud account access alone does not satisfy that requirement.

### Remaining work

Configure the actual Zetaris instance, authorized evidence dataset and
Nightshift runtime; capture real query/model traces and review source-backed
outputs. Validate setup and the extension on the demonstration machine, then
prepare the public repository, real 1-4 minute video, deck and sponsor
explanation. Model and memory outputs must retain their stated limitations.

### Data and rollback notes

Local records, pairing credentials, H-MEM persistence and traces remain under
the gitignored `server/local-data/` by default and are unencrypted. Do not copy
them into submission materials. Preserve this append-only diary and the
upstream license/provenance. If reverting this phase, restore a coordinated
snapshot of app, workflow, adapters, memory bridge, dashboard and tests; do not
remove user data as part of a code rollback.

---

## 2026-10-25 - Phase P4: real Nightshift local generation and output constraints

### Live result and its limits

- The official Nightshift desktop runtime at localhost port 8088 ran the local
  Llama 3.2 1B Instruct model with an 8192-token context and one runtime slot.
  Two structured responses passed the SafeGuard output/reference checks.
  Investigation `run-47dcd39da9b2` reported `status=online` and model
  `local-runtime/llama-3.2-1b-instruct`; real H-MEM recall and storage also ran.
  These were actual model requests, not mocked HTTP fixtures.
- Nightshift receipts for the observed requests reported successful local-only
  execution with zero cloud cost. This describes those requests only. Route IDs
  remain distinct from the model identity reported by the runtime; app routing
  settings can take precedence over a requested routing mode.
- The 1B model's semantic quality was insufficient: ordinary example.com content
  was labelled elevated using unavailable BlackIPS and unconfigured Zetaris
  checks, with generic claims rather than concrete supporting observations.
  Schema/reference validity does not validate that reasoning.
- A larger local 3B model is under evaluation. No successful 3B result is claimed
  in this entry. No live Zetaris query or NVIDIA model use has been demonstrated;
  no AWS resources were created as part of this work at this point.

### Changes

- `server/integrations.py` now sends a strict JSON Schema with exactly the
  existing analysis fields, no extra object fields, and claim references
  restricted to this request's evidence IDs. It sets `max_tokens=1024` and
  `meterless-tier-split=off`. The official Nightshift proxy, orchestrator and
  local runtime were inspected to confirm the parameters are forwarded.
- When a model response is structurally invalid, the safe failure result keeps
  the requested route and reported model identity without exposing raw model
  content. The existing response validator and its rejection rules remain.
- The system prompt now states that missing/empty/unavailable checks prove
  neither safety nor risk; historical context is not current verification;
  risk elevation requires concrete current observations. It permits empty
  claims, requires record-supported observations, distinguishes instruction
  handling from claims of maliciousness, and requests concrete user checks.
  This prompt change still requires live semantic evaluation; it is not a
  guarantee that a small model follows the rules.
- `README.md` now separates the demonstrated Nightshift/H-MEM integration from
  model-quality issues and the outstanding Zetaris/data-layer work.

### Verification

- `py -3 -m unittest discover -s tests -p test_integrations.py -v`: 28/28 passed
  after the structured-output and prompt changes. These are mocked adapter
  tests covering the HTTP/schema contract, bounded evidence IDs, model identity
  on failure and existing error handling; they do not measure model semantics.
- No test was added solely to mirror the prompt text. No live AI request was
  made by the prompt/documentation edit itself.
- The earlier P3 entry records the state before the successful live requests;
  its then-pending Nightshift connection is superseded by this entry.

### Next checks

Evaluate the updated prompt and candidate 3B model using an isolated test data
directory so earlier 1B summaries do not contaminate the comparison. Preserve
existing records. Compare an ordinary page, a concrete credential/fee request,
and a legitimate warning against that request, including unavailable-service
and historical-only cases. Complete Zetaris authentication and a relevant
evidence query before claiming the required data-layer integration.

---

## 2026-10-25 - Phase P5: local 3B evaluation and keyword-context correction

- Downloaded Llama 3.2 3B Instruct and replaced the active 1B route with
  `local-runtime/llama-3.2-3b-instruct`. Nightshift reports local/local-only
  routing with an 8192-token context and one slot. Real generation works.
- The first three live evaluation cases matched expectations in two cases.
  A legitimate reminder not to share an OTP was a false positive: the only
  citable content observation was a derived phrase match about credentials,
  while the full original sentence had no evidence ID. This is an unresolved
  semantic limitation at the time of this entry, despite valid structured output.
- Added one sentence to `server/integrations.py`'s system prompt: a
  `keyword_signal` is a derived phrase match, cannot alone raise risk, and must
  be interpreted using the complete submitted text's behavior and negation.
  No schema, interface or validator rule was relaxed. The companion workflow
  change to include the original text as evidence is being handled separately;
  the corrected complete flow still needs live regression evaluation.
- Updated `README.md` to report the real 3B connection, the two-of-three result
  and the outstanding false positive without presenting it as reliable detection.
- Before this correction, the full Python suite passed 87/87 in a fresh valid
  run (11.630 seconds); the official H-MEM conformance result remains 13/13.
  Those checks do not establish model semantics. This entry supersedes P4's
  statement that 3B generation had not yet been demonstrated.
- The targeted adapter suite was rerun after the one-sentence prompt change:
  28/28 passed. No prompt-mirroring test was added.
- README reproduction notes record the separate official runtime executable,
  Llama 3.2 3B Instruct Q4_K_M, one lane with 8192 context/one slot, the
  `safeguard-ai` local binding and local-only privacy floor. They distinguish
  the actual reported model from a reused old lane ID. Tokens stay only in the
  local `.env`; no private absolute paths, runtime binaries or model files were
  added to repository documentation or source.

---

## 2026-10-25 - Phase P6: runtime isolation and auditable risk review

### Findings and changes

- Full submitted message text now has a current evidence ID (up to 8,000
  characters, with explicit truncation metadata). Phrase matches remain derived
  `keyword_signal` records and cannot alone establish risk. Historical records
  retain their original time and cannot support a current risk conclusion.
- Fresh SafeGuard memory directories did not initially eliminate contamination:
  Nightshift's independent automatic memory injected earlier model answers, and
  its synthesis could replace strict JSON with prose. Using the official 1.2.3
  control interface, set only `hmemKnowledge=false` and `moaSynthesis=off`, while
  preserving other setpoints and the `local-only` privacy floor. No saved memory
  was deleted and SafeGuard's own real H-MEM integration remains active.
- Added `server/evidence_validation.py`. After schema and reference validation,
  it checks bounded current behavioral support, including English/Chinese
  negation, a distinct request after protective wording, and attributed adverse
  listings. Missing tools, keywords and history are not current risk facts.
  Unsupported raised risk is withheld as `unknown`; a listing alone supports
  at most `caution`. This is neither complete semantic verification nor a
  safety classification, and unrecognized behavior can remain unknown.
- Added brief contrasting prompt examples. The adapter retains actual
  Nightshift generation and includes `semantic_validation` with original model
  risk, support observations and correction reason. The coordinator records
  `validate_risk_support` in its trace. No extra model call was introduced by
  this check; the existing structural-response retry remains bounded.
- The dashboard, popup and floating assistant now label the result
  **AI + evidence review**. When review abstains or limits a conclusion, they
  visibly show the original model risk, reviewed risk and reason. Unknown is
  explicitly not a safety confirmation; retained claims are labelled as such.
- README and both integration guides record the required runtime setpoints,
  preserved project H-MEM, reproduction contract and evidence limitations.

### Verification

- The final real 3B run (`nightshift-eval-20261025T103423325632Z`) covered seven
  cases: ordinary example.com, English and Chinese credential requests,
  protective reminders, and mixed wording that warns against disclosure but
  then requests the code. All seven final outcomes matched expectations.
- The English reminder was still `elevated` in the raw model output. The
  bounded support check abstained and returned `unknown`; this is a system
  correction, not a correct raw model judgment. The seven selected examples
  are a regression set, not a general accuracy benchmark.
- Every case used an independent real project H-MEM directory. The actual model
  was `local-runtime/llama-3.2-3b-instruct`, with local-only routing, no runtime
  memory injection, no synthesis adoption and reported cloud inference cost of
  $0. Optional Zetaris and BlackIPS were disabled for this evaluation, so it
  makes no claim about those service connections. Final JSON/reference checks
  passed. Receipt signatures were not independently verified; reported costs
  exclude electricity, licensing and unrelated services.
- The complete Python suite passed **101/101** in 11.490 seconds. This includes
  30 adapter, 10 coordinator and eight semantic-support methods with multiple
  English/Chinese subcases. These local tests are distinct from the live model
  evaluation. The official H-MEM conformance result remains the previously
  recorded 13/13; it was not rerun just for this documentation update.
- This entry supersedes P5's pending semantic regression. Other agents' service
  connection and deployment work is recorded separately after verification.
- The later display/documentation update passed JavaScript syntax checks for
  the dashboard, popup, floating assistant and documented configuration snippet.
  It did not rerun the model evaluation, alter runtime state or repeat the full
  Python suite.

## P7 — Verified local/AWS integration and extension acceptance (2026-10-25)

- Deployed the official Zetaris bundle and a hardened BlackIPS fork on one
  temporary AWS Linux instance. Services bind to loopback and are reached by
  authenticated SSH tunnels. Both an AWS schedule and an OS timer terminate the
  instance at 2026-10-27 10:53:17 UTC; its encrypted root disk is deleted with it.
  The first short attempt was terminated and its associated resources cleaned
  after a new-role propagation error; the replacement's guards were verified.
- Fixed Zetaris's initial password bootstrap to satisfy its documented policy.
  Verified actual login, numeric organization, SELECT 1, table schema, exact
  example.com lookup and an absent-domain result. The new Query API adapter
  uses its measured records/pagination contract and closes server query caches.
  Credentials remain private; no token or credential is embedded in source.
- Registered one IANA observation in security.domain_evidence, clearly marked
  curated_demo_observation. This proves real SQL integration, not a complete
  threat or company-verification database.
- BlackIPS imported 145,616 real public IPv4 addresses from two dated feeds.
  Fixed Redis module initialization by replacing command deletion with a narrow
  command/key ACL. Verified healthy empty data, positive/negative lookups,
  invalid/private/IPv6 rejection, actual Redis outage and persistence on restart.
  Daily refresh is active; failed refreshes never extend old evidence freshness.
- Extension pairing now validates a private backend endpoint before confirming
  saved state, rejects empty keys, reports real messaging errors, and supports
  pairing inside its current popup. The dashboard offers masked manual copying.
  The user confirmed real installed-Edge scanning and the floating assistant.
- Corrected final risk persistence: reviewed AI risk is the public final risk,
  raw keyword risk is separate, and current independent listings retain a
  caution floor. All three views show the final reviewed risk and its basis;
  older historical records retain their original labels and are not rewritten.
- Final live backend acceptance passed all four cases: protective warning with
  existing history -> unknown; explicit OTP request -> elevated; example.com
  with actual Zetaris/BlackIPS evidence -> unknown; repeated warning after the
  risky case -> unknown. Project history was actually recalled on the warnings.
  Unsupported raw model conclusions were withheld by the evidence review.
- Final automated verification: 113 Python tests, 12 extension pairing tests,
  and 13 risk-rendering tests passed. These are separate from the real API/model
  acceptance and the user's manual installed-extension confirmation.

## P8 — Local-first usability and reproducible optional integrations (2026-10-25)

- Default analysis now uses current evidence rules, SQLite history and optional
  private dated IP snapshots. Default mode does not call a model, Zetaris or
  H-MEM. Model mode remains available and falls back visibly to rules.
- ProofShield uses a short chat response with green safe, yellow uncertain and
  red danger labels plus icons. Green has a narrow explicit protective-message
  scope; unavailable data and blacklist misses never imply safety. Sources and
  limitations are collapsed. Previous investigations never become new evidence.
- Removed copied pairing codes. A stable public extension identity can obtain
  an internal loopback token automatically; unrelated origins cannot. Private
  APIs still require the token. The dashboard opens directly on this computer.
- Added persistent opt-in assistant display on explicitly approved websites,
  with page/startup activation and removal when disabled. The assistant does
  not scan pages automatically. The user confirmed that the actual upgraded Edge
  extension connects automatically and appears after refreshing example.com.
- Added subscription editing, optional cancel_on and a long_term marker while
  preserving existing records. Browser startup and hourly checks cover both
  renewal and cancellation dates starting seven days ahead, with daily target
  deduplication and overdue follow-up. No payment/cancellation is performed.
- Added provenance/hash-checked private IP snapshot synchronization and restore.
  Missing/stale snapshots remain unavailable; message/subscription features
  continue. Raw feeds are excluded from public source packages pending license
  review. Historical cloud observations remain recorded as historical.
- Added Chinese setup instructions, judge reproduction, backup, integration,
  competition-evidence and optional AWS/Zetaris deployment guides. Default
  read-only deployment templates have local guard tests; they were not used to
  launch new resources. No source confirms that documentation-only adapters
  satisfy required sponsor integrations. Remote/Nemotron quality is unverified.
- Validation: 130 Python tests, 33 extension/rendering tests and 7 deployment
  guard tests passed. Actual dashboard checks verified three verdict colors,
  history isolation, subscription editing, retained long-term preference and
  clearing a cancellation date. The temporary UI-test subscription was removed;
  pre-existing subscriptions were preserved. Real private snapshot acceptance
  verified 145,616 entries with network/model/Node calls forbidden.


## P11 — Portable source delivery (2026-10-25)

- Added project-relative launchers, a standard-library-only startup check and
  English first-run/new-device instructions. Python is explicitly not bundled.
- Removed the PowerShell helper's Codex-cache lookup. The default app needs no
  Node, model, Docker, account or configuration from the original computer.
- Added four tests using relocated copies with spaced/non-ASCII paths, isolated
  Python and no site packages, private config, data or Node/Codex environment.
  Verified fresh HTTP startup, occupied-port errors, records across restart,
  and database-only migration with a new device-specific local token.
- The 182 Python tests passed. The unchanged same-day JavaScript/deployment
  baselines remain 58 and 7 (247 checks total). Actual Windows `.cmd` and
  PowerShell prerequisite checks passed with Python 3.13.7. No physical second
  computer or native macOS/Linux run is claimed.
- The release includes all root launchers and preserves Unix executable modes.
  It checks the extracted launcher and repeats the four portability tests before
  HTTP smoke acceptance. Hashes and actual outcomes accompany the final ZIP.

## P10 — v0.3.2 website checks and English date controls (2026-10-25)

- Added a positive current-page decision path. A usable HTTPS page can be green
  after URL, redirect, form and current-evidence checks; missing optional services
  alone do not force yellow. This does not certify official company identity.
- Separated incomplete inspection from a supported concern. Normal login entry
  is no longer treated as out-of-band credential disclosure. Concrete OTP or
  payment requests, unsafe destinations and current listings retain warnings.
- Bounded HTML to 1 MiB and text to 16,000 characters, verified TLS, recorded
  redacted redirects and checked final-host IP evidence. Added structural forms,
  base URL resolution, control association and submit overrides without values.
- Explicit extension page scans provide bounded visible text/form structure.
  The worker binds it to the current main-frame tab, strips unknown properties,
  and the server validates it again. No capture occurs merely on assistant
  display or when the user pastes a URL. Browser context cannot bypass TLS,
  blocked redirects, missing form metadata or a supported current warning.
- Added an English calendar and required-field/date validation independent of
  browser locale. Actual UI date selection and empty-form validation passed.
- Validation: 178 Python, 58 JavaScript and 7 deployment-template tests passed
  (243 total). Actual local HTTP checks returned green for six public pages;
  JobStreet returned 403 and an explicit incomplete result. Details and manual
  extension acceptance limits are in docs/RELEASE_ACCEPTANCE.md.
- After the user reloaded, the backend recorded a Google browser-context scan
  at 15:40:30 UTC, with one form observation and a safe verdict. The extracted
  source archive also passed nine local HTTP acceptance checks with external
  networking and child processes forbidden.
- No new cloud resources or paid model calls were made. Default rules/local
  history remain usable without optional integrations. Private data stays out
  of the source archive; extracted archive acceptance is recorded separately.

## P9 — v0.3.1 English release (2026-10-25)

- Converted application interface labels, assistant messages, notifications,
  rule-generated explanations and optional model-output instructions to English.
  Multilingual detector inputs and deliberate multilingual test fixtures remain
  supported; verbatim submitted input and evidence are not rewritten.
- Added `server/presentation.py` to translate exact known legacy generated text
  when reading history. Stored input, evidence, decisions, timestamps and the
  SQLite database remain unchanged. Two new tests verify this presentation-only
  compatibility behavior. Unknown user/source text is not translated by a broad
  replacement rule.
- Replaced the translated quick-start with `docs/GETTING_STARTED.md`, updated
  README and verdict documentation, and added an English release changelog.
  All authored documentation and release filenames are English. The original
  supplied competition PDF is preserved separately and omitted from the source
  archive. `.cursor/mcp.json` contains no untranslated documentation.
- Kept the stable extension identity and automatic local connection. No new
  pairing or reinstall is required for this language update; the extension can
  be reloaded as part of its usual update workflow. The user confirmed that the
  actual installed Edge extension v0.3.1 was reloaded and is fully English. This
  is real user acceptance, separate from automated or mocked extension tests;
  the remaining dashboard calendar change requires no further extension reload.
- Validation: all 132 Python tests, 35 extension/display tests and 7 deployment
  guard tests passed (174 total). Actual HTTP/dashboard checks verified English
  Safe for the protective reminder, Danger for credential solicitation and
  Uncertain for ordinary input, without history cross-contamination.
- The release pipeline extracts the exact candidate archive to a temporary
  directory and checks local HTTP behavior, English conclusions, origin-bound
  connection, isolated history and subscription editing before emitting the
  archive, hash manifest and acceptance report. It forbids outbound networking,
  DNS and child processes during that smoke check and does not read the original
  `.env`. Historical deliverables were moved to private archival storage.
- No AWS resources were created or changed, no external publication occurred,
  and no root project license was selected. Historical service/model acceptance
  remains historical; the English release does not claim new live integrations.
