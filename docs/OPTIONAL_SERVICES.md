# Optional services: setup and real acceptance

Default operation is Python-only (`rules/local/none`). Change only the settings
you intend to enable in private `.env`, preserve other values, and restart the
backend. Process environment variables take precedence over `.env`. Do not
publish tokens or use saved final answers to simulate a service.

## Official Meterless H-MEM

Install Node.js 24. Set `SAFEGUARD_MEMORY_MODE=hmem`; optionally set
`SAFEGUARD_NODE` to its executable. No npm packages or API keys are needed.
Run the upstream conformance runner and Python bridge tests from
[HMEM_INTEGRATION.md](HMEM_INTEGRATION.md). Investigate two related non-sensitive
messages; inspect real stored/recalled IDs, timestamps and historical markers.
History is never current evidence. Revert to `local` to keep SQLite history
without calling Node. The real reference uses deterministic hash embeddings;
it is not a trained multilingual semantic model.

## Official Nightshift desktop: demonstrated local configuration

Obtain the desktop runtime from [Meterless](https://meterless.ai/) and follow its
[official provider/hotspot guide](https://github.com/Meterless/Meterless/blob/main/docs/agent-ready/add-meterless-provider.md).
The web interface alone is not the demonstrated local API hotspot. Review the
runtime and model license/availability; no free-service promise is made here.

1. Start the official runtime and its local API hotspot. The tested runtime was
   Windows Nightshift 1.2.3, listening at `http://127.0.0.1:8088/v1`.
2. Download **Llama 3.2 3B Instruct Q4_K_M** through its supported local runtime
   controls. Use one lane, 8,192 context and one slot for the recorded setup.
3. Bind application **safeguard-ai** to `local` and set privacy floor `local-only`.
   An app binding can override the request route; verify the receipt.
4. Disable Nightshift `hmemKnowledge` and set `moaSynthesis=off`, preserving all
   other settings. These prevent unrelated memory insertion and JSON rewriting.
   The version-specific supported procedure is in
   [Runtime isolation](INTEGRATIONS.md#runtime-isolation-for-reproduction).
   This does not disable SafeGuard's separate optional H-MEM reference.
5. Store the actual runtime proxy token only in private `.env`:

```dotenv
SAFEGUARD_ANALYSIS_MODE=model
METERLESS_BASE_URL=http://127.0.0.1:8088/v1
METERLESS_RUNTIME_TOKEN=YOUR_PRIVATE_RUNTIME_TOKEN
METERLESS_MODEL=meterless/local
```

Restart SafeGuard. First inspect the model-list status, then submit a fresh
message and inspect generation status, cited evidence IDs and the receipt.
Expected actual identity in the recorded setup is
`local-runtime/llama-3.2-3b-instruct`. An old lane ID containing `1b` or the
routing alias `meterless/local` does not identify the loaded model.

The adapter sends Bearer authorization, `meterless-app: safeguard-ai`, user
scope, strict JSON Schema, `max_tokens=1024` and `meterless-tier-split: off`.
No caller page/model can choose a new provider or execute an action. Schema
validation is followed by bounded support checking. A failed model request
falls back visibly to rules. Model `unknown` alone is not positive safety
evidence; any green webpage result needs its separate current-page checks. The 3B model
misread protective wording in real tests, so successful connectivity does not
establish strong fraud-detection accuracy. Do not feed personal secrets.

## Optional stronger/remote model: interface available, not demonstrated

Configure an authorized provider/model **inside Nightshift** using the official
runtime documentation. Choose a route actually returned by its `/v1/models`,
bind `safeguard-ai` accordingly and set `METERLESS_MODEL` to that route. If the
runtime itself is remote, use a real HTTPS Nightshift URL and its private token.
Do not replace this URL with an unrelated OpenAI-compatible provider and call
it Nightshift. There is no direct-provider bypass implemented here.

Remote execution requires deliberately changing the local-only app/privacy
policy and reviewing costs/data disclosure. Set provider/runtime limits before
a test, use synthetic input, and verify routing, actual model, JSON/reference
validation, receipt and incurred usage. No remote model or NVIDIA Nemotron has
been run in this project. Better quality, free usage and award eligibility are
not guaranteed. Missing configuration or failure is never reported as success.

## Zetaris: demonstrated single-host bundle

Obtain your own authorized official bundle and registry access through Zetaris.
The [official getting-started repository](https://github.com/zetaris/getting-started)
documents local and hosted instances. A platform license is separate from the
public setup-script license. Use a machine with Docker virtualization enabled,
or the optional [AWS single-host guide](AWS_DEPLOYMENT.md); no managed EKS or
external account role is required for the demonstrated path.

Keep published UI/API ports on loopback and use an authenticated SSH tunnel for
a remote host. Before first initialization, generate a private password meeting
the bundle's lowercase/uppercase/digit/allowed-special policy; `!` avoids Compose
`$` interpolation. Never reuse published defaults. Preserve a working database
when changing credentials; do not reset volumes to diagnose login.

After bundle `preflight.sh`, image pull, Compose startup and `verify.sh` succeed,
open the tunneled UI and log in. In its SQL Editor run `SELECT 1`. Then copy the
public [CSV](../deploy/zetaris/domain_evidence.csv) into the driver's shared data
volume, as shown in the AWS guide, and execute
[register_demo.sql](../deploy/zetaris/register_demo.sql). Check existing databases
tables first: create only missing objects, and do not drop existing data. The
one row is team-curated IANA provenance, not a blacklist or safety certificate.

```dotenv
SAFEGUARD_DOMAIN_PROVIDER=zetaris
ZETARIS_QUERY_ROUTE=ui_query
ZETARIS_BASE_URL=http://127.0.0.1:3000
ZETARIS_REST_URL=
ZETARIS_API_KEY=
ZETARIS_USERNAME=YOUR_INSTANCE_USER
ZETARIS_PASSWORD=YOUR_PRIVATE_PASSWORD
ZETARIS_ORG_ID=
ZETARIS_EVIDENCE_TABLE=security.domain_evidence
ZETARIS_QUERY_LIMIT=100
ZETARIS_TIMEOUT_SECONDS=60
```

Blank organization uses the actual login response; if supplied it must match
that numeric ID. The account-management dashboard is not the instance API.
The adapter caches the access JWT in memory, re-logs in once after HTTP 401,
reads named records from `/api/proxy/query/sql/start` and closes the query cache.
See [INTEGRATIONS.md](INTEGRATIONS.md) for exact legacy/modern contracts.

Restart SafeGuard and inspect its authenticated status. Investigate example.com:
the actual row should retain source URL and `curated_demo_observation`. An absent
domain must return empty rows, never a fabricated record. Verify `query_closed`
and explicit unavailable/unauthorized status if the tunnel is stopped. The
historical real tests passed these cases; a new deployment still needs its own
acceptance. Revert domain provider to `none` when finished.

## BlackIPS

[BLACKIPS_LOCAL_SETUP.md](BLACKIPS_LOCAL_SETUP.md) covers the fully local snapshot
path and optional remote HTTP contract. It is independent of model and Zetaris
settings. A hit supports an observation, not a proof that a website is malicious;
a miss never certifies safety.
