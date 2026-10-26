# SafeGuard AI


SafeGuard combines **ProofShield** (message and public-website checks) with
**SubGuard** (subscription records and reminders), a local dashboard, and a
Chrome/Edge extension with a floating assistant.

The default version runs with **Python 3.10+ and its standard library**. It uses
local evidence rules and SQLite history; it needs no AWS account, model, Docker,
Node.js or API key. Website fetching still needs Internet access. An optional
dated IP snapshot supports local reputation checks; missing or expired data is
shown as unavailable and does not prevent message checks or subscription use.

## Start locally

From the project directory:

```powershell
if (!(Test-Path .env)) { Copy-Item .env.example .env }
py -3 start.py
```

Windows also provides `Start-Windows.cmd` for double-click startup.
On macOS/Linux use `python3 start.py`. Open
[the dashboard](http://127.0.0.1:8765). The application listens on loopback only.
The shipped configuration selects rules, local history, optional automatic IP
data selection, and no Zetaris connection. The dashboard does not require a
copied pairing code.

To use the extension, open `chrome://extensions` or `edge://extensions`, enable
Developer mode, choose **Load unpacked**, and select `extension/`. Keep the
Python server running. If upgrading from the earlier manual-pairing version,
reload the extension. Its public identity is fixed by the manifest key and
`server/extension_identity.json`. Only that exact extension origin can request
its connection token. Other web pages cannot bootstrap a connection.

Try these non-sensitive inputs:

1. `Never share your OTP.`
2. `Send me your OTP to verify your account now.`
3. `https://example.com`

Each result is calculated from current evidence. Green **Safe** means no
warning signs were found within the completed check: either a narrowly defined
protective message or a usable current webpage with the relevant URL, transport,
redirect and form checks. It does not authenticate a company or guarantee a
transaction. Yellow **Uncertain** means a concern needs review or the page check
could not be completed; a failed fetch is not an accusation that a site is fake.
Red **Danger** requires specific current risky behavior. Missing optional feeds,
a list miss or model `unknown` alone establish neither safety nor danger.
See [website-check scope and result meanings](docs/WEBSITE_CHECKS.md).

SubGuard stores user-entered subscriptions. Records can be edited and include
an optional cancellation date (`cancel_on`) and long-term marker (`long_term`).
Browser startup checks both cancellation and renewal reminders within seven
days; cancellation reminders are shown first, without suppressing renewal.
The long-term marker does not suppress a cancellation reminder. SafeGuard does not cancel subscriptions or make payments.

## Optional services

Set these values in the private `.env`, then restart the server:

| Setting | Default | Optional behavior |
| --- | --- | --- |
| `SAFEGUARD_ANALYSIS_MODE` | `rules` | `model` uses Nightshift and falls back visibly to rules on failure |
| `SAFEGUARD_MEMORY_MODE` | `local` | `hmem` calls the official Meterless H-MEM reference; requires Node.js 24 |
| `SAFEGUARD_DOMAIN_PROVIDER` | `none` | `zetaris` queries the configured evidence table |
| `SAFEGUARD_IP_PROVIDER` | `auto` | `snapshot`, `remote`, or `disabled`; auto tries a configured service, then a local snapshot |

To obtain a private local IP snapshot, review the source terms and run:

```powershell
py -3 scripts/sync_blackips_snapshot.py
```

This downloads two source files with provenance and hashes into the ignored
data directory. It does not grant permission to redistribute them. A snapshot
expires 72 hours after its original source time; syncing does not renew that
time. See [backup and data terms](docs/DATA_BACKUP.md).

Detailed guides:

- [Clean-machine and judge reproduction](docs/JUDGE_REPRODUCTION.md)
- [Optional Nightshift, remote model, Zetaris and H-MEM setup](docs/OPTIONAL_SERVICES.md)
- [HTTP integration contracts and real checks](docs/INTEGRATIONS.md)
- [IP snapshots and optional BlackIPS service](docs/BLACKIPS_LOCAL_SETUP.md)
- [Optional AWS deployment, cost review and cleanup](docs/AWS_DEPLOYMENT.md)
- [Competition evidence and unresolved eligibility](docs/HACKATHON_REQUIREMENTS.md)

## Implemented and demonstrated

| Capability | Evidence and boundary |
| --- | --- |
| Local rules, dashboard, extension, subscriptions and SQLite | Default path; rules have limited language/context coverage |
| Meterless H-MEM | Real pinned Apache-2.0 reference, storage/recall, and 13 upstream conformance checks; optional |
| Nightshift local models | Real Llama 3.2 1B and 3B calls through official desktop runtime; structured output/reference validation passed |
| Evidence review | Withholds unsupported elevated model ratings; the small model still makes semantic mistakes |
| Zetaris | Real login, SELECT 1, named rows, empty lookup and query-cache close verified on the official bundle |
| Domain demo data | One attributed IANA record in [the public CSV](deploy/zetaris/domain_evidence.csv); not a fraud database or safety certificate |
| BlackIPS | Real Linux/Redis integration and dated two-feed lookups verified; daily use now supports private local snapshots |
| Remote model / NVIDIA Nemotron | Configurable through Nightshift; not demonstrated or claimed for an award |

The earlier connected acceptance on 2026-10-25 used temporary AWS services,
local Nightshift 3B, project H-MEM and the installed Edge extension. The user
confirmed an example.com scan and floating assistant. Its seven-case regression
matched expected **reviewed system** outcomes, including an English protective
reminder whose raw model rating was wrong and was withheld by evidence review.
This is not a model accuracy benchmark. Temporary services may expire;
historical checks do not mean they are online now.

The v0.3.2 portable distribution passed **182 Python tests, 58 extension/display
tests, and 7 deployment-template tests** (247 total) on 2026-10-25. Four of the
Python tests exercise relocated startup and private database migration; the
unchanged extension and deployment checks are retained from the same-day release.
A separate live check
returned green for Google, DeepL, Microsoft, GitHub, gov.sg and example.com;
JobStreet returned HTTP 403 and an explicitly incomplete check. These are
point-in-time examples, not an accuracy benchmark or permanent safety ratings.
See [release acceptance](docs/RELEASE_ACCEPTANCE.md). Run:

```powershell
py -3 -m unittest discover -s tests -v
node --test tests/test_extension_runtime.js tests/test_extension_controls.js tests/test_assistant_view.js tests/test_risk_rendering.js tests/test_date_picker.js tests/test_page_context.js
py -3 -m unittest discover -s deploy -p test_deployment.py -v
```

Node.js 24 is needed for the full H-MEM tests, not default startup. Contract/mock
tests are separate from real service acceptance. Follow each service guide's
verification before describing a connection as working.

## Data and submission boundaries

The source ZIP does not include the separately supplied competition PDF. This
project currently has no root license grant; the team has not selected its own
open-source license. Included third-party components retain their own licenses.
Sharing this source is not a license for the excluded services or data.

History, subscriptions and tokens live under `server/local-data/` (or
`SAFEGUARD_DATA_DIR`). Keep `.env`, private data, raw threat feeds, model weights,
licensed platform bundles and cloud keys out of public releases. Source
attribution does not itself grant redistribution rights.

The credential-free default does **not** prove that documentation and reserved
interfaces can replace competition-required working integrations. The supplied
guide requires real Zetaris/Meterless use while permitting sample inputs without
credentials; the latest signed-in event rules still need confirmation. Do not
claim NVIDIA use, a complete threat database, or guaranteed fraud detection.

If the extension cannot connect, confirm port 8765 is running, reload this
version of the extension, and inspect dashboard status. If a snapshot is stale,
sync again or continue with visibly reduced evidence. Optional service errors
must remain visible rather than being reported as a successful check.
