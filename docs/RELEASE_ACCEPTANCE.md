# SafeGuard AI v0.3.2 portable distribution acceptance

Checked on 2026-10-25. Application text, generated explanations, calendars,
notifications and authored delivery documentation are English. User input and
quoted source evidence retain their original language.

## Automated checks

| Suite | Passed | Coverage |
| --- | ---: | --- |
| Python | 182 | HTTP/auth, subscriptions, rules, evidence isolation, optional integrations, snapshots, collection, website policy and portable startup |
| JavaScript | 58 | Assistant, extension connection and permissions, reminders, rendering, English dates, bounded page context and sender binding |
| Deployment templates | 7 | Cost and launch guards, template configuration |
| Total | 247 | Deterministic checks; not a model accuracy benchmark |

The Python suite was rerun after adding the portable launcher. The unchanged
JavaScript and deployment results are from the same-day v0.3.2 release.
The website tests cover normal login, out-of-band OTP requests, current versus
stale listings, unavailable pages, challenges, redirects, TLS failure, form
destinations/ports/overrides, context mismatch, bounded collection and model
abstention. Form-value access is rejected in the JavaScript privacy fixtures.

## Actual local HTTP and browser checks

The following public URLs were requested through the running local application's
HTTP interface at approximately 15:39 UTC. No model or new AWS resource was used.

| URL | Result in this run | Observation |
| --- | --- | --- |
| https://example.com/ | Safe | Readable HTTPS page; no observed warning |
| https://www.google.com/ | Safe | Readable HTTPS page; no observed warning |
| https://www.deepl.com/en/translator | Safe | Readable HTTPS page; no observed warning |
| https://www.microsoft.com/ | Safe | Public redirect to `/en-my`; final page checked |
| https://github.com/ | Safe | Readable HTTPS page; no observed warning |
| https://www.gov.sg/ | Safe | Readable HTTPS page; no observed warning |
| https://my.jobstreet.com/ | Uncertain / incomplete | HTTP 403; transport verified, readable content unavailable |

These are point-in-time observations, not hardcoded answers, official-identity
verification or permanent website ratings. The machine-readable live report is
delivered alongside the source ZIP, rather than used as application evidence.

The actual dashboard displayed Google's green result and JobStreet's yellow
incomplete-check explanation. Its English calendar was exercised, a date was
selected, and empty subscription submission showed `Enter a service name.`
without creating a record. Existing history and subscriptions were preserved.

The user previously confirmed automatic assistant appearance, automatic local
connection and English text in installed Edge v0.3.1. After the v0.3.2 reload
request, the user replied `OK`. The local backend recorded a new Google scan at
15:40:30 UTC with `browser_page_observation`, one form-structure observation and
a `safe` verdict. This confirms the updated browser-context path reached the
running backend. The extension identity and granted permissions did not change.
The final extension popup was not independently screenshotted; the separate
automated tests are not substituted for that visual check.

## New-device checks

The portable distribution adds `start.py`, `Start-Windows.cmd`,
`Start-macOS.command`, `start-linux.sh`, `START_HERE.txt` and
[portability instructions](PORTABILITY.md). The PowerShell helper no longer
searches a Codex cache for Node. Python is installed separately.

Four new tests launch fresh copies with spaces and non-ASCII folder names,
outside the project working directory, using isolated Python without site
packages, old config or a Node/Codex path. They check prerequisite reporting,
port-collision reporting, real local HTTP startup, persistence across restart,
and database-only migration that generates a new local token. The actual Windows
and PowerShell launcher prerequisite checks also passed. Runtime: Windows,
Python 3.13.7. No physical second device or native macOS/Linux run is claimed.

The actual extracted delivery ZIP repeats the prerequisite check and all four
portable tests before the nine HTTP smoke checks. The separate `.smoke.json`
records these outcomes. No test copies the original private database or token.

## Source archive and reproduction

The delivery process builds a source allowlist, rejects secrets/private data,
checks documentation links and file hashes, extracts the resulting ZIP, then
runs a fresh local HTTP smoke check with outbound networking and child-process
creation forbidden. The separate `.smoke.json` records its actual outcome.
Only a passing candidate is copied to the delivery directory.

Start with [Getting started](GETTING_STARTED.md), then
[Judge reproduction](JUDGE_REPRODUCTION.md). Optional real integrations and AWS
setup are described in the linked deployment guides. Their historical acceptance
does not mean they are currently running, nor does a reserved interface alone
prove competition eligibility. The default project does not require them.

The archive excludes private `.env`, connection tokens, history, subscriptions,
cloud keys, licensed bundles, model weights and raw threat feeds. Public source
data can be fetched and privately backed up using [Data backup](DATA_BACKUP.md).
No paid model or new cloud resource was created for this release.
