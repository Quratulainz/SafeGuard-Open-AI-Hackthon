# Getting started and optional deployment

The default application requires **Python 3.10 or newer**. It does not require
AWS, Docker, Node.js or a model. Message checks use local rules; history and
subscriptions stay on this computer. Website checks still need Internet access.
Missing, expired or absent evidence is visible and never treated as proof of safety.

For a new device, extract the whole package and follow
[portability and private migration](PORTABILITY.md). Install a currently supported
Python release; 3.10 is the source compatibility floor. The package does not
bundle Python, accounts or personal data.

## Start on your computer

Open PowerShell in the project directory:

```powershell
if (!(Test-Path .env)) { Copy-Item .env.example .env }
py -3 start.py
```

Open [the local dashboard](http://127.0.0.1:8765). Keep the server running; press
Ctrl+C to stop. Windows also has `Start-Windows.cmd` for double-click startup.
On macOS/Linux use `python3 start.py`. Preserve an existing
`.env` and edit only the required settings. Process environment variables take
precedence over `.env`; restart the server after configuration changes.

In Chrome/Edge, open `chrome://extensions` or `edge://extensions`, enable
Developer mode, select **Load unpacked**, and choose the project's `extension/`
directory. The extension connects automatically; no pairing code is required.
Reload it after upgrading an older version. Its fixed identity uses a public
manifest key; the team does not need an extension private key.

### Show the assistant automatically

1. Open a regular website, then open the SafeGuard extension popup.
2. Expand **Assistant and connection** and choose **Allow this site only**.
   Choose **Allow all websites** only if you intentionally want broader access.
3. Confirm the browser's website-access request. The assistant then appears
   automatically on approved websites, with no pairing code to copy.

Turning **Show assistant automatically** off removes it from open pages.
Automatic display does not scan pages; checking page content still requires
you to choose **Scan**. Browser-internal and other restricted pages cannot host
the assistant.

Use **Scan this page** in the extension popup, or the current-page scan in the
floating assistant, when a public website cannot be fetched by the server.
This sends up to 16,000 characters of visible text and bounded form structure
to the local app. It does not read form values, editable text, cookies or browser
storage. Form destinations have query strings and fragments removed. Browser
context must match the scanned tab, and the server still checks HTTPS and
redirects. Pasting a URL alone does not collect the browser's page content.

### Try a check and a subscription

Try these non-sensitive inputs:

1. `Never share your OTP.` — can be green only as an explicit protective message
   without a request to disclose credentials or another detected inducement.
2. `Send me your OTP to verify your account now.` — the specific credential
   request supports a red danger warning.
3. `https://example.com` — a usable current page with completed checks and no
   observed warnings can be green. If fetching/context is insufficient, it stays
   yellow with the explanation **Could not complete page check**.

Green **Safe** is a scoped assessment of the examined message or current page,
not authentication of a sender, a company or future behavior. A website result
uses successful HTTPS retrieval or explicitly identified usable browser-visible
context, together with URL, redirect and form checks. A normal login or same-origin
form is not by itself a scam. Actual out-of-band credential requests and upfront
fees for a promised benefit remain risk signals. Yellow **Uncertain** includes
incomplete checks and supported concerns; Red **Danger** requires concrete risk
observations. A missing optional feed does not automatically make a usable page
yellow, while stale feeds cannot provide current listing evidence. A real current
listing keeps at least a caution result. See [website checks](WEBSITE_CHECKS.md).
Blacklist misses, missing services, model `unknown` and history do not by
themselves establish safety. Displayed interface text and generated explanations are
English; the detector may still examine multilingual input.

Subscriptions can be added or edited, with a long-term preference and optional
cancellation date. Browser startup and hourly checks cover both cancellation and
renewal dates from seven days before the target, with overdue follow-up and daily
deduplication. Cancellation reminders appear first without suppressing renewal;
the long-term marker does not suppress cancellation. Clicking a reminder opens
the subscription page. The application does not charge, cancel or message anyone.
The date controls and form-validation messages use English independently of
the browser or operating system language.

## Local IP data and private backups

The public release excludes raw IP lists because redistribution rights have not
been established. After reviewing source terms, obtain a private checked snapshot:

```powershell
py -3 scripts/sync_blackips_snapshot.py
```

The default directory is the Git-ignored `server/local-data/blackips-snapshot`.
Data expires 72 hours after its original source time. Copying, querying or
importing cannot renew it. You can skip the download and continue using message
rules and subscriptions; unavailable reputation data remains clearly marked.

Stop the app before backing up its database. A full private backup copies
`server/local-data`, which includes history, subscriptions and a local connection
secret; do not publish it. For an IP-only backup, copy the entire
`blackips-snapshot` directory. Restore by copying it or run:

```powershell
py -3 scripts/sync_blackips_snapshot.py --from-dir "D:\private-backup\blackips-snapshot" --destination "D:\private-data\blackips-snapshot"
```

Set `BLACKIPS_SNAPSHOT_DIR` to the restored snapshot directory. To restore all
local application data elsewhere, set `SAFEGUARD_DATA_DIR` to the private restored
directory. See [data and backups](DATA_BACKUP.md) for provenance and licensing.

## Optional modes

| Setting | Default | Other supported choices |
| --- | --- | --- |
| `SAFEGUARD_ANALYSIS_MODE` | `rules` | `model` calls Nightshift; failure visibly falls back to rules |
| `SAFEGUARD_MEMORY_MODE` | `local` | `hmem` uses the official reference and requires Node.js 24 |
| `SAFEGUARD_DOMAIN_PROVIDER` | `none` | `zetaris` queries the configured evidence database |
| `SAFEGUARD_IP_PROVIDER` | `auto` | `snapshot` uses local data, `remote` uses the service, `disabled` skips reputation |

`auto` tries a configured remote IP service, then falls back to the local
snapshot when unavailable. Daily use can select `rules / local / none / snapshot`
to avoid optional service dependencies. Fetching a public URL still needs Internet.

For the demonstrated local model, install official Nightshift desktop Runtime
and download Llama 3.2 3B Instruct Q4_K_M. Use one lane, context 8,192 and one slot;
bind `safeguard-ai` to local and set privacy floor local-only. Disable runtime
`hmemKnowledge` and `moaSynthesis` to prevent old-answer injection or rewriting
structured JSON. Store its actual proxy token only in private `.env`.
`meterless/local` is a route; inspect the receipt for the actual loaded model.

Configure any stronger or remote model inside Nightshift, with provider spending
limits and deliberate privacy/routing choices, before changing application
settings. Remote execution can disclose input and incur costs. This project has
not run a remote model or NVIDIA Nemotron and does not claim their quality or
award eligibility. Follow [optional services](OPTIONAL_SERVICES.md) and the
[version-specific runtime procedure](INTEGRATIONS.md#runtime-isolation-for-reproduction).

## Optional AWS and Zetaris deployment

A temporary Linux host is an alternative when local Docker virtualization is
unavailable, not a default requirement. Real Zetaris login, SELECT 1, a sourced
IANA row and empty lookups passed previously. The public templates derive from
that deployment but have local safety tests only; they have not launched a new
public-template deployment.

1. Read [the AWS guide](AWS_DEPLOYMENT.md). Review your account plan, permissions,
   existing costs and current prices. The checked Sydney estimate is **USD 6.18
   for 48 hours**, before taxes, transfers and unrelated resources; two attempts
   plus reserve total about USD 15.36. This is not an account-wide spending cap.
2. Generate an SSH key on your computer and keep its private part there. Upload
   only the public key, launch script and user-data script to CloudShell. Restrict
   SSH to your current public IPv4/32; do not expose application service ports.
3. Start with `launch_cloudshell.py --dry-run --with-scheduler` and your own key/IP.
   Creation requires explicit apply, reviewed account/prices/prior cost, and an
   independent expiry schedule. Do not delete the attempt ledger to bypass its
   limit or upgrade the account automatically.
4. Immediately verify AWS's 48-hour termination schedule, the OS timer and root
   disk deletion. Budget alerts do not stop billing. If expiry protection fails,
   terminate and inspect that attempt instead of repeatedly creating machines.
5. Obtain your own authorized Zetaris bundle and registry credentials. Transfer
   them privately with SCP. The public fresh-bundle helper defaults to a plan;
   it generates private passwords and loopback UI configuration only when
   explicitly applied to a new installation. It refuses existing containers or
   volumes and is not a database password-reset tool.
6. Complete the bundle's preflight, pull, Compose startup and verify. Use SSH
   tunnels for UI3000/API8888 and log in privately. Do not expose database, Redis
   or administration ports to the Internet.
7. Import the [IANA sample CSV](../deploy/zetaris/domain_evidence.csv) and run
   [the registration SQL](../deploy/zetaris/register_demo.sql), creating only
   missing objects. This is a sourced demonstration fact, not a safety certificate.
8. Configure `ZETARIS_*` using [the optional-service guide](OPTIONAL_SERVICES.md),
   restart SafeGuard and check authenticated status, the sample row, empty
   results and query closure. Back up wanted private data before cleanup, then
   verify the recorded instance and disks are removed and inspect billing.

## Documentation and competition evidence

- [Judge reproduction](JUDGE_REPRODUCTION.md): clean setup, examples and verification.
- [Competition evidence](HACKATHON_REQUIREMENTS.md): supplied PDF page references,
  official source differences and unresolved current-rule access.
- [Data and backups](DATA_BACKUP.md): private raw lists, public scripts and provenance.
- [Optional services](OPTIONAL_SERVICES.md): model, database and H-MEM configuration.
- [BlackIPS](BLACKIPS_LOCAL_SETUP.md): local snapshots and optional remote contracts.
- [AWS deployment](AWS_DEPLOYMENT.md): costs, permissions, expiry and cleanup.
- [Website checks](WEBSITE_CHECKS.md): current-page scope, green evidence and incomplete checks.
- [Changelog](CHANGELOG.md): v0.3.2 and earlier releases.

No verified source permits documentation and reserved interfaces to replace
required actual sponsor integration. The supplied guide requires real
Zetaris/Meterless integration as well as a credential-free sample mode. The
current detailed event resources require sign-in and still need confirmation.
The local default helps reproduction but alone does not demonstrate eligibility.
