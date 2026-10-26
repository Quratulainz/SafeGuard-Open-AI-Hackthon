# Clean-machine and judge reproduction

## Credential-free default

1. Obtain the source and install Python 3.10 or newer.
2. Copy `.env.example` to `.env` only for a fresh setup. Keep analysis `rules`,
   memory `local`, domain provider `none`.
3. Run `python3 start.py` (`py -3 start.py` or `Start-Windows.cmd` on Windows).
4. Open `http://127.0.0.1:8765`. No account, API key or pairing code is required.
5. Load `extension/` as an unpacked Chrome/Edge extension. Keep the backend
   running; reload the extension when migrating from an older version.

No Docker, Node, cloud or model is needed. Message checks, subscriptions and
SQLite history run offline. A public URL needs DNS/HTTP Internet access; fetch
failures remain visible. Optional services must show disabled/unavailable,
not fabricated success.

For a different computer, see [new-device setup](PORTABILITY.md). Python is a
prerequisite. The public archive contains no old credentials or personal data.

## Three non-sensitive inputs

| Input | Inspect the freshly computed result |
| --- | --- |
| `Never share your OTP.` | Rules may give green `safe` for this protective text without inducement |
| `Send me your OTP to verify your account now.` | Concrete credential solicitation supports red `danger` |
| `https://example.com` | Completed current-page checks without warnings can be green; insufficient retrieval/context stays yellow with an incomplete-check explanation |

These are inputs, not stored final answers. `decision.verdict` is `safe`,
`uncertain` or `danger` (Safe / Uncertain / Danger). Website green means no warning
signs were found in the current scoped page check; it is not official-company,
sender, payment or future-behavior verification. A normal login form is not itself
a scam. Unsupported retrieval, a challenge page or insufficient visible context
stays uncertain with **Could not complete page check**, not a claim of fakery.
Optional-feed failure alone is not a yellow verdict; stale data supplies no
current listing evidence, while a real current adverse listing prevents green.
A list miss or model `unknown` is not positive safety evidence. The optional
model schema remains `elevated/caution/unknown`; the webpage check has its own
current evidence and reasons. See [website-check scope](WEBSITE_CHECKS.md).

For a separate message with insufficient evidence, use `The library opens at
nine.` and inspect the yellow result. Do not reuse historical saved results as
current output.

Add a fictional subscription with a cancellation date within seven days, edit
it and restart the browser to inspect its reminder. Cancellation and renewal are checked independently; cancellation reminders
are shown first and the long-term marker does not suppress cancellation. No payment or real subscription cancellation occurs.

## Optional IP evidence without a server

Review [data terms](DATA_BACKUP.md), then run:

```powershell
py -3 scripts/sync_blackips_snapshot.py
```

Set `SAFEGUARD_IP_PROVIDER=snapshot` and restart. The source dates determine its
72-hour validity. Inspect offline/source/date metadata; list misses do not prove
safety and stale/missing data remain unavailable. Clean releases intentionally
exclude raw IP feeds because redistribution permission is not cleared.

## Sponsor demonstration and verification

Follow [Optional services](OPTIONAL_SERVICES.md). Enable each integration only
after real setup. Record actual status, a new investigation, source-linked rows,
memory IDs and the reported model identity. A route such as `meterless/local`
is not an actual model name. Temporary services may already have expired.

```powershell
py -3 -m unittest discover -s tests -v
node --test tests/test_extension_runtime.js tests/test_extension_controls.js tests/test_assistant_view.js tests/test_risk_rendering.js tests/test_date_picker.js tests/test_page_context.js
node --experimental-transform-types --disable-warning=ExperimentalWarning server/vendor/meterless_hmem/conformance/runner.ts
```

The full suite includes H-MEM tests and needs Node.js 24; default startup does
not. HTTP mock tests check contracts and errors, the conformance runner checks
the real reference, and neither proves live sponsor connectivity. Use the
service guides' live checks for that. Keep historical counts separate from
current runs. Exclude `.env`, private data/backups/keys, bundles, model weights
and feeds from publication. Check [competition evidence](HACKATHON_REQUIREMENTS.md)
before claiming eligibility.
