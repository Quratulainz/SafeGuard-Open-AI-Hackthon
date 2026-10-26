# Website checks and result meanings

SafeGuard assesses the page it can currently inspect. It does not verify a
company's legal identity, certify a website, guarantee a transaction, or prove
that every page on a domain is safe.

| Result | Meaning for a website |
| --- | --- |
| **Safe** (green) | The current scoped page check completed with usable evidence and found no warning signs in the checks performed |
| **Uncertain** (yellow) | A supported concern needs review, or SafeGuard could not obtain enough usable page evidence to complete the check |
| **Danger** (red) | Specific current behavior, such as asking you to send a password/OTP out of band or pay an upfront fee for a promised benefit, supports a warning |

A familiar name, ordinary branding, a hostname suffix, a valid TLS certificate,
a blacklist miss or a previous successful check cannot alone make a site green.
No blanket list of supposedly safe companies is used. No new government-domain
or corporate-identity registry is required by this release.

## What supports a completed page check

The assessment uses current HTTPS retrieval or explicitly identified usable
browser-visible context when server retrieval cannot complete. It considers
available URL, redirect, content and form evidence. The result should explain
which evidence was actually available and why the check completed or remained
incomplete. Browser-visible text is not relabelled as independent server-side
TLS or organization verification. Evidence from the original URL must not be
silently attributed to a different final destination.

The server verifies TLS using Python's trusted certificate configuration, follows only public
HTTP(S) destinations, retains a redacted redirect path, and checks the final
host's IP evidence. HTTPS alone cannot produce green. The HTML fetch is bounded
to 1 MiB and readable text to 16,000 characters; any clipping is disclosed.
Form inspection is bounded to 20 destinations, including submit-button
overrides. A form inspection overflow prevents a completed green result.

An explicit current-page scan can supply visible text when a site serves a
challenge or requires browser rendering. This path still requires verified
HTTPS to the matching destination and complete bounded form metadata. It
cannot rescue a blocked private-address redirect or a failed TLS check.
Browser observations are labelled as browser observations. No input values,
editable text, cookies or storage are collected. Form query strings, fragments
and embedded credentials are removed; malformed or credential-bearing form
destinations remain flagged. Arbitrary JavaScript submission logic is outside
the form-structure inspection.

Ordinary login navigation and a normal same-origin form are not automatically
scams. That does not prove a form's business purpose: concrete requests to send
credentials to another person, suspicious destinations, or payment inducements
remain relevant. A benign sentence does not cancel a later risky instruction.

A failed fetch, anti-bot challenge, empty page or unusable visible context should
say **Could not complete page check** and remain yellow. This describes an
inspection limit, not a finding that the site is fake. A user can retry or use
the explicitly available page-context path; the app must not invent content.

## Optional data and limits

A missing optional reputation service does not automatically make a usable page
yellow. It is a disclosed coverage limit. Expired snapshots cannot establish a
current adverse listing. A real current listing retains at least caution and
prevents green, while a miss is only absence from those particular dated lists.
Neither source age nor expiry is reset by copying or checking a snapshot.

Zetaris's IANA demonstration row proves that a real sourced SQL lookup can work;
it is not a positive website-safety certificate. Historical H-MEM or SQLite
records remain historical. The model's `unknown` output is not positive safety
evidence, and a model cannot override an adverse current finding by calling a
site safe.

Completed positive page checks survive an optional model's unsupported
uncertainty. Concrete current credential-disclosure or payment requests also
remain visible when the model abstains. Neither path uses previous checks as
fresh evidence.

HTTPS protects the connection to the verified hostname; it does not establish
that a business is trustworthy. This distinction is also explained by the
[Chromium project](https://blog.chromium.org/2023/05/an-update-on-lock-icon.html).
Public HTML inspection does not execute every script, authenticate a user,
complete checkout, inspect all downloads or scan an entire website. Read the
result's current scope and limitations before acting on a sensitive request.
