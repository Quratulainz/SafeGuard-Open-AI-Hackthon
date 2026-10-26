# Competition evidence and delivery boundaries

Evidence checked on **2026-10-26 Singapore time**. The supplied guide, public official pages and
earlier notes have different evidence status. This is not an organizer ruling.

The starter PDF was supplied by the user and remains readable in the original
project root. It is **not redistributed in the source ZIP**; page references
below identify that separately supplied document.

## Available official evidence

| Source | Evidence | Meaning |
| --- | --- | --- |
| [Current official event and rules](https://hackathon.genai.works/event/open-agent-hackathon-2026) | Public rule 5 requires Zetaris and Meterless; Cursor is optional. Rule 6 lists video, slides, GitHub source/README and integration explanation. | This current rule takes precedence over conflicting starter-guide wording. |
| Supplied starter guide (`vibe-coding-starter-guide.pdf`, provided separately), page 2 | “Required in every submission: Zetaris and Meterless integrated, and the project developed in Cursor.” | The guide requires integration, not just interfaces or documentation. |
| Same PDF, page 11 | “Sample mode may load sample input data”; it must not load prewritten final answers, fake interaction or pretend a sponsor service was called. | Credential-free sample inputs are allowed; results must be genuinely computed. |
| Same PDF, page 18 | “Zetaris and Meterless are integrated, not mocked”; “sample mode works with no credentials”. | These requirements appear together; sample mode is not an explicit replacement. |
| Same PDF, page 1 | “Where this guide and the Official Rules on the event page disagree, the Official Rules apply.” | Current event rules take precedence. |
| [Official Academy event page](https://academy.genai.works/courses/open-agent-hackathon-2026/details) | Describes real data via Zetaris, a Meterless Engine, and Nightshift/Nemotron. Allows Cursor or another AI coding tool; gives October 22–27, 2026. | Supports actual technology use; coding-tool wording differs from the PDF. |
| [Official resources](https://hackathon.genai.works/resources) | Public access redirected to sign-in during this review. | Gated materials were not retrieved; the current public event rules were available separately. |
| [Official Meterless hackathon guide](https://github.com/Meterless/Meterless/blob/main/docs/community/hackathon-guide.md) | Describes runnable engines/Nightshift but retains October 15–20 dates. | A conflicting revision; do not adopt its dates or rubric as current. |

**No verified source grants permission to replace required working sponsor
integrations with documentation and reserved interfaces.** A credential-free
default can coexist with real optional integration, genuine tests and run
evidence. Eligibility depends on the authoritative rules and what judges must
be able to run or see.

Earlier team notes stated: Zetaris data layer, at least one tested Meterless
Engine in a working feature, Nightshift as primary AI provider, and Nemotron
through Nightshift for a sponsor award. Those detailed notes were not preserved
as a signed-in official rules snapshot. Verify them rather than treating notes
as current rules. The current public rules resolve Cursor as optional. They do
not explicitly mandate Nightshift as the primary provider or Nemotron for every
entry; award-specific or gated details still require their own verification.

## Present submission position

| Item | Current evidence | Remaining delivery action |
| --- | --- | --- |
| Product | Local rules, history, dashboard, extension and subscriptions | Reproduce a clean checkout and record its revision |
| Zetaris | Actual authenticated SQL, source-labelled table, empty lookup and cache close previously passed | Provide a currently available optional deployment if judging requires it |
| Meterless Engine | Official H-MEM reference, real recall/storage and conformance tests | Enable `SAFEGUARD_MEMORY_MODE=hmem` for sponsor demonstration |
| Nightshift | Actual official desktop runtime with local Llama 3.2 1B/3B | Enable `SAFEGUARD_ANALYSIS_MODE=model`; record live status and actual reported model |
| NVIDIA Nemotron | Not demonstrated | Do not claim NVIDIA use or award eligibility until evidenced |
| Data | Public IANA demo input; private source-tracked IP snapshots | Keep raw feeds private; publish fetch/hash code and provenance |

Default `rules/local/none` mode does not call Nightshift, H-MEM or Zetaris. A
video showing only that mode does not demonstrate sponsor integration. The
local model remains error-prone; show its evidence review and abstention, not
an implied claim that every raw answer was correct.

## Materials to finish

The current event confirms a **1–4 minute video**, slides, a GitHub repository
with README setup/dependencies, and sponsor integration explanation. Declare
pre-existing work. The published deadline is **2026-10-27 23:45 UTC**, which is
**2026-10-28 07:45 in Singapore**; recheck for schedule changes before submitting.
The supplied guide pages 18–20 also call for reproducible setup and three inputs
with real outputs.

Prepare a clean release, follow [judge reproduction](JUDGE_REPRODUCTION.md),
record three fresh results and show sponsor calls separately with true status.
Identify pre-existing work and event changes. Preserve timestamps/revisions for
real acceptance. No organizer has been contacted on the team's behalf.
