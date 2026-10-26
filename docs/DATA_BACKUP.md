# Local data, backup and redistribution

## What is public and what stays private

| Material | Public release policy |
| --- | --- |
| Application code, fetch/hash scripts and synthetic test fixtures | Included; synthetic fixtures are not presented as real reputation evidence |
| Official Meterless H-MEM source | Included with its pinned provenance and Apache-2.0 license |
| `deploy/zetaris/domain_evidence.csv` | One team-authored, attributed IANA demonstration observation, not a threat dataset |
| Downloaded IP lists | Private only; redistribution permission is not cleared |
| History, subscriptions, tokens and `.env` | Private; do not commit or include in a public backup |
| Zetaris bundles/container images, Nightshift binaries/model weights | Obtain separately under their terms; not bundled |

The public IP mirror [njcx/blackip_list](https://github.com/njcx/blackip_list)
warns that constituent lists have their own licenses. The
[AbuseIPDB mirror](https://github.com/borestad/blocklist-abuseipdb) says its author
has permission; this does not grant this project a new redistribution license.
[blocklist.de terms](https://www.blocklist.de/en/terms.html) describe exports and
retention without establishing our right to repackage a mirror. Missing LICENSE
files are not permission. Therefore the public release contains source-fetching
and validation code, not the real feed bytes. No personal SMS or Kaggle corpus
was downloaded for this implementation.

## Create or refresh a private IP snapshot

From the project root, after reviewing the sources' terms:

```powershell
py -3 scripts/sync_blackips_snapshot.py
```

The sync command does not load the project's `.env`. If the application uses a
custom snapshot location, pass that same path with `--destination` or export it
in the command's environment. A custom path saved only in `.env` is not used by
this script automatically.

The script fetches the current `njcx/blackip_list` commit and pins
`abuseipdb_30d.ipset` plus `blocklist_de.ipset`. It verifies source format, dates,
public IPv4 entries and file hashes before publishing an atomic `current.json`
pointer. Failure retains the prior active snapshot. Files live under
`server/local-data/blackips-snapshot/` unless `--destination` is supplied.

The directory contains `current.json`, immutable `snapshots/<commit>-<suffix>/`
with `manifest.json` and both feed files, and `sync-report.json`. The report
records source URLs, commit, dates, counts and hash provenance. Raw source age,
not download/lookup time, determines the 72-hour validity. Copying or restoring
expired data never renews it. Old data returns unavailable with `listed=null`.
Coverage is exact public IPv4 membership; no IPv6, CIDR expansion, country or
Tor classification is implied.

Set `SAFEGUARD_IP_PROVIDER=snapshot` for no remote reputation service attempts.
Set `BLACKIPS_SNAPSHOT_DIR` to a custom directory if needed. `auto` tries a
configured remote service then this local snapshot; its fallback status remains
visible. The source itself still needs periodic Internet refresh.

## Backup and restore

Stop SafeGuard before copying its database. The default private data directory
contains `records.sqlite3` (history/subscriptions), `local-token.txt` (local
connection secret), optional `hmem/`, and `blackips-snapshot/`. A legacy
`pairing-key.txt` may remain after migration. Use a private/encrypted backup
location; none of these files is an open data release.

For a full same-user backup, copy the entire data directory after shutdown.
Restore it to a private location and set `SAFEGUARD_DATA_DIR` to that directory
before startup. Keep `.env`/provider credentials in a separate private backup.
Do not put the same restored credentials on a shared/public machine. The default
local records are not encrypted and are intended for one local user.

For reputation-only backup, copy the entire `blackips-snapshot` directory.
Restore by copying it and setting `BLACKIPS_SNAPSHOT_DIR`, or import it atomically:

```powershell
py -3 scripts/sync_blackips_snapshot.py --from-dir "D:\private-backup\blackips-snapshot" --destination "D:\private-data\blackips-snapshot"
```

`--from-dir` makes no network request and accepts either a complete pointer-based
backup or a flat pinned directory containing the manifest and both files.
Original dates/hashes remain authoritative, including expiry. Confirm status and
source dates after restoring; a successful copy is not a current-data guarantee.

The demonstrated private snapshot had 145,616 unique addresses from source files
dated 2026-10-24. That historical count is not hardcoded as a current requirement.
Positive and negative samples must be checked against the current pinned source;
old sample outcomes can legitimately change.
