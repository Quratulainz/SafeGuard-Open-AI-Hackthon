# Local IP snapshots and optional BlackIPS service

## Default reproducible path

The application can read private, hash-checked files directly with Python; no
Redis, Go service, AWS or model is required. Follow
[DATA_BACKUP.md](DATA_BACKUP.md) to download or restore a pinned snapshot and set:

```dotenv
SAFEGUARD_IP_PROVIDER=snapshot
BLACKIPS_SNAPSHOT_DIR=
```

A blank path uses the data directory's `blackips-snapshot/`. The loader checks
manifest/source/hash/timestamp consistency and exact public IPv4 entries.
Seventy-two hours after the original source time it returns unavailable with
`listed=null`; refresh/copy/lookup time does not extend freshness. Real feed bytes
stay private because redistribution permission has not been cleared.

`auto` tries a configured remote provider and then the local snapshot on
unavailability, displaying offline/fallback metadata. `remote` uses only HTTP;
`disabled` skips reputation. Missing data remains visible in every mode. A
ready snapshot's miss means only absence from those dated lists, not safety.

## Optional external HTTP service

Upstream: [njcx/BlackIPS](https://github.com/njcx/BlackIPS). Obtain source and feeds
under their terms in a separate directory. The project does not bundle the
upstream binary or the private evaluated fork: source and aggregated-feed
redistribution permissions have not been established for that package. Therefore
this is a service contract/hardening guide, not a claim that the public release
contains a turnkey BlackIPS server. The fully local snapshot path above is the
reproducible default.

The demonstrated architecture was `blackapi -> Redis -> dated IPv4 feeds`.
SafeGuard only requests `GET /check?ip=<public-ip>`; it never needs Redis secrets.
Use a loopback service or authenticated SSH tunnel:

```dotenv
SAFEGUARD_IP_PROVIDER=remote
BLACKIPS_BASE_URL=http://127.0.0.1:9091
```

The basic upstream response is an integer `code` (1 listed, 0 not listed), the
same `ip`, and a `message` containing feed/source identity, not an attack type.
A hardened deployment should also return `data_snapshot` with repository,
commit, feed source URLs/dates, `unique_ips`, `loaded_at` and UTC `refresh_by`.
SafeGuard preserves provenance and rejects stale/incomplete supplied metadata.

The original upstream API can hide Redis errors. Do not interpret its bare zero
as proof of a usable dataset. A service claiming the demonstrated behavior must:

- Bind API and Redis to loopback and restrict Redis to its needed commands/keys.
- Reject invalid/non-public addresses and report unsupported IPv6.
- Return HTTP 503 plus an explicit error for empty, incomplete, stale or failed
  data (`dataset_unavailable`, `dataset_invalid`, `dataset_stale`,
  `dataset_incomplete`, `dataset_changed` or `redis_unavailable`).
- Validate feeds, preserve source dates/hashes and atomically switch snapshots.
- Refresh regularly; failed refresh must not extend the old expiry.
- Keep feeds, passwords and internal Redis keys out of public output.

Verify a ready positive/negative lookup, empty data, expiry, actual Redis outage
and recovery/restart. A status page alone is insufficient. With `remote` mode
set, use `py -3 scripts/test_blackips_live.py 1.1.1.1` and inspect the response;
the sample IP's current outcome is not guaranteed. Dashboard status needs no
manual pairing key. A remote test must not be mistaken for snapshot fallback.

## Historical live evidence

On 2026-10-25 the private hardened Linux deployment imported 145,616 unique
addresses from `abuseipdb_30d` and `blocklist_de`, tested actual Redis outage,
persistence, unsupported/private inputs and positive/negative lookups. It bound
API to host loopback 9091 and Redis to loopback 6381, with daily refresh and SSH
tunnels. This was a modified deployment, not an unchanged upstream release.
It ran on a temporary instance; these historical facts do not assert present
availability. No country/Tor/CIDR/IPv6 classification or complete threat coverage
is claimed. The optional service is not necessary for the public offline path.
