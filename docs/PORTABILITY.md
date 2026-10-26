# Use SafeGuard on another computer

The delivery contains portable source code and operating-system launchers.
It contains no personal machine paths or requirement to install Codex. Python
is a prerequisite, not a bundled runtime. Desktop Chrome or Edge is needed for
the extension; the dashboard can run without it. This package does not target
mobile browsers, Safari extensions or Firefox extensions.

## Fresh device

1. Extract the entire ZIP into a writable folder, such as a folder under your
   Documents directory. Keep `start.py`, `server/` and `extension/` together.
   Do not launch from inside a ZIP viewer or a read-only system directory.
2. Install a currently supported [Python release](https://www.python.org/downloads/).
   The source requires Python 3.10 or newer. No `pip install` is needed for the
   default application. Python 3.10 is a compatibility floor, not the recommended
   release for a new installation.
3. Start using the appropriate entry point below. A fresh copy works without
   `.env`; configuration and private data from the old device are unnecessary.
4. Keep the launcher window open. The dashboard opens at
   [127.0.0.1:8765](http://127.0.0.1:8765). Closing the service stops checks and
   reminders until it is started again.
5. In Chrome/Edge, load `extension/` using Developer mode and **Load unpacked**.
   Open the extension on a regular website and choose **Allow this site only**
   under **Assistant and connection**. Website permissions must be granted on
   each device. Local connection is automatic; no pairing code is copied.

| System | Start | Check prerequisites without starting |
| --- | --- | --- |
| Windows | Double-click `Start-Windows.cmd` | `py -3 start.py --check` |
| macOS | From the extracted folder: `sh Start-macOS.command` | `python3 start.py --check` |
| Linux | From the extracted folder: `sh start-linux.sh` | `python3 start.py --check` |

The launchers resolve the project folder from their own location, so moving or
renaming the extracted folder does not require editing code. If launching
`start.py` directly, use `py -3 start.py` on Windows or `python3 start.py` on
macOS/Linux. `--no-browser` suppresses automatic browser opening.

On macOS, complete the **Install Certificates.command** step from the
[official Python installation guide](https://docs.python.org/3/using/mac.html).
On Linux, Python's SQLite and SSL modules and trusted CA certificates must be
installed; use your distribution's supported Python packages. A prerequisite
check confirms local imports and files, not Internet reachability or cloud access.

The bundled extension connects to port **8765** on the same computer. Do not
change that port for normal use, and run only one copy at a time. `127.0.0.1`
means this device; it never points back to the original developer's computer.
No router port forwarding or public cloud deployment is required.

## What works without old accounts or data

- Message checks, history and subscriptions use Python and a local SQLite file.
- The assistant and reminders require the extension plus the running local app.
- Public-website checks need DNS/HTTPS Internet access. Site access challenges
  can still result in an explicitly incomplete check.
- BLACKIPS is optional. Fetch a fresh private snapshot using
  `python3 scripts/sync_blackips_snapshot.py` (`py -3` on Windows), following
  [data terms and backup instructions](DATA_BACKUP.md). A missing or expired
  snapshot is reported as unavailable; it does not stop the application.
- Optional models, Zetaris and AWS require new-device configuration and any
  relevant accounts or licenses. Follow [Optional services](OPTIONAL_SERVICES.md).
  Temporary cloud servers and SSH tunnels are not required by the default app.

No personal history, subscriptions, `.env`, local tokens, private keys, threat
feeds or licensed platform bundles are included in the public delivery.

## Move your existing records privately

For the default data location:

1. Stop SafeGuard on both computers so the SQLite database is not being written.
2. On the old computer, copy `server/local-data/records.sqlite3` to a private
   transfer location. This file contains your history and subscriptions; do not
   include it in a public submission.
3. On the new computer, use a fresh extracted project. Create
   `server/local-data/` if needed, then place `records.sqlite3` there. If the new
   computer already has records, back up that database first. This procedure
   replaces it; it does not merge two histories.
4. Optionally copy the whole `blackips-snapshot` directory into the new data
   directory. Keep all metadata; copying does not extend source expiry. If data
   is expired, fetch a fresh snapshot instead.
5. Do **not** copy `local-token.txt`, `pairing-key.txt`, `.env`, SSH keys or other
   runtime credentials. Start the new app: it generates its own local token and
   the extension connects automatically. Reapprove desired website permissions.
6. Check History and SubGuard before discarding the private backup. Notification
   settings and daily notification deduplication belong to each browser profile;
   due reminders may appear again on a new device.

If you previously configured `SAFEGUARD_DATA_DIR`, use that directory instead
of the default above. Recreate optional configuration from `.env.example` only
when needed. Old absolute paths, tunnels and service addresses must be reviewed
for the new machine. Keep the restored data private.

## Verification and limits

The portability tests create relocated copies in paths containing spaces and
non-ASCII characters and launch them from an unrelated working directory. They
use isolated Python with site packages disabled, a minimal environment, no old
`.env`, no data files and no Node/Codex path. Tests check fresh automatic
connection, default message checks, persistence across restart, and database-only
migration that keeps records while generating a different local token.

The release builder separately extracts the actual ZIP and runs local HTTP
acceptance with external networking and child processes forbidden. Its portable
launcher is also checked from that extracted directory. Machine-readable reports
are delivered next to the ZIP.

Native execution has been verified on Windows. macOS/Linux launchers and
instructions are supplied, but this release was not run on those operating
systems. A clean directory on one Windows machine is not claimed as a physical
second-computer or cross-OS test. The default desktop workflow does not require
your original machine to remain powered on.
