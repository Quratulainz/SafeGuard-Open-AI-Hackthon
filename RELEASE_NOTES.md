# SafeGuard AI v0.3.2 portable English source release

Start with START_HERE.txt, docs/PORTABILITY.md or docs/GETTING_STARTED.md.
Install a supported Python release (source compatibility floor: 3.10).
Python is not bundled. Default startup needs no third-party Python packages.
Windows: Start-Windows.cmd. macOS: sh Start-macOS.command. Linux: sh start-linux.sh.
The launchers locate their own project directory and never require Codex.
Windows relocation was executed; macOS/Linux native acceptance was not performed.
Optional H-MEM/full tests require Node.js 24; external integrations are opt-in.
Website green is a scoped current-page result, not official identity certification.
See docs/WEBSITE_CHECKS.md and the English calendar/assistant setup guide.
Current automated validation is recorded in MODIFICATION_DIARY.md and README.md.
The separate English archive smoke report covers fresh local HTTP acceptance.
Intentional multilingual detector patterns and input fixtures are retained;
they are not untranslated interface messages.

This archive excludes .env, local history/subscriptions/tokens, SSH keys, raw
threat feeds, runtime/model binaries, licensed platform bundles, private outputs,
the separately supplied competition PDF, and the superseded original diary.
The current MODIFICATION_DIARY.md is included. Competition PDF page citations
refer to the user's separately provided document, not an included file.
Unmodified upstream H-MEM documentation may link optional upstream examples not
vendored here; use server/vendor/meterless_hmem/UPSTREAM.md for the pinned source.

The team has not chosen a root project license. Do not interpret source delivery
as a new license grant. Included third-party code keeps its own license notices.
Threat-feed redistribution rights have not been cleared; use the documented
private fetch/backup procedure rather than republishing raw source lists.

RELEASE_MANIFEST.json lists SHA-256 and byte size for every payload file except
the manifest itself. The separate archive SHA-256 verifies the whole ZIP.
The delivered smoke report describes fresh local HTTP acceptance from an
extracted copy with external networking and child processes forbidden. It does
not claim live cloud/model connectivity or repeat browser UI acceptance.
