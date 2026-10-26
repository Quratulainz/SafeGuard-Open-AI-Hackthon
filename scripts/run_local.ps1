param([switch]$NoBrowser, [switch]$Check)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot

$launcherArguments = @()
if ($NoBrowser) { $launcherArguments += '--no-browser' }
if ($Check) { $launcherArguments += '--check' }

if (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 start.py @launcherArguments
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    & python start.py @launcherArguments
} else {
    throw 'Install Python 3.10 or later, then run this script again.'
}
exit $LASTEXITCODE
