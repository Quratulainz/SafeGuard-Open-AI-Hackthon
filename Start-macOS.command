#!/bin/sh
# Run with sh if extraction did not preserve the executable flag.
cd -- "$(dirname -- "$0")" || exit 1
if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' 'Install Python 3.10 or newer from https://www.python.org/downloads/ and try again.'
  exit 1
fi
exec python3 ./start.py "$@"
