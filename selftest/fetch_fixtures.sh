#!/usr/bin/env bash
# fetch_fixtures.sh — download the third-party sample binaries the toolchain smoke tests use.
#
# These are NOT engagement targets and NOT part of the measured corpus (that range is generated
# locally by make_range.py). They are real-world installers used to prove the unpackers and
# parsers work against files this project did not create. They are not redistributed in the
# repository — this script fetches them from the vendors.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
get(){ echo "  -> $2"; curl -fsSL -o "$HERE/$2" "$1" || echo "     FAILED: $1"; }
echo "fetching toolchain-validation fixtures into $HERE"
get https://www.7-zip.org/a/7z2408.exe           7z2408.exe           # NSIS-style installer, unsigned
get https://www.7-zip.org/a/7z2408-x64.msi       7z2408-x64.msi       # real MSI with 32 tables
get https://www.nuget.org/api/v2/package/Newtonsoft.Json/13.0.3 newtonsoft.json.nupkg  # .NET assemblies
echo
echo "done. These are only for smoke-testing the parsers, e.g.:"
echo "  TARGETS_FILE=$HERE/scope_selftest.txt ../scripts/hunt.sh --target $HERE/7z2408-x64.msi --name smoke --fast"
echo
echo "The MEASURED corpus needs none of them:  ../scripts/corpus_check.py"
