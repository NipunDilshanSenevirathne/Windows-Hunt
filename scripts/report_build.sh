#!/usr/bin/env bash
# report_build.sh — assemble a submission-ready finding directory.
#   report_build.sh --loot loot/<name> --id F1 --title "LPE via ..." [--out /path]
# Creates <out>/F1-<slug>/ with report.md, evidence/, poc/ and a reproduction script slot.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOOT=""; ID="F1"; TITLE="finding"; OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --loot)  shift; LOOT="${1:-}" ;;
    --id)    shift; ID="${1:-F1}" ;;
    --title) shift; TITLE="${1:-finding}" ;;
    --out)   shift; OUT="${1:-}" ;;
  esac; shift
done
[ -z "$LOOT" ] && { echo "usage: report_build.sh --loot <loot> --id F1 --title '...'"; exit 1; }
OUT="${OUT:-$LOOT/findings}"
slug="$(echo "$TITLE" | tr 'A-Z' 'a-z' | tr -cs 'a-z0-9' '-' | sed 's/^-//; s/-$//' | cut -c1-60)"
DIR="$OUT/$ID-$slug"
mkdir -p "$DIR/evidence" "$DIR/poc"

cat > "$DIR/report.md" <<EOF
# $ID — $TITLE

## Summary

As an attacker with <starting position>, I can <the action>, which results in <the impact>.

## Security boundary crossed

<user-to-system | web-to-local | update-channel | ...>
Why this is a boundary: <one line; if it is NOT on the MSRC boundary list, say why it still matters>

## Severity

Run: \`scripts/severity_win.py --vector "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" --boundary user-to-system\`
Paste the "report sentence" it prints here.

## Affected

- Product / version:
- File(s):
- SHA-256:
- Tested on: Windows <build>, <default install | custom path>

## Preconditions

- [ ] attacker position:
- [ ] user interaction required:
- [ ] non-default configuration required:  (if yes, say how common it is)

## Steps to reproduce

1.
2.
3.

Expected: <what a correct implementation would do>
Actual:   <what happens, with the artifact that proves it>

## Proof

<the artifact — a file written by the privileged process, a command line captured in Process
Explorer, a Procmon line, a decoded token. Not a screenshot of calc.exe.>

## Root cause

<the specific code / configuration / ACL, with file:line or the registry path>

## Impact

<what an attacker gains, stated once, without adjectives>

## Remediation

<the specific change; name the API or setting>

## References

-
EOF

for f in unwrap.md surface.md dll_hijack.md dotnet_il.md electron.md secrets.md sbom.md drivers.md native.md chains.md verified.md ledger.md; do
  [ -f "$LOOT/$f" ] && cp "$LOOT/$f" "$DIR/evidence/" 2>/dev/null
done
[ -d "$LOOT/runbook" ] && cp -r "$LOOT/runbook" "$DIR/evidence/" 2>/dev/null

cat > "$DIR/evidence/README.md" <<EOF
Analysis artifacts for $ID. These are the full engine outputs the finding was drawn from;
the report cites specific lines from them. Trim anything not referenced before submitting —
a triager should not have to read the whole run.
EOF

echo "[report_build] -> $DIR"
echo "  report.md      fill it in — the summary sentence first, it decides how the rest is read"
echo "  evidence/      engine outputs (trim to what you cite)"
echo "  poc/           put the runnable PoC here (scripts/poc_gen.py)"
