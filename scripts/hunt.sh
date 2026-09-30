#!/usr/bin/env bash
# hunt.sh — one command, the whole static pipeline, scope-gated.
#
#   hunt.sh --target /path/to/Setup.exe --name acme [--online] [--fast] [--top 12]
#
# 24 stages: scope gate -> unwrap -> pe_triage -> surface_model -> integration_points ->
#   com_audit -> rpc_audit -> dll_hijack -> dotnet_il -> runtime_lane -> electron_audit ->
#   secrets_hunt -> credstore_audit -> sign_audit -> sbom_cve -> driver_ioctl -> toctou_audit ->
#   process_audit -> native_sinks -> fuzz_harness -> chain -> primitive_to_exploit ->
#   dedup_oracle -> runbook_gen -> procmon_filter -> ledger init.
#
# Everything lands in loot/<name>/. Each stage writes both .json (for the next stage) and
# .md (for you). Stages are independent: re-run any one of them alone.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$HERE/.venv/bin/python"; [ -x "$PY" ] || PY=python3
TARGET=""; NAME=""; ONLINE=""; FAST=0; TOP=12
while [ $# -gt 0 ]; do
  case "$1" in
    --target) shift; TARGET="${1:-}" ;;
    --name)   shift; NAME="${1:-}" ;;
    --online) ONLINE="--online" ;;
    --fast)   FAST=1 ;;
    --top)    shift; TOP="${1:-12}" ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
  esac; shift
done
[ -z "$TARGET" ] && { echo "usage: hunt.sh --target <file|dir> --name <short-name>"; exit 1; }
[ -e "$TARGET" ] || { echo "hunt.sh: no such target: $TARGET"; exit 1; }
# canonicalise before the gate: a path-prefix scope entry is absolute, and a
# relative invocation must not read as "unauthorized" when it is the same file.
TARGET="$(realpath "$TARGET")"
NAME="${NAME:-$(basename "$TARGET" | tr -cd '[:alnum:]._-')}"
LOOT="$HERE/loot/$NAME"

echo "=============================================================="
echo " Windows Hunt — $NAME"
echo " target: $TARGET"
echo "=============================================================="

# ---- PHASE 0: authorization. Hard fail. ----------------------------------
if ! "$HERE/scripts/scope_gate.sh" target "$TARGET"; then
  echo
  echo "REFUSED. Add the target to scope/authorized_targets.txt only with real authorization"
  echo "(your own product, or a program that lists it). The gate fails closed by design."
  exit 1
fi
sha="$(sha256sum "$TARGET" 2>/dev/null | cut -d' ' -f1)"
[ -n "$sha" ] && echo "sha256: $sha"

mkdir -p "$LOOT"
step() { echo; echo "---- $* ----"; }
run()  { echo "\$ ${*}"; "$@" 2>&1 | tail -n "${TAIL:-6}"; }

step "1/24 unwrap (recursive container extraction)"
run "$PY" "$HERE/scripts/unwrap.py" --target "$TARGET" --out "$LOOT"
[ -f "$LOOT/unwrap.json" ] || { echo "unwrap produced nothing — stopping"; exit 1; }

step "2/24 pe_triage (mitigations, signing, imports, manifests)"
run "$PY" "$HERE/scripts/pe_triage.py" --loot "$LOOT"

step "3/24 surface_model (services, COM, pipes, URI, listeners, ACL intent)"
run "$PY" "$HERE/scripts/surface_model.py" --loot "$LOOT"

step "4/24 integration_points (native messaging, shell ext, hooks, tasks, AppX, assoc)"
run "$PY" "$HERE/scripts/integration_points.py" --loot "$LOOT"

step "5/24 com_audit (CLSID server paths, elevation, AppID identity + ACL)"
run "$PY" "$HERE/scripts/com_audit.py" --loot "$LOOT"

step "6/24 rpc_audit (RPC/ALPC interface UUIDs, opnum counts, endpoints)"
run "$PY" "$HERE/scripts/rpc_audit.py" --loot "$LOOT"

step "7/24 dll_hijack (phantom / side-load, privilege-ranked)"
run "$PY" "$HERE/scripts/dll_hijack.py" --loot "$LOOT"

step "8/24 dotnet_il (managed sink analysis)"
run "$PY" "$HERE/scripts/dotnet_il.py" --loot "$LOOT"

step "9/24 runtime_lane (Java / Python / Node / CLR probing paths)"
run "$PY" "$HERE/scripts/runtime_lane.py" --loot "$LOOT"

step "10/24 electron_audit (Electron / CEF / WebView2)"
run "$PY" "$HERE/scripts/electron_audit.py" --loot "$LOOT"

step "11/24 secrets_hunt"
run "$PY" "$HERE/scripts/secrets_hunt.py" --loot "$LOOT"

step "12/24 credstore_audit (DPAPI scope, hardcoded keys, stores at rest)"
run "$PY" "$HERE/scripts/credstore_audit.py" --loot "$LOOT"

step "13/24 sign_audit (Authenticode depth + does the product verify anything?)"
run "$PY" "$HERE/scripts/sign_audit.py" --loot "$LOOT"

step "14/24 sbom_cve (bundled components -> known CVEs)"
run "$PY" "$HERE/scripts/sbom_cve.py" --loot "$LOOT" $ONLINE

step "15/24 driver_ioctl (kernel drivers)"
run "$PY" "$HERE/scripts/driver_ioctl.py" --loot "$LOOT"

step "16/24 toctou_audit (race / symlink / impersonation-gap primitives)"
run "$PY" "$HERE/scripts/toctou_audit.py" --loot "$LOOT"

step "17/24 process_audit (child processes, handles, tokens, privileges)"
run "$PY" "$HERE/scripts/process_audit.py" --loot "$LOOT"

if [ "$FAST" = 1 ]; then
  echo; echo "---- 18/24 native_sinks SKIPPED (--fast) ----"
else
  step "18/24 native_sinks (capa + radare2 xrefs — the slow one)"
  TAIL=4 run "$PY" "$HERE/scripts/native_sinks.py" --loot "$LOOT" --top "$TOP"
fi

step "19/24 fuzz_harness (parser inventory + ready harnesses)"
run "$PY" "$HERE/scripts/fuzz_harness.py" --loot "$LOOT"

step "20/24 chain (compose weaknesses into boundary crossings)"
run "$PY" "$HERE/scripts/chain.py" --loot "$LOOT"

step "21/24 primitive_to_exploit (what each primitive turns into)"
run "$PY" "$HERE/scripts/primitive_to_exploit.py" --loot "$LOOT" --auto

if [ -n "$ONLINE" ]; then
  step "22/24 dedup_oracle (published CVEs for this product)"
  run "$PY" "$HERE/scripts/dedup_oracle.py" --loot "$LOOT"
else
  echo; echo "---- 22/24 dedup_oracle SKIPPED (pass --online to query NVD/OSV) ----"
fi

step "23/24 runbook (what to run in your own Windows VM)"
run "$PY" "$HERE/scripts/runbook_gen.py" --loot "$LOOT"

step "24/24 procmon (session plan + CSV analyzer for the VM)"
run "$PY" "$HERE/scripts/procmon_filter.py" --loot "$LOOT"
"$PY" "$HERE/scripts/hunt_state.py" init --loot "$LOOT" --target "$NAME" >/dev/null 2>&1

echo
echo "=============================================================="
echo " DONE — read in this order:"
echo "   unwrap.md        what it is, what came out"
echo "   surface.md       the boundaries this product creates      <- start here"
echo "   integration.md   what it asks Windows to load for it      <- then here"
echo "   chains.md        proposed boundary crossings"
echo "   exploit_paths.md what each primitive turns into           <- then here"
echo "   com.md  rpc.md  dll_hijack.md  dotnet_il.md  runtime.md  electron.md"
echo "   toctou.md  process.md  credstore.md  secrets.md  signing.md"
echo "   sbom.md  drivers.md  native.md  fuzz.md  dedup.md"
echo "   procmon/ (VM session plan)   frida/ (runtime instrumentation)"
echo "   (all under $LOOT/)"
echo "   $LOOT/runbook/verify.ps1   <- run in YOUR OWN Windows VM, then:"
echo "        scripts/runbook_ingest.py --loot $LOOT --result wh-verify.json"
echo
echo " Then work the ledger:  scripts/hunt_state.py next --loot $LOOT"
echo "=============================================================="
