#!/usr/bin/env bash
# install.sh — install Windows Hunt as a Claude Code skill on this machine.
#
#   ./install.sh                 # install to ~/.claude/skills/windowshunt + provision toolchain
#   ./install.sh --link          # symlink instead of copy (for developing the skill itself)
#   ./install.sh --no-provision  # install files only; run scripts/provision.sh yourself later
#   ./install.sh --dest PATH     # install somewhere other than ~/.claude/skills/windowshunt
#
# Requires: Linux (Debian/Ubuntu/Kali tested), python3 >= 3.9, sudo for the apt packages.
# Everything else is fetched by scripts/provision.sh.
set -uo pipefail
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${HOME}/.claude/skills/windowshunt"
LINK=0; PROVISION=1
while [ $# -gt 0 ]; do
  case "$1" in
    --link) LINK=1 ;;
    --no-provision) PROVISION=0 ;;
    --dest) shift; DEST="${1:-$DEST}" ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
  esac; shift
done

say(){ printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok(){  printf '  \033[32m[ok]\033[0m   %s\n' "$*"; }
bad(){ printf '  \033[31m[!]\033[0m    %s\n' "$*"; }

say "Windows Hunt — install"
echo "  source: $SRC"
echo "  dest  : $DEST"

# --- prerequisites -----------------------------------------------------------------
command -v python3 >/dev/null 2>&1 || { bad "python3 not found"; exit 1; }
PYV=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
ok "python3 $PYV"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)' \
  || { bad "python 3.9+ required (found $PYV)"; exit 1; }
python3 -c 'import venv' 2>/dev/null || bad "python3-venv missing — apt install python3-venv"

# --- place the files ---------------------------------------------------------------
if [ -e "$DEST" ] && [ ! -L "$DEST" ]; then
  echo
  read -r -p "  $DEST already exists. Replace it? [y/N] " a
  case "$a" in y|Y) rm -rf "$DEST" ;; *) echo "  aborted."; exit 1 ;; esac
fi
[ -L "$DEST" ] && rm -f "$DEST"
mkdir -p "$(dirname "$DEST")"
if [ "$LINK" = 1 ]; then
  ln -s "$SRC" "$DEST"; ok "symlinked $DEST -> $SRC"
else
  mkdir -p "$DEST"
  tar -C "$SRC" --exclude=.git --exclude=__pycache__ --exclude='*.pyc' -cf - . | tar -C "$DEST" -xf -
  ok "copied $(find "$DEST" -type f | wc -l) files"
fi
chmod +x "$DEST"/scripts/*.sh "$DEST"/install.sh 2>/dev/null

# --- toolchain ----------------------------------------------------------------------
if [ "$PROVISION" = 1 ]; then
  say "provisioning the toolchain (apt + venv + rule packs; this takes a few minutes)"
  "$DEST/scripts/provision.sh" || bad "provisioning reported problems — see above"
else
  echo; ok "skipped provisioning — run: $DEST/scripts/provision.sh"
fi

say "status"
"$DEST/scripts/preflight.sh" 2>&1 | tail -n 22

cat <<EOF

────────────────────────────────────────────────────────────────────────────
Installed. In Claude Code the skill is now available as:   /windowshunt

Verify it works end to end (builds its own test range, ~2 min):
    $DEST/scripts/corpus_check.py
  expected:  DETECTION 70/70   FALSE POSITIVE 0/70

Before any real work, authorize a target — all three scope files are EMPTY
and the gate fails closed by design:
    $DEST/scope/authorized_targets.txt
    $DEST/scope/authorized_hosts.txt
    $DEST/scope/authorized_actions.txt
    $DEST/scope/rules.md          <- fill in the engagement intake

Then:
    $DEST/scripts/hunt.sh --target "/path/Setup.exe" --name myapp
────────────────────────────────────────────────────────────────────────────
EOF
