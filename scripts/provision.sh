#!/usr/bin/env bash
# provision.sh — Windows Hunt auto-provisioner.
#
# Installs everything the skill needs to take a Windows installer/executable apart on Linux.
# Idempotent: re-running only fills gaps. Tiered so a hunt can start before the slow tiers land.
#
#   provision.sh                 # core + analysis + dotnet (the default hunt set)
#   provision.sh --tier core     # just enough to unpack and triage
#   provision.sh --tier all      # everything incl. wine + fuzzing (slow, ~2 GB)
#   provision.sh --check         # report only, install nothing
#
# Tiers:
#   core      unpackers + PE parsers        (apt + venv, ~2 min)
#   analysis  capa, floss, yara rules       (venv + rule clones, ~3 min)
#   dotnet    .NET IL lane (dnfile/dncil)   (venv, fast)  + ilspycmd if dotnet SDK present
#   dynamic   wine + frida                  (apt, ~1.5 GB)
#   fuzz      afl++, radamsa                (apt)
#   all       every tier above
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$HERE/.venv"
PY="$VENV/bin/python"
PIP="$VENV/bin/pip"
VENDOR="$HERE/vendor"
TIER="core analysis dotnet"
CHECK=0
while [ $# -gt 0 ]; do
  case "$1" in
    --tier) shift; case "${1:-}" in
              all) TIER="core analysis dotnet dynamic fuzz" ;;
              *)   TIER="${1:-core}" ;; esac ;;
    --check) CHECK=1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
  esac; shift
done
say(){ printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok(){  printf '  \033[32m[ok]\033[0m   %s\n' "$*"; }
add(){ printf '  \033[33m[+]\033[0m    %s\n' "$*"; }
bad(){ printf '  \033[31m[!]\033[0m    %s\n' "$*"; }
have(){ command -v "$1" >/dev/null 2>&1; }
SUDO=""; if [ "$(id -u)" -ne 0 ]; then if sudo -n true 2>/dev/null; then SUDO="sudo -n"; else SUDO="sudo"; fi; fi

APT_CORE="cabextract msitools innoextract yara osslsigncode binutils p7zip p7zip-full unzip xz-utils zstd libmagic1 file exiftool radare2"
APT_DYN="wine wine64 winetricks winbind"
APT_FUZZ="afl++ radamsa"
PIP_CORE="pefile lief capstone yara-python signify pyasn1 cryptography rich construct python-magic"
PIP_ANALYSIS="flare-capa flare-floss"
PIP_DOTNET="dnfile dncil"

apt_install(){
  local want="$1" missing=""
  for p in $want; do
    dpkg -s "$p" >/dev/null 2>&1 || { apt-cache show "$p" >/dev/null 2>&1 && missing="$missing $p"; }
  done
  if [ -z "$(echo "$missing" | tr -d ' ')" ]; then ok "apt: all present"; return 0; fi
  add "apt install:$missing"
  [ "$CHECK" = 1 ] && return 0
  $SUDO apt-get update -qq 2>/dev/null
  # shellcheck disable=SC2086
  $SUDO apt-get install -y -qq $missing >/dev/null 2>&1 || bad "apt partially failed:$missing"
  for p in $missing; do dpkg -s "$p" >/dev/null 2>&1 && ok "apt $p" || bad "apt $p MISSING"; done
}

venv_ensure(){
  if [ ! -x "$PY" ]; then
    [ "$CHECK" = 1 ] && { add "venv would be created at $VENV"; return 0; }
    add "creating venv $VENV"
    python3 -m venv "$VENV" || { bad "venv creation failed"; return 1; }
    "$PIP" -q install --upgrade pip setuptools wheel >/dev/null 2>&1
  fi
  ok "venv $VENV"
}

pip_install(){
  local want="$1" missing=""
  [ -x "$PY" ] || { add "pip (no venv yet):$want"; return 0; }
  for p in $want; do
    mod="$(echo "$p" | sed 's/flare-//; s/python-magic/magic/; s/yara-python/yara/; s/-/_/g')"
    "$PY" -c "import $mod" >/dev/null 2>&1 || missing="$missing $p"
  done
  if [ -z "$(echo "$missing" | tr -d ' ')" ]; then ok "pip: all present"; return 0; fi
  add "pip install:$missing"
  [ "$CHECK" = 1 ] && return 0
  # shellcheck disable=SC2086
  "$PIP" -q install $missing 2>&1 | tail -2
  for p in $missing; do
    mod="$(echo "$p" | sed 's/flare-//; s/python-magic/magic/; s/yara-python/yara/; s/-/_/g')"
    "$PY" -c "import $mod" >/dev/null 2>&1 && ok "pip $p" || bad "pip $p MISSING"
  done
}

clone_or_pull(){ # url dest [--depth]
  local url="$1" dest="$2"
  if [ -d "$dest/.git" ]; then ok "repo $(basename "$dest")"; return 0; fi
  add "clone $(basename "$dest")"
  [ "$CHECK" = 1 ] && return 0
  mkdir -p "$(dirname "$dest")"
  git clone --depth 1 -q "$url" "$dest" 2>/dev/null && ok "repo $(basename "$dest")" || bad "clone failed: $url"
}

echo "=== Windows Hunt provisioner — tiers: $TIER$([ $CHECK = 1 ] && echo '  (CHECK ONLY)') ==="

for t in $TIER; do
case "$t" in
  core)
    say "tier core — unpackers + PE parsers"
    apt_install "$APT_CORE"; venv_ensure; pip_install "$PIP_CORE"
    # pure-python helpers vendored so no node/dotnet is required for the common cases
    ;;
  analysis)
    say "tier analysis — capa, floss, rule packs"
    venv_ensure; pip_install "$PIP_ANALYSIS"
    clone_or_pull https://github.com/mandiant/capa-rules.git "$VENDOR/capa-rules"
    clone_or_pull https://github.com/Neo23x0/signature-base.git "$VENDOR/signature-base"
    # capa refuses to run without FLIRT signatures; fetch just the sigs dir (no full repo clone)
    if [ -d "$VENDOR/capa-sigs" ] && [ "$(ls -1 "$VENDOR/capa-sigs"/*.sig 2>/dev/null | wc -l)" -ge 3 ]; then
      ok "capa-sigs"
    else
      add "download capa FLIRT signatures"
      if [ "$CHECK" != 1 ]; then
        mkdir -p "$VENDOR/capa-sigs"
        curl -sS https://api.github.com/repos/mandiant/capa/contents/sigs 2>/dev/null \
          | grep -o '"download_url": *"[^"]*"' | cut -d'"' -f4 \
          | while read -r u; do curl -sSL -o "$VENDOR/capa-sigs/$(basename "$u")" "$u"; done
        [ "$(ls -1 "$VENDOR/capa-sigs"/*.sig 2>/dev/null | wc -l)" -ge 3 ] && ok "capa-sigs" || bad "capa-sigs download failed"
      fi
    fi
    ;;
  dotnet)
    say "tier dotnet — managed-code lane"
    venv_ensure; pip_install "$PIP_DOTNET"
    if have dotnet; then
      if [ -x "$HOME/.dotnet/tools/ilspycmd" ]; then ok "ilspycmd"
      else add "dotnet tool install ilspycmd (full C# decompile)"
        [ "$CHECK" = 1 ] || dotnet tool install -g ilspycmd >/dev/null 2>&1 && ok "ilspycmd" || bad "ilspycmd failed"
      fi
    else
      bad "dotnet SDK absent — IL lane runs on dnfile/dncil (pure python, no C# source recovery)."
      bad "     optional upgrade:  sudo apt install -y dotnet-sdk-8.0 && dotnet tool install -g ilspycmd"
    fi
    ;;
  dynamic)
    say "tier dynamic — wine + frida (partial Linux-side execution)"
    apt_install "$APT_DYN"
    venv_ensure; pip_install "frida-tools"
    ;;
  fuzz)
    say "tier fuzz — afl++ / radamsa"
    apt_install "$APT_FUZZ"
    ;;
esac
done

say "result"
"$HERE/scripts/preflight.sh" --quiet 2>/dev/null || true
echo
echo "venv python: $PY"
echo "Run a full status check any time:  scripts/preflight.sh"
