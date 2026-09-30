#!/usr/bin/env bash
# preflight.sh — Windows Hunt toolchain + reality check. Run before every hunt.
# Exit 0 always (informational); prints what is missing and how to get it.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="$HERE/.venv"; PY="$VENV/bin/python"
QUIET=0; [ "${1:-}" = "--quiet" ] && QUIET=1
miss_req=0; miss_opt=0
ok(){   printf '  \033[32m[ok]\033[0m   %-16s %s\n' "$1" "${2:-}"; }
warn(){ printf '  \033[33m[!]\033[0m    %-16s %s\n' "$1" "${2:-}"; }
sec(){  printf '\n\033[1m-- %s --\033[0m\n' "$*"; }
req(){ if p=$(command -v "$1" 2>/dev/null); then ok "$1" "$p"; else warn "$1" "REQUIRED — ${2:-}"; miss_req=$((miss_req+1)); fi; }
opt(){ if p=$(command -v "$1" 2>/dev/null); then ok "$1" "$p"; else warn "$1" "optional — ${2:-}"; miss_opt=$((miss_opt+1)); fi; }
pym(){ if [ -x "$PY" ] && "$PY" -c "import $1" >/dev/null 2>&1; then ok "py:$1"; else
        if [ "${2:-req}" = req ]; then warn "py:$1" "REQUIRED — scripts/provision.sh"; miss_req=$((miss_req+1));
        else warn "py:$1" "optional — scripts/provision.sh --tier ${3:-analysis}"; miss_opt=$((miss_opt+1)); fi; fi; }

echo "=== Windows Hunt preflight ==="

sec "unpackers (installer → file tree)"
req 7z          "apt install p7zip-full"
req cabextract  "apt install cabextract"
req msiextract  "apt install msitools"
opt innoextract "apt install innoextract  — Inno Setup installers"
opt binwalk     "apt install binwalk"
opt upx         "apt install upx-ucl"
opt unzip       "apt install unzip"

sec "binary analysis"
req objdump   "apt install binutils"
req strings   "apt install binutils"
req file      "apt install file"
opt radare2   "apt install radare2 — native xref/disasm lane"
opt ghidra    "headless decompiler for the hard native cases"
opt osslsigncode "apt install osslsigncode — Authenticode verification"
opt yara      "apt install yara"
opt exiftool  "apt install exiftool"

sec "python analysis stack (venv)"
if [ -x "$PY" ]; then ok "venv" "$VENV"; else warn "venv" "ABSENT — run scripts/provision.sh"; miss_req=$((miss_req+1)); fi
pym pefile     req
pym capstone   req
pym yara       opt analysis
pym lief       opt core
pym signify    opt core
pym dnfile     opt dotnet
pym dncil      opt dotnet
pym capa       opt analysis
pym floss      opt analysis

sec "managed / scripted code lanes"
opt ilspycmd "dotnet tool install -g ilspycmd — full C# recovery (dnfile/dncil cover IL without it)"
opt dotnet   "apt install dotnet-sdk-8.0"
echo "  [i]  asar (Electron), PyInstaller, py2exe, Nuitka, AutoIt, InstallShield, NSIS, SFX:"
echo "       handled in-tree by scripts/unwrap.py — no node/wine required."

sec "rule packs"
for r in capa-rules signature-base; do
  if [ -d "$HERE/vendor/$r" ]; then ok "$r" "$(find "$HERE/vendor/$r" -name '*.yml' -o -name '*.yar' 2>/dev/null | wc -l) rules"
  else warn "$r" "provision.sh --tier analysis"; miss_opt=$((miss_opt+1)); fi
done
if [ -d "$HERE/rules" ]; then ok "windowshunt-rules" "$(ls "$HERE/rules"/*.yml "$HERE/rules"/*.yar 2>/dev/null | wc -l) own packs"; fi

sec "own scripts"
bad=0
shopt -s nullglob
for f in "$HERE"/scripts/*.py; do "$PY" -m py_compile "$f" 2>/dev/null || python3 -m py_compile "$f" 2>/dev/null || { warn "$(basename "$f")" "SYNTAX ERROR"; bad=$((bad+1)); }; done
for f in "$HERE"/scripts/*.sh; do bash -n "$f" 2>/dev/null || { warn "$(basename "$f")" "SYNTAX ERROR"; bad=$((bad+1)); }; done
n=$(ls "$HERE"/scripts/* 2>/dev/null | wc -l)
[ "$bad" = 0 ] && ok "all $n scripts parse" || warn "$bad script(s)" "FAILED to parse"

sec "EXECUTION REALITY CHECK (this decides which lane you are in)"
winvm="$HERE/scope/vm.md"
has_vm=0
if [ -f "$winvm" ] && grep -qiE '^\s*(host|ip|winrm|ssh|rdp)\s*:' "$winvm" 2>/dev/null; then has_vm=1; fi
if command -v wine >/dev/null 2>&1; then ok "wine" "$(wine --version 2>/dev/null) — PARTIAL execution only"; else warn "wine" "absent — provision.sh --tier dynamic"; fi
for h in qemu-system-x86_64 virsh VBoxManage vmrun; do command -v $h >/dev/null 2>&1 && ok "hypervisor" "$h"; done
[ -e /dev/kvm ] && ok "/dev/kvm" "present — you can run a real Windows VM" || warn "/dev/kvm" "ABSENT — no hardware-accelerated Windows VM on this box"
if [ "$has_vm" = 1 ]; then
  ok "windows target VM" "declared in scope/vm.md"
  echo "  ==> FULL LANE: dynamic confirmation available. Still gated by scope/authorized_actions.txt."
else
  echo
  printf "  \033[1;33m==> NO-WINDOWS-VM LANE IS ACTIVE.\033[0m  Read references/no-vm-lane.md.\n"
  echo "      Fully provable without Windows: installer/ACL intent, DLL-hijack candidates, service"
  echo "      and task definitions, URI handlers, Electron/CEF config, .NET IL sinks, deserialization,"
  echo "      hardcoded secrets, signing gaps, bundled-CVE exposure, update-channel design."
  echo "      Capped at 'static-proof-complete': anything needing a live ACL, a running service, a"
  echo "      real token, or a crash. Those ship as generated PowerShell/C# runbooks for the"
  echo "      operator's own VM — labelled UNCONFIRMED until that run comes back."
fi

sec "authorization"
for f in authorized_targets.txt authorized_hosts.txt authorized_actions.txt; do
  p="$HERE/scope/$f"
  n=$(grep -vE '^\s*(#|!|$)' "$p" 2>/dev/null | grep -c . || true)
  if [ "${n:-0}" -gt 0 ]; then ok "$f" "$n entry/entries"; else warn "$f" "EMPTY — gate fails closed"; fi
done
[ -f "$HERE/scope/rules.md" ] && ok "rules.md" "READ IT before any intrusive action" || warn "rules.md" "missing"

sec "discipline"
cat <<'EOD'
  Authorized targets only. Installers RUN CODE — never execute one outside a disposable VM
  you own. UAC is not a security boundary (MSRC): admin->SYSTEM alone is not a finding.
  A finding is not a finding until it is reproduced with an artifact a triager can replay.
EOD
echo
echo "=== preflight done ($miss_req required missing, $miss_opt optional missing) ==="
[ "$miss_req" -gt 0 ] && echo "    fix:  scripts/provision.sh"
exit 0
