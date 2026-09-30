#!/usr/bin/env python3
"""
dll_hijack.py — DLL search-order / phantom / side-load candidate finder, privilege-ranked.

The class is old and still pays, because the question tools get wrong is not "does it import
a DLL that isn't in System32" — it is "**who** loads it, **from where**, and **can I write
there**". This ranks by that, not by count.

Classification per (loader, dll):
  PHANTOM        imported by name, not shipped in the package, not a known system/API-set DLL
                 -> resolved through the search order; drop a DLL in the app dir and you own it
  SIDELOAD       shipped in the same directory as the loader; if that directory is user-writable
                 (ProgramData / AppData / Public / a non-default install root) it is replaceable
  KNOWNDLL       protected by the KnownDLLs section — NOT hijackable in-process, suppressed
  SYSTEM         resolved from System32, requires admin to replace -> only relevant with a
                 writable-PATH or current-directory precondition
  DYNAMIC        loaded by LoadLibrary with a computed/relative name (string evidence)

Privilege weight comes from the loader: service / requireAdministrator manifest / autoElevate /
installed under a privileged path => LPE. Everything else is at best code execution in the
user's own context (usually only interesting as a persistence or AV-bypass note, or as the
second stage of a chain).

Usage:  dll_hijack.py --loot loot/<name> [--min-score 0]
Writes: <loot>/dll_hijack.json, <loot>/dll_hijack.md
"""
import argparse, json, os, re, sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# KnownDLLs (HKLM\SYSTEM\CCS\Control\Session Manager\KnownDLLs, Win10/11 typical) — these
# resolve from the section cache, so an app-directory copy is NOT loaded. Suppressing them is
# the difference between a real report and 200 lines of noise.
KNOWNDLLS = set("""advapi32.dll clbcatq.dll combase.dll comdlg32.dll coml2.dll difxapi.dll
gdi32.dll gdiplus.dll imagehlp.dll imm32.dll kernel32.dll kernelbase.dll msctf.dll msvcrt.dll
normaliz.dll nsi.dll ntdll.dll ole32.dll oleaut32.dll psapi.dll rpcrt4.dll sechost.dll
setupapi.dll shcore.dll shell32.dll shlwapi.dll user32.dll wldap32.dll ws2_32.dll
wow64.dll wow64base.dll wow64con.dll wow64cpu.dll wow64win.dll xtajit.dll""".split())

# Broad System32 set. Not exhaustive by design: anything unknown is reported as
# VERIFY-ON-WINDOWS rather than silently called a phantom.
SYSTEM32 = KNOWNDLLS | set("""ntoskrnl.exe hal.dll win32u.dll dwmapi.dll uxtheme.dll
propsys.dll winhttp.dll wininet.dll urlmon.dll iertutil.dll crypt32.dll cryptbase.dll
cryptsp.dll bcrypt.dll bcryptprimitives.dll ncrypt.dll ncryptsslp.dll wintrust.dll
msasn1.dll secur32.dll sspicli.dll schannel.dll credui.dll netapi32.dll netutils.dll
srvcli.dll wkscli.dll samcli.dll logoncli.dll dnsapi.dll iphlpapi.dll mswsock.dll
winnsi.dll rasapi32.dll rasman.dll wtsapi32.dll userenv.dll profapi.dll
version.dll winmm.dll winmmbase.dll avrt.dll audioses.dll mmdevapi.dll
dbghelp.dll dbgcore.dll symsrv.dll msvcp_win.dll ucrtbase.dll vcruntime140.dll
vcruntime140_1.dll msvcp140.dll concrt140.dll api-ms-win-crt-runtime-l1-1-0.dll
comctl32.dll msimg32.dll winspool.drv mpr.dll authz.dll mstask.dll taskschd.dll
powrprof.dll umpdc.dll cfgmgr32.dll devobj.dll devrtl.dll newdev.dll
oleacc.dll msi.dll msiltcfg.dll cabinet.dll wer.dll faultrep.dll
d3d11.dll d3d9.dll dxgi.dll d2d1.dll dwrite.dll windowscodecs.dll
opengl32.dll glu32.dll wldp.dll amsi.dll appidapi.dll
sfc.dll sfc_os.dll slc.dll sppc.dll winsta.dll rstrtmgr.dll
fwpuclnt.dll ntmarta.dll dsrole.dll activeds.dll adsldpc.dll
wevtapi.dll tdh.dll advpack.dll apphelp.dll acgenral.dll
mfplat.dll mf.dll mfreadwrite.dll evr.dll dsound.dll dinput8.dll xinput1_4.dll
scrrun.dll vbscript.dll jscript.dll jscript9.dll mshtml.dll
rasadhlp.dll dhcpcsvc.dll wshbth.dll nlaapi.dll napinsp.dll pnrpnsp.dll winrnr.dll
msxml3.dll msxml6.dll xmllite.dll
twinapi.dll twinapi.appcore.dll windows.storage.dll windows.ui.dll
coremessaging.dll coreuicomponents.dll bcp47langs.dll bcp47mrm.dll
ntdsapi.dll dpapi.dll dpapiprovider.dll keyiso.dll vaultcli.dll
mscoree.dll mscoreei.dll clr.dll clrjit.dll coreclr.dll hostfxr.dll hostpolicy.dll
system.ni.dll gpapi.dll cryptnet.dll winsqlite3.dll sqlite3.dll
imm32.dll msctfmonitor.dll input.dll tiptsf.dll
edputil.dll shdocvw.dll browseui.dll duser.dll dui70.dll
rometadata.dll wintypes.dll threadpoolwinrt.dll
""".split())

VENDORED_RUNTIME = re.compile(r'(?i)^(msvcp\d+|msvcr\d+|vcruntime\d+|vcomp\d+|concrt\d+|'
                              r'mfc\d+u?|api-ms-win-.*|ext-ms-.*|ucrtbase.*|python\d+|'
                              r'libgcc.*|libstdc\+\+.*|libwinpthread.*)\.dll$')

USER_WRITABLE_HINT = re.compile(r'(?i)(programdata|appdata|users\\public|\\public\\|\\temp\\|'
                                r'localappdata|roaming)')


def privileged(binrec, surface, path):
    """Score how privileged the LOADER is. This is what decides severity."""
    why, w = [], 0.0
    man = binrec.get('manifest') or {}
    lvl = man.get('requestedExecutionLevel')
    if lvl in ('requireAdministrator', 'highestAvailable'):
        w += 0.55; why.append(f'manifest {lvl}')
    if man.get('autoElevate'):
        w += 0.30; why.append('autoElevate')
    if man.get('uiAccess') in ('true', 'True'):
        w += 0.15; why.append('uiAccess')
    caps = binrec.get('capabilities') or {}
    if 'service' in caps:
        w += 0.45; why.append('service APIs (likely runs as LocalSystem)')
    base = os.path.basename(path).lower()
    if re.search(r'(?i)(service|svc|daemon|agent|updater|update|helper|elev|admin|host|broker)', base):
        w += 0.25; why.append(f'name suggests privileged role ({base})')
    for s in surface.get('services', []):
        v = s['v']
        nm = (v.get('name') if isinstance(v, dict) else str(v)) or ''
        if base.split('.')[0] and base.split('.')[0] in nm.lower():
            w += 0.40; why.append(f'matches declared service "{nm}"')
            break
    if binrec.get('is_driver'):
        w += 0.5; why.append('kernel driver')
    return min(w, 1.0), why


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--loot', required=True)
    ap.add_argument('--min-score', type=float, default=0.0)
    a = ap.parse_args()
    loot = a.loot
    tri = json.load(open(os.path.join(loot, 'pe_triage.json')))
    man = json.load(open(os.path.join(loot, 'unwrap.json')))
    sfile = os.path.join(loot, 'surface.json')
    surface = json.load(open(sfile)) if os.path.isfile(sfile) else {}

    # shipped DLL inventory, by directory
    shipped = {}          # lowercase basename -> [paths]
    dirs_of = {}
    for f in man['files']:
        b = os.path.basename(f['path']).lower()
        if b.endswith(('.dll', '.ocx', '.drv', '.cpl', '.node', '.pyd', '.sys', '.exe')):
            shipped.setdefault(b, []).append(f['path'])
            dirs_of.setdefault(b, set()).add(os.path.dirname(f['path']))

    findings = []
    for b in tri['binaries']:
        if not b.get('ok'):
            continue
        path = b['path']
        bdir = os.path.dirname(path)
        pw, pwhy = privileged(b, surface, path)
        delay = set(b.get('delay_imports') or [])
        for dll in (b.get('imports') or {}):
            d = dll.lower().strip()
            if not d.endswith(('.dll', '.drv', '.ocx')):
                continue
            if d in KNOWNDLLS:
                cls, note = 'KNOWNDLL', 'protected by the KnownDLLs section — not hijackable in-process'
            elif d.startswith(('api-ms-win', 'ext-ms-')):
                cls, note = 'APISET', 'API set — resolved by the loader, not by path'
            elif d in shipped:
                same_dir = bdir in dirs_of.get(d, set())
                cls = 'SIDELOAD'
                note = ('shipped beside the loader — replaceable if the install directory is writable'
                        if same_dir else
                        f"shipped elsewhere in the package ({sorted(dirs_of[d])[0]}) — the loader still "
                        f"searches its own directory FIRST, so a same-name drop wins")
            elif d in SYSTEM32:
                cls, note = 'SYSTEM', 'resolves from System32 (admin-only to replace); only reachable via a writable PATH entry or current-directory precondition'
            elif VENDORED_RUNTIME.match(d):
                cls, note = 'RUNTIME', 'redistributable runtime — usually present in System32 on a real host; VERIFY on Windows'
            else:
                cls, note = 'PHANTOM', 'NOT in the package and not a known system DLL — the loader will walk the search order and find nothing; drop a same-named DLL in the application directory and it is loaded'
            if cls in ('KNOWNDLL', 'APISET'):
                continue
            score = 0.0
            if cls == 'PHANTOM':
                score = 0.55
            elif cls == 'SIDELOAD':
                score = 0.35
            elif cls == 'RUNTIME':
                score = 0.25
            else:
                score = 0.10
            if d in delay:
                score += 0.10
                note += ' · DELAY-LOADED (resolved at first call, after the process is running)'
            mit = set()
            fl = sum(([f.lower() for f in v] for v in [b.get('imports', {}).get(k, []) for k in b.get('imports', {})]), [])
            if any('setdefaultdlldirectories' in x for x in fl):
                mit.add('SetDefaultDllDirectories imported (hardening present — check it is called EARLY)')
                score -= 0.15
            if any('setdlldirectory' in x for x in fl):
                mit.add('SetDllDirectory imported')
                score -= 0.05
            writable = bool(USER_WRITABLE_HINT.search(path))
            if writable:
                score += 0.20
            total = round(max(0.0, min(1.0, score)) * (0.35 + 0.65 * pw), 3)
            if total < a.min_score:
                continue
            findings.append({
                'loader': path, 'loader_arch': b.get('arch'), 'dll': d, 'class': cls,
                'note': note, 'delay_loaded': d in delay,
                'loader_privilege': round(pw, 2), 'privilege_why': pwhy,
                'mitigations': sorted(mit), 'score': total,
                'shipped_at': sorted(dirs_of.get(d, []))[:3],
                'impact': ('LOCAL PRIVILEGE ESCALATION' if pw >= 0.4 else
                           'code execution in the loading user context (chain component / persistence)'),
            })

    findings.sort(key=lambda x: -x['score'])
    json.dump({'count': len(findings), 'findings': findings},
              open(os.path.join(loot, 'dll_hijack.json'), 'w'), indent=1)

    ph = [f for f in findings if f['class'] == 'PHANTOM']
    lpe = [f for f in findings if f['loader_privilege'] >= 0.4]
    L = ['# DLL search-order / side-load candidates', '',
         f'- candidates: **{len(findings)}**  (phantom: **{len(ph)}**, '
         f'loaded by a privileged process: **{len(lpe)}**)', '',
         '> KnownDLLs and API-set imports are suppressed — they are not hijackable and reporting',
         '> them is how a report gets closed as noise.', '']
    if lpe:
        L += ['## PRIORITY — privileged loader (LPE candidates)', '']
        for f in lpe[:40]:
            L += [f"### `{f['dll']}` ← `{f['loader']}`  ({f['class']}, score {f['score']})",
                  f"- loader privilege **{f['loader_privilege']}**: {'; '.join(f['privilege_why']) or 'unclear'}",
                  f"- {f['note']}",
                  f"- impact if confirmed: **{f['impact']}**"]
            if f['mitigations']:
                L.append(f"- mitigation seen: {'; '.join(f['mitigations'])}")
            L += ['- verify on Windows:', '  ```powershell',
                  f"  # 1. is the directory writable by a normal user?",
                  f"  icacls \"C:\\Path\\To\\{os.path.basename(f['loader'])}\\..\"",
                  f"  # 2. does the process actually look for it? (Procmon, filter: Result is NAME NOT FOUND)",
                  f"  #    Path contains {f['dll']}",
                  f"  # 3. drop a benign proxy DLL and confirm load + the token it runs under",
                  '  ```', '']
    L += ['## All candidates', '', '| score | dll | class | loader | priv | delay |', '|---|---|---|---|---|---|']
    for f in findings[:120]:
        L.append(f"| {f['score']} | `{f['dll']}` | {f['class']} | `{f['loader']}` | {f['loader_privilege']} | "
                 f"{'yes' if f['delay_loaded'] else ''} |")
    L += ['', '## How to turn a candidate into a finding', '',
          '1. Confirm the load attempt (Procmon: `Result is NAME NOT FOUND` + `Path ends with <dll>`).',
          '2. Confirm the directory ACL grants a non-admin principal write/create '
          '(`icacls`, look for `(M)`, `(W)`, `(F)` on `BUILTIN\\Users`, `Authenticated Users`, `Everyone`, or an `(OI)(CI)` inherited equivalent).',
          '3. Confirm the loading process token (`Process Explorer` → Security tab). SYSTEM or a',
          '   different user = privilege boundary crossed. Same user = not a boundary on its own.',
          '4. Drop a proof DLL (`scripts/poc_gen.py --kind proxy-dll`) and capture the whoami it writes.',
          '',
          '> Reportability note: if the hijack only works when the user is already an administrator',
          "> and UAC is at its default level, MSRC treats that as **not a security boundary**. Say so",
          '> in the report and pivot to the non-admin case, or the case is closed as by-design.']
    open(os.path.join(loot, 'dll_hijack.md'), 'w').write('\n'.join(L))
    print(f'[dll_hijack] {len(findings)} candidates ({len(ph)} phantom, {len(lpe)} privileged-loader)')
    print(f'[dll_hijack] -> {loot}/dll_hijack.json + dll_hijack.md')


if __name__ == '__main__':
    main()
