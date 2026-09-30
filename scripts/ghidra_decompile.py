#!/usr/bin/env python3
"""
ghidra_decompile.py — decompile exactly the functions that matter, headless.

`native_sinks.py` names the functions worth reading: the ones that call a dangerous API, and
the ones that both touch a user-writable path AND call a sink. Reading their disassembly is
slow; reading their decompilation is not. This drives Ghidra headless to produce C for only
those functions — no GUI, no full-program decompile, no 20-minute wait.

Usage:
  ghidra_decompile.py --loot loot/<name> --binary "<substring of the path>" [--auto]
  ghidra_decompile.py --loot loot/<name> --binary AcmeSvc.exe --targets "api:CreateProcessW,api:CopyFileW,0x401000"
  --auto  picks the targets from native.json (taint candidates first, then every dangerous-API caller)

Writes: <loot>/decompiled/<binary>/*.c + _index.txt
"""
import argparse, json, os, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HEADLESS_CANDIDATES = [
    '/usr/share/ghidra/support/analyzeHeadless',
    '/opt/ghidra/support/analyzeHeadless',
    os.path.expanduser('~/ghidra/support/analyzeHeadless'),
]


def find_headless():
    for p in HEADLESS_CANDIDATES:
        if os.path.isfile(p):
            return p
    g = shutil.which('analyzeHeadless')
    if g:
        return g
    g = shutil.which('ghidra')
    if g:
        try:
            txt = open(g).read()
            for line in txt.splitlines():
                if 'analyzeHeadless' in line and os.path.isfile(line.strip()):
                    return line.strip()
        except Exception:
            pass
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--loot', required=True)
    ap.add_argument('--binary', required=True, help='substring of the binary path in the loot')
    ap.add_argument('--targets', default='', help='comma list: api:Name | 0xADDR | FunctionName')
    ap.add_argument('--auto', action='store_true', help='derive targets from native.json')
    ap.add_argument('--timeout', type=int, default=2400)
    a = ap.parse_args()

    hl = find_headless()
    if not hl:
        sys.exit('ghidra_decompile: analyzeHeadless not found. Install Ghidra '
                 '(apt install ghidra) or set it on PATH.')

    man = json.load(open(os.path.join(a.loot, 'unwrap.json')))
    match = [f for f in man['files'] if a.binary.lower() in f['path'].lower() and f['kind'] == 'pe']
    if not match:
        sys.exit(f'ghidra_decompile: no PE in the loot matching "{a.binary}"')
    match.sort(key=lambda f: -f['size'])
    tgt = match[0]
    print(f"[ghidra] binary: {tgt['path']} ({tgt['size']//1024} KB)")

    targets = [t for t in a.targets.split(',') if t.strip()]
    if a.auto or not targets:
        np = os.path.join(a.loot, 'native.json')
        if os.path.isfile(np):
            nat = json.load(open(np))
            for r in nat.get('analysed', []):
                if a.binary.lower() not in r['path'].lower():
                    continue
                for t in r.get('taint_candidates', []):
                    fn = t['function'] if isinstance(t, dict) else str(t)
                    targets.append(fn)
                for api in (r.get('callers') or {}):
                    targets.append(f'api:{api}')
                for c in (r.get('capa') or [])[:20]:
                    for addr in c.get('addresses', [])[:2]:
                        targets.append(addr)
        if not targets:
            # nothing flagged: fall back to the classic sinks
            targets = ['api:CreateProcess', 'api:ShellExecute', 'api:LoadLibrary',
                       'api:CopyFile', 'api:MoveFileEx', 'api:CreateNamedPipe',
                       'api:RegSetValue', 'api:SetNamedSecurityInfo', 'api:DeviceIoControl',
                       'api:WinVerifyTrust', 'api:CreateService', 'api:ChangeServiceConfig']
    targets = list(dict.fromkeys(t.strip() for t in targets if t.strip()))[:60]
    print(f'[ghidra] {len(targets)} targets: {", ".join(targets[:8])}'
          + (' …' if len(targets) > 8 else ''))

    outdir = os.path.join(a.loot, 'decompiled', os.path.basename(tgt['path']))
    os.makedirs(outdir, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='wh_ghidra_') as proj:
        cmd = [hl, proj, 'whproj', '-import', tgt['abs'],
               '-scriptPath', os.path.join(HERE, 'ghidra_scripts'),
               '-postScript', 'WHDecompile.java', outdir, ','.join(targets),
               '-deleteProject', '-analysisTimeoutPerFile', str(max(300, a.timeout - 120))]
        print('[ghidra] running headless analysis (this is the slow part)…')
        try:
            p = subprocess.run(cmd, capture_output=True, timeout=a.timeout)
            out = (p.stdout + p.stderr).decode('utf-8', 'replace')
        except subprocess.TimeoutExpired:
            sys.exit(f'[ghidra] timed out after {a.timeout}s — raise --timeout or pick fewer targets')
    for line in out.splitlines():
        if 'WHDecompile' in line or 'ERROR' in line or 'Exception' in line:
            print('   ' + line.strip()[:200])

    files = sorted(f for f in os.listdir(outdir) if f.endswith('.c'))
    print(f'[ghidra] {len(files)} functions decompiled -> {outdir}')
    if files:
        L = [f'# Decompiled functions — {os.path.basename(tgt["path"])}', '',
             f'- source: `{tgt["path"]}`  sha256 `{tgt["sha256"][:16]}`',
             f'- targets requested: {", ".join(targets[:20])}',
             f'- functions written: **{len(files)}**', '',
             '> Read each one for a single question: **does data a lower-privileged actor controls',
             '> reach the dangerous argument?** A path from argv, a pipe read, a registry value, a',
             '> file under ProgramData, a network response. If yes, that is the finding and this',
             '> file is the root-cause evidence for the report.', '', '## Files', '']
        for f in files:
            L.append(f'- `decompiled/{os.path.basename(outdir)}/{f}`')
        open(os.path.join(a.loot, 'decompiled', 'README.md'), 'w').write('\n'.join(L))
        print(f'[ghidra] index -> {a.loot}/decompiled/README.md')


if __name__ == '__main__':
    main()
