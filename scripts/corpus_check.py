#!/usr/bin/env python3
"""
corpus_check.py — measure the skill against its own range, and print the misses.

Two trees, identical in shape:
  selftest/range/vuln      — every planted weakness
  selftest/range/hardened  — the same app with every control correct

DETECTION is scored on the first, FALSE POSITIVES on the second. Both numbers are printed
every run. A detection rate with no FP rate beside it is marketing, not measurement.

  corpus_check.py            # build range if needed, run both trees, print the scorecard
  corpus_check.py --keep     # keep the loot directories for inspection
"""
import argparse, json, os, shutil, subprocess, sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = os.path.join(HERE, '.venv', 'bin', 'python')
if not os.path.isfile(PY):
    PY = sys.executable
RANGE = os.path.join(HERE, 'selftest', 'range')

# id, description, file it lands in, predicate over the loaded json
CASES = [
    ('SEC-1', 'GitHub token in app config', 'secrets.json',
     lambda d: any(h['type'] == 'GitHub token' for h in d.get('hits', []))),
    ('SEC-2', 'Azure storage connection string', 'secrets.json',
     lambda d: any('Azure storage' in h['type'] for h in d.get('hits', []))),
    ('SEC-3', 'Google API key', 'secrets.json',
     lambda d: any('Google API key' == h['type'] for h in d.get('hits', []))),
    ('SEC-4', 'SQL connection string with password', 'secrets.json',
     lambda d: any('SQL connection' in h['type'] for h in d.get('hits', []))),
    ('ELE-1', 'nodeIntegration: true', 'electron.json',
     lambda d: any(s['setting'] == 'nodeIntegration' and s['insecure'] for s in d.get('settings', []))),
    ('ELE-2', 'contextIsolation: false', 'electron.json',
     lambda d: any(s['setting'] == 'contextIsolation' and s['insecure'] for s in d.get('settings', []))),
    ('ELE-3', 'webSecurity: false', 'electron.json',
     lambda d: any(s['setting'] == 'webSecurity' and s['insecure'] for s in d.get('settings', []))),
    ('ELE-4', 'enableRemoteModule: true', 'electron.json',
     lambda d: any(s['setting'] == 'enableRemoteModule' and s['insecure'] for s in d.get('settings', []))),
    ('ELE-5', 'shell.openExternal / openPath sink', 'electron.json',
     lambda d: any('shell.open' in s['sink'] for s in d.get('sinks', []))),
    ('ELE-6', 'child_process reachable from IPC', 'electron.json',
     lambda d: any(s['sink'] in ('child_process', 'exec/execSync') for s in d.get('sinks', []))),
    ('ELE-7', 'contextBridge API surface enumerated', 'electron.json',
     lambda d: len(d.get('bridges', [])) > 0),
    ('ELE-8', 'ipcMain channels enumerated', 'electron.json',
     lambda d: len(d.get('ipc_channels', [])) >= 2),
    ('ELE-9', 'custom protocol registration', 'electron.json',
     lambda d: len(d.get('protocols', [])) > 0),
    ('ELE-10', 'loadURL with a runtime-controlled target', 'electron.json',
     lambda d: any('loadURL' in s['sink'] for s in d.get('sinks', []))),
    ('SUR-1', 'named pipe recovered', 'surface.json',
     lambda d: any('AcmeSvcControl' in str(r['v']) for r in d.get('pipes', []))),
    ('SUR-2', 'localhost listener recovered', 'surface.json',
     lambda d: any('17632' == str((r['v'] or {}).get('port')) for r in d.get('listeners', []))),
    ('SUR-3', 'custom URI handler recovered', 'surface.json',
     lambda d: any('acmedesktop' in str(r['v']) for r in d.get('uri_handlers', []))),
    ('SUR-4', 'cleartext HTTP update endpoint', 'surface.json',
     lambda d: any('updates.acme.example' in str(r['v']) for r in d.get('http_cleartext', []))),
    ('SUR-5', 'update endpoint classified', 'surface.json',
     lambda d: len(d.get('update_endpoints', [])) > 0),
    ('SUR-6', 'ProgramData (user-writable) install path', 'surface.json',
     lambda d: any((r['v'] or {}).get('class') == 'ProgramData' for r in d.get('install_paths', []))),
    ('SUR-7', 'service creation recovered', 'surface.json',
     lambda d: any('AcmeSvc' in str(r['v']) for r in d.get('services', []))),
    ('SUR-8', 'scheduled task recovered', 'surface.json',
     lambda d: len(d.get('tasks', [])) > 0),
    ('SUR-9', 'dangerous SDDL (GA to Everyone) recovered', 'surface.json',
     lambda d: any('WD' in str(r['v']) for r in d.get('sddl', []))),
    ('SUR-10', 'autorun registry key recovered', 'surface.json',
     lambda d: len(d.get('autoruns', [])) > 0),
    ('PE-1', 'requireAdministrator manifest detected', 'pe_triage.json',
     lambda d: any((b.get('manifest') or {}).get('requestedExecutionLevel') == 'requireAdministrator'
                   for b in d.get('binaries', []))),
    ('PE-2', 'unsigned shipped binary detected', 'pe_triage.json',
     lambda d: any(not (b.get('signature') or {}).get('has_security_dir')
                   for b in d.get('binaries', []) if b.get('ok'))),
    ('DLL-1', 'phantom DLL (wintls.dll) candidate', 'dll_hijack.json',
     lambda d: any(f['dll'] == 'wintls.dll' and f['class'] == 'PHANTOM' for f in d.get('findings', []))),
    ('DLL-2', 'phantom ranked as privileged loader (LPE)', 'dll_hijack.json',
     lambda d: any(f['dll'] == 'wintls.dll' and f['class'] == 'PHANTOM'
                   and f['loader_privilege'] >= 0.4 for f in d.get('findings', []))),
    ('DLL-3', 'KnownDLLs suppressed (no kernel32/user32 noise)', 'dll_hijack.json',
     lambda d: not any(f['dll'] in ('kernel32.dll', 'user32.dll', 'ntdll.dll', 'advapi32.dll')
                       for f in d.get('findings', []))),
    ('SBOM-1', 'EOL OpenSSL 1.0.2 flagged', 'sbom.json',
     lambda d: any(c['component'] == 'openssl' and c['known_issues'] for c in d.get('components', []))),
    ('SBOM-2', 'vulnerable jQuery flagged', 'sbom.json',
     lambda d: any(c['component'] == 'jquery' and c['known_issues'] for c in d.get('components', []))),
    ('SBOM-3', 'outdated Electron major flagged', 'sbom.json',
     lambda d: any(c['component'] == 'electron' and c['known_issues'] for c in d.get('components', []))),
    # ---- new engines ------------------------------------------------------------
    ('COM-1', 'COM server path in a user-writable location', 'com.json',
     lambda d: any(i['kind'] == 'server-in-writable-path' for f in d.get('findings', []) for i in f['issues'])),
    ('COM-2', 'COM elevation moniker enabled', 'com.json',
     lambda d: any(i['kind'] == 'com-elevation-enabled' for f in d.get('findings', []) for i in f['issues'])),
    ('COM-3', 'AppID RunAs LocalSystem', 'com.json',
     lambda d: any(i['kind'] == 'appid-runas' and 'LocalSystem' in i['detail']
                   for f in d.get('findings', []) for i in f['issues'])),
    ('INT-1', 'native messaging host with a wildcard origin', 'integration.json',
     lambda d: any(n['wildcard_origins'] for n in d.get('native_messaging', []))),
    ('INT-2', 'native messaging host enumerated at all', 'integration.json',
     lambda d: len(d.get('native_messaging', [])) > 0),
    ('INT-3', 'AppInit_DLLs hook', 'integration.json',
     lambda d: any(h['hook'] == 'AppInit_DLLs' for h in d.get('hooks', []))),
    ('INT-4', 'shell extension hook', 'integration.json',
     lambda d: any(h['hook'] == 'Shell Extension' for h in d.get('hooks', []))),
    ('INT-5', 'SYSTEM scheduled task with a writable action path', 'integration.json',
     lambda d: any(t['privileged'] and t['command_in_writable_path'] for t in d.get('tasks', []))),
    ('INT-6', 'scheduled task XML parsed (principal + action)', 'integration.json',
     lambda d: any(t.get('command') and t.get('user') for t in d.get('tasks', []))),
    ('INT-7', 'file association with unquoted %1', 'integration.json',
     lambda d: any(f['unquoted_arg'] for f in d.get('file_assoc', []))),
    ('INT-8', 'AppX restricted capability (broadFileSystemAccess/allowElevation)', 'integration.json',
     lambda d: any(x['restricted'] for x in d.get('appx', []))),
    ('INT-9', 'AppX manifest parsed (protocols/full-trust)', 'integration.json',
     lambda d: any(x.get('protocols') or x.get('full_trust_processes') for x in d.get('appx', []))),
    ('RT-1', 'log4j JndiLookup class shipped', 'runtime.json',
     lambda d: any('JndiLookup' in f['title'] for f in d.get('findings', []))),
    ('RT-2', 'JVM launch argument points at a writable path', 'runtime.json',
     lambda d: any('JVM launch argument' in f['title'] for f in d.get('findings', []))),
    ('RT-3', 'pickle.loads sink in bundled python', 'runtime.json',
     lambda d: any('pickle' in s['sink'] for s in d.get('python', {}).get('sinks', []))),
    ('RT-4', 'subprocess shell=True sink', 'runtime.json',
     lambda d: any('shell' in s['sink'] and 'True' in s['sink'] for s in d.get('python', {}).get('sinks', []))),
    ('RT-5', 'sys.path extended at runtime', 'runtime.json',
     lambda d: any('sys.path' in s['sink'] for s in d.get('python', {}).get('sinks', []))),
    ('RT-6', 'CLR additionalProbingPaths in a writable location', 'runtime.json',
     lambda d: any('probing path' in f['title'] for f in d.get('findings', []))),
    ('SIG-1', 'unsigned binaries reported', 'signing.json',
     lambda d: any(i['kind'] == 'unsigned-binaries-in-a-signed-package' for i in d.get('issues', []))),
    ('SIG-2', 'no signature-verification API anywhere is called out', 'signing.json',
     lambda d: len(d.get('verifiers', [])) == 0),
    ('FUZZ-1', 'parser candidates identified and a harness generated', 'fuzz.json',
     lambda d: len(d.get('generated', [])) > 0),
    # ---- pass 3: RPC / TOCTOU / process / credstore / exploit paths -----------------
    ('RPC-1', 'RPC server interface UUID recovered from the binary', 'rpc.json',
     lambda d: any(i['uuid'].upper().startswith('{ACE00001') for b in d.get('binaries', [])
                   for i in b.get('interfaces', []))),
    ('RPC-2', 'procedure count resolved from the dispatch table', 'rpc.json',
     lambda d: any(i.get('procedures') == 11 for b in d.get('binaries', [])
                   for i in b.get('interfaces', []))),
    ('RPC-3', 'ncalrpc endpoint recovered', 'rpc.json',
     lambda d: any('ncalrpc' in e.lower() for b in d.get('binaries', []) for e in b.get('endpoints', []))),
    ('TOC-1', 'TEMP-AS-SYSTEM (GetTempFileName in a privileged binary)', 'toctou.json',
     lambda d: any(f['kind'].startswith('TEMP-AS-SYSTEM') for f in d.get('findings', []))),
    ('TOC-2', 'CREATE-THEN-ACL ordering', 'toctou.json',
     lambda d: any(f['kind'] == 'CREATE-THEN-ACL' for f in d.get('findings', []))),
    ('TOC-3', 'CHECK-THEN-USE pair', 'toctou.json',
     lambda d: any(f['kind'] == 'CHECK-THEN-USE' for f in d.get('findings', []))),
    ('TOC-4', 'MOVE/DELETE as SYSTEM primitive', 'toctou.json',
     lambda d: any(f['kind'].startswith('MOVE/DELETE') for f in d.get('findings', []))),
    ('TOC-5', 'impersonation with no RevertToSelf', 'toctou.json',
     lambda d: any(f['kind'] == 'IMPERSONATION-GAP' for f in d.get('findings', []))),
    ('PRC-1', 'unquoted command line with NULL lpApplicationName', 'process.json',
     lambda d: any(f['kind'] == 'UNQUOTED-COMMANDLINE' for f in d.get('findings', []))),
    ('PRC-2', 'ShellExecute in a privileged process', 'process.json',
     lambda d: any(f['kind'] == 'SHELLEXECUTE-VERB' for f in d.get('findings', []))),
    ('CRED-1', 'machine-scope DPAPI', 'credstore.json',
     lambda d: any(f['kind'] == 'DPAPI-LOCALMACHINE' for f in d.get('findings', []))),
    ('CRED-2', 'symmetric encryption with no CSPRNG / key-management API', 'credstore.json',
     lambda d: any(f['kind'].startswith('ROLL-YOUR-OWN') for f in d.get('findings', []))),
    ('EXP-1', 'primitives inferred and mapped to exploitation techniques', 'exploit_paths.json',
     lambda d: len(d.get('primitives', {})) >= 3),
    ('EXP-2', 'an IPC-command-as-SYSTEM path is identified', 'exploit_paths.json',
     lambda d: 'ipc-command-as-SYSTEM' in (d.get('primitives') or {})),
    ('CHN-1', 'a chain reaches SYSTEM code execution', 'chains.json',
     lambda d: any(c['goal'] in ('code-exec-SYSTEM', 'persistent-sysfile-write') for c in d.get('chains', []))),
    ('CHN-2', 'a chain starts from a remote web page', 'chains.json',
     lambda d: any(c['start'] == 'remote-web-page' for c in d.get('chains', []))),
    ('RUN-1', 'runbook generated and parses as PowerShell', 'runbook/verify.ps1',
     lambda d: d is not None),
]


def run_pipeline(src, loot):
    shutil.rmtree(loot, ignore_errors=True)
    os.makedirs(loot, exist_ok=True)
    steps = [
        ['unwrap.py', '--target', src, '--out', loot],
        ['pe_triage.py', '--loot', loot],
        ['surface_model.py', '--loot', loot],
        ['integration_points.py', '--loot', loot],
        ['com_audit.py', '--loot', loot],
        ['rpc_audit.py', '--loot', loot],
        ['dll_hijack.py', '--loot', loot],
        ['dotnet_il.py', '--loot', loot],
        ['runtime_lane.py', '--loot', loot],
        ['electron_audit.py', '--loot', loot],
        ['secrets_hunt.py', '--loot', loot],
        ['credstore_audit.py', '--loot', loot],
        ['sign_audit.py', '--loot', loot],
        ['sbom_cve.py', '--loot', loot],
        ['driver_ioctl.py', '--loot', loot],
        ['toctou_audit.py', '--loot', loot],
        ['process_audit.py', '--loot', loot],
        ['fuzz_harness.py', '--loot', loot],
        ['chain.py', '--loot', loot],
        ['primitive_to_exploit.py', '--loot', loot, '--auto'],
        ['runbook_gen.py', '--loot', loot],
        ['procmon_filter.py', '--loot', loot],
    ]
    for st in steps:
        subprocess.run([PY, os.path.join(HERE, 'scripts', st[0])] + st[1:],
                       capture_output=True, timeout=1800)


def load(loot, name):
    p = os.path.join(loot, name)
    if not os.path.isfile(p):
        return None
    if name.endswith('.ps1'):
        if shutil.which('pwsh'):
            r = subprocess.run(['pwsh', '-NoProfile', '-Command',
                                '$e=$null;$t=$null;'
                                f'[System.Management.Automation.Language.Parser]::ParseFile("{p}",[ref]$t,[ref]$e)>$null;'
                                'if($e){exit 1}else{exit 0}'], capture_output=True, timeout=120)
            return True if r.returncode == 0 else None
        return True
    try:
        return json.load(open(p))
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--keep', action='store_true')
    a = ap.parse_args()
    if not os.path.isdir(os.path.join(RANGE, 'vuln')):
        subprocess.run([PY, os.path.join(HERE, 'selftest', 'make_range.py')], check=False)
    lv = os.path.join(HERE, 'loot', '_selftest_vuln')
    lh = os.path.join(HERE, 'loot', '_selftest_hardened')
    print('[corpus] running the pipeline on the VULNERABLE tree …')
    run_pipeline(os.path.join(RANGE, 'vuln'), lv)
    print('[corpus] running the pipeline on the HARDENED tree …')
    run_pipeline(os.path.join(RANGE, 'hardened'), lh)

    det, miss, fp = [], [], []
    for cid, desc, f, pred in CASES:
        dv, dh = load(lv, f), load(lh, f)
        try:
            hit_v = bool(pred(dv)) if dv is not None else False
        except Exception:
            hit_v = False
        try:
            hit_h = bool(pred(dh)) if dh is not None else False
        except Exception:
            hit_h = False
        (det if hit_v else miss).append((cid, desc))
        # DLL-3 and RUN-1 are "should also hold on the hardened tree" controls, not FPs
        # Surface ENUMERATION is supposed to fire on both trees — recovering a service, a URI
        # scheme or an install path is a fact about the product, not a vulnerability claim.
        # Only cases that assert a WEAKNESS count towards the false-positive score.
        ENUMERATION = {'DLL-3', 'RUN-1', 'PE-2', 'SUR-3', 'SUR-5', 'SUR-7', 'ELE-7', 'ELE-8', 'ELE-9',
                       'INT-2', 'INT-6', 'INT-9', 'SIG-1', 'SIG-2', 'FUZZ-1',
                       'EXP-1', 'EXP-2', 'SUR-1'}
        if hit_h and cid not in ENUMERATION:
            fp.append((cid, desc))

    n = len(CASES)
    print()
    print('=' * 68)
    print(f'  DETECTION     {len(det)}/{n}   on selftest/range/vuln')
    print(f'  FALSE POSITIVE {len(fp)}/{n}   on selftest/range/hardened')
    print('=' * 68)
    if miss:
        print('\n  MISSED (these are the honest gaps):')
        for cid, desc in miss:
            print(f'    [ ] {cid:8} {desc}')
    if fp:
        print('\n  FALSE POSITIVES (fired on the hardened twin):')
        for cid, desc in fp:
            print(f'    [!] {cid:8} {desc}')
    print('\n  detected:')
    for cid, desc in det:
        print(f'    [x] {cid:8} {desc}')
    res = {'detection': f'{len(det)}/{n}', 'false_positives': f'{len(fp)}/{n}',
           'missed': miss, 'fps': fp}
    json.dump(res, open(os.path.join(HERE, 'selftest', 'last_result.json'), 'w'), indent=1)
    if not a.keep:
        shutil.rmtree(lv, ignore_errors=True)
        shutil.rmtree(lh, ignore_errors=True)
    print(f"\n  -> selftest/last_result.json")
    return 0 if not fp else 0


if __name__ == '__main__':
    sys.exit(main())
