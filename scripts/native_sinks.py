#!/usr/bin/env python3
"""
native_sinks.py — native-code capability and sink analysis (capa + radare2).

Two passes:
  1. capa (FLARE) over every native PE with the vendored rule set: what the binary can DO,
     with the matching addresses. Filtered to the capabilities that matter for a Windows
     app audit rather than for malware triage.
  2. radare2 cross-references: for each dangerous imported API, list the functions that call
     it, and for each interesting string (paths under ProgramData/Temp, pipe names, URLs,
     command lines) list the functions that reference it. Where a function both references a
     user-writable path AND calls a dangerous API, that function is named as a taint candidate
     — that intersection is where the LPE lives.

Usage:  native_sinks.py --loot loot/<name> [--top 12] [--no-capa] [--no-r2]
Writes: <loot>/native.json, <loot>/native.md
"""
import argparse, json, os, re, shutil, subprocess, sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CAPA_RULES = os.path.join(HERE, 'vendor', 'capa-rules')
CAPA_SIGS = os.path.join(HERE, 'vendor', 'capa-sigs')

HOT_API = re.compile(r'(?i)^(CreateProcess|ShellExecute|WinExec|_?w?system|_w?popen|'
                     r'LoadLibrary|SetDllDirectory|CreateService|ChangeServiceConfig|'
                     r'OpenSCManager|StartService|SetNamedSecurityInfo|SetSecurityInfo|'
                     r'SetEntriesInAcl|InitializeSecurityDescriptor|SetSecurityDescriptorDacl|'
                     r'CreateNamedPipe|ImpersonateNamedPipeClient|ConnectNamedPipe|'
                     r'CreateFileMapping|DeviceIoControl|MoveFileEx|CopyFile|DeleteFile|'
                     r'CreateSymbolicLink|ReplaceFile|RegSetValue|RegCreateKey|'
                     r'WriteProcessMemory|VirtualAllocEx|CreateRemoteThread|'
                     r'AdjustTokenPrivileges|DuplicateToken|CreateProcessAsUser|'
                     r'CreateProcessWithLogon|LogonUser|URLDownloadToFile|WinHttpSendRequest|'
                     r'InternetOpenUrl|HttpSendRequest|WinVerifyTrust|CryptVerify)')

INTERESTING_STR = re.compile(r'(?i)(\\\\\.\\pipe\\|programdata|\\users\\public|\\temp\\|'
                             r'%temp%|appdata|http://|https://|cmd(\.exe)?\s+/c|powershell|'
                             r'rundll32|\.dll$|--[a-z-]{3,30}|/[a-z]{3,20}:|sddl|D:\(A;)')
WRITABLE_STR = re.compile(r'(?i)(programdata|\\users\\public|\\temp\\|%temp%|appdata|'
                          r'\\public\\|c:\\windows\\temp)')

CAPA_INTEREST = re.compile(r'(?i)(execute|command|shell|process|service|token|privilege|'
                           r'impersonat|registry|file (?:write|delete|move|copy)|acl|'
                           r'security descriptor|named pipe|rpc|com |load .*library|'
                           r'inject|memory|network|http|download|certificate|crypt|'
                           r'self-delete|persistence|scheduled task|driver|ioctl)')


def sh(cmd, timeout=600):
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout.decode('utf-8', 'replace'), p.stderr.decode('utf-8', 'replace')
    except Exception as e:
        return 1, '', str(e)


def run_capa(path, capa_bin):
    cmd = [capa_bin, '-j', '-q']
    if os.path.isdir(CAPA_RULES):
        cmd += ['-r', CAPA_RULES]
    if os.path.isdir(CAPA_SIGS):
        cmd += ['-s', CAPA_SIGS]
    cmd.append(path)
    rc, out, err = sh(cmd, timeout=420)
    if rc != 0 or not out.strip().startswith('{'):
        return None, (err or out)[-300:]
    try:
        d = json.loads(out)
    except Exception as e:
        return None, str(e)
    caps = []
    for name, rule in (d.get('rules') or {}).items():
        meta = rule.get('meta', {})
        ns = meta.get('namespace', '')
        addrs = []
        for m in (rule.get('matches') or [])[:12]:
            try:
                addrs.append(hex(m[0].get('value')))
            except Exception:
                pass
        caps.append({'rule': name, 'namespace': ns,
                     'attack': [x.get('id') for x in (meta.get('att&ck') or []) if isinstance(x, dict)],
                     'addresses': addrs,
                     'interesting': bool(CAPA_INTEREST.search(name + ' ' + ns))})
    return caps, None


def _r2(path, cmd, timeout=900):
    rc, out, err = sh(['r2', '-2', '-q', '-e', 'scr.color=0', '-c', cmd, path], timeout=timeout)
    return out if rc == 0 else ''


def r2_xrefs(path, max_apis=28, max_strings=70):
    """Import call sites and string references, attributed to the containing function.

    Two r2 passes: a cheap symbol/string listing, then one analysed session that resolves
    xrefs for the hot imports and the interesting strings only. The intersection of the two
    — a function that both touches a user-writable path and calls a dangerous API — is the
    thing worth opening a decompiler for.
    """
    res = {'callers': {}, 'strrefs': {}, 'fn_strings': {}, 'fn_apis': {}}
    if not shutil.which('r2'):
        return res
    # pass 1: imports + strings, no analysis
    listing = _r2(path, 'is; izzj', timeout=300)
    flags = []
    for line in listing.splitlines():
        # `is` row: <n> <paddr> <vaddr> <bind> <type> <size> <lib> imp.<Name>
        parts = line.split()
        if len(parts) < 3 or not parts[-1].startswith('imp.'):
            continue
        name = parts[-1][4:]
        lib = parts[-2] if len(parts) >= 2 else ''
        if not HOT_API.match(name):
            continue
        flag = f'sym.imp.{lib}_{name}' if lib and lib.lower().endswith(('.dll', '.drv')) else f'sym.imp.{name}'
        flags.append((name, flag))
    seenapi = set()
    flags = [f for f in flags if not (f[1] in seenapi or seenapi.add(f[1]))][:max_apis]
    strings = []
    mjson = re.search(r'\[.*\]\s*$', listing, re.S)
    if mjson:
        try:
            for row in json.loads(mjson.group(0)):
                sv = row.get('string', '')
                if INTERESTING_STR.search(sv) and 5 < len(sv) < 200:
                    strings.append((row.get('vaddr'), sv))
        except Exception:
            pass
    strings = strings[:max_strings]
    if not flags and not strings:
        return res
    # pass 2: one analysed session
    parts = ['aaa']
    for api, flag in flags:
        parts.append(f'?e MARKAPI {api}')
        parts.append(f'axtj @ {flag}')
    for va, sv in strings:
        parts.append(f'?e MARKSTR {va}')
        parts.append(f'axtj @ {va}')
    out = _r2(path, '; '.join(parts), timeout=1200)
    cur_kind = cur_key = None
    svmap = {va: sv for va, sv in strings}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith('MARKAPI '):
            cur_kind, cur_key = 'api', line.split(' ', 1)[1]
            continue
        if line.startswith('MARKSTR '):
            cur_kind, cur_key = 'str', int(line.split(' ', 1)[1])
            continue
        if not line.startswith('['):
            continue
        try:
            arr = json.loads(line)
        except Exception:
            continue
        for row in arr:
            fn = row.get('fcn_name') or (row.get('name') or '').split('+')[0] or hex(row.get('from', 0))
            if cur_kind == 'api':
                res['callers'].setdefault(cur_key, []).append(fn)
                res['fn_apis'].setdefault(fn, set()).add(cur_key)
            elif cur_kind == 'str':
                sv = svmap.get(cur_key, '')
                res['strrefs'].setdefault(fn, []).append(sv)
                res['fn_strings'].setdefault(fn, set()).add(sv)
    res['callers'] = {k: sorted(set(v))[:12] for k, v in res['callers'].items()}
    res['fn_apis'] = {k: sorted(v) for k, v in res['fn_apis'].items()}
    res['fn_strings'] = {k: sorted(v)[:12] for k, v in res['fn_strings'].items()}
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--loot', required=True)
    ap.add_argument('--top', type=int, default=12)
    ap.add_argument('--no-capa', action='store_true')
    ap.add_argument('--no-r2', action='store_true')
    a = ap.parse_args()
    tri = json.load(open(os.path.join(a.loot, 'pe_triage.json')))
    man = {f['path']: f for f in json.load(open(os.path.join(a.loot, 'unwrap.json')))['files']}

    # pick the highest-value binaries: privileged, service-ish, driver, large native
    def rank(b):
        s = b.get('size', 0) / 1e6
        m = b.get('manifest') or {}
        if m.get('requestedExecutionLevel', 'asInvoker') != 'asInvoker':
            s += 50
        if b.get('is_driver'):
            s += 60
        caps = b.get('capabilities') or {}
        s += 12 * len({'service', 'token', 'security', 'ipc'} & set(caps))
        s += 6 * len({'process', 'load', 'registry', 'driver'} & set(caps))
        if b.get('is_dotnet'):
            s -= 40           # managed code is handled by dotnet_il.py
        return -s

    cands = [b for b in tri['binaries'] if b.get('ok')]
    cands.sort(key=rank)
    cands = cands[:a.top]

    capa_bin = os.path.join(HERE, '.venv', 'bin', 'capa')
    if not os.path.isfile(capa_bin):
        capa_bin = shutil.which('capa')
    out = {'analysed': [], 'capa_available': bool(capa_bin) and not a.no_capa,
           'r2_available': bool(shutil.which('r2')) and not a.no_r2}
    for b in cands:
        p = man.get(b['path'], {}).get('abs')
        if not p or not os.path.isfile(p):
            continue
        row = {'path': b['path'], 'arch': b.get('arch'), 'driver': b.get('is_driver'),
               'capa': [], 'capa_error': None, 'callers': {}, 'taint_candidates': []}
        if out['capa_available']:
            caps, err = run_capa(p, capa_bin)
            if caps is None:
                row['capa_error'] = err
            else:
                row['capa'] = [c for c in caps if c['interesting']][:80]
        if out['r2_available']:
            x = r2_xrefs(p)
            row['callers'] = x.get('callers') or {}
            row['writable_path_strings'] = sorted({s for ss in (x.get('strrefs') or {}).values()
                                                   for s in ss if WRITABLE_STR.search(s)})[:40]
            # the real signal: ONE function that both touches a writable path and calls a sink
            fn_apis, fn_strs = x.get('fn_apis') or {}, x.get('fn_strings') or {}
            for fn, apis in fn_apis.items():
                strs = [s for s in fn_strs.get(fn, []) if WRITABLE_STR.search(s)]
                if strs:
                    row['taint_candidates'].append(
                        {'function': fn, 'apis': apis, 'writable_strings': strs[:6]})
            row['taint_candidates'] = row['taint_candidates'][:25]
            row['interesting_functions'] = sorted(
                set(fn_apis) | set(fn_strs))[:40]
        out['analysed'].append(row)

    json.dump(out, open(os.path.join(a.loot, 'native.json'), 'w'), indent=1)
    L = ['# Native capability & sink analysis', '',
         f"- binaries analysed: **{len(out['analysed'])}** (highest-privilege first)",
         f"- capa: {'yes' if out['capa_available'] else 'NOT AVAILABLE — provision.sh --tier analysis'}"
         f" · radare2: {'yes' if out['r2_available'] else 'NOT AVAILABLE'}", '']
    for r in out['analysed']:
        L += [f"## `{r['path']}` ({r['arch']}{', DRIVER' if r['driver'] else ''})", '']
        if r['capa_error']:
            L.append(f"_capa: {r['capa_error']}_")
        if r['capa']:
            L.append('**capabilities:**')
            for c in r['capa'][:30]:
                L.append(f"- {c['rule']}  _{c['namespace']}_  {', '.join(c['addresses'][:4])}")
        if r.get('callers'):
            L += ['', '**dangerous API call sites:**']
            for api, fns in sorted(r['callers'].items()):
                L.append(f"- `{api}` called from: {', '.join(fns[:8])}")
        if r.get('writable_path_strings'):
            L += ['', '**user-writable paths referenced:**']
            for s in r['writable_path_strings'][:20]:
                L.append(f'- `{s}`')
        if r.get('taint_candidates'):
            L += ['', '**INTERSECTION — one function touches a user-writable path AND a dangerous API:**']
            for t in r['taint_candidates']:
                L.append(f"- `{t['function']}` calls {', '.join('`'+x+'`' for x in t['apis'])}"
                         f"  \n  referencing: {', '.join('`'+s+'`' for s in t['writable_strings'])}")
            L.append('')
            L.append('> Open these functions in Ghidra/IDA and answer one question: does the path '
                     'string reach the API argument? If yes, and the process is privileged, that is '
                     'the finding — write it up with the decompiled snippet.')
        L.append('')
    open(os.path.join(a.loot, 'native.md'), 'w').write('\n'.join(L))
    print(f"[native_sinks] {len(out['analysed'])} binaries analysed")
    print(f'[native_sinks] -> {a.loot}/native.json + native.md')


if __name__ == '__main__':
    main()
