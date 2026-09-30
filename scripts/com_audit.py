#!/usr/bin/env python3
"""
com_audit.py — COM / DCOM registration analysis.

surface_model.py collects CLSIDs. That is enumeration, not analysis. The bug is never "a COM
class exists" — it is in the *registration*: where the server binary lives, who can activate
it, what identity it runs under, and whether the registration is complete.

What this decides:

  SERVER PATH        InprocServer32 / LocalServer32 / InprocHandler32. A server path under
                     ProgramData / Public / Temp / a writable root is code execution at
                     whatever privilege activates it.
  PHANTOM CLSID      a class the product's code activates but nothing registers. If the key
                     it would be read from is user-writable, that is a hijack.
  ELEVATION          `Elevation\\Enabled=1` + a LocalizedString makes an object activatable
                     through the COM elevation moniker. Read what it then does with the
                     caller's arguments.
  RUNAS IDENTITY     AppID `RunAs` = `Interactive User` / `LocalSystem` / a named account.
                     LocalSystem plus a permissive LaunchPermission is the classic DCOM LPE.
  ACTIVATION ACL     AppID `LaunchPermission` / `AccessPermission` binary SD or SDDL granting
                     Everyone / Users / Authenticated Users.
  APARTMENT          `ThreadingModel=Both/Free` on an in-proc server that is not thread safe.
  SURROGATE          `DllSurrogate` hosts an in-proc DLL in dllhost.exe — often as a different
                     identity than the caller expects.

Sources: shipped `.reg` files, MSI `Class` / `ProgId` / `AppId` / `Registry` tables, TypeLibs,
`DllRegisterServer` exports, and the CLSIDs referenced from each binary's strings (which tells
you who ACTIVATES what).

Usage:  com_audit.py --loot loot/<name>
Writes: <loot>/com.json, <loot>/com.md
"""
import argparse, json, os, re
from collections import defaultdict

GUID = r'\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}'
WRITABLE = re.compile(r'(?i)(programdata|\\users\\public|\\public\\|\\temp\\|%temp%|'
                      r'appdata|localappdata|\\users\\[^\\]+\\)')
SYSDIR = re.compile(r'(?i)(system32|syswow64|program files)')

# SDDL principals that should never appear in a Launch/Access permission on a SYSTEM-hosted server
LOW_PRINCIPALS = {
    'WD': 'Everyone', 'AU': 'Authenticated Users', 'BU': 'Builtin\\Users',
    'IU': 'Interactive Users', 'AN': 'Anonymous', 'WR': 'Write Restricted',
    'S-1-1-0': 'Everyone', 'S-1-5-32-545': 'Builtin\\Users', 'S-1-5-11': 'Authenticated Users',
}


def read(p, cap=8 << 20):
    try:
        return open(p, 'rb').read(cap).decode('utf-8', 'replace')
    except Exception:
        return ''


def bin_strings(p, cap=32 << 20):
    try:
        d = open(p, 'rb').read(cap)
    except Exception:
        return ''
    out = b'\n'.join(re.findall(rb'[\x20-\x7e]{4,}', d)).decode('latin1')
    try:
        out += '\n' + '\n'.join(re.findall(r'[\x20-\x7e]{4,}', d.decode('utf-16-le', 'ignore')))
    except Exception:
        pass
    return out


def parse_reg(txt, rel, reg):
    """Walk a .reg file into {clsid: {...}} plus AppID rows."""
    cur, vals = None, {}
    blocks = re.split(r'(?m)^\[', txt)
    for b in blocks[1:]:
        nl = b.find(']')
        if nl < 0:
            continue
        key, body = b[:nl], b[nl + 1:]
        kl = key.lower()
        g = re.search(GUID, key)
        if not g:
            continue
        guid = g.group(0).upper()
        e = reg.setdefault(guid, {'guid': guid, 'evidence': set(), 'servers': {}, 'appid': {},
                                  'names': set(), 'progids': set(), 'elevation': {},
                                  'surrogate': None, 'threading': None, 'treatas': None})
        e['evidence'].add(rel)
        default = re.search(r'(?m)^@\s*=\s*"(.*?)"\s*$', body)
        named = dict(re.findall(r'(?m)^"([^"]+)"\s*=\s*"(.*?)"\s*$', body))
        hexv = dict(re.findall(r'(?m)^"([^"]+)"\s*=\s*hex(?:\(\d\))?:([0-9a-fA-F,\\\s]+)', body))
        for srv in ('inprocserver32', 'localserver32', 'inprochandler32', 'inprocserverx86'):
            if kl.endswith('\\' + srv):
                path = (default.group(1) if default else '') or named.get('', '')
                e['servers'][srv] = {'path': path.replace('\\\\', '\\'),
                                     'threading': named.get('ThreadingModel')}
                if named.get('ThreadingModel'):
                    e['threading'] = named['ThreadingModel']
        if kl.endswith('\\elevation'):
            e['elevation'] = {k: v for k, v in named.items()}
            m = re.search(r'(?m)^"Enabled"\s*=\s*dword:0*([0-9a-fA-F]+)', body)
            if m:
                e['elevation']['Enabled'] = int(m.group(1), 16)
        if kl.endswith('\\progid') or kl.endswith('\\versionindependentprogid'):
            if default:
                e['progids'].add(default.group(1))
        if kl.endswith('\\treatas'):
            e['treatas'] = default.group(1) if default else None
        if '\\appid\\' in kl or kl.endswith('\\appid'):
            for k, v in named.items():
                e['appid'][k] = v
            if 'RunAs' in named:
                e['appid']['RunAs'] = named['RunAs']
            if 'DllSurrogate' in named:
                e['surrogate'] = named['DllSurrogate'] or '(default dllhost.exe)'
            for k in ('LaunchPermission', 'AccessPermission'):
                if k in hexv:
                    e['appid'][k + '_hex'] = re.sub(r'[\s\\]', '', hexv[k])[:400]
        if default and re.search(r'(?i)\\clsid\\' + GUID + r'$', key):
            e['names'].add(default.group(1))
        if 'appid' in named:
            e['appid']['AppID'] = named['appid']
        if 'AppID' in named:
            e['appid']['AppID'] = named['AppID']
    return reg


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--loot', required=True)
    a = ap.parse_args()
    loot = a.loot
    man = json.load(open(os.path.join(loot, 'unwrap.json')))
    tri = {}
    tp = os.path.join(loot, 'pe_triage.json')
    if os.path.isfile(tp):
        tri = {b['path']: b for b in json.load(open(tp))['binaries'] if b.get('ok')}

    reg = {}
    activators = defaultdict(set)      # guid -> binaries whose strings reference it
    self_reg = []                      # binaries exporting DllRegisterServer
    typelibs = []

    for f in man['files']:
        p, rel, ext = f['abs'], f['path'], f['ext']
        if f['size'] == 0:
            continue
        if ext == '.reg' or (ext in ('.txt',) and '_msi_tables' in rel):
            txt = read(p)
            if ext == '.reg' or 'Registry' in os.path.basename(rel) or 'Class' in os.path.basename(rel) \
               or 'AppId' in os.path.basename(rel):
                parse_reg(txt, rel, reg)
                # MSI Registry table rows: root \t key \t name \t value
                if '_msi_tables' in rel:
                    for line in txt.splitlines():
                        c = line.split('\t')
                        if len(c) >= 4 and re.search(GUID, ' '.join(c)):
                            g = re.search(GUID, ' '.join(c)).group(0).upper()
                            e = reg.setdefault(g, {'guid': g, 'evidence': set(), 'servers': {},
                                                   'appid': {}, 'names': set(), 'progids': set(),
                                                   'elevation': {}, 'surrogate': None,
                                                   'threading': None, 'treatas': None})
                            e['evidence'].add(rel)
                            kk = (c[2] if len(c) > 2 else '').lower()
                            vv = c[4] if len(c) > 4 else ''
                            for srv in ('inprocserver32', 'localserver32', 'inprochandler32'):
                                if srv in kk:
                                    e['servers'][srv] = {'path': vv, 'threading': None}
                            if 'elevation' in kk:
                                e['elevation']['Enabled'] = 1
                            if 'appid' in kk:
                                e['appid']['AppID'] = vv
            continue
        if ext in ('.tlb', '.olb'):
            typelibs.append(rel)
            continue
        if f['kind'] == 'pe':
            b = tri.get(rel, {})
            if 'DllRegisterServer' in (b.get('exports') or []):
                self_reg.append(rel)
            caps = b.get('capabilities') or {}
            if 'ipc' in caps or ext in ('.exe', '.dll', '.ocx'):
                s = bin_strings(p)
                for g in set(re.findall(GUID, s)):
                    activators[g.upper()].add(rel)

    # --- privilege of each activator -------------------------------------------
    def priv_of(rel):
        b = tri.get(rel, {})
        m = b.get('manifest') or {}
        if m.get('requestedExecutionLevel') in ('requireAdministrator', 'highestAvailable'):
            return 'elevated (manifest)'
        if 'service' in (b.get('capabilities') or {}):
            return 'service (likely SYSTEM)'
        if re.search(r'(?i)(service|svc|updater|agent|helper|elev|broker|host)', os.path.basename(rel)):
            return 'probably privileged (name)'
        return 'user'

    shipped = {os.path.basename(f['path']).lower() for f in man['files']}
    findings = []
    for g, e in reg.items():
        issues = []
        for srv, d in (e['servers'] or {}).items():
            path = d.get('path') or ''
            if not path:
                continue
            if WRITABLE.search(path):
                issues.append({'kind': 'server-in-writable-path', 'severity': 9,
                               'detail': f"{srv} = `{path}` is under a location standard users can write",
                               'why': 'whoever activates this class loads attacker-controlled code at '
                                      'that process privilege'})
            elif not SYSDIR.search(path) and re.match(r'(?i)^[a-z]:\\', path):
                issues.append({'kind': 'server-outside-protected-path', 'severity': 4,
                               'detail': f"{srv} = `{path}`",
                               'why': 'confirm the directory ACL on the host — a non-standard install '
                                      'root frequently inherits a permissive ACE'})
            base = os.path.basename(path.strip('"').split()[0] if path.strip() else '').lower()
            if base and base not in shipped and base.endswith(('.dll', '.exe', '.ocx')):
                issues.append({'kind': 'server-binary-not-shipped', 'severity': 6,
                               'detail': f"{srv} points at `{base}`, which is not in this package",
                               'why': 'either it comes from elsewhere on the host, or the registration '
                                      'is dangling — a dangling CLSID whose key is writable is a hijack'})
        if e['elevation'].get('Enabled'):
            issues.append({'kind': 'com-elevation-enabled', 'severity': 7,
                           'detail': f"Elevation\\Enabled=1 {e['elevation']}",
                           'why': 'activatable through the COM elevation moniker. Read every method: if '
                                  'any takes a path, a command or a URL and acts on it as the elevated '
                                  'identity, that is the finding. (Same-user UAC bypass alone is not a '
                                  'boundary — look for a cross-user or service-account caller.)'})
        runas = (e['appid'] or {}).get('RunAs')
        if runas:
            sev = 8 if re.search(r'(?i)localsystem|nt authority', runas) else 5
            issues.append({'kind': 'appid-runas', 'severity': sev,
                           'detail': f"AppID RunAs = `{runas}`",
                           'why': 'the out-of-process server runs under this identity regardless of who '
                                  'activates it — check the activation ACL next'})
        for k in ('LaunchPermission_hex', 'AccessPermission_hex'):
            if k in (e['appid'] or {}):
                issues.append({'kind': 'appid-explicit-acl', 'severity': 6,
                               'detail': f"{k.replace('_hex','')} is set explicitly (binary SD, {len(e['appid'][k])//2} bytes)",
                               'why': 'decode it on the host: `Get-ItemProperty`/OleView. An ACE for '
                                      'Everyone/Users on a LocalSystem server is a direct LPE'})
        if e['surrogate'] is not None:
            issues.append({'kind': 'dll-surrogate', 'severity': 5,
                           'detail': f"DllSurrogate = `{e['surrogate']}`",
                           'why': 'the in-proc DLL is hosted in dllhost.exe, often under a different '
                                  'identity than the caller assumes'})
        if e['treatas']:
            issues.append({'kind': 'treatas-redirect', 'severity': 4,
                           'detail': f"TreatAs -> {e['treatas']}",
                           'why': 'activation is redirected to another class; follow it'})
        if e['threading'] in ('Both', 'Free') and 'inprocserver32' in e['servers']:
            issues.append({'kind': 'threading-model', 'severity': 2,
                           'detail': f"ThreadingModel={e['threading']}",
                           'why': 'free-threaded in-proc server — only relevant if you find a race'})
        acts = sorted(activators.get(g, []))
        if issues or acts:
            findings.append({'guid': g, 'names': sorted(e['names']), 'progids': sorted(e['progids']),
                             'servers': e['servers'], 'appid': e['appid'],
                             'elevation': e['elevation'], 'surrogate': e['surrogate'],
                             'evidence': sorted(e['evidence'])[:4],
                             'activated_by': [{'binary': x, 'privilege': priv_of(x)} for x in acts[:6]],
                             'issues': issues,
                             'score': max([i['severity'] for i in issues], default=0)})

    # CLSIDs referenced by privileged binaries but never registered in this package
    phantom = []
    for g, bins in activators.items():
        if g in reg:
            continue
        priv = [b for b in bins if priv_of(b) != 'user']
        if priv:
            phantom.append({'guid': g, 'activated_by': sorted(priv)[:5],
                            'note': 'activated by a privileged binary and NOT registered by this '
                                    'package — it either belongs to Windows/another product, or the '
                                    'registration is missing. Check on the host: if the CLSID key does '
                                    'not exist, or exists with a writable ACL, it is hijackable.'})

    findings.sort(key=lambda x: -x['score'])
    out = {'registered': len(reg), 'with_issues': sum(1 for f in findings if f['issues']),
           'phantom_candidates': len(phantom), 'self_registering': self_reg,
           'typelibs': typelibs, 'findings': findings, 'phantom': phantom}
    json.dump(out, open(os.path.join(loot, 'com.json'), 'w'), indent=1)

    hot = [f for f in findings if f['score'] >= 6]
    L = ['# COM / DCOM', '',
         f"- CLSIDs registered by this package: **{len(reg)}**",
         f"- with a registration issue: **{out['with_issues']}** (severity>=6: **{len(hot)}**)",
         f"- CLSIDs a privileged binary activates but nothing here registers: **{len(phantom)}**",
         f"- self-registering servers (DllRegisterServer): {len(self_reg)}", '']
    if hot:
        L += ['## Priority', '']
        for f in hot[:25]:
            nm = ', '.join(f['names'] or f['progids']) or '(unnamed)'
            L += [f"### `{f['guid']}` {nm}", '']
            for i in f['issues']:
                L += [f"- **{i['kind']}** ({i['severity']}/10) — {i['detail']}", f"  - {i['why']}"]
            if f['activated_by']:
                L.append('- activated by: ' + ', '.join(f"`{x['binary']}` _{x['privilege']}_"
                                                        for x in f['activated_by']))
            L.append(f"- evidence: {', '.join('`'+e+'`' for e in f['evidence'])}")
            L.append('')
    L += ['## All registered classes', '', '| score | CLSID | server | RunAs | elevation | activated by |',
          '|---|---|---|---|---|---|']
    for f in findings[:80]:
        srv = next(iter(f['servers'].values()), {}).get('path', '') if f['servers'] else ''
        L.append(f"| {f['score']} | `{f['guid'][:38]}` | `{srv[:50]}` | "
                 f"{(f['appid'] or {}).get('RunAs','')} | {'yes' if f['elevation'].get('Enabled') else ''} | "
                 f"{len(f['activated_by'])} |")
    if phantom:
        L += ['', f'## Unregistered CLSIDs activated by privileged binaries ({len(phantom)})', '',
              'On the host, for each: does `HKCR\\CLSID\\<guid>` exist? If not, the activation fails',
              'silently today and a registration you can create wins. If it exists, check the key ACL',
              'and the server path. `Get-Acl "HKLM:\\SOFTWARE\\Classes\\CLSID\\<guid>"`.', '']
        for p in phantom[:40]:
            L.append(f"- `{p['guid']}` ← {', '.join('`'+b+'`' for b in p['activated_by'])}")
    if self_reg:
        L += ['', '## Self-registering servers', ''] + [f'- `{x}`' for x in self_reg[:20]]
        L.append('')
        L.append('> `regsvr32` on these writes the registration at install time. Read what they write: '
                 '`DllRegisterServer` is ordinary code and frequently sets a permissive key ACL.')
    L += ['', '## Verify on the host', '', '```powershell',
          '# server path, identity and activation ACL for one class',
          '$g = "{...}"',
          'Get-ItemProperty "HKLM:\\SOFTWARE\\Classes\\CLSID\\$g\\InprocServer32","HKLM:\\SOFTWARE\\Classes\\CLSID\\$g\\LocalServer32" -EA 0',
          '$appid = (Get-ItemProperty "HKLM:\\SOFTWARE\\Classes\\CLSID\\$g" -EA 0).AppID',
          'Get-ItemProperty "HKLM:\\SOFTWARE\\Classes\\AppID\\$appid" -EA 0   # RunAs, LaunchPermission',
          '# can a standard user activate it?',
          '$t = [Type]::GetTypeFromCLSID($g); $o = [Activator]::CreateInstance($t)',
          '$o | Get-Member          # then read every method that takes a path/command/URL',
          '```']
    open(os.path.join(loot, 'com.md'), 'w').write('\n'.join(L))
    print(f"[com_audit] {len(reg)} registered, {out['with_issues']} with issues, {len(phantom)} phantom")
    print(f'[com_audit] -> {loot}/com.json + com.md')


if __name__ == '__main__':
    main()
