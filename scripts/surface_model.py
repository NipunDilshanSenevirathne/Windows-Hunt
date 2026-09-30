#!/usr/bin/env python3
"""
surface_model.py — reconstruct WHAT THE APP EXPOSES, and AT WHAT PRIVILEGE.

Windows bugs are privilege-boundary bugs. A finding is only a finding if code on one side of
a boundary can make code on the other side do something. So before hunting, build the model:
every boundary this product creates, who sits on each side, and what crosses it.

Extracted surfaces:
  services + their accounts      scheduled tasks              COM/DCOM classes & AppIDs
  named pipes                    RPC/ALPC interfaces          localhost listeners (the
  URI protocol handlers          file associations            DNS-rebinding class)
  update/telemetry endpoints     cleartext HTTP endpoints     plugin/extension load dirs
  install paths by privilege     registry autoruns            firewall/cert installation
  Electron/CEF/WebView2 hosts    embedded interpreters        credential stores

Sources: MSI tables (ServiceInstall/Class/ProgId/Extension/Verb/Registry/Directory/
CustomAction), .reg files, Inno/NSIS scripts, task XML, app manifests, config/json/xml,
and PE string + import evidence. Every row carries its evidence path so a triager can check it.

Usage:  surface_model.py --loot loot/<name> [--max-strings-mb 64]
Writes: <loot>/surface.json, <loot>/surface.md
"""
import argparse, json, os, re, subprocess, sys
from collections import defaultdict

TEXTY = {'.txt', '.xml', '.json', '.config', '.ini', '.reg', '.ps1', '.bat', '.cmd', '.vbs',
         '.js', '.ts', '.yml', '.yaml', '.toml', '.manifest', '.rdp', '.inf', '.iss', '.nsi',
         '.html', '.htm', '.css', '.sql', '.md', '.plist', '.properties', '.env', '.conf'}

PRIV_PATHS = [
    (r'(?i)%?ProgramFiles(\(x86\))?%?|\[ProgramFiles', 'ProgramFiles', 'admin-write-only (good)'),
    (r'(?i)%?ProgramData%?|\[CommonAppDataFolder', 'ProgramData', 'ROOT WRITABLE BY USERS BY DEFAULT '
     '— any SYSTEM process reading code/config here is an LPE candidate'),
    (r'(?i)%?PUBLIC%?|\[CommonDocuments', 'Public', 'user-writable'),
    (r'(?i)%?SystemRoot%?|\[SystemFolder|\[WindowsFolder|C:\\Windows', 'Windows', 'admin-write-only'),
    (r'(?i)%?APPDATA%?|\[AppDataFolder|\[LocalAppDataFolder', 'AppData', 'per-user'),
    (r'(?i)C:\\Temp|\[TempFolder|%TEMP%', 'Temp', 'user-writable, race-prone'),
]

RX = {
    'pipe':      re.compile(r'(?i)\\\\[.?]\\pipe\\([A-Za-z0-9_.\-{}\\]{2,80})'),
    'pipe_bare': re.compile(r'(?i)\bpipe\\([A-Za-z0-9_.\-{}]{3,60})'),
    'url':       re.compile(r'(?i)\b((?:https?|wss?|ftp)://[A-Za-z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{4,200})'),
    'localhost': re.compile(r'(?i)\b((?:https?|wss?)://(?:127\.0\.0\.1|localhost|\[::1\]|0\.0\.0\.0)(?::(\d{2,5}))?[^\s"\'<>]{0,80})'),
    'bindport':  re.compile(r'(?i)(?:127\.0\.0\.1|localhost|0\.0\.0\.0)[:\s]+(\d{2,5})'),
    'clsid':     re.compile(r'\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}'),
    'uri':       re.compile(r'(?i)(?:^|["\'\s=>])([a-z][a-z0-9+.\-]{2,24})://(?![/\\])'),
    'regrun':    re.compile(r'(?i)(SOFTWARE\\+Microsoft\\+Windows\\+CurrentVersion\\+Run[A-Za-z]*)'),
    'regkey':    re.compile(r'(?i)\b(HKEY_[A-Z_]+|HKLM|HKCU|HKCR)\\+([A-Za-z0-9_\\.\- {}]{4,120})'),
    'sccreate':  re.compile(r'(?i)\bsc(?:\.exe)?\s+(?:\\\\\S+\s+)?create\s+("?[\w.\- ]{1,64}"?)'),
    'schtasks':  re.compile(r'(?i)\bschtasks(?:\.exe)?[^\n"]{0,200}'),
    'cmdexec':   re.compile(r'(?i)\b(cmd(?:\.exe)?\s+/c|powershell(?:\.exe)?\s+-|wscript|cscript|rundll32|regsvr32|mshta|certutil|bitsadmin|msiexec\s+/i)\b'),
    'sddl':      re.compile(r'\b([DSO]:(?:(?:P|AI|AR|NO_ACCESS_CONTROL)?)(?:\([A-Z;()\-\w]{4,80}\)){1,20})'),
    'privname':  re.compile(r'\b(Se[A-Z][A-Za-z]{4,30}Privilege)\b'),
}

# Schemes that belong to the OS, a browser or a spec — never a product's own handler.
SCHEME_DENY = {
    'http', 'https', 'ftp', 'ftps', 'file', 'ws', 'wss', 'data', 'about', 'mailto', 'blob',
    'javascript', 'view-source', 'res', 'urn', 'tel', 'sms', 'callto', 'xmpp', 'news', 'nntp',
    'gopher', 'ldap', 'ldaps', 'dns', 'dict', 'git', 'svn', 'ssh', 'sftp', 'smb', 'nfs',
    'chrome', 'chrome-extension', 'chrome-search', 'chrome-untrusted', 'chrome-devtools',
    'moz-extension', 'moz-icon', 'resource', 'edge-extension', 'extension', 'safari-extension',
    'safari-web-extension', 'devtools', 'webkit', 'filesystem', 'content', 'isolated-app',
    'ms-appx', 'ms-appx-web', 'ms-appdata', 'ms-local-stream', 'ms-settings', 'ms-windows-store',
    'ms-resource', 'ms-browser-extension', 'x-wmapp', 'shell', 'search-ms',
    'vnd', 'xmlns', 'urn', 'uuid', 'tag', 'mid', 'cid', 'crid', 'example', 'localhost',
    'jar', 'jrt', 'classpath', 'bundle', 'osgi', 'maven', 'npm', 'pkg', 'go',
    'application', 'text', 'image', 'audio', 'video', 'multipart', 'message', 'model', 'font',
}

UPDATE_HINT = re.compile(r'(?i)(update|upgrade|version|latest|release|patch|manifest|appcast|'
                         r'feed|download|installer|setup|package|autoupdate|squirrel|sparkle|'
                         r'winsparkle|nupkg|RELEASES)')
TELEMETRY_HINT = re.compile(r'(?i)(telemetry|analytics|sentry|bugsnag|crashpad|crashlytics|'
                            r'mixpanel|amplitude|segment|datadog|newrelic|appinsights|ga\.js|'
                            r'google-analytics|matomo)')

FRAMEWORKS = [
    ('Electron', [r'electron\.asar', r'chrome_100_percent\.pak', r'resources[\\/]app\.asar',
                  r'ELECTRON_RUN_AS_NODE', r'libEGL\.dll.*swiftshader', r'v8_context_snapshot\.bin']),
    ('CEF',      [r'libcef\.dll', r'cef\.pak', r'cefsharp', r'devtools_resources\.pak']),
    ('WebView2', [r'WebView2Loader\.dll', r'msedgewebview2', r'Microsoft\.Web\.WebView2']),
    ('Qt',       [r'Qt5\w+\.dll', r'Qt6\w+\.dll', r'qt\.conf', r'platforms[\\/]qwindows\.dll']),
    ('.NET',     [r'\.runtimeconfig\.json', r'hostfxr\.dll', r'coreclr\.dll', r'mscoree\.dll',
                  r'System\.Private\.CoreLib\.dll']),
    ('Java',     [r'jvm\.dll', r'\.jar$', r'java\.exe']),
    ('Python',   [r'python\d\d\.dll', r'\.pyd$', r'base_library\.zip']),
    ('NodeJS',   [r'node\.exe', r'node_modules[\\/]', r'package\.json']),
    ('Go',       [r'Go build ID', r'go:buildid']),
    ('Rust',     [r'\.cargo[\\/]registry', r'rust_begin_unwind']),
    ('Delphi',   [r'Borland|Embarcadero|TApplication']),
    ('AutoIt',   [r'AutoIt v3']),
    ('InstallShield', [r'InstallShield|ISSetup\.dll|setup\.inx']),
    ('Squirrel', [r'Squirrel\.exe|Update\.exe.*Squirrel|RELEASES$']),
    ('NSIS',     [r'Nullsoft']),
    ('WiX',      [r'\.wixburn|WixBundle|wixstdba']),
]


def read_text(p, cap=8 << 20):
    try:
        if os.path.getsize(p) > cap:
            with open(p, 'rb') as f:
                return f.read(cap).decode('utf-8', 'replace')
        return open(p, 'rb').read().decode('utf-8', 'replace')
    except Exception:
        return ''


def bin_strings(p, minlen=5, cap=64 << 20):
    """ASCII + UTF-16LE strings without shelling out per-file."""
    try:
        sz = os.path.getsize(p)
        with open(p, 'rb') as f:
            data = f.read(min(sz, cap))
    except Exception:
        return ''
    out = []
    # ascii
    cur = bytearray()
    for b in data:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode('latin1'))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append(cur.decode('latin1'))
    # utf-16le
    try:
        u = data.decode('utf-16-le', 'ignore')
        out.extend(re.findall(r'[\x20-\x7e]{%d,}' % minlen, u))
    except Exception:
        pass
    return '\n'.join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--loot', required=True)
    ap.add_argument('--max-strings-mb', type=int, default=64)
    a = ap.parse_args()
    loot = a.loot
    man = json.load(open(os.path.join(loot, 'unwrap.json')))
    triage = {}
    tp = os.path.join(loot, 'pe_triage.json')
    if os.path.isfile(tp):
        for b in json.load(open(tp))['binaries']:
            triage[b['path']] = b

    S = {'services': [], 'tasks': [], 'com': [], 'pipes': [], 'rpc': [], 'listeners': [],
         'uri_handlers': [], 'file_assoc': [], 'urls': [], 'http_cleartext': [],
         'update_endpoints': [], 'telemetry': [], 'registry_writes': [], 'autoruns': [],
         'install_paths': [], 'frameworks': [], 'sddl': [], 'privileges': [], 'exec_shellouts': [],
         'plugin_dirs': [], 'custom_actions': [], 'evidence_files': 0}
    seen = defaultdict(set)

    def push(bucket, value, ev, extra=None):
        key = json.dumps(value, sort_keys=True) if isinstance(value, dict) else str(value)
        if key in seen[bucket]:
            # merge evidence
            for row in S[bucket]:
                if (json.dumps(row.get('v'), sort_keys=True) if isinstance(row.get('v'), dict) else str(row.get('v'))) == key:
                    if ev not in row['evidence'] and len(row['evidence']) < 8:
                        row['evidence'].append(ev)
                    return
            return
        seen[bucket].add(key)
        row = {'v': value, 'evidence': [ev]}
        if extra:
            row.update(extra)
        S[bucket].append(row)

    # ---------- MSI tables: the highest-fidelity source there is -----------------
    for f in man['files']:
        p = f['abs']
        if '_msi_tables' not in p:
            continue
        name = os.path.basename(p)[:-4]
        txt = read_text(p)
        rel = f['path']
        if name == 'ServiceInstall':
            for line in txt.splitlines()[1:]:
                c = line.split('\t')
                if len(c) >= 6:
                    push('services', {'name': c[1] if len(c) > 1 else c[0], 'display': c[2] if len(c) > 2 else '',
                                      'type': c[3] if len(c) > 3 else '', 'start': c[4] if len(c) > 4 else '',
                                      'account': (c[8] if len(c) > 8 else '') or 'LocalSystem (default)',
                                      'args': c[7] if len(c) > 7 else ''}, rel,
                         {'source': 'MSI ServiceInstall'})
        elif name == 'CustomAction':
            for line in txt.splitlines()[1:]:
                c = line.split('\t')
                if len(c) >= 4 and c[0]:
                    try:
                        t = int(c[1])
                    except Exception:
                        continue
                    deferred = bool(t & 0x400)
                    noimp = bool(t & 0x800)
                    base = t & 0x3F
                    kind = {1: 'DLL in Binary table', 2: 'EXE in Binary table', 5: 'JScript',
                            6: 'VBScript', 17: 'DLL installed', 18: 'EXE installed',
                            19: 'error', 21: 'JScript file', 22: 'VBScript file',
                            34: 'EXE with directory', 35: 'set directory', 37: 'JScript text',
                            38: 'VBScript text', 50: 'EXE from property',
                            51: 'set property', 53: 'JScript property', 54: 'VBScript property'}.get(base, f'type{base}')
                    push('custom_actions', {'action': c[0], 'type': t, 'kind': kind,
                                            'deferred': deferred, 'no_impersonate': noimp,
                                            'source': c[2] if len(c) > 2 else '',
                                            'target': (c[3] if len(c) > 3 else '')[:200]}, rel,
                         {'source': 'MSI CustomAction',
                          'risk': 'RUNS AS SYSTEM (deferred + no-impersonate)' if (deferred and noimp) else ''})
        elif name in ('Class', 'AppId', 'ProgId'):
            for g in RX['clsid'].findall(txt):
                push('com', {'guid': g, 'table': name}, rel, {'source': f'MSI {name}'})
        elif name in ('Extension', 'Verb'):
            for line in txt.splitlines()[1:]:
                c = line.split('\t')
                if c and c[0]:
                    push('file_assoc', {'ext_or_verb': c[0], 'row': '\t'.join(c[:5])[:160]}, rel,
                         {'source': f'MSI {name}'})
        elif name == 'Registry':
            for line in txt.splitlines()[1:]:
                c = line.split('\t')
                if len(c) >= 4:
                    push('registry_writes', {'root': c[1] if len(c) > 1 else '', 'key': c[2] if len(c) > 2 else '',
                                             'name': c[3] if len(c) > 3 else '',
                                             'value': (c[4] if len(c) > 4 else '')[:160]}, rel,
                         {'source': 'MSI Registry'})
        elif name in ('LockPermissions', 'MsiLockPermissionsEx'):
            for line in txt.splitlines()[1:]:
                if line.strip():
                    push('sddl', line.strip()[:200], rel, {'source': f'MSI {name}',
                         'note': 'EXPLICIT ACL set by the installer — read it carefully'})
        elif name == 'Directory':
            for pat, label, note in PRIV_PATHS:
                if re.search(pat, txt):
                    push('install_paths', {'class': label, 'note': note}, rel, {'source': 'MSI Directory'})

    # ---------- every file: text + binary string mining -------------------------
    budget = a.max_strings_mb << 20
    used = 0
    for f in man['files']:
        p, rel, ext = f['abs'], f['path'], f['ext']
        if f['size'] == 0:
            continue
        istext = ext in TEXTY or f['kind'] in ('xml',)
        isbin = f['kind'] in ('pe', 'upx', 'nsis', 'inno', 'burn', 'installshield', 'sfx7z',
                              'pyinstaller', 'autoit', 'dotnetbundle')
        if not (istext or isbin):
            continue
        if used > budget:
            break
        txt = read_text(p) if istext else bin_strings(p)
        used += min(f['size'], 64 << 20)
        if not txt:
            continue
        S['evidence_files'] += 1
        low = txt.lower()

        for m in RX['pipe'].finditer(txt):
            push('pipes', m.group(1), rel)
        for m in RX['url'].finditer(txt):
            u = m.group(1).rstrip('".,);')
            if len(u) < 12 or u.startswith(('http://schemas.', 'http://www.w3.org', 'https://www.w3.org',
                                            'http://purl.org', 'http://tempuri.org',
                                            'http://docs.oasis', 'https://schemas.')):
                continue
            push('urls', u, rel)
            if u.lower().startswith('http://') and '127.0.0.1' not in u and 'localhost' not in u:
                push('http_cleartext', u, rel)
            if UPDATE_HINT.search(u):
                push('update_endpoints', u, rel)
            if TELEMETRY_HINT.search(u):
                push('telemetry', u, rel)
        for m in RX['localhost'].finditer(txt):
            push('listeners', {'url': m.group(1)[:120], 'port': m.group(2)}, rel)
        for m in RX['bindport'].finditer(txt):
            push('listeners', {'url': f'bind 127.0.0.1:{m.group(1)}', 'port': m.group(1)}, rel)
        for m in RX['uri'].finditer(txt):
            s = m.group(1).lower()
            # Platform- and browser-internal schemes are not handlers this product registers.
            # `chrome-extension://` in a native-messaging manifest is an ORIGIN, not a URI the
            # product owns — treating it as one manufactures a web->local chain out of nothing.
            if s in SCHEME_DENY:
                continue
            push('uri_handlers', s, rel)
        for m in RX['sccreate'].finditer(txt):
            push('services', {'name': m.group(1).strip('"'), 'source': 'sc create'}, rel)
        for m in RX['schtasks'].finditer(txt):
            push('tasks', m.group(0)[:200], rel)
        for m in RX['regrun'].finditer(txt):
            push('autoruns', m.group(1), rel)
        for m in RX['sddl'].finditer(txt):
            push('sddl', m.group(1)[:160], rel)
        for m in RX['privname'].finditer(txt):
            push('privileges', m.group(1), rel)
        for m in RX['cmdexec'].finditer(txt):
            push('exec_shellouts', m.group(1).lower(), rel)
        if ext == '.reg' or 'Windows Registry Editor' in txt[:200]:
            for m in RX['regkey'].finditer(txt):
                push('registry_writes', {'root': m.group(1), 'key': m.group(2)[:120]}, rel,
                     {'source': '.reg file'})
            if re.search(r'(?i)shell\\+open\\+command', txt):
                # Pair each HKCR class with the command line registered for it. Whether %1 is
                # quoted decides argument injection, and it is knowable right here.
                for m in re.finditer(r'(?i)\[HKEY_CLASSES_ROOT\\+([A-Za-z0-9+.\-]{2,32})\\+shell'
                                     r'\\+open\\+command\]\s*\r?\n\s*@\s*=\s*"(.*?)"\s*$',
                                     txt, re.M):
                    scheme, cmd = m.group(1).lower(), m.group(2)
                    unq = ('%1' in cmd) and not re.search(r'\\?"%1\\?"', cmd)
                    push('uri_handlers', scheme, rel,
                         {'source': 'HKCR .reg', 'command': cmd[:200],
                          'unquoted_arg': unq,
                          'note': 'UNQUOTED %1 — the shell splits on spaces, so a web page can '
                                  'append command-line arguments' if unq else 'quoted %1'})
                for m in re.finditer(r'(?i)\[HKEY_CLASSES_ROOT\\+([A-Za-z0-9+.\-]{2,32})\]', txt):
                    push('uri_handlers', m.group(1).lower(), rel, {'source': 'HKCR .reg'})
        for g in RX['clsid'].findall(txt)[:200]:
            if isbin or ext in ('.reg', '.xml', '.json', '.config'):
                push('com', {'guid': g}, rel)
        if 'rpcrt4' in low or 'RpcServerUseProtseq' in txt or 'NdrServerCall' in txt:
            push('rpc', {'hint': 'RPC server symbols present'}, rel)
        for name, pats in FRAMEWORKS:
            for pt in pats:
                if re.search(pt, rel) or re.search(pt, txt[:400000]):
                    push('frameworks', name, rel)
                    break
        for d in re.findall(r'(?i)([A-Za-z]:\\[^\s"\'<>|*?]{4,120}|%[A-Za-z]+%\\[^\s"\'<>|*?]{2,100})', txt)[:400]:
            for pat, label, note in PRIV_PATHS:
                if re.search(pat, d):
                    push('install_paths', {'class': label, 'path': d[:120], 'note': note}, rel)
                    break
        for d in re.findall(r'(?i)([A-Za-z]:\\[^\s"\'<>|*?]{0,110}(?:plugins?|extensions?|addons?|modules?|scripts?)\\?)', txt)[:80]:
            push('plugin_dirs', d[:120], rel)

    # ---------- PE-derived surface -----------------------------------------------
    for path, b in triage.items():
        caps = b.get('capabilities') or {}
        if 'service' in caps:
            push('services', {'name': f'(hosted by {os.path.basename(path)})', 'evidence': 'service APIs imported'},
                 path, {'source': 'imports', 'apis': caps['service'][:6]})
        if 'ipc' in caps:
            push('rpc', {'hint': 'IPC/COM/RPC APIs imported', 'binary': os.path.basename(path)},
                 path, {'apis': caps['ipc'][:8]})
        if 'net' in caps and b.get('imports'):
            pass
        exports = b.get('exports') or []
        if 'DllRegisterServer' in exports:
            push('com', {'guid': '(self-registering COM server)', 'binary': os.path.basename(path)},
                 path, {'source': 'DllRegisterServer export'})
        if b.get('is_driver'):
            push('rpc', {'hint': 'KERNEL DRIVER — IOCTL surface', 'binary': os.path.basename(path)}, path,
                 {'source': 'driver'})

    S['counts'] = {k: len(v) for k, v in S.items() if isinstance(v, list)}
    json.dump(S, open(os.path.join(loot, 'surface.json'), 'w'), indent=1)

    # ---------- narrative -------------------------------------------------------
    def block(title, key, fmt, limit=40, lead=None):
        rows = S[key]
        L = [f'### {title} ({len(rows)})', '']
        if lead:
            L.append(lead)
            L.append('')
        if not rows:
            L.append('_none found_')
        for r in rows[:limit]:
            L.append('- ' + fmt(r) + f"  \n  _evidence: {', '.join(r['evidence'][:3])}_")
        if len(rows) > limit:
            L.append(f'- … {len(rows)-limit} more in surface.json')
        L.append('')
        return L

    L = ['# Attack-surface model', '',
         f"Files mined: {S['evidence_files']} · frameworks: "
         + (', '.join(sorted({r['v'] for r in S['frameworks']})) or 'none detected'), '',
         '> Every row below is a **boundary**. For each, the question is the same: who is on the',
         '> other side, at what privilege, and what can they make this side do?', '']

    ca_sys = [r for r in S['custom_actions'] if r.get('risk')]
    L += ['## PRIORITY — boundaries that run as SYSTEM', '']
    if ca_sys:
        L.append(f'**{len(ca_sys)} MSI custom action(s) run deferred + no-impersonate = NT AUTHORITY\\SYSTEM.**')
        L.append('Anything they read, execute or write from a user-controllable path is a direct LPE.')
        L.append('')
        for r in ca_sys:
            v = r['v']
            L.append(f"- `{v['action']}` type={v['type']} ({v['kind']}) source=`{v['source']}` target=`{v['target']}`")
        L.append('')
    else:
        L.append('_no deferred/no-impersonate MSI custom actions found (or no MSI in this target)_\n')
    svc = S['services']
    if svc:
        L.append(f'**{len(svc)} service definition(s)** — services default to LocalSystem; their binary path,')
        L.append('working directory and every DLL they load are privilege-boundary assets.\n')

    L += block('Services', 'services', lambda r: f"`{r['v'] if isinstance(r['v'],str) else r['v'].get('name')}` "
               + (f"account={r['v'].get('account')} start={r['v'].get('start')} args=`{r['v'].get('args','')}`" if isinstance(r['v'], dict) else ''))
    L += block('MSI custom actions (all)', 'custom_actions',
               lambda r: f"`{r['v']['action']}` {r['v']['kind']}"
                         + (' **deferred**' if r['v']['deferred'] else '')
                         + (' **no-impersonate→SYSTEM**' if r['v']['no_impersonate'] else '')
                         + f" target=`{r['v']['target'][:120]}`", 30)
    L += block('Scheduled tasks', 'tasks', lambda r: f"`{r['v'][:160]}`", 20)
    L += block('Named pipes', 'pipes', lambda r: f"`\\\\.\\pipe\\{r['v']}`", 40,
               'A pipe created with a NULL DACL, or with an ACE for Everyone/Authenticated Users, is '
               'callable by any logged-on user. If the server end is SYSTEM and takes a path, a command '
               'or a config blob, that is the LPE.')
    L += block('COM / DCOM', 'com', lambda r: f"`{r['v'].get('guid')}` {r['v'].get('binary','')} {r['v'].get('table','')}", 30)
    L += block('RPC / kernel / IPC symbols', 'rpc', lambda r: f"{r['v'].get('hint')} {r['v'].get('binary','')}"
               + (f" — {', '.join(r.get('apis',[])[:5])}" if r.get('apis') else ''), 25)
    L += block('Localhost listeners', 'listeners', lambda r: f"`{r['v'].get('url')}` port={r['v'].get('port')}", 30,
               'A 127.0.0.1 HTTP/WS server is reachable from **any web page the user visits** unless it '
               'checks Origin AND authenticates. This is the single most under-tested Windows-app class.')
    L += block('URI protocol handlers', 'uri_handlers',
               lambda r: f"`{r['v']}://`"
                         + (f" → `{r['command']}`" if r.get('command') else '')
                         + ('  **UNQUOTED %1 — argument injection**' if r.get('unquoted_arg') else ''), 40,
               'Each handler is remote attack surface: a web page can navigate to it. Check how the '
               'argument reaches the process — `%1` unquoted in shell\\open\\command is argument injection.')
    L += block('File associations', 'file_assoc', lambda r: f"`{r['v'].get('ext_or_verb')}`", 25)
    L += block('Update endpoints', 'update_endpoints', lambda r: f"`{r['v']}`", 30,
               'The update channel is the highest-impact surface in any desktop app: it ends in code '
               'execution by design. Transport, signature verification and rollback all have to hold.')
    L += block('Cleartext HTTP', 'http_cleartext', lambda r: f"`{r['v']}`", 30)
    L += block('Registry writes', 'registry_writes', lambda r: f"`{r['v'].get('root','')}\\{r['v'].get('key','')}` "
               f"{r['v'].get('name','')} = `{str(r['v'].get('value',''))[:80]}`", 30)
    L += block('Autoruns', 'autoruns', lambda r: f"`{r['v']}`", 12)
    L += block('Explicit ACLs / SDDL', 'sddl', lambda r: f"`{r['v']}`", 25,
               'Decode every one. `A;;GA;;;WD` = GENERIC_ALL to Everyone. `A;;FA;;;BU` = full access '
               'to Builtin\\Users. On a SYSTEM-owned object that is the whole finding.')
    L += block('Privileges referenced', 'privileges', lambda r: f"`{r['v']}`", 20)
    L += block('Shell-out primitives', 'exec_shellouts', lambda r: f"`{r['v']}`", 15)
    L += block('Plugin / extension directories', 'plugin_dirs', lambda r: f"`{r['v']}`", 20,
               'If a privileged process enumerates and loads from a directory users can write to, '
               'that is code execution at that privilege.')
    L += block('Install paths by privilege class', 'install_paths',
               lambda r: f"**{r['v'].get('class')}** `{r['v'].get('path','')}` — {r['v'].get('note','')}", 25)
    L += block('Telemetry', 'telemetry', lambda r: f"`{r['v']}`", 15)

    L += ['## Next', '', '```',
          'scripts/dll_hijack.py   --loot <loot>   # phantom/side-load candidates, privilege-ranked',
          'scripts/dotnet_il.py    --loot <loot>   # IL sink analysis on every managed assembly',
          'scripts/electron_audit.py --loot <loot> # if Electron/CEF/WebView2 above',
          'scripts/secrets_hunt.py --loot <loot>   # credentials with validators',
          'scripts/sbom_cve.py     --loot <loot>   # bundled-component CVE exposure',
          '```']
    open(os.path.join(loot, 'surface.md'), 'w').write('\n'.join(L))
    print(f"[surface_model] {S['counts']}")
    print(f"[surface_model] -> {loot}/surface.json + surface.md")


if __name__ == '__main__':
    main()
