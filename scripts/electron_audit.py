#!/usr/bin/env python3
"""
electron_audit.py — Electron / CEF / WebView2 / Node-in-desktop audit.

Electron apps are web apps with a Win32 privilege level. The bugs are the web bugs plus:
a renderer that can reach Node, a preload bridge that exposes more than it means to, fuses
left off, a custom protocol that skips the same-origin model, and `shell.openExternal` on a
URL the page controls. This reads the real code out of app.asar (already extracted by
unwrap.py) and grades each control.

Checks: nodeIntegration / nodeIntegrationInWorker / nodeIntegrationInSubFrames,
contextIsolation, sandbox, webSecurity, allowRunningInsecureContent, experimentalFeatures,
enableRemoteModule / @electron/remote, preload exposure surface (contextBridge API shape),
will-navigate / new-window / setWindowOpenHandler allowlists, shell.openExternal sinks,
custom protocol registration, ASAR integrity + fuses, Electron version → known CVEs,
CSP, devtools, and the Node primitives reachable from renderer code.

Usage:  electron_audit.py --loot loot/<name>
Writes: <loot>/electron.json, <loot>/electron.md
"""
import argparse, json, os, re, sys

CHECKS = [
    ('nodeIntegration', r'nodeIntegration\s*:\s*(true|false)', 'true', 10,
     'renderer gets require() — any XSS or attacker-controlled page becomes native code execution'),
    ('nodeIntegrationInWorker', r'nodeIntegrationInWorker\s*:\s*(true|false)', 'true', 9,
     'Node in web workers'),
    ('nodeIntegrationInSubFrames', r'nodeIntegrationInSubFrames\s*:\s*(true|false)', 'true', 9,
     'Node in iframes — a single embedded third-party frame becomes RCE'),
    ('contextIsolation', r'contextIsolation\s*:\s*(true|false)', 'false', 9,
     'preload and page share a JS context — prototype pollution in the page reaches the bridge'),
    ('sandbox', r'\bsandbox\s*:\s*(true|false)', 'false', 6,
     'renderer is not OS-sandboxed; a Chromium RCE becomes a full-privilege compromise'),
    ('webSecurity', r'webSecurity\s*:\s*(true|false)', 'false', 9,
     'same-origin policy disabled — any loaded page can read any origin, including file://'),
    ('allowRunningInsecureContent', r'allowRunningInsecureContent\s*:\s*(true|false)', 'true', 7,
     'mixed content permitted — a network attacker injects script into an HTTPS page'),
    ('experimentalFeatures', r'experimentalFeatures\s*:\s*(true|false)', 'true', 5,
     'unstable Chromium features widen the renderer attack surface'),
    ('enableRemoteModule', r'enableRemoteModule\s*:\s*(true|false)', 'true', 9,
     'the remote module hands the renderer main-process objects — effectively nodeIntegration'),
    ('webviewTag', r'webviewTag\s*:\s*(true|false)', 'true', 6,
     '<webview> allows embedding with its own (often weaker) settings'),
    ('allowpopups', r'allowpopups', None, 5, '<webview allowpopups> — child windows inherit settings'),
]

SINKS = [
    ('shell.openExternal', r'shell\.openExternal\s*\(([^)]{0,160})', 9,
     'openExternal on a URL the page controls executes the OS handler for that scheme — '
     '`file:`, `ms-msdt:`, `search-ms:`, SMB paths and .url/.lnk drops all become code execution'),
    ('shell.openPath', r'shell\.openPath\s*\(([^)]{0,160})', 9, 'opens a path with the OS handler'),
    ('child_process', r'(?:child_process|require\([\'"]child_process[\'"]\))[^\n]{0,120}', 9,
     'process execution from JS'),
    ('exec/execSync', r'\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(([^)]{0,160})', 8,
     'command execution — check the argument is not built from page content'),
    ('eval / Function', r'\b(?:eval|new\s+Function)\s*\(', 6, 'dynamic code evaluation'),
    ('innerHTML sink', r'\.(?:innerHTML|outerHTML|insertAdjacentHTML)\s*=', 5,
     'DOM XSS sink — in Electron an XSS is usually a foothold, not the end'),
    ('ipcMain.handle/on', r'ipc(?:Main|Renderer)\.(?:handle|on|once)\s*\(\s*[\'"]([^\'"]{1,64})', 6,
     'IPC channel — the main process side runs with full privilege; validate every argument and '
     'never accept a path or a command from the renderer without an allowlist'),
    ('contextBridge.exposeInMainWorld', r'contextBridge\.exposeInMainWorld\s*\(\s*[\'"]([^\'"]{1,64})[\'"]', 5,
     'the bridge API surface — every exposed function is reachable from any script in the page'),
    ('protocol.register*', r'protocol\.register(\w+)Protocol\s*\(\s*[\'"]([^\'"]{1,32})', 7,
     'custom scheme handler — check for path traversal in the file resolver and whether the '
     'scheme is registered as standard/secure'),
    ('setWindowOpenHandler', r'setWindowOpenHandler\s*\(', 3, 'window-open policy (good if it denies by default)'),
    ('will-navigate', r'[\'"]will-navigate[\'"]', 3, 'navigation policy hook'),
    ('loadURL with variable', r'loadURL\s*\(\s*(?!["\'])([A-Za-z_$][\w.$\[\]\'"+ ]{0,60})', 7,
     'window target computed at runtime — if it can be pointed at attacker content with a '
     'privileged webPreferences, that is the whole chain'),
    ('fs module', r'require\([\'"]fs[\'"]\)', 4, 'filesystem access from JS'),
    ('asar integrity', r'(?:EnableEmbeddedAsarIntegrityValidation|asarIntegrity)', 2, 'integrity fuse referenced'),
    ('nodeCliInspect', r'(?:--inspect|--remote-debugging-port)', 7,
     'a debugging port in shipped code is a local RCE (any process can attach and evaluate JS)'),
]

CVE_NOTE = """Electron support policy: only the latest three majors get security fixes.
Anything older ships known, public Chromium and Node RCEs. Map the version to
https://www.electronjs.org/docs/latest/tutorial/electron-timelines and, for the Chromium
side, to the Chrome release that major is built on."""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--loot', required=True)
    a = ap.parse_args()
    man = json.load(open(os.path.join(a.loot, 'unwrap.json')))
    res = {'is_electron': False, 'is_cef': False, 'is_webview2': False, 'versions': {},
           'settings': [], 'sinks': [], 'bridges': [], 'protocols': [], 'ipc_channels': [],
           'csp': [], 'fuses': {}, 'packages': []}
    jsfiles = []
    for f in man['files']:
        p, rel = f['abs'], f['path']
        b = os.path.basename(rel).lower()
        if b in ('electron.exe',) or 'electron.asar' in rel or 'app.asar' in rel:
            res['is_electron'] = True
        if b == 'libcef.dll' or 'cef.pak' in rel:
            res['is_cef'] = True
        if 'webview2loader' in b or 'msedgewebview2' in b:
            res['is_webview2'] = True
        if f['ext'] in ('.js', '.mjs', '.cjs', '.ts', '.json', '.html') and f['size'] < (12 << 20):
            jsfiles.append(f)
        if b == 'package.json':
            try:
                d = json.load(open(p))
                res['packages'].append({'file': rel, 'name': d.get('name'),
                                        'version': d.get('version'),
                                        'main': d.get('main'),
                                        'electron': (d.get('devDependencies') or {}).get('electron')
                                        or (d.get('dependencies') or {}).get('electron')})
                if (d.get('devDependencies') or {}).get('electron') or (d.get('dependencies') or {}).get('electron'):
                    res['is_electron'] = True
            except Exception:
                pass

    # Electron version from the binary's version resource / strings
    tp = os.path.join(a.loot, 'pe_triage.json')
    if os.path.isfile(tp):
        for bnr in json.load(open(tp))['binaries']:
            v = bnr.get('version') or {}
            for k in ('ProductName', 'FileVersion', 'ProductVersion', 'CompanyName', 'OriginalFilename'):
                if k in v and re.search(r'(?i)electron|chromium|cef', str(v.get('ProductName', '')) + str(v.get('CompanyName', ''))):
                    res['versions'][bnr['path']] = v
                    res['is_electron'] = True

    for f in jsfiles:
        try:
            t = open(f['abs'], 'rb').read(8 << 20).decode('utf-8', 'replace')
        except Exception:
            continue
        rel = f['path']
        for name, rx, bad, sev, why in CHECKS:
            for m in re.finditer(rx, t):
                val = m.group(1) if m.groups() else 'present'
                insecure = (bad is None) or (val == bad)
                res['settings'].append({'setting': name, 'value': val, 'insecure': insecure,
                                        'severity_hint': sev if insecure else 0,
                                        'why': why, 'file': rel,
                                        'context': t[max(0, m.start() - 80):m.end() + 80].replace('\n', ' ')[:220]})
        for name, rx, sev, why in SINKS:
            for m in re.finditer(rx, t):
                arg = (m.group(1) if m.groups() else '')[:120]
                row = {'sink': name, 'arg': arg, 'severity_hint': sev, 'why': why, 'file': rel,
                       'context': t[max(0, m.start() - 60):m.end() + 60].replace('\n', ' ')[:220]}
                res['sinks'].append(row)
                if name == 'contextBridge.exposeInMainWorld':
                    res['bridges'].append({'api': arg, 'file': rel})
                if name == 'protocol.register*':
                    res['protocols'].append({'scheme': arg, 'file': rel})
                if name == 'ipcMain.handle/on':
                    res['ipc_channels'].append({'channel': arg, 'file': rel})
        for m in re.finditer(r'(?i)content-security-policy[^\n]{0,300}', t):
            res['csp'].append({'file': rel, 'csp': m.group(0)[:300]})
        for m in re.finditer(r'(?i)(runAsNode|enableNodeCliInspectArguments|enableNodeOptionsEnvironmentVariable|onlyLoadAppFromAsar|loadBrowserProcessSpecificV8Snapshot|grantFileProtocolExtraPrivileges)\W{0,4}(true|false|1|0)?', t):
            res['fuses'][m.group(1)] = m.group(2) or 'referenced'

    insec = [s for s in res['settings'] if s['insecure']]
    res['counts'] = {'settings': len(res['settings']), 'insecure_settings': len(insec),
                     'sinks': len(res['sinks']), 'bridges': len(res['bridges']),
                     'protocols': len(res['protocols']), 'ipc': len(res['ipc_channels'])}
    json.dump(res, open(os.path.join(a.loot, 'electron.json'), 'w'), indent=1)

    L = ['# Electron / CEF / WebView2 audit', '',
         f"- Electron: **{res['is_electron']}** · CEF: **{res['is_cef']}** · WebView2: **{res['is_webview2']}**", '']
    if not (res['is_electron'] or res['is_cef'] or res['is_webview2']):
        L.append('_No embedded-browser framework detected in this target._')
        open(os.path.join(a.loot, 'electron.md'), 'w').write('\n'.join(L))
        print('[electron_audit] no embedded-browser framework detected')
        return
    if res['packages']:
        L += ['## package.json', '']
        for p in res['packages'][:20]:
            L.append(f"- `{p['file']}` — {p.get('name')} {p.get('version')} main=`{p.get('main')}` electron={p.get('electron')}")
        L += ['', CVE_NOTE, '']
    L += [f"## Insecure webPreferences ({len(insec)})", '']
    if insec:
        for s in sorted(insec, key=lambda x: -x['severity_hint'])[:40]:
            L += [f"- **{s['setting']} = {s['value']}** (hint {s['severity_hint']}/10) — {s['why']}",
                  f"  - `{s['file']}`", f"  - `{s['context']}`"]
    else:
        L.append('_none of the classic switches are set insecurely — check the defaults for the '
                 'Electron major in use, and read the preload instead_')
    L += ['', f"## contextBridge surface ({len(res['bridges'])})", '',
          'Every exposed function is callable by **any** script in the renderer, including one',
          'injected by an XSS. Read each one: does it take a path, a URL, a command, or a',
          'serialisable object that reaches the main process?', '']
    for b in res['bridges'][:30]:
        L.append(f"- `{b['api']}` in `{b['file']}`")
    L += ['', f"## IPC channels ({len(res['ipc_channels'])})", '']
    for c in res['ipc_channels'][:60]:
        L.append(f"- `{c['channel']}` — `{c['file']}`")
    L += ['', f"## Custom protocols ({len(res['protocols'])})", '']
    for p in res['protocols'][:20]:
        L.append(f"- `{p['scheme']}` — `{p['file']}`")
    if res['fuses']:
        L += ['', '## Fuses referenced', '']
        for k, v in res['fuses'].items():
            L.append(f'- {k} = {v}')
        L.append('')
        L.append('> `runAsNode` and `enableNodeCliInspectArguments` left ON mean any local process can '
                 'restart the signed binary as a Node interpreter (`ELECTRON_RUN_AS_NODE=1`) — a '
                 'signed-binary-proxy execution and, if the app is privileged, an LPE.')
    L += ['', f"## Dangerous sinks ({len(res['sinks'])})", '']
    for s in sorted(res['sinks'], key=lambda x: -x['severity_hint'])[:60]:
        L += [f"- **{s['sink']}** (hint {s['severity_hint']}/10) `{s['arg']}`",
              f"  - {s['why']}", f"  - `{s['file']}` :: `{s['context']}`"]
    if res['csp']:
        L += ['', '## CSP', ''] + [f"- `{c['file']}`: `{c['csp']}`" for c in res['csp'][:10]]
    L += ['', '## The chain to prove', '',
          '1. Find a renderer entry point you control: a `loadURL` target, a custom protocol, an',
          '   injected string rendered without escaping, or a third-party iframe/ad.',
          '2. From that context, reach the bridge: `window.<exposedApi>` or an `ipcRenderer.invoke`',
          '   channel whose main-process handler takes a path/URL/command.',
          '3. Convert to native execution: `child_process`, `shell.openExternal` with a handler',
          '   scheme, a written file plus a load, or Node via `ELECTRON_RUN_AS_NODE`.',
          '4. Capture proof: calc.exe is not proof — write a file with the process token in it.']
    open(os.path.join(a.loot, 'electron.md'), 'w').write('\n'.join(L))
    print(f"[electron_audit] {res['counts']}")
    print(f'[electron_audit] -> {a.loot}/electron.json + electron.md')


if __name__ == '__main__':
    main()
