#!/usr/bin/env python3
"""
chain.py — compose individual weaknesses into the chain that actually crosses a boundary.

Single findings on Windows are often "so what": a writable directory that nothing privileged
reads, a URI handler that takes a benign argument, a phantom DLL in a user-level app. The
paid finding is the composition — web page → URI handler → argument injection → Electron
Node flag → local code execution → writable ProgramData → SYSTEM service DLL load.

This models each finding as an edge `precondition -> capability` and searches for paths from
an unprivileged START to a boundary-crossing GOAL. It PROPOSES; you verify each link. A chain
whose weakest link is unverified is a hypothesis, and the report must say so.

Usage:  chain.py --loot loot/<name> [--max-len 5]
Writes: <loot>/chains.json, <loot>/chains.md
"""
import argparse, json, os, re

START = {
    'remote-web-page': 'an attacker-controlled web page the user visits (no local access)',
    'network-mitm': 'an attacker on the network path (public Wi-Fi, malicious mirror, DNS)',
    'local-standard-user': 'code running as a normal logged-on user (the LPE start position)',
    'malicious-file': 'a file the user opens (email attachment, download, share)',
}
GOAL = {
    'code-exec-SYSTEM': ('SYSTEM/administrator code execution', 'user-to-system'),
    'code-exec-local': ('code execution as the logged-on user from a remote position', 'remote-to-local'),
    'other-user-data': ("another local user's data or session", 'user-to-user'),
    'persistent-sysfile-write': ('arbitrary file write as SYSTEM', 'user-to-system'),
}


def edges_from(loot):
    E = []

    def J(n):
        p = os.path.join(loot, n)
        return json.load(open(p)) if os.path.isfile(p) else {}

    hij, surf, el = J('dll_hijack.json'), J('surface.json'), J('electron.json')
    il, sec, drv = J('dotnet_il.json'), J('secrets.json'), J('drivers.json')
    com, integ = J('com.json'), J('integration.json')
    rt, sig = J('runtime.json'), J('signing.json')

    for f in (hij.get('findings') or []):
        if f['class'] not in ('PHANTOM', 'SIDELOAD'):
            continue
        cap = 'code-exec-SYSTEM' if f['loader_privilege'] >= 0.4 else 'code-exec-local-persist'
        E.append({'pre': 'write-to-app-dir', 'cap': cap, 'kind': 'dll-hijack',
                  'what': f"{f['class']} `{f['dll']}` loaded by `{os.path.basename(f['loader'])}`",
                  'evidence': 'dll_hijack.md', 'confidence': f['score'],
                  'verify': 'ACL on the loader directory + Procmon NAME NOT FOUND + proxy DLL'})

    for r in (surf.get('install_paths') or []):
        v = r['v']
        if isinstance(v, dict) and v.get('class') in ('ProgramData', 'Public', 'Temp'):
            E.append({'pre': 'local-standard-user', 'cap': 'write-to-app-dir', 'kind': 'writable-path',
                      'what': f"product uses {v['class']} (`{v.get('path','')}`), writable by users by default",
                      'evidence': 'surface.md#install-paths', 'confidence': 0.5,
                      'verify': 'icacls the real directory in the VM (runbook `paths[]`)'})

    for r in (surf.get('custom_actions') or []):
        v = r['v']
        if v.get('deferred') and v.get('no_impersonate'):
            E.append({'pre': 'write-to-app-dir', 'cap': 'code-exec-SYSTEM', 'kind': 'msi-custom-action',
                      'what': f"MSI custom action `{v['action']}` runs as SYSTEM ({v['kind']}) target=`{v['target'][:80]}`",
                      'evidence': 'surface.md#msi-custom-actions', 'confidence': 0.6,
                      'verify': 'trigger installer repair (msiexec /fa) as a standard user and watch the token'})

    for r in (surf.get('uri_handlers') or []):
        # If the registered command line was recovered, quoting is KNOWN, not guessed.
        if r.get('unquoted_arg') is True:
            conf, note = 0.75, ' with an UNQUOTED %1 (`' + str(r.get('command', ''))[:80] + '`)'
        elif r.get('unquoted_arg') is False:
            conf, note = 0.12, ' (%1 is correctly quoted — injection needs a parser bug instead)'
        else:
            conf, note = 0.45, ' (quoting unknown until the registry is read on the host)'
        E.append({'pre': 'remote-web-page', 'cap': 'local-arg-injection', 'kind': 'uri-handler',
                  'what': f"`{r['v']}://` protocol handler is navigable from a web page" + note,
                  'evidence': 'surface.md#uri-protocol-handlers', 'confidence': conf,
                  'verify': 'read HKCR shell\\open\\command on the host (runbook `uriHandlers[]`)'})

    for r in (surf.get('listeners') or []):
        v = r['v']
        E.append({'pre': 'remote-web-page', 'cap': 'local-api-access', 'kind': 'localhost-listener',
                  'what': f"local listener {v.get('url')} reachable from any web origin without CORS",
                  'evidence': 'surface.md#localhost-listeners', 'confidence': 0.45,
                  'verify': 'poc_gen.py --kind localhost --port <p>; check Origin validation and auth'})

    for r in (surf.get('pipes') or []):
        E.append({'pre': 'local-standard-user', 'cap': 'privileged-service-api', 'kind': 'named-pipe',
                  'what': f"named pipe `\\\\.\\pipe\\{r['v']}`",
                  'evidence': 'surface.md#named-pipes', 'confidence': 0.4,
                  'verify': 'can a standard user connect? (runbook `pipes[]`), then read the protocol'})

    for r in (surf.get('update_endpoints') or []):
        cleartext = str(r['v']).lower().startswith('http://')
        # HTTPS with no other signal is not a weakness: an updater existing is not a finding.
        # It only becomes an edge worth chaining when the transport is cleartext or something
        # else (a TLS-validation override, no signature check) has been observed.
        E.append({'pre': 'network-mitm', 'cap': 'update-package-substitution', 'kind': 'update-channel',
                  'what': f"update endpoint `{r['v']}`" + (' over CLEARTEXT HTTP' if cleartext else ''),
                  'evidence': 'surface.md#update-endpoints', 'confidence': 0.7 if cleartext else 0.12,
                  'verify': 'update_mitm.py: does it accept a bad cert? a bumped manifest? an unsigned package?'})
        E.append({'pre': 'update-package-substitution', 'cap': 'code-exec-SYSTEM', 'kind': 'update-exec',
                  'what': 'the updater installs and runs the package it downloaded',
                  'evidence': 'by design for any updater', 'confidence': 0.8,
                  'verify': 'confirm the updater runs as SYSTEM and verifies the signature before exec'})

    for s in (el.get('settings') or []):
        if s.get('insecure') and s['setting'] in ('nodeIntegration', 'contextIsolation',
                                                  'webSecurity', 'enableRemoteModule',
                                                  'nodeIntegrationInSubFrames'):
            E.append({'pre': 'renderer-content-control', 'cap': 'code-exec-local', 'kind': 'electron',
                      'what': f"{s['setting']}={s['value']} — renderer reaches Node",
                      'evidence': f"electron.md ({s['file']})", 'confidence': 0.7,
                      'verify': 'load attacker content in that window and call require()'})
    for s in (el.get('sinks') or []):
        if s['sink'] in ('shell.openExternal', 'child_process', 'exec/execSync'):
            E.append({'pre': 'renderer-content-control', 'cap': 'code-exec-local', 'kind': 'electron-sink',
                      'what': f"{s['sink']} reachable from renderer-influenced data",
                      'evidence': f"electron.md ({s['file']})", 'confidence': 0.5,
                      'verify': 'trace the argument back to a renderer-controlled value'})
        if s['sink'] == 'loadURL with variable':
            E.append({'pre': 'local-arg-injection', 'cap': 'renderer-content-control', 'kind': 'electron-nav',
                      'what': 'window target is computed at runtime',
                      'evidence': 'electron.md', 'confidence': 0.4, 'verify': 'can the value come from argv/URI?'})
    if el.get('is_electron'):
        E.append({'pre': 'local-arg-injection', 'cap': 'code-exec-local', 'kind': 'electron-flags',
                  'what': 'Chromium/Node command-line flags (--gpu-launcher, --inspect, ELECTRON_RUN_AS_NODE) '
                          'turn argument injection into code execution',
                  'evidence': 'electron.md', 'confidence': 0.6,
                  'verify': 'launch the app with the flag and confirm the child process'})

    for r in (il.get('results') or []):
        for h in r.get('hits', []):
            if h['family'] == 'deser' and h['severity_hint'] >= 9:
                E.append({'pre': 'controlled-input-to-app', 'cap': 'code-exec-local', 'kind': 'deserialization',
                          'what': f"{h['sink']} in `{h['method']}`",
                          'evidence': f"dotnet_il.md ({r['path']})", 'confidence': 0.55,
                          'verify': 'find the input path into that method; build a ysoserial.net gadget'})
            if h['family'] == 'tls':
                E.append({'pre': 'network-mitm', 'cap': 'update-package-substitution', 'kind': 'tls-bypass',
                          'what': f"{h['sink']} — certificate validation overridden",
                          'evidence': f"dotnet_il.md ({r['path']})", 'confidence': 0.6,
                          'verify': 'read the callback: does it return true unconditionally?'})
            if h['family'] == 'acl':
                E.append({'pre': 'local-standard-user', 'cap': 'write-to-app-dir', 'kind': 'acl-widening',
                          'what': f"{h['sink']} in `{h['method']}` — the app sets ACLs itself",
                          'evidence': f"dotnet_il.md ({r['path']})", 'confidence': 0.5,
                          'verify': 'read the ACE being added; Everyone/Users FullControl on a privileged path?'})

    for d in (drv.get('drivers') or []):
        if not d.get('secure_create'):
            E.append({'pre': 'local-standard-user', 'cap': 'code-exec-SYSTEM', 'kind': 'driver-ioctl',
                      'what': f"driver `{os.path.basename(d['path'])}` with {len(d.get('ioctls', []))} IOCTLs and "
                              f"no explicit device SDDL",
                      'evidence': 'drivers.md', 'confidence': 0.4,
                      'verify': 'can a standard user CreateFile the device? then fuzz handlers under a kernel debugger'})

    for h in (sec.get('hits') or []):
        if h['confidence'] >= 0.85:
            E.append({'pre': 'local-standard-user', 'cap': 'backend-access', 'kind': 'secret',
                      'what': f"{h['type']} shipped in `{h['file']}`",
                      'evidence': 'secrets.md', 'confidence': h['confidence'],
                      'verify': h['validate']})


    # ---- COM: server path in a writable location, elevation, SYSTEM identity ----------
    for f in (com.get('findings') or []):
        kinds = {i['kind'] for i in f['issues']}
        runas = str((f.get('appid') or {}).get('RunAs') or '')
        sysid = bool(re.search(r'(?i)localsystem|nt authority', runas))
        if 'server-in-writable-path' in kinds:
            cap = 'code-exec-SYSTEM' if (sysid or any(
                x['privilege'] != 'user' for x in f.get('activated_by', []))) else 'code-exec-local'
            E.append({'pre': 'local-standard-user', 'cap': cap, 'kind': 'com-writable-server',
                      'what': f"COM class `{f['guid'][:38]}` loads its server from a user-writable path"
                              + (f' and runs as {runas}' if runas else ''),
                      'evidence': 'com.md', 'confidence': 0.6 if sysid else 0.45,
                      'verify': 'confirm the directory ACL, then activate the class and see which '
                                'token loads the DLL'})
        if 'appid-runas' in kinds and sysid:
            E.append({'pre': 'com-activation', 'cap': 'code-exec-SYSTEM', 'kind': 'com-runas-system',
                      'what': f"AppID for `{f['guid'][:38]}` runs as {runas}",
                      'evidence': 'com.md', 'confidence': 0.5,
                      'verify': 'decode LaunchPermission on the host: can a standard user activate it?'})
            E.append({'pre': 'local-standard-user', 'cap': 'com-activation', 'kind': 'com-activation',
                      'what': 'CoCreateInstance on the class', 'evidence': 'com.md',
                      'confidence': 0.4, 'verify': 'try it from a standard-user PowerShell'})

    # ---- native messaging hosts: a browser extension's direct line to a native binary ---
    for n in (integ.get('native_messaging') or []):
        wide = bool(n.get('wildcard_origins'))
        E.append({'pre': 'remote-web-page', 'cap': 'native-host-message', 'kind': 'native-messaging',
                  'what': f"native messaging host `{n.get('name')}` -> `{n.get('path')}`"
                          + (' with a WILDCARD allowed_origin' if wide else ''),
                  'evidence': 'integration.md', 'confidence': 0.6 if wide else 0.3,
                  'verify': 'can a web page reach the extension (externally_connectable / content '
                            'script)? then read the native binary\'s message loop'})
        cap = 'code-exec-SYSTEM' if str(n.get('path', '')).lower().find('programdata') >= 0 \
            else 'code-exec-local'
        E.append({'pre': 'native-host-message', 'cap': cap, 'kind': 'native-host-handler',
                  'what': 'the native host acts on the message (path / command / update URL)',
                  'evidence': 'integration.md', 'confidence': 0.35,
                  'verify': 'enumerate the message types the host accepts'})

    # ---- OS hooks loaded into other processes ------------------------------------------
    HOOK_CAP = {'AppInit_DLLs': ('code-exec-SYSTEM', 0.6), 'AppCertDlls': ('code-exec-SYSTEM', 0.6),
                'LSA package': ('code-exec-SYSTEM', 0.65), 'Credential Provider': ('code-exec-SYSTEM', 0.65),
                'Winlogon Notify': ('code-exec-SYSTEM', 0.6), 'Print Monitor/Provider': ('code-exec-SYSTEM', 0.55),
                'Shell Extension': ('other-user-data', 0.35), 'WMI provider': ('code-exec-SYSTEM', 0.45),
                'IFEO Debugger': ('code-exec-SYSTEM', 0.4), 'Root certificate': ('network-to-local', 0.5)}
    for h in (integ.get('hooks') or []):
        cap, conf = HOOK_CAP.get(h['hook'], (None, 0))
        if not cap:
            continue
        E.append({'pre': 'write-to-app-dir', 'cap': cap, 'kind': f"hook-{h['hook'].split()[0].lower()}",
                  'what': f"{h['hook']} registered by this product — Windows loads it into another process",
                  'evidence': 'integration.md', 'confidence': conf,
                  'verify': 'who loads it, and can a standard user change the DLL, its directory, '
                            'or the registry value naming it?'})

    # ---- privileged scheduled task whose action lives somewhere writable ----------------
    for t in (integ.get('tasks') or []):
        if t.get('privileged') and t.get('command_in_writable_path'):
            E.append({'pre': 'local-standard-user', 'cap': 'code-exec-SYSTEM', 'kind': 'task-writable-action',
                      'what': f"scheduled task runs `{t.get('command')}` as {t.get('user')} from a "
                              f"user-writable path",
                      'evidence': 'integration.md', 'confidence': 0.65,
                      'verify': 'icacls the action path, replace the binary, wait for the trigger'})

    # ---- file association with an unquoted %1 -------------------------------------------
    for fa in (integ.get('file_assoc') or []):
        if fa.get('unquoted_arg'):
            E.append({'pre': 'malicious-file', 'cap': 'local-arg-injection', 'kind': 'assoc-unquoted',
                      'what': f"file association `{fa['progid']}` has an unquoted %1: `{fa['command'][:90]}`",
                      'evidence': 'integration.md', 'confidence': 0.6,
                      'verify': 'craft a filename containing a space and a flag, open it'})

    # ---- embedded-runtime load paths ------------------------------------------------------
    for f in (rt.get('findings') or []):
        if f['severity'] >= 8 and ('probing path' in f['title'] or 'writable' in f['title']
                                   or 'Class-Path' in f['title'] or 'codeBase' in f['title']):
            E.append({'pre': 'write-to-app-dir', 'cap': 'code-exec-local', 'kind': 'runtime-load-path',
                      'what': f["title"] + ' — ' + str(f['detail'])[:90],
                      'evidence': 'runtime.md', 'confidence': 0.5,
                      'verify': 'confirm the directory is writable and that the runtime really loads from it'})
        if 'JndiLookup' in f['title']:
            E.append({'pre': 'controlled-input-to-app', 'cap': 'code-exec-local', 'kind': 'log4shell',
                      'what': 'log4j JndiLookup present — a logged attacker-controlled string is RCE',
                      'evidence': 'runtime.md', 'confidence': 0.55,
                      'verify': 'find a field that reaches a log call; confirm the log4j-core version'})

    # ---- signing: nothing verifies the code it downloads -----------------------------------
    if sig and not (sig.get('verifiers') or []):
        if (surf.get('update_endpoints') or []):
            E.append({'pre': 'update-package-substitution', 'cap': 'code-exec-SYSTEM',
                      'kind': 'no-signature-verification',
                      'what': 'no binary in the package imports any signature-verification API, yet '
                              'the product has an update endpoint',
                      'evidence': 'signing.md', 'confidence': 0.55,
                      'verify': 'serve a modified package and see whether it installs'})

    # generic glue edges (always true, low confidence, make the graph connected)
    E += [
        {'pre': 'local-arg-injection', 'cap': 'code-exec-local', 'kind': 'glue',
         'what': 'argument injection into a locally installed program', 'evidence': '-',
         'confidence': 0.35, 'verify': 'which flags does that program accept?'},
        {'pre': 'code-exec-local', 'cap': 'local-standard-user', 'kind': 'glue',
         'what': 'code as the user IS the local-standard-user position', 'evidence': '-',
         'confidence': 0.95, 'verify': '-'},
        {'pre': 'privileged-service-api', 'cap': 'code-exec-SYSTEM', 'kind': 'glue',
         'what': 'a SYSTEM service API that takes a path/command/config', 'evidence': '-',
         'confidence': 0.35, 'verify': 'read the command set the pipe/RPC server exposes'},
        {'pre': 'local-api-access', 'cap': 'code-exec-local', 'kind': 'glue',
         'what': 'a local API endpoint that opens, runs, downloads or configures something',
         'evidence': '-', 'confidence': 0.35, 'verify': 'enumerate the endpoints'},
        {'pre': 'malicious-file', 'cap': 'controlled-input-to-app', 'kind': 'glue',
         'what': 'the app parses the file the user opened', 'evidence': '-', 'confidence': 0.7, 'verify': '-'},
        {'pre': 'remote-web-page', 'cap': 'controlled-input-to-app', 'kind': 'glue',
         'what': 'content fetched or rendered by the app', 'evidence': '-', 'confidence': 0.4, 'verify': '-'},
    ]
    return E


MIN_CHAIN_CONF = 0.20      # below this the chain is "everything is theoretically possible"


def search(E, max_len, floor=MIN_CHAIN_CONF):
    adj = {}
    for e in E:
        adj.setdefault(e['pre'], []).append(e)
    out = []
    for s in START:
        stack = [(s, [], {s}, 1.0)]
        while stack:
            node, path, seen, conf = stack.pop()
            if len(path) >= max_len:
                continue
            for e in adj.get(node, []):
                if e['cap'] in seen:
                    continue
                np, nc = path + [e], conf * max(e['confidence'], 0.05)
                if e['cap'] in GOAL:
                    if nc >= floor:
                        out.append({'start': s, 'goal': e['cap'], 'links': np,
                                    'confidence': round(nc, 3), 'length': len(np)})
                else:
                    stack.append((e['cap'], np, seen | {e['cap']}, nc))
    # dedupe: keep the best chain per (start, goal, kinds)
    best = {}
    for c in out:
        k = (c['start'], c['goal'], tuple(l['kind'] for l in c['links']))
        if k not in best or c['confidence'] > best[k]['confidence']:
            best[k] = c
    return sorted(best.values(), key=lambda c: (-c['confidence'], c['length']))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--loot', required=True)
    ap.add_argument('--max-len', type=int, default=5)
    a = ap.parse_args()
    E = edges_from(a.loot)
    chains = search(E, a.max_len)
    json.dump({'edges': len(E), 'chains': chains}, open(os.path.join(a.loot, 'chains.json'), 'w'), indent=1)
    L = ['# Chain synthesis', '',
         f'- weakness edges modelled: **{len(E)}**  ·  candidate chains: **{len(chains)}** '
         f'(composite confidence >= {MIN_CHAIN_CONF})', '',
         '> These are PROPOSALS. Each link carries its own verification step; a chain is worth',
         '> exactly as much as its weakest verified link. Report the verified prefix and label',
         '> the rest as the projected impact, or the whole thing gets closed as speculation.', '']
    if not chains:
        L.append('_no chain reaches a boundary from the modelled surface. That is a real result: '
                 'record it, and go back to the surfaces that produced no edges at all._')
    for i, c in enumerate(chains[:25], 1):
        g, boundary = GOAL[c['goal']]
        L += [f"## Chain {i} — {START[c['start']]} → {g}", '',
              f"- boundary crossed: **{boundary}** · composite confidence **{c['confidence']}** "
              f"({c['length']} links)", '']
        for n, l in enumerate(c['links'], 1):
            L += [f"{n}. **{l['kind']}** — {l['what']}",
                  f"   - needs: `{l['pre']}` → gives: `{l['cap']}`  (link confidence {l['confidence']})",
                  f"   - evidence: {l['evidence']}",
                  f"   - VERIFY: {l['verify']}"]
        L += ['', f"- severity if fully verified: `scripts/severity_win.py --boundary {boundary} "
              f"--vector ...`", '']
    open(os.path.join(a.loot, 'chains.md'), 'w').write('\n'.join(L))
    print(f'[chain] {len(E)} edges -> {len(chains)} chains')
    print(f'[chain] -> {a.loot}/chains.json + chains.md')


if __name__ == '__main__':
    main()
