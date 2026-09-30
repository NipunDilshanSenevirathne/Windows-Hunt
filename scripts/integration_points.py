#!/usr/bin/env python3
"""
integration_points.py — every way the product wires itself into Windows.

A desktop product does not just install files. It registers handlers, hosts, extensions,
providers and tasks that the OS then loads into OTHER processes — sometimes into explorer.exe,
sometimes into every process on the machine, sometimes into a browser. Each hook is a boundary,
and several of them are boundaries almost nobody audits.

What it finds:

  native messaging hosts   a JSON manifest that lets a browser extension talk to a native
                           binary. `allowed_origins` / `allowed_extensions` is the ACL, and it
                           is frequently too wide. This is a direct web->native bridge.
  shell extensions         context menu, icon overlay, preview, property, thumbnail handlers.
                           Windows loads these INTO EXPLORER.EXE and other apps.
  AppInit_DLLs             loaded into (almost) every process that links user32
  AppCertDlls              loaded into every process that calls CreateProcess
  IFEO / SilentProcessExit debugger hijack of another image, and a monitor process on exit
  Winlogon notify / shell  loaded by winlogon at logon, as SYSTEM
  WER LocalDumps           a dump path a privileged crash handler writes to
  credential providers     loaded by LogonUI as SYSTEM, pre-authentication
  LSA / SSP / netprovider  loaded by lsass as SYSTEM
  print / port monitors    loaded by spoolsv as SYSTEM (the PrintNightmare family of surfaces)
  WMI providers            hosted by wmiprvse, frequently as SYSTEM
  scheduled task XML       the real definition: principal, run level, action path, triggers
  file associations        the `shell\\open\\command` line and whether `%1` is quoted
  AppX / MSIX manifest     declared capabilities, protocol/file extensions, full-trust processes
  ClickOnce                deployment manifests and their trust settings
  certificate install      a root CA being added to the machine store is a finding on its own
  firewall rules           holes the installer punches
  startup / Run entries    per-machine autoruns and where they point
  PATH / env modification  a PATH prepend turns every unresolved import into a hijack

Usage:  integration_points.py --loot loot/<name>
Writes: <loot>/integration.json, <loot>/integration.md
"""
import argparse, json, os, re, xml.etree.ElementTree as ET

WRITABLE = re.compile(r'(?i)(programdata|\\users\\public|\\public\\|\\temp\\|%temp%|'
                      r'appdata|localappdata)')

REG_HOOKS = [
    ('AppInit_DLLs', r'(?i)AppInit_DLLs', 9,
     'loaded into every process that links user32.dll. If the DLL path is user-writable this is '
     'code execution everywhere, including in privileged processes'),
    ('AppCertDlls', r'(?i)AppCertDlls', 9,
     'loaded into every process that calls CreateProcess'),
    ('IFEO Debugger', r'(?i)Image File Execution Options\\+[^\\\s"]+\\*.{0,40}Debugger', 8,
     'a debugger entry replaces the launched image — if the product sets one, check the path; '
     'if the key is writable, anyone can set one'),
    ('SilentProcessExit', r'(?i)SilentProcessExit', 7,
     'MonitorProcess runs when the target exits, inheriting the exiting process context'),
    ('Winlogon Notify', r'(?i)Winlogon\\+Notify', 9,
     'loaded by winlogon.exe as SYSTEM at logon'),
    ('Winlogon Shell/Userinit', r'(?i)Winlogon\\*"?(Shell|Userinit)', 9,
     'the logon shell — replaced value runs at every logon'),
    ('Credential Provider', r'(?i)Authentication\\+Credential Providers', 9,
     'loaded by LogonUI as SYSTEM, before anyone is authenticated'),
    ('LSA package', r'(?i)Lsa\\*"?(Security Packages|Authentication Packages|Notification Packages)', 10,
     'loaded into lsass.exe as SYSTEM'),
    ('Network Provider', r'(?i)NetworkProvider\\+Order|ProviderOrder', 7,
     'loaded by the multi-provider router in a SYSTEM service'),
    ('Print Monitor/Provider', r'(?i)Print\\+(Monitors|Providers)', 9,
     'loaded by spoolsv.exe as SYSTEM — the PrintNightmare surface'),
    ('Shell Extension', r'(?i)(ShellEx\\+(ContextMenuHandlers|PropertySheetHandlers|IconHandler|'
     r'DragDropHandlers)|ShellIconOverlayIdentifiers|PreviewHandlers|Approved)', 6,
     'loaded into explorer.exe and any app that shows a shell dialog'),
    ('Browser Helper Object', r'(?i)Browser Helper Objects', 6, 'loaded into Internet Explorer / WebOC hosts'),
    ('WER LocalDumps', r'(?i)Windows Error Reporting\\+LocalDumps', 6,
     'a dump folder written by a privileged crash handler — check the path and its ACL'),
    ('Run key (HKLM)', r'(?i)HKEY_LOCAL_MACHINE\\+SOFTWARE\\+Microsoft\\+Windows\\+CurrentVersion\\+Run', 5,
     'per-machine autorun — check where it points and who can write there'),
    ('Services key', r'(?i)HKEY_LOCAL_MACHINE\\+SYSTEM\\+CurrentControlSet\\+Services', 5,
     'service definition written directly to the registry'),
    ('Environment/PATH', r'(?i)(Session Manager\\+Environment|\\bPATH\\b\s*=)', 6,
     'a PATH entry the product adds turns every unresolved DLL import on the host into a hijack '
     'candidate if that directory is writable'),
    ('WMI provider', r'(?i)(__Win32Provider|HostingModel|root\\\\cimv2)', 6,
     'hosted by wmiprvse.exe, often as LocalSystem'),
    ('Root certificate', r'(?i)(SystemCertificates\\+ROOT|certutil[^\n]{0,60}-addstore[^\n]{0,20}root|'
     r'X509Store\("?Root)', 9,
     'installing a root CA into the machine store means every TLS connection on the host can be '
     'silently intercepted by whoever holds that key — a finding on its own, and a Critical if '
     'the private key ships with the product'),
    ('Firewall rule', r'(?i)(netsh\s+advfirewall|New-NetFirewallRule|HNetCfg\.FwPolicy)', 4,
     'an inbound allow rule widens the network attack surface; check the port and the profile'),
]


def loads_lenient(txt):
    """Parse JSON that real installers actually ship: comments, trailing commas, and
    Windows paths with unescaped backslashes. A strict failure here loses the finding."""
    try:
        return json.loads(txt)
    except Exception:
        pass
    t = re.sub(r'(?m)//[^\n]*$', '', txt)
    t = re.sub(r'/\*.*?\*/', '', t, flags=re.S)
    t = re.sub(r',(\s*[}\]])', r'\1', t)
    t = re.sub(r'\\(?![\\"/bfnrtu])', r'\\\\', t)
    try:
        return json.loads(t)
    except Exception:
        return {}


def read(p, cap=8 << 20):
    try:
        return open(p, 'rb').read(cap).decode('utf-8', 'replace')
    except Exception:
        return ''


def strings(p, cap=24 << 20):
    try:
        d = open(p, 'rb').read(cap)
    except Exception:
        return ''
    out = b'\n'.join(re.findall(rb'[\x20-\x7e]{5,}', d)).decode('latin1')
    try:
        out += '\n' + '\n'.join(re.findall(r'[\x20-\x7e]{5,}', d.decode('utf-16-le', 'ignore')))
    except Exception:
        pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--loot', required=True)
    a = ap.parse_args()
    loot = a.loot
    man = json.load(open(os.path.join(loot, 'unwrap.json')))
    R = {'native_messaging': [], 'hooks': [], 'tasks': [], 'file_assoc': [], 'appx': [],
         'clickonce': [], 'browser_ext': [], 'startup': [], 'notes': []}

    for f in man['files']:
        p, rel, ext, base = f['abs'], f['path'], f['ext'], os.path.basename(f['path']).lower()
        if f['size'] == 0:
            continue

        # ---- native messaging host manifests (the web->native bridge) -----------
        if ext == '.json' and f['size'] < (256 << 10):
            txt = read(p, 256 << 10)
            if '"allowed_origins"' in txt or '"allowed_extensions"' in txt or \
               ('"path"' in txt and '"type"' in txt and 'stdio' in txt):
                d = loads_lenient(txt)
                origins = d.get('allowed_origins') or d.get('allowed_extensions') or []
                if not origins:
                    # real manifests ship with comments, trailing commas and unescaped
                    # Windows paths; a strict parse failure must not silently drop the host
                    origins = re.findall(r'"((?:chrome|moz|edge)-extension://[^"]*|\*(?://\*)?[^"]*)"',
                                         txt)[:20]
                wide = [o for o in origins if isinstance(o, str) and
                        (o.strip() in ('*', 'chrome-extension://*/', '*://*/*') or o.count('*') > 0)]
                R['native_messaging'].append({
                    'file': rel, 'name': d.get('name'), 'path': d.get('path'),
                    'type': d.get('type'), 'origins': origins[:20],
                    'wildcard_origins': wide,
                    'severity': 8 if wide else 6,
                    'why': 'a browser extension speaks to this native binary over stdio. The origin '
                           'list IS the access control — a wildcard, or an extension id that is not '
                           'the vendor\'s own, means any page that can talk to that extension reaches '
                           'native code. Read the binary\'s message handler next.'
                           + (' **WILDCARD ORIGIN**' if wide else '')})
                continue

        # ---- AppX / MSIX manifest ------------------------------------------------
        if base in ('appxmanifest.xml', 'package.appxmanifest'):
            txt = read(p)
            caps = sorted(set(re.findall(r'<(?:rescap:|uap\d*:)?Capability[^>]*Name="([^"]+)"', txt)))
            devcaps = sorted(set(re.findall(r'<DeviceCapability[^>]*Name="([^"]+)"', txt)))
            protos = sorted(set(re.findall(r'<uap\d*:Protocol[^>]*Name="([^"]+)"', txt)))
            fta = sorted(set(re.findall(r'<uap\d*:FileType>\s*([^<]+)</uap\d*:FileType>', txt)))
            fulltrust = re.findall(r'<desktop\d*:Extension[^>]*Category="windows\.fullTrustProcess"[^>]*Executable="([^"]+)"', txt)
            startup = re.findall(r'Category="windows\.startupTask"[^>]*Executable="([^"]+)"', txt)
            svc = re.findall(r'Category="windows\.service"[^>]*', txt)
            R['appx'].append({'file': rel, 'capabilities': caps, 'device_capabilities': devcaps,
                              'protocols': protos, 'file_types': fta,
                              'full_trust_processes': fulltrust, 'startup_tasks': startup,
                              'services': len(svc),
                              # runFullTrust is how essentially every packaged Win32 app ships;
                              # calling it a weakness is noise. These are the ones that actually
                              # remove a part of the sandbox contract.
                              'restricted': [c for c in caps if c.lower() in
                                             ('allowelevation', 'packagemanagement',
                                              'localsystemservices', 'broadfilesystemaccess',
                                              'unvirtualizedresources', 'confirmapprove',
                                              'devicemanagementdmaccount', 'runfullTrust'.lower()
                                              if False else 'allowelevation')],
                              'full_trust': 'runFullTrust' in caps,
                              'why': 'declared capabilities are the sandbox contract. `runFullTrust`, '
                                     '`allowElevation`, `broadFileSystemAccess` and '
                                     '`unvirtualizedResources` each remove part of it. Protocol and '
                                     'file-type activations are the remote entry points.'})
            continue

        # ---- ClickOnce -------------------------------------------------------------
        if ext in ('.application', '.vsto') or base.endswith('.manifest') and 'clickonce' in read(p, 4096).lower():
            txt = read(p)
            R['clickonce'].append({'file': rel,
                                   'codebase': (re.search(r'codebase="([^"]+)"', txt) or [None, ''])[1]
                                   if re.search(r'codebase="([^"]+)"', txt) else '',
                                   'unrestricted': 'Unrestricted="true"' in txt,
                                   'http': bool(re.search(r'(?i)codebase="http://', txt)),
                                   'why': 'ClickOnce deployment: an http:// codebase or '
                                          'Unrestricted trust means the update path is the attack path'})
            continue

        # ---- scheduled task XML ------------------------------------------------------
        if ext == '.xml' and f['size'] < (1 << 20):
            txt = read(p, 1 << 20)
            if '<Task ' in txt and 'RegistrationInfo' in txt:
                ns = {'t': 'http://schemas.microsoft.com/windows/2004/02/mit/task'}
                try:
                    root = ET.fromstring(txt)
                except Exception:
                    root = None
                def gt(path):
                    if root is None:
                        return None
                    e = root.find(path, ns)
                    return (e.text or '').strip() if e is not None else None
                cmd = gt('.//t:Exec/t:Command') or (re.search(r'<Command>([^<]+)', txt) or [None, ''])[1]
                args = gt('.//t:Exec/t:Arguments') or ''
                userid = gt('.//t:Principal/t:UserId') or ''
                runlevel = gt('.//t:Principal/t:RunLevel') or ''
                logon = gt('.//t:Principal/t:LogonType') or ''
                sysish = bool(re.search(r'(?i)(S-1-5-18|SYSTEM|LocalService|NetworkService)', userid)) \
                    or runlevel == 'HighestAvailable'
                R['tasks'].append({'file': rel, 'command': cmd, 'arguments': args,
                                   'user': userid, 'run_level': runlevel, 'logon_type': logon,
                                   'privileged': sysish,
                                   'command_in_writable_path': bool(cmd and WRITABLE.search(cmd)),
                                   'severity': 9 if (sysish and cmd and WRITABLE.search(cmd)) else (6 if sysish else 3),
                                   'why': 'a task running as SYSTEM whose action binary (or its '
                                          'directory) a standard user can write is a complete LPE'})
                continue

        # ---- registry hooks + file associations from .reg / scripts / binaries ---------
        scan = ''
        if ext in ('.reg', '.ps1', '.bat', '.cmd', '.inf', '.txt', '.iss', '.nsi', '.xml',
                   '.json', '.config', '.ini', '.vbs', '.js'):
            scan = read(p)
        elif f['kind'] == 'pe':
            scan = strings(p)
        if not scan:
            continue
        for name, rx, sev, why in REG_HOOKS:
            for m in re.finditer(rx, scan):
                ctx = scan[max(0, m.start() - 100):m.end() + 160].replace('\n', ' ')[:300]
                R['hooks'].append({'hook': name, 'severity': sev, 'why': why,
                                   'file': rel, 'context': ctx})
                break     # one row per hook per file
        if ext == '.reg':
            for m in re.finditer(r'(?i)\[HKEY_(?:CLASSES_ROOT|LOCAL_MACHINE\\+SOFTWARE\\+Classes)\\+'
                                 r'([A-Za-z0-9_.\-]{2,48})\\+shell\\+([A-Za-z0-9_]+)\\+command\]\s*\r?\n'
                                 r'\s*@\s*=\s*"(.*?)"\s*$', scan, re.M):
                progid, verb, cmd = m.group(1), m.group(2), m.group(3)
                unq = ('%1' in cmd) and not re.search(r'\\?"%1\\?"', cmd)
                R['file_assoc'].append({'progid': progid, 'verb': verb, 'command': cmd[:220],
                                        'unquoted_arg': unq, 'file': rel,
                                        'severity': 8 if unq else 3,
                                        'why': 'opening a file of this type runs this command. An '
                                               'unquoted %1 lets a crafted FILE NAME inject '
                                               'command-line arguments'})
            for m in re.finditer(r'(?i)\[HKEY_LOCAL_MACHINE\\+SOFTWARE\\+Microsoft\\+Windows\\+'
                                 r'CurrentVersion\\+Run[A-Za-z]*\]\s*\r?\n((?:\s*"[^"]+"\s*=\s*"[^"]*"\s*\r?\n)+)',
                                 scan):
                for k, v in re.findall(r'"([^"]+)"\s*=\s*"([^"]*)"', m.group(1)):
                    R['startup'].append({'name': k, 'command': v[:200], 'file': rel,
                                         'in_writable_path': bool(WRITABLE.search(v)),
                                         'severity': 8 if WRITABLE.search(v) else 4})
        # shipped browser extensions
        if base == 'manifest.json' and '"manifest_version"' in scan:
            d = loads_lenient(scan)
            if d.get('name') or d.get('manifest_version'):
                R['browser_ext'].append({
                    'file': rel, 'name': d.get('name'), 'version': d.get('version'),
                    'permissions': (d.get('permissions') or [])[:30],
                    'host_permissions': (d.get('host_permissions') or [])[:20],
                    'externally_connectable': d.get('externally_connectable'),
                    'nativeMessaging': 'nativeMessaging' in (d.get('permissions') or []),
                    'severity': 7 if 'nativeMessaging' in (d.get('permissions') or []) else 4,
                    'why': 'a shipped browser extension with `nativeMessaging` is the other half of '
                           'the web->native bridge; `externally_connectable` says which web pages '
                           'can talk to it directly'})

    # de-duplicate hooks by (hook, file)
    seen = set()
    hooks = []
    for h in R['hooks']:
        k = (h['hook'], h['file'])
        if k in seen:
            continue
        seen.add(k)
        hooks.append(h)
    R['hooks'] = sorted(hooks, key=lambda x: -x['severity'])
    R['counts'] = {k: len(v) for k, v in R.items() if isinstance(v, list)}
    json.dump(R, open(os.path.join(loot, 'integration.json'), 'w'), indent=1)

    L = ['# OS integration points', '',
         'Every row is something the product asks **Windows** to load or run on its behalf — '
         'often inside another process, sometimes inside every process.', '']

    def sec(title, rows, fmt, lead=None):
        out = [f'## {title} ({len(rows)})', '']
        if lead:
            out += [lead, '']
        if not rows:
            out += ['_none found_', '']
            return out
        for r in rows[:40]:
            out.append(fmt(r))
        if len(rows) > 40:
            out.append(f'- … {len(rows)-40} more in integration.json')
        out.append('')
        return out

    L += sec('Native messaging hosts (web → native bridge)', R['native_messaging'],
             lambda r: (f"- **{r.get('name')}** → `{r.get('path')}` ({r.get('severity')}/10)\n"
                        f"  - allowed origins: {r['origins'] or '(none listed)'}"
                        + ('  **WILDCARD**' if r['wildcard_origins'] else '')
                        + f"\n  - `{r['file']}`\n  - {r['why']}"),
             'This is the most under-tested web→desktop bridge that exists. The manifest names a '
             'native binary and the browser extensions allowed to speak to it over stdio. Read the '
             'binary\'s message loop: every message is attacker-influenced if the extension is.')
    L += sec('Registry hooks Windows loads into other processes', R['hooks'],
             lambda r: (f"- **{r['hook']}** ({r['severity']}/10) — `{r['file']}`\n"
                        f"  - {r['why']}\n  - context: `{r['context']}`"))
    L += sec('Scheduled tasks (parsed definitions)', R['tasks'],
             lambda r: (f"- `{r['command']}` {r['arguments'][:80]}\n"
                        f"  - runs as **{r['user'] or '(default)'}** level={r['run_level']} "
                        f"logon={r['logon_type']} ({r['severity']}/10)"
                        + ('\n  - **ACTION BINARY IS IN A USER-WRITABLE PATH**' if r['command_in_writable_path'] else '')
                        + f"\n  - `{r['file']}`"))
    L += sec('File associations', R['file_assoc'],
             lambda r: (f"- `{r['progid']}` verb `{r['verb']}` → `{r['command']}`"
                        + ('  **UNQUOTED %1 — a crafted filename injects arguments**' if r['unquoted_arg'] else '')
                        + f"\n  - `{r['file']}`"))
    L += sec('AppX / MSIX manifest', R['appx'],
             lambda r: (f"- `{r['file']}`\n"
                        f"  - capabilities: {', '.join(r['capabilities']) or 'none'}\n"
                        f"  - restricted/high-impact: **{', '.join(r['restricted']) or 'none'}**\n"
                        f"  - protocols: {', '.join(r['protocols']) or 'none'} · file types: "
                        f"{', '.join(r['file_types']) or 'none'}\n"
                        f"  - full-trust processes: {', '.join(r['full_trust_processes']) or 'none'} · "
                        f"startup tasks: {', '.join(r['startup_tasks']) or 'none'} · services: {r['services']}\n"
                        f"  - {r['why']}"))
    L += sec('ClickOnce / VSTO deployment', R['clickonce'],
             lambda r: f"- `{r['file']}` codebase=`{r['codebase']}` unrestricted={r['unrestricted']} "
                       f"http={r['http']}\n  - {r['why']}")
    L += sec('Shipped browser extensions', R['browser_ext'],
             lambda r: (f"- **{r.get('name')}** {r.get('version')} ({r['severity']}/10)\n"
                        f"  - permissions: {', '.join(map(str, r['permissions'])) or 'none'}\n"
                        f"  - hosts: {', '.join(map(str, r['host_permissions'])) or 'none'}\n"
                        f"  - externally_connectable: {r['externally_connectable']}\n"
                        f"  - `{r['file']}`"))
    L += sec('Per-machine startup entries', R['startup'],
             lambda r: f"- `{r['name']}` → `{r['command']}`"
                       + ('  **IN A USER-WRITABLE PATH**' if r['in_writable_path'] else '')
                       + f"\n  - `{r['file']}`")
    L += ['## What to do with these', '',
          '1. For every hook, find **which process loads it** and at what privilege. `AppInit_DLLs` '
          'is everything; a shell extension is explorer.exe; a credential provider is LogonUI as '
          'SYSTEM before logon.',
          '2. Then ask the only question that matters: **can a standard user change what gets '
          'loaded?** The DLL path, the directory it sits in, or the registry key itself.',
          '3. Native messaging hosts and file associations are *remote* entry points — treat them '
          'like the URI-handler class in `references/class-playbooks.md`.',
          '4. Confirm on the host with the runbook, then write the boundary into the report.']
    open(os.path.join(loot, 'integration.md'), 'w').write('\n'.join(L))
    print(f"[integration_points] {R['counts']}")
    print(f'[integration_points] -> {loot}/integration.json + integration.md')


if __name__ == '__main__':
    main()
