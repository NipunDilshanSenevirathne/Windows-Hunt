#!/usr/bin/env python3
"""
runtime_lane.py — the embedded-runtime lanes: Java, Python/frozen, Node, and .NET probing.

A Windows product that ships a runtime inherits that runtime's attack surface *and* adds a
Windows-specific one: where the runtime looks for code it will execute. Every runtime has a
search path, and every search path that includes a user-writable directory is code execution at
the host process's privilege.

  JAVA     jar inventory · log4j-core with JndiLookup (Log4Shell) · gadget libraries
           (commons-collections, commons-beanutils, groovy, spring-core) · launcher scripts with
           `-cp`/`-javaagent`/`-Djava.class.path` pointing at writable paths · jvm.dll placement
  PYTHON   PyInstaller/py2exe/Nuitka/cx_Freeze frozen apps · the `_MEIPASS` extraction directory
           (a frozen app running as SYSTEM that extracts to a predictable, user-writable path is
           a classic LPE) · pickle/marshal/eval/os.system/subprocess sinks in bundled .py
  NODE     node_modules inventory · `postinstall` scripts · asar-unpacked native modules ·
           `NODE_OPTIONS`/`--require` handling
  .NET     `runtimeconfig.json` additionalProbingPaths · `deps.json` · `app.config`
           `<probing privatePath>` and `<codeBase href>` · binding redirects ·
           `AppDomain.AssemblyResolve` handlers — each one a place the CLR will load a DLL from

Usage:  runtime_lane.py --loot loot/<name>
Writes: <loot>/runtime.json, <loot>/runtime.md
"""
import argparse, json, os, re, zipfile

WRITABLE = re.compile(r'(?i)(programdata|\\users\\public|\\public\\|\\temp\\|%temp%|appdata|'
                      r'localappdata|/tmp/|\.\.[\\/])')

JAVA_GADGETS = {
    'commons-collections': 'the original ysoserial gadget source; <3.2.2 / <4.1 is directly exploitable',
    'commons-beanutils': 'gadget chain source',
    'groovy': 'gadget chain source',
    'spring-core': 'gadget chain source; also the Spring4Shell family',
    'aspectjweaver': 'gadget chain source',
    'c3p0': 'gadget chain source',
    'rome': 'gadget chain source',
    'xstream': 'unsafe by default before 1.4.18 — RCE on untrusted XML',
    'snakeyaml': 'unsafe constructor before 2.0 — RCE on untrusted YAML',
    'jackson-databind': 'polymorphic typing gadgets when default typing is enabled',
    'log4j-core': 'Log4Shell (CVE-2021-44228) below 2.17.1',
    'h2': 'H2 console / JDBC URL RCE',
    'bsh': 'BeanShell gadget',
}
PY_SINKS = [
    (r'\bpickle\.(loads|load)\b', 9, 'pickle deserialization — RCE on any attacker-controlled blob'),
    (r'\bmarshal\.(loads|load)\b', 8, 'marshal is equally unsafe'),
    (r'\byaml\.load\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?SafeLoader)', 8,
     'yaml.load without SafeLoader instantiates arbitrary objects'),
    (r'\bos\.system\s*\(', 7, 'shell execution'),
    (r'\bsubprocess\.(?:call|run|Popen|check_output)\s*\([^)]*shell\s*=\s*True', 8,
     'shell=True with a composed string is command injection'),
    (r'\beval\s*\(', 6, 'eval'),
    (r'\bexec\s*\(', 6, 'exec'),
    (r'\b__import__\s*\(', 4, 'dynamic import'),
    (r'\bctypes\.(?:WinDLL|windll|CDLL)\s*\(', 5, 'loads a native DLL — by what path?'),
    (r'\bshutil\.(?:copy|move)\s*\(', 3, 'file placement'),
    (r'\bsys\.path\.(?:append|insert)\s*\(', 6,
     'the module search path is being extended at runtime — if the added directory is writable, '
     'any import after it is attacker-controlled'),
    (r'\bverify\s*=\s*False', 7, 'TLS verification disabled in requests'),
    (r'\bssl\._create_unverified_context', 7, 'TLS verification disabled'),
]
NODE_RISK = {
    'postinstall': 'runs at install time with the installing user privilege',
    'preinstall': 'runs at install time',
    'install': 'runs at install time',
}


def loads_lenient(txt):
    """Tolerate the JSON real products ship: comments, trailing commas, unescaped paths."""
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


def read(p, cap=4 << 20):
    try:
        return open(p, 'rb').read(cap).decode('utf-8', 'replace')
    except Exception:
        return ''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--loot', required=True)
    a = ap.parse_args()
    loot = a.loot
    man = json.load(open(os.path.join(loot, 'unwrap.json')))
    R = {'java': {'present': False, 'jars': [], 'gadgets': [], 'launchers': [], 'jvm': []},
         'python': {'present': False, 'frozen': [], 'sinks': [], 'modules': 0, 'extract_dirs': []},
         'node': {'present': False, 'packages': [], 'lifecycle_scripts': [], 'native_modules': []},
         'dotnet_probing': [], 'findings': []}

    def finding(lane, sev, title, detail, why, ev):
        R['findings'].append({'lane': lane, 'severity': sev, 'title': title,
                              'detail': detail, 'why': why, 'evidence': ev})

    for f in man['files']:
        p, rel, ext, base = f['abs'], f['path'], f['ext'], os.path.basename(f['path']).lower()
        if f['size'] == 0:
            continue

        # ---------------- JAVA ----------------
        if ext in ('.jar', '.war', '.ear'):
            R['java']['present'] = True
            entry = {'jar': rel, 'size': f['size'], 'log4shell': False, 'gadgets': []}
            try:
                with zipfile.ZipFile(p) as z:
                    names = z.namelist()
                    if any(n.endswith('JndiLookup.class') for n in names):
                        entry['log4shell'] = True
                        finding('java', 10, 'log4j JndiLookup class present',
                                f'`{rel}` contains JndiLookup.class',
                                'this is the Log4Shell (CVE-2021-44228) gadget. Confirm the log4j-core '
                                'version; anything below 2.17.1 with a reachable log sink is RCE. The '
                                'standard mitigation is removing this class — it is still here',
                                rel)
                    mf = [n for n in names if n.upper() == 'META-INF/MANIFEST.MF']
                    if mf:
                        m = z.read(mf[0]).decode('utf-8', 'replace')
                        for k in ('Implementation-Version', 'Bundle-Version', 'Specification-Version'):
                            v = re.search(rf'{k}:\s*(\S+)', m)
                            if v:
                                entry['version'] = v.group(1)
                                break
                        cp = re.search(r'Class-Path:\s*([^\r\n]+)', m)
                        if cp:
                            entry['class_path'] = cp.group(1)[:200]
                            if WRITABLE.search(cp.group(1)):
                                finding('java', 8, 'jar Class-Path includes a writable location',
                                        f"`{rel}`: {cp.group(1)[:140]}",
                                        'the JVM loads classes from every Class-Path entry; a writable '
                                        'one is code execution at the JVM process privilege', rel)
            except Exception:
                pass
            for g, why in JAVA_GADGETS.items():
                if g in base:
                    entry['gadgets'].append(g)
                    sev = 9 if g in ('log4j-core', 'xstream', 'snakeyaml', 'commons-collections') else 5
                    finding('java', sev, f'gadget/vulnerable library shipped: {g}',
                            f'`{rel}`' + (f" version {entry.get('version')}" if entry.get('version') else ''),
                            why, rel)
            R['java']['jars'].append(entry)
            continue
        if base == 'jvm.dll' or base == 'java.exe' or base == 'javaw.exe':
            R['java']['present'] = True
            R['java']['jvm'].append(rel)
        if ext in ('.bat', '.cmd', '.ps1', '.vbs', '.ini', '.cfg', '.conf', '.vmoptions') or base.endswith('.l4j.ini'):
            t = read(p, 512 << 10)
            if re.search(r'(?i)\b(java|javaw)\b|-Djava\.|-classpath|-cp\b|-javaagent', t):
                R['java']['present'] = True
                R['java']['launchers'].append({'file': rel, 'excerpt': t[:400]})
                for m in re.finditer(r'(?i)(-javaagent:|-cp\s+|-classpath\s+|-Djava\.class\.path=)([^\s"\']+)', t):
                    if WRITABLE.search(m.group(2)):
                        finding('java', 8, 'JVM launch argument points at a writable path',
                                f'`{rel}`: {m.group(0)[:120]}',
                                '-javaagent and classpath entries are loaded as code by the JVM',
                                rel)
                for m in re.finditer(r'(?i)-Dcom\.sun\.management\.jmxremote[^\s]*', t):
                    finding('java', 7, 'JMX remote management enabled on the JVM',
                            f'`{rel}`: {m.group(0)[:120]}',
                            'JMX without authentication is remote code execution; check the '
                            'authenticate and ssl sub-options', rel)

        # ---------------- PYTHON ----------------
        if base in ('base_library.zip', 'python3.dll') or re.match(r'python\d\d\.dll', base) \
           or ext == '.pyd':
            R['python']['present'] = True
        if ext in ('.py', '.pyw'):
            R['python']['present'] = True
            R['python']['modules'] += 1
            t = read(p, 2 << 20)
            for rx, sev, why in PY_SINKS:
                for m in re.finditer(rx, t):
                    ctx = t[max(0, m.start() - 70):m.end() + 90].replace('\n', ' ')[:220]
                    R['python']['sinks'].append({'file': rel, 'sink': m.group(0)[:60],
                                                 'severity': sev, 'why': why, 'context': ctx})
                    break
        if f['kind'] == 'pyinstaller' or 'pyinstaller' in str(f.get('detail', '')).lower():
            R['python']['present'] = True
            R['python']['frozen'].append({'file': rel, 'kind': 'PyInstaller'})
            finding('python', 6, 'PyInstaller one-file bundle',
                    f'`{rel}`',
                    'a one-file build extracts itself to `_MEIxxxxxx` under %TEMP% at every run and '
                    'loads its DLLs and modules from there. If this binary runs as SYSTEM (service, '
                    'scheduled task, installer helper) the extraction directory is predictable and '
                    'the window between extract and load is a race — a classic frozen-app LPE. '
                    'Confirm: does it run privileged, and can a standard user write to the '
                    'extraction root (%TEMP% for SYSTEM is C:\\Windows\\Temp, which is '
                    'write-but-not-traverse for Users — check it on the host)', rel)

        # ---------------- NODE ----------------
        if base == 'package.json':
            t = read(p, 2 << 20)
            d = loads_lenient(t)
            if d:
                R['node']['present'] = True
                R['node']['packages'].append({'file': rel, 'name': d.get('name'),
                                              'version': d.get('version')})
                for k, why in NODE_RISK.items():
                    v = (d.get('scripts') or {}).get(k)
                    if v:
                        R['node']['lifecycle_scripts'].append({'file': rel, 'hook': k, 'cmd': str(v)[:160]})
                        finding('node', 5, f'npm {k} script shipped',
                                f'`{rel}`: {str(v)[:120]}', why, rel)
        if ext == '.node':
            R['node']['present'] = True
            R['node']['native_modules'].append(rel)

        # ---------------- .NET assembly probing ----------------
        if base.endswith('.runtimeconfig.json') or base.endswith('.deps.json'):
            t = read(p, 2 << 20)
            d = loads_lenient(t)
            probing = (((d.get('runtimeOptions') or {}).get('additionalProbingPaths')) or [])
            if not probing and 'additionalProbingPaths' in t:
                # malformed JSON must not lose the finding
                blk = re.search(r'"additionalProbingPaths"\s*:\s*\[(.*?)\]', t, re.S)
                if blk:
                    probing = re.findall(r'"([^"]+)"', blk.group(1))
            row = {'file': rel, 'kind': 'runtimeconfig' if 'runtimeconfig' in base else 'deps',
                   'probing_paths': probing,
                   'framework': ((d.get('runtimeOptions') or {}).get('framework') or {}),
                   'rollForward': (d.get('runtimeOptions') or {}).get('rollForward')}
            R['dotnet_probing'].append(row)
            for pp in probing:
                if WRITABLE.search(str(pp)):
                    finding('dotnet', 8, 'CLR probing path in a writable location',
                            f'`{rel}`: {pp}',
                            'the runtime loads assemblies from every additionalProbingPath. A '
                            'writable one is code execution in the managed process', rel)
        if ext == '.config' and base.endswith('.exe.config') or base == 'app.config' or base == 'web.config':
            t = read(p, 2 << 20)
            for m in re.finditer(r'(?i)<probing[^>]*privatePath\s*=\s*"([^"]+)"', t):
                R['dotnet_probing'].append({'file': rel, 'kind': 'probing privatePath',
                                            'probing_paths': [m.group(1)]})
                if WRITABLE.search(m.group(1)) or '..' in m.group(1):
                    finding('dotnet', 8, 'assembly probing privatePath escapes the app base',
                            f'`{rel}`: {m.group(1)}',
                            'the CLR will load assemblies from here', rel)
            for m in re.finditer(r'(?i)<codeBase[^>]*href\s*=\s*"([^"]+)"', t):
                R['dotnet_probing'].append({'file': rel, 'kind': 'codeBase href',
                                            'probing_paths': [m.group(1)]})
                sev = 9 if m.group(1).lower().startswith('http://') else 6
                finding('dotnet', sev, 'assembly codeBase href',
                        f'`{rel}`: {m.group(1)}',
                        'the CLR fetches the assembly from this location'
                        + (' **over cleartext HTTP — a network attacker supplies the code**'
                           if sev == 9 else ''), rel)
            n = len(re.findall(r'(?i)<bindingRedirect', t))
            if n:
                R['dotnet_probing'].append({'file': rel, 'kind': 'bindingRedirect', 'count': n})
            if re.search(r'(?i)<loadFromRemoteSources\s+enabled\s*=\s*"true"', t):
                finding('dotnet', 7, 'loadFromRemoteSources enabled',
                        f'`{rel}`',
                        'assemblies loaded from remote/UNC locations run with full trust', rel)
            if re.search(r'(?i)<NetFx40_LegacySecurityPolicy\s+enabled\s*=\s*"true"', t):
                finding('dotnet', 6, 'legacy CAS security policy enabled', f'`{rel}`',
                        'reintroduces the .NET 2.0 security model', rel)

    # AppDomain.AssemblyResolve from the IL pass, if present
    dp = os.path.join(loot, 'dotnet_il.json')
    if os.path.isfile(dp):
        for r in json.load(open(dp)).get('results', []):
            for h in r.get('hits', []):
                if h['sink'] in ('System.Reflection.Assembly::LoadFrom',
                                 'System.Reflection.Assembly::LoadFile',
                                 'System.Activator::CreateInstanceFrom'):
                    R['findings'].append({
                        'lane': 'dotnet', 'severity': 7,
                        'title': 'assembly loaded from a runtime-chosen path',
                        'detail': f"{h['sink']} in `{h['method']}`",
                        'why': 'trace the path argument: if it can point anywhere a standard user '
                               'writes, this is code execution at the host process privilege',
                        'evidence': r['path']})

    R['findings'].sort(key=lambda x: -x['severity'])
    R['counts'] = {'java_jars': len(R['java']['jars']), 'python_modules': R['python']['modules'],
                   'python_sinks': len(R['python']['sinks']),
                   'node_packages': len(R['node']['packages']),
                   'dotnet_probing': len(R['dotnet_probing']),
                   'findings': len(R['findings'])}
    json.dump(R, open(os.path.join(loot, 'runtime.json'), 'w'), indent=1)

    lanes = [k for k in ('java', 'python', 'node') if R[k]['present']] + \
            (['dotnet-probing'] if R['dotnet_probing'] else [])
    L = ['# Embedded runtime lanes', '',
         f"- runtimes detected: **{', '.join(lanes) or 'none'}**",
         f"- findings: **{len(R['findings'])}**", '']
    if R['findings']:
        L += ['## Findings', '']
        for f in R['findings'][:50]:
            L += [f"- **[{f['lane']}] {f['title']}** ({f['severity']}/10)",
                  f"  - {f['detail']}", f"  - {f['why']}", f"  - `{f['evidence']}`"]
        L.append('')
    if R['java']['present']:
        L += [f"## Java ({len(R['java']['jars'])} archives)", '']
        for j in R['java']['jars'][:40]:
            L.append(f"- `{j['jar']}` {j.get('version','')} "
                     + ('**LOG4SHELL CLASS PRESENT** ' if j['log4shell'] else '')
                     + (f"gadgets: {', '.join(j['gadgets'])}" if j['gadgets'] else ''))
        if R['java']['launchers']:
            L += ['', '**launchers:**'] + [f"- `{x['file']}`" for x in R['java']['launchers'][:15]]
        L.append('')
        L.append('> Also check: is the shipped JRE patched? A bundled JRE is never updated by '
                 'Windows Update and is frequently years old. Compare `release`/`version` against '
                 'the current LTS.')
        L.append('')
    if R['python']['present']:
        L += [f"## Python ({R['python']['modules']} .py modules, {len(R['python']['frozen'])} frozen bundles)", '']
        for s in sorted(R['python']['sinks'], key=lambda x: -x['severity'])[:40]:
            L += [f"- **{s['sink']}** ({s['severity']}/10) in `{s['file']}`",
                  f"  - {s['why']}", f"  - `{s['context']}`"]
        L.append('')
        L.append('> Bundled `.pyc` decompile: `pip install decompyle3 xdis` or `uncompyle6` for '
                 '<=3.8. The PyInstaller CArchive is already extracted under `_unpacked/`.')
        L.append('')
    if R['node']['present']:
        L += [f"## Node ({len(R['node']['packages'])} package.json, "
              f"{len(R['node']['native_modules'])} native modules)", '']
        for x in R['node']['lifecycle_scripts'][:20]:
            L.append(f"- {x['hook']} in `{x['file']}`: `{x['cmd']}`")
        for x in R['node']['native_modules'][:15]:
            L.append(f"- native module `{x}` — a .node is a DLL; it is in the DLL-hijack scope too")
        L.append('')
    if R['dotnet_probing']:
        L += [f"## .NET assembly resolution ({len(R['dotnet_probing'])} entries)", '',
              'Every probing path, codeBase and binding redirect is a place the CLR will load a DLL '
              'from. Cross-check each against the writable-path list in `surface.md`.', '']
        for x in R['dotnet_probing'][:40]:
            L.append(f"- `{x['file']}` — {x['kind']}: {x.get('probing_paths') or x.get('count')}")
        L.append('')
    if not lanes:
        L.append('_no embedded Java/Python/Node runtime and no managed probing configuration._')
    open(os.path.join(loot, 'runtime.md'), 'w').write('\n'.join(L))
    print(f"[runtime_lane] {R['counts']}")
    print(f'[runtime_lane] -> {loot}/runtime.json + runtime.md')


if __name__ == '__main__':
    main()
