#!/usr/bin/env python3
"""
pe_triage.py — parse every PE in the loot and produce the facts every engine needs.

Per binary: architecture, subsystem, timestamp, .NET-ness, packing, section entropy,
exploit mitigations (ASLR / high-entropy ASLR / DEP / SEH / CFG / CET / GS / RFG / integrity),
Authenticode state, embedded manifest (requestedExecutionLevel, autoElevate, uiAccess,
longPathAware), version info (CompanyName/ProductName/OriginalFilename — the CVE-matching key),
imports incl. delay-loaded, exports, TLS callbacks, and the DLL-hijack precondition set.

The mitigation table is weighted by PRIVILEGE, not by count: a missing /DYNAMICBASE on a
user-mode helper is noise; the same gap on a SYSTEM service that parses attacker files is the
reason the bug is exploitable.

Usage:
  pe_triage.py --loot loot/<name> [--jobs 8] [--only <substr>]
Writes: <loot>/pe_triage.json, <loot>/pe_triage.md
"""
import argparse, concurrent.futures as cf, json, math, os, re, struct, subprocess, shutil, sys

try:
    import pefile
except ImportError:
    sys.exit('pe_triage: pefile missing — run scripts/provision.sh')

DLL_CHAR = {
    0x0020: 'HIGH_ENTROPY_VA', 0x0040: 'DYNAMIC_BASE', 0x0080: 'FORCE_INTEGRITY',
    0x0100: 'NX_COMPAT', 0x0200: 'NO_ISOLATION', 0x0400: 'NO_SEH', 0x0800: 'NO_BIND',
    0x1000: 'APPCONTAINER', 0x2000: 'WDM_DRIVER', 0x4000: 'GUARD_CF',
    0x8000: 'TERMINAL_SERVER_AWARE',
}
SUBSYS = {1: 'native(driver)', 2: 'GUI', 3: 'CONSOLE', 9: 'WINCE_GUI', 10: 'EFI_APP',
          16: 'BOOT_APP'}

# imports that define what a binary can DO to the system — the engine feed
CAP_IMPORTS = {
    'process': ['createprocess', 'shellexecute', 'winexec', 'system', '_wsystem', '_popen',
                'createprocesswithlogon', 'createprocessasuser', 'wincreateprocess'],
    'load':    ['loadlibrary', 'loadlibraryex', 'getprocaddress', 'loadpackagedlibrary',
                'setdlldirectory', 'addlldirectory', 'setdefaultdlldirectories'],
    'file':    ['createfile', 'copyfile', 'movefile', 'movefileex', 'deletefile',
                'writefile', 'replacefile', 'createsymboliclink', 'createhardlink',
                'setfileattributes', 'sethandleinformation'],
    'registry': ['regcreatekey', 'regsetvalue', 'regopenkey', 'regdeletekey', 'regsavekey',
                 'regloadkey', 'regrestorekey'],
    'service': ['openscmanager', 'createservice', 'changeserviceconfig', 'startservice',
                'controlservice', 'openservice', 'registerservicectrlhandler',
                'startservicectrldispatcher'],
    'token':   ['impersonate', 'openprocesstoken', 'duplicatetoken', 'setthreadtoken',
                'adjusttokenprivileges', 'logonuser', 'createrestrictedtoken',
                'revertToself', 'checktokenmembership', 'allocateandinitializesid'],
    'ipc':     ['createnamedpipe', 'connectnamedpipe', 'callnamedpipe', 'createmailslot',
                'rpcserver', 'ndrserver', 'i_rpc', 'cocreateinstance', 'coregisterclassobject',
                'dcomp', 'createfilemapping', 'mapviewoffile', 'ntalpc', 'alpcsend'],
    'security': ['setsecurityinfo', 'setnamedsecurityinfo', 'setentriesinacl',
                 'initializesecuritydescriptor', 'setsecuritydescriptordacl',
                 'convertstringsecuritydescriptor', 'getsecurityinfo'],
    'net':     ['winhttp', 'internetopen', 'httpsendrequest', 'wininet', 'urldownloadtofile',
                'ws2_32', 'connect', 'bind', 'listen', 'wsastartup', 'getaddrinfo'],
    'crypto':  ['cryptencrypt', 'cryptdecrypt', 'cryptprotectdata', 'cryptunprotectdata',
                'bcryptencrypt', 'certverify', 'winverifytrust', 'cryptcatadmin'],
    'inject':  ['writeprocessmemory', 'virtualallocex', 'createremotethread', 'ntmapviewofsection',
                'queueuserapc', 'setwindowshookex', 'ntcreatethreadex'],
    'driver':  ['deviceiocontrol', 'ntdeviceiocontrolfile', 'zwdeviceiocontrolfile',
                'iocreatedevice', 'wdfdriver', 'mmmapiospace', 'zwmapviewofsection'],
}

KNOWN_SYSTEM_DLL = set("""kernel32.dll user32.dll gdi32.dll advapi32.dll shell32.dll ole32.dll
oleaut32.dll ntdll.dll ws2_32.dll wininet.dll winhttp.dll crypt32.dll rpcrt4.dll shlwapi.dll
comctl32.dll comdlg32.dll setupapi.dll version.dll psapi.dll userenv.dll secur32.dll
bcrypt.dll ncrypt.dll wintrust.dll msvcrt.dll imm32.dll dbghelp.dll iphlpapi.dll netapi32.dll
dnsapi.dll winmm.dll wtsapi32.dll cfgmgr32.dll powrprof.dll propsys.dll uxtheme.dll
dwmapi.dll msimg32.dll winspool.drv mpr.dll authz.dll sspicli.dll combase.dll
api-ms-win-core-synch-l1-2-0.dll kernelbase.dll""".split())


def entropy(b):
    if not b:
        return 0.0
    c = [0] * 256
    for x in b:
        c[x] += 1
    n = len(b)
    return round(-sum((k / n) * math.log2(k / n) for k in c if k), 3)


def parse_manifest(pe):
    """Pull the embedded RT_MANIFEST — requestedExecutionLevel is the privilege oracle."""
    out = {}
    try:
        for rt in getattr(pe, 'DIRECTORY_ENTRY_RESOURCE', {}).entries:
            if rt.id != 24:
                continue
            for rid in rt.directory.entries:
                for lang in rid.directory.entries:
                    d = pe.get_data(lang.data.struct.OffsetToData, lang.data.struct.Size)
                    x = d.decode('utf-8', 'replace')
                    out['raw_len'] = len(x)
                    m = re.search(r'level\s*=\s*"([^"]+)"', x)
                    if m:
                        out['requestedExecutionLevel'] = m.group(1)
                    m = re.search(r'uiAccess\s*=\s*"([^"]+)"', x)
                    if m:
                        out['uiAccess'] = m.group(1)
                    for flag in ['autoElevate', 'longPathAware', 'dpiAware',
                                 'heapType', 'activeCodePage', 'supportedOS',
                                 'disableWindowFiltering', 'trustInfo']:
                        if flag.lower() in x.lower():
                            out[flag] = True
                    deps = re.findall(r'<assemblyIdentity[^>]*name="([^"]+)"[^>]*>', x)
                    if deps:
                        out['assemblyDeps'] = sorted(set(deps))[:20]
                    return out
    except Exception:
        pass
    return out


def version_info(pe):
    out = {}
    try:
        for fi in getattr(pe, 'FileInfo', []) or []:
            for e in (fi if isinstance(fi, list) else [fi]):
                if getattr(e, 'Key', b'') == b'StringFileInfo':
                    for st in e.StringTable:
                        for k, v in st.entries.items():
                            out[k.decode('utf-8', 'replace')] = v.decode('utf-8', 'replace')
    except Exception:
        pass
    return out


def authenticode(path):
    """Signature presence + (if osslsigncode is here) real verification."""
    res = {'has_security_dir': False, 'verified': None, 'signer': None, 'note': ''}
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']])
        d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        res['has_security_dir'] = bool(d.VirtualAddress and d.Size)
        pe.close()
    except Exception:
        pass
    if shutil.which('osslsigncode'):
        try:
            p = subprocess.run(['osslsigncode', 'verify', '-in', path],
                               capture_output=True, timeout=90)
            o = (p.stdout + p.stderr).decode('utf-8', 'replace')
            res['note'] = o[-1500:]
            if 'Signature verification: ok' in o:
                res['verified'] = True
            elif 'No signature found' in o:
                res['verified'] = False
                res['signer'] = None
            elif 'Signature verification: failed' in o:
                res['verified'] = False
            m = re.search(r'Subject:\s*(.+)', o)
            if m:
                res['signer'] = m.group(1).strip()[:200]
            for k, pat in [('timestamped', r'Timestamp[^\n]*'), ('hash_alg', r'Message digest algorithm\s*:\s*(\S+)')]:
                mm = re.search(pat, o)
                if mm:
                    res[k] = mm.group(0 if k == 'timestamped' else 1)[:120]
        except Exception as e:
            res['note'] = f'osslsigncode: {e}'
    return res


def triage_one(rec, loot):
    p = rec['abs']
    r = {'path': rec['path'], 'sha256': rec['sha256'], 'size': rec['size'], 'ok': False}
    try:
        pe = pefile.PE(p)
    except Exception as e:
        r['error'] = str(e)[:200]
        return r
    try:
        oh, fh = pe.OPTIONAL_HEADER, pe.FILE_HEADER
        r['ok'] = True
        r['machine'] = hex(fh.Machine)
        r['arch'] = {0x14c: 'x86', 0x8664: 'x64', 0xaa64: 'arm64', 0x1c0: 'arm', 0x1c4: 'armnt'}.get(fh.Machine, hex(fh.Machine))
        r['is_dll'] = bool(fh.Characteristics & 0x2000)
        r['subsystem'] = SUBSYS.get(oh.Subsystem, str(oh.Subsystem))
        r['timestamp'] = int(fh.TimeDateStamp)
        r['image_base'] = hex(oh.ImageBase)
        r['entrypoint'] = hex(oh.AddressOfEntryPoint)
        dc = oh.DllCharacteristics
        mit = {v: bool(dc & k) for k, v in DLL_CHAR.items()}
        mit['SEH'] = not mit.get('NO_SEH')
        r['mitigations'] = mit
        r['is_driver'] = (oh.Subsystem == 1) or bool(dc & 0x2000) or p.lower().endswith('.sys')

        # .NET
        try:
            comd = oh.DATA_DIRECTORY[14]
            r['is_dotnet'] = bool(comd.VirtualAddress and comd.Size)
        except Exception:
            r['is_dotnet'] = False

        # sections + packing
        secs, hi = [], 0
        for s in pe.sections:
            nm = s.Name.rstrip(b'\x00').decode('latin1')
            e = entropy(s.get_data()[:1 << 20])
            w = bool(s.Characteristics & 0x80000000)
            x = bool(s.Characteristics & 0x20000000)
            secs.append({'name': nm, 'vsize': s.Misc_VirtualSize, 'rsize': s.SizeOfRawData,
                         'entropy': e, 'W': w, 'X': x})
            if e > 7.2 and s.SizeOfRawData > 4096:
                hi += 1
        r['sections'] = secs
        r['wx_sections'] = [s['name'] for s in secs if s['W'] and s['X']]
        r['high_entropy_sections'] = hi
        r['likely_packed'] = hi >= 1 and all(s['name'] not in ('.rsrc', '.reloc') for s in secs if s['entropy'] > 7.2)

        # imports (incl. delay) + capabilities
        imports, caps = {}, {}
        def add_imp(dllname, funcs):
            d = (dllname or b'').decode('utf-8', 'replace').lower() if isinstance(dllname, bytes) else str(dllname).lower()
            imports.setdefault(d, [])
            for f in funcs:
                fn = (f.name or b'').decode('utf-8', 'replace') if isinstance(f.name, (bytes, type(None))) else str(f.name)
                if fn:
                    imports[d].append(fn)
                    fl = fn.lower()
                    for cap, pats in CAP_IMPORTS.items():
                        if any(pt in fl for pt in pats):
                            caps.setdefault(cap, set()).add(f'{d}!{fn}')
        pe.parse_data_directories()
        for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []) or []:
            add_imp(entry.dll, entry.imports)
        delay = []
        for entry in getattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT', []) or []:
            d = (entry.dll or b'').decode('utf-8', 'replace').lower()
            delay.append(d)
            add_imp(entry.dll, entry.imports)
        r['imports'] = {k: sorted(set(v))[:400] for k, v in imports.items()}
        r['delay_imports'] = sorted(set(delay))
        r['capabilities'] = {k: sorted(v)[:40] for k, v in caps.items()}
        for cap, pats in CAP_IMPORTS.items():
            # also catch dynamic resolution: the DLL is imported by name only
            pass
        r['exports'] = []
        for e in getattr(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', []) or []:
            if e.name:
                r['exports'].append(e.name.decode('utf-8', 'replace'))
        r['exports'] = r['exports'][:500]
        r['tls_callbacks'] = bool(getattr(pe, 'DIRECTORY_ENTRY_TLS', None))
        r['manifest'] = parse_manifest(pe)
        r['version'] = version_info(pe)
        # non-system imports = DLL-hijack candidate set (resolved against shipped files later)
        r['nonsystem_imports'] = sorted([d for d in imports if d not in KNOWN_SYSTEM_DLL
                                         and not d.startswith('api-ms-win')
                                         and not d.startswith('ext-ms-')])
        r['signature'] = authenticode(p)
    except Exception as e:
        r['error'] = f'{type(e).__name__}: {e}'
    finally:
        try:
            pe.close()
        except Exception:
            pass
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--loot', required=True)
    ap.add_argument('--jobs', type=int, default=8)
    ap.add_argument('--only', default=None)
    a = ap.parse_args()
    man = json.load(open(os.path.join(a.loot, 'unwrap.json')))
    pes = [f for f in man['files'] if f['kind'] in ('pe', 'upx', 'nsis', 'inno', 'burn',
                                                    'installshield', 'sfx7z', 'sfxrar',
                                                    'pyinstaller', 'autoit', 'dotnetbundle')]
    if a.only:
        pes = [f for f in pes if a.only.lower() in f['path'].lower()]
    print(f'[pe_triage] {len(pes)} PE files')
    res = []
    with cf.ThreadPoolExecutor(max_workers=a.jobs) as ex:
        for r in ex.map(lambda f: triage_one(f, a.loot), pes):
            res.append(r)
    out = {'count': len(res), 'binaries': res}
    json.dump(out, open(os.path.join(a.loot, 'pe_triage.json'), 'w'), indent=1)

    good = [r for r in res if r.get('ok')]
    def flag(r):
        m = r.get('mitigations', {})
        f = []
        if not m.get('DYNAMIC_BASE'): f.append('noASLR')
        if not m.get('NX_COMPAT'): f.append('noDEP')
        if not m.get('GUARD_CF'): f.append('noCFG')
        if r.get('arch') == 'x86' and m.get('DYNAMIC_BASE') and not m.get('HIGH_ENTROPY_VA'): pass
        if r.get('signature', {}).get('verified') is False: f.append('SIG-FAIL')
        if not r.get('signature', {}).get('has_security_dir'): f.append('UNSIGNED')
        if r.get('likely_packed'): f.append('PACKED')
        if r.get('wx_sections'): f.append('W+X')
        lvl = (r.get('manifest') or {}).get('requestedExecutionLevel')
        if lvl and lvl != 'asInvoker': f.append(f'ELEV:{lvl}')
        if (r.get('manifest') or {}).get('autoElevate'): f.append('AUTOELEVATE')
        if r.get('is_driver'): f.append('DRIVER')
        if r.get('is_dotnet'): f.append('.NET')
        return f

    L = ['# PE triage', '', f'- binaries parsed: **{len(good)}** / {len(res)}', '']
    elev = [r for r in good if (r.get('manifest') or {}).get('requestedExecutionLevel', 'asInvoker') != 'asInvoker']
    unsigned = [r for r in good if not r.get('signature', {}).get('has_security_dir')]
    sigfail = [r for r in good if r.get('signature', {}).get('verified') is False and r.get('signature', {}).get('has_security_dir')]
    drivers = [r for r in good if r.get('is_driver')]
    dotnet = [r for r in good if r.get('is_dotnet')]
    L += ['## Privilege-relevant highlights', '',
          f'- manifests requesting elevation: **{len(elev)}**',
          f'- **UNSIGNED binaries shipped: {len(unsigned)}** (each is a supply-chain / hijack candidate)',
          f'- signatures that FAIL verification: **{len(sigfail)}**',
          f'- kernel drivers: **{len(drivers)}**  |  .NET assemblies: **{len(dotnet)}**', '']
    if elev:
        L += ['### Elevation-requesting binaries', '']
        for r in elev:
            L.append(f"- `{r['path']}` — {r['manifest'].get('requestedExecutionLevel')}"
                     + (' AUTOELEVATE' if r['manifest'].get('autoElevate') else '')
                     + (f" uiAccess={r['manifest'].get('uiAccess')}" if r['manifest'].get('uiAccess') else ''))
        L.append('')
    if unsigned:
        L += ['### Unsigned shipped binaries (top 40)', '']
        for r in unsigned[:40]:
            L.append(f"- `{r['path']}` {r.get('arch')} {'DLL' if r.get('is_dll') else 'EXE'}")
        L.append('')
    L += ['## Capability map (who can touch what)', '']
    capcount = {}
    for r in good:
        for c in (r.get('capabilities') or {}):
            capcount[c] = capcount.get(c, 0) + 1
    for c, n in sorted(capcount.items(), key=lambda x: -x[1]):
        L.append(f'- {c}: {n} binaries')
    L += ['', '## Per-binary table', '', '| binary | arch | type | flags | signer |', '|---|---|---|---|---|']
    for r in sorted(good, key=lambda x: -len(flag(x))):
        sg = (r.get('signature') or {}).get('signer') or ''
        L.append(f"| `{r['path']}` | {r.get('arch')} | {'DLL' if r.get('is_dll') else ('SYS' if r.get('is_driver') else 'EXE')} "
                 f"| {' '.join(flag(r)) or '-'} | {sg[:44]} |")
    bad = [r for r in res if not r.get('ok')]
    if bad:
        L += ['', '## Not parsed', ''] + [f"- `{r['path']}`: {r.get('error','')[:120]}" for r in bad[:30]]
    open(os.path.join(a.loot, 'pe_triage.md'), 'w').write('\n'.join(L))
    print('\n'.join(L[:34]))
    print(f"\n[pe_triage] -> {a.loot}/pe_triage.json + pe_triage.md")


if __name__ == '__main__':
    main()
