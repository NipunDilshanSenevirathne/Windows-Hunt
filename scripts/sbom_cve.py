#!/usr/bin/env python3
"""
sbom_cve.py — build an SBOM from what is actually shipped, then map it to known CVEs.

Desktop apps bundle their whole dependency tree and update it rarely. A four-year-old
OpenSSL or a Chromium two majors behind is frequently the highest-impact finding in the whole
engagement, and it is cheap to prove: version string in, CVE list out.

Sources: embedded version banners (OpenSSL/zlib/curl/sqlite/libpng/libxml2/expat/freetype/
Qt/Chromium/CEF/Electron/node/python/openjpeg/libwebp...), .NET AssemblyRef versions,
package.json / package-lock, requirements.txt, *.nuspec, and PE VERSIONINFO.

CVE mapping uses OSV.dev (https://osv.dev) — a tooling service, queried only with
`--online`, and only with component names and versions. Nothing about the target's own
hosts or your traffic leaves the box, and `scope/authorized_hosts.txt` still governs any
request to the TARGET's own infrastructure (this is not that).

Usage:  sbom_cve.py --loot loot/<name> [--online] [--min-severity MEDIUM]
Writes: <loot>/sbom.json, <loot>/sbom.md
"""
import argparse, json, os, re, sys, urllib.request

# name, regex over strings, osv ecosystem+package (None = CPE-style, OSV 'OSS-Fuzz'/'CRAN' n/a)
BANNERS = [
    ('openssl',   r'OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)', ('OSS-Fuzz', 'openssl'), 'openssl'),
    ('zlib',      r'(?:deflate|inflate)\s+1\.(\d+\.\d+)\s+Copyright', None, 'zlib'),
    ('zlib2',     r'zlib version (\d+\.\d+\.\d+)', None, 'zlib'),
    ('libcurl',   r'libcurl/(\d+\.\d+\.\d+)', None, 'curl'),
    ('sqlite',    r'(?:SQLite version |3\.(?:\d+)\.(?:\d+)\x00)(\d+\.\d+\.\d+)', None, 'sqlite'),
    ('libpng',    r'libpng version (\d+\.\d+\.\d+)', None, 'libpng'),
    ('libjpeg',   r'libjpeg-turbo version (\d+\.\d+\.\d+)', None, 'libjpeg-turbo'),
    ('libwebp',   r'libwebp[ /-](\d+\.\d+\.\d+)', None, 'libwebp'),
    ('libxml2',   r'libxml2[ /-](\d+\.\d+\.\d+)', None, 'libxml2'),
    ('expat',     r'expat_(\d+\.\d+\.\d+)', None, 'expat'),
    ('freetype',  r'FreeType\s+(\d+\.\d+\.\d+)', None, 'freetype'),
    ('chromium',  r'Chrome/(\d+\.\d+\.\d+\.\d+)', None, 'chromium'),
    ('cef',       r'CEF/(\d+\.\d+\.\d+)', None, 'chromium'),
    ('electron',  r'Electron/(\d+\.\d+\.\d+)', ('npm', 'electron'), 'electron'),
    ('node',      r'node\.js/v?(\d+\.\d+\.\d+)', None, 'node.js'),
    ('nodev',     r'\bv(\d+\.\d+\.\d+)\s+node', None, 'node.js'),
    ('python',    r'Python (\d+\.\d+\.\d+)', ('PyPI', 'python'), 'python'),
    ('openjpeg',  r'openjpeg[ /-](\d+\.\d+\.\d+)', None, 'openjpeg'),
    ('libssh2',   r'libssh2/(\d+\.\d+\.\d+)', None, 'libssh2'),
    ('nghttp2',   r'nghttp2/(\d+\.\d+\.\d+)', None, 'nghttp2'),
    ('boost',     r'Boost (\d+\.\d+\.\d+)', None, 'boost'),
    ('qt',        r'Qt (\d+\.\d+\.\d+)', None, 'qt'),
    ('ffmpeg',    r'(?:Lavf|Lavc|FFmpeg version )(\d+\.\d+\.\d+)', None, 'ffmpeg'),
    ('7zip',      r'7-Zip (\d+\.\d+)', None, '7-zip'),
    ('log4net',   r'log4net[ ,-]?(\d+\.\d+\.\d+)', ('NuGet', 'log4net'), 'log4net'),
    ('newtonsoft', r'Newtonsoft\.Json[ ,-]?(\d+\.\d+\.\d+)', ('NuGet', 'Newtonsoft.Json'), 'newtonsoft.json'),
    ('jquery',    r'jQuery(?: JavaScript Library)? v(\d+\.\d+\.\d+)', ('npm', 'jquery'), 'jquery'),
    ('angular',   r'AngularJS v(\d+\.\d+\.\d+)', ('npm', 'angular'), 'angularjs'),
    ('bootstrap', r'Bootstrap v(\d+\.\d+\.\d+)', ('npm', 'bootstrap'), 'bootstrap'),
    ('openvpn',   r'OpenVPN (\d+\.\d+\.\d+)', None, 'openvpn'),
    ('libsodium', r'libsodium (\d+\.\d+\.\d+)', None, 'libsodium'),
    ('mbedtls',   r'mbed TLS (\d+\.\d+\.\d+)', None, 'mbedtls'),
    ('wolfssl',   r'wolfSSL (\d+\.\d+\.\d+)', None, 'wolfssl'),
]

# hard end-of-life / known-bad floors — usable offline, no network needed
EOL = [
    ('openssl',  lambda v: v < '1.1.1', 'OpenSSL < 1.1.1 is end-of-life (no security fixes since 2019) — '
                                        'includes unpatched CVE-2022-0778 DoS and the 1.0.2 padding/TLS issues'),
    ('openssl',  lambda v: v.startswith('3.0.') and _num(v) < (3, 0, 7), 'OpenSSL 3.0 < 3.0.7 — CVE-2022-3602/3786 X.509 buffer overflows'),
    ('electron', lambda v: _num(v)[0] < 28, 'Electron major older than the supported window — ships public, '
                                            'unpatched Chromium/Node RCEs'),
    ('chromium', lambda v: _num(v)[0] < 120, 'Chromium major far behind — dozens of public renderer RCEs'),
    ('node.js',  lambda v: _num(v)[0] < 18, 'Node.js EOL major'),
    ('curl',     lambda v: _num(v) < (7, 88, 0), 'curl < 7.88 — several heap overflows (CVE-2023-27536/38545 family)'),
    ('zlib',     lambda v: _num(v) < (1, 2, 12), 'zlib < 1.2.12 — CVE-2018-25032 memory corruption'),
    ('libwebp',  lambda v: _num(v) < (1, 3, 2), 'libwebp < 1.3.2 — CVE-2023-4863/5129 heap overflow, exploited in the wild'),
    ('sqlite',   lambda v: _num(v) < (3, 39, 2), 'SQLite < 3.39.2 — CVE-2022-35737 array-bounds overflow'),
    ('log4net',  lambda v: _num(v) < (2, 0, 10), 'log4net < 2.0.10 — CVE-2018-1285 XXE via config'),
    ('newtonsoft.json', lambda v: _num(v) < (13, 0, 1), 'Newtonsoft.Json < 13.0.1 — CVE-2024-21907 '
                                                        'StackOverflow DoS on deeply nested input'),
    ('jquery',   lambda v: _num(v) < (3, 5, 0), 'jQuery < 3.5.0 — CVE-2020-11022/11023 XSS in htmlPrefilter'),
    ('bootstrap', lambda v: _num(v) < (4, 3, 1), 'Bootstrap < 4.3.1 — XSS in data-template/tooltip'),
    ('angularjs', lambda v: True, 'AngularJS is end-of-life (Jan 2022) — no security fixes at any version'),
    ('python',   lambda v: _num(v) < (3, 9, 0), 'Python EOL minor'),
    ('freetype', lambda v: _num(v) < (2, 10, 4), 'FreeType < 2.10.4 — CVE-2020-15999 heap overflow, exploited in the wild'),
    ('expat',    lambda v: _num(v) < (2, 4, 9), 'expat < 2.4.9 — CVE-2022-40674 use-after-free'),
    ('libxml2',  lambda v: _num(v) < (2, 10, 3), 'libxml2 < 2.10.3 — CVE-2022-40303/40304'),
]


def _num(v):
    return tuple(int(x) for x in re.findall(r'\d+', v)[:4]) or (0,)


def strings_of(path, cap=24 << 20):
    try:
        with open(path, 'rb') as f:
            d = f.read(cap)
    except Exception:
        return ''
    out = b'\n'.join(re.findall(rb'[\x20-\x7e]{5,}', d)).decode('latin1')
    try:
        u = d.decode('utf-16-le', 'ignore')
        out += '\n' + '\n'.join(re.findall(r'[\x20-\x7e]{5,}', u))
    except Exception:
        pass
    return out


def osv_query(pkgs, timeout=30):
    """Batch query OSV.dev. pkgs = [(ecosystem, name, version)]"""
    out = {}
    qs = [{'version': v, 'package': {'name': n, 'ecosystem': e}} for e, n, v in pkgs]
    if not qs:
        return out
    try:
        req = urllib.request.Request(
            'https://api.osv.dev/v1/querybatch',
            data=json.dumps({'queries': qs}).encode(),
            headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
        for (e, n, v), res in zip(pkgs, data.get('results', [])):
            ids = [x.get('id') for x in (res.get('vulns') or [])]
            if ids:
                out[f'{e}:{n}@{v}'] = ids
    except Exception as ex:
        out['_error'] = str(ex)[:200]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--loot', required=True)
    ap.add_argument('--online', action='store_true', help='query OSV.dev for CVE ids')
    a = ap.parse_args()
    man = json.load(open(os.path.join(a.loot, 'unwrap.json')))
    comps = {}          # (component, version) -> set(files)

    def add(comp, ver, f):
        if not ver:
            return
        comps.setdefault((comp, ver), set()).add(f)

    for f in man['files']:
        if f['size'] == 0 or f['ext'] in ('.png', '.jpg', '.ico'):
            continue
        rel = f['path']
        if os.path.basename(rel).lower() in ('package.json', 'package-lock.json'):
            try:
                d = json.load(open(f['abs']))
                for sec in ('dependencies', 'devDependencies'):
                    for k, v in (d.get(sec) or {}).items():
                        if isinstance(v, str):
                            add(k.lower(), v.lstrip('^~>=< '), rel)
                        elif isinstance(v, dict) and v.get('version'):
                            add(k.lower(), v['version'], rel)
            except Exception:
                pass
            continue
        if f['ext'] in ('.nuspec',):
            t = open(f['abs'], 'rb').read().decode('utf-8', 'replace')
            for m in re.finditer(r'<dependency\s+id="([^"]+)"\s+version="([^"]+)"', t):
                add(m.group(1).lower(), m.group(2), rel)
            continue
        if f['kind'] != 'pe' and f['ext'] not in ('.dll', '.exe', '.node', '.pyd', '.js', '.txt'):
            continue
        t = strings_of(f['abs'])
        if not t:
            continue
        for _, rx, _, canon in BANNERS:
            for m in re.finditer(rx, t):
                add(canon, m.group(1), rel)

    # .NET AssemblyRefs
    dp = os.path.join(a.loot, 'dotnet_il.json')
    if os.path.isfile(dp):
        for r in json.load(open(dp))['results']:
            for ref in r.get('refs', []):
                parts = ref.rsplit(' ', 1)
                if len(parts) == 2:
                    add(parts[0].lower(), parts[1], r['path'])

    rows = []
    for (c, v), files in sorted(comps.items()):
        eol = [note for name, test, note in EOL if name == c and _safe(test, v)]
        rows.append({'component': c, 'version': v, 'files': sorted(files)[:5],
                     'known_issues': eol})
    online = {}
    if a.online:
        pk = []
        for r in rows:
            for eco, nm in (('npm', r['component']), ('NuGet', r['component']), ('PyPI', r['component'])):
                pass
        # only query ecosystems OSV actually indexes by name
        for r in rows:
            c, v = r['component'], r['version']
            if not re.match(r'^\d', v):
                continue
            for eco in ('npm', 'NuGet', 'PyPI'):
                pk.append((eco, c, v))
        online = osv_query(pk[:400])
        for r in rows:
            for eco in ('npm', 'NuGet', 'PyPI'):
                k = f"{eco}:{r['component']}@{r['version']}"
                if k in online:
                    r.setdefault('osv', []).extend(online[k])

    json.dump({'components': rows, 'osv_raw': online},
              open(os.path.join(a.loot, 'sbom.json'), 'w'), indent=1)
    flagged = [r for r in rows if r['known_issues'] or r.get('osv')]
    L = ['# SBOM & known-vulnerability exposure', '',
         f'- distinct components: **{len(rows)}**  ·  flagged: **{len(flagged)}**',
         '' if a.online else '- _offline mode: only the hard EOL/known-bad floors were applied. '
                             'Re-run with `--online` to resolve CVE ids from OSV.dev._', '']
    if flagged:
        L += ['## Flagged', '']
        for r in flagged:
            L += [f"### {r['component']} {r['version']}", '']
            for k in r['known_issues']:
                L.append(f'- **{k}**')
            if r.get('osv'):
                L.append(f"- OSV: {', '.join(sorted(set(r['osv']))[:20])}")
            L.append(f"- shipped in: {', '.join('`'+x+'`' for x in r['files'])}")
            L.append('')
        L += ['> To make a bundled-CVE finding land: name the exact shipped version, name the CVE,',
              '> and then answer the question a triager will ask — **is the vulnerable code path',
              '> reachable in this product?** A vulnerable image decoder in a binary that never',
              "> decodes untrusted images is an informational. Show the input path.", '']
    L += ['## Full inventory', '', '| component | version | shipped in |', '|---|---|---|']
    for r in rows:
        L.append(f"| {r['component']} | {r['version']} | `{r['files'][0] if r['files'] else ''}` |")
    open(os.path.join(a.loot, 'sbom.md'), 'w').write('\n'.join(L))
    print(f'[sbom_cve] {len(rows)} components, {len(flagged)} flagged')
    print(f'[sbom_cve] -> {a.loot}/sbom.json + sbom.md')


def _safe(test, v):
    try:
        return bool(test(v))
    except Exception:
        return False


if __name__ == '__main__':
    main()
