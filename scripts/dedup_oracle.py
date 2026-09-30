#!/usr/bin/env python3
"""
dedup_oracle.py — is this already public?

The fastest way to burn credibility with a triage team is to report something that has a CVE.
This checks the product's published history before you write, and scores each of YOUR candidate
findings against it: same class + same component + same product = probable duplicate.

Sources (all public tooling APIs — nothing about the target's own infrastructure is contacted):
  NVD   services.nvd.nist.gov keyword search over the product and vendor names
  OSV   api.osv.dev for every bundled component+version in sbom.json

It also prints the searches you should run by hand, because vendor advisories and the
program's own disclosed-report list are where the near-duplicates actually live.

Usage:
  dedup_oracle.py --loot loot/<name> [--product "Acme Desktop"] [--vendor Acme] [--offline]
Writes: <loot>/dedup.json, <loot>/dedup.md
"""
import argparse, json, os, re, time, urllib.parse, urllib.request
from collections import Counter

NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}&resultsPerPage=60'

# how our finding classes map onto CVE description language
CLASS_WORDS = {
    'dll-hijack': ['dll', 'search order', 'hijack', 'side-load', 'sideload', 'preload', 'planting'],
    'unquoted-path': ['unquoted', 'service path'],
    'weak-acl': ['permission', 'acl', 'incorrect default permissions', 'privilege escalation',
                 'writable', 'access control'],
    'lpe': ['privilege escalation', 'elevation of privilege', 'local privilege'],
    'uri-handler': ['uri', 'protocol handler', 'custom scheme', 'deep link', 'argument injection'],
    'localhost': ['localhost', '127.0.0.1', 'cors', 'origin', 'websocket', 'dns rebinding'],
    'update-channel': ['update', 'signature', 'verification', 'downgrade', 'man-in-the-middle'],
    'deserialization': ['deserial', 'binaryformatter', 'gadget'],
    'electron': ['electron', 'nodeintegration', 'context isolation', 'chromium'],
    'driver': ['ioctl', 'driver', 'kernel', 'device'],
    'secrets': ['hardcoded', 'hard-coded', 'credential', 'key', 'password'],
    'com': ['com object', 'clsid', 'dcom', 'activation'],
    'pipe-rpc': ['named pipe', 'rpc', 'ipc', 'inter-process'],
    'traversal': ['path traversal', 'directory traversal', 'zip slip', '../'],
    'memory': ['buffer overflow', 'out-of-bounds', 'use-after-free', 'heap', 'memory corruption'],
}


def get(url, timeout=40):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'windowshunt-dedup/1.0'})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.load(r)
    except Exception as e:
        return {'_error': str(e)[:160]}


def nvd_search(term):
    d = get(NVD.format(urllib.parse.quote(term)))
    if '_error' in d:
        return [], d['_error']
    out = []
    for v in d.get('vulnerabilities', []):
        c = v.get('cve', {})
        desc = next((x['value'] for x in c.get('descriptions', []) if x.get('lang') == 'en'), '')
        metrics = c.get('metrics', {})
        score = None
        for k in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
            if metrics.get(k):
                score = metrics[k][0].get('cvssData', {}).get('baseScore')
                break
        out.append({'id': c.get('id'), 'published': (c.get('published') or '')[:10],
                    'score': score, 'description': desc[:400]})
    return out, None


def classify(desc):
    d = desc.lower()
    return sorted({k for k, words in CLASS_WORDS.items() if any(w in d for w in words)})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--loot', required=True)
    ap.add_argument('--product', default=None)
    ap.add_argument('--vendor', default=None)
    ap.add_argument('--offline', action='store_true')
    a = ap.parse_args()
    loot = a.loot

    def J(n):
        p = os.path.join(loot, n)
        return json.load(open(p)) if os.path.isfile(p) else {}

    tri, unwrap = J('pe_triage.json'), J('unwrap.json')
    # product / vendor from VERSIONINFO if not given
    prods, vendors = Counter(), Counter()
    for b in tri.get('binaries', []):
        v = b.get('version') or {}
        if v.get('ProductName'):
            prods[v['ProductName'].strip()] += 1
        if v.get('CompanyName'):
            vendors[v['CompanyName'].strip()] += 1
    product = a.product or (prods.most_common(1)[0][0] if prods else
                            os.path.basename(unwrap.get('target', 'unknown')))
    vendor = a.vendor or (vendors.most_common(1)[0][0] if vendors else '')

    res = {'product': product, 'vendor': vendor, 'nvd': [], 'osv': {}, 'errors': []}
    if not a.offline:
        seen = set()
        for term in [t for t in (product, vendor) if t]:
            rows, err = nvd_search(term)
            if err:
                res['errors'].append(f'NVD "{term}": {err}')
            for r in rows:
                if r['id'] in seen:
                    continue
                seen.add(r['id'])
                r['classes'] = classify(r['description'])
                r['matched_term'] = term
                res['nvd'].append(r)
            time.sleep(6)          # NVD asks for <=5 req/30s without a key
        sb = J('sbom.json')
        pk = []
        for c in sb.get('components', []):
            if re.match(r'^\d', c.get('version', '')):
                for eco in ('npm', 'NuGet', 'PyPI'):
                    pk.append({'package': {'name': c['component'], 'ecosystem': eco},
                               'version': c['version']})
        if pk:
            try:
                req = urllib.request.Request('https://api.osv.dev/v1/querybatch',
                                             data=json.dumps({'queries': pk[:300]}).encode(),
                                             headers={'Content-Type': 'application/json'})
                with urllib.request.urlopen(req, timeout=40) as r:
                    data = json.load(r)
                for q, rr in zip(pk, data.get('results', [])):
                    ids = [x.get('id') for x in (rr.get('vulns') or [])]
                    if ids:
                        res['osv'][f"{q['package']['name']}@{q['version']}"] = ids[:25]
            except Exception as e:
                res['errors'].append(f'OSV: {e}')

    # ---- score OUR candidate findings against the published history -------------
    ours = []
    for eng, key, cls in [
        ('dll_hijack.json', 'findings', 'dll-hijack'),
        ('com.json', 'findings', 'com'),
        ('secrets.json', 'hits', 'secrets'),
        ('drivers.json', 'drivers', 'driver'),
    ]:
        d = J(eng)
        n = len(d.get(key) or [])
        if n:
            ours.append({'class': cls, 'count': n, 'source': eng})
    for eng, cls in [('electron.json', 'electron'), ('runtime.json', 'deserialization'),
                     ('integration.json', 'lpe'), ('signing.json', 'update-channel')]:
        d = J(eng)
        if d:
            ours.append({'class': cls, 'count': len(d.get('findings') or d.get('issues') or
                                                    d.get('sinks') or []), 'source': eng})
    published = Counter()
    for r in res['nvd']:
        for c in r.get('classes', []):
            published[c] += 1
    for o in ours:
        hits = [r for r in res['nvd'] if o['class'] in r.get('classes', [])]
        o['published_same_class'] = len(hits)
        o['examples'] = [f"{h['id']} ({h['published']})" for h in hits[:4]]
        o['dup_risk'] = ('HIGH — this exact class already has CVEs for this product'
                         if len(hits) >= 3 else
                         'MEDIUM — the class appears in this product\'s history'
                         if hits else
                         'LOW — no published CVE in this class for this product')
    res['our_classes'] = ours

    json.dump(res, open(os.path.join(loot, 'dedup.json'), 'w'), indent=1)

    L = ['# Duplicate / novelty check', '',
         f'- product: **{product}**  ·  vendor: **{vendor or "unknown"}**',
         f"- published CVEs matched: **{len(res['nvd'])}**"
         + ('  _(offline mode — nothing queried)_' if a.offline else ''), '']
    if res['errors']:
        L += ['> lookup errors: ' + '; '.join(res['errors']), '']
    if ours:
        L += ['## Your finding classes vs the published history', '',
              '| your class | candidates | published CVEs in this class | duplicate risk |',
              '|---|---|---|---|']
        for o in sorted(ours, key=lambda x: -x['published_same_class']):
            L.append(f"| {o['class']} | {o['count']} | {o['published_same_class']} "
                     f"{'(' + ', '.join(o['examples']) + ')' if o['examples'] else ''} | "
                     f"{o['dup_risk'].split(' —')[0]} |")
        L += ['', 'A HIGH row does not mean stop — it means **read those CVEs first**. Either your '
              'finding is the same bug in a new place (still reportable, cite the prior art and say '
              'what is different), or the vendor fixed one instance and missed yours (a strong '
              'report: "the fix for CVE-x did not cover y").', '']
    if published:
        L += ['## What this product has historically been vulnerable to', '']
        for c, n in published.most_common():
            L.append(f'- **{c}**: {n} CVE(s)')
        L += ['', 'This is also a hunting map: a vendor that shipped three DLL-hijack CVEs has a '
              'systemic loader problem, and the next one is probably still there.', '']
    if res['nvd']:
        L += ['## Published CVEs', '', '| CVE | date | CVSS | classes | description |', '|---|---|---|---|---|']
        for r in sorted(res['nvd'], key=lambda x: x['published'], reverse=True)[:60]:
            L.append(f"| {r['id']} | {r['published']} | {r['score'] or ''} | "
                     f"{', '.join(r.get('classes', []))} | {r['description'][:150].replace('|','/')} |")
        L.append('')
    if res['osv']:
        L += ['## Bundled components with known vulnerabilities (OSV)', '']
        for k, v in res['osv'].items():
            L.append(f"- `{k}`: {', '.join(v[:12])}")
        L.append('')
    q = urllib.parse.quote(product)
    L += ['## Searches to run by hand (this is where near-duplicates hide)', '', '```',
          f'https://nvd.nist.gov/vuln/search/results?query={q}',
          f'https://github.com/advisories?query={q}',
          f'https://www.exploit-db.com/search?q={q}',
          f'https://www.google.com/search?q=%22{q}%22+(CVE+OR+advisory+OR+%22privilege+escalation%22)',
          f'https://hackerone.com/hacktivity?querystring={q}      # disclosed reports',
          f'https://www.zerodayinitiative.com/advisories/published/?q={q}',
          '<vendor>/security  ·  <vendor>/security-advisories  ·  the product release notes',
          '```', '',
          'Release notes are the most underused source: "fixed an issue where the updater could '
          'load a library from the working directory" is a silently-fixed CVE-class bug, and it '
          'tells you both what to look for and which older version still has it.']
    open(os.path.join(loot, 'dedup.md'), 'w').write('\n'.join(L))
    print(f"[dedup_oracle] product='{product}' vendor='{vendor}' "
          f"{len(res['nvd'])} CVEs, {len(res['osv'])} vulnerable components")
    print(f'[dedup_oracle] -> {loot}/dedup.json + dedup.md')


if __name__ == '__main__':
    main()
