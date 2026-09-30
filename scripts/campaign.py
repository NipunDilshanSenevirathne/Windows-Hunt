#!/usr/bin/env python3
"""
campaign.py — hunt a vendor's portfolio, not one product.

Vendors ship the same updater, the same service, the same installer framework and the same
bundled libraries across their whole product line. A weakness in a shared component is a
platform-scale finding for the same work as one product — and it is the argument that turns a
Medium into a High, because the vendor has to fix it everywhere.

This correlates every loot directory:

  SHARED BINARIES     identical sha256 across products: one bug, N products
  SHARED COMPONENTS   the same bundled library and version everywhere (one CVE, N products)
  SHARED SURFACES     the same pipe name, service name, URI scheme, CLSID or update host
  DIVERGENT VERSIONS  the same component at DIFFERENT versions — the older one is unpatched,
                      and the newer one tells you what was fixed
  FINDING OVERLAP     the same finding class recurring, which is a systemic engineering problem
                      and worth saying out loud in the report

Usage:
  campaign.py --loots loot/prodA loot/prodB loot/prodC
  campaign.py --all                   # every directory under loot/
Writes: loot/_campaign/campaign.json + campaign.md
"""
import argparse, glob, json, os
from collections import defaultdict

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def J(loot, name):
    p = os.path.join(loot, name)
    if not os.path.isfile(p):
        return {}
    try:
        return json.load(open(p))
    except Exception:
        return {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--loots', nargs='*', default=[])
    ap.add_argument('--all', action='store_true')
    ap.add_argument('--out', default=None)
    a = ap.parse_args()
    loots = a.loots
    if a.all or not loots:
        loots = sorted(d for d in glob.glob(os.path.join(HERE, 'loot', '*'))
                       if os.path.isdir(d) and os.path.isfile(os.path.join(d, 'unwrap.json')))
    loots = [l for l in loots if os.path.isfile(os.path.join(l, 'unwrap.json'))]
    if len(loots) < 2:
        print(f'[campaign] need at least 2 analysed targets, found {len(loots)}')
        print('           run scripts/hunt.sh for each product first')
        return
    names = [os.path.basename(l.rstrip('/')) for l in loots]
    print(f'[campaign] correlating: {", ".join(names)}')

    sha = defaultdict(set)         # sha256 -> {product}
    shaname = {}
    comp = defaultdict(lambda: defaultdict(set))   # component -> version -> {product}
    surf = defaultdict(lambda: defaultdict(set))   # kind -> value -> {product}
    finds = defaultdict(lambda: defaultdict(int))  # product -> class -> count
    publishers = defaultdict(set)

    for l, n in zip(loots, names):
        for f in J(l, 'unwrap.json').get('files', []):
            if f.get('kind') == 'pe' and f.get('sha256') and f['sha256'] != 'skipped-large':
                sha[f['sha256']].add(n)
                shaname.setdefault(f['sha256'], os.path.basename(f['path']))
        for c in J(l, 'sbom.json').get('components', []):
            comp[c['component']][c['version']].add(n)
        s = J(l, 'surface.json')
        for kind, key in (('pipes', 'pipes'), ('uri_handlers', 'uri_handlers'),
                          ('services', 'services'), ('update_endpoints', 'update_endpoints'),
                          ('listeners', 'listeners'), ('com', 'com')):
            for r in (s.get(key) or []):
                v = r['v']
                v = (v.get('name') or v.get('guid') or v.get('url') or json.dumps(v, sort_keys=True)) \
                    if isinstance(v, dict) else str(v)
                if v:
                    surf[kind][str(v)[:120]].add(n)
        for eng, key, cls in (('dll_hijack.json', 'findings', 'dll-hijack'),
                              ('toctou.json', 'findings', 'toctou'),
                              ('com.json', 'findings', 'com'),
                              ('process.json', 'findings', 'process'),
                              ('credstore.json', 'findings', 'credstore'),
                              ('runtime.json', 'findings', 'runtime'),
                              ('secrets.json', 'hits', 'secrets')):
            finds[n][cls] = len(J(l, eng).get(key) or [])
        for p, _c in (J(l, 'signing.json').get('publishers') or []):
            publishers[p].add(n)

    shared_bins = sorted(((shaname[h], h, sorted(ps)) for h, ps in sha.items() if len(ps) > 1),
                         key=lambda x: -len(x[2]))
    shared_comp = []
    divergent = []
    for c, vers in comp.items():
        allp = set().union(*vers.values())
        if len(vers) == 1 and len(allp) > 1:
            v = next(iter(vers))
            shared_comp.append({'component': c, 'version': v, 'products': sorted(allp)})
        elif len(vers) > 1:
            divergent.append({'component': c,
                              'versions': {v: sorted(ps) for v, ps in sorted(vers.items())}})
    shared_surf = {k: sorted(((v, sorted(ps)) for v, ps in d.items() if len(ps) > 1),
                             key=lambda x: -len(x[1]))
                   for k, d in surf.items()}
    shared_surf = {k: v for k, v in shared_surf.items() if v}

    out = a.out or os.path.join(HERE, 'loot', '_campaign')
    os.makedirs(out, exist_ok=True)
    data = {'products': names, 'shared_binaries': [{'name': n2, 'sha256': h, 'products': p}
                                                   for n2, h, p in shared_bins[:200]],
            'shared_components': shared_comp, 'divergent_components': divergent,
            'shared_surfaces': shared_surf, 'findings_by_product': finds,
            'publishers': {k: sorted(v) for k, v in publishers.items()}}
    json.dump(data, open(os.path.join(out, 'campaign.json'), 'w'), indent=1)

    L = ['# Campaign correlation', '',
         f"- products analysed: **{len(names)}** ({', '.join(names)})",
         f'- binaries shared between products: **{len(shared_bins)}**',
         f'- components at the same version everywhere: **{len(shared_comp)}**',
         f'- components at DIFFERENT versions: **{len(divergent)}**', '',
         '> A weakness in anything below is a **platform finding**. Say so in the report: it',
         '> changes the severity argument and it changes what the vendor has to fix.', '']
    if shared_bins:
        L += ['## Shared binaries (byte-identical)', '', '| binary | products | sha256 |', '|---|---|---|']
        for n2, h, ps in shared_bins[:50]:
            L.append(f"| `{n2}` | **{len(ps)}**: {', '.join(ps)} | `{h[:16]}` |")
        L += ['', 'Hunt these ONCE. Every finding in a shared binary multiplies by the number of '
              'products that ship it — and by every other vendor who licenses the same component.', '']
    if shared_comp:
        L += ['## Components shipped at one version across the line', '',
              '| component | version | products |', '|---|---|---|']
        for c in sorted(shared_comp, key=lambda x: -len(x['products']))[:40]:
            L.append(f"| {c['component']} | {c['version']} | {', '.join(c['products'])} |")
        L += ['', 'One CVE here is one report covering the whole line.', '']
    if divergent:
        L += ['## Components at DIFFERENT versions (the fastest lead in the file)', '']
        for d in divergent[:30]:
            vs = ' · '.join(f"**{v}** ({', '.join(ps)})" for v, ps in d['versions'].items())
            L.append(f"- `{d['component']}`: {vs}")
        L += ['', 'Read this as a diff: the product on the OLDER version is missing whatever the '
              'newer one fixed. Check the component\'s changelog between the two versions, then '
              'test the older product for exactly that bug. This is the single highest-yield '
              'correlation in a portfolio audit.', '']
    for kind, rows in shared_surf.items():
        L += [f'## Shared {kind}', '']
        for v, ps in rows[:25]:
            L.append(f"- `{v}` — {', '.join(ps)}")
        L.append('')
    L += ['## Finding classes by product', '', '| class | ' + ' | '.join(names) + ' |',
          '|---' * (len(names) + 1) + '|']
    classes = sorted({c for d in finds.values() for c in d})
    for c in classes:
        L.append(f'| {c} | ' + ' | '.join(str(finds[n].get(c, 0)) for n in names) + ' |')
    L += ['', 'A class that is non-zero in every column is a **systemic engineering problem**, '
          'not N separate bugs. Report it that way — one root-cause report about the shared '
          'pattern lands better than five instance reports, and it is harder to close as '
          '"fixed in the next release of product A".', '']
    if publishers:
        L += ['## Signing publishers across the line', '']
        for p, ps in sorted(publishers.items(), key=lambda x: -len(x[1]))[:20]:
            L.append(f'- `{p}` — {", ".join(sorted(ps))}')
    open(os.path.join(out, 'campaign.md'), 'w').write('\n'.join(L))
    print(f'[campaign] {len(shared_bins)} shared binaries, {len(shared_comp)} shared components, '
          f'{len(divergent)} divergent')
    print(f'[campaign] -> {out}/campaign.md')


if __name__ == '__main__':
    main()
