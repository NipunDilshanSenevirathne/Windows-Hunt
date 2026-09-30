#!/usr/bin/env python3
"""
version_diff.py — hunt what CHANGED. The lowest-duplicate surface that exists.

Everything shipped in version N-1 has been looked at by everyone else. The code added last
month has not. This diffs two unwrapped loots and tells you precisely where to spend the hunt:
new binaries, new imports (new capability), new exports, new surfaces (pipes, URIs, listeners,
services), new endpoints, changed manifests (a binary that just started requesting elevation),
lost mitigations, and changed signing.

It also works backwards: a binary whose imports SHRANK, or whose manifest dropped from
requireAdministrator to asInvoker, is a silent security fix — and a silent fix is a map to the
bug that was there in the older version, which is often still installed on real machines.

Usage:
  scripts/hunt.sh --target old/Setup.exe --name acme-4.1
  scripts/hunt.sh --target new/Setup.exe --name acme-4.2
  version_diff.py --old loot/acme-4.1 --new loot/acme-4.2
Writes: <new>/version_diff.json, <new>/version_diff.md
"""
import argparse, json, os
from collections import defaultdict


def J(loot, name, default=None):
    p = os.path.join(loot, name)
    if not os.path.isfile(p):
        return default if default is not None else {}
    try:
        return json.load(open(p))
    except Exception:
        return default if default is not None else {}


def norm(path):
    """Compare by the path *inside* the package, ignoring the unpack-hash directory names."""
    parts = path.replace('\\', '/').split('/')
    parts = [p for p in parts if not p.startswith('_unpacked') and '_' not in p[:2]]
    keep = []
    for p in parts:
        if len(p) > 12 and p.count('_') >= 2 and any(c.isdigit() for c in p):
            continue
        keep.append(p)
    return '/'.join(keep[-4:]).lower()


def surf_set(s, key, f=lambda v: str(v)):
    return {f(r['v']) for r in (s.get(key) or [])}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--old', required=True)
    ap.add_argument('--new', required=True)
    a = ap.parse_args()
    O, N = a.old, a.new
    D = {'old': O, 'new': N}

    om, nm = J(O, 'unwrap.json'), J(N, 'unwrap.json')
    ot = {b['path']: b for b in J(O, 'pe_triage.json', {}).get('binaries', []) if b.get('ok')}
    nt = {b['path']: b for b in J(N, 'pe_triage.json', {}).get('binaries', []) if b.get('ok')}
    ob = {norm(k): v for k, v in ot.items()}
    nb = {norm(k): v for k, v in nt.items()}

    oh = {f['sha256']: norm(f['path']) for f in om.get('files', [])}
    nh = {f['sha256']: norm(f['path']) for f in nm.get('files', [])}
    onames = {norm(f['path']) for f in om.get('files', [])}
    nnames = {norm(f['path']) for f in nm.get('files', [])}

    D['files'] = {
        'added': sorted(nnames - onames)[:400],
        'removed': sorted(onames - nnames)[:400],
        'changed': sorted({v for k, v in nh.items() if k not in oh and v in onames})[:400],
        'identical': len(set(oh) & set(nh)),
    }

    # --- per-binary capability deltas ------------------------------------------------
    caps, mits, mani, sigs = [], [], [], []
    for name in sorted(set(ob) & set(nb)):
        o, n = ob[name], nb[name]
        oi = {f"{d}!{f}" for d, fs in (o.get('imports') or {}).items() for f in fs}
        ni = {f"{d}!{f}" for d, fs in (n.get('imports') or {}).items() for f in fs}
        addi, remi = ni - oi, oi - ni
        ocap, ncap = set(o.get('capabilities') or {}), set(n.get('capabilities') or {})
        if addi or remi or ocap != ncap:
            caps.append({'binary': name,
                         'new_capabilities': sorted(ncap - ocap),
                         'lost_capabilities': sorted(ocap - ncap),
                         'new_imports': sorted(addi)[:40],
                         'removed_imports': sorted(remi)[:40],
                         'new_import_count': len(addi), 'removed_import_count': len(remi)})
        om_, nm_ = o.get('mitigations') or {}, n.get('mitigations') or {}
        lost = [k for k in nm_ if om_.get(k) and not nm_.get(k)]
        gained = [k for k in nm_ if not om_.get(k) and nm_.get(k)]
        if lost or gained:
            mits.append({'binary': name, 'lost': lost, 'gained': gained})
        oml, nml = (o.get('manifest') or {}), (n.get('manifest') or {})
        if oml.get('requestedExecutionLevel') != nml.get('requestedExecutionLevel') or \
           bool(oml.get('autoElevate')) != bool(nml.get('autoElevate')):
            mani.append({'binary': name,
                         'old': oml.get('requestedExecutionLevel'), 'new': nml.get('requestedExecutionLevel'),
                         'old_autoelevate': bool(oml.get('autoElevate')),
                         'new_autoelevate': bool(nml.get('autoElevate'))})
        os_, ns_ = (o.get('signature') or {}), (n.get('signature') or {})
        if bool(os_.get('has_security_dir')) != bool(ns_.get('has_security_dir')) or \
           (os_.get('signer') or '') != (ns_.get('signer') or ''):
            sigs.append({'binary': name, 'old_signed': bool(os_.get('has_security_dir')),
                         'new_signed': bool(ns_.get('has_security_dir')),
                         'old_signer': os_.get('signer'), 'new_signer': ns_.get('signer')})
    D['capability_changes'] = sorted(caps, key=lambda x: -(len(x['new_capabilities']) * 10 + x['new_import_count']))[:60]
    D['mitigation_changes'] = mits
    D['manifest_changes'] = mani
    D['signing_changes'] = sigs

    # --- surface deltas ----------------------------------------------------------------
    osf, nsf = J(O, 'surface.json'), J(N, 'surface.json')
    sd = {}
    for key in ('services', 'pipes', 'uri_handlers', 'listeners', 'update_endpoints',
                'http_cleartext', 'com', 'tasks', 'registry_writes', 'autoruns',
                'install_paths', 'plugin_dirs', 'sddl', 'custom_actions'):
        old_s, new_s = surf_set(osf, key), surf_set(nsf, key)
        add, rem = sorted(new_s - old_s), sorted(old_s - new_s)
        if add or rem:
            sd[key] = {'added': add[:40], 'removed': rem[:40]}
    D['surface_changes'] = sd

    # --- engine deltas -----------------------------------------------------------------
    oh2 = {(f['dll'], norm(f['loader'])) for f in J(O, 'dll_hijack.json', {}).get('findings', [])}
    nh2 = {(f['dll'], norm(f['loader'])) for f in J(N, 'dll_hijack.json', {}).get('findings', [])}
    D['new_hijack_candidates'] = sorted(f'{d} <- {l}' for d, l in (nh2 - oh2))[:40]
    osb = {(c['component'], c['version']) for c in J(O, 'sbom.json', {}).get('components', [])}
    nsb = {(c['component'], c['version']) for c in J(N, 'sbom.json', {}).get('components', [])}
    upgraded = defaultdict(lambda: [None, None])
    for c, v in osb:
        upgraded[c][0] = v
    for c, v in nsb:
        upgraded[c][1] = v
    D['component_changes'] = [{'component': c, 'old': o, 'new': n}
                              for c, (o, n) in sorted(upgraded.items()) if o != n][:60]
    osk = {(h['type'], h['value']) for h in J(O, 'secrets.json', {}).get('hits', [])}
    nsk = {(h['type'], h['value']) for h in J(N, 'secrets.json', {}).get('hits', [])}
    D['new_secrets'] = [{'type': t, 'value': v[:60]} for t, v in sorted(nsk - osk)][:30]
    D['rotated_secrets'] = [{'type': t, 'value': v[:60]} for t, v in sorted(osk - nsk)][:30]

    json.dump(D, open(os.path.join(N, 'version_diff.json'), 'w'), indent=1)

    L = ['# Version diff — hunt what changed', '',
         f'- old: `{O}`  ·  new: `{N}`',
         f"- files: **+{len(D['files']['added'])}** added, **{len(D['files']['changed'])}** changed, "
         f"**-{len(D['files']['removed'])}** removed, {D['files']['identical']} byte-identical", '',
         '> New code is the lowest-duplicate surface there is. Work this list first, then the',
         '> "silent fix" section — a fix in the new version is a map to the bug still live in the old.',
         '']
    if D['files']['added']:
        L += ['## New files', ''] + [f'- `{x}`' for x in D['files']['added'][:60]] + ['']
    if D['capability_changes']:
        L += ['## Binaries that gained capability', '',
              'A binary that just learned to create processes, write the registry, touch tokens or '
              'talk IPC has new attack surface that nobody has looked at yet.', '']
        for c in D['capability_changes'][:30]:
            if not c['new_capabilities'] and c['new_import_count'] < 3:
                continue
            L += [f"### `{c['binary']}`",
                  f"- **new capabilities: {', '.join(c['new_capabilities']) or 'none'}**"
                  + (f" · lost: {', '.join(c['lost_capabilities'])}" if c['lost_capabilities'] else ''),
                  f"- +{c['new_import_count']} imports / -{c['removed_import_count']}"]
            if c['new_imports']:
                L.append(f"- new: {', '.join('`'+i+'`' for i in c['new_imports'][:14])}")
            L.append('')
    if D['manifest_changes']:
        L += ['## Elevation changes', '']
        for m in D['manifest_changes']:
            arrow = f"{m['old']} → {m['new']}"
            silent = (m['old'] in ('requireAdministrator', 'highestAvailable')
                      and m['new'] == 'asInvoker')
            L.append(f"- `{m['binary']}`: {arrow}"
                     + ('  **DROPPED ELEVATION — look for what they fixed; the old version still '
                        'has it**' if silent else ''))
        L.append('')
    if D['mitigation_changes']:
        L += ['## Mitigation changes', '']
        for m in D['mitigation_changes']:
            L.append(f"- `{m['binary']}`: lost {m['lost'] or '-'} · gained {m['gained'] or '-'}")
        L.append('')
    if D['signing_changes']:
        L += ['## Signing changes', '']
        for s in D['signing_changes']:
            L.append(f"- `{s['binary']}`: signed {s['old_signed']}→{s['new_signed']} "
                     f"signer `{(s['old_signer'] or '')[:40]}` → `{(s['new_signer'] or '')[:40]}`")
        L.append('')
    if D['surface_changes']:
        L += ['## Surface changes', '']
        for k, v in D['surface_changes'].items():
            L.append(f"### {k}")
            for x in v['added'][:20]:
                L.append(f"- **+** `{x[:150]}`")
            for x in v['removed'][:12]:
                L.append(f"- **−** `{x[:150]}`  _(removed — why? a removed pipe/handler is often a fix)_")
            L.append('')
    if D['new_hijack_candidates']:
        L += ['## New DLL-hijack candidates', ''] + [f'- `{x}`' for x in D['new_hijack_candidates']] + ['']
    if D['component_changes']:
        L += ['## Bundled component changes', '', '| component | old | new |', '|---|---|---|']
        for c in D['component_changes']:
            L.append(f"| {c['component']} | {c['old'] or '—'} | {c['new'] or '—'} |")
        L += ['', '> A component that jumped several versions in one release is usually a silent '
              'security update. Read that project\'s changelog between the two versions: the CVE '
              'they fixed is live in every install of the old version.', '']
    if D['new_secrets']:
        L += ['## New secrets', ''] + [f"- {s['type']}: `{s['value']}`" for s in D['new_secrets']] + ['']
    if D['rotated_secrets']:
        L += ['## Secrets that disappeared (rotated or removed)', ''] + \
             [f"- {s['type']}: `{s['value']}`" for s in D['rotated_secrets']] + ['']
    L += ['## How to use this', '',
          '1. Every **new file** and every binary with **new capability** goes in the ledger as a '
          'hypothesis before you look at anything else.',
          '2. Every **removed** surface and **dropped elevation** is a silent fix — reconstruct what '
          'it fixed, then check whether the old version is still supported/shipped. A live bug in '
          'a supported older release is a valid report.',
          '3. Component jumps → read the upstream changelog → map to a CVE → show reachability.']
    open(os.path.join(N, 'version_diff.md'), 'w').write('\n'.join(L))
    print(f"[version_diff] +{len(D['files']['added'])} files, "
          f"{len(D['capability_changes'])} capability deltas, "
          f"{len(D['surface_changes'])} surface categories changed")
    print(f'[version_diff] -> {N}/version_diff.json + version_diff.md')


if __name__ == '__main__':
    main()
