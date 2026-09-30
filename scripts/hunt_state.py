#!/usr/bin/env python3
"""
hunt_state.py — the hunt ledger. Every hypothesis, its evidence, its status, its score.

A long Windows audit dies from forgetting, not from lack of ideas: 300 binaries, 40 surfaces,
six engines, and the thing you noticed on hour two is gone by hour nine. This is the resumable
state — it survives context compaction, and refutations are first-class rows because a
recorded dead end is what stops you walking it twice.

Expected value keeps effort honest:

    EV = impact x reachability x (1 - dup_risk) x confidence x boundary_weight

`boundary` is the Windows-specific factor: a beautiful admin->SYSTEM trick scores near zero
because MSRC does not treat it as a boundary, which is the correct answer.

Usage:
  hunt_state.py init   --loot <loot> --target "Acme Desktop 4.2"
  hunt_state.py add    --loot <loot> --engine dll-hijack \\
        --hypothesis "AcmeSvc (SYSTEM) loads phantom wintls.dll from its install dir" \\
        --evidence "dll_hijack.md:12; pe_triage.json AcmeSvc.exe imports" \\
        --test "icacls the dir; Procmon NAME NOT FOUND; drop proxy dll; capture whoami" \\
        --boundary user-to-system [--impact 8] [--reach 0.6] [--dup 0.2] [--conf 0.4]
  hunt_state.py set    --loot <loot> --id H3 --status confirmed [--note ...] [--reach 1.0]
  hunt_state.py list   --loot <loot> [--status open] [--engine ...]
  hunt_state.py next   --loot <loot>
  hunt_state.py report --loot <loot>

Statuses: hypothesis | testing | blocked-no-vm | blocked-scope | confirmed | refuted | reported
"""
import argparse, json, os, time

STATUSES = ['hypothesis', 'testing', 'blocked-no-vm', 'blocked-scope', 'confirmed', 'refuted', 'reported']
OPEN = {'hypothesis', 'testing', 'blocked-no-vm', 'blocked-scope'}
BW = {'user-to-system': 1.0, 'user-to-admin': 1.0, 'service-to-system': 0.9, 'sandbox-escape': 1.0,
      'user-to-user': 0.95, 'remote-to-local': 1.0, 'web-to-local': 0.95, 'update-channel': 1.0,
      'network-to-local': 0.95, 'file-to-code': 0.9, 'admin-to-system': 0.15, 'uac-bypass': 0.15,
      'admin-precondition': 0.1, 'physical': 0.35, 'av-bypass': 0.1, 'same-user': 0.2,
      'unknown': 0.6}


def path(loot):
    return os.path.join(loot, 'ledger.json')


def load(loot):
    p = path(loot)
    return json.load(open(p)) if os.path.isfile(p) else {'target': None, 'created': None, 'rows': []}


def ev(r):
    return round(r.get('impact', 5) * r.get('reach', 0.5) * (1 - r.get('dup', 0.4))
                 * r.get('conf', 0.5) * BW.get(r.get('boundary', 'unknown'), 0.6), 2)


def save(loot, d):
    os.makedirs(loot, exist_ok=True)
    json.dump(d, open(path(loot), 'w'), indent=1)
    render(loot, d)


def render(loot, d):
    rows = sorted(d['rows'], key=lambda r: (-ev(r), r['id']))
    L = [f"# Hunt ledger — {d.get('target') or ''}", '',
         f"rows: {len(rows)} · open: {sum(1 for r in rows if r['status'] in OPEN)} · "
         f"confirmed: {sum(1 for r in rows if r['status']=='confirmed')} · "
         f"refuted: {sum(1 for r in rows if r['status']=='refuted')}", '',
         '| EV | id | status | boundary | engine | hypothesis |', '|---|---|---|---|---|---|']
    for r in rows:
        L.append(f"| {ev(r)} | {r['id']} | {r['status']} | {r.get('boundary','?')} | "
                 f"{r.get('engine','')} | {r['hypothesis'][:110]} |")
    L += ['', '## Detail', '']
    for r in rows:
        L += [f"### {r['id']} — {r['status']} (EV {ev(r)})", '',
              f"- **hypothesis**: {r['hypothesis']}",
              f"- engine: {r.get('engine','')} · boundary: {r.get('boundary','?')}",
              f"- impact {r.get('impact')} · reach {r.get('reach')} · dup {r.get('dup')} · conf {r.get('conf')}",
              f"- evidence: {r.get('evidence','')}",
              f"- test: {r.get('test','')}"]
        for n in r.get('notes', []):
            L.append(f"- note ({n['t']}): {n['v']}")
        L.append('')
    refuted = [r for r in rows if r['status'] == 'refuted']
    if refuted:
        L += ['## Refutations (do not re-walk these)', '']
        for r in refuted:
            L.append(f"- **{r['id']}** {r['hypothesis'][:120]} — "
                     + (r['notes'][-1]['v'] if r.get('notes') else 'no reason recorded'))
    open(os.path.join(loot, 'ledger.md'), 'w').write('\n'.join(L))


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    for c in ('init', 'add', 'set', 'list', 'next', 'report'):
        s = sub.add_parser(c)
        s.add_argument('--loot', required=True)
        if c == 'init':
            s.add_argument('--target', default=None)
        if c == 'add':
            s.add_argument('--engine', required=True)
            s.add_argument('--hypothesis', required=True)
            s.add_argument('--evidence', default='')
            s.add_argument('--test', default='')
            s.add_argument('--boundary', default='unknown', choices=sorted(BW))
            s.add_argument('--impact', type=float, default=5)
            s.add_argument('--reach', type=float, default=0.5)
            s.add_argument('--dup', type=float, default=0.4)
            s.add_argument('--conf', type=float, default=0.5)
        if c == 'set':
            s.add_argument('--id', required=True)
            s.add_argument('--status', choices=STATUSES)
            s.add_argument('--note', default=None)
            for k in ('impact', 'reach', 'dup', 'conf'):
                s.add_argument(f'--{k}', type=float, default=None)
            s.add_argument('--boundary', default=None, choices=sorted(BW))
        if c == 'list':
            s.add_argument('--status', default=None)
            s.add_argument('--engine', default=None)
    a = ap.parse_args()
    d = load(a.loot)
    if a.cmd == 'init':
        d['target'] = a.target or d.get('target')
        d['created'] = d.get('created') or time.strftime('%Y-%m-%dT%H:%M:%S')
        save(a.loot, d)
        print(f"[ledger] initialised for {d['target']} -> {path(a.loot)}")
    elif a.cmd == 'add':
        rid = f'H{len(d["rows"]) + 1}'
        d['rows'].append({'id': rid, 'engine': a.engine, 'hypothesis': a.hypothesis,
                          'evidence': a.evidence, 'test': a.test, 'boundary': a.boundary,
                          'impact': a.impact, 'reach': a.reach, 'dup': a.dup, 'conf': a.conf,
                          'status': 'hypothesis', 'notes': [],
                          'created': time.strftime('%Y-%m-%dT%H:%M:%S')})
        save(a.loot, d)
        print(f'[ledger] {rid} added (EV {ev(d["rows"][-1])})')
    elif a.cmd == 'set':
        for r in d['rows']:
            if r['id'] == a.id:
                if a.status:
                    r['status'] = a.status
                if a.boundary:
                    r['boundary'] = a.boundary
                for k in ('impact', 'reach', 'dup', 'conf'):
                    v = getattr(a, k)
                    if v is not None:
                        r[k] = v
                if a.note:
                    r.setdefault('notes', []).append({'t': time.strftime('%Y-%m-%dT%H:%M'), 'v': a.note})
                save(a.loot, d)
                print(f'[ledger] {a.id} -> {r["status"]} (EV {ev(r)})')
                return
        print(f'[ledger] no row {a.id}')
    elif a.cmd == 'list':
        rows = d['rows']
        if a.status:
            rows = [r for r in rows if (r['status'] in OPEN if a.status == 'open' else r['status'] == a.status)]
        if a.engine:
            rows = [r for r in rows if a.engine in r.get('engine', '')]
        for r in sorted(rows, key=lambda r: -ev(r)):
            print(f"{ev(r):5}  {r['id']:4} {r['status']:14} {r.get('boundary','?'):18} {r['hypothesis'][:90]}")
    elif a.cmd == 'next':
        rows = [r for r in d['rows'] if r['status'] in OPEN]
        if not rows:
            print('[ledger] nothing open — add hypotheses or write the report')
            return
        r = max(rows, key=ev)
        print(f"NEXT: {r['id']} (EV {ev(r)}, {r.get('boundary')})\n  {r['hypothesis']}\n"
              f"  evidence: {r.get('evidence')}\n  test: {r.get('test')}")
    elif a.cmd == 'report':
        save(a.loot, d)
        print(f'[ledger] -> {a.loot}/ledger.md')


if __name__ == '__main__':
    main()
