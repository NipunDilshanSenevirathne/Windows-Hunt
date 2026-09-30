#!/usr/bin/env python3
"""
runbook_ingest.py — read wh-verify.json back from the Windows VM and turn leads into findings.

The runbook answers the questions static analysis could not. This converts those answers into
verdicts: which hypotheses are now CONFIRMED, which are REFUTED (equally valuable), and what
the severity becomes now that the boundary is known.

Usage:  runbook_ingest.py --loot loot/<name> --result /path/to/wh-verify.json
Writes: <loot>/verified.md  (+ updates ledger rows whose id you pass with --confirm/--refute)
"""
import argparse, json, os

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--loot', required=True)
    ap.add_argument('--result', required=True)
    a = ap.parse_args()
    R = json.load(open(a.result))
    meta = R.get('meta', {})
    conf, refu, open_ = [], [], []

    def add(lst, title, detail, sev, action):
        lst.append({'title': title, 'detail': detail, 'severity': sev, 'action': action})

    ran_as_admin = bool(meta.get('isAdmin'))
    for p in R.get('paths', []):
        if not p.get('exists'):
            continue
        wr = [x for x in (p.get('acl') or []) if isinstance(x, dict) and x.get('VERDICT') == 'USER-WRITABLE']
        if p.get('realWrite') or wr:
            add(conf, f"user-writable privileged path: {p['path']}",
                f"real write {'succeeded' if p.get('realWrite') else 'not attempted'}; "
                f"ACEs: {[x.get('identity') + '=' + str(x.get('rights')) for x in wr][:4]}",
                'precondition confirmed',
                'pair with any DLL load / binary exec / config read from this path')
        for c in (p.get('children') or []):
            if c.get('realWrite'):
                add(conf, f"user-writable subdirectory: {c['dir']}", 'real write succeeded',
                    'precondition confirmed', 'check what privileged code reads from here')
        for e in (p.get('exeAcls') or []):
            w = [x for x in (e.get('acl') or []) if isinstance(x, dict) and x.get('VERDICT') == 'USER-WRITABLE']
            if w:
                add(conf, f"user-writable EXECUTABLE: {e['file']}",
                    f"ACEs: {[x.get('identity') for x in w]}", 'High',
                    'if anything privileged runs this binary, it is a direct LPE')

    for s in R.get('services', []):
        sysacct = str(s.get('account', '')).lower() in ('localsystem', 'nt authority\\system', '.\\localsystem')
        if s.get('UNQUOTED_PATH'):
            add(conf if sysacct else open_, f"unquoted service path: {s['name']}",
                f"account={s.get('account')} path={s.get('pathName')}",
                'High' if sysacct else 'Medium',
                'confirm an intermediate directory is user-writable (see paths[]), then the '
                'C:\\Program.exe style hijack applies')
        if s.get('canReconfigure'):
            add(conf, f"service DACL lets non-admins reconfigure: {s['name']}",
                f"sddl={s.get('sddl')}", 'High',
                'sc config binPath + restart = code execution as ' + str(s.get('account')))
        bd = [x for x in (s.get('binaryDirAcl') or []) if isinstance(x, dict) and x.get('VERDICT') == 'USER-WRITABLE']
        if bd and sysacct:
            add(conf, f"SYSTEM service binary directory is user-writable: {s['name']}",
                f"{[x.get('identity') for x in bd]}", 'High',
                'replace or side-load into the service binary directory')

    for t in R.get('tasks', []):
        w = [x for x in (t.get('acl') or []) + (t.get('dirAcl') or [])
             if isinstance(x, dict) and x.get('VERDICT') == 'USER-WRITABLE']
        if w:
            add(conf, f"privileged scheduled task with writable target: {t['task']}",
                f"runAs={t.get('runAs')} execute={t.get('execute')}", 'High',
                'replace the binary, wait for the trigger')

    for p in R.get('pipes', []):
        if p.get('exists') and str(p.get('clientConnect', '')).startswith('connect-ok'):
            add(conf if not ran_as_admin else open_,
                f"named pipe openable by the running user: {p['pipe']}",
                str(p.get('clientConnect')),
                'surface confirmed' if not ran_as_admin else 'rerun as a standard user',
                'now read the protocol: any command that takes a path, a command line or a '
                'config blob is the finding')

    for u in R.get('uriHandlers', []):
        if u.get('UNQUOTED_ARG'):
            add(conf, f"URI handler with unquoted %1: {u['scheme']}://",
                f"command={u.get('command')}", 'High',
                'a web page can inject additional command-line arguments — poc_gen.py --kind uri-arg')
        elif u.get('command'):
            add(open_, f"URI handler present: {u['scheme']}://", f"command={u.get('command')}",
                'surface', 'check how the app parses the URL internally')

    for l in R.get('listeners', []):
        sev = 'High' if l.get('BOUND_TO_ALL') else 'surface'
        add(conf if l.get('BOUND_TO_ALL') else open_,
            f"listener on {l.get('address')}:{l.get('port')} ({l.get('process')})",
            f"owner={l.get('owner')} path={l.get('path')}", sev,
            'poc_gen.py --kind localhost --port %s; check Origin validation and authentication'
            % l.get('port'))

    for ph in R.get('phantoms', []):
        if not ph.get('found'):
            refu.append({'title': f"phantom {ph['dll']}: loader not installed", 'detail': '',
                         'severity': '-', 'action': 'no longer a candidate on this install'})
        elif ph.get('dllPresent') or ph.get('inSystem32'):
            refu.append({'title': f"phantom {ph['dll']}: actually present on the host",
                         'detail': f"present={ph.get('dllPresent')} system32={ph.get('inSystem32')}",
                         'severity': '-', 'action': 'not a phantom — drop it'})
        elif ph.get('dirRealWrite'):
            add(conf, f"DLL hijack confirmed-writable: {ph['dll']} for {ph['loader']}",
                'directory is writable AND the DLL is absent everywhere', 'High (if the loader is privileged)',
                'poc_gen.py --kind proxy-dll, then capture the token in wh_proof.txt')
        else:
            add(open_, f"phantom {ph['dll']} present but directory not writable", '', 'low',
                'only reachable if the user can write there some other way (installer repair, another bug)')

    for d in R.get('pathDirs', []):
        if d.get('writable'):
            add(conf, f"writable PATH entry: {d['dir']}", '', 'High',
                'every unresolved DLL import in every process on this host becomes hijackable')
    for k in R.get('autoruns', []):
        if k.get('WRITABLE_BY_USERS'):
            add(conf, f"autorun/service registry key writable by users: {k['key']}",
                str(k.get('aces'))[:200], 'High', 'direct persistence/LPE')

    L = ['# Runbook results — verified on the Windows host', '',
         f"- host: {meta.get('hostname')} · {meta.get('osVersion')} build {meta.get('osBuild')}",
         f"- runbook ran as: `{meta.get('whoami')}` (admin: **{meta.get('isAdmin')}**)",
         f"- UAC ConsentPromptBehaviorAdmin: {meta.get('uacLevel')}", '']
    if ran_as_admin:
        L += ['> **This run was elevated.** Writability observed from an admin context proves nothing',
              '> about the attacker position. Re-run as a standard user before reporting anything below.', '']
    for title, rows in (('CONFIRMED', conf), ('REFUTED (close these out)', refu), ('Still open', open_)):
        L += [f'## {title} ({len(rows)})', '']
        if not rows:
            L.append('_none_\n')
            continue
        for r in rows:
            L += [f"- **{r['title']}** — severity: {r['severity']}",
                  (f"  - {r['detail']}" if r['detail'] else ''),
                  f"  - next: {r['action']}"]
        L.append('')
    L += ['## Update the ledger', '', '```bash']
    for i, r in enumerate(conf[:10], 1):
        L.append(f"scripts/hunt_state.py set --loot <loot> --id H? --status confirmed "
                 f"--reach 1.0 --conf 0.9 --note \"{r['title'][:80]}\"")
    for r in refu[:6]:
        L.append(f"scripts/hunt_state.py set --loot <loot> --id H? --status refuted "
                 f"--note \"{r['title'][:80]}\"")
    L.append('```')
    open(os.path.join(a.loot, 'verified.md'), 'w').write('\n'.join(x for x in L if x is not None))
    print(f'[runbook_ingest] confirmed={len(conf)} refuted={len(refu)} open={len(open_)}')
    print(f'[runbook_ingest] -> {a.loot}/verified.md')


if __name__ == '__main__':
    main()
