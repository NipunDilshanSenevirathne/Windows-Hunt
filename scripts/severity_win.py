#!/usr/bin/env python3
"""
severity_win.py — CVSS 3.1 plus the Windows reportability gate.

CVSS alone gets Windows desktop findings wrong in both directions. The gate that decides
whether a report is paid or closed is not the vector — it is **which security boundary was
crossed**. Microsoft publishes that list, and most vendors and platforms follow it.

NOT security boundaries (MSRC), i.e. do not report these alone:
  * admin -> SYSTEM / kernel (an administrator is already trusted)
  * UAC bypass at the default UAC level (UAC is a convenience, not a boundary)
  * anything requiring an attacker who is already SYSTEM or already admin
  * AV/EDR bypass, ASLR/CFG bypass with no memory-corruption bug behind it
  * "the installer writes to a directory admins can write to"
  * physical access to an unlocked machine, unless the product claims to defend it
ARE boundaries:
  * standard user -> admin/SYSTEM (the classic LPE; this is the money case)
  * low-integrity / sandboxed / AppContainer -> medium or higher
  * remote/unauthenticated -> any local code execution
  * one local user -> another local user's data or session
  * a web page -> the local application (URI handler, localhost listener, file association)
  * the update channel -> code execution (network attacker or malicious mirror)
  * a non-admin service account -> SYSTEM

Usage:
  severity_win.py --vector "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" --boundary user-to-system \\
                  [--precondition "app installed to default path"] [--json]
  severity_win.py --list-boundaries
"""
import argparse, json, sys

W = {'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},
     'AC': {'L': 0.77, 'H': 0.44},
     'PR': {'U': {'N': 0.85, 'L': 0.62, 'H': 0.27}, 'C': {'N': 0.85, 'L': 0.68, 'H': 0.50}},
     'UI': {'N': 0.85, 'R': 0.62},
     'CIA': {'H': 0.56, 'L': 0.22, 'N': 0.0}}

BOUNDARIES = {
    'user-to-system':      (1.00, True,  'standard user to admin/SYSTEM — the canonical Windows LPE. Report it.'),
    'user-to-admin':       (1.00, True,  'standard user to administrator — a boundary.'),
    'service-to-system':   (0.90, True,  'a constrained service account to SYSTEM — a boundary.'),
    'sandbox-escape':      (1.00, True,  'AppContainer/low-integrity/renderer escape — a boundary.'),
    'user-to-user':        (0.95, True,  "one local user reaching another user's data or session — a boundary."),
    'remote-to-local':     (1.00, True,  'unauthenticated remote input reaching local code execution — the strongest case.'),
    'web-to-local':        (0.95, True,  'a web page reaching the application (URI handler, localhost listener, file association) — a boundary, and usually one-click or zero-click.'),
    'update-channel':      (1.00, True,  'an attacker on the update path (network, mirror, DNS) reaching code execution — a boundary.'),
    'network-to-local':    (0.95, True,  'a network-position attacker reaching the app (missing TLS validation, cleartext) — a boundary.'),
    'file-to-code':        (0.90, True,  'opening a malicious file leads to code execution — a boundary if the file type is one users open.'),
    'admin-to-system':     (0.15, False, 'admin to SYSTEM/kernel is NOT a boundary (MSRC). Only report as a defence-in-depth note, or if the product explicitly claims to defend it.'),
    'uac-bypass':          (0.15, False, 'UAC bypass at the default level is NOT a boundary (MSRC). Do not lead with it.'),
    'admin-precondition':  (0.10, False, 'the attack requires the attacker to already be admin — not a boundary.'),
    'physical':            (0.35, False, 'physical access to an unlocked machine — out of scope for most programs unless the product claims to defend it.'),
    'av-bypass':           (0.10, False, 'AV/EDR/mitigation bypass with no underlying vulnerability — not a boundary.'),
    'same-user':           (0.20, False, 'code running as the user affecting that same user — no boundary crossed. Usable only as a link in a chain.'),
}


# Finding class -> MITRE ATT&CK technique. Triage teams and CISO reports both use these; a
# report that names the technique reads as written by someone who knows the ecosystem.
ATTCK = {
    'dll-hijack':        [('T1574.001', 'Hijack Execution Flow: DLL Search Order Hijacking')],
    'dll-sideload':      [('T1574.002', 'Hijack Execution Flow: DLL Side-Loading')],
    'unquoted-path':     [('T1574.009', 'Hijack Execution Flow: Path Interception by Unquoted Path')],
    'path-interception': [('T1574.007', 'Path Interception by PATH Environment Variable')],
    'weak-acl-service':  [('T1574.010', 'Services File Permissions Weakness'),
                          ('T1543.003', 'Create or Modify System Process: Windows Service')],
    'weak-acl-file':     [('T1222.001', 'File and Directory Permissions Modification: Windows')],
    'com-hijack':        [('T1546.015', 'Event Triggered Execution: Component Object Model Hijacking')],
    'appinit':           [('T1546.010', 'Event Triggered Execution: AppInit DLLs')],
    'appcert':           [('T1546.009', 'Event Triggered Execution: AppCert DLLs')],
    'ifeo':              [('T1546.012', 'Event Triggered Execution: Image File Execution Options Injection')],
    'shell-extension':   [('T1546.001', 'Change Default File Association'),
                          ('T1547.001', 'Registry Run Keys / Startup Folder')],
    'lsa-plugin':        [('T1547.005', 'Security Support Provider')],
    'print-monitor':     [('T1547.010', 'Port Monitors')],
    'winlogon':          [('T1547.004', 'Winlogon Helper DLL')],
    'scheduled-task':    [('T1053.005', 'Scheduled Task/Job: Scheduled Task')],
    'token-impersonation': [('T1134.001', 'Access Token Manipulation: Token Impersonation/Theft'),
                            ('T1134.002', 'Create Process with Token')],
    'named-pipe-impersonation': [('T1134.002', 'Create Process with Token')],
    'driver-ioctl':      [('T1068', 'Exploitation for Privilege Escalation'),
                          ('T1211', 'Exploitation for Defense Evasion')],
    'byovd':             [('T1068', 'Exploitation for Privilege Escalation')],
    'update-channel':    [('T1195.002', 'Supply Chain Compromise: Compromise Software Supply Chain'),
                          ('T1553.002', 'Subvert Trust Controls: Code Signing')],
    'signature-bypass':  [('T1553.002', 'Subvert Trust Controls: Code Signing')],
    'uri-handler':       [('T1204.001', 'User Execution: Malicious Link'),
                          ('T1546.001', 'Change Default File Association')],
    'localhost-listener': [('T1071.001', 'Application Layer Protocol: Web Protocols')],
    'deserialization':   [('T1203', 'Exploitation for Client Execution')],
    'electron-rce':      [('T1203', 'Exploitation for Client Execution')],
    'secrets':           [('T1552.001', 'Unsecured Credentials: Credentials In Files'),
                          ('T1552.002', 'Credentials in Registry')],
    'credstore':         [('T1555.004', 'Credentials from Password Stores: Windows Credential Manager'),
                          ('T1555.003', 'Credentials from Web Browsers')],
    'dpapi':             [('T1555.004', 'Windows Credential Manager')],
    'toctou-symlink':    [('T1548.002', 'Abuse Elevation Control Mechanism: Bypass UAC'),
                          ('T1068', 'Exploitation for Privilege Escalation')],
    'msi-repair':        [('T1218.007', 'System Binary Proxy Execution: Msiexec')],
    'signed-binary-proxy': [('T1218', 'System Binary Proxy Execution')],
    'rpc-opnum':         [('T1559', 'Inter-Process Communication'),
                          ('T1068', 'Exploitation for Privilege Escalation')],
    'named-pipe-ipc':    [('T1559.001', 'Inter-Process Communication: Component Object Model'),
                          ('T1570', 'Lateral Tool Transfer')],
    'native-messaging':  [('T1176', 'Browser Extensions')],
    'env-hijack':        [('T1574.006', 'Dynamic Linker Hijacking / env-based load'),
                          ('T1574.007', 'Path Interception by PATH Environment Variable')],
    'handle-inheritance': [('T1134', 'Access Token Manipulation')],
    'memory-corruption': [('T1203', 'Exploitation for Client Execution'),
                          ('T1068', 'Exploitation for Privilege Escalation')],
}


def cvss(v):
    p = dict(x.split(':') for x in v.replace('CVSS:3.1/', '').strip().split('/') if ':' in x)
    sc = p.get('S', 'U')
    av, ac = W['AV'][p['AV']], W['AC'][p['AC']]
    pr = W['PR'][sc][p['PR']]
    ui = W['UI'][p['UI']]
    c, i, aa = (W['CIA'][p[k]] for k in ('C', 'I', 'A'))
    iss = 1 - ((1 - c) * (1 - i) * (1 - aa))
    imp = 6.42 * iss if sc == 'U' else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exp = 8.22 * av * ac * pr * ui
    if imp <= 0:
        return 0.0, 'None', imp, exp
    base = min(imp + exp, 10) if sc == 'U' else min(1.08 * (imp + exp), 10)
    import math
    base = math.ceil(base * 10) / 10
    band = ('None' if base == 0 else 'Low' if base < 4 else 'Medium' if base < 7
            else 'High' if base < 9 else 'Critical')
    return base, band, imp, exp


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--vector')
    ap.add_argument('--boundary', choices=sorted(BOUNDARIES))
    ap.add_argument('--precondition', default='')
    ap.add_argument('--list-boundaries', action='store_true')
    ap.add_argument('--class', dest='cls', choices=sorted(ATTCK),
                    help='finding class, to add the MITRE ATT&CK technique(s) to the output')
    ap.add_argument('--list-classes', action='store_true')
    ap.add_argument('--json', action='store_true')
    a = ap.parse_args()
    if a.list_classes:
        for k, v in sorted(ATTCK.items()):
            print(f"{k:24} {', '.join(t for t, _ in v)}  {v[0][1]}")
        return
    if a.list_boundaries:
        for k, (w, ok, why) in sorted(BOUNDARIES.items(), key=lambda x: -x[1][0]):
            print(f"{'REPORTABLE' if ok else 'NOT A BOUNDARY':16} {k:20} w={w:<5} {why}")
        return
    if not a.vector or not a.boundary:
        ap.error('--vector and --boundary are required (or --list-boundaries)')
    base, band, imp, exp = cvss(a.vector)
    w, reportable, why = BOUNDARIES[a.boundary]
    adj = round(base * w, 1)
    aband = ('None' if adj == 0 else 'Low' if adj < 4 else 'Medium' if adj < 7
             else 'High' if adj < 9 else 'Critical')
    out = {'vector': a.vector, 'cvss_base': base, 'cvss_band': band,
           'impact_sub': round(imp, 2), 'exploitability_sub': round(exp, 2),
           'boundary': a.boundary, 'boundary_weight': w, 'reportable': reportable,
           'boundary_note': why, 'adjusted': adj, 'adjusted_band': aband,
           'precondition': a.precondition}
    sentence = (f"CVSS 3.1 base {base} ({band}) via {a.vector}. The finding crosses the "
                f"{a.boundary.replace('-', ' ')} boundary, which Microsoft treats as "
                f"{'a defended security boundary' if reportable else 'NOT a security boundary'}"
                f"{'; severity is reported as ' + str(adj) + ' (' + aband + ') after boundary weighting' if reportable else ''}.")
    if a.precondition:
        sentence += f" Precondition: {a.precondition}."
    if a.cls:
        tech = ATTCK[a.cls]
        out['attck'] = [{'id': t, 'name': n} for t, n in tech]
        sentence += (' MITRE ATT&CK: '
                     + '; '.join(f'{t} ({n})' for t, n in tech) + '.')
    out['report_sentence'] = sentence
    if a.json:
        print(json.dumps(out, indent=1))
        return
    print(f"CVSS base        : {base}  ({band})")
    print(f"boundary         : {a.boundary}  weight {w}")
    print(f"reportable       : {'YES' if reportable else 'NO — do not submit this alone'}")
    print(f"adjusted severity: {adj}  ({aband})")
    print(f"\nwhy: {why}")
    if not reportable:
        print("\n>> Pivot: find the same primitive reachable WITHOUT the disqualifying precondition,\n"
              "   or chain it behind something that does cross a boundary. On its own it is a\n"
              "   by-design close and it costs you signal with the triager.")
    print(f"\nreport sentence:\n{sentence}")


if __name__ == '__main__':
    main()
