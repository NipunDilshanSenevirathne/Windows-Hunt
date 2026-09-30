#!/usr/bin/env python3
"""
rpc_audit.py — recover the actual RPC/ALPC interfaces, statically.

"The binary imports rpcrt4" is not analysis. A Windows service that exposes an RPC interface is
exposing a *named, versioned, numbered* API to whoever the endpoint's ACL allows — and on
Windows that is very often every logged-on user. This recovers the interfaces the way RpcView
does at runtime, but from the file:

  * the compiler emits an `RPC_SERVER_INTERFACE` for every server interface, and every one of
    them embeds the **NDR transfer syntax GUID** `8a885d04-1ceb-11c9-9fe8-08002b104860`
    (or NDR64 `71710533-beba-4937-8319-b5dbef9ccc36`). That constant is the anchor.
  * 24 bytes before it sits the structure start: `Length`, then the **interface UUID** and its
    major/minor version.
  * `DispatchTable` points at an `RPC_DISPATCH_TABLE` whose first field is the **procedure
    count** — the number of opnums an attacker can call.
  * endpoint strings (`ncalrpc:`, `ncacn_np:\\pipe\\x`, `ncacn_ip_tcp:`) and
    `RpcServerRegisterIf*` / `RpcServerUseProtseq*` imports say how it is reachable, and
    `RpcServerRegisterIfEx` with a security callback says whether it is filtered at all.

Output tells you, per interface: the UUID to bind to, the version, how many opnums to enumerate,
which transport, and whether the server registered a security callback.

Usage:  rpc_audit.py --loot loot/<name>
Writes: <loot>/rpc.json, <loot>/rpc.md
"""
import argparse, json, os, re, struct

NDR20 = bytes.fromhex('045d888aeb1cc9119fe808002b104860')     # 8a885d04-1ceb-11c9-9fe8-08002b104860
NDR64 = bytes.fromhex('33057171babe37438319b5dbef9ccc36')     # 71710533-beba-4937-8319-b5dbef9ccc36

REG_APIS = {
    'RpcServerRegisterIf': ('no security callback — the interface is callable by anyone the '
                            'endpoint ACL admits', 7),
    'RpcServerRegisterIf2': ('registered with flags; check for RPC_IF_ALLOW_SECURE_ONLY / '
                             'RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH', 6),
    'RpcServerRegisterIfEx': ('takes a security callback — read it; a callback that returns '
                              'RPC_S_OK unconditionally is no filter at all', 5),
    'RpcServerRegisterIf3': ('takes a security descriptor and a callback — the good form', 3),
    'RpcServerUseProtseqEp': ('binds a specific endpoint', 4),
    'RpcServerUseProtseq': ('binds a protocol sequence', 4),
    'RpcServerUseAllProtseqs': ('registers on EVERY available transport, including remote ones', 8),
    'RpcServerUseAllProtseqsIf': ('every transport for this interface', 8),
    'RpcServerInqCallAttributes': ('inspects the caller — a sign someone thought about authz', 2),
    'RpcImpersonateClient': ('impersonates the caller — correct; check RpcRevertToSelf on every '
                             'path including errors', 3),
    'RpcRevertToSelf': ('impersonation released', 1),
    'RpcBindingSetAuthInfo': ('client-side auth', 2),
    'RpcServerRegisterAuthInfo': ('server requires authentication — good', 2),
    'NdrServerCall2': ('the MIDL server stub dispatcher', 3),
    'NdrServerCallAll': ('MIDL server stub dispatcher', 3),
    'RpcAsyncCompleteCall': ('async RPC server', 3),
    'I_RpcBindingInqLocalClientPID': ('caller PID lookup — often used for a weak "is the caller '
                                      'our own process" check that is racy and spoofable', 6),
    'AlpcInitializeMessageAttribute': ('raw ALPC — no RPC runtime checks at all', 6),
    'NtAlpcCreatePort': ('raw ALPC port', 6),
    'NtAlpcSendWaitReceivePort': ('raw ALPC message loop', 6),
}
EP_RX = re.compile(r'(?i)\b(ncalrpc|ncacn_np|ncacn_ip_tcp|ncacn_http|ncadg_ip_udp|ncacn_nb_tcp)'
                   r'[:\]]?\s*([\\A-Za-z0-9_.\-]{0,64})')
SEC_CB_HINT = re.compile(r'(?i)(SecurityCallback|IfCallbackFn|RPC_IF_ALLOW|RPC_S_ACCESS_DENIED)')


def guid_str(b):
    d1, d2, d3 = struct.unpack('<IHH', b[:8])
    return ('{%08X-%04X-%04X-%s-%s}' % (d1, d2, d3, b[8:10].hex().upper(),
                                        b[10:16].hex().upper()))


def strings_of(data):
    out = b'\n'.join(re.findall(rb'[\x20-\x7e]{4,}', data)).decode('latin1')
    try:
        out += '\n' + '\n'.join(re.findall(r'[\x20-\x7e]{4,}', data.decode('utf-16-le', 'ignore')))
    except Exception:
        pass
    return out


def scan_binary(path, b_triage):
    """Return interfaces + registration evidence for one PE."""
    try:
        import pefile
        pe = pefile.PE(path)
    except Exception:
        return None
    try:
        data = open(path, 'rb').read()
    except Exception:
        return None
    base = pe.OPTIONAL_HEADER.ImageBase
    is64 = pe.FILE_HEADER.Machine == 0x8664
    psz = 8 if is64 else 4

    def rva_to_off(rva):
        try:
            return pe.get_offset_from_rva(rva)
        except Exception:
            return None

    def va_to_off(va):
        if va < base:
            return None
        return rva_to_off(va - base)

    def rd_ptr(off):
        if off is None or off + psz > len(data):
            return None
        return struct.unpack('<Q' if is64 else '<I', data[off:off + psz])[0]

    ifaces = []
    seen = set()
    for magic, syntax in ((NDR20, 'NDR20'), (NDR64, 'NDR64')):
        start = 0
        while True:
            i = data.find(magic, start)
            if i < 0:
                break
            start = i + 1
            # RPC_SERVER_INTERFACE: Length(4) InterfaceId{GUID(16)+ver(4)} TransferSyntax{GUID+ver}
            s = i - 24
            if s < 0:
                continue
            try:
                length = struct.unpack('<I', data[s:s + 4])[0]
            except Exception:
                continue
            if length not in (0x44, 0x60, 0x48, 0x64):        # x86 / x64 (± variants)
                continue
            uuid = guid_str(data[s + 4:s + 20])
            vmaj, vmin = struct.unpack('<HH', data[s + 20:s + 24])
            if uuid in seen:
                continue
            seen.add(uuid)
            row = {'uuid': uuid, 'version': f'{vmaj}.{vmin}', 'transfer_syntax': syntax,
                   'struct_offset': hex(s), 'length': hex(length), 'procedures': None,
                   'dispatch_table_va': None}
            # DispatchTable pointer follows the two syntax identifiers
            dt_off = s + 4 + 20 + 20
            dt = rd_ptr(dt_off)
            if dt:
                row['dispatch_table_va'] = hex(dt)
                o = va_to_off(dt)
                if o is not None and o + 4 <= len(data):
                    cnt = struct.unpack('<I', data[o:o + 4])[0]
                    if 0 < cnt < 4096:
                        row['procedures'] = cnt
            ifaces.append(row)

    s = strings_of(data[:32 << 20])
    endpoints = sorted({f'{m.group(1)}:{m.group(2)}'.rstrip(':') for m in EP_RX.finditer(s)
                        if m.group(2) or m.group(1).lower() == 'ncalrpc'})[:40]
    imports = {f for v in (b_triage.get('imports') or {}).values() for f in v}
    regs = {}
    for api, (why, sev) in REG_APIS.items():
        if any(api.lower() == f.lower() or api.lower() in f.lower() for f in imports) or api in s:
            regs[api] = {'why': why, 'severity': sev}
    return {'interfaces': ifaces, 'endpoints': endpoints, 'registration_apis': regs,
            'security_callback_hint': bool(SEC_CB_HINT.search(s)), 'arch': 'x64' if is64 else 'x86'}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--loot', required=True)
    a = ap.parse_args()
    loot = a.loot
    tri = json.load(open(os.path.join(loot, 'pe_triage.json')))
    man = {f['path']: f for f in json.load(open(os.path.join(loot, 'unwrap.json')))['files']}

    results, total_if = [], 0
    for b in tri['binaries']:
        if not b.get('ok') or b.get('is_dotnet'):
            continue
        p = man.get(b['path'], {}).get('abs')
        if not p or not os.path.isfile(p):
            continue
        imps = {f.lower() for v in (b.get('imports') or {}).values() for f in v}
        dlls = {d.lower() for d in (b.get('imports') or {})}
        rpc_imports = bool({'rpcrt4.dll'} & dlls) or any('rpc' in i or 'alpc' in i for i in imps)
        # Do NOT gate on imports alone: a server hosted in svchost, or one that resolves rpcrt4
        # dynamically, has no import entry but still carries the interface structures. A byte
        # scan for the transfer-syntax GUID is cheap and catches those.
        if not rpc_imports:
            try:
                with open(p, 'rb') as fh:
                    blob = fh.read(48 << 20)
                if NDR20 not in blob and NDR64 not in blob:
                    continue
            except Exception:
                continue
        r = scan_binary(p, b)
        if not r:
            continue
        man_ = b.get('manifest') or {}
        priv = (man_.get('requestedExecutionLevel', 'asInvoker') != 'asInvoker') or \
               ('service' in (b.get('capabilities') or {})) or \
               bool(re.search(r'(?i)(svc|service|host|broker|agent|updater)', os.path.basename(b['path'])))
        r.update({'path': b['path'], 'privileged_hint': priv})
        total_if += len(r['interfaces'])
        if r['interfaces'] or r['registration_apis']:
            results.append(r)

    servers = [r for r in results if r['interfaces']]
    json.dump({'binaries': results, 'interface_count': total_if},
              open(os.path.join(loot, 'rpc.json'), 'w'), indent=1)

    L = ['# RPC / ALPC interfaces', '',
         f'- binaries with RPC/ALPC code: **{len(results)}**',
         f'- server interfaces recovered: **{total_if}**', '',
         '> An RPC interface is a named API with numbered procedures. If the endpoint lets a',
         '> standard user bind, every opnum is reachable attack surface — and the server usually',
         '> runs as SYSTEM. This is the highest-value, least-audited local surface on Windows.', '']
    for r in sorted(results, key=lambda x: (-len(x['interfaces']), not x['privileged_hint'])):
        L += [f"## `{r['path']}` ({r['arch']}{', privileged' if r['privileged_hint'] else ''})", '']
        if r['interfaces']:
            L += ['| interface UUID | ver | opnums | syntax |', '|---|---|---|---|']
            for i in r['interfaces']:
                L.append(f"| `{i['uuid']}` | {i['version']} | {i['procedures'] if i['procedures'] is not None else '?'} "
                         f"| {i['transfer_syntax']} |")
            L.append('')
        if r['endpoints']:
            L.append('**endpoints:** ' + ', '.join(f'`{e}`' for e in r['endpoints'][:20]))
            L.append('')
        if r['registration_apis']:
            L.append('**registration / security APIs:**')
            for api, d in sorted(r['registration_apis'].items(), key=lambda x: -x[1]['severity']):
                L.append(f"- `{api}` ({d['severity']}/10) — {d['why']}")
            L.append('')
        if r['interfaces'] and 'RpcServerRegisterIfEx' not in r['registration_apis'] \
           and 'RpcServerRegisterIf3' not in r['registration_apis'] \
           and not r['security_callback_hint']:
            L += ['> **No security callback and no security descriptor is registered for these '
                  'interfaces.** Access is then decided only by the endpoint (for `ncalrpc`, the '
                  'ALPC port ACL; for `ncacn_np`, the pipe ACL), which on many products admits '
                  'every logged-on user. Confirm on the host and enumerate the opnums.', '']
    if servers:
        L += ['## How to work an interface', '', '```powershell',
              '# 1. On the host: is it registered, and on which endpoint?',
              '#    RpcView (GUI) or:  Get-ChildItem \\\\.\\pipe\\ ; (ALPC ports: NtObjectManager)',
              '    Import-Module NtObjectManager',
              '    Get-RpcServer C:\\Path\\To\\service.exe | Format-List           # parses the same structures',
              '    Get-RpcEndpoint -SearchType ALPC | Where-Object InterfaceId -eq "<uuid>"',
              '# 2. Can a standard user bind?',
              '    $c = Get-RpcClient -Server (Get-RpcServer .\\service.exe)[0]',
              '    Connect-RpcClient $c -EndpointPath "<endpoint>"',
              '# 3. Enumerate the opnums and their argument shapes, then look for the usual:',
              '#    a path, a command line, a file copy, a service reconfigure, an ACL change.',
              '```', '',
              '> NtObjectManager (James Forshaw) is the reference toolkit for step 2 and 3; it parses',
              "> the same `RPC_SERVER_INTERFACE`/MIDL structures this engine finds statically, and it",
              '> can generate a working client from them. Put its output in the report — a triager',
              '> can replay it.', '',
              '## Reportability', '',
              '- Any user can bind + an opnum performs a privileged action on attacker input =',
              '  **user-to-system**, High. This is the canonical modern Windows LPE.',
              '- A caller-PID check (`I_RpcBindingInqLocalClientPID`) is **not** an authorization',
              '  check: PIDs are reusable and the parent can be spoofed. Say so explicitly.',
              '- A security callback that returns `RPC_S_OK` for everything is the same as none.']
    else:
        L.append('_No RPC server interface structures were recovered. If the binary still imports '
                 'rpcrt4, it is probably an RPC **client** — check what it connects to instead._')
    open(os.path.join(loot, 'rpc.md'), 'w').write('\n'.join(L))
    print(f'[rpc_audit] {len(results)} binaries, {total_if} server interfaces')
    print(f'[rpc_audit] -> {loot}/rpc.json + rpc.md')


if __name__ == '__main__':
    main()
