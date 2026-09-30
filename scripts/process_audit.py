#!/usr/bin/env python3
"""
process_audit.py — how this product creates processes, and what it leaks to them.

Process creation is where a surprising share of Windows LPE lives, and none of it is exotic:

  UNQUOTED-COMMANDLINE  CreateProcess with lpApplicationName = NULL and a command line whose
                        path contains spaces and is not quoted. The API then tries
                        `C:\\Program.exe`, `C:\\Program Files\\Acme\\Acme.exe`, … in order.
  HANDLE-INHERITANCE    bInheritHandles = TRUE. Every inheritable handle in the parent — tokens,
                        privileged file handles, pipes — lands in the child. If the child is a
                        lower-privileged process or takes attacker input, that is a leak.
  NO-MITIGATION-POLICY  no PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY on a child that parses
                        untrusted input: no ACG/CIG/blocking of non-Microsoft binaries.
  TOKEN-SPRAWL          CreateProcessAsUser / WithLogonW / DuplicateTokenEx / AdjustTokenPrivileges
                        — read which privileges are enabled and whether a token is ever
                        duplicated into a less trusted context.
  SEIMPERSONATE         a service account that holds SeImpersonatePrivilege is one named pipe
                        away from SYSTEM (the "potato" family). Worth stating explicitly when
                        the product runs anything as LocalService/NetworkService.
  ENV-INHERITANCE       the child inherits the parent environment. For a privileged child spawned
                        from a user-controlled context, PATH / NODE_OPTIONS / PYTHONPATH /
                        ELECTRON_RUN_AS_NODE / _NT_SYMBOL_PATH are code-execution vectors.
  SHELLEXECUTE-VERB     ShellExecute resolves the verb through the registry, so the actual image
                        is chosen by HKCU associations the user controls.
  JOB/DESKTOP           no job object or separate desktop for a sandboxed child.

Usage:  process_audit.py --loot loot/<name>
Writes: <loot>/process.json, <loot>/process.md
"""
import argparse, json, os, re

CREATE = ['CreateProcessA', 'CreateProcessW', 'CreateProcessAsUserA', 'CreateProcessAsUserW',
          'CreateProcessWithLogonW', 'CreateProcessWithTokenW', 'ShellExecuteA', 'ShellExecuteW',
          'ShellExecuteExA', 'ShellExecuteExW', 'WinExec', 'system', '_wsystem', '_popen',
          '_wpopen', 'CreateProcessInternalW']
TOKEN = ['OpenProcessToken', 'DuplicateTokenEx', 'DuplicateToken', 'SetThreadToken',
         'AdjustTokenPrivileges', 'LogonUserA', 'LogonUserW', 'CreateRestrictedToken',
         'ImpersonateLoggedOnUser', 'CheckTokenMembership', 'GetTokenInformation',
         'SeImpersonatePrivilege', 'SeAssignPrimaryTokenPrivilege', 'SeDebugPrivilege',
         'SeBackupPrivilege', 'SeRestorePrivilege', 'SeTakeOwnershipPrivilege',
         'SeLoadDriverPrivilege', 'SeTcbPrivilege']
HARDENING = ['InitializeProcThreadAttributeList', 'UpdateProcThreadAttribute',
             'SetProcessMitigationPolicy', 'CreateJobObjectW', 'AssignProcessToJobObject',
             'SetInformationJobObject', 'CreateDesktopW', 'SetHandleInformation',
             'PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY', 'PROCESS_CREATION_MITIGATION_POLICY',
             'CreateAppContainerProfile', 'InitializeSecurityDescriptor']
DANGEROUS_PRIV = {
    'SeImpersonatePrivilege': 'holding this in a service account is one named pipe away from '
                              'SYSTEM (the potato family) — say so explicitly in the report',
    'SeAssignPrimaryTokenPrivilege': 'allows assigning a primary token to a new process',
    'SeDebugPrivilege': 'read/write any process — an immediate path to SYSTEM',
    'SeBackupPrivilege': 'read any file regardless of ACL',
    'SeRestorePrivilege': 'write any file regardless of ACL — arbitrary write by design',
    'SeTakeOwnershipPrivilege': 'take ownership of any object',
    'SeLoadDriverPrivilege': 'load a kernel driver — ring 0',
    'SeTcbPrivilege': 'act as part of the operating system',
}
# A path is exploitable when AT LEAST ONE directory segment contains a space — not when every
# one does. `C:\Program Files\AcmeDesktop\Acme Service\x.exe` is the canonical case.
UNQUOTED_RX = re.compile(
    r'(?<![\"\w])('
    r'[A-Za-z]:\\'                                   # drive
    r'(?:[^\\\"\r\n<>|*?]+\\){0,6}'                  # some directories
    r'[^\\\"\r\n<>|*?]* [^\\\"\r\n<>|*?]*\\'        # at least one WITH a space
    r'(?:[^\\\"\r\n<>|*?]+\\){0,6}'                  # more directories
    r'[^\\\"\r\n<>|*?]*\.exe)', re.I)
ENV_VECTORS = ['PATH', 'NODE_OPTIONS', 'PYTHONPATH', 'PYTHONSTARTUP', 'ELECTRON_RUN_AS_NODE',
               '_NT_SYMBOL_PATH', 'COR_ENABLE_PROFILING', 'COR_PROFILER', 'CLASSPATH',
               'JAVA_TOOL_OPTIONS', 'LD_PRELOAD', 'DOTNET_STARTUP_HOOKS', 'PSModulePath']



def _call_target(ins, is64):
    """Absolute VA a `call qword ptr [rip + X]` / `call dword ptr [X]` reaches.

    On x64 the IAT is referenced RIP-relative, so the operand string carries a displacement,
    not the slot address. Matching the raw text against IAT addresses silently finds nothing —
    which is how a call-site analyser ends up reporting zero call sites on a binary full of them.
    """
    o = ins.op_str.lower().replace(' ', '')
    m = re.search(r'\[rip([+\-])0x([0-9a-f]+)\]', o)
    if m:
        d = int(m.group(2), 16)
        return ins.address + ins.size + (d if m.group(1) == '+' else -d)
    m = re.search(r'\[(?:0x)?([0-9a-f]{4,})\]', o)
    if m:
        return int(m.group(1), 16)
    return None


def _resolve_thunks(insns, slots, is64):
    """Map import-thunk addresses to their IAT slot.

    MSVC calls the IAT directly (`call qword ptr [rip+X]`); GCC/mingw emits a one-instruction
    thunk (`jmp qword ptr [rip+X]`) and calls THAT. Matching only the direct form finds nothing
    on a mingw binary — and reporting "0 call sites" on a binary full of them is worse than not
    looking, because it reads as a clean result.
    """
    thunks = {}
    for ins in insns:
        if ins.mnemonic != 'jmp':
            continue
        t = _call_target(ins, is64)
        if t is not None and t in slots:
            thunks[ins.address] = t
    return thunks


def _direct_target(ins, is64, slots, thunks):
    """The IAT slot this call ultimately reaches, through a thunk if there is one."""
    t = _call_target(ins, is64)
    if t is not None and t in slots:
        return t
    o = ins.op_str.strip().lower()
    if o.startswith('0x'):
        try:
            a = int(o, 16)
        except ValueError:
            return None
        return thunks.get(a)
    return None


def _find_calls(code, sec_va, targets, is64):
    """Byte-scan for calls that reach `targets`, instead of a linear disassembly sweep.

    A linear sweep from the start of .text desynchronises on the first data-in-code island and
    then silently misses every instruction after it. Scanning for the call encodings and
    computing their targets arithmetically cannot desynchronise. Three forms matter:

        E8 rel32                     call <relative>            addr + 5 + rel32
        FF 15 rel32                  call qword [rip+rel32]     addr + 6 + rel32   (MSVC -> IAT)
        48 8B 05 rel32 ... FF D0     mov rax,[rip+rel32]; call rax
                                                                (GCC/mingw -O0 -> IAT)

    The third form is the one that matters most in practice and the one naive scanners miss:
    mingw loads the import into a register first, so there is no call instruction that names
    the IAT at all.

    Returns [(call_va, iat_slot_va)].
    """
    out = []
    n = len(code)
    # --- register-load-then-call (the GCC form) ------------------------------------------
    # 48 8B /r with ModRM 05/0D/15/1D/25/2D/35/3D = mov r64, [rip+disp32]
    REG_OF_MODRM = {0x05: 'rax', 0x0D: 'rcx', 0x15: 'rdx', 0x1D: 'rbx',
                    0x25: 'rsp', 0x2D: 'rbp', 0x35: 'rsi', 0x3D: 'rdi'}
    CALL_REG = {'rax': b'\xff\xd0', 'rcx': b'\xff\xd1', 'rdx': b'\xff\xd2', 'rbx': b'\xff\xd3',
                'rsp': b'\xff\xd4', 'rbp': b'\xff\xd5', 'rsi': b'\xff\xd6', 'rdi': b'\xff\xd7'}
    if is64:
        for i in range(n - 7):
            if code[i] != 0x48 or code[i + 1] != 0x8B:
                continue
            reg = REG_OF_MODRM.get(code[i + 2])
            if not reg:
                continue
            d = int.from_bytes(code[i + 3:i + 7], 'little', signed=True)
            t = sec_va + i + 7 + d
            if t not in targets:
                continue
            pat = CALL_REG[reg]
            j = code.find(pat, i + 7, min(n, i + 7 + 48))
            if j >= 0:
                out.append((sec_va + j, targets[t]))
    # --- direct and IAT-indirect calls ------------------------------------------------------
    for i in range(n - 6):
        b = code[i]
        if b == 0xE8:
            rel = int.from_bytes(code[i + 1:i + 5], 'little', signed=True)
            t = sec_va + i + 5 + rel
        elif b == 0xFF and code[i + 1] == 0x15:
            d = int.from_bytes(code[i + 2:i + 6], 'little', signed=True)
            t = (sec_va + i + 6 + d) if is64 else (d & 0xFFFFFFFF)
        else:
            continue
        if t in targets:
            out.append((sec_va + i, targets[t]))
    return sorted(set(out))


def _insns_before(md, code, sec_va, call_va, window=64):
    """Instructions immediately preceding `call_va`, decoded so they END exactly on it.

    Try progressively earlier start offsets until the decode lands on the call — that is the
    only start that was in-phase with the real instruction stream.
    """
    off = call_va - sec_va
    # Longest in-phase window first: the shortest one decodes cleanly but contains only the
    # instruction immediately before the call, which is never where the arguments were set.
    for back in range(window, 7, -1):
        if off - back < 0:
            continue
        chunk = code[off - back:off]
        ins = list(md.disasm(chunk, sec_va + off - back))
        if ins and (ins[-1].address + ins[-1].size) == call_va:
            return ins
    return []

def createprocess_callsites(path):
    """Read the CreateProcess call sites instead of guessing from strings.

    "There is an unquoted spaced path in .rdata" is not the finding — the finding is
    "CreateProcess is called with lpApplicationName = NULL and an unquoted command line".
    The first argument decides it, so disassemble backwards from each call to the IAT slot and
    look for the register being zeroed (x64: rcx; x86: the last push before the call).

    Returns {'null_appname': n, 'nonnull_appname': n, 'inherit_true': n, 'total': n} or None
    when it could not be determined.
    """
    try:
        import pefile
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
        pe = pefile.PE(path)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
        slots = {}
        for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []) or []:
            for imp in entry.imports:
                if imp.name and imp.name.startswith(b'CreateProcess'):
                    slots[imp.address] = imp.name.decode()
        if not slots:
            pe.close()
            return None
        is64 = pe.FILE_HEADER.Machine == 0x8664
        md = Cs(CS_ARCH_X86, CS_MODE_64 if is64 else CS_MODE_32)
        base = pe.OPTIONAL_HEADER.ImageBase
        res = {'null_appname': 0, 'nonnull_appname': 0, 'inherit_true': 0, 'total': 0}
        slotset = set(slots)
        for sec in pe.sections:
            if not (sec.Characteristics & 0x20000000):
                continue
            code = sec.get_data()
            sec_va = base + sec.VirtualAddress
            # direct IAT calls, plus one level of import thunk (mingw/GCC emit `jmp [iat]`)
            targets = {a: a for a in slotset}
            for i in range(len(code) - 6):
                if code[i] == 0xFF and code[i + 1] == 0x25:            # jmp [rip+X] / jmp [abs]
                    d = int.from_bytes(code[i + 2:i + 6], 'little', signed=True)
                    t = (sec_va + i + 6 + d) if is64 else (d & 0xFFFFFFFF)
                    if t in slotset:
                        targets[sec_va + i] = t
            for call_va, _slot in _find_calls(code, sec_va, targets, is64):
                res['total'] += 1
                window = _insns_before(md, code, sec_va, call_va)
                null_app = nonnull_app = False
                for m in reversed(window):
                    mo = m.op_str.lower()
                    if is64:
                        flat = mo.replace(' ', '')
                        if m.mnemonic == 'xor' and flat in ('ecx,ecx', 'rcx,rcx'):
                            null_app = True
                            break
                        # `mov ecx, 0` zeroes the whole of rcx — the commonest GCC form
                        if m.mnemonic in ('mov', 'lea') and (flat.startswith('rcx,')
                                                             or flat.startswith('ecx,')):
                            tail = flat.split(',', 1)[1]
                            if m.mnemonic == 'mov' and tail in ('0', '0x0'):
                                null_app = True
                            else:
                                nonnull_app = True
                            break
                    else:
                        if m.mnemonic == 'push':
                            if mo.strip() in ('0', '0x0'):
                                null_app = True
                            else:
                                nonnull_app = True
                            break
                if null_app:
                    res['null_appname'] += 1
                elif nonnull_app:
                    res['nonnull_appname'] += 1
                for m in reversed(window):
                    mo = m.op_str.lower().replace(' ', '')
                    if is64 and m.mnemonic == 'mov' and mo.startswith('dwordptr[rsp+0x20],'):
                        v = mo.rsplit(',', 1)[-1]
                        if v not in ('0', '0x0'):
                            res['inherit_true'] += 1
                        break
        pe.close()
        return res
    except Exception:
        return None


def strings_of(p, cap=24 << 20):
    try:
        d = open(p, 'rb').read(cap)
    except Exception:
        return ''
    s = b'\n'.join(re.findall(rb'[\x20-\x7e]{5,}', d)).decode('latin1')
    try:
        s += '\n' + '\n'.join(re.findall(r'[\x20-\x7e]{5,}', d.decode('utf-16-le', 'ignore')))
    except Exception:
        pass
    return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--loot', required=True)
    a = ap.parse_args()
    loot = a.loot
    tri = json.load(open(os.path.join(loot, 'pe_triage.json')))
    files = {f['path']: f for f in json.load(open(os.path.join(loot, 'unwrap.json')))['files']}
    il = {}
    ilp = os.path.join(loot, 'dotnet_il.json')
    if os.path.isfile(ilp):
        il = json.load(open(ilp))

    F, rows = [], []

    def add(sev, kind, binary, detail, why, verify):
        F.append({'severity': sev, 'kind': kind, 'binary': binary, 'detail': detail,
                  'why': why, 'verify': verify})

    for b in tri['binaries']:
        if not b.get('ok'):
            continue
        rel = b['path']
        imps = {f for v in (b.get('imports') or {}).values() for f in v}
        creates = sorted(set(CREATE) & imps)
        tokens = sorted(set(TOKEN) & imps)
        hard = sorted(set(HARDENING) & imps)
        m = b.get('manifest') or {}
        priv = (m.get('requestedExecutionLevel', 'asInvoker') != 'asInvoker') or \
               ('service' in (b.get('capabilities') or {})) or \
               bool(re.search(r'(?i)(svc|service|updater|agent|helper|broker|host|elev)',
                              os.path.basename(rel)))
        fp = files.get(rel, {}).get('abs')
        s = strings_of(fp) if fp and os.path.isfile(fp) else ''
        unq = sorted({u for u in UNQUOTED_RX.findall(s)})[:12]
        privs = sorted({p for p in DANGEROUS_PRIV if p in s})
        envs = sorted({e for e in ENV_VECTORS if re.search(rf'\b{re.escape(e)}\b', s)})
        inherit_true = bool(re.search(r'(?i)bInheritHandles\s*[,=]\s*(TRUE|1)', s))
        rows.append({'binary': rel, 'privileged': priv, 'creates': creates, 'tokens': tokens,
                     'hardening': hard, 'unquoted_paths': unq, 'privileges': privs,
                     'env_vectors': envs})

        cs = createprocess_callsites(fp) if (fp and creates) else None
        if cs:
            rows[-1]['callsites'] = cs
        # The finding is the NULL lpApplicationName, confirmed at the call site. A spaced path
        # literal raises confidence but is not required: command lines are frequently built at
        # runtime, so demanding a literal in .rdata would miss the majority of real cases.
        if cs and cs['null_appname']:
            add((9 if unq else 8) if priv else 5, 'UNQUOTED-COMMANDLINE', rel,
                f"{cs['null_appname']} of {cs['total']} CreateProcess call(s) pass "
                f"lpApplicationName = NULL"
                + (f", and the binary carries unquoted spaced path literal(s) such as "
                   f"`{unq[0]}`" if unq else " (the command line is built at runtime — hook it "
                                             "with frida/win_process.js to see the real value)"),
                'CreateProcess with lpApplicationName = NULL splits the command line on spaces '
                'and tries each prefix in turn. `C:\\Program Files\\Acme\\x.exe` becomes an attempt '
                'to run `C:\\Program.exe` first. If any prefix directory is writable — and the '
                'root of C: is writable by Authenticated Users on default installs for CREATING '
                'files — that is code execution at this process privilege',
                'the NULL argument is confirmed at the call site; now check write access to each '
                'path prefix (runbook `paths[]`)')
        elif unq and creates:
            add(4 if priv else 2, 'UNQUOTED-PATH-LITERAL', rel,
                f"carries unquoted spaced path literal(s) such as `{unq[0]}`"
                + (f" but all {cs['total']} CreateProcess call(s) pass an explicit "
                   f"lpApplicationName" if cs and cs['nonnull_appname'] and not cs['null_appname']
                   else ' (call sites could not be read statically)'),
                'a spaced path in .rdata is only exploitable when it is passed as the COMMAND '
                'LINE with a NULL lpApplicationName. When the application name is explicit, the '
                'shell never splits it. Do not report this on its own',
                'read the call site: ghidra_decompile.py --targets api:CreateProcessW, or hook it '
                'live with frida/win_process.js')
        if inherit_true or (cs and cs['inherit_true']):
            add(7 if priv else 4, 'HANDLE-INHERITANCE', rel,
                'CreateProcess called with bInheritHandles = TRUE'
                + (f" ({cs['inherit_true']} call site(s) confirmed)" if cs and cs['inherit_true'] else ''),
                'every inheritable handle in the parent is duplicated into the child — including '
                'token handles, privileged file handles and pipe ends. A child that is less '
                'trusted, or that processes untrusted input, then holds them',
                'in the VM: Process Explorer -> the child -> Handles; look for anything the child '
                'should not have')
        if creates and priv and not hard:
            add(5, 'NO-MITIGATION-POLICY', rel,
                f"creates processes ({', '.join(creates[:3])}) with no ProcThreadAttribute / "
                f"job / mitigation-policy APIs",
                'children get no ACG/CIG, no binary-signature policy and no job restrictions. This '
                'is defence-in-depth, not a boundary on its own — report it only alongside a real '
                'finding, or as a hardening note',
                '-')
        for p in privs:
            add(7 if p in ('SeImpersonatePrivilege', 'SeDebugPrivilege', 'SeRestorePrivilege',
                           'SeLoadDriverPrivilege', 'SeTcbPrivilege') else 5,
                'PRIVILEGE-REFERENCE', rel, f'references `{p}`', DANGEROUS_PRIV[p],
                'check which account the process runs as and whether the privilege is ENABLED '
                '(`whoami /priv` from that context)')
        if envs and priv:
            add(6, 'ENV-INHERITANCE', rel,
                f"references environment variables that are code-execution vectors: "
                f"{', '.join(envs)}",
                'a privileged child inherits the parent environment by default. If a lower-'
                'privileged actor can influence the environment of whatever launches this '
                'process, variables like NODE_OPTIONS, PYTHONPATH, COR_PROFILER, CLASSPATH and '
                'DOTNET_STARTUP_HOOKS load attacker code into it',
                'can a standard user set these for the launching context? (per-user environment '
                'is user-writable by definition)')
        if {'ShellExecuteA', 'ShellExecuteW', 'ShellExecuteExW'} & set(creates) and priv:
            add(6, 'SHELLEXECUTE-VERB', rel,
                'a privileged process uses ShellExecute',
                'ShellExecute resolves the verb and the target through the registry, and HKCU '
                'associations are user-writable. A privileged ShellExecute on a user-supplied '
                'path or extension runs whatever the user registered',
                'check the path/extension source; then register a HKCU handler and trigger it')
        if {'CreateProcessAsUserW', 'CreateProcessWithTokenW', 'DuplicateTokenEx'} & set(tokens):
            add(5, 'TOKEN-SPRAWL', rel,
                f"token APIs: {', '.join(sorted({'CreateProcessAsUserW','CreateProcessWithTokenW','DuplicateTokenEx'} & set(tokens)))}",
                'read where the token comes from and where it goes. A SYSTEM token duplicated into '
                'a process the user can open, or a primary token assigned from a caller-supplied '
                'handle, is a direct escalation',
                'decompile the function (ghidra_decompile.py --auto)')

    for r in (il.get('results') or []):
        hits = {h['sink']: h['method'] for h in r.get('hits', [])}
        if 'System.Diagnostics.ProcessStartInfo::set_FileName' in hits or \
           'System.Diagnostics.Process::Start' in hits:
            uargs = 'System.Diagnostics.ProcessStartInfo::set_Arguments' in hits
            add(6, 'MANAGED-PROCESS-START', r['path'],
                f"Process.Start in `{hits.get('System.Diagnostics.Process::Start', '?')}`"
                + (' with a runtime-built Arguments string' if uargs else ''),
                'check that FileName is an absolute, quoted path and that Arguments is built from '
                'a fixed template — not concatenated from input. UseShellExecute=true additionally '
                'hands target selection to the registry',
                'read the method; trace the FileName/Arguments sources')

    F.sort(key=lambda x: -x['severity'])
    json.dump({'findings': F, 'binaries': rows},
              open(os.path.join(loot, 'process.json'), 'w'), indent=1)

    L = ['# Process creation, tokens and privileges', '',
         f'- findings: **{len(F)}**  ·  binaries that create processes: '
         f"**{sum(1 for r in rows if r['creates'])}**", '']
    by = {}
    for f in F:
        by.setdefault(f['kind'], []).append(f)
    for kind, rs in sorted(by.items(), key=lambda x: -x[1][0]['severity']):
        L += [f'## {kind} ({len(rs)})', '', f"_{rs[0]['why']}_", '']
        for r in rs[:20]:
            L += [f"- **`{r['binary']}`** ({r['severity']}/10) — {r['detail']}"]
            if r['verify'] != '-':
                L.append(f"  - verify: {r['verify']}")
        L.append('')
    L += ['## Per-binary', '', '| binary | priv | creates | token APIs | hardening |', '|---|---|---|---|---|']
    for r in rows:
        if not (r['creates'] or r['tokens']):
            continue
        L.append(f"| `{r['binary']}` | {'YES' if r['privileged'] else ''} | "
                 f"{', '.join(r['creates'][:3])} | {', '.join(r['tokens'][:3])} | "
                 f"{', '.join(r['hardening'][:2])} |")
    L += ['', '## The SeImpersonate note worth making every time', '',
          'If any component runs as `LocalService`, `NetworkService`, `IIS APPPOOL\\*` or a '
          'similar constrained account, check `whoami /priv` in that context. Those accounts hold '
          '**SeImpersonatePrivilege** by default, and a service account with SeImpersonate that '
          'can be made to connect to an attacker-controlled named pipe or COM endpoint reaches '
          'SYSTEM through the well-known potato technique. That is a **service-account → SYSTEM** '
          'boundary crossing and it is reportable; it is also the reason "it only runs as '
          'NetworkService" is not the mitigation vendors think it is.']
    open(os.path.join(loot, 'process.md'), 'w').write('\n'.join(L))
    print(f'[process_audit] {len(F)} findings across {len(by)} classes')
    print(f'[process_audit] -> {loot}/process.json + process.md')


if __name__ == '__main__':
    main()
