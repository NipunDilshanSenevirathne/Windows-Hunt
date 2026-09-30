#!/usr/bin/env python3
"""
toctou_audit.py — the race and redirection primitives that turn "writes a file" into SYSTEM.

The LPE classes that do not need a memory-corruption bug all look the same: a privileged
process touches a path a lower-privileged user influences, and the gap between *deciding* and
*doing* is exploitable. This finds the code shapes that create that gap.

Detected shapes:

  TEMP-AS-SYSTEM      a privileged process using GetTempPath/GetTempFileName. For SYSTEM that
                      resolves to C:\\Windows\\Temp, where every user can CREATE files. Predictable
                      names plus create-permission is the oldest LPE in the book.
  CREATE-THEN-ACL     the file/key/directory is created first and secured afterwards. Between
                      the two calls it inherits a permissive ACL, and an opportunistic lock or a
                      simple loop wins that window.
  CHECK-THEN-USE      GetFileAttributes / PathFileExists / a signature check, then CreateFile /
                      CreateProcess / LoadLibrary on the same path. Swap the path in between.
  MOVE/DELETE-AS-SYS  MoveFileEx, ReplaceFile, DeleteFile, SHFileOperation, RemoveDirectory
                      executed by a privileged process on a user-influenced path. With a junction
                      plus an object-manager symlink these become arbitrary write/delete as SYSTEM.
  SYMLINK-ENABLERS    CreateSymbolicLink, junction/reparse APIs, or the app following links with
                      no FILE_FLAG_OPEN_REPARSE_POINT.
  IMPERSONATION-GAP   ImpersonateNamedPipeClient / ImpersonateLoggedOnUser / RpcImpersonateClient
                      with no matching RevertToSelf, or fewer reverts than impersonations — the
                      classic "acts as SYSTEM on the error path".
  NO-IMPERSONATION    a named-pipe or RPC server that never impersonates at all: it does
                      everything the caller asks as SYSTEM, by construction.
  UNSAFE-EXTRACT      an archive/update extractor without path canonicalisation (Zip-Slip) or
                      without rejecting links.

Usage:  toctou_audit.py --loot loot/<name>
Writes: <loot>/toctou.json, <loot>/toctou.md
"""
import argparse, json, os, re

W_API = {
    'temp': ['GetTempPathA', 'GetTempPathW', 'GetTempFileNameA', 'GetTempFileNameW',
             'GetTempPath2A', 'GetTempPath2W'],
    'create': ['CreateFileA', 'CreateFileW', 'CreateDirectoryA', 'CreateDirectoryW',
               'CreateFile2', 'SHCreateDirectoryExW', 'RegCreateKeyExA', 'RegCreateKeyExW'],
    'acl': ['SetSecurityInfo', 'SetNamedSecurityInfoA', 'SetNamedSecurityInfoW',
            'SetFileSecurityA', 'SetFileSecurityW', 'SetEntriesInAclA', 'SetEntriesInAclW',
            'SetKernelObjectSecurity', 'ConvertStringSecurityDescriptorToSecurityDescriptorA',
            'ConvertStringSecurityDescriptorToSecurityDescriptorW'],
    'check': ['GetFileAttributesA', 'GetFileAttributesW', 'GetFileAttributesExW',
              'PathFileExistsA', 'PathFileExistsW', 'GetFileSecurityW', 'FindFirstFileW',
              'WinVerifyTrust', 'CryptCATAdminCalcHashFromFileHandle', '_waccess', '_access'],
    'use': ['CreateProcessA', 'CreateProcessW', 'CreateProcessAsUserW', 'ShellExecuteA',
            'ShellExecuteW', 'ShellExecuteExW', 'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExW',
            'CopyFileA', 'CopyFileW', 'CopyFileExW', 'MoveFileExA', 'MoveFileExW'],
    'moveDelete': ['MoveFileA', 'MoveFileW', 'MoveFileExA', 'MoveFileExW', 'MoveFileWithProgressW',
                   'ReplaceFileA', 'ReplaceFileW', 'DeleteFileA', 'DeleteFileW',
                   'RemoveDirectoryA', 'RemoveDirectoryW', 'SHFileOperationA', 'SHFileOperationW',
                   'RegDeleteKeyExW', 'RegDeleteTreeW'],
    'symlink': ['CreateSymbolicLinkA', 'CreateSymbolicLinkW', 'CreateHardLinkA', 'CreateHardLinkW',
                'DeviceIoControl', 'NtCreateSymbolicLinkObject', 'NtCreateFile'],
    'impersonate': ['ImpersonateNamedPipeClient', 'ImpersonateLoggedOnUser', 'ImpersonateSelf',
                    'RpcImpersonateClient', 'ImpersonateAnonymousToken',
                    'CoImpersonateClient', 'SetThreadToken'],
    'revert': ['RevertToSelf', 'RpcRevertToSelf', 'CoRevertToSelf'],
    'ipcserver': ['CreateNamedPipeA', 'CreateNamedPipeW', 'ConnectNamedPipe',
                  'RpcServerRegisterIf', 'RpcServerRegisterIfEx', 'RpcServerRegisterIf2',
                  'RpcServerRegisterIf3', 'NtAlpcCreatePort'],
    'oplock': ['DeviceIoControl', 'NtFsControlFile'],
}
IL_SINKS = {
    'temp': ['System.IO.Path::GetTempPath', 'System.IO.Path::GetTempFileName'],
    'moveDelete': ['System.IO.File::Move', 'System.IO.File::Delete', 'System.IO.File::Replace',
                   'System.IO.Directory::Delete'],
    'acl': ['System.Security.AccessControl.FileSystemSecurity::AddAccessRule',
            'System.Security.AccessControl.FileSystemSecurity::SetAccessRule',
            'System.IO.FileSystemAclExtensions::SetAccessControl'],
    'check': ['System.IO.File::Exists', 'System.IO.Directory::Exists'],
    'use': ['System.Diagnostics.Process::Start', 'System.Reflection.Assembly::LoadFrom',
            'System.IO.File::Copy'],
    'impersonate': ['System.Security.Principal.WindowsIdentity::Impersonate'],
    'revert': ['System.Security.Principal.WindowsImpersonationContext::Undo'],
    'extract': ['System.IO.Compression.ZipFile::ExtractToDirectory',
                'System.IO.Compression.ZipFileExtensions::ExtractToFile'],
}
WRITABLE = re.compile(r'(?i)(programdata|\\users\\public|\\public\\|\\windows\\temp|\\temp\\|'
                      r'%temp%|appdata|localappdata)')
CANON = re.compile(r'(?i)(GetFullPathName|PathCanonicalize|PathCchCanonicalize|'
                   r'Path\.GetFullPath|FILE_FLAG_OPEN_REPARSE_POINT|FSCTL_GET_REPARSE_POINT|'
                   r'startswith.{0,40}basepath|IsPathUnderRoot)')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--loot', required=True)
    a = ap.parse_args()
    loot = a.loot

    def J(n):
        p = os.path.join(loot, n)
        return json.load(open(p)) if os.path.isfile(p) else {}

    tri, surf = J('pe_triage.json'), J('surface.json')
    il, man = J('dotnet_il.json'), J('unwrap.json')
    files = {f['path']: f for f in man.get('files', [])}
    F = []

    def add(sev, kind, binary, detail, why, verify, boundary='user-to-system'):
        F.append({'severity': sev, 'kind': kind, 'binary': binary, 'detail': detail,
                  'why': why, 'verify': verify, 'boundary': boundary})

    # ---------------- native ----------------------------------------------------
    for b in tri.get('binaries', []):
        if not b.get('ok'):
            continue
        rel = b['path']
        imps = {f for v in (b.get('imports') or {}).values() for f in v}
        have = {k: sorted({x for x in names if x in imps}) for k, names in W_API.items()}
        m = b.get('manifest') or {}
        priv = (m.get('requestedExecutionLevel', 'asInvoker') != 'asInvoker') or \
               ('service' in (b.get('capabilities') or {})) or \
               bool(re.search(r'(?i)(svc|service|updater|update|agent|helper|broker|host|elev)',
                              os.path.basename(rel)))
        # strings once
        s = ''
        fp = files.get(rel, {}).get('abs')
        if fp and os.path.isfile(fp):
            try:
                d = open(fp, 'rb').read(24 << 20)
                s = b'\n'.join(re.findall(rb'[\x20-\x7e]{5,}', d)).decode('latin1')
                s += '\n' + '\n'.join(re.findall(r'[\x20-\x7e]{5,}', d.decode('utf-16-le', 'ignore')))
            except Exception:
                pass
        writable_strings = sorted({x for x in re.findall(r'(?i)[A-Za-z]:\\[^\s"\'<>|*?]{4,110}', s)
                                   if WRITABLE.search(x)})[:20]

        if have['temp'] and priv:
            add(8, 'TEMP-AS-SYSTEM', rel,
                f"uses {', '.join(have['temp'])} and looks privileged",
                'for a SYSTEM process GetTempPath resolves to C:\\Windows\\Temp, which grants '
                'Users create-file permission. GetTempFileName names are predictable '
                '(tmpXXXX.tmp, 0000-FFFF) — a standard user can pre-create, squat or symlink the '
                'file before the privileged process opens it',
                'Procmon the privileged process: does it CreateFile under C:\\Windows\\Temp? then '
                'pre-create the same name as a standard user and watch what happens')
        if have['create'] and have['acl']:
            add(7, 'CREATE-THEN-ACL', rel,
                f"creates objects ({', '.join(have['create'][:3])}) AND sets ACLs "
                f"({', '.join(have['acl'][:3])})",
                'if the object is created first and secured afterwards, it inherits the parent ACL '
                'for the duration. An oplock or a tight loop wins that window; on a directory the '
                'attacker can also drop a file inside before the ACL lands',
                'decompile the creating function (ghidra_decompile.py) and read the ORDER; then '
                'race it in the VM')
        if have['check'] and have['use']:
            add(7, 'CHECK-THEN-USE', rel,
                f"checks ({', '.join(have['check'][:3])}) then acts ({', '.join(have['use'][:3])})",
                'a path validated and then used in two separate calls is a TOCTOU. If the check is '
                'a SIGNATURE check (WinVerifyTrust) and the use is CreateProcess/LoadLibrary, the '
                'file can be swapped between them — the signature proves nothing about what ran',
                'decompile and confirm the same path is re-opened rather than a handle reused; '
                'then swap the file with an oplock held')
        if have['moveDelete'] and priv:
            add(8, 'MOVE/DELETE-AS-SYSTEM', rel,
                f"privileged process calls {', '.join(have['moveDelete'][:4])}",
                'arbitrary file delete and arbitrary file move are both known-good LPE primitives. '
                'With an NTFS junction plus an object-manager symlink the operation lands wherever '
                'the attacker chooses. MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT is especially '
                'strong: it writes to the registry and executes as SYSTEM at boot',
                'Procmon the operation, confirm the source path is under a directory you control, '
                'then use CreateMountPoint + CreateSymlink (symboliclink-testing-tools)')
        if have['symlink']:
            add(4, 'SYMLINK-ENABLERS', rel,
                f"link/reparse APIs present: {', '.join(have['symlink'][:3])}",
                'the product creates or follows links. Following a link without '
                'FILE_FLAG_OPEN_REPARSE_POINT means a junction under a writable directory '
                'redirects the privileged operation',
                'check every CreateFile for FILE_FLAG_OPEN_REPARSE_POINT')
        nimp, nrev = len(have['impersonate']), len(have['revert'])
        if nimp and not nrev:
            add(9, 'IMPERSONATION-GAP', rel,
                f"impersonates ({', '.join(have['impersonate'])}) but imports NO RevertToSelf",
                'the thread keeps the caller token, or worse, never drops back — but the far more '
                'common bug is the opposite: the privileged operation happens BEFORE the '
                'impersonation or AFTER an early return. Either way the server acts as SYSTEM on '
                'input it was given',
                'decompile the pipe/RPC handler and trace every path, including exception paths')
        elif have['ipcserver'] and not have['impersonate']:
            add(8, 'NO-IMPERSONATION', rel,
                f"exposes an IPC server ({', '.join(have['ipcserver'][:3])}) and never impersonates",
                'the server performs every requested operation with its own token. If it runs as '
                'SYSTEM and any opnum/message takes a path, a command or a config, that is the '
                'LPE by construction — there is no authorization step at all',
                'enumerate the message/opnum set; find one that acts on a caller-supplied path')
        if writable_strings and (have['use'] or have['create']):
            add(6, 'WRITABLE-PATH-IN-PRIVILEGED-BINARY' if priv else 'WRITABLE-PATH', rel,
                f"references {len(writable_strings)} user-writable path(s), e.g. "
                f"`{writable_strings[0]}`",
                'cross this against what the binary DOES with the path (native.md names the '
                'function). A privileged read of code/config from here is the LPE',
                'ghidra_decompile.py --binary ' + os.path.basename(rel) + ' --auto',
                'user-to-system' if priv else 'same-user')
        if ('CopyFileW' in imps or 'CopyFileExW' in imps) and priv and not CANON.search(s):
            add(6, 'NO-CANONICALISATION', rel,
                'copies files and shows no canonicalisation/reparse-guard strings',
                'a copy that does not canonicalise and does not open with '
                'FILE_FLAG_OPEN_REPARSE_POINT will follow a junction out of the intended directory',
                'test with a junction in the source directory')

    # ---------------- managed ----------------------------------------------------
    for r in (il.get('results') or []):
        sinks = {h['sink'] for h in r.get('hits', [])}
        methods = {h['sink']: h['method'] for h in r.get('hits', [])}
        fam = {k: sorted(sinks & set(v)) for k, v in IL_SINKS.items()}
        if fam['temp'] and (fam['use'] or fam['moveDelete']):
            add(7, 'TEMP-AS-SYSTEM (managed)', r['path'],
                f"{', '.join(fam['temp'])} combined with {', '.join((fam['use'] + fam['moveDelete'])[:3])}",
                'same class as the native case — predictable names in a shared temp directory',
                'check whether this assembly runs in a privileged host process')
        if fam['acl']:
            add(7, 'CREATE-THEN-ACL (managed)', r['path'],
                f"{', '.join(fam['acl'])} in `{methods.get(fam['acl'][0], '')}`",
                'read the ACE being added and WHEN it is added relative to creation',
                'decompile with ilspycmd, or read the IL around the call')
        if fam['impersonate'] and not fam['revert']:
            add(8, 'IMPERSONATION-GAP (managed)', r['path'],
                'WindowsIdentity::Impersonate with no WindowsImpersonationContext::Undo',
                'an impersonation not wrapped in using/try-finally leaks the identity on the '
                'exception path; the inverse (operation outside the impersonated block) is the '
                'more common and more serious bug',
                'read the method; confirm the privileged call sits inside the impersonated scope')
        if fam['extract']:
            add(7, 'UNSAFE-EXTRACT', r['path'],
                f"{', '.join(fam['extract'])}",
                'Zip-Slip: an entry named ..\\..\\Windows\\System32\\x.dll escapes the target '
                'directory. Pre-4.5.1 ExtractToDirectory and every hand-rolled loop are affected; '
                'symlink entries are a second, separate bug',
                'build an archive with a traversing entry name and extract it')

    # ---------------- installer-level ----------------------------------------------
    for r in (surf.get('custom_actions') or []):
        v = r['v']
        if v.get('deferred') and v.get('no_impersonate'):
            add(8, 'MSI-SYSTEM-CUSTOM-ACTION', 'installer',
                f"custom action `{v['action']}` ({v['kind']}) runs as SYSTEM, target "
                f"`{v['target'][:100]}`",
                'a per-machine MSI can be REPAIRED by a standard user (`msiexec /fa`), which '
                're-runs deferred custom actions as SYSTEM on demand. If the action executes a '
                'file, a script, or a command built from a property the user can influence, that '
                'is a repeatable LPE',
                'as a standard user: msiexec /fa {ProductCode} and watch the token in Procmon')

    F.sort(key=lambda x: -x['severity'])
    json.dump({'count': len(F), 'findings': F}, open(os.path.join(loot, 'toctou.json'), 'w'), indent=1)

    L = ['# TOCTOU / race / redirection primitives', '',
         f'- candidate primitives: **{len(F)}**', '',
         '> These are the LPE classes that need no memory-corruption bug. Each one is a *shape*',
         '> in the code; confirming it means reading the function (`ghidra_decompile.py`) and then',
         '> winning the race or planting the link in the VM.', '']
    by = {}
    for f in F:
        by.setdefault(f['kind'], []).append(f)
    for kind, rows in sorted(by.items(), key=lambda x: -x[1][0]['severity']):
        L += [f'## {kind} ({len(rows)})', '', f"_{rows[0]['why']}_", '']
        for r in rows[:20]:
            L += [f"- **`{r['binary']}`** ({r['severity']}/10) — {r['detail']}",
                  f"  - verify: {r['verify']}"]
        L.append('')
    if F:
        L += ['## Exploiting the primitives once confirmed', '',
              '| primitive | standard technique |', '|---|---|',
              '| arbitrary file WRITE as SYSTEM | drop a DLL a privileged process loads; or write '
              'a `.MOF`/scheduled-task/service binary; or target a directory in the DLL search path |',
              '| arbitrary file DELETE as SYSTEM | delete-to-rollback (MSI), or delete a file whose '
              'absence causes a privileged process to fall back to a writable location |',
              '| arbitrary folder CREATE as SYSTEM | create a directory that a privileged loader '
              'searches before the real one |',
              '| file MOVE as SYSTEM | the same as write, with the source under your control |',
              '| ACL window on create | drop a file into the directory before the ACL is applied |',
              '',
              '`scripts/primitive_to_exploit.py` expands each of these into the concrete chain, '
              'the preconditions, and the PoC to generate.', '',
              '## Tooling for the VM', '',
              '- **symboliclink-testing-tools** (Forshaw): `CreateMountPoint`, `CreateSymlink`, '
              '`SetOpLock`, `BaitAndSwitch` — the reference primitives for junction + object-manager '
              'symlink redirection and for winning check-then-use windows.',
              '- **Procmon** with the filter generated by `scripts/procmon_filter.py` — it is '
              'pre-filtered to the paths and processes this engine flagged.']
    else:
        L.append('_no race/redirection shapes found. Record that in the ledger — it is a real '
                 'result, and it means the LPE, if there is one, is elsewhere._')
    open(os.path.join(loot, 'toctou.md'), 'w').write('\n'.join(L))
    print(f'[toctou_audit] {len(F)} primitives across {len(by)} classes')
    print(f'[toctou_audit] -> {loot}/toctou.json + toctou.md')


if __name__ == '__main__':
    main()
