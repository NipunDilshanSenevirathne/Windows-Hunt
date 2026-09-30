#!/usr/bin/env python3
"""
credstore_audit.py — where the product keeps secrets on disk, and whether that holds.

`secrets_hunt.py` finds credentials sitting in the package. This is the other half: the
credentials the product stores at RUNTIME on the user's machine — session tokens, saved
passwords, licence keys, refresh tokens, device identities — and whether the storage means
anything.

What it decides:

  DPAPI-SCOPE        CryptProtectData/ProtectedData with CurrentUser scope protects against
                     ANOTHER user, not against code running as that user. That is fine, and
                     claiming otherwise is a bad report — but LocalMachine scope protects against
                     nothing on the machine at all, and no entropy parameter weakens it further.
  ROLL-YOUR-OWN      a hardcoded AES/DES key plus a fixed IV used to "encrypt" a stored blob is
                     obfuscation, not encryption. The key is in the binary this engine read.
  PLAINTEXT-AT-REST  credentials written to a config/json/ini/registry value with no protection.
  CREDMAN            CredWrite/CredRead — the right API, but CRED_PERSIST_LOCAL_MACHINE plus a
                     generic target name is readable by every process of that user.
  TOKEN-CACHE        SQLite/JSON caches that hold bearer/refresh tokens.
  WEAK-KDF           a password turned into a key with MD5/SHA1/one PBKDF2 round.
  REGISTRY-SECRET    secrets written under HKLM where any user can read them.

Usage:  credstore_audit.py --loot loot/<name>
Writes: <loot>/credstore.json, <loot>/credstore.md
"""
import argparse, json, os, re

NATIVE = {
    'CryptProtectData': ('DPAPI protect', 4),
    'CryptUnprotectData': ('DPAPI unprotect', 4),
    'CryptProtectMemory': ('in-memory protection', 2),
    'CredWriteA': ('Credential Manager write', 4), 'CredWriteW': ('Credential Manager write', 4),
    'CredReadA': ('Credential Manager read', 3), 'CredReadW': ('Credential Manager read', 3),
    'CredEnumerateW': ('enumerates stored credentials — read WHY', 5),
    'BCryptEncrypt': ('CNG encryption', 3), 'BCryptGenerateSymmetricKey': ('CNG key import', 4),
    'CryptEncrypt': ('legacy CryptoAPI encryption', 4),
    'CryptDeriveKey': ('legacy key derivation — frequently MD5/SHA1-based', 6),
    'CryptGenKey': ('key generation', 3),
    'CryptGenRandom': ('CSPRNG — good', 1),
    'BCryptGenRandom': ('CSPRNG — good', 1),
    'NCryptOpenKey': ('CNG key storage (often TPM-backed) — the strong option', 1),
    'CryptAcquireContextW': ('CSP context', 2),
    'LsaStorePrivateData': ('LSA secrets — SYSTEM-only, strong, but readable by SYSTEM code', 3),
    'LsaRetrievePrivateData': ('LSA secrets read', 3),
    'SystemFunction041': ('undocumented RtlDecryptMemory', 5),
}
IL = {
    'System.Security.Cryptography.ProtectedData::Protect': ('DPAPI protect', 4),
    'System.Security.Cryptography.ProtectedData::Unprotect': ('DPAPI unprotect', 4),
    'System.Security.Cryptography.SymmetricAlgorithm::set_Key': ('symmetric key assigned', 7),
    'System.Security.Cryptography.SymmetricAlgorithm::set_IV': ('IV assigned', 6),
    'System.Security.Cryptography.SymmetricAlgorithm::set_Mode': ('cipher mode', 5),
    'System.Security.Cryptography.Rfc2898DeriveBytes::.ctor': ('PBKDF2', 3),
    'System.Security.Cryptography.MD5::Create': ('MD5', 5),
    'System.Security.Cryptography.SHA1::Create': ('SHA1', 4),
    'System.Random::.ctor': ('non-cryptographic RNG', 6),
}
SCOPE_LM = re.compile(r'(?i)(DataProtectionScope\.LocalMachine|CRYPTPROTECT_LOCAL_MACHINE|'
                      r'LocalMachine)')
PERSIST_LM = re.compile(r'(?i)CRED_PERSIST_LOCAL_MACHINE')
STORE_HINT = re.compile(r'(?i)([A-Za-z]:\\[^\s"\'<>|*?]{0,110}|%[A-Za-z]+%\\[^\s"\'<>|*?]{0,90})'
                        r'[\\/]?([A-Za-z0-9_.\-]{1,40}\.(?:json|xml|ini|cfg|conf|config|dat|db|'
                        r'sqlite3?|creds?|store|keystore|token|session|secret))', re.I)
CRED_NAME = re.compile(r'(?i)\b(refresh_?token|access_?token|id_?token|session_?key|'
                       r'saved_?password|remember_?me|credential|api_?secret|master_?key|'
                       r'device_?key|licen[cs]e_?key|auth_?blob)\b')
WRITABLE = re.compile(r'(?i)(programdata|\\users\\public|\\public\\|\\temp\\|%temp%)')
ECB = re.compile(r'(?i)(CipherMode\.ECB|CRYPT_MODE_ECB|BCRYPT_CHAIN_MODE_ECB)')
HARDKEY = re.compile(r'(?i)(?:key|iv)\s*=\s*(?:new\s+byte\[\]\s*)?\{\s*(?:0x[0-9a-fA-F]{2}\s*,\s*){7,}')


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

def dpapi_scope_flags(path):
    """Find the flag immediate passed to CryptProtectData.

    Native code passes CRYPTPROTECT_LOCAL_MACHINE (0x4) as a numeric constant, so there is no
    string to grep. Disassemble backwards from each call to the IAT slot and read the immediate
    that lands in the flags argument (r9d/[rsp+0x20] on x64, a push on x86). Returns the set of
    flag values observed, or None when it could not be determined — and "could not determine"
    is reported as such rather than guessed.
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
                if imp.name and b'CryptProtectData' in imp.name:
                    slots[imp.address] = imp.name.decode()
        if not slots:
            pe.close()
            return None
        is64 = pe.FILE_HEADER.Machine == 0x8664
        md = Cs(CS_ARCH_X86, CS_MODE_64 if is64 else CS_MODE_32)
        base = pe.OPTIONAL_HEADER.ImageBase
        found = set()
        slotset = set(slots)
        for sec in pe.sections:
            if not (sec.Characteristics & 0x20000000):
                continue
            code = sec.get_data()
            sec_va = base + sec.VirtualAddress
            targets = {x: x for x in slotset}
            for i in range(len(code) - 6):
                if code[i] == 0xFF and code[i + 1] == 0x25:
                    d = int.from_bytes(code[i + 2:i + 6], 'little', signed=True)
                    t = (sec_va + i + 6 + d) if is64 else (d & 0xFFFFFFFF)
                    if t in slotset:
                        targets[sec_va + i] = t
            for call_va, _slot in _find_calls(code, sec_va, targets, is64):
                # CryptProtectData(pDataIn, szDesc, pEntropy, pvReserved, pPrompt, dwFlags, pDataOut)
                # x64: arg6 -> [rsp+0x28]   x86: 6th push from the call
                window = _insns_before(md, code, sec_va, call_va, window=96)
                pushes = 0
                for m in reversed(window):
                    mo = m.op_str.lower().replace(' ', '')
                    if is64 and m.mnemonic == 'mov' and (
                            mo.startswith('dwordptr[rsp+0x28],')
                            or mo.startswith('qwordptr[rsp+0x28],')):
                        v = mo.rsplit(',', 1)[-1]
                        try:
                            found.add(int(v, 16) if v.startswith('0x') else int(v))
                        except ValueError:
                            pass
                        break
                    if not is64 and m.mnemonic == 'push':
                        pushes += 1
                        if pushes == 2:      # pDataOut, dwFlags
                            v = mo.strip()
                            try:
                                found.add(int(v, 16) if v.startswith('0x') else int(v))
                            except ValueError:
                                pass
                            break
        pe.close()
        return found or None
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--loot', required=True)
    a = ap.parse_args()
    loot = a.loot
    tri = json.load(open(os.path.join(loot, 'pe_triage.json')))
    files = {f['path']: f for f in json.load(open(os.path.join(loot, 'unwrap.json')))['files']}
    ilj = {}
    p = os.path.join(loot, 'dotnet_il.json')
    if os.path.isfile(p):
        ilj = json.load(open(p))

    F, stores, apis = [], [], []

    def add(sev, kind, where, detail, why, verify):
        F.append({'severity': sev, 'kind': kind, 'where': where, 'detail': detail,
                  'why': why, 'verify': verify})

    for b in tri['binaries']:
        if not b.get('ok'):
            continue
        rel = b['path']
        imps = {f for v in (b.get('imports') or {}).values() for f in v}
        got = {k: v for k, v in NATIVE.items() if k in imps}
        fp = files.get(rel, {}).get('abs')
        s = strings_of(fp) if fp and os.path.isfile(fp) else ''
        if got:
            apis.append({'binary': rel, 'apis': {k: v[0] for k, v in got.items()}})
        for pth, nm in STORE_HINT.findall(s)[:60]:
            full = (pth.rstrip('\\/') + '\\' + nm)
            if CRED_NAME.search(s) or re.search(r'(?i)(cred|token|secret|session|key|auth)', nm):
                stores.append({'binary': rel, 'path': full[:160],
                               'writable_location': bool(WRITABLE.search(full))})
        flags = dpapi_scope_flags(fp) if ('CryptProtectData' in got and fp) else None
        lm = bool(SCOPE_LM.search(s)) or bool(flags and any(f & 0x4 for f in flags))
        if 'CryptProtectData' in got and lm:
            add(7, 'DPAPI-LOCALMACHINE', rel,
                'CRYPTPROTECT_LOCAL_MACHINE'
                + (f' (flag 0x4 read at the call site; observed flags: '
                   f"{', '.join(hex(f) for f in sorted(flags))})" if flags else ' referenced'),
                'machine-scope DPAPI is decryptable by ANY process on the machine, including a '
                'standard user\'s. It protects against offline theft of the file only — if the '
                'blob holds a token or password, any local user recovers it',
                'copy the blob as another user and call CryptUnprotectData')
        if 'CryptProtectData' in got and not lm and flags is None:
            add(3, 'DPAPI-SCOPE-UNVERIFIED', rel,
                'CryptProtectData is used but the scope flag could not be read statically',
                'the 6th argument decides whether this protects against other users only '
                '(CurrentUser, correct) or against nobody on the machine (LOCAL_MACHINE). Read it '
                'at the call site rather than assuming',
                'scripts/ghidra_decompile.py --binary ' + os.path.basename(rel)
                + ' --targets api:CryptProtectData')
        if 'CryptProtectData' in got and not re.search(r'(?i)(pOptionalEntropy|entropy)', s):
            add(4, 'DPAPI-NO-ENTROPY', rel, 'no optional-entropy parameter in evidence',
                'without app-specific entropy, any code running as the user can unprotect the '
                'blob — which is usually acceptable, but say so rather than claiming the storage '
                'is secure', 'read the call in the decompiled function')
        if PERSIST_LM.search(s):
            add(6, 'CREDMAN-MACHINE-PERSIST', rel, 'CRED_PERSIST_LOCAL_MACHINE',
                'the credential is stored for the machine rather than the session; combined with a '
                'generic target name it is readable by every process of that user',
                'CredEnumerate as a standard user and look for it')
        if 'CryptDeriveKey' in got:
            add(6, 'WEAK-KDF', rel, 'CryptDeriveKey',
                'the legacy CryptoAPI derivation is typically a single MD5/SHA1 pass over the '
                'password — brute-forceable at enormous speed',
                'read the algorithm id passed to CryptDeriveKey')
        if HARDKEY.search(s) or (('BCryptGenerateSymmetricKey' in got or 'CryptEncrypt' in got)
                                 and not ({'CryptGenRandom', 'BCryptGenRandom', 'NCryptOpenKey'} & set(got))):
            add(8, 'ROLL-YOUR-OWN-CRYPTO', rel,
                'symmetric encryption with no CSPRNG / no key-storage API in evidence',
                'a key that is not generated and not stored by a key-management API is a constant '
                'in the binary. That is obfuscation: anyone with the file decrypts every user\'s '
                'stored blob. Extract the key and show one decrypted',
                'find the key bytes (secrets.md / native.md crypto capabilities) and decrypt a '
                'real stored blob in the VM')
        if ECB.search(s):
            add(5, 'ECB-MODE', rel, 'ECB cipher mode',
                'ECB leaks structure and permits block shuffling; on a credential store it is '
                'frequently enough to forge or recover values', 'decrypt a sample and show it')

    for r in (ilj.get('results') or []):
        hits = {h['sink']: h for h in r.get('hits', [])}
        got = {k: v for k, v in IL.items() if k in hits}
        if got:
            apis.append({'binary': r['path'], 'apis': {k: v[0] for k, v in got.items()}})
        if 'System.Security.Cryptography.SymmetricAlgorithm::set_Key' in got:
            near = hits['System.Security.Cryptography.SymmetricAlgorithm::set_Key'].get('nearby_strings') or []
            add(8, 'ROLL-YOUR-OWN-CRYPTO (managed)', r['path'],
                f"SymmetricAlgorithm::set_Key in `{hits['System.Security.Cryptography.SymmetricAlgorithm::set_Key']['method']}`"
                + (f"; nearby literals: {', '.join(repr(x)[:40] for x in near[:2])}" if near else ''),
                'trace the key source. A literal byte array, a constant string, or a value derived '
                'from a machine identifier is a hardcoded key',
                'ilspycmd the method, extract the key, decrypt a stored blob')
        if 'System.Security.Cryptography.System.Random::.ctor' in got or \
           'System.Random::.ctor' in got:
            add(6, 'NON-CRYPTO-RNG', r['path'], 'System.Random',
                'System.Random is predictable. Fatal if it produces tokens, session ids, nonces '
                'or passwords', 'find what the value is used for')
        if 'System.Security.Cryptography.ProtectedData::Protect' in got:
            add(3, 'DPAPI (managed)', r['path'], 'ProtectedData.Protect',
                'the right primitive. Check the DataProtectionScope: CurrentUser is correct, '
                'LocalMachine is not',
                'read the scope argument')

    F.sort(key=lambda x: -x['severity'])
    seen = set()
    stores = [s for s in stores if not (s['path'].lower() in seen or seen.add(s['path'].lower()))]
    json.dump({'findings': F, 'stores': stores[:80], 'apis': apis},
              open(os.path.join(loot, 'credstore.json'), 'w'), indent=1)

    L = ['# Credential storage at rest', '',
         f'- findings: **{len(F)}**  ·  candidate store paths: **{len(stores)}**  ·  '
         f'binaries using crypto/credential APIs: **{len(apis)}**', '',
         '> The bar here is specific: a credential store is a finding when **someone who should '
         '> not be able to read it, can**. DPAPI CurrentUser protecting against another user is '
         '> working as designed — do not report it as a weakness. A hardcoded key that decrypts '
         '> every installation\'s blob is a real finding, and it is Critical when the blob holds '
         '> a token to someone else\'s account.', '']
    by = {}
    for f in F:
        by.setdefault(f['kind'], []).append(f)
    for kind, rs in sorted(by.items(), key=lambda x: -x[1][0]['severity']):
        L += [f'## {kind} ({len(rs)})', '', f"_{rs[0]['why']}_", '']
        for r in rs[:15]:
            L += [f"- **`{r['where']}`** ({r['severity']}/10) — {r['detail']}",
                  f"  - verify: {r['verify']}"]
        L.append('')
    if stores:
        L += ['## Candidate store locations', '']
        for s in stores[:40]:
            L.append(f"- `{s['path']}`" + ('  **in a user-writable location**' if s['writable_location'] else '')
                     + f"  _(from {os.path.basename(s['binary'])})_")
        L += ['', 'On the host: open each one. If it is plaintext, that is the finding. If it is '
              'a DPAPI blob, note the scope. If it is custom-encrypted, find the key in the binary '
              'and decrypt it — **shipping the decryption is what turns a hardcoded key from a '
              'code-quality note into a credential-theft report.**', '']
    if apis:
        L += ['## Crypto / credential APIs by binary', '']
        for x in apis[:25]:
            L.append(f"- `{x['binary']}`: " + ', '.join(f'`{k}`' for k in list(x['apis'])[:8]))
    open(os.path.join(loot, 'credstore.md'), 'w').write('\n'.join(L))
    print(f'[credstore_audit] {len(F)} findings, {len(stores)} store paths')
    print(f'[credstore_audit] -> {loot}/credstore.json + credstore.md')


if __name__ == '__main__':
    main()
