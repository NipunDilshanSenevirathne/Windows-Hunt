#!/usr/bin/env python3
"""
driver_ioctl.py — kernel driver (.sys) attack-surface extraction.

A shipped driver is the highest-severity surface a desktop product has: a bad IOCTL handler
is ring-0 from a standard user, and a signed-but-vulnerable driver is a BYOVD primitive for
everyone else too. This recovers:

  * the device name(s) the driver creates (\\Device\\X, \\DosDevices\\X, \\??\\X) — if a
    \\DosDevices symlink exists, user mode can open it
  * whether the driver sets a DACL on its device object (IoCreateDeviceSecure /
    SDDL strings) — no SDDL usually means the default, which for a non-FILE_DEVICE_SECURE_OPEN
    device is frequently openable by any user
  * the IOCTL codes it compares against, decoded into device type / function / method / access
  * the dangerous primitives it imports (MmMapIoSpace, ZwOpenProcess, MmGetPhysicalAddress,
    ObReferenceObjectByHandle, KeStackAttachProcess, ZwTerminateProcess, port I/O, MSR access)
  * whether it is WDM or KMDF, and the signing state

Usage:  driver_ioctl.py --loot loot/<name>
Writes: <loot>/drivers.json, <loot>/drivers.md
"""
import argparse, json, os, re, struct, subprocess, shutil

PRIMS = {
    'physical memory map': ['MmMapIoSpace', 'MmMapIoSpaceEx', 'ZwMapViewOfSection',
                            'MmGetPhysicalAddress', 'MmAllocateContiguousMemory'],
    'arbitrary process access': ['ZwOpenProcess', 'PsLookupProcessByProcessId',
                                 'ObOpenObjectByPointer', 'KeStackAttachProcess',
                                 'MmCopyVirtualMemory', 'ZwTerminateProcess'],
    'handle/object abuse': ['ObReferenceObjectByHandle', 'ObRegisterCallbacks',
                            'ObGetObjectType'],
    'file/registry as kernel': ['ZwCreateFile', 'ZwWriteFile', 'ZwDeleteFile',
                                'ZwSetValueKey', 'ZwCreateKey', 'ZwOpenKey'],
    'token manipulation': ['SeTokenIsAdmin', 'PsReferencePrimaryToken', 'SeCaptureSubjectContext'],
    'MSR / port I/O': ['__readmsr', '__writemsr', 'READ_PORT_UCHAR', 'WRITE_PORT_UCHAR',
                       'HalGetBusDataByOffset', 'HalSetBusDataByOffset'],
    'code execution helpers': ['ZwLoadDriver', 'ZwUnloadDriver', 'PsCreateSystemThread',
                               'ExAllocatePool', 'ExAllocatePoolWithTag'],
    'callbacks / hooks': ['PsSetCreateProcessNotifyRoutine', 'PsSetLoadImageNotifyRoutine',
                          'CmRegisterCallback', 'FltRegisterFilter'],
}
SECURE = ['IoCreateDeviceSecure', 'WdmlibIoCreateDeviceSecure', 'SDDL_DEVOBJ',
          'WdfDeviceInitAssignSDDLString']
DEVTYPE = {0x22: 'FILE_DEVICE_UNKNOWN', 0x9: 'FILE_DEVICE_DISK', 0x7: 'FILE_DEVICE_DISK_FILE_SYSTEM',
           0x12: 'FILE_DEVICE_NETWORK', 0x1f: 'FILE_DEVICE_ACPI', 0x8: 'FILE_DEVICE_CONTROLLER'}
METHOD = {0: 'METHOD_BUFFERED', 1: 'METHOD_IN_DIRECT', 2: 'METHOD_OUT_DIRECT', 3: 'METHOD_NEITHER'}
ACCESS = {0: 'FILE_ANY_ACCESS', 1: 'FILE_READ_ACCESS', 2: 'FILE_WRITE_ACCESS', 3: 'FILE_READ|WRITE'}


def decode_ioctl(code):
    return {'code': hex(code),
            'device_type': DEVTYPE.get((code >> 16) & 0xffff, hex((code >> 16) & 0xffff)),
            'access': ACCESS.get((code >> 14) & 0x3, str((code >> 14) & 0x3)),
            'function': hex((code >> 2) & 0xfff),
            'method': METHOD.get(code & 0x3, str(code & 0x3))}


def strings_of(p, cap=32 << 20):
    d = open(p, 'rb').read(cap)
    out = b'\n'.join(re.findall(rb'[\x20-\x7e]{4,}', d)).decode('latin1')
    try:
        out += '\n' + '\n'.join(re.findall(r'[\x20-\x7e]{4,}', d.decode('utf-16-le', 'ignore')))
    except Exception:
        pass
    return out, d


def find_ioctls(path):
    """cmp/sub against 32-bit immediates that decode as plausible IOCTLs."""
    codes = set()
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
        import pefile
        pe = pefile.PE(path)
        mode = CS_MODE_64 if pe.FILE_HEADER.Machine == 0x8664 else CS_MODE_32
        md = Cs(CS_ARCH_X86, mode)
        for s in pe.sections:
            if not (s.Characteristics & 0x20000000):
                continue
            base = pe.OPTIONAL_HEADER.ImageBase + s.VirtualAddress
            for ins in md.disasm(s.get_data(), base):
                if ins.mnemonic not in ('cmp', 'sub', 'mov', 'xor'):
                    continue
                m = re.search(r'0x([0-9a-f]{6,8})$', ins.op_str)
                if not m:
                    continue
                v = int(m.group(1), 16)
                dt = (v >> 16) & 0xffff
                meth = v & 3
                if 0 < dt <= 0xffff and (v >> 2) & 0xfff and meth <= 3 and 0x10000 <= v <= 0xfffffff:
                    # plausible CTL_CODE shape; the device type is usually 0x22 for third-party
                    if dt in DEVTYPE or dt >= 0x8000 or dt == 0x22:
                        codes.add(v)
        pe.close()
    except Exception:
        pass
    return sorted(codes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--loot', required=True)
    a = ap.parse_args()
    tri = json.load(open(os.path.join(a.loot, 'pe_triage.json')))
    man = {f['path']: f for f in json.load(open(os.path.join(a.loot, 'unwrap.json')))['files']}
    out = []
    for b in tri['binaries']:
        if not (b.get('is_driver') or b['path'].lower().endswith('.sys')):
            continue
        p = man.get(b['path'], {}).get('abs')
        if not p or not os.path.isfile(p):
            continue
        s, raw = strings_of(p)
        row = {'path': b['path'], 'arch': b.get('arch'),
               'signed': (b.get('signature') or {}).get('has_security_dir'),
               'signer': (b.get('signature') or {}).get('signer'),
               'devices': sorted(set(re.findall(r'\\(?:Device|DosDevices|\?\?)\\[A-Za-z0-9_.\-]{2,48}', s)))[:20],
               'sddl': sorted(set(re.findall(r'[DOSG]:(?:\([A-Za-z;()\-\w]{4,60}\)){1,12}', s)))[:10],
               'secure_create': [k for k in SECURE if k in s or k in ''.join(sum((b.get('imports') or {}).values(), []))],
               'framework': 'KMDF' if ('WdfVersionBind' in s or 'WdfDriverCreate' in s) else 'WDM',
               'primitives': {}, 'ioctls': []}
        allimp = [f for v in (b.get('imports') or {}).values() for f in v] + re.findall(r'\b[A-Za-z_][A-Za-z0-9_]{5,40}\b', s[:400000])
        for fam, names in PRIMS.items():
            got = sorted({n for n in names if any(n == x or n in x for x in allimp)})
            if got:
                row['primitives'][fam] = got
        row['ioctls'] = [decode_ioctl(c) for c in find_ioctls(p)[:120]]
        out.append(row)

    json.dump({'drivers': out}, open(os.path.join(a.loot, 'drivers.json'), 'w'), indent=1)
    L = ['# Kernel drivers', '', f'- drivers found: **{len(out)}**', '']
    if not out:
        L.append('_no .sys / native-subsystem binaries in this target_')
    for r in out:
        L += [f"## `{r['path']}` ({r['arch']}, {r['framework']})", '',
              f"- signed: {r['signed']} {('— ' + r['signer']) if r.get('signer') else ''}",
              f"- device objects: {', '.join('`'+d+'`' for d in r['devices']) or 'none recovered'}",
              f"- secure device creation: {', '.join(r['secure_create']) or '**NONE FOUND** — if the device '
               'is created with IoCreateDevice and no explicit SDDL, check whether a standard user can open it'}"]
        if r['sddl']:
            L.append(f"- SDDL strings: {', '.join('`'+x+'`' for x in r['sddl'])}")
        if r['primitives']:
            L += ['', '**kernel primitives present:**']
            for fam, names in r['primitives'].items():
                L.append(f"- {fam}: {', '.join(names)}")
        if r['ioctls']:
            L += ['', f"**IOCTL codes ({len(r['ioctls'])} candidates, decoded):**", '',
                  '| code | device type | function | method | access |', '|---|---|---|---|---|']
            for i in r['ioctls'][:60]:
                L.append(f"| {i['code']} | {i['device_type']} | {i['function']} | {i['method']} | {i['access']} |")
            L += ['', '> `METHOD_NEITHER` with `FILE_ANY_ACCESS` is the classic combination: the driver',
                  '> receives raw user pointers and any user can open the device. Check every handler',
                  '> for ProbeForRead/ProbeForWrite and for a length the caller controls.']
        L += ['', '**how to test (your own VM, `debug-attach`/`fuzz-local` must be authorized):**', '',
              '```powershell', '# 1. can a standard user open it?',
              r'#    CreateFile("\\.\<DeviceName>", GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL)',
              '# 2. enumerate reachable handlers: send each IOCTL with a small buffer, watch for',
              '#    STATUS_INVALID_PARAMETER vs STATUS_SUCCESS vs a bugcheck',
              '# 3. attach WinDbg to the VM (kernel debugging) BEFORE fuzzing — a crash with no',
              '#    debugger attached is a lost bug',
              '```', '']
    open(os.path.join(a.loot, 'drivers.md'), 'w').write('\n'.join(L))
    print(f'[driver_ioctl] {len(out)} drivers')
    print(f'[driver_ioctl] -> {a.loot}/drivers.json + drivers.md')


if __name__ == '__main__':
    main()
