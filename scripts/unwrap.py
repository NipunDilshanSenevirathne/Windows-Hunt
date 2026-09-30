#!/usr/bin/env python3
"""
unwrap.py — recursive Windows-container unwrapper.

Most tools stop at "it's an installer". Every interesting bug lives INSIDE: the service exe
three layers down, the .NET assembly inside the MSI inside the Burn bundle, the phantom DLL
the Electron app loads, the update key in an asar. This walks every container type Windows
ships and produces a flat, hashed, typed file tree plus a manifest the rest of the pipeline
reads.

Containers handled:
  MSI (msiextract + full table dump)        NSIS (7z)              Inno Setup (innoextract)
  WiX Burn bundle (7z / attached container) InstallShield (7z)     MSIX/APPX/ZIP (zip)
  CAB (cabextract)                          SFX exe (7z)           UPX (upx -d)
  Electron .asar (pure python)              PyInstaller (pure python)
  .NET single-file bundle (detect+carve)    NuGet .nupkg           7z/rar/tar/gz/xz
  generic carve fallback (binwalk)

Usage:
  unwrap.py --target <file> --out loot/<name> [--depth 6] [--max-mb 4096]
  unwrap.py --target <dir>  --out loot/<name>          # already-installed app directory

Writes:
  <out>/extracted/...        the file tree
  <out>/unwrap.json          manifest: every file, sha256, type, size, container lineage
  <out>/unwrap.md            human summary: what it is, what came out, what to look at first
"""
import argparse, hashlib, json, os, re, shutil, struct, subprocess, sys, zipfile, tarfile

MAXD = 6
SKIP_EXT = {'.png', '.jpg', '.jpeg', '.gif', '.ico', '.bmp', '.svg', '.ttf', '.otf', '.woff',
            '.woff2', '.mp3', '.mp4', '.wav', '.avi', '.pdb'}


def sh(cmd, cwd=None, timeout=900):
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=timeout)
        return p.returncode, p.stdout.decode('utf-8', 'replace'), p.stderr.decode('utf-8', 'replace')
    except Exception as e:
        return 1, '', str(e)


def have(t):
    return shutil.which(t) is not None


def sha256(p):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for c in iter(lambda: f.read(1 << 20), b''):
            h.update(c)
    return h.hexdigest()


def head(p, n=4096):
    try:
        with open(p, 'rb') as f:
            return f.read(n)
    except Exception:
        return b''


# ---------------------------------------------------------------- identification
def identify(p):
    """Return (kind, detail). kind drives the extractor table."""
    b = head(p, 1 << 16)
    name = os.path.basename(p).lower()
    if not b:
        return 'empty', ''
    if b[:2] == b'MZ':
        blob = b''
        try:
            with open(p, 'rb') as f:
                blob = f.read(6 << 20)
        except Exception:
            pass
        low = blob.lower()
        if b'UPX0' in blob or b'UPX1' in blob:
            return 'upx', 'UPX-packed PE'
        if b'\xef\xbe\xad\xdeNullsoftInst' in blob:
            return 'nsis', 'NSIS installer'
        if b'Inno Setup' in blob or b'JR.Inno.Setup' in blob:
            return 'inno', 'Inno Setup installer'
        if b'WixBundle' in blob or b'.wixburn' in low:
            return 'burn', 'WiX Burn bundle'
        if b'InstallShield' in blob or b'ISSetup' in blob:
            return 'installshield', 'InstallShield'
        if b'PyInstaller' in blob or b'MEI\x0c\x0b\x0a\x0b\x0e' in blob or b'pyi-windows-manifest' in blob:
            return 'pyinstaller', 'PyInstaller bundle'
        if b'AutoIt v3' in blob:
            return 'autoit', 'AutoIt3 compiled script'
        if b'7-Zip' in blob and b'SfxVar' in blob:
            return 'sfx7z', '7-Zip SFX'
        if b'WinRAR SFX' in blob or b'winrarsfx' in low:
            return 'sfxrar', 'WinRAR SFX'
        if b'.netbundle' in low or b'\x8b\x12\x02\xb9\x6a\x61\x20\x38' in blob:
            return 'dotnetbundle', '.NET single-file bundle'
        if b'Squirrel' in blob:
            return 'pe', 'PE (Squirrel-packaged app)'
        return 'pe', 'PE executable/DLL'
    if b[:8] == b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1':
        return 'msi', 'MSI / OLE compound file'
    if b[:4] == b'MSCF':
        return 'cab', 'Microsoft CAB'
    if b[:4] == b'PK\x03\x04':
        if name.endswith(('.msix', '.appx', '.msixbundle', '.appxbundle')):
            return 'msix', 'MSIX/APPX package'
        if name.endswith('.nupkg'):
            return 'nupkg', 'NuGet package'
        return 'zip', 'ZIP archive'
    if b[:6] == b'7z\xbc\xaf\x27\x1c':
        return '7z', '7-Zip archive'
    if b[:4] == b'Rar!':
        return 'rar', 'RAR archive'
    if b[:2] == b'\x1f\x8b':
        return 'tar', 'gzip'
    if b[:6] == b'\xfd7zXZ\x00':
        return 'tar', 'xz'
    if b[:4] == b'\x04\x22\x4d\x18':
        return 'other', 'lz4'
    if name.endswith('.asar') or b[:4] == b'\x04\x00\x00\x00' and b'"files"' in b[:8192]:
        return 'asar', 'Electron asar'
    if b[:5] == b'<?xml' or b[:1] == b'<':
        return 'xml', 'XML/manifest'
    if b[:4] == b'\x53\x51\x4c\x69':
        return 'sqlite', 'SQLite DB'
    return 'other', ''


# ---------------------------------------------------------------- extractors
def x_zip(src, dst):
    try:
        with zipfile.ZipFile(src) as z:
            for m in z.infolist():
                # zip-slip safe
                t = os.path.normpath(os.path.join(dst, m.filename))
                if not t.startswith(os.path.abspath(dst)):
                    continue
                if m.is_dir():
                    os.makedirs(t, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(t), exist_ok=True)
                with z.open(m) as fi, open(t, 'wb') as fo:
                    shutil.copyfileobj(fi, fo)
        return True, 'zipfile'
    except Exception as e:
        return False, str(e)


def x_7z(src, dst):
    if not have('7z'):
        return False, '7z missing'
    rc, o, e = sh(['7z', 'x', '-y', '-bd', f'-o{dst}', src])
    return (os.path.isdir(dst) and any(os.scandir(dst))), f'7z rc={rc}'


def x_msi(src, dst):
    os.makedirs(dst, exist_ok=True)
    notes = []
    if have('msiextract'):
        rc, o, e = sh(['msiextract', '-C', dst, src])
        notes.append(f'msiextract rc={rc}')
    if have('msiinfo'):
        tdir = os.path.join(dst, '_msi_tables')
        os.makedirs(tdir, exist_ok=True)
        src_abs = os.path.abspath(src)
        rc, o, e = sh(['msiinfo', 'tables', src_abs], cwd=tdir)
        tables = [t.strip() for t in o.splitlines() if t.strip()]
        # the tables that decide whether this installer creates an LPE
        want = ['CustomAction', 'InstallExecuteSequence', 'InstallUISequence', 'Directory',
                'File', 'Component', 'Registry', 'ServiceInstall', 'ServiceControl', 'Shortcut',
                'Property', 'Binary', 'LockPermissions', 'MsiLockPermissionsEx', 'Media',
                'Environment', 'Extension', 'Verb', 'ProgId', 'Class', 'AppId', 'Upgrade']
        got = 0
        for t in tables:
            if t in want or len(tables) < 40:
                rc2, o2, _ = sh(['msiinfo', 'export', src_abs, t], cwd=tdir)
                if rc2 == 0 and o2:
                    open(os.path.join(tdir, f'{t}.txt'), 'w').write(o2)
                    got += 1
        open(os.path.join(tdir, '_tables.txt'), 'w').write('\n'.join(tables))
        notes.append(f'msiinfo exported {got}/{len(tables)} tables')
    if not any(os.scandir(dst)):
        return x_7z(src, dst)
    return True, '; '.join(notes)


def x_cab(src, dst):
    os.makedirs(dst, exist_ok=True)
    if have('cabextract'):
        rc, o, e = sh(['cabextract', '-q', '-d', dst, src])
        if os.path.isdir(dst) and any(os.scandir(dst)):
            return True, f'cabextract rc={rc}'
    return x_7z(src, dst)


def x_inno(src, dst):
    if have('innoextract'):
        os.makedirs(dst, exist_ok=True)
        rc, o, e = sh(['innoextract', '-s', '-d', dst, src])
        if any(os.scandir(dst)):
            return True, f'innoextract rc={rc}'
    return x_7z(src, dst)


def x_upx(src, dst):
    os.makedirs(dst, exist_ok=True)
    out = os.path.join(dst, 'unpacked_' + os.path.basename(src))
    shutil.copy2(src, out)
    if have('upx'):
        rc, o, e = sh(['upx', '-d', '-q', out])
        if rc == 0:
            return True, 'upx -d'
    return False, 'upx failed (custom/modified packer — treat as packed)'


def x_asar(src, dst):
    """Pure-python Electron asar extractor: uint32 pickle-ish header, JSON index, blob body."""
    try:
        with open(src, 'rb') as f:
            data = f.read()
        if len(data) < 16:
            return False, 'too small'
        (hsz,) = struct.unpack('<I', data[0:4])
        (jlen,) = struct.unpack('<I', data[12:16])
        js = data[16:16 + jlen].decode('utf-8', 'replace').rstrip('\x00')
        idx = json.loads(js)
        base = 16 + jlen
        base = base + ((4 - base % 4) % 4)
        n = [0]

        def walk(node, path):
            for name, v in (node.get('files') or {}).items():
                t = os.path.normpath(os.path.join(path, name))
                if 'files' in v:
                    os.makedirs(t, exist_ok=True)
                    walk(v, t)
                elif 'offset' in v:
                    off = base + int(v['offset'])
                    sz = int(v.get('size', 0))
                    os.makedirs(os.path.dirname(t), exist_ok=True)
                    with open(t, 'wb') as fo:
                        fo.write(data[off:off + sz])
                    n[0] += 1
        os.makedirs(dst, exist_ok=True)
        walk(idx, dst)
        open(os.path.join(dst, '_asar_index.json'), 'w').write(json.dumps(idx, indent=1)[:2_000_000])
        return n[0] > 0, f'asar: {n[0]} files'
    except Exception as e:
        return False, f'asar: {e}'


def x_pyinstaller(src, dst):
    """Minimal PyInstaller CArchive extractor (PYZ left as-is for the python engine)."""
    MAGIC = b'MEI\x0c\x0b\x0a\x0b\x0e'
    try:
        data = open(src, 'rb').read()
        pos = data.rfind(MAGIC)
        if pos < 0:
            return False, 'no PyInstaller cookie'
        # cookie: magic(8) lengthofPackage(4) toc(4) tocLen(4) pyver(4) [pylibname(64) in >=2.1]
        pkglen, toc, toclen, pyver = struct.unpack('!IIII', data[pos + 8:pos + 24])
        tail = len(data) - pos
        # locate archive start
        start = len(data) - tail - (pkglen - tail) if pkglen > tail else pos + 24 - pkglen
        start = max(0, len(data) - pkglen - (tail - 24) if False else data.rfind(MAGIC) + 24 - pkglen)
        tocpos = start + toc
        p = tocpos
        end = tocpos + toclen
        os.makedirs(dst, exist_ok=True)
        import zlib
        n = 0
        while p < end and p + 18 <= len(data):
            (entlen,) = struct.unpack('!I', data[p:p + 4])
            if entlen < 18 or p + entlen > len(data):
                break
            entry = data[p:p + entlen]
            epos, cmplen, uncmplen, cflag = struct.unpack('!IIIB', entry[4:17])
            typ = entry[17:18].decode('latin1')
            nm = entry[18:].split(b'\x00')[0].decode('utf-8', 'replace') or f'unnamed_{n}'
            raw = data[start + epos:start + epos + cmplen]
            if cflag:
                try:
                    raw = zlib.decompress(raw)
                except Exception:
                    pass
            t = os.path.normpath(os.path.join(dst, nm.replace('\\', '/').lstrip('/')))
            if t.startswith(os.path.abspath(dst)):
                os.makedirs(os.path.dirname(t), exist_ok=True)
                sfx = '.pyc' if typ in ('s', 'm', 'M') else ''
                open(t + sfx, 'wb').write(raw)
                n += 1
            p += entlen
        return n > 0, f'pyinstaller: {n} entries (pyver {pyver})'
    except Exception as e:
        return False, f'pyinstaller: {e}'


def x_tar(src, dst):
    try:
        os.makedirs(dst, exist_ok=True)
        with tarfile.open(src) as t:
            for m in t.getmembers():
                p = os.path.normpath(os.path.join(dst, m.name))
                if p.startswith(os.path.abspath(dst)):
                    t.extract(m, dst)
        return True, 'tarfile'
    except Exception:
        return x_7z(src, dst)


def x_binwalk(src, dst):
    if not have('binwalk'):
        return False, 'binwalk missing'
    os.makedirs(dst, exist_ok=True)
    rc, o, e = sh(['binwalk', '-e', '--run-as=root', '-q', '-C', dst, src], timeout=600)
    return (any(os.scandir(dst)) if os.path.isdir(dst) else False), f'binwalk rc={rc}'


EXTRACT = {
    'msi': x_msi, 'cab': x_cab, 'nsis': x_7z, 'inno': x_inno, 'burn': x_7z,
    'installshield': x_7z, 'sfx7z': x_7z, 'sfxrar': x_7z, 'zip': x_zip, 'msix': x_zip,
    'nupkg': x_zip, '7z': x_7z, 'rar': x_7z, 'tar': x_tar, 'upx': x_upx, 'asar': x_asar,
    'pyinstaller': x_pyinstaller, 'autoit': x_7z, 'dotnetbundle': x_binwalk,
}
# containers we will recurse into even when they arrive as plain PEs
PE_CONTAINERS = {'nsis', 'inno', 'burn', 'installshield', 'sfx7z', 'sfxrar', 'upx',
                 'pyinstaller', 'autoit', 'dotnetbundle'}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--target', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--depth', type=int, default=MAXD)
    ap.add_argument('--max-mb', type=int, default=4096)
    a = ap.parse_args()

    out = os.path.abspath(a.out)
    exdir = os.path.join(out, 'extracted')
    os.makedirs(exdir, exist_ok=True)
    man = {'target': os.path.abspath(a.target), 'root_kind': None, 'files': [], 'containers': [],
           'errors': [], 'budget_mb': a.max_mb}
    seen = set()
    total = [0]

    def record(path, lineage, depth):
        try:
            sz = os.path.getsize(path)
        except OSError:
            return None
        if sz == 0:
            return None
        ext = os.path.splitext(path)[1].lower()
        h = sha256(path) if sz < (512 << 20) else 'skipped-large'
        if h in seen:
            return None
        seen.add(h)
        kind, detail = identify(path)
        rec = {'path': os.path.relpath(path, out) if path.startswith(out) else path,
               'abs': path, 'size': sz, 'sha256': h, 'kind': kind, 'detail': detail,
               'ext': ext, 'lineage': lineage, 'depth': depth}
        man['files'].append(rec)
        return rec

    def walk_dir(d, lineage, depth):
        for root, dirs, files in os.walk(d):
            dirs[:] = [x for x in dirs if x not in ('.git', 'node_modules_cache')]
            for f in files:
                p = os.path.join(root, f)
                if os.path.islink(p):
                    continue
                if os.path.splitext(f)[1].lower() in SKIP_EXT:
                    continue
                r = record(p, lineage, depth)
                if r:
                    consider(r, depth)

    def consider(rec, depth):
        if depth >= a.depth:
            return
        kind = rec['kind']
        if kind not in EXTRACT:
            return
        if kind == 'pe':
            return
        if total[0] > a.max_mb * (1 << 20):
            man['errors'].append(f"budget exceeded, skipped {rec['path']}")
            return
        sub = os.path.join(out, '_unpacked', f"{depth}_{os.path.basename(rec['abs'])[:60]}_{rec['sha256'][:8]}")
        ok, note = EXTRACT[kind](rec['abs'], sub)
        man['containers'].append({'path': rec['path'], 'kind': kind, 'detail': rec['detail'],
                                  'ok': bool(ok), 'note': note, 'into': os.path.relpath(sub, out),
                                  'depth': depth})
        if ok and os.path.isdir(sub):
            for root, _, fs in os.walk(sub):
                for f in fs:
                    try:
                        total[0] += os.path.getsize(os.path.join(root, f))
                    except OSError:
                        pass
            walk_dir(sub, rec['lineage'] + [rec['path']], depth + 1)

    tgt = os.path.abspath(a.target)
    if os.path.isdir(tgt):
        man['root_kind'] = 'directory'
        walk_dir(tgt, [], 0)
    else:
        r = record(tgt, [], 0)
        if r:
            man['root_kind'] = f"{r['kind']} ({r['detail']})"
            consider(r, 0)
        else:
            man['errors'].append('target unreadable/empty')

    # summary
    by_kind = {}
    for f in man['files']:
        by_kind[f['kind']] = by_kind.get(f['kind'], 0) + 1
    man['summary'] = by_kind
    json.dump(man, open(os.path.join(out, 'unwrap.json'), 'w'), indent=1)

    L = [f"# Unwrap — {os.path.basename(tgt)}", '',
         f"- target: `{tgt}`", f"- root kind: **{man['root_kind']}**",
         f"- files recovered: **{len(man['files'])}** ({len(man['containers'])} containers opened)", '']
    L.append('## Container lineage')
    if man['containers']:
        for c in man['containers']:
            mark = 'OK ' if c['ok'] else 'FAIL'
            L.append(f"- [{mark}] d{c['depth']} `{c['path']}` — {c['kind']} ({c['detail']}) → `{c['into']}`  _{c['note']}_")
    else:
        L.append('- none (single flat file or plain directory)')
    L += ['', '## File kinds', '']
    for k, v in sorted(by_kind.items(), key=lambda x: -x[1]):
        L.append(f"- {k}: {v}")
    pes = [f for f in man['files'] if f['kind'] == 'pe']
    L += ['', f'## PE binaries ({len(pes)}) — the analysis surface', '']
    for f in sorted(pes, key=lambda x: -x['size'])[:60]:
        L.append(f"- `{f['path']}` ({f['size']//1024} KB) {f['sha256'][:12]}")
    if man['errors']:
        L += ['', '## Errors', ''] + [f'- {e}' for e in man['errors']]
    L += ['', '## Next', '', '```',
          'scripts/pe_triage.py --loot <out>        # parse every PE: mitigations, signing, imports',
          'scripts/surface_model.py --loot <out>    # reconstruct services/COM/pipes/URI/listeners',
          '```']
    open(os.path.join(out, 'unwrap.md'), 'w').write('\n'.join(L))
    print('\n'.join(L[:40]))
    print(f"\n[unwrap] manifest -> {os.path.join(out,'unwrap.json')}")


if __name__ == '__main__':
    main()
