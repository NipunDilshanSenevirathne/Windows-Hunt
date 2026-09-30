#!/usr/bin/env python3
"""
fuzz_harness.py — find the parsers, then generate the harness that fuzzes them.

Memory corruption is the class this skill otherwise leaves on the table, and the reason people
skip it is setup cost. This removes the setup cost: it inventories what the product PARSES
(file associations, magic strings, extension tables, import patterns), picks the parser
entry points, and writes ready-to-run harnesses plus a seed corpus plan.

Outputs, per selected target:
  winafl.cmd        WinAFL + DynamoRIO command line with the target module/offset filled in
  harness.c         a standalone harness that calls one exported parse function on a file
                    (build with MSVC or mingw; works with WinAFL, libFuzzer, or plain looping)
  fuzz_dumb.ps1     radamsa/bitflip mutation loop with crash triage via Windows Error Reporting
  corpus/README     which seed files to collect and where to get them
  triage.ps1        turn a crash into a report: !exploitable-style classification via cdb

Usage:
  fuzz_harness.py --loot loot/<name> [--binary <substr>] [--export <FuncName>] [--out <dir>]
Writes: <loot>/fuzz/…  and <loot>/fuzz.md
"""
import argparse, json, os, re

MAGICS = {
    b'%PDF': 'PDF', b'\x89PNG': 'PNG', b'GIF8': 'GIF', b'\xff\xd8\xff': 'JPEG',
    b'BM': 'BMP', b'II*\x00': 'TIFF', b'RIFF': 'RIFF/WAV/AVI/WEBP', b'OggS': 'Ogg',
    b'PK\x03\x04': 'ZIP/OOXML', b'Rar!': 'RAR', b'7z\xbc\xaf': '7z', b'\x1f\x8b': 'GZIP',
    b'{\\rtf': 'RTF', b'\xd0\xcf\x11\xe0': 'OLE/CFB', b'<?xml': 'XML', b'<svg': 'SVG',
    b'\x00\x01\x00\x00': 'TTF/ICO', b'OTTO': 'OTF', b'ID3': 'MP3', b'\x1aE\xdf\xa3': 'MKV',
    b'ftyp': 'MP4', b'SQLite format 3': 'SQLite', b'MSCF': 'CAB', b'MZ': 'PE',
}
PARSER_IMPORTS = ['createfile', 'readfile', 'mapviewoffile', 'createfilemapping',
                  'stgopenstorage', 'oleloadfromstream', 'gdiplus', 'windowscodecs',
                  'msxml', 'xmllite', 'expat', 'libxml', 'zlib', 'inflate', 'png_', 'jpeg_']
PARSE_EXPORT = re.compile(r'(?i)(parse|load|open|read|decode|import|deserial|unpack|extract|'
                          r'render|convert|process)[A-Za-z0-9_]*')

WINAFL = r'''@echo off
REM WinAFL harness for {binary}
REM   target module : {module}
REM   target offset : {offset}    <-- RVA of the parse function (see harness notes)
REM   nargs         : {nargs}
REM
REM Prereqs in the VM: DynamoRIO (drrun.exe) + WinAFL (winafl.dll, afl-fuzz.exe) matching the
REM target bitness ({arch}).  Persistent mode needs the function to be re-enterable; if it is
REM not, drop -fuzz_iterations to 1 and accept the slower rate.

set DR=C:\DynamoRIO\bin{bits}\drrun.exe
set WINAFL=C:\winafl\bin{bits}
set TARGET={target_path}

REM 1) sanity-check instrumentation BEFORE fuzzing (this step catches 90% of setup mistakes)
"%DR%" -c "%WINAFL%\winafl.dll" -debug ^
  -target_module {module} -target_offset {offset} -fuzz_iterations 10 -nargs {nargs} ^
  -covtype edge -coverage_module {module} ^
  -- "%TARGET%" .\corpus\seed1{ext}

REM  -> read the generated log: it must show the target function being reached and returning.

REM 2) fuzz
"%WINAFL%\afl-fuzz.exe" -i .\corpus -o .\findings -D C:\DynamoRIO\bin{bits} -t 5000 ^
  -- -coverage_module {module} -target_module {module} -target_offset {offset} ^
     -fuzz_iterations 5000 -nargs {nargs} -- "%TARGET%" @@
'''

HARNESS_C = r'''/* harness.c — call one parse entry point on one file, once.
 *
 * Use it three ways:
 *   1. plain:      harness.exe input.bin            (loop it with fuzz_dumb.ps1)
 *   2. WinAFL:     target_offset = RVA of fuzz_one
 *   3. libFuzzer:  build with -fsanitize=fuzzer and rename fuzz_one to LLVMFuzzerTestOneInput
 *
 * Build (MSVC):  cl /Zi /Od harness.c
 * Build (mingw): x86_64-w64-mingw32-gcc -g -O0 -o harness.exe harness.c
 *
 * Target: {binary}   export: {export}
 * ADJUST THE PROTOTYPE BELOW to the real signature before fuzzing — a wrong signature
 * produces crashes in your harness, not in the target, and wastes a day.
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

typedef int (__stdcall *PARSE_FN)(const void *data, size_t len);   /* <-- ADJUST */

static HMODULE g_mod;
static PARSE_FN g_fn;

__declspec(noinline) int fuzz_one(const unsigned char *data, size_t len) {{
    if (!g_fn) return 0;
    return g_fn(data, len);
}}

int main(int argc, char **argv) {{
    if (argc < 2) {{ printf("usage: harness.exe <input>\n"); return 1; }}
    g_mod = LoadLibraryA("{binary}");
    if (!g_mod) {{ printf("LoadLibrary failed: %lu\n", GetLastError()); return 1; }}
    g_fn = (PARSE_FN)GetProcAddress(g_mod, "{export}");
    if (!g_fn) {{ printf("GetProcAddress(%s) failed\n", "{export}"); return 1; }}

    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *buf = (unsigned char *)malloc(n ? n : 1);
    if (fread(buf, 1, n, f) != (size_t)n) {{ fclose(f); return 1; }}
    fclose(f);

    int r = fuzz_one(buf, (size_t)n);
    free(buf);
    return r;
}}
'''

DUMB_PS = r'''# fuzz_dumb.ps1 — mutation fuzzing without instrumentation.
# Slower than WinAFL but it runs in five minutes and finds the shallow bugs first.
param(
  [string]$Target  = "{target_path}",
  [string]$Corpus  = ".\corpus",
  [string]$OutDir  = ".\crashes",
  [int]   $Iterations = 20000,
  [string]$ArgTemplate = '"{{0}}"'
)
$ErrorActionPreference = 'SilentlyContinue'
New-Item -ItemType Directory -Force $OutDir | Out-Null

# Make Windows keep full dumps for the target so a crash is not just a gone process.
$k = "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\$(Split-Path $Target -Leaf)"
New-Item -Force -Path $k | Out-Null
Set-ItemProperty $k DumpFolder (Resolve-Path $OutDir) ; Set-ItemProperty $k DumpType 2

$seeds = Get-ChildItem $Corpus -File
if (-not $seeds) {{ Write-Host "no seeds in $Corpus — see corpus\README.md"; exit 1 }}
$rand = [Random]::new()

for ($i = 0; $i -lt $Iterations; $i++) {{
  $seed = $seeds[$rand.Next($seeds.Count)]
  $b = [IO.File]::ReadAllBytes($seed.FullName)
  # bit flips + byte splices + length changes, weighted toward small edits
  $muts = 1 + $rand.Next(8)
  for ($m = 0; $m -lt $muts; $m++) {{
    $op = $rand.Next(4)
    $p  = $rand.Next($b.Length)
    switch ($op) {{
      0 {{ $b[$p] = $b[$p] -bxor (1 -shl $rand.Next(8)) }}
      1 {{ $b[$p] = [byte]$rand.Next(256) }}
      2 {{ $b[$p] = @(0,1,0x7f,0x80,0xff)[$rand.Next(5)] }}
      3 {{ if ($b.Length -gt 8) {{ $b[$p] = $b[$rand.Next($b.Length)] }} }}
    }}
  }}
  $tmp = Join-Path $env:TEMP ("wh_fz_" + $i + $seed.Extension)
  [IO.File]::WriteAllBytes($tmp, $b)
  $pr = Start-Process -FilePath $Target -ArgumentList ($ArgTemplate -f $tmp) -PassThru -WindowStyle Hidden
  if (-not $pr.WaitForExit(5000)) {{ $pr.Kill(); Remove-Item $tmp -Force; continue }}
  $code = $pr.ExitCode
  # 0xC0000005 access violation, 0xC0000374 heap corruption, 0xC00000FD stack overflow
  if ($code -ne 0 -and ($code -band 0xC0000000) -eq 0xC0000000) {{
    $name = "crash_{{0:x8}}_{{1}}{{2}}" -f $code, $i, $seed.Extension
    Copy-Item $tmp (Join-Path $OutDir $name)
    Write-Host ("[CRASH] 0x{{0:x8}}  -> {{1}}" -f $code, $name) -ForegroundColor Red
  }}
  Remove-Item $tmp -Force
  if ($i % 500 -eq 0) {{ Write-Host "  $i / $Iterations" }}
}}
Write-Host "done. crashes in $OutDir (with full dumps, via WER LocalDumps)"
'''

TRIAGE_PS = r'''# triage.ps1 — turn a crash file into something reportable.
# Needs the Windows SDK Debugging Tools (cdb.exe).
param([string]$Target = "{target_path}", [string]$CrashDir = ".\crashes")
$cdb = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"
Get-ChildItem $CrashDir -File | Where-Object {{ $_.Extension -ne '.dmp' }} | ForEach-Object {{
  $f = $_.FullName
  Write-Host "=== $($_.Name) ===" -ForegroundColor Cyan
  $pattern = 'ExceptionCode|ExceptionAddress|FAULTING_IP|STACK_TEXT|PRIMARY_PROBLEM_CLASS|BUGCHECK_STR|Attempt to (read|write)'
  & $cdb -g -G -c "g; .lastevent; r; k 12; !analyze -v; q" $Target $f 2>&1 |
    Select-String -Pattern $pattern -Context 0,2
}}
# What decides severity here:
#   * write AV / heap corruption / stack overflow with controlled length -> exploitable-ish
#   * read AV near NULL                                                  -> usually just a DoS
#   * the same crash from many seeds                                     -> one bug, not many
# And the Windows question on top: WHICH PROCESS parses this input, and at what privilege?
# A crash in a user-level viewer is Low. The same crash in a SYSTEM service parsing a file a
# standard user can drop is the whole finding.
'''


def strings_of(p, cap=24 << 20):
    try:
        d = open(p, 'rb').read(cap)
    except Exception:
        return '', b''
    s = b'\n'.join(re.findall(rb'[\x20-\x7e]{4,}', d)).decode('latin1')
    try:
        s += '\n' + '\n'.join(re.findall(r'[\x20-\x7e]{4,}', d.decode('utf-16-le', 'ignore')))
    except Exception:
        pass
    return s, d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--loot', required=True)
    ap.add_argument('--binary', default=None)
    ap.add_argument('--export', default=None)
    ap.add_argument('--out', default=None)
    a = ap.parse_args()
    loot = a.loot
    man = json.load(open(os.path.join(loot, 'unwrap.json')))
    tri = {b['path']: b for b in json.load(open(os.path.join(loot, 'pe_triage.json')))['binaries']
           if b.get('ok')}
    surf = {}
    sp = os.path.join(loot, 'surface.json')
    if os.path.isfile(sp):
        surf = json.load(open(sp))
    integ = {}
    ip = os.path.join(loot, 'integration.json')
    if os.path.isfile(ip):
        integ = json.load(open(ip))

    # ---- what does this product PARSE? -------------------------------------------
    formats = set()
    for r in (surf.get('file_assoc') or []):
        v = r['v']
        e = (v.get('ext_or_verb') if isinstance(v, dict) else str(v)) or ''
        if e.startswith('.') or (e and '.' not in e and len(e) <= 6):
            formats.add(e if e.startswith('.') else '.' + e)
    for r in (integ.get('file_assoc') or []):
        formats.add(r.get('progid', ''))
    for ax in (integ.get('appx') or []):
        for ft in ax.get('file_types', []):
            formats.add(ft)

    # ---- candidate parser binaries -----------------------------------------------
    cands = []
    for path, b in tri.items():
        f = next((x for x in man['files'] if x['path'] == path), None)
        if not f:
            continue
        if b.get('is_dotnet'):
            continue          # managed: fuzz through the .NET surface instead
        imps = {x.lower() for v in (b.get('imports') or {}).values() for x in v}
        score = sum(1 for p in PARSER_IMPORTS if any(p in i for i in imps))
        exports = [e for e in (b.get('exports') or []) if PARSE_EXPORT.match(e)]
        s, raw = strings_of(f['abs'], 6 << 20)
        mag = sorted({v for k, v in MAGICS.items() if k in raw[:1 << 20]})
        extmentions = sorted(set(re.findall(r'(?i)\*?(\.[a-z0-9]{2,5})\b', s)))[:40]
        score += 2 * len(exports) + len(mag)
        m = b.get('manifest') or {}
        priv = (m.get('requestedExecutionLevel', 'asInvoker') != 'asInvoker') or \
               ('service' in (b.get('capabilities') or {}))
        if priv:
            score += 6
        if score >= 3:
            cands.append({'path': path, 'abs': f['abs'], 'arch': b.get('arch'),
                          'is_dll': b.get('is_dll'), 'score': score,
                          'parse_exports': exports[:25], 'magics': mag,
                          'extensions': [e for e in extmentions if e not in
                                         ('.dll', '.exe', '.sys', '.pdb', '.txt')][:20],
                          'privileged': priv})
    cands.sort(key=lambda x: -x['score'])
    if a.binary:
        cands = [c for c in cands if a.binary.lower() in c['path'].lower()]

    out = a.out or os.path.join(loot, 'fuzz')
    os.makedirs(out, exist_ok=True)
    generated = []
    for c in cands[:3]:
        name = os.path.basename(c['path'])
        d = os.path.join(out, name)
        os.makedirs(os.path.join(d, 'corpus'), exist_ok=True)
        bits = '64' if c['arch'] == 'x64' else '32'
        ext = (c['extensions'] or ['.bin'])[0]
        exp = a.export or (c['parse_exports'][0] if c['parse_exports'] else 'ParseFile')
        vals = {'binary': name, 'module': name, 'offset': '0x1000', 'nargs': '2',
                'arch': c['arch'], 'bits': bits, 'target_path': f'C:\\Path\\To\\{name}',
                'ext': ext, 'export': exp}
        open(os.path.join(d, 'winafl.cmd'), 'w').write(WINAFL.format(**vals))
        open(os.path.join(d, 'harness.c'), 'w').write(HARNESS_C.format(**vals))
        open(os.path.join(d, 'fuzz_dumb.ps1'), 'w').write(DUMB_PS.format(**vals))
        open(os.path.join(d, 'triage.ps1'), 'w').write(TRIAGE_PS.format(**vals))
        open(os.path.join(d, 'corpus', 'README.md'), 'w').write(
            f"""# Seed corpus for {name}

Formats this binary looks like it parses: **{', '.join(c['magics']) or 'unknown'}**
Extensions referenced in its strings: {', '.join(c['extensions']) or 'none recovered'}

Get seeds from, in order of value:
1. **The product's own sample/test files** — already in the loot, and already in the exact
   dialect the parser expects.
2. Public corpora for the format: the format's reference test suite, `afl`'s testcases
   directory, Google's fuzzing-corpora for common media/document types.
3. Files you generate with the product itself (round-trip its own export).

Then MINIMISE before fuzzing (`afl-cmin`/`winafl-cmin`) — an unminimised corpus wastes most
of the run. 50 distinct-coverage seeds beat 5000 near-duplicates.
""")
        generated.append({'binary': c['path'], 'dir': os.path.relpath(d, loot),
                          'export_guess': exp, 'score': c['score'],
                          'privileged': c['privileged'], 'magics': c['magics']})

    json.dump({'formats_accepted': sorted(x for x in formats if x),
               'candidates': cands[:20], 'generated': generated},
              open(os.path.join(loot, 'fuzz.json'), 'w'), indent=1)

    L = ['# Fuzzing — parsers and harnesses', '',
         f"- input formats the product registers: **{', '.join(sorted(x for x in formats if x)) or 'none found'}**",
         f'- parser-shaped binaries: **{len(cands)}**  ·  harnesses generated: **{len(generated)}**', '',
         '> The Windows question sits on top of the memory-safety one: a crash only matters as much',
         '> as the privilege of the process that parses the input. Fuzz the SYSTEM service that',
         '> reads a file a standard user can drop, before the GUI viewer.', '']
    if cands:
        L += ['## Parser candidates', '', '| score | binary | privileged | formats | parse-like exports |',
              '|---|---|---|---|---|']
        for c in cands[:20]:
            L.append(f"| {c['score']} | `{c['path']}` | {'YES' if c['privileged'] else ''} | "
                     f"{', '.join(c['magics'][:4])} | {', '.join(c['parse_exports'][:4])} |")
        L.append('')
    for g in generated:
        L += [f"## Harness: `{g['binary']}`", '',
              f"- directory: `{g['dir']}`",
              f"- guessed export: `{g['export_guess']}` — **verify the real signature before building**",
              f"- formats: {', '.join(g['magics']) or 'unknown'}",
              '- files: `winafl.cmd` (instrumented), `harness.c` (standalone/libFuzzer), '
              '`fuzz_dumb.ps1` (no setup), `triage.ps1` (crash → classification), `corpus/`', '']
    L += ['## Order of work', '',
          '1. **Collect seeds** (`corpus/README.md`) and minimise them. This is where the run is won.',
          '2. Start with `fuzz_dumb.ps1` — no DynamoRIO, no instrumentation, results in minutes. '
          'It finds the shallow bugs and proves the target actually parses your seeds.',
          '3. Move to WinAFL for coverage. Run the `-debug` sanity check first: if the log does not '
          'show your target function being entered and returning, nothing you do after that matters.',
          '4. Triage with `triage.ps1`. Group by faulting instruction, not by input.',
          '5. For each unique crash, answer the two questions: **is it a write or a read**, and '
          '**which process, at which privilege, parses this input in the real product?**',
          '',
          '> `scope/authorized_actions.txt` must grant `fuzz-local`, and this runs in your own VM.',
          '> Fuzzing a kernel driver additionally needs `debug-attach` and a kernel debugger '
          '> attached before you start.']
    open(os.path.join(loot, 'fuzz.md'), 'w').write('\n'.join(L))
    print(f'[fuzz_harness] {len(cands)} parser candidates, {len(generated)} harnesses')
    print(f'[fuzz_harness] -> {loot}/fuzz/ + fuzz.md')


if __name__ == '__main__':
    main()
