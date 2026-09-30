#!/usr/bin/env python3
"""
procmon_filter.py — turn the static findings into a Procmon session that answers them.

Procmon with no filter produces a million events and no answers. This generates:

  procmon_filters.md   the exact filter rows to enter, each with the finding it settles
  analyze_procmon.ps1  a post-processor for a Procmon CSV export that finds the LPE shapes
                       automatically: privileged access to user-writable paths, NAME NOT FOUND
                       DLL probes, hot registry writes, temp-file races, and check-then-use pairs

The analyzer is the more useful half: filters narrow what is captured, but the shapes only
become visible when you correlate *sequences* — a GetFileAttributes followed by a CreateFile on
the same path from the same thread is a TOCTOU, and no filter shows you that.

Usage:  procmon_filter.py --loot loot/<name>
Writes: <loot>/procmon/
"""
import argparse, json, os, re

COL = {'Process Name': 'Process Name', 'Path': 'Path', 'Operation': 'Operation',
       'Result': 'Result', 'Detail': 'Detail', 'Integrity': 'Integrity'}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--loot', required=True)
    a = ap.parse_args()
    loot = a.loot

    def J(n):
        p = os.path.join(loot, n)
        return json.load(open(p)) if os.path.isfile(p) else {}

    hij, surf = J('dll_hijack.json'), J('surface.json')
    toc, integ = J('toctou.json'), J('integration.json')
    tri = J('pe_triage.json')

    procs = sorted({os.path.basename(b['path']) for b in tri.get('binaries', [])
                    if b.get('ok') and not b.get('is_dll')})[:30]
    phantoms = sorted({f['dll'] for f in (hij.get('findings') or [])
                       if f['class'] == 'PHANTOM'})[:30]
    writable = sorted({(r['v'] or {}).get('path', '') for r in (surf.get('install_paths') or [])
                       if isinstance(r['v'], dict) and r['v'].get('class') in
                       ('ProgramData', 'Public', 'Temp')} - {''})[:20]
    pipes = sorted({str(r['v']) for r in (surf.get('pipes') or [])})[:20]

    out = os.path.join(loot, 'procmon')
    os.makedirs(out, exist_ok=True)

    L = ['# Procmon session plan', '',
         'Enter these under **Filter → Filter…**. Add the INCLUDEs first, then the EXCLUDEs.',
         'Capture with **Enable Boot Logging** if the finding involves a service start or a',
         'scheduled task — most of the interesting events happen before you can click Capture.', '',
         '## Include', '', '| column | relation | value | settles |', '|---|---|---|---|']
    for p in procs[:20]:
        L.append(f'| Process Name | is | `{p}` | scopes the capture to this product |')
    for w in writable:
        L.append(f'| Path | begins with | `{w}` | any privileged access to a user-writable location |')
    L.append('| Path | contains | `\\ProgramData\\` | the single most common LPE location |')
    L.append('| Path | contains | `\\Windows\\Temp\\` | SYSTEM\'s temp directory — users can create here |')
    for d in phantoms[:12]:
        L.append(f'| Path | ends with | `{d}` | confirms the phantom DLL probe (expect NAME NOT FOUND) |')
    for pp in pipes[:8]:
        L.append(f'| Path | contains | `{pp}` | pipe creation and connection |')
    L += ['', '## Exclude (cuts ~95% of the noise)', '',
          '| column | relation | value |', '|---|---|---|',
          '| Operation | is | `RegQueryValue` (only after you have the writes you need) |',
          '| Result | is | `SUCCESS` — *temporarily*, while hunting NAME NOT FOUND |',
          '| Process Name | is | `Procmon.exe`, `Procmon64.exe`, `System` |',
          '| Path | ends with | `.pf`, `.etl`, `.evtx`, `.db-wal` |', '',
          '## The three searches that find most of it', '',
          '1. **Phantom DLL**: `Result is NAME NOT FOUND` + `Path ends with .dll`',
          '2. **Privileged write to a shared path**: `Operation is CreateFile` + '
          '`Detail contains Write` + `Path contains \\ProgramData\\`, then add the **Integrity** '
          'column (Options → Select Columns) and look for `System`.',
          '3. **TOCTOU**: enable **Tools → Process Tree** and the *Thread ID* column, then look for '
          'the same path appearing in two operations from one thread with a gap between them.', '',
          '## Do not forget', '',
          '- Add the **Integrity** and **User** columns. Without them you cannot tell a SYSTEM '
          'access from a user one, which is the entire question.',
          '- Run the product both as a standard user and as admin, and diff the two captures.',
          '- `Tools → Count Occurrences → Path` is the fastest way to spot the one directory the '
          'privileged process keeps touching.']
    open(os.path.join(out, 'procmon_filters.md'), 'w').write('\n'.join(L))

    ps = r'''# analyze_procmon.ps1 — find the LPE shapes in a Procmon CSV export.
#
# In Procmon:  File -> Save... -> Comma-Separated Values (CSV), "All events".
# Make sure the Integrity and User columns are enabled (Options -> Select Columns) before saving.
#
#   .\analyze_procmon.ps1 -Csv .\Logfile.CSV
#
# It reports, in order of value:
#   1. privileged processes touching user-writable paths
#   2. DLL probes that returned NAME NOT FOUND   (confirmed hijack candidates)
#   3. writes to hot registry keys
#   4. temp-file usage by a privileged process
#   5. check-then-use pairs on the same path from the same thread   (TOCTOU)
param(
  [Parameter(Mandatory=$true)][string]$Csv,
  [string]$OutDir = ".\wh-procmon"
)
New-Item -ItemType Directory -Force $OutDir | Out-Null
$ev = Import-Csv $Csv
Write-Host "loaded $($ev.Count) events"

$WRITABLE = '(?i)\\ProgramData\\|\\Users\\Public\\|\\Windows\\Temp\\|\\AppData\\|\\Temp\\'
$HOTREG   = '(?i)CurrentVersion\\Run|CurrentControlSet\\Services|AppInit_DLLs|AppCertDlls|' +
            'Image File Execution Options|Winlogon|ShellEx|CLSID|Print\\Monitors|Environment'

function Priv($e) {
  # Integrity is the reliable signal; fall back to the User column.
  ($e.Integrity -match '(?i)system|high') -or ($e.User -match '(?i)SYSTEM|NETWORK SERVICE|LOCAL SERVICE')
}

# --- 1. privileged access to user-writable locations -----------------------------------
$hot = $ev | Where-Object { $_.Path -match $WRITABLE -and (Priv $_) -and
                            $_.Operation -match 'CreateFile|WriteFile|SetRenameInformationFile|SetDispositionInformationFile' }
Write-Host "`n=== [1] privileged access to user-writable paths: $($hot.Count) ===" -ForegroundColor Yellow
$hot | Group-Object Path | Sort-Object Count -Descending | Select-Object -First 30 |
  ForEach-Object { "{0,6}  {1}" -f $_.Count, $_.Name }
$hot | Export-Csv (Join-Path $OutDir '1_privileged_writable.csv') -NoTypeInformation

# --- 2. phantom DLL probes ---------------------------------------------------------------
$nf = $ev | Where-Object { $_.Result -eq 'NAME NOT FOUND' -and $_.Path -match '\.dll$' }
Write-Host "`n=== [2] DLL probes that found nothing: $($nf.Count) ===" -ForegroundColor Yellow
$nf | Group-Object { Split-Path $_.Path -Leaf } | Sort-Object Count -Descending |
  Select-Object -First 30 | ForEach-Object {
    $dir = ($nf | Where-Object { (Split-Path $_.Path -Leaf) -eq $_.Name } |
            Select-Object -First 1).Path
    "{0,5}  {1}" -f $_.Count, $_.Name }
$nf | Export-Csv (Join-Path $OutDir '2_phantom_dlls.csv') -NoTypeInformation
Write-Host "  -> for each: is the DIRECTORY writable? icacls it. That is the finding."

# --- 3. hot registry writes ---------------------------------------------------------------
$rw = $ev | Where-Object { $_.Operation -match 'RegSetValue|RegCreateKey|RegDeleteValue' -and
                           $_.Path -match $HOTREG }
Write-Host "`n=== [3] writes to keys that change what other processes load: $($rw.Count) ===" -ForegroundColor Yellow
$rw | Select-Object -First 25 | ForEach-Object { "  {0}  {1}  {2}" -f $_.'Process Name', $_.Operation, $_.Path }
$rw | Export-Csv (Join-Path $OutDir '3_hot_registry.csv') -NoTypeInformation

# --- 4. temp files from a privileged process ------------------------------------------------
$tmp = $ev | Where-Object { $_.Path -match '(?i)\\Windows\\Temp\\|\\Temp\\' -and (Priv $_) -and
                            $_.Operation -match 'CreateFile' }
Write-Host "`n=== [4] privileged temp-file usage: $($tmp.Count) ===" -ForegroundColor Yellow
$tmp | Group-Object Path | Sort-Object Count -Descending | Select-Object -First 20 |
  ForEach-Object { "{0,5}  {1}" -f $_.Count, $_.Name }
$tmp | Export-Csv (Join-Path $OutDir '4_privileged_temp.csv') -NoTypeInformation

# --- 5. check-then-use on one path from one thread -------------------------------------------
Write-Host "`n=== [5] check-then-use candidates (TOCTOU) ===" -ForegroundColor Yellow
$CHECK = 'QueryBasicInformationFile|QueryAttributeInformationFile|QueryStandardInformationFile|QuerySecurityFile'
$USE   = 'CreateFile|WriteFile|ReadFile|Process Create|Load Image'
$byThread = $ev | Where-Object { $_.Path -and $_.TID } | Group-Object TID
$pairs = @()
foreach ($t in $byThread) {
  $list = @($t.Group)
  for ($i = 0; $i -lt $list.Count - 1; $i++) {
    if ($list[$i].Operation -match $CHECK) {
      for ($j = $i + 1; $j -lt [Math]::Min($i + 25, $list.Count); $j++) {
        if ($list[$j].Path -eq $list[$i].Path -and $list[$j].Operation -match $USE) {
          $pairs += [pscustomobject]@{
            TID = $t.Name; Path = $list[$i].Path
            Check = $list[$i].Operation; Use = $list[$j].Operation
            Gap = $j - $i; Process = $list[$i].'Process Name'
            Writable = ($list[$i].Path -match $WRITABLE)
            Privileged = (Priv $list[$i])
          }
          break
        }
      }
    }
  }
}
$pairs | Where-Object { $_.Writable -and $_.Privileged } | Sort-Object Gap -Descending |
  Select-Object -First 25 | Format-Table -AutoSize
$pairs | Export-Csv (Join-Path $OutDir '5_toctou_pairs.csv') -NoTypeInformation
Write-Host "  -> a pair on a WRITABLE path from a PRIVILEGED process is the race to attack."
Write-Host "     Hold an oplock on the checked file (SetOpLock.exe) and swap it in the gap."

Write-Host "`nCSV reports written to $OutDir" -ForegroundColor Green
'''
    open(os.path.join(out, 'analyze_procmon.ps1'), 'w').write(ps)
    print(f'[procmon_filter] -> {out}/procmon_filters.md + analyze_procmon.ps1')
    print(f'[procmon_filter] {len(procs)} processes, {len(phantoms)} phantom DLLs, '
          f'{len(writable)} writable paths, {len(pipes)} pipes in the plan')


if __name__ == '__main__':
    main()
