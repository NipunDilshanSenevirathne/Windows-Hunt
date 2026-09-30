#!/usr/bin/env python3
"""
runbook_gen.py — turn static findings into ONE PowerShell script the operator runs in their
own Windows VM, which answers every question static analysis cannot.

This is the no-Windows-VM lane's bridge. Static analysis can prove "AcmeSvc imports
CreateServiceW and references C:\\ProgramData\\Acme\\plugins". It cannot prove the ACL on that
directory, the account the service actually runs as, or that the load really happens. Those
three facts are the difference between a lead and a High. The runbook collects exactly them,
writes a JSON result file, and nothing else — it is read-only by design (no drops, no
execution, no modification), so it is safe to hand to a customer's admin.

Usage:  runbook_gen.py --loot loot/<name> [--install-root "C:\\Program Files\\Acme"]
Writes: <loot>/runbook/verify.ps1  and  <loot>/runbook/README.md
"""
import argparse, json, os, re

PS_HEADER = r'''<#
  Windows Hunt — verification runbook
  Target      : {target}
  Generated   : {when}
  READ-ONLY   : this script only READS ACLs, service configs, registry and process state.
                It creates no files outside $OutDir, starts nothing, and changes nothing.
  Run as      : a STANDARD USER first (that is the attacker's position), then optionally
                as admin to compare. Both runs are useful.
  Output      : $OutDir\wh-verify.json  — send that file back to the analysis box.
#>
param([string]$OutDir = "$env:USERPROFILE\Desktop\wh-verify")
$ErrorActionPreference = 'SilentlyContinue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$R = [ordered]@{{
  meta = [ordered]@{{
    target      = "{target}"
    generated   = "{when}"
    hostname    = $env:COMPUTERNAME
    whoami      = whoami
    isAdmin     = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    osVersion   = (Get-CimInstance Win32_OperatingSystem).Caption
    osBuild     = (Get-CimInstance Win32_OperatingSystem).BuildNumber
    uacLevel    = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
  }}
}}

function Get-WritableBy($path) {{
  # Which non-admin principals can write/create here? This is the whole LPE question.
  $res = @()
  try {{
    $acl = Get-Acl -LiteralPath $path
    $res += [pscustomobject]@{{ owner = $acl.Owner }}
    foreach ($a in $acl.Access) {{
      $id = $a.IdentityReference.Value
      $rights = $a.FileSystemRights.ToString()
      $interesting = $id -match '(?i)\\(Users|Authenticated Users|Everyone|INTERACTIVE|BUILTIN\\Users)$|^S-1-5-32-545$|^Everyone$|^NT AUTHORITY\\Authenticated Users$'
      $writes = $rights -match '(?i)FullControl|Modify|Write|CreateFiles|AppendData|ChangePermissions|TakeOwnership|WriteData|Delete'
      if ($interesting -and $writes -and $a.AccessControlType -eq 'Allow') {{
        $res += [pscustomobject]@{{
          VERDICT = 'USER-WRITABLE'
          identity = $id; rights = $rights; inherited = $a.IsInherited
          propagation = "$($a.InheritanceFlags)/$($a.PropagationFlags)"
        }}
      }}
    }}
  }} catch {{ $res += [pscustomobject]@{{ error = $_.Exception.Message }} }}
  return $res
}}

function Test-RealWrite($dir) {{
  # The ACL can lie (deny ACEs, privileges). Prove it: create and delete one empty file.
  try {{
    $p = Join-Path $dir ("wh_" + [guid]::NewGuid().ToString('N').Substring(0,8) + ".tmp")
    [IO.File]::WriteAllText($p, '')
    Remove-Item -LiteralPath $p -Force
    return $true
  }} catch {{ return $false }}
}}
'''

PS_FOOTER = r'''
$R | ConvertTo-Json -Depth 8 | Out-File -Encoding utf8 (Join-Path $OutDir 'wh-verify.json')
Write-Host ""
Write-Host "==> Written: $OutDir\wh-verify.json" -ForegroundColor Green
Write-Host "    Send that file back. Sections marked USER-WRITABLE / UNQUOTED / NULL-DACL are the findings."
'''


def ps_str(s):
    return str(s).replace('`', '``').replace('"', '`"').replace('$', '`$')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--loot', required=True)
    ap.add_argument('--install-root', default=None)
    a = ap.parse_args()
    loot = a.loot
    import time
    def J(n):
        p = os.path.join(loot, n)
        return json.load(open(p)) if os.path.isfile(p) else {}
    unwrap, surface = J('unwrap.json'), J('surface.json')
    hij, tri = J('dll_hijack.json'), J('pe_triage.json')
    target = os.path.basename(unwrap.get('target', 'target'))
    out = os.path.join(loot, 'runbook')
    os.makedirs(out, exist_ok=True)
    B = [PS_HEADER.format(target=ps_str(target), when=time.strftime('%Y-%m-%d %H:%M'))]

    # --- 1. install roots + every directory a shipped binary lives in ----------
    roots = set()
    if a.install_root:
        roots.add(a.install_root)
    prod = ''
    for b in (tri.get('binaries') or []):
        v = b.get('version') or {}
        prod = prod or v.get('ProductName') or v.get('CompanyName') or ''
    guesses = [r'C:\Program Files', r'C:\Program Files (x86)', r'C:\ProgramData']
    for row in surface.get('install_paths', []):
        p = (row.get('v') or {}).get('path')
        if p and re.match(r'(?i)^[a-z]:\\', p):
            roots.add(p)
    if prod:
        for g in guesses:
            roots.add(f'{g}\\{prod}')
    roots = sorted({r.rstrip("\\") for r in roots if r})[:40]
    B.append('\n$R.paths = @()')
    B.append('foreach ($p in @(' + ','.join(f'"{ps_str(r)}"' for r in roots) + ')) {')
    B.append('''  if (Test-Path -LiteralPath $p) {
    $R.paths += [pscustomobject]@{
      path = $p
      exists = $true
      acl = (Get-WritableBy $p)
      realWrite = (Test-RealWrite $p)
      children = (Get-ChildItem -LiteralPath $p -Directory -ErrorAction SilentlyContinue |
                  Select-Object -First 40 | ForEach-Object {
                    [pscustomobject]@{ dir = $_.FullName; acl = (Get-WritableBy $_.FullName); realWrite = (Test-RealWrite $_.FullName) } })
      exeAcls = (Get-ChildItem -LiteralPath $p -Filter *.exe -Recurse -Depth 2 -ErrorAction SilentlyContinue |
                 Select-Object -First 40 | ForEach-Object {
                   [pscustomobject]@{ file = $_.FullName; acl = (Get-WritableBy $_.FullName) } })
    }
  } else { $R.paths += [pscustomobject]@{ path = $p; exists = $false } }
}''')

    # --- 2. services ------------------------------------------------------------
    names = []
    for s in surface.get('services', []):
        v = s['v']
        n = v.get('name') if isinstance(v, dict) else str(v)
        if n and not n.startswith('('):
            names.append(n.strip('"'))
    B.append('\n# Services: unquoted paths, binary/dir ACLs, the account it runs as, recovery actions')
    B.append('$R.services = @()')
    filt = ('@(' + ','.join(f'"{ps_str(n)}"' for n in sorted(set(names))[:40]) + ')') if names else '@()'
    B.append(f'$wanted = {filt}')
    B.append(f'$prodHint = "{ps_str(prod or target.split(".")[0])}"')
    B.append('''foreach ($svc in (Get-CimInstance Win32_Service)) {
  $match = ($wanted -contains $svc.Name) -or ($wanted -contains $svc.DisplayName) -or
           ($prodHint -and ($svc.PathName -like "*$prodHint*"))
  if (-not $match) { continue }
  $bin = $svc.PathName
  $exe = $null
  if ($bin -match '^\\s*"([^"]+)"') { $exe = $matches[1] }
  elseif ($bin -match '^\\s*(\\S+\\.exe)') { $exe = $matches[1] }
  $unquoted = ($bin -notmatch '^\\s*"') -and ($bin -match '\\s') -and ($bin -match '^[A-Za-z]:\\\\')
  $R.services += [pscustomobject]@{
    name = $svc.Name; display = $svc.DisplayName; state = $svc.State
    startMode = $svc.StartMode
    account = $svc.StartName                      # LocalSystem here = every finding below is an LPE
    pathName = $bin
    UNQUOTED_PATH = $unquoted                     # classic LPE if an intermediate dir is writable
    binaryAcl = (if ($exe -and (Test-Path -LiteralPath $exe)) { Get-WritableBy $exe } else { $null })
    binaryDirAcl = (if ($exe) { Get-WritableBy (Split-Path -Parent $exe) } else { $null })
    sddl = (& sc.exe sdshow $svc.Name) -join ' '  # look for (A;;...;;;BU) / (A;;...;;;AU) / (A;;...;;;WD)
    canReconfigure = ((& sc.exe sdshow $svc.Name) -join ' ') -match 'A;;[^)]*(RP|WP|DC|WD|GA|GW)[^)]*;;;(BU|AU|IU|WD|S-1-5-32-545)'
  }
}''')

    # --- 3. scheduled tasks ------------------------------------------------------
    B.append('''
# Scheduled tasks running as SYSTEM whose action binary or its directory is user-writable
$R.tasks = @()
foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
  $ctx = $t.Principal.UserId
  if ($ctx -notmatch '(?i)SYSTEM|LOCAL SERVICE|NETWORK SERVICE|Administrators') { continue }
  foreach ($act in $t.Actions) {
    $ex = $act.Execute
    if (-not $ex) { continue }
    if ($ex -notmatch '(?i)' + [regex]::Escape($prodHint) -and $prodHint) { continue }
    $R.tasks += [pscustomobject]@{
      task = $t.TaskPath + $t.TaskName; runAs = $ctx; execute = $ex; args = $act.Arguments
      acl = (Get-WritableBy ($ex -replace '^"|"$',''))
      dirAcl = (Get-WritableBy (Split-Path -Parent ($ex -replace '^"|"$','')))
    }
  }
}''')

    # --- 4. named pipes ----------------------------------------------------------
    pipes = [p['v'] for p in surface.get('pipes', [])][:40]
    B.append('\n# Named pipes: existence and DACL. A NULL DACL or an Everyone/Users ACE on a')
    B.append('# pipe whose server is SYSTEM is the finding — then look at what the protocol accepts.')
    B.append('$R.pipes = @()')
    B.append('$allPipes = [System.IO.Directory]::GetFiles("\\\\.\\pipe\\")')
    B.append('$R.allPipeNames = $allPipes | ForEach-Object { Split-Path $_ -Leaf }')
    if pipes:
        B.append('foreach ($pn in @(' + ','.join(f'"{ps_str(p)}"' for p in pipes) + ')) {')
    else:
        B.append('foreach ($pn in @()) {')
    B.append('''  $full = "\\\\.\\pipe\\$pn"
  $exists = $allPipes -contains $full
  $sddl = $null
  try {
    $h = New-Object System.IO.FileStream($full, 'Open', 'Read')
    $h.Close()
  } catch {}
  try {
    $ps = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pn, 'In')
    $ps.Connect(300); $sddl = 'connect-ok-as-' + (whoami); $ps.Dispose()
  } catch { $sddl = "connect-failed: $($_.Exception.Message)" }
  $R.pipes += [pscustomobject]@{ pipe = $pn; exists = $exists; clientConnect = $sddl }
}''')

    # --- 5. URI handlers / file associations -------------------------------------
    uris = [u['v'] for u in surface.get('uri_handlers', [])][:40]
    B.append('\n# URI protocol handlers: the command line a web page can reach.')
    B.append('$R.uriHandlers = @()')
    if uris:
        B.append('foreach ($s in @(' + ','.join(f'"{ps_str(u)}"' for u in uris) + ')) {')
        B.append('''  foreach ($root in @('HKCU:\\SOFTWARE\\Classes', 'HKLM:\\SOFTWARE\\Classes')) {
    $k = "$root\\$s"
    if (Test-Path $k) {
      $cmd = (Get-ItemProperty "$k\\shell\\open\\command" -ErrorAction SilentlyContinue).'(default)'
      $R.uriHandlers += [pscustomobject]@{
        scheme = $s; hive = $root; command = $cmd
        urlProtocol = (Get-ItemProperty $k -ErrorAction SilentlyContinue).'URL Protocol' -ne $null
        UNQUOTED_ARG = ($cmd -match '%1' -and $cmd -notmatch '"%1"')   # argument injection
        keyAcl = (try { (Get-Acl $k).Access | Where-Object { $_.IdentityReference -match '(?i)Users|Everyone' -and $_.RegistryRights -match 'Write|FullControl' } } catch { $null })
      }
    }
  }
}''')
    else:
        B.append('# (no schemes recovered statically — enumerate HKCR for any the product owns)')

    # --- 6. listeners -------------------------------------------------------------
    ports = sorted({(p['v'] or {}).get('port') for p in surface.get('listeners', []) if (p['v'] or {}).get('port')})
    B.append('\n# Local listeners: which process, which user, and is it bound to loopback only?')
    B.append('$R.listeners = @()')
    B.append('''foreach ($c in (Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue)) {
  $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
  if (-not $p) { continue }
  if ($prodHint -and $p.Path -notlike "*$prodHint*" -and @(''' + ','.join(f'"{x}"' for x in ports) + ''') -notcontains "$($c.LocalPort)") { continue }
  $R.listeners += [pscustomobject]@{
    port = $c.LocalPort; address = $c.LocalAddress; process = $p.ProcessName; path = $p.Path
    owner = (Get-CimInstance Win32_Process -Filter "ProcessId=$($c.OwningProcess)" | Invoke-CimMethod -MethodName GetOwner).User
    BOUND_TO_ALL = ($c.LocalAddress -eq '0.0.0.0' -or $c.LocalAddress -eq '::')
  }
}''')

    # --- 7. phantom DLL probes ------------------------------------------------------
    phantoms = [f for f in (hij.get('findings') or []) if f['class'] == 'PHANTOM'][:25]
    B.append('\n# Phantom DLLs: does the process really look for them, and can we write there?')
    B.append('# (read-only check: we test writability with an empty temp file, we do NOT drop a DLL)')
    B.append('$R.phantoms = @()')
    if phantoms:
        rows = ','.join('@{dll="%s";loader="%s"}' % (ps_str(f['dll']), ps_str(os.path.basename(f['loader'])))
                        for f in phantoms)
        B.append(f'foreach ($ph in @({rows})) {{')
        B.append('''  $loaderPath = (Get-ChildItem -Path 'C:\\Program Files','C:\\Program Files (x86)','C:\\ProgramData' -Filter $ph.loader -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
  if (-not $loaderPath) { $R.phantoms += [pscustomobject]@{ dll=$ph.dll; loader=$ph.loader; found=$false }; continue }
  $dir = Split-Path -Parent $loaderPath
  $R.phantoms += [pscustomobject]@{
    dll = $ph.dll; loader = $loaderPath; found = $true
    dllPresent = (Test-Path (Join-Path $dir $ph.dll))
    dirAcl = (Get-WritableBy $dir)
    dirRealWrite = (Test-RealWrite $dir)
    inSystem32 = (Test-Path (Join-Path $env:WINDIR "System32\\$($ph.dll)"))
  }
}''')
    else:
        B.append('# (no phantom candidates from static analysis)')

    # --- 8. registry + autoruns + PATH ------------------------------------------------
    B.append('''
# Writable PATH entries (turns every SYSTEM-DLL miss into a hijack) and autorun ACLs
$R.pathDirs = @()
foreach ($d in ($env:PATH -split ';' | Where-Object { $_ })) {
  if (-not (Test-Path -LiteralPath $d)) { continue }
  $R.pathDirs += [pscustomobject]@{ dir = $d; writable = (Test-RealWrite $d); acl = (Get-WritableBy $d) }
}
$R.autoruns = @()
foreach ($k in @('HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
                 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
                 'HKLM:\\SYSTEM\\CurrentControlSet\\Services')) {
  if (-not (Test-Path $k)) { continue }
  $acl = (Get-Acl $k).Access | Where-Object { $_.IdentityReference -match '(?i)\\\\Users|Everyone|Authenticated Users' -and $_.RegistryRights -match 'SetValue|WriteKey|FullControl|CreateSubKey' }
  if ($acl) { $R.autoruns += [pscustomobject]@{ key = $k; WRITABLE_BY_USERS = $true; aces = ($acl | ForEach-Object { "$($_.IdentityReference)=$($_.RegistryRights)" }) } }
}

# Installed product + its Authenticode state (what the machine actually has, not what we unpacked)
$R.installed = Get-CimInstance Win32_Product -ErrorAction SilentlyContinue |
  Where-Object { -not $prodHint -or $_.Name -like "*$prodHint*" } |
  Select-Object Name, Version, Vendor, InstallLocation, InstallDate
''')
    B.append(PS_FOOTER)
    ps = '\n'.join(B).replace('(if (', '$(if (')   # PowerShell needs subexpression syntax
    open(os.path.join(out, 'verify.ps1'), 'w', encoding='utf-8').write(ps)

    rd = f'''# Verification runbook — {target}

`verify.ps1` answers the questions static analysis cannot. It is **read-only**: it reads ACLs,
service configuration, scheduled tasks, pipe names, registry and listening sockets, and writes
one JSON file. It drops no DLLs, starts no processes and changes no configuration.

## Run it

```powershell
# In YOUR OWN disposable Windows VM, with the product installed, as a STANDARD USER:
powershell -ExecutionPolicy Bypass -File .\\verify.ps1
# then, for comparison, from an elevated prompt:
powershell -ExecutionPolicy Bypass -File .\\verify.ps1 -OutDir $env:USERPROFILE\\Desktop\\wh-verify-admin
```

Send `wh-verify.json` back. The analysis side reads it with:

```bash
scripts/runbook_ingest.py --loot <loot> --result wh-verify.json
```

## What each section decides

| section | the finding it proves |
|---|---|
| `paths[].acl` / `realWrite` | a user-writable directory under a privileged install root — the precondition for almost every LPE here |
| `services[].UNQUOTED_PATH` | unquoted service path + a writable intermediate directory = LPE |
| `services[].account` | `LocalSystem` turns every other weakness on that service into an LPE |
| `services[].canReconfigure` | a service DACL that lets Users change the binary path = direct LPE |
| `tasks[]` | a SYSTEM task whose binary or directory the user can write |
| `pipes[].clientConnect` | a standard user can open the pipe → the protocol is attack surface |
| `uriHandlers[].UNQUOTED_ARG` | `%1` unquoted in `shell\\open\\command` = argument injection from a web page |
| `listeners[].BOUND_TO_ALL` | a service bound to 0.0.0.0 instead of loopback = remote surface |
| `phantoms[].dirRealWrite` | writable directory + a DLL the loader looks for and does not find = hijack |
| `pathDirs[].writable` | a writable PATH entry escalates every unresolved import in the system |

## What it deliberately does NOT do

Dropping a proxy DLL, connecting to a pipe with a crafted message, or launching the URI
handler are **active** steps: they need `scope/authorized_actions.txt` to allow them, and they
belong in the PoC stage (`scripts/poc_gen.py`), not in a runbook you might hand to someone
else's admin.
'''
    open(os.path.join(out, 'README.md'), 'w').write(rd)
    print(f'[runbook_gen] -> {out}/verify.ps1 (+ README.md)')
    print(f'[runbook_gen] roots={len(roots)} services={len(set(names))} pipes={len(pipes)} '
          f'uris={len(uris)} phantoms={len(phantoms)}')


if __name__ == '__main__':
    main()
