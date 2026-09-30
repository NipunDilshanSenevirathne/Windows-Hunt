# rpc_client.ps1 — bind to the interface and enumerate its procedures, as a standard user.
# Interface: {00000000-0000-0000-0000-000000000000}
#
# Needs NtObjectManager:  Install-Module NtObjectManager -Scope CurrentUser
# (James Forshaw's toolkit — it parses the same RPC_SERVER_INTERFACE structures rpc_audit.py
#  recovered statically, and it can generate a working client from them.)

Import-Module NtObjectManager
Write-Host "running as: $(whoami)"

$binary = "C:\Program Files\Target\target.exe"
$servers = Get-RpcServer $binary
$servers | Format-Table InterfaceId, InterfaceVersion, ProcedureCount, Name -AutoSize

$iface = $servers | Where-Object { $_.InterfaceId -eq "{00000000-0000-0000-0000-000000000000}" }
if (-not $iface) { $iface = $servers | Select-Object -First 1 }
if (-not $iface) { Write-Host "no server interface found in $binary"; exit }

# Where is it reachable from?
Get-RpcEndpoint -InterfaceId $iface.InterfaceId -EA 0 | Format-Table Endpoint, Protocol -AutoSize
Get-RpcEndpoint -SearchType ALPC -EA 0 | Where-Object InterfaceId -eq $iface.InterfaceId |
  Format-Table Endpoint -AutoSize

# Every procedure, with its arguments — read these for a path / command / config parameter.
$iface.Procedures | ForEach-Object {
  "{0,3}  {1}({2})" -f $_.ProcNum, $_.Name,
    (($_.Params | ForEach-Object { "$($_.Type) $($_.Name)" }) -join ', ')
}

# Bind as a standard user. If this succeeds, every procedure above is reachable.
$client = Get-RpcClient $iface
try {
  Connect-RpcClient $client -EA Stop
  Write-Host "[+] BOUND as $(whoami) — the interface is callable by a standard user" -ForegroundColor Green
  $client | Get-Member -MemberType Method | Format-Table Name -AutoSize
} catch { Write-Host "[-] bind failed: $($_.Exception.Message)" }
