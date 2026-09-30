# com_elevation.ps1 — activate a COM class and enumerate what it will do for you.
# Target CLSID: {00000000-0000-0000-0000-000000000000}
#
# Run this as a STANDARD USER. The two questions are: does activation succeed, and does any
# method act on a path / command / URL you supply.

$clsid = "{00000000-0000-0000-0000-000000000000}"
Write-Host "running as: $(whoami)"

# --- 1. plain activation (the class's own ACL decides) ---------------------------------
try {
  $t = [Type]::GetTypeFromCLSID([Guid]$clsid)
  $o = [Activator]::CreateInstance($t)
  Write-Host "[+] plain activation SUCCEEDED as a standard user" -ForegroundColor Green
  $o | Get-Member -MemberType Method | Format-Table Name, Definition -AutoSize
} catch { Write-Host "[-] plain activation failed: $($_.Exception.Message)" }

# --- 2. elevation moniker (only meaningful if Elevation\Enabled=1) ----------------------
# NOTE: same-user UAC bypass is NOT a security boundary (MSRC). This matters when the caller
# is a DIFFERENT user or a constrained service account.
$code = @'
using System;
using System.Runtime.InteropServices;
public static class Elev {
  [DllImport("ole32.dll")] static extern int CoGetObject(string name, IntPtr bind, ref Guid iid, out IntPtr ppv);
  public static IntPtr Get(string moniker, Guid iid) {
    IntPtr p; int hr = CoGetObject(moniker, IntPtr.Zero, ref iid, out p);
    if (hr != 0) Marshal.ThrowExceptionForHR(hr);
    return p;
  }
}
'@
Add-Type -TypeDefinition $code -ErrorAction SilentlyContinue
$iid = [Guid]"00000000-0000-0000-C000-000000000046"   # IUnknown
try {
  $p = [Elev]::Get("Elevation:Administrator!new:$clsid", $iid)
  Write-Host "[+] elevation moniker activation SUCCEEDED (ptr $p)" -ForegroundColor Yellow
} catch { Write-Host "[-] elevation moniker: $($_.Exception.Message)" }

# --- 3. server path and identity --------------------------------------------------------
Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32",
                 "HKLM:\SOFTWARE\Classes\CLSID\$clsid\LocalServer32" -EA 0 |
  Select-Object PSPath, '(default)', ThreadingModel
$appid = (Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\$clsid" -EA 0).AppID
if ($appid) { Get-ItemProperty "HKLM:\SOFTWARE\Classes\AppID\$appid" -EA 0 | Format-List }
