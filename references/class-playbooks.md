# Class playbooks — how each Windows bug class is actually found

One page per class: where it lives, what the engine gives you, what you must confirm yourself,
and the exact shape of the finished finding.

---

## 1. LPE via a privileged reader and a writable location

**The pattern.** A process running as SYSTEM (service, scheduled task, updater, installer
custom action, COM server) reads code, configuration, a path or a DLL out of a location a
standard user can write.

**Where it lives.** `C:\ProgramData\<product>\` is the single most common location, because
developers reach for it as "the machine-wide place" without realising its default ACL grants
`CREATOR OWNER` full control and Users write+append at the root. Also: `%PUBLIC%`, `C:\Temp`,
a custom `C:\<Product>\` created with an inherited permissive ACE, and any directory the
installer creates with an explicit `LockPermissions` / `icacls /grant Everyone` entry.

**Engine gives you.** `surface.md` install-path rows (ProgramData/Public/Temp), MSI
`LockPermissions` / SDDL strings, `native.md` writable-path-plus-dangerous-API intersections,
`dotnet_il.md` ACL-widening and file-write sinks.

**You must confirm.** (a) the ACL — `runbook verify.ps1 → paths[]`, and the *real write* test,
because a deny ACE or a privilege can contradict the ACL; (b) the reading process's token;
(c) that the read actually happens — Procmon, `Operation is CreateFile`, `Integrity: System`.

**The finished finding.** "As a standard user I can write `C:\ProgramData\Acme\plugins\x.dll`.
`AcmeSvc` (LocalSystem) enumerates and loads every DLL in that directory at service start. I
placed a DLL that writes its token to disk; the file contains `NT AUTHORITY\SYSTEM`."

**Variants worth checking every time.** Writable log directory + the service opens the log with
`CREATE_ALWAYS` (symlink to an arbitrary path) · writable temp file the installer later executes
· a `.config`/`.json`/`.ini` the SYSTEM process parses where one key is a path or a command ·
an `sqlite` database a SYSTEM service reads · a writable `PATH` entry.

---

## 2. DLL search-order / phantom / side-loading

**The pattern.** A binary imports a DLL that is not in `System32`, not in the KnownDLLs section,
and not shipped beside it. The loader walks the search order and finds nothing — so whatever you
put in the application directory (or a writable `PATH` entry, or the current directory in the
legacy order) is loaded.

**Engine gives you.** `dll_hijack.md`, classified PHANTOM / SIDELOAD / RUNTIME / SYSTEM, with
KnownDLLs and API sets suppressed, ranked by loader privilege. Delay-loaded imports are flagged
— they resolve after the process is running, which often means *after* any early hardening call.

**You must confirm.** The load attempt (Procmon: `Result is NAME NOT FOUND`, `Path ends with
<dll>`), the directory ACL, and the loading process's token. Check whether
`SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` is called — and called **early**, in
`main` before anything else, not after the vulnerable load.

**The finished finding.** Include the Procmon line, the `icacls` output, and the proxy DLL's
output file. `scripts/poc_gen.py --kind proxy-dll` builds one that compiles with mingw on Linux.

**Do not report.** A hijack that only works for a user against their own processes. A KnownDLL.
A DLL that is genuinely present in System32 on a real host (the engine marks these
VERIFY-ON-WINDOWS — check before writing).

---

## 3. Named pipes, RPC, COM, ALPC

**The pattern.** A SYSTEM service exposes an IPC endpoint so its unprivileged UI can ask it to do
privileged things. The endpoint is reachable by any logged-on user, and the server trusts what it
is told: a path to install, a command to run, a configuration to apply, an update URL to fetch.

**Where it lives.** Pipe names in strings (`\\.\pipe\...`), `CreateNamedPipe` imports, RPC
interface UUIDs with `RpcServerUseProtseq`, COM CLSIDs registered by the installer, `DllRegisterServer`
exports, and — for the LPE-relevant half — whether the endpoint's DACL is explicit.

**Engine gives you.** `surface.md` pipes/RPC/COM sections, `pe_triage.json` capability map
(`ipc`, `service`, `token`, `security`).

**You must confirm.** (a) can a standard user connect? (`runbook → pipes[]`, or
`poc_gen.py --kind pipe-client`); (b) what does the protocol accept? Reverse the message
handler — for .NET use `dotnet_il.md` and find the deserializer or the dispatch switch; for
native, `native.md` gives you the function that reads the pipe; (c) does the server
**impersonate** the caller before acting? `ImpersonateNamedPipeClient` followed by the
privileged operation is correct; acting as SYSTEM on the caller's behalf is the bug.

**The highest-yield questions.** Does any command take a *file path*? A *command line*? A
*URL the service will download and execute*? Does it *copy* a file the caller names into a
privileged location? Does it *set an ACL*?

**Also check.** An impersonation that is dropped too early, or not restored after an exception
(`RevertToSelf` missing on the error path) — that turns a correct design into an LPE.

---

## 4. Custom URI protocol handlers

**The pattern.** The product registers `myapp://` in HKCR so the web can deep-link into it. The
shell resolves the handler and runs `"C:\...\app.exe" %1`. If `%1` is **unquoted**, the shell
splits the URL on spaces and everything after the first token becomes extra **command-line
arguments** to a locally installed program.

**Why it pays.** The starting position is *any web page the user visits*. Chromium- and
Node-based applications accept flags that are directly code execution:
`--gpu-launcher=<command>`, `--utility-cmd-prefix=<command>`, `--renderer-cmd-prefix`,
`--inspect-brk=0.0.0.0:9229`, `ELECTRON_RUN_AS_NODE`, `--require=\\attacker\share\p.js`,
`--no-sandbox`. Java accepts `-Xshare`, `-javaagent`. Many apps accept a `--config` or
`--plugin-dir` pointing at a UNC path.

**Engine gives you.** `surface.md` URI handlers, and — when a `.reg` file was shipped — the
registered command line and whether `%1` is quoted.

**You must confirm.** Read the real registry value on the host (`runbook → uriHandlers[]`). Then
`poc_gen.py --kind uri-arg` and capture the resulting **command line** in Process Explorer.

**Second half of the class.** Even with a quoted `%1`, the app's own URL parser is attack
surface: path traversal in the resource it opens, an attacker-chosen server it connects to, a
token it hands over, a window it navigates.

---

## 5. Localhost listeners (the most under-tested class in desktop software)

**The pattern.** The app runs an HTTP or WebSocket server on `127.0.0.1` for its browser
extension, its CLI, its IDE plugin or its own UI. It assumes loopback means trusted. **Any web
page the user visits can reach it.**

**What defeats what:**
* CORS stops a page *reading* a cross-origin response — it does not stop the request being
  *delivered*. Any state-changing GET/POST still happens.
* WebSockets are not subject to CORS at all. The server must check the `Origin` header itself.
* `Host: localhost` checks are defeated by **DNS rebinding**: a hostname that resolves to your
  IP first and `127.0.0.1` afterwards.
* A token in the URL that any local process can read is not authentication against local
  malware, but *is* protection against a web page — say which threat you are demonstrating.

**Engine gives you.** `surface.md` listeners (URLs and bind ports found in strings/config).

**You must confirm.** The port is really listening and bound to loopback (`runbook →
listeners[]`), then `poc_gen.py --kind localhost --port <p>` from a real web origin. Enumerate
endpoints: `/`, `/status`, `/version`, `/api`, `/rpc`, `/json`, `/config`, `/debug`, `/metrics`.

**Escalate.** Does any endpoint open a file, run a command, set an update URL, return a token,
or expose the user's data? A read-only `/version` is informative; `/open?path=` is High.

---

## 6. The update channel

**The pattern.** Every desktop product has one thing that downloads code and runs it. Three
controls have to hold and usually one does not: **transport** (TLS, validated), **manifest
integrity** (signed or at least authenticated), **package verification** (Authenticode checked
*before* execution, against a pinned publisher, with the version not allowed to go backwards).

**Engine gives you.** `surface.md` update endpoints and cleartext HTTP, `dotnet_il.md` TLS
override sinks (`ServerCertificateValidationCallback` — read the callback: does it
`return true`?), `sbom.md` for the updater framework (Squirrel, WinSparkle, NetSparkle, Omaha).

**You must confirm, in order.** (1) does it accept a self-signed cert? (2) does it accept a
modified manifest — a bumped version, a changed URL? (3) does it accept a package whose
Authenticode signature is absent, invalid, or valid-but-from-a-different-publisher? Only (3) is
reliably a Critical; (1) and (2) are the road to it.
`poc_gen.py --kind update-mitm` gives you the proxy. **Gated**: the upstream host must be in
`scope/authorized_hosts.txt` and `mitm-update` must be an allowed action.

**Also.** Downgrade: will it install an older, known-vulnerable version? Rollback protection is
frequently missing and is a legitimate finding on its own.

---

## 7. .NET desktop applications

**The pattern.** Managed code is trivially readable, so the bugs are logic bugs, and the biggest
one is deserialization.

**Read the IL, not the strings.** `dotnet_il.py` resolves every call to
`Namespace.Type::Method`. The families that matter, in order:
* `BinaryFormatter`, `NetDataContractSerializer`, `LosFormatter`, `SoapFormatter`,
  `ObjectStateFormatter` — unsafe by design. Attacker-controlled stream = RCE, gadgets from
  ysoserial.net.
* `TypeNameHandling` != `None` on Json.NET — the same thing in JSON.
* `Assembly.LoadFrom` / `LoadFile` / `UnsafeLoadFrom` with a path — if the path is user-writable
  that is code execution at this process's privilege.
* `ServerCertificateValidationCallback` set to something that returns `true`.
* `FileSystemSecurity::AddAccessRule` — read the ACE being added.
* `ZipFile.ExtractToDirectory` / hand-rolled extraction loops — Zip-Slip.
* `Process.Start` with a composed argument string.
* P/Invoke into the dangerous half of Win32 (the engine lists these separately).

**Upgrade path.** `ilspycmd` (installed by `provision.sh --tier dotnet` when a dotnet SDK is
present) gives full C# for the methods the IL pass flagged. You rarely need it — the IL plus the
method name is usually enough to write the finding.

---

## 8. Electron / CEF / WebView2

**The pattern.** A web app with a Win32 privilege level. The chain is always the same shape:
*get content into a renderer* → *reach the bridge* → *convert to native execution*.

**Get content in.** A `loadURL` target computed at runtime, a custom protocol handler with a
traversal, an `<iframe>` or ad in a page the app renders, an OAuth or help window, a markdown or
HTML field rendered without escaping, or a URI-handler argument that becomes the start URL.

**Reach the bridge.** `contextIsolation:false` means page JS and preload share a context.
`nodeIntegration:true` means `require()` directly. Otherwise read every
`contextBridge.exposeInMainWorld` function and every `ipcMain.handle` channel: any that takes a
path, a URL, a command or an object the main process acts on is the bridge.

**Convert to execution.** `child_process`, `shell.openExternal` (with a handler scheme —
`file:`, `ms-msdt:`, `search-ms:`, a UNC path, a dropped `.url`/`.lnk`), `shell.openPath`, a
written file plus a load, or `ELECTRON_RUN_AS_NODE=1` against the app's own signed binary.

**Also check.** Fuses: `runAsNode` and `enableNodeCliInspectArguments` left on mean any local
process can restart the signed binary as a Node interpreter. ASAR integrity off means the app's
own JS can be rewritten on disk — which, if the app is privileged or the directory is writable,
is the whole bug. And the Electron **major**: only the latest three get security fixes.

---

## 9. Kernel drivers (.sys)

**The pattern.** A product ships a driver for performance counters, anti-cheat, backup, USB or
disk access. The device object is openable by any user, the IOCTL handlers do not validate, and
the driver exposes physical-memory mapping or arbitrary process access — ring 0 from a standard
user, and a BYOVD primitive for everyone else forever after.

**Engine gives you.** `drivers.md`: device names, whether `IoCreateDeviceSecure`/SDDL is used at
all, decoded IOCTL codes (device type / function / method / access) and the ring-0 primitives
present (`MmMapIoSpace`, `ZwOpenProcess`, `MmCopyVirtualMemory`, MSR/port I/O, `ZwLoadDriver`).

**The combination to look for.** `METHOD_NEITHER` + `FILE_ANY_ACCESS` + no explicit device SDDL:
raw user pointers, any user can open it, no probing. Then check every handler for
`ProbeForRead`/`ProbeForWrite` and for a length the caller controls.

**Test only under a kernel debugger.** A bugcheck with no debugger attached is a lost bug.
Requires `debug-attach` and `fuzz-local` in `scope/authorized_actions.txt`.

---

## 10. Installers and MSI

**The pattern.** The installer is the most privileged code the product ever runs, and it runs on
every machine.

**MSI specifics.** A custom action whose type has **both** `msidbCustomActionTypeInScript`
(0x400, deferred) **and** `msidbCustomActionTypeNoImpersonate` (0x800) runs as
`NT AUTHORITY\SYSTEM`. `surface.md` flags these explicitly. If such an action executes a file, a
script or a command built from a property, and a standard user can influence that property or
write that path, it is an LPE — and `msiexec /fa` (repair) lets a standard user *trigger* it on
demand for a per-machine install.

**Also check.** `LockPermissions` / `MsiLockPermissionsEx` (explicit ACLs — decode every SDDL;
`A;;GA;;;WD` is GENERIC_ALL to Everyone), the `Directory` table (where things land), advertised
shortcuts, and whether the MSI is signed at all.

**NSIS / Inno.** The install script is recoverable (`innoextract`, `7z`). Read it for `icacls`
calls, `SetOutPath` into shared locations, `nsExec`/`Exec` of downloaded files, and services
created with `sc create` without quoting.

---

## 11. Secrets and crypto

A secret is a finding when it is **live** and **grants something**. Ship the decrypt path too: a
key is far stronger when you also show what it opens (the app's own stored credential blob, the
licence file, the local database).

Desktop-specific places to look that web scanners miss: PE resources, `.config` transforms,
`.nupkg`/`.nuspec` metadata, the MSI `Property` table, installer scripts, `%APPDATA%` templates
shipped in the package, and obfuscated blobs the app decrypts with a hardcoded key (find the key
via `dotnet_il.md` `SymmetricAlgorithm::set_Key` or `native.md` crypto capabilities).

DPAPI with `CurrentUser` scope protects against another *user*, not against code running as that
user — do not report it as a secure-storage failure unless the threat model says otherwise.

---

## 12. Supply chain

`sbom.md` lists shipped component versions. To make a bundled-CVE finding land, answer the
question the triager will ask: **is the vulnerable code path reachable in this product?** A
vulnerable image decoder in a binary that never decodes untrusted images is informational.
Show the input path — a file type the app opens, a network response it parses, a field the user
pastes — and it becomes the CVE's own severity.

Also check what the vendor *does not* ship: an unsigned third-party DLL shipped beside signed
first-party binaries is both a hijack candidate and a supply-chain question worth asking.

---

## 13. COM / DCOM registration

**The pattern.** COM is a registry-driven loader. A CLSID maps to a server binary, an identity
and an activation ACL — and all three are attacker-relevant.

**Engine gives you.** `com.md`: server paths (`InprocServer32` / `LocalServer32`), which of them
sit in writable locations, `Elevation\Enabled`, AppID `RunAs` and explicit Launch/Access
permissions, `DllSurrogate`, `TreatAs` redirects, and — the useful inversion — **which CLSIDs a
privileged binary activates that nothing in the package registers**.

**The four findings that live here.**
1. **Server path in a writable location.** `InprocServer32 = C:\ProgramData\<app>\bin\x.dll`.
   Whoever activates the class loads your DLL at their privilege. This is the strongest and the
   most common.
2. **`RunAs = LocalSystem` plus a permissive activation ACL.** A standard user calls
   `CoCreateInstance`, a SYSTEM process starts and does what they ask. Decode the
   `LaunchPermission` on the host: an ACE for `BU`/`AU`/`WD` is the finding.
3. **Elevation moniker objects.** `Elevation\Enabled=1` makes the class callable through
   `CoGetObject("Elevation:Administrator!new:{clsid}")`. Same-user UAC bypass alone is **not a
   boundary** — but read every method anyway: one that takes a path, a command or a URL and acts
   on it as SYSTEM is frequently reachable from a *service account* or another user too.
4. **Dangling CLSID.** The product activates a class that is not registered. On the host, check
   whether the key exists and who can write it. `HKCU\Software\Classes\CLSID` wins over HKLM for
   same-user activation — which makes it persistence and a same-user escalation path, not a
   cross-user boundary. Say which one you are claiming.

**Verify.** `com.md` ends with the exact PowerShell. The key question is always the pair
(*who can activate*, *what identity runs*).

---

## 14. Native messaging hosts — the browser's line to native code

**The pattern.** A product installs a browser extension plus a **native messaging host**: a JSON
manifest naming a native binary, and the list of extensions allowed to speak to it over stdio.
The manifest's `allowed_origins` / `allowed_extensions` **is the entire access control**.

**Why it is worth your time.** The starting position is a web page. If the extension can be
reached by a page (`externally_connectable`, a content script on a broad host pattern, or a
compromised/sideloaded extension), that page's messages land in a native process — often a
privileged one, often one that takes a path or a command.

**Engine gives you.** `integration.md` → native messaging hosts, with wildcard origins flagged,
plus any shipped extension's permissions and `externally_connectable`.

**Work it in this order.**
1. Read the manifest: wildcard origin, or an extension id that is not the vendor's own? Either
   is a finding on its own.
2. Read the native binary's **message loop**. Every message is attacker-influenced. Look for
   the usual: a path, a command line, an update URL, a file copy, a registry write.
3. Check the binary's privilege. A host that runs as the user is an ACE at best; one launched by
   a SYSTEM service, or that talks to one over a pipe, is an LPE chain.
4. Check for a length/format check on the 4-byte message header — classic parser bugs live here.

---

## 15. Hooks Windows loads into *other* processes

`AppInit_DLLs`, `AppCertDlls`, shell extensions, icon-overlay handlers, preview handlers,
Winlogon `Notify`/`Shell`/`Userinit`, credential providers, LSA packages, network providers,
print monitors and providers, WMI providers, IFEO `Debugger` and `SilentProcessExit`.

**The single question.** For each hook the product registers: **which process loads it, at what
privilege, and can a standard user change what gets loaded?** The "what gets loaded" has three
handles — the DLL file itself, the directory it sits in, and the registry value naming it.

**Severity anchors.** LSA package or credential provider → SYSTEM, pre-authentication:
Critical if hijackable. `AppInit_DLLs` → nearly every process: High. Shell extension →
explorer.exe at the user's own integrity: usually Medium, and only an LPE if another user or a
privileged process renders the same folder. Print monitor → spoolsv as SYSTEM: High.

**Do not report** the mere existence of a hook. Report the writable handle.

---

## 16. Fuzzing the parsers

**Where to point it.** `fuzz.md` inventories what the product parses and ranks the parser
binaries — and it weights **privilege** into the ranking, because that is what decides whether a
crash is a finding. Fuzz the SYSTEM service that reads a file a standard user can drop, or the
component behind a file association, before the GUI viewer.

**The order that actually works.**
1. Seeds first. A minimised 50-file corpus beats 5,000 near-duplicates. The product's own sample
   and test files are already in the loot and are already in the dialect the parser expects.
2. `fuzz_dumb.ps1` — no instrumentation, results in minutes, proves your seeds are actually
   parsed, and finds the shallow bugs.
3. WinAFL for coverage. **Run the `-debug` sanity check first**: if the log does not show your
   target function entered and returning, nothing after that matters.
4. `triage.ps1` groups crashes by faulting instruction, not by input.

**Then apply the Windows question on top:** write AV or heap corruption is exploitable-shaped;
a read AV near NULL is a DoS. And a DoS in a user-level viewer is Low, while the same crash in a
SYSTEM service parsing attacker-droppable input is the whole report.

Kernel drivers: attach a kernel debugger **before** you start. A bugcheck with no debugger
attached is a lost bug. Needs `debug-attach` and `fuzz-local` in `authorized_actions.txt`.

---

## 17. Checking for duplicates before you write

`dedup_oracle.py` scores your finding classes against the product's published CVE history and
prints what the vendor has historically got wrong. Use it twice:

- **Before writing**, so you do not submit a known issue. A HIGH duplicate-risk row is not a
  stop sign — read those CVEs. Either yours is the same bug in a new place (still reportable:
  cite the prior art and state the difference), or the vendor fixed one instance and missed
  yours, which is a *stronger* report: "the fix for CVE-X did not cover Y".
- **Before hunting**, as a map. A vendor with four DLL-hijack CVEs has a systemic loader
  problem and the fifth is probably still there. Release notes are the most underused source:
  "fixed an issue where the updater could load a library from the working directory" is a
  silently-fixed CVE-class bug that tells you both what to look for and which shipped version
  still has it.

---

## 18. RPC and ALPC interfaces

**The pattern.** A SYSTEM service exposes an RPC interface so its unprivileged UI can ask for
privileged work. The interface is a named, versioned API with numbered procedures, and access is
decided by the endpoint's ACL — which on many products admits every logged-on user.

**Engine gives you.** `rpc.md` recovers the `RPC_SERVER_INTERFACE` structures from the file: the
**interface UUID** to bind to, the version, the **opnum count** read out of the dispatch table,
the endpoints (`ncalrpc:`, `ncacn_np:`), and which registration API was used.

**What each registration API tells you.**
* `RpcServerRegisterIf` — no security callback. Access is whatever the endpoint allows.
* `RpcServerRegisterIfEx` — takes a callback. Read it: one that returns `RPC_S_OK`
  unconditionally is no filter at all, and that is a common shape.
* `RpcServerRegisterIf3` — security descriptor **and** callback. The good form.
* `RpcServerUseAllProtseqs` — registers on **every** transport, including remote ones.

**Work it.** `NtObjectManager` (Forshaw) parses the same structures at runtime and generates a
client: `Get-RpcServer <binary>`, `Get-RpcEndpoint`, `Get-RpcClient`, `Connect-RpcClient`. Bind
as a standard user; if that succeeds, walk the opnums looking for one that takes a path, a
command line, an update URL or a configuration blob.
`scripts/poc_gen.py --kind rpc-client` writes the script.

**The trap.** A caller-PID check (`I_RpcBindingInqLocalClientPID`) is **not** authorization: PIDs
are reusable and the parent process is spoofable via `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`. If
the vendor argues the PID check mitigates it, demonstrate the spoof.

---

## 19. Races, symlinks and impersonation gaps

**The three shapes**, all found by `toctou_audit.py`:

1. **Temp-as-SYSTEM.** `GetTempPath` for a SYSTEM process is `C:\Windows\Temp`, where every user
   holds *create* permission, and `GetTempFileName` names are predictable. Pre-create, squat or
   symlink the file before the privileged process opens it.
2. **Create-then-ACL.** The object is created and secured in two calls. Between them it carries
   the inherited ACL. An oplock, or a plain loop, wins that window.
3. **Check-then-use.** `GetFileAttributes`/`WinVerifyTrust` and then `CreateFile`/`CreateProcess`
   on the same *path*. Swap it in between. When the check is a **signature** check and the use is
   an execution, the signature proves nothing about what actually ran.

**Impersonation gaps** are the fourth and the most common in IPC servers: a pipe or RPC handler
that impersonates, but performs the privileged operation *before* the impersonation or *after*
an early return, does the caller's work with its own SYSTEM token. Count the impersonate/revert
pairs — `frida/win_ipc.js` does it live — and read every exception path.

**Tooling.** symboliclink-testing-tools (Forshaw): `CreateMountPoint`, `CreateSymlink`,
`SetOpLock`, `BaitAndSwitch`. `poc_gen.py --kind oplock-race` writes the sequence for the report.

**MSI repair is the trigger you are looking for.** A per-machine MSI lets a standard user run
`msiexec /fa {ProductCode}`, re-executing deferred custom actions as SYSTEM on demand. That
turns a one-shot install-time race into something you can trigger at will.

---

## 20. Turning a primitive into a demonstrated escalation

Most audits stall at "a SYSTEM process writes a file whose path I influence" because converting
that into a shell is separate knowledge. `scripts/primitive_to_exploit.py` encodes it: give it a
primitive (or `--auto` against a loot) and it prints the techniques, preconditions, steps and the
PoC to generate.

The conversions worth memorising:

| primitive | the standard conversion |
|---|---|
| arbitrary file **write** as SYSTEM | drop a DLL into a privileged process's search path — the cleanest proof |
| arbitrary file **delete** as SYSTEM | delete a file whose absence makes a privileged process fall back to a location you control |
| arbitrary **folder create** as SYSTEM | create a directory earlier in a DLL search path, then populate it |
| service **reconfigure** right | `sc config binPath=` + restart; restore immediately afterwards |
| a SYSTEM process **connects to your pipe** | `ImpersonateNamedPipeClient` — and if you already hold `SeImpersonate`, this is the potato family |
| **IPC command** as SYSTEM | no exploit needed: find the opnum/message that takes a path or a command |
| **registry write** to HKLM | service `ImagePath`, `AppInit_DLLs`, an IFEO `Debugger`, or a COM `InprocServer32` |
| **update package substitution** | the updater runs as SYSTEM and executes what it downloaded, by design |

**The SeImpersonate note.** Any component running as `LocalService`, `NetworkService` or
`IIS APPPOOL\*` holds `SeImpersonatePrivilege` by default. "It only runs as NetworkService" is
therefore not the mitigation vendors believe it is — that account is one coerced connection away
from SYSTEM, and it is a legitimate **service-account → SYSTEM** boundary crossing.

---

## 21. Credential storage at rest

The bar is specific: a store is a finding when **someone who should not be able to read it, can**.

* DPAPI `CurrentUser` protecting against *another user* is working as designed. Reporting it as a
  weakness is a bad report.
* DPAPI `LocalMachine` protects against nobody on the machine. `credstore_audit.py` reads the
  flag **at the call site** rather than grepping for a string, because native code passes the
  constant numerically.
* A hardcoded symmetric key plus a fixed IV is obfuscation. Extract the key and **decrypt a real
  stored blob** — shipping the decryption is what turns a code-quality note into a
  credential-theft report.
* `System.Random` for anything security-relevant is predictable; `CryptDeriveKey` is typically a
  single MD5/SHA-1 pass over the password.
