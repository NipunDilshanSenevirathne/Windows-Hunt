# The no-Windows-VM lane

`preflight.sh` prints `NO-WINDOWS-VM LANE IS ACTIVE` when there is no adb-style Windows target,
no `/dev/kvm`, and no VM declared in `scope/vm.md`. This is a working lane, not a dead end. Most
of a Windows audit is decided before anything runs.

## Fully provable without Windows

| what | how |
|---|---|
| what the installer *intends* to do to the system | MSI tables (`ServiceInstall`, `CustomAction`, `Directory`, `Registry`, `LockPermissions`), Inno/NSIS scripts |
| **MSI custom actions that run as SYSTEM** | type flags 0x400 + 0x800 — a static fact |
| services, their arguments and their configured accounts | MSI `ServiceInstall`, `sc create` strings |
| every DLL each binary imports, and which are phantoms | import table vs the shipped file set vs KnownDLLs |
| exploit mitigations, Authenticode state, manifests | PE headers, security directory, RT_MANIFEST |
| **`requireAdministrator` / `autoElevate` / `uiAccess`** | embedded manifest |
| the whole URI-handler / file-association surface | shipped `.reg`, MSI `Extension`/`Verb`/`ProgId` |
| whether `%1` is quoted in a shipped `.reg` | the file says so |
| localhost listener ports and paths | strings and config |
| update endpoints, cleartext transport, telemetry | strings and config |
| **every .NET sink, with the method name** | IL analysis (dnfile/dncil) |
| Electron/CEF configuration, bridge surface, IPC channels, fuses | the app's own JS |
| hardcoded secrets | the whole extracted tree |
| bundled component versions → CVE exposure | version banners + OSV |
| kernel driver device names, IOCTL codes, ring-0 primitives | PE + disassembly |
| a **compiled, ready-to-drop** proxy DLL PoC | mingw builds a real PE on Linux |
| the complete verification runbook | generated from all of the above |

## Caps at `static-proof-complete` (needs a Windows host)

* the **actual ACL** on an installed directory, and whether a real write succeeds
* which account a service **actually** runs as after install
* whether the loader **actually** looks for a phantom DLL at runtime
* whether a standard user can **actually** open a named pipe, and what the server replies
* whether the listener is really bound, on which interface, owned by which process
* the registry values as **installed** (rather than as shipped in a `.reg`)
* anything involving a token, a race, a crash, or a bugcheck

## How to work the lane

1. Run the full static pipeline. Take every finding as far as the evidence goes.
2. `runbook_gen.py` — the questions above become one read-only PowerShell script.
3. Hand it to whoever has a Windows VM (usually the operator). It is safe to hand over: it
   reads, it does not write.
4. `runbook_ingest.py` — the answers become CONFIRMED / REFUTED verdicts and severity.
5. Anything still unconfirmed ships as a **lead**, labelled as such, with the exact step that
   would confirm it. Never as a finding.

## Getting a VM

The lane exists because this box has no KVM. If the operator can provide one:

* Microsoft ships free, time-limited Windows evaluation VMs for VirtualBox/VMware/Hyper-V.
* Declare it in `scope/vm.md` with a `host:` / `ssh:` / `winrm:` line and preflight switches to
  the full lane.
* Take a clean snapshot **before** installing the target, and revert between tests. An installer
  is code; a dirty VM produces findings you cannot reproduce.
* Install Sysinternals (Procmon, Process Explorer, accesschk, pipelist), and enable
  **standard-user** testing by creating a non-admin account — that is the attacker's position,
  and results from an admin session are not evidence.
