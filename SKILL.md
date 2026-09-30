---
name: windowshunt
version: 1.2
author: "Windows Hunt — by Nipun Dilshan"
description: >
  Windows Hunt by Nipun Dilshan — the deepest Windows application security auditing and
  exploitation workflow in this skill line, built to run natively in Claude Code where the tools
  actually execute. Give it an installer, an executable, a DLL, an MSI/MSIX, an Electron app, a
  kernel driver or an installed application directory and it provisions its own toolchain, takes
  the target apart recursively, reconstructs every privilege boundary the product creates, hunts
  the classes that actually pay on Windows, composes them into chains, maps each primitive to the
  technique that converts it into a demonstrated escalation, scores everything against the MSRC
  boundary rules, generates runnable PoCs plus a read-only verification runbook for your own
  Windows VM, and records every hypothesis in a resumable ledger.

  24-stage pipeline: authorization gate -> auto-provisioning toolchain preflight -> recursive
  container unwrapping (MSI with full table dump, NSIS, Inno, WiX Burn, InstallShield, MSIX/APPX,
  CAB, SFX, UPX, Electron asar, PyInstaller, NuGet) -> PE triage (mitigations, Authenticode,
  manifests, imports, capabilities) -> attack-surface MODEL reconstruction (services, COM, named
  pipes, RPC, URI handlers, localhost listeners, scheduled tasks, MSI custom actions, SDDL/ACL
  intent) -> OS integration points (browser native messaging hosts, shell extensions,
  AppInit/AppCert/IFEO/Winlogon/LSA/credential-provider/print-monitor hooks, parsed task XML,
  file-association %1 quoting, AppX capabilities, ClickOnce, root-certificate installs) ->
  COM/DCOM registration analysis -> RPC/ALPC interface recovery (interface UUID, version, opnum
  count from the dispatch table, endpoints) -> DLL search-order/phantom/side-load -> .NET IL sink
  analysis -> embedded Java/Python/Node/CLR probing-path lanes -> Electron/CEF/WebView2 ->
  secrets -> credential storage at rest -> Authenticode depth -> SBOM to CVE (OSV) -> kernel
  driver IOCTL surface -> TOCTOU/race/symlink/impersonation-gap primitives -> process creation,
  handle inheritance, tokens and privileges -> native capa + radare2 taint intersection ->
  parser inventory and fuzzing harness generation -> chain synthesis -> primitive-to-exploit
  mapping -> duplicate/novelty check against published CVEs -> PoC and runbook generation ->
  Procmon session plan and CSV analyzer -> ledger-driven agentic loop. Plus Ghidra headless
  decompilation of only the flagged functions, release version-diffing, portfolio campaign
  correlation across a vendor's product line, MITRE ATT&CK mapping, seven Windows Frida
  instrumentation scripts, and self-measurement against a vulnerable/hardened twin range it
  builds itself (currently 70/70 detection, 0/70 false positives).

  Three engines perform real static CALL-SITE analysis rather than string heuristics: whether
  CreateProcess passes lpApplicationName = NULL, whether bInheritHandles is TRUE, and whether
  DPAPI uses CRYPTPROTECT_LOCAL_MACHINE — each read from the argument setup at the call site.

  USE THIS SKILL FOR: Windows application security audit, .exe / .msi / .msix / .dll / .sys
  analysis, installer reverse engineering, local privilege escalation (LPE) hunting, DLL
  hijacking and search-order abuse, unquoted service paths, weak service/file/registry ACLs,
  named pipe and RPC and ALPC and COM abuse, RPC interface enumeration, TOCTOU races, symlink and
  junction redirection, impersonation gaps, SeImpersonate and potato-family escalation, arbitrary
  file write/delete as SYSTEM, custom URI protocol handler exploitation, localhost listener and
  DNS-rebinding attacks on desktop apps, browser native messaging host abuse, COM/DCOM hijacking
  and elevation-moniker review, shell extension and AppInit/AppCert/IFEO/Winlogon/LSA hook
  review, Electron and CEF and WebView2 auditing, .NET decompilation and unsafe deserialization,
  CLR assembly probing-path hijack, bundled Java (Log4Shell, gadget libraries) and Python
  (pickle, frozen-app) review, insecure auto-update channels, Authenticode and code-signing gaps,
  signature-verification bypass, hardcoded secrets and credential stores in desktop software,
  DPAPI misuse, bundled third-party CVE exposure, kernel driver IOCTL surface and BYOVD review,
  parser fuzzing harness generation (WinAFL/libFuzzer), Frida instrumentation on Windows, Procmon
  analysis, Ghidra headless decompilation, release diffing, vendor-portfolio correlation,
  duplicate checking against published CVEs, and Windows PoC exploit development for AUTHORIZED
  targets.

  TRIGGER PHRASES: "audit this exe", "analyse this installer", "hunt this MSI", "windows app
  pentest", "desktop application security", "find LPE", "privilege escalation in this app",
  "DLL hijacking", "unquoted service path", "reverse this windows binary", "electron app
  security", "check this .NET app", "is this installer safe", "windows bug bounty", "audit this
  driver", "native messaging host", "shell extension", "COM hijacking", "RPC interface", "named
  pipe LPE", "TOCTOU", "symlink attack", "potato", "SeImpersonate", "arbitrary file write as
  SYSTEM", "DPAPI", "AppX capability review", "fuzz this parser", "procmon", "frida windows",
  "windowshunt". Use it whenever the task is reviewing Windows software for vulnerabilities,
  even without the word "audit".

  Authorized targets only — the scope gate refuses everything else and fails closed.
---

# ╔════════════════════════════════════════════════════════════════════════════╗
# ║   WINDOWS HUNT — by Nipun Dilshan                                          ║
# ║   the boundary is the bug; everything else is a fact about the software    ║
# ╚════════════════════════════════════════════════════════════════════════════╝

> **The one rule everything else serves.** On Windows, a finding is not "the app does something
> insecure". A finding is **code on one side of a privilege boundary making code on the other
> side do something it should not**. Name the boundary in the first sentence of every report or
> the report is not finished. Everything in this skill — the surface model, the privilege
> ranking, the chain search, the severity gate — exists to answer that one question.

**Thesis.** Scanners tell you a binary lacks ASLR. That is a fact, not a bug. The money on
Windows desktop software is in three places, and all three require reasoning a scanner cannot do:

1. **Local privilege escalation** — a SYSTEM service, scheduled task, updater or installer that
   reads code, configuration or a path from somewhere a standard user can write. The weakness is
   never in one file; it is in the *relationship* between a privileged reader and a writable
   location.
2. **The web-to-desktop bridge** — a custom URI handler, a localhost HTTP/WebSocket listener, a
   file association, an Electron renderer. A web page the user merely visits reaches a native
   process. Almost nobody tests these, and they are frequently zero- or one-click.
3. **The update channel** — the one part of every desktop product that executes code by design.
   Transport, signature verification and rollback all have to hold, and one of them usually does
   not.

Tools unpack and disassemble. **The model reasons about who runs what, from where, at what
privilege.** That is the entire edge.

## Measured, not asserted

Every run of `scripts/corpus_check.py` builds two identical application trees — one with every
planted weakness, one with every control correct — and scores both:

```
DETECTION      70/70   on selftest/range/vuln
FALSE POSITIVE  0/70   on selftest/range/hardened
```

Detection without a false-positive number beside it is marketing. If you change an engine, rerun
this; a regression shows up in one command.

---

## ⛔ PHASE 0 — AUTHORIZATION (always first, hard-fail, fails closed)

Analyse only software you own, wrote, or are explicitly authorized to test. **An installer is
executable code**: never run one outside a disposable VM you own.

Three gates, each independent, each refusing by default:

| file | gates | verify |
|---|---|---|
| `scope/authorized_targets.txt` | unpacking and analysis of a binary | `scripts/scope_gate.sh target <path>` |
| `scope/authorized_hosts.txt` | any LIVE request to the target's infrastructure | `scripts/scope_gate.sh host <host>` |
| `scope/authorized_actions.txt` | every intrusive verb (install, run, trace, fuzz, MITM, exploit) | `scripts/scope_gate.sh action <verb>` |

Deny entries (`!` prefix) always beat allows. Empty file = nothing authorized. `scope/rules.md`
holds the engagement's ROE and the Phase-0 intake; fill it in before touching the target.

**Pull the program's in-scope AND out-of-scope lists together.** A wildcard exclusion that slips
through is an incident, not a nit.

Static reverse engineering of an authorized binary needs only the `target` gate. Everything that
touches a running system needs `action`, and runs **in your own VM with your own accounts**.

---

## PHASE 1 — PROVISION & PREFLIGHT

```bash
scripts/provision.sh            # core + analysis + dotnet  (auto-installs everything)
scripts/provision.sh --tier all # + wine, afl++, frida
scripts/preflight.sh            # status, and WHICH LANE YOU ARE IN
```

`provision.sh` is idempotent and tiered. It installs the unpackers (cabextract, msitools,
innoextract, 7z), the PE stack (pefile, lief, capstone, signify), the analysis stack (capa with
its FLIRT signatures, floss, yara, capa-rules, signature-base) and the managed lane
(dnfile + dncil — pure python, so **no dotnet SDK and no Windows are required** to read IL).

**Read the preflight's EXECUTION REALITY CHECK.** It decides how you work:

* **Full lane** — a Windows VM is declared in `scope/vm.md`. Static findings get confirmed the
  same day.
* **No-Windows-VM lane** — no VM, no `/dev/kvm`. This is a real lane, not a failure: see
  `references/no-vm-lane.md` for exactly what stays provable (nearly everything) and what caps
  at `static-proof-complete`. Those ship as a generated runbook for the operator's own hardware,
  labelled UNCONFIRMED until the results come back.

---

## PHASE 2 — INTAKE & RECURSIVE UNWRAP

```bash
scripts/hunt.sh --target "/path/to/Setup.exe" --name acme        # the whole pipeline
# or stage by stage:
scripts/unwrap.py --target Setup.exe --out loot/acme
```

Most tools stop at "it's an installer". Every interesting bug is *inside*: the service exe three
layers down, the .NET assembly inside the MSI inside the Burn bundle, the phantom DLL an Electron
app loads, the update key in an asar. `unwrap.py` walks every container Windows ships — MSI (with
a full table dump), NSIS, Inno, WiX Burn, InstallShield, MSIX/APPX, CAB, SFX, UPX, `.asar`,
PyInstaller, NuGet, 7z/rar/tar — recursively, deduplicating by hash, recording lineage.

**The MSI table dump is not a detail.** `CustomAction`, `ServiceInstall`, `Directory`, `Registry`
and `LockPermissions` tell you what the installer *intends* to do to the system, at what
privilege, before you ever run it.

---

## PHASE 3 — THE SURFACE MODEL (do not skip; this is where the hunt is decided)

```bash
scripts/pe_triage.py         --loot loot/acme  # mitigations, signing, manifests, imports, caps
scripts/surface_model.py     --loot loot/acme  # the boundaries this product creates
scripts/integration_points.py --loot loot/acme # what it asks WINDOWS to load on its behalf
```

Read `surface.md` before any engine output. It is the map: services and the accounts they run
as, MSI custom actions that run as SYSTEM, scheduled tasks, COM classes, named pipes, RPC
symbols, localhost listeners, URI handlers, file associations, update endpoints, cleartext HTTP,
registry writes, autoruns, explicit SDDL, referenced privileges, plugin directories, install
paths classified by who can write to them.

For every row, ask the same three questions and write the answer in the ledger:

1. **Who is on the other side?** (any local user / any web page / a network position / another app)
2. **At what privilege does this side run?** (SYSTEM / admin / the user / AppContainer)
3. **What can the other side make this side do?** (load a DLL, run a command, write a file,
   read a secret, reconfigure itself)

A surface where all three answers are boring is a surface you can stop looking at — and *saying
so in the ledger* is worth as much as a finding, because it stops you walking it again.

`integration.md` is the second half of the map, and it is the half most audits never draw. A
product does not only run its own code: it asks Windows to load code **into other processes**.
A shell extension goes into explorer.exe. `AppInit_DLLs` goes into nearly every process on the
machine. A credential provider goes into LogonUI as SYSTEM *before anyone has authenticated*.
A print monitor goes into spoolsv as SYSTEM. A native messaging host is a browser extension's
direct line to a native binary. Each is a boundary with a different, usually higher-privileged
process on the other side.

### The single highest-yield pattern in Windows desktop software

> A process running as **SYSTEM** reads a file, DLL, configuration or executable path out of
> **`C:\ProgramData\<product>\`**, `%PUBLIC%`, `C:\Temp`, or a custom root created with an
> inherited permissive ACE — all of which are **writable by standard users by default**.

`surface.md` flags every ProgramData/Public/Temp reference it finds. Cross it against the
services and the DLL-hijack output; that intersection is where the LPE lives.

---

## PHASE 4 — ENGINES

| engine | script | what it decides |
|---|---|---|
| **OS integration** | `integration_points.py` | native messaging hosts, shell extensions, AppInit/AppCert/IFEO/Winlogon/LSA/print-monitor hooks, parsed task XML, file-association quoting, AppX/MSIX capabilities, ClickOnce, root-cert installs |
| **RPC / ALPC** | `rpc_audit.py` | recovers `RPC_SERVER_INTERFACE` structures from the binary: interface **UUID**, version, **opnum count** from the dispatch table, endpoints, and whether a security callback is registered at all |
| **COM / DCOM** | `com_audit.py` | server paths in writable locations, phantom CLSIDs a privileged binary activates, elevation moniker, AppID `RunAs` identity and activation ACL, surrogates |
| **DLL search order** | `dll_hijack.py` | phantom / side-load candidates, KnownDLLs suppressed, ranked by **loader privilege** |
| **Managed code** | `dotnet_il.py` | IL-level sinks: deserialization, dynamic load, TLS override, ACL widening, P/Invoke, crypto, Zip-Slip |
| **Embedded runtimes** | `runtime_lane.py` | Java (Log4Shell, gadget libs, `-javaagent`/classpath), Python (pickle, `shell=True`, `sys.path`, frozen-app `_MEIPASS`), Node lifecycle scripts, **CLR probing paths / `codeBase` / binding redirects** |
| **Embedded browser** | `electron_audit.py` | webPreferences, contextBridge surface, IPC channels, custom protocols, fuses, `shell.openExternal` |
| **Secrets** | `secrets_hunt.py` | format-proving credentials with validation commands; generic hits only with a key name |
| **Code signing** | `sign_audit.py` | digest algorithm, timestamp, expiry, mixed publishers, page hashes, data after the signed region, and **whether the product verifies anything itself — and how** |
| **Supply chain** | `sbom_cve.py` | shipped component versions -> EOL floors offline, real CVE ids via OSV with `--online` |
| **Kernel** | `driver_ioctl.py` | device objects, missing device SDDL, decoded IOCTL codes, ring-0 primitives |
| **Native** | `native_sinks.py` | capa capabilities with addresses + radare2 xrefs; flags **one function that touches both a user-writable path and a dangerous API** |
| **Installer intent** | (in `surface_model.py`) | MSI custom actions that are deferred + no-impersonate = **running as SYSTEM** |
| **TOCTOU / races** | `toctou_audit.py` | temp-as-SYSTEM, create-then-ACL, check-then-use, move/delete-as-SYSTEM, symlink enablers, **impersonation gaps**, unsafe extraction, MSI repair-mode |
| **Process & tokens** | `process_audit.py` | **reads the CreateProcess call site**: is `lpApplicationName` NULL, is `bInheritHandles` TRUE — plus dangerous privileges, env-inheritance vectors, ShellExecute verb resolution |
| **Credential storage** | `credstore_audit.py` | **reads the DPAPI scope flag at the call site**, roll-your-own crypto, ECB, weak KDF, CredMan persistence, store locations |
| **Exploitation** | `primitive_to_exploit.py` | infers which primitives the target grants and expands each into concrete techniques, preconditions, steps and the PoC to generate |
| **Parsers / fuzzing** | `fuzz_harness.py` | what the product parses, which binary parses it at what privilege, plus ready WinAFL / libFuzzer / dumb-fuzz / crash-triage artifacts |
| **Decompilation** | `ghidra_decompile.py` | headless Ghidra C for **only** the functions the native pass flagged — root-cause evidence without a 20-minute full decompile |
| **Novelty** | `dedup_oracle.py` | your finding classes vs this product's published CVE history (NVD + OSV); also a map of what the vendor keeps getting wrong |
| **Portfolio** | `campaign.py` | shared binaries, shared components, **divergent versions** and recurring finding classes across a vendor's whole product line |
| **Release diff** | `version_diff.py` | new files, binaries that **gained capability**, elevation/mitigation/signing changes, new surfaces, component jumps, and **silent fixes** |
| **Composition** | `chain.py` | edges `precondition -> capability`, searched from an unprivileged start to a boundary crossing |

Each writes `<engine>.json` (machine) and `<engine>.md` (you). Stages are independent — rerun any
one alone after a fix.

### What the engines deliberately do NOT report

KnownDLLs imports. API-set imports. "Missing ASLR" on an unprivileged helper. An updater that
exists and uses HTTPS. A public client id the app is supposed to ship. `runFullTrust` on a
packaged app (that is how every packaged Win32 app ships). A browser-internal scheme like
`chrome-extension://` mistaken for a product handler. Reporting these is how a
researcher's signal with a triage team is destroyed. If one looks relevant, it is because it is a
*link in a chain* — report the chain, not the link.

---

## PHASE 5 — VERIFY (the runbook loop)

```bash
scripts/runbook_gen.py --loot loot/acme            # -> loot/acme/runbook/verify.ps1
#   run verify.ps1 IN YOUR OWN WINDOWS VM, as a STANDARD USER first
scripts/runbook_ingest.py --loot loot/acme --result wh-verify.json
```

`verify.ps1` is **read-only**: it reads ACLs, service configuration, scheduled tasks, pipe names,
registry and listening sockets, and writes one JSON file. It drops nothing, starts nothing,
changes nothing — so it is safe to hand to a customer's administrator.

It answers exactly the questions static analysis cannot, and `runbook_ingest.py` turns those
answers into CONFIRMED / REFUTED verdicts:

| question | decides |
|---|---|
| is this directory really writable by a standard user? | the precondition for almost every LPE here |
| what account does the service actually run as? | whether anything else on that service matters |
| is the service path unquoted, and is an intermediate directory writable? | a complete LPE |
| does the service DACL let Users change `binPath`? | a direct LPE |
| can a standard user open this named pipe? | whether the protocol behind it is attack surface |
| is `%1` quoted in `shell\open\command`? | argument injection from a web page |
| is the listener on `127.0.0.1` or `0.0.0.0`? | local-only or remote |
| does the loader really look for the phantom DLL, and can we write there? | the hijack |
| is any `PATH` entry writable? | escalates every unresolved import on the whole host |

**Run it as a standard user.** Writability observed from an elevated context proves nothing about
the attacker's position, and the ingester will say so.

---

## PHASE 6 — PROVE IT

```bash
scripts/poc_gen.py --list
scripts/poc_gen.py --kind proxy-dll --out loot/acme/poc --dll wintls.dll --loader AcmeSvc.exe
x86_64-w64-mingw32-gcc -shared -o wintls.dll loot/acme/poc/poc.c      # builds a real PE, on Linux
```

Every template proves the boundary crossing **and nothing else**: it writes a file containing the
token the code ran under. No payloads, no persistence, no data touched.

`proxy-dll` (with `--forward <real.dll>` it emits real export forwarders, so the host keeps
working) · `pipe-client` · `impersonate` (receive a privileged connection and record the token)
· `com-elevation` · `rpc-client` (NtObjectManager: bind and enumerate opnums as a standard user)
· `ioctl-probe` · `oplock-race` · `uri-arg` · `localhost` · `acl-check` · `service-abuse` ·
`symlink` · `update-mitm`

### Runtime instrumentation for the VM

`frida/` ships seven Windows scripts — file operations, process creation, IPC and impersonation
pairing, registry, **key material dumped as hex**, `LoadLibrary` resolution, and
`win_verify.js --flip`, which forces every `WinVerifyTrust` to succeed. If the product behaves
identically with verification forced to success, the signature check was the only thing between
an attacker and code execution — and you have just proved it.

`procmon_filter.py` writes the Procmon session plan **and** `analyze_procmon.ps1`, which
post-processes a CSV export to find privileged access to writable paths, `NAME NOT FOUND` DLL
probes, hot registry writes and **check-then-use pairs on the same path from the same thread**.

> **calc.exe is not proof.** The proof is the *token*: a file written by the privileged process
> containing `whoami`, the pid and the image path, or the full command line captured in Process
> Explorer, or the Procmon line with `Integrity: System`.

---

### Reading the call site, not the strings

Three engines do real static argument analysis rather than string heuristics, because the
difference decides whether something is a finding or noise:

| question | how it is answered |
|---|---|
| is `lpApplicationName` NULL on this `CreateProcess`? | scan for the call encodings (including GCC's `mov rax,[iat]; call rax`), decode backwards to the argument setup, read `rcx` |
| is `bInheritHandles` TRUE? | same window, read `[rsp+0x20]` |
| is DPAPI using `CRYPTPROTECT_LOCAL_MACHINE`? | same window, read the flags argument at `[rsp+0x28]` |

A linear disassembly sweep desynchronises on the first data-in-code island and then silently
reports **zero** call sites on a binary full of them — which reads like a clean result. These
engines byte-scan for the call encodings instead, so they cannot desynchronise.

### Going deeper on one target

```bash
# root cause, in C, for exactly the functions that matter
scripts/ghidra_decompile.py --loot loot/acme --binary AcmeSvc.exe --auto

# the memory-safety lane: what does it parse, and who parses it at what privilege?
scripts/fuzz_harness.py --loot loot/acme

# is it already public? (also: what has this vendor historically got wrong?)
scripts/dedup_oracle.py --loot loot/acme --online

# hunt only what changed between two releases — the lowest-duplicate surface there is
scripts/hunt.sh --target old/Setup.exe --name acme-4.1
scripts/version_diff.py --old loot/acme-4.1 --new loot/acme-4.2

# a vendor's whole product line at once: shared binaries, shared components, divergent versions
scripts/campaign.py --all

# you have a primitive — what does it turn into?
scripts/primitive_to_exploit.py --primitive arbitrary-file-write-as-SYSTEM
```

`version_diff.py` also reads backwards: a binary that **dropped** `requireAdministrator`, a
surface that **disappeared**, or a bundled component that **jumped several versions** is a
silent security fix — and a silent fix is a map to the bug that is still live in the older
release the vendor is still supporting.

---

## PHASE 7 — SCORE IT HONESTLY

```bash
scripts/severity_win.py --list-boundaries
scripts/severity_win.py --vector "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" --boundary user-to-system
```

CVSS alone gets Windows findings wrong in both directions. The gate is **which boundary was
crossed** (`references/windows-boundaries.md` for the full list and the reasoning):

**Report these:** standard user → admin/SYSTEM · sandbox/AppContainer escape · one user → another
user's data · remote/unauthenticated → local code execution · a web page → the local app · the
update channel → code execution · a constrained service account → SYSTEM.

**Do not report these alone:** admin → SYSTEM · UAC bypass at the default level · anything
requiring the attacker to already be admin · AV/EDR or mitigation bypass with no underlying bug ·
physical access to an unlocked machine (unless the product claims to defend it).

If your finding is in the second list, **pivot**: find the same primitive reachable without the
disqualifying precondition, or chain it behind something that does cross a boundary. Submitting
it as-is is a by-design close and it costs you credibility for the next report.

---

## PHASE 8 — REPORT

```bash
scripts/report_build.sh --loot loot/acme --id F1 --title "LPE via phantom wintls.dll in AcmeSvc"
```

The summary sentence is always the same shape and it is always first:

> **As an attacker with `<starting position>`, I can `<action>`, which results in `<impact>`.**

Declarative. No "could potentially". Then: boundary crossed, severity sentence from
`severity_win.py`, affected versions with SHA-256, preconditions stated honestly (including the
inconvenient ones), numbered reproduction, the artifact, the root cause with `file:line` or the
registry path, impact once without adjectives, and the specific fix.

State what you did **not** verify. A report that says "the ACL check was run on Windows 11 23H2
with a default install; I did not test a custom install path" survives triage. One that quietly
assumes it does not.

---

## THE AGENTIC LOOP — how to actually work a target

The ledger is the loop. It survives context compaction, which is the real failure mode of a long
audit.

```bash
scripts/hunt_state.py init --loot loot/acme --target "Acme Desktop 4.2"
scripts/hunt_state.py add  --loot loot/acme --engine dll-hijack \
  --hypothesis "AcmeSvc (SYSTEM) loads phantom wintls.dll from its install dir" \
  --evidence "dll_hijack.md:12" --test "icacls; Procmon NAME NOT FOUND; proxy dll; capture token" \
  --boundary user-to-system --impact 8 --reach 0.6 --dup 0.2 --conf 0.4
scripts/hunt_state.py next --loot loot/acme          # highest expected value, right now
scripts/hunt_state.py set  --loot loot/acme --id H3 --status refuted --note "dll ships in System32"
```

`EV = impact × reachability × (1 − dup) × confidence × boundary_weight`

The boundary weight is what keeps you honest: a beautiful admin→SYSTEM trick scores near zero,
which is the correct answer.

**The loop, per iteration:**

1. `hunt_state.py next` — take the highest-EV open row. Do not browse; the ledger decides.
2. Gather the evidence that would **refute** it first. Refuting is faster than confirming and a
   refutation is a permanent gain.
3. If it survives, find the cheapest step that raises confidence: read the decompiled function,
   read the installer table, add the check to the runbook.
4. Update the row — always, including when nothing changed and *especially* when it died.
5. When a row is CONFIRMED, immediately ask: **what does this now make possible?** A confirmed
   capability invalidates earlier "not exploitable" conclusions that depended on not having it.
   Re-open those rows. This is the only step that produces chains.
6. Every ~10 iterations, reread `surface.md` and ask which surfaces still have **no rows at all**.
   Those are your blind spots, and they are where the non-duplicate findings are.

**Parallelising with subagents.** For a large target, partition by *surface*, never by file:
one agent per {services+installer, IPC+pipes+COM, web-facing (URI/listener/Electron), managed
code, native+drivers, supply chain}. Each gets `agents/partition-brief.md`, works its partition
exhaustively, and returns either a reproduced finding or a recorded refutation. Merge into one
ledger. Do not spawn agents unless the operator asks or the target is genuinely large — a cold
agent re-derives context you already have.

---

## CAMPAIGN MODE

A vendor ships six products that share three DLLs. Hunt them as a portfolio:

```bash
for t in ProductA.msi ProductB.exe ProductC.msi; do
  scripts/hunt.sh --target "$t" --name "$(basename "$t" | cut -d. -f1)"
done
```

Then diff the shared components across loots. **A weakness in a shared updater, shared service or
shared installer framework is a platform-scale finding**, and it is the same amount of work as
one product. Record the correlation in `references/hunt-memory.md`.

---

## REFERENCES (read the one that matches what you are hunting)

| file | when |
|---|---|
| `references/windows-boundaries.md` | before scoring anything — the MSRC boundary list and how to argue the edge cases |
| `references/class-playbooks.md` | the per-class hunting recipes: LPE, DLL hijack, pipes/RPC/COM, URI handlers, localhost, update channels, .NET, Electron, drivers, installers |
| `references/no-vm-lane.md` | when preflight says there is no Windows VM |
| `references/hunt-memory.md` | what worked, what duplicated, across engagements — write to it at the end of every hunt |
| `agents/partition-brief.md` | the brief handed to a subagent working one surface |

## LAYOUT

```
scope/      authorization (targets, hosts, actions, ROE, vm.md)   <- fails closed
scripts/    the pipeline (23+ engines); every one runs standalone with --loot
ghidra_scripts/ WHDecompile.java — the headless decompilation script
rules/      yara pack for Windows-app audit signals
frida/      seven Windows instrumentation scripts for the VM
references/ the knowledge this skill reasons with
poc_templates/ ready PoC sources (also emitted by poc_gen.py)
selftest/   the vulnerable/hardened range + make_range.py
loot/<name>/  per-target output: *.json (machine), *.md (you), ledger, runbook, decompiled,
            fuzz harnesses, findings
vendor/     capa-rules, capa FLIRT signatures, signature-base
.venv/      the python analysis stack
```

## DISCIPLINE

* Authorized targets only. The gate fails closed; do not edit around it.
* **An installer runs code.** Never execute the target outside a disposable VM you own.
* UAC is not a security boundary. Admin→SYSTEM alone is not a finding.
* A finding is not a finding until it is reproduced with an artifact a triager can replay.
* Refutations go in the ledger. They are the most valuable rows you will write.
* Report what you proved; label what you projected. Confidence comes from verification, never
  from adjectives.
