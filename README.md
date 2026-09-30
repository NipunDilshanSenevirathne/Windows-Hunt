# Windows Hunt

**A deep security auditing and exploitation-research toolkit for Windows applications, built as a Claude Code skill.**

Point it at an installer, an executable, a DLL, an MSI/MSIX, an Electron app, a kernel driver or an installed application directory. It provisions its own toolchain, takes the target apart recursively, reconstructs every privilege boundary the product creates, hunts the classes that actually pay on Windows, composes them into chains, maps each primitive to the technique that converts it into a demonstrated escalation, scores everything against Microsoft's own boundary rules, and generates runnable proofs plus a read-only verification runbook for your own Windows VM.

It runs on **Linux** and analyses Windows software without needing Windows for the static half.

```
DETECTION      70/70   on its own vulnerable range
FALSE POSITIVE  0/70   on the hardened twin
```

Those numbers are produced by `scripts/corpus_check.py` on every run, against two application trees the project builds itself — identical in shape, one with every planted weakness, one with every control correct. Detection without a false-positive number beside it is marketing.

---

## Table of contents

- [Why this exists](#why-this-exists)
- [Install](#install)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [The authorization model](#the-authorization-model)
- [The pipeline — 24 stages](#the-pipeline--24-stages)
- [Engine reference](#engine-reference)
- [Output files](#output-files)
- [Workflows](#workflows)
- [The no-Windows-VM lane](#the-no-windows-vm-lane)
- [Proof-of-concept generation](#proof-of-concept-generation)
- [Runtime instrumentation](#runtime-instrumentation)
- [Severity and the MSRC boundary model](#severity-and-the-msrc-boundary-model)
- [The hunt ledger](#the-hunt-ledger)
- [Self-measurement](#self-measurement)
- [Repository layout](#repository-layout)
- [Extending it](#extending-it)
- [Design notes](#design-notes)
- [Troubleshooting](#troubleshooting)
- [Responsible use](#responsible-use)

---

## Why this exists

Scanners tell you a binary lacks ASLR. That is a fact, not a bug.

On Windows, a finding is **code on one side of a privilege boundary making code on the other side do something it should not**. Everything in this project serves that single question — the surface model, the privilege ranking, the chain search, the severity gate.

The money is in three places, and all three need reasoning a scanner cannot do:

1. **Local privilege escalation.** A SYSTEM service, scheduled task, updater or installer that reads code, configuration or a path from somewhere a standard user can write. The weakness is never in one file; it is in the *relationship* between a privileged reader and a writable location.
2. **The web-to-desktop bridge.** A custom URI handler, a localhost HTTP/WebSocket listener, a browser native-messaging host, a file association, an Electron renderer. A web page the user merely visits reaches a native process. Almost nobody tests these, and they are frequently zero- or one-click.
3. **The update channel.** The one component in every desktop product whose job is to execute new code. Transport, manifest integrity and package signature all have to hold, and one of them usually does not.

Tools unpack and disassemble. The analyst — or the model driving this skill — reasons about *who runs what, from where, at what privilege*. That is the whole edge.

---

## Install

```bash
git clone https://github.com/<you>/Windowshunt.git
cd Windowshunt
./install.sh
```

`install.sh` copies the skill to `~/.claude/skills/windowshunt`, then runs `scripts/provision.sh`, which installs the toolchain. It is idempotent — re-running only fills gaps.

Options:

| flag | effect |
|---|---|
| `--link` | symlink instead of copy (for developing the skill itself) |
| `--no-provision` | install files only; run `scripts/provision.sh` yourself later |
| `--dest PATH` | install somewhere other than `~/.claude/skills/windowshunt` |

Verify the installation end to end (builds its own test range, ~2 minutes):

```bash
~/.claude/skills/windowshunt/scripts/corpus_check.py
# expected:  DETECTION 70/70   FALSE POSITIVE 0/70
```

In Claude Code the skill is then available as `/windowshunt`. It also works as a plain CLI toolkit with no Claude involved — every script runs standalone.

### What provisioning installs

| tier | contents |
|---|---|
| `core` | `cabextract`, `msitools`, `innoextract`, `p7zip`, `yara`, `osslsigncode`, `radare2`, `binutils`, `exiftool` + a dedicated venv with `pefile`, `lief`, `capstone`, `yara-python`, `signify`, `cryptography`, `construct`, `python-magic` |
| `analysis` | `flare-capa`, `flare-floss`, the **capa rule set**, capa's **FLIRT signatures** (capa refuses to run without them), and `signature-base` |
| `dotnet` | `dnfile` + `dncil` — a pure-Python .NET IL lane, so **no dotnet SDK and no Windows are needed** to resolve managed sinks. `ilspycmd` is installed as an optional upgrade if a dotnet SDK is present. |
| `dynamic` | `wine`, `winetricks`, `frida-tools` (optional) |
| `fuzz` | `afl++`, `radamsa` (optional) |

```bash
scripts/provision.sh                 # core + analysis + dotnet (the default hunt set)
scripts/provision.sh --tier all      # everything, including wine and fuzzing (~2 GB)
scripts/provision.sh --check         # report only, install nothing
scripts/preflight.sh                 # status, and which lane you are in
```

---

## Requirements

* **Linux.** Tested on Kali and Debian/Ubuntu derivatives.
* **Python 3.9+** with `venv`.
* **sudo** for the apt packages (provisioning only).
* ~300 MB of disk for the venv and rule packs.
* Optional: `x86_64-w64-mingw32-gcc` (lets the PoC generator build real Windows DLLs on Linux), `ghidra` (headless decompilation), `pwsh` (syntax-checks generated PowerShell), `node` (syntax-checks the Frida scripts).
* Optional but transformative: **a disposable Windows VM you own**. See [the no-VM lane](#the-no-windows-vm-lane).

---

## Quick start

```bash
cd ~/.claude/skills/windowshunt

# 1. authorize the target — the gate fails closed and this is not optional
echo "MyApp Setup.exe" >> scope/authorized_targets.txt

# 2. run everything
./scripts/hunt.sh --target "/path/to/MyApp Setup.exe" --name myapp

# 3. read in this order
less loot/myapp/surface.md          # the boundaries this product creates
less loot/myapp/integration.md      # what it asks Windows to load on its behalf
less loot/myapp/exploit_paths.md    # what each primitive turns into
less loot/myapp/chains.md           # proposed boundary crossings, ranked

# 4. confirm the runtime questions in YOUR OWN Windows VM
#    (verify.ps1 is read-only: it reads ACLs and config, changes nothing)
#    then bring the result back:
./scripts/runbook_ingest.py --loot loot/myapp --result wh-verify.json
```

Useful flags for `hunt.sh`:

| flag | effect |
|---|---|
| `--fast` | skip `native_sinks` (capa + radare2), the slow stage |
| `--online` | enable OSV and NVD lookups (bundled-CVE resolution + duplicate checking) |
| `--top N` | how many binaries the native stage analyses (default 12) |

---

## The authorization model

Three independent gates, each refusing by default. This is not decoration — it is the thing that makes the toolkit safe to hand to someone.

| file | gates | verify with |
|---|---|---|
| `scope/authorized_targets.txt` | unpacking and analysing a binary | `scripts/scope_gate.sh target <path>` |
| `scope/authorized_hosts.txt` | any live request to the target's own infrastructure | `scripts/scope_gate.sh host <host>` |
| `scope/authorized_actions.txt` | every intrusive verb (install, run, trace, fuzz, MITM, exploit) | `scripts/scope_gate.sh action <verb>` |

Rules:

* **Deny entries (`!` prefix) always beat allows.** A wildcard exclusion that slips through is an incident, not a nit.
* **An empty file authorizes nothing.** All three ship empty.
* Static reverse engineering of an authorized binary needs only the `target` gate.
* Anything touching a running system needs an `action` entry, and runs **in your own VM with your own accounts**.
* Tooling downloads (PyPI, GitHub, OSV, NVD) are *provisioning*, not engagement traffic, and are governed by `provision.sh` rather than the host gate.

`scope/rules.md` holds the engagement intake — product, versions, SHA-256, program, authorization basis, excluded classes. Fill it in before touching the target.

> **An installer is executable code.** Never run one outside a disposable VM you own, from a clean snapshot, reverted between tests.

---

## The pipeline — 24 stages

`scripts/hunt.sh` runs these in order. Every stage is independent and re-runnable alone with `--loot`.

| # | stage | what it produces |
|---|---|---|
| 0 | scope gate | hard fail unless the target is authorized |
| 1 | `unwrap` | recursive container extraction + a hashed, typed file manifest |
| 2 | `pe_triage` | per-binary mitigations, Authenticode, manifests, imports, capability map |
| 3 | `surface_model` | services, COM, pipes, RPC, URI handlers, listeners, tasks, MSI custom actions, SDDL, install paths by privilege |
| 4 | `integration_points` | native messaging hosts, shell extensions, AppInit/AppCert/IFEO/Winlogon/LSA/print-monitor hooks, parsed task XML, file-association quoting, AppX capabilities, ClickOnce, root-cert installs |
| 5 | `com_audit` | CLSID server paths, phantom CLSIDs, elevation moniker, AppID `RunAs` + activation ACL, surrogates |
| 6 | `rpc_audit` | RPC/ALPC interface UUIDs, versions, **opnum counts**, endpoints, registration APIs |
| 7 | `dll_hijack` | phantom / side-load candidates, KnownDLLs suppressed, ranked by loader privilege |
| 8 | `dotnet_il` | IL-level managed sinks with `Namespace.Type::Method` resolution |
| 9 | `runtime_lane` | Java (Log4Shell, gadget libs), Python (pickle, frozen apps), Node, CLR probing paths |
| 10 | `electron_audit` | webPreferences, contextBridge surface, IPC channels, protocols, fuses |
| 11 | `secrets_hunt` | format-proving credentials with validation commands |
| 12 | `credstore_audit` | DPAPI scope **read at the call site**, roll-your-own crypto, store locations |
| 13 | `sign_audit` | digest algorithm, timestamp, expiry, mixed publishers, data after the signed region, and whether the product verifies anything itself |
| 14 | `sbom_cve` | shipped component versions → EOL floors offline, CVE ids via OSV with `--online` |
| 15 | `driver_ioctl` | device objects, missing device SDDL, decoded IOCTL codes, ring-0 primitives |
| 16 | `toctou_audit` | temp-as-SYSTEM, create-then-ACL, check-then-use, move/delete primitives, symlink enablers, impersonation gaps, MSI repair trigger |
| 17 | `process_audit` | **CreateProcess call sites read directly**: NULL `lpApplicationName`, `bInheritHandles`, plus privileges and env-inheritance vectors |
| 18 | `native_sinks` | capa capabilities with addresses + radare2 xrefs; flags one function that touches both a writable path and a dangerous API |
| 19 | `fuzz_harness` | parser inventory ranked by privilege + WinAFL / libFuzzer / dumb-fuzz / triage artifacts |
| 20 | `chain` | edges `precondition → capability`, searched from an unprivileged start to a boundary crossing |
| 21 | `primitive_to_exploit` | which primitives the target grants, and the technique that converts each one |
| 22 | `dedup_oracle` | your finding classes vs this product's published CVE history *(needs `--online`)* |
| 23 | `runbook_gen` | a read-only PowerShell script that answers every runtime question |
| 24 | `procmon_filter` | Procmon session plan + a CSV analyzer that finds the LPE shapes automatically |

On-demand stages, not in the default run:

| script | use |
|---|---|
| `ghidra_decompile.py` | headless Ghidra C for **only** the functions the native stage flagged |
| `version_diff.py` | diff two releases; hunt only what changed, and spot silent fixes |
| `campaign.py` | correlate a vendor's whole product line |
| `severity_win.py` | CVSS + boundary weighting + MITRE ATT&CK |
| `poc_gen.py` | generate a proof for a specific finding class |
| `report_build.sh` | assemble a submission-ready finding directory |
| `hunt_state.py` | the resumable hypothesis ledger |

### Containers `unwrap.py` opens

MSI (with a full table dump), NSIS, Inno Setup, WiX Burn, InstallShield, MSIX/APPX, CAB, self-extracting archives, UPX, Electron `.asar` (pure Python), PyInstaller (pure Python), NuGet `.nupkg`, 7z/RAR/tar/gzip/xz, and a binwalk carve fallback — recursively, deduplicating by hash, recording lineage.

The MSI table dump is not a detail. `CustomAction`, `ServiceInstall`, `Directory`, `Registry` and `LockPermissions` tell you what the installer *intends* to do to the system, at what privilege, before you ever run it.

---

## Engine reference

### What the engines deliberately do **not** report

KnownDLLs imports. API-set imports. "Missing ASLR" on an unprivileged helper. An updater that exists and uses HTTPS. A public client id the app is supposed to ship. `runFullTrust` on a packaged app — that is how every packaged Win32 app ships. A browser-internal scheme like `chrome-extension://` mistaken for a product handler.

Reporting these is how a researcher's signal with a triage team is destroyed. If one looks relevant, it is because it is a *link in a chain* — report the chain, not the link.

### The highest-yield pattern in Windows desktop software

> A process running as **SYSTEM** reads a file, DLL, configuration or executable path out of **`C:\ProgramData\<product>\`**, `%PUBLIC%`, `C:\Windows\Temp`, or a custom root created with an inherited permissive ACE — all of which are **writable by standard users by default**.

`surface.md` flags every such reference. Cross it against the services and the DLL-hijack output; that intersection is where the LPE lives.

---

## Output files

Everything lands in `loot/<name>/`. Each engine writes `.json` (for the next stage) and `.md` (for you).

| file | contents |
|---|---|
| `unwrap.md` | what the target is, what came out, container lineage |
| `pe_triage.md` | per-binary mitigations, signing, elevation manifests, capability map |
| **`surface.md`** | **start here** — every boundary the product creates |
| **`integration.md`** | what it asks Windows to load on its behalf |
| `com.md` / `rpc.md` | COM registration analysis / recovered RPC interfaces |
| `dll_hijack.md` | phantom and side-load candidates, privilege-ranked |
| `dotnet_il.md` / `runtime.md` / `electron.md` | managed sinks / embedded runtimes / browser framework |
| `toctou.md` / `process.md` / `credstore.md` | race primitives / process + token analysis / credential storage |
| `secrets.md` / `signing.md` / `sbom.md` / `drivers.md` | credentials / Authenticode depth / bundled CVEs / kernel drivers |
| `native.md` | capa capabilities + radare2 xrefs + the taint intersection |
| `fuzz.md` + `fuzz/` | parser inventory and ready harnesses |
| **`chains.md`** | proposed boundary crossings, ranked by composite confidence |
| **`exploit_paths.md`** | each primitive expanded into techniques, steps and PoCs |
| `dedup.md` | published CVEs for this product and what the vendor keeps getting wrong |
| `runbook/verify.ps1` | the read-only script to run in your VM |
| `procmon/` | Procmon session plan + `analyze_procmon.ps1` |
| `ledger.md` | the hypothesis ledger, EV-ranked |
| `findings/` | assembled report directories |

---

## Workflows

### Static-only (no Windows machine)

```bash
./scripts/hunt.sh --target "Setup.exe" --name acme --online
# read surface.md -> integration.md -> exploit_paths.md -> chains.md
# everything runtime-dependent ships as runbook/verify.ps1
```

### With a Windows VM

```bash
# 1. declare the VM so preflight switches to the full lane
$EDITOR scope/vm.md

# 2. static pass
./scripts/hunt.sh --target "Setup.exe" --name acme

# 3. in the VM, as a STANDARD USER (this is the attacker's position):
#    powershell -ExecutionPolicy Bypass -File .\verify.ps1
#    bring wh-verify.json back, then:
./scripts/runbook_ingest.py --loot loot/acme --result wh-verify.json

# 4. prove the confirmed ones
./scripts/poc_gen.py --kind proxy-dll --out loot/acme/poc \
      --dll wintls.dll --loader AcmeSvc.exe --forward /path/to/real/wintls.dll
x86_64-w64-mingw32-gcc -shared -o wintls.dll loot/acme/poc/poc.c loot/acme/poc/wintls.dll.def
```

### Hunt only what changed between releases

```bash
./scripts/hunt.sh --target old/Setup.exe --name acme-4.1
./scripts/hunt.sh --target new/Setup.exe --name acme-4.2
./scripts/version_diff.py --old loot/acme-4.1 --new loot/acme-4.2
```

New code is the lowest-duplicate surface there is. The diff also reads backwards: a binary that **dropped** `requireAdministrator`, a surface that **disappeared**, or a bundled component that **jumped several versions** is a silent security fix — and a silent fix is a map to the bug still live in the older release the vendor still supports.

### A vendor's whole product line

```bash
for t in /targets/*.msi /targets/*.exe; do
  ./scripts/hunt.sh --target "$t" --name "$(basename "${t%.*}")"
done
./scripts/campaign.py --all
```

Shared binaries, shared components, **divergent versions** and recurring finding classes. A weakness in a shared updater or installer framework is a platform finding for the same work as one product — and a class that is non-zero for every product is a systemic engineering problem, which reports better as one root-cause finding than as five instance reports.

---

## The no-Windows-VM lane

`preflight.sh` prints `NO-WINDOWS-VM LANE IS ACTIVE` when there is no VM declared and no `/dev/kvm`. This is a working lane, not a dead end. Most of a Windows audit is decided before anything runs.

**Fully provable without Windows:** what the installer intends to do · MSI custom actions that run as SYSTEM · services and their configured accounts · every DLL each binary imports and which are phantoms · mitigations, Authenticode state and manifests · the whole URI-handler and file-association surface (including whether `%1` is quoted in a shipped `.reg`) · localhost listener ports · update endpoints and cleartext transport · every .NET sink with its method name · RPC interface UUIDs and opnum counts · Electron configuration and bridge surface · hardcoded secrets · bundled-component CVE exposure · kernel driver IOCTL codes · **a compiled, ready-to-drop proxy DLL** · the complete verification runbook.

**Caps at `static-proof-complete`:** the actual ACL on an installed directory · which account a service actually runs as · whether the loader actually probes for a phantom DLL · whether a standard user can actually open a pipe · the registry as *installed* rather than as shipped · anything involving a token, a race or a crash.

Those ship as the generated runbook, and stay labelled **UNCONFIRMED** until the results come back. Never as findings.

---

## Proof-of-concept generation

```bash
./scripts/poc_gen.py --list
```

| kind | proves |
|---|---|
| `proxy-dll` | DLL hijack. With `--forward <real.dll>` it reads the victim's exports and emits a `.def` of forwarders, so the host keeps working instead of crashing |
| `pipe-client` | a standard user can open the pipe, and what the server replies |
| `impersonate` | receives a privileged connection on a pipe you own and records the impersonated token |
| `com-elevation` | activation as a standard user + the elevation moniker + server path and identity |
| `rpc-client` | NtObjectManager script: bind as a standard user and enumerate opnums |
| `ioctl-probe` | opens the device as a standard user and walks the IOCTL surface |
| `oplock-race` | the check-then-use / create-then-ACL race sequence |
| `uri-arg` | argument injection through a custom URI handler, from a real web origin |
| `localhost` | a web page reaching a 127.0.0.1 listener, with the DNS-rebinding case |
| `acl-check` | reads the ACL *and* proves it with a real write |
| `service-abuse` | decodes the service SDDL and shows the reconfiguration right |
| `symlink` | the junction + object-manager symlink primitive sequence |
| `update-mitm` | a proxy that tests TLS validation, manifest trust and package signature in order |

Every template proves the boundary crossing **and nothing else**: it writes a file containing the token the code ran under. No payloads, no persistence, no data touched.

> **calc.exe is not proof.** The proof is the token: a file written by the privileged process containing `whoami`, the pid and the image path — or the full command line captured in Process Explorer, or the Procmon line with `Integrity: System`.

---

## Runtime instrumentation

`frida/` ships seven Windows scripts for the operator's VM:

| script | answers |
|---|---|
| `win_fileops.js` | every path touched, flagged when user-writable; catches the TOCTOU shapes |
| `win_process.js` | full command lines, `lpApplicationName == NULL`, `bInheritHandles`, env reads |
| `win_ipc.js` | pipe DACLs decoded to SDDL, and **impersonation vs revert pairing** |
| `win_registry.js` | key/value writes, flagged for the keys that change what other processes load |
| `win_crypto.js` | DPAPI scope and **symmetric keys/IVs dumped as hex** — run twice and diff to prove a key is hardcoded |
| `win_verify.js` | `WinVerifyTrust` tracing, and `--flip` mode: force every verification to succeed. If the product behaves identically, the signature check was the only control on that path |
| `win_loadlibrary.js` | every `LoadLibrary` with the resolved path — confirms phantom candidates live |

`scripts/procmon_filter.py` writes a Procmon session plan **and** `analyze_procmon.ps1`, which post-processes a CSV export to surface privileged access to writable paths, `NAME NOT FOUND` DLL probes, hot registry writes, privileged temp usage, and **check-then-use pairs on the same path from the same thread**.

---

## Severity and the MSRC boundary model

```bash
./scripts/severity_win.py --list-boundaries
./scripts/severity_win.py --vector "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" \
                          --boundary user-to-system --class dll-hijack
```

CVSS alone gets Windows findings wrong in both directions. The gate is **which boundary was crossed**.

**Report these:** standard user → admin/SYSTEM · service account → SYSTEM · sandbox/AppContainer escape · one user → another user's data · remote/unauthenticated → local code execution · a web page → the local app · the update channel → code execution · a network position → the app · an untrusted file → code execution.

**Do not report these alone:** admin → SYSTEM · UAC bypass at the default level · anything requiring the attacker to already be admin · AV/EDR or mitigation bypass with no underlying bug · physical access to an unlocked machine unless the product claims to defend it.

If your finding is in the second list, **pivot**: find the same primitive reachable without the disqualifying precondition, or chain it behind something that does cross a boundary. Submitting it as-is is a by-design close and it costs you credibility for the next report.

`--class` adds the MITRE ATT&CK technique. `references/windows-boundaries.md` has the full reasoning, the edge-case arguments, and severity anchors that survive triage.

---

## The hunt ledger

A long audit dies from forgetting, not from lack of ideas.

```bash
./scripts/hunt_state.py init --loot loot/acme --target "Acme Desktop 4.2"
./scripts/hunt_state.py add  --loot loot/acme --engine dll-hijack \
  --hypothesis "AcmeSvc (SYSTEM) loads phantom wintls.dll from its install dir" \
  --evidence "dll_hijack.md:12" --test "icacls; Procmon NAME NOT FOUND; proxy dll; capture token" \
  --boundary user-to-system --impact 8 --reach 0.6 --dup 0.2 --conf 0.4
./scripts/hunt_state.py next --loot loot/acme      # highest expected value, right now
./scripts/hunt_state.py set  --loot loot/acme --id H3 --status refuted --note "ships in System32"
```

```
EV = impact × reachability × (1 − dup) × confidence × boundary_weight
```

The boundary weight keeps it honest: a beautiful admin→SYSTEM trick scores near zero, which is the correct answer. **Refutations are first-class rows** — a recorded dead end is what stops you walking it twice.

---

## Self-measurement

```bash
./scripts/corpus_check.py          # builds the range if needed, runs both trees
./scripts/corpus_check.py --keep   # keep the loot directories for inspection
```

`selftest/make_range.py` generates two application trees — identical in shape, one vulnerable and one hardened — including **mingw-compiled PE binaries** with real imports, a real RPC server interface structure, a phantom DLL import, elevation manifests, a jar with a Log4Shell class, COM registrations, native messaging manifests, scheduled task XML and AppX manifests.

70 cases run against both. Detection is scored on the vulnerable tree, false positives on the hardened twin. Surface-*enumeration* cases (recovering a service name, a URI scheme, a pipe) are expected to fire on both and are excluded from the FP score; only cases that assert a **weakness** count.

If you change an engine, re-run this. A regression shows up in one command.

---

## Repository layout

```
SKILL.md              the skill definition Claude Code loads (frontmatter + full methodology)
README.md             this file
install.sh            installer for a fresh machine
scripts/              32 Python engines + 5 shell drivers; each runs standalone with --loot
frida/                7 Windows instrumentation scripts for the VM
ghidra_scripts/       WHDecompile.java — headless decompilation of flagged functions
references/           the domain knowledge the skill reasons with (4 documents, 21 playbooks)
rules/                15-rule YARA pack for Windows-app audit signals
poc_templates/        13 rendered PoC sources (also emitted targeted by poc_gen.py)
agents/               the brief handed to a subagent working one surface
scope/                authorization: targets, hosts, actions, ROE, VM declaration — all EMPTY
selftest/             make_range.py (the twin range) + fetch_fixtures.sh (third-party samples)
campaigns/            portfolio-mode notes
loot/                 per-target output (gitignored)
.venv/  vendor/       provisioned, never committed
```

### The reference documents

| file | when to read it |
|---|---|
| `references/windows-boundaries.md` | before scoring anything — the MSRC boundary list, edge-case arguments, severity anchors |
| `references/class-playbooks.md` | 21 per-class hunting recipes: LPE, DLL hijack, pipes/RPC/COM, URI handlers, localhost, update channels, .NET, Electron, drivers, installers, secrets, supply chain, COM registration, native messaging, OS hooks, fuzzing, dedup, RPC/ALPC, races, primitive conversion, credential storage |
| `references/no-vm-lane.md` | when preflight says there is no Windows VM |
| `references/hunt-memory.md` | what worked and what duplicated, across engagements — append to it at the end of every hunt |

---

## Extending it

### Add an engine

1. Write `scripts/my_engine.py` taking `--loot <dir>`, reading the earlier stages' `.json`, writing `my_engine.json` + `my_engine.md`.
2. Add a stage line to `scripts/hunt.sh`.
3. If it produces exploitable weaknesses, add edges in `scripts/chain.py` so they compose.
4. **Add corpus cases** — one that must fire on the vulnerable tree, and confirm it does not fire on the hardened one.
5. Re-run `corpus_check.py`.

### Add a corpus case

In `scripts/corpus_check.py`:

```python
('ABC-1', 'human-readable description', 'my_engine.json',
 lambda d: any(f['kind'] == 'THE-THING' for f in d.get('findings', []))),
```

If the case is surface *enumeration* rather than a weakness claim, add its id to the `ENUMERATION` set so it is excluded from the false-positive score.

Plant the corresponding weakness in `selftest/make_range.py` under the vulnerable branch, and the correct control under the hardened branch.

### House style for engine output

Every finding carries: **what** (the observation), **why it matters** (the mechanism, in the report's own words), **how to verify** (the single cheapest next step), and **evidence** (a path, a line, an address). A finding a triager cannot replay is not finished.

---

## Design notes

Things that were non-obvious, cost real debugging time, and are worth knowing before you modify the code.

**Call-site analysis beats string heuristics.** Three engines read real argument values rather than grepping:

* A **linear capstone sweep** of `.text` desynchronises on the first data-in-code island and then silently reports **zero** call sites on a binary full of them — which reads like a clean result. These engines byte-scan for call encodings instead, which cannot desynchronise.
* Three call forms must all be handled: `E8 rel32`, `FF 15 rel32` (MSVC → IAT), and **`48 8B 05 rel32` + `FF D0`** — GCC/mingw loads the import into `rax` and calls the register, so no call instruction names the IAT at all. mingw also emits `jmp [iat]` thunks.
* When decoding backwards from a call, take the **longest** in-phase window. The shortest decodes cleanly but contains only the instruction before the call, which is never where the arguments were set.
* `mov ecx, 0` zeroes `rcx` just like `xor ecx, ecx`.

**radare2 quirks** in `native_sinks.py`: `#` starts a comment and `@@` is the iterator, so marker commands must avoid both (`?e MARKAPI x`). Import xref flags are `sym.imp.<LIB.dll>_<Func>`, built from the `is` row's last two columns.

**capa refuses to run without FLIRT signatures.** The provisioner fetches them from the capa repository's `sigs` directory via the GitHub contents API.

**The .NET lane is pure Python** (`dnfile` + `dncil`). In dnfile 0.18, `TypeDef.MethodList` resolves to a *list of rows*, so methods map to their owning type by `id(row)`, not by index arithmetic.

**`msiinfo export` writes binary streams into a CWD-relative directory** — always invoke it with `cwd` set to the destination.

**The secrets engine is one combined regex pass.** Twenty-four separate passes over multi-MB blobs took minutes. A generic container pattern (a config `<add>`, a JSON field) wins the alternation simply by starting earlier in the line, so matched values are re-tested against the high-confidence formats and reclassified — "GitHub token" is worth far more to a triager than "config appSetting".

**Real installers ship malformed JSON** — comments, trailing commas, unescaped Windows paths. A strict parse failure silently loses the finding, so the JSON-reading engines fall back to a lenient parse and then to regex extraction.

**The twin range earns its keep.** Two engine bugs were caught only because a case fired on the *hardened* tree: `runFullTrust` counted as a restricted AppX capability (it is how every packaged Win32 app ships), and `chrome-extension://` scraped from a native-messaging manifest was treated as a product URI handler — manufacturing a web→local chain out of nothing.

---

## Troubleshooting

| symptom | cause / fix |
|---|---|
| `scope_gate: ... REFUSED` | the target is not authorized. That is the design. Add it to `scope/authorized_targets.txt` — only with real authorization. |
| `preflight: N required missing` | run `scripts/provision.sh` |
| capa errors about signatures | `scripts/provision.sh --tier analysis` fetches the FLIRT signatures |
| `dotnet_il` finds 0 assemblies | the target has no managed code, or `provision.sh --tier dotnet` has not run |
| `native_sinks` is slow | it is the heavy stage. Use `--fast` to skip it, or `--top 3` to narrow it |
| `ghidra_decompile: analyzeHeadless not found` | `apt install ghidra`, or put `analyzeHeadless` on `PATH` |
| Generated PowerShell will not parse | install `pwsh` and the corpus will syntax-check it for you |
| `UNAUTHORIZED-TARGET` on a relative path | `hunt.sh` canonicalises paths before the gate; call the gate with an absolute path if you invoke it directly |
| NVD lookups are slow | NVD rate-limits keyless clients to ~5 requests / 30s. `dedup_oracle.py` sleeps accordingly |

---

## Responsible use

This is an offensive security toolkit. Use it only on software you own, wrote, or are explicitly authorized to test — your own product, or a bug bounty program that lists it in scope.

* The scope gate fails closed. Do not edit around it.
* Installers execute code. Run them only in a disposable VM you own.
* Dynamic testing uses your own machine and your own accounts. Never a customer's production host, never a third party's machine.
* No destructive actions, no DoS, no mass scanning, no touching real user data.
* Every PoC template here proves a boundary crossing and stops. Keep it that way.
* Report findings through the vendor's disclosure process or the program that authorized the test.

The authors accept no responsibility for use outside those limits.

---

## Credits

Built by **Nipun Dilshan**.

Standing on: [capa](https://github.com/mandiant/capa) and its rule set, [FLOSS](https://github.com/mandiant/flare-floss), [dnfile](https://github.com/malwarefrank/dnfile) / [dncil](https://github.com/mandiant/dncil), [pefile](https://github.com/erocarrera/pefile), [LIEF](https://lief.re/), [Capstone](https://www.capstone-engine.org/), [radare2](https://rada.re/), [Ghidra](https://ghidra-sre.org/), [signify](https://github.com/ralphje/signify), [msitools](https://wiki.gnome.org/msitools), [innoextract](https://constexpr.org/innoextract/), [YARA](https://virustotal.github.io/yara/), [Frida](https://frida.re/), [OSV](https://osv.dev/), [NVD](https://nvd.nist.gov/), and [signature-base](https://github.com/Neo23x0/signature-base).

The Windows privilege-boundary methodology owes a great deal to the published research of **James Forshaw** (NtObjectManager, symboliclink-testing-tools, the RPC and COM work) and to Microsoft's own [security servicing criteria](https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria), which is the only widely agreed answer to "is this a vulnerability or is it Tuesday".

## License

[MIT](LICENSE) — Copyright (c) 2026 Nipun Dilshan.

Two things the license does not cover, and that you should know before redistributing:

* **The rule sets fetched at provisioning time are not redistributed here.** `scripts/provision.sh`
  clones [capa-rules](https://github.com/mandiant/capa-rules) and
  [signature-base](https://github.com/Neo23x0/signature-base) and downloads capa's FLIRT
  signatures into `vendor/`, which is gitignored. Those projects carry their own licenses
  (Apache-2.0 and CC BY-NC 4.0 respectively at the time of writing) — check them before you
  bundle or ship anything derived from them.
* **`selftest/fetch_fixtures.sh` downloads third-party installers** from their vendors for
  smoke-testing the parsers. They are not part of this repository and are not covered by this
  license.

The MIT license also does not grant permission to test software you are not authorized to test.
See [Responsible use](#responsible-use).
