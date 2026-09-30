# Windows security boundaries — what is reportable and how to argue it

Microsoft publishes which boundaries it defends. Most vendors, most bug bounty programs and most
triage teams follow the same list, because it is the only widely agreed answer to "is this a
vulnerability or is it Tuesday". Learn it once and you stop losing reports.

## Defended boundaries (report these)

| boundary | meaning | typical severity |
|---|---|---|
| **standard user → admin / SYSTEM** | any non-admin local account gains admin or SYSTEM | High (7.8 is the canonical LPE score) |
| **service account → SYSTEM** | LocalService / NetworkService / a custom low-priv account gains SYSTEM | High |
| **AppContainer / low-IL → medium+** | sandbox escape | High–Critical |
| **user A → user B** | one interactive user reads or acts as another | High |
| **remote unauthenticated → local code** | network input reaches execution | Critical |
| **web origin → local application** | a page the user visits reaches the app (URI handler, localhost listener, file association, Electron renderer) | High–Critical, and usually one-click |
| **update channel → code execution** | a network/mirror/DNS attacker gets the updater to run their package | Critical |
| **network position → app** | missing TLS validation, cleartext transport carrying anything that matters | High |
| **untrusted file → code execution** | opening a document/archive/image runs code | High |
| **guest VM → host** | hypervisor escape | Critical |

## NOT boundaries (do not submit these alone)

| non-boundary | why | what to do instead |
|---|---|---|
| **admin → SYSTEM / kernel** | an administrator is already fully trusted on the machine | find the same primitive reachable as a standard user |
| **UAC bypass at the default level** | UAC is a convenience feature, explicitly not a boundary | only relevant if it is *part of* a standard-user chain |
| **anything needing the attacker to already be admin** | the precondition is the compromise | rework the precondition |
| **AV / EDR / ASLR / CFG bypass with no bug** | a mitigation being bypassable is not itself a vulnerability | pair it with the memory-corruption bug it enables |
| **physical access to an unlocked machine** | out of the threat model for almost everything | unless the product *claims* to defend it (disk encryption, kiosk mode, DLP) — then it is in scope, say so |
| **"the installer writes to a directory admins can write to"** | that is what admins are | check whether *non*-admins can write |
| **code running as the user affecting that same user** | no boundary crossed | only usable as a link inside a chain |

## Arguing the edge cases

**"The service runs as the logged-on user, not SYSTEM."** Then it is not an LPE. But if two
users share the machine (terminal server, shared workstation, a family PC), user A reaching
user B's session *is* a boundary. Say which model you are claiming.

**"It requires the app to be installed to a non-default path."** Severity drops but it is not
dead. State how the non-default path arises — an enterprise deployment script, a per-user
install, an older version's default. If the vendor's own documentation suggests it, say so.

**"It requires the user to click something."** One click on an attacker-supplied link is widely
accepted and barely reduces severity for web-to-local. Requiring the user to install a second
application, or to type a command, usually kills it.

**"UAC is on by default, so the attacker is an admin already."** This is the argument that closes
the most reports. Pre-empt it: demonstrate from a **standard user account** — create one, log in,
and run the PoC there. A PoC recorded from an admin session invites the close.

**"The product is only used by administrators."** Vendors say this a lot. Counter with the actual
install: does it install for all users? Does it run at boot? Is there a standard-user-facing
component (a tray app, a browser extension, an updater)? If yes, the boundary exists regardless
of who the vendor imagines the user is.

## Severity anchors that survive triage

| finding | typical outcome |
|---|---|
| unquoted service path + writable intermediate directory, SYSTEM service | High 7.8 |
| phantom DLL in a SYSTEM service's directory, directory writable by Users | High 7.8 |
| service DACL grants Users `SERVICE_CHANGE_CONFIG` | High 7.8 |
| SYSTEM process reads config/plugins from writable `ProgramData` | High 7.8 |
| updater accepts an unsigned or wrongly-signed package | Critical 9.8 (remote) / High (local mirror) |
| updater over cleartext HTTP with no signature check | Critical |
| custom URI handler with unquoted `%1` reaching Chromium/Node flags | High 8.8, one-click |
| localhost API with no Origin check performing privileged actions | High 8.8 |
| localhost API with no Origin check leaking data only | Medium–High |
| Electron `nodeIntegration:true` on a window that can load remote content | Critical |
| BinaryFormatter on attacker-controlled data | Critical 9.8 |
| hardcoded cloud credential with production access | Critical |
| hardcoded third-party key, free tier, no user data | Low / informative |
| arbitrary file delete as SYSTEM | High (it is a known-good LPE primitive) |
| kernel driver IOCTL reachable by any user, no probing, `METHOD_NEITHER` | Critical |
| bundled library with a known CVE, **reachable input path shown** | matches the CVE |
| bundled library with a known CVE, reachability not shown | Low / informative — expect it |
