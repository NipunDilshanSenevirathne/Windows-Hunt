# Rules of Engagement — NO ENGAGEMENT OPEN

Fill this in at Phase 0, before touching the target. The gates in `authorized_targets.txt`,
`authorized_hosts.txt` and `authorized_actions.txt` enforce what this document declares.

## Intake

Product / version:      <name, version, build>
Target artifact(s):     <path(s)>
SHA-256:                <per artifact — record it before anything modifies the file>
Source:                 <vendor download URL / customer-supplied / store>
Platform:               Windows <versions in scope>
Program:                <bug bounty program + URL, or "direct written authorization">
Authorization basis:    <policy URL, contract, written permission, or the operator's statement>
Environment:            <production build / internal build / staging>
Severity cap:           <if the program states one>
Test accounts:          <supplied, or self-registered throwaway only>
Backend hosts:          -> authorized_hosts.txt (only hosts the binary demonstrably contacts,
                        confirmed first-party, and in the program's scope)
Windows VM:             -> scope/vm.md (declare it, or the no-VM lane applies)
Excluded classes:       <paste the program's out-of-scope list VERBATIM; deny wins>

## Standing rules

- The scope gate fails closed and is not to be edited around. `deny` always beats `allow`.
- **An installer is executable code.** It is never run outside a disposable VM the operator
  owns, from a clean snapshot, reverted between tests.
- Dynamic testing uses the operator's own machine and the operator's own accounts. Never a
  customer's production host, never a third party's machine.
- No destructive actions, no DoS, no mass scanning, no touching real user data.
- Live requests only to hosts in `authorized_hosts.txt`. Tooling downloads (pypi, github, OSV)
  are provisioning, not engagement traffic, and are governed by `scripts/provision.sh`.
- UAC is not a security boundary. Admin→SYSTEM alone is not reported.
- Findings are reproduced with an artifact before they are written up. Leads are labelled leads.
- Every hypothesis — confirmed or refuted — goes in the ledger.
