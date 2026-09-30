# Subagent brief — one surface, worked exhaustively

You are hunting **one partition** of a Windows application's attack surface. Another agent has
the others; do not wander into theirs, and do not re-derive the intake.

## Your inputs

- `loot/<name>/unwrap.md` — what the target is and what came out of it
- `loot/<name>/surface.md` — the full boundary map (yours is one section of it)
- `loot/<name>/pe_triage.json` — per-binary facts
- your partition, one of:
  1. **services + installer** — services, accounts, MSI custom actions, scheduled tasks, ACL intent
  2. **IPC** — named pipes, RPC, COM/DCOM, ALPC, shared memory
  3. **web-facing** — URI handlers, file associations, localhost listeners, Electron/CEF/WebView2
  4. **managed code** — every .NET assembly, IL sinks, deserialization, dynamic load
  5. **native + kernel** — native binaries, capa/r2, drivers and IOCTL surface
  6. **supply chain + secrets** — bundled components, CVE exposure, credentials, crypto

## Your job

For every row in your partition, answer the three questions and record the answer:

1. Who is on the other side of this boundary?
2. At what privilege does this side run?
3. What can the other side make this side do?

Then, for anything that survives those three, add a ledger row:

```bash
scripts/hunt_state.py add --loot <loot> --engine <partition> \
  --hypothesis "<attacker position> can <action> because <mechanism>, resulting in <impact>" \
  --evidence "<file:line or artifact>" --test "<the single cheapest step that would settle it>" \
  --boundary <see references/windows-boundaries.md> --impact N --reach N --dup N --conf N
```

## Rules

- **A refutation is a result.** Record it with the reason. Returning "nothing here, and here is
  why" is a successful run.
- Do not report KnownDLLs, API sets, missing ASLR on unprivileged helpers, or an updater that
  merely exists. Read `references/class-playbooks.md` for what your class actually reports.
- Do not run anything. Static analysis only unless `scope/authorized_actions.txt` says otherwise
  and the operator asked.
- Cite evidence by path and line. A claim without a citation will be dropped at merge.

## Return

- the ledger rows you added (ids)
- the one highest-EV lead in your partition, in the summary sentence shape
- what you could not settle statically, and the exact runbook check that would settle it
