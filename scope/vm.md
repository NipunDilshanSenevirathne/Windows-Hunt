# Windows test VM

Declare a VM here and `preflight.sh` switches from the no-VM lane to the full lane. Leave it
as-is and the no-VM lane stays active (see `references/no-vm-lane.md`).

Uncomment and fill in whichever access method exists:

```
# host:  192.168.122.50
# ssh:   tester@192.168.122.50
# winrm: https://192.168.122.50:5986
# rdp:   192.168.122.50:3389
```

## Requirements for the VM to be useful

- **Disposable.** Snapshot it clean before installing the target; revert between tests.
- **Not domain-joined**, unless the finding needs a domain — then say so in the report.
- **A standard (non-admin) user account exists and is used for testing.** This is the attacker's
  position. Results captured from an elevated session are not evidence of an LPE.
- Sysinternals installed: Procmon, Process Explorer, accesschk, pipelist, Autoruns.
- Optional: WinDbg (required before fuzzing any kernel driver), x64dbg, Frida for Windows.

## What the VM is for

Confirming the questions in `loot/<name>/runbook/verify.ps1`, then running PoCs from
`scripts/poc_gen.py`. Nothing in this skill runs the target automatically — every execution is
an explicit, `authorized_actions.txt`-gated step the operator takes.
