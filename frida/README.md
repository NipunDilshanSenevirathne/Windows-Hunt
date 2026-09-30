# Frida scripts for Windows

Dynamic instrumentation for the operator's own VM. These answer, at runtime, the questions the
static engines can only flag: **which path does it really open, under which token, and does the
check it appears to perform actually change anything?**

```powershell
# in the VM (frida-tools installed, matching bitness)
pip install frida-tools
frida -f "C:\Program Files\Acme\AcmeSvc.exe" -l win_fileops.js --no-pause
frida -n AcmeSvc.exe -l win_ipc.js                # attach to a running service (needs admin)
frida -p 1234 -l win_verify.js
```

Attaching to a **service** needs an elevated Frida. That is fine — you are observing the
privileged side; the *attack* still has to be demonstrated from a standard-user context.

| script | answers |
|---|---|
| `win_fileops.js` | every file path touched, flagged when it is in a user-writable location; catches the TOCTOU shapes `toctou_audit.py` predicts |
| `win_process.js` | full command lines, `lpApplicationName == NULL`, `bInheritHandles`, environment blocks |
| `win_ipc.js` | pipe creation with its DACL, connections, **impersonation vs revert pairing**, COM activations |
| `win_registry.js` | key/value writes with data, flagged for HKLM and autorun locations |
| `win_crypto.js` | DPAPI scope, symmetric keys and IVs **dumped as hex** — this is how you recover a hardcoded key |
| `win_verify.js` | `WinVerifyTrust` calls, and `--flip` mode: force the result to success to prove whether the product's signature check is load-bearing |
| `win_loadlibrary.js` | every `LoadLibrary` with the resolved path — confirms phantom/side-load candidates live |

Every script prints a **call stack** for the interesting cases, so you can map a runtime event
back to the function `ghidra_decompile.py` decompiled.

`scope/authorized_actions.txt` must grant `dynamic-trace` (and `debug-attach` for `--flip`).
