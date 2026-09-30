# Hunt memory — what worked, what duplicated, across engagements

Append one block per engagement, at the end. Read this file at the start of the next one. The
point is to stop re-learning the same lesson and to spot the patterns that repeat across
vendors.

## Template

```
## <product> <version> — <date>
target:      <file(s) + sha256>
lane:        full | no-vm
findings:    <n> (C/H/M/L)
best:        <the one finding worth remembering, in one line>
what found it: <the specific step — not "static analysis", the actual step>
refuted:     <the hypotheses that died, and why — this is the most reusable part>
duplicated:  <what a triager had already seen>
lesson:      <one transferable sentence>
```

## Standing observations

*(These accumulate. Each one started as a single engagement's lesson.)*

- **ProgramData is the default mistake.** If a product has a SYSTEM component and a
  `C:\ProgramData\<name>\` directory, check the relationship between them before anything else.
- **The updater is always worth an hour.** It is the only component whose job is to execute new
  code, and its three controls (transport, manifest, package signature) are rarely all present.
- **Read the preload, not the webPreferences.** Modern Electron apps set the switches correctly
  and then expose a bridge function that takes a path.
- **An unquoted `%1` in a shipped `.reg` is free.** It is a static fact, it is one-click from a
  web page, and the Chromium/Node flag surface behind it is enormous.
- **Refutations compound.** "This pipe requires SYSTEM to open" is worth writing down; the same
  vendor's next product will have the same pipe.
- **Check what the installer sets, not only what it installs.** `LockPermissions` and `icacls`
  in an install script are the vendor telling you where the weak ACL is.
