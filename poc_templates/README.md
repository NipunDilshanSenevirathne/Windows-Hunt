# PoC templates

Reference copies, rendered with placeholder values. Generate a targeted one instead:

```bash
scripts/poc_gen.py --list
scripts/poc_gen.py --kind proxy-dll --out loot/<name>/poc --dll wintls.dll --loader AcmeSvc.exe
x86_64-w64-mingw32-gcc -shared -o wintls.dll loot/<name>/poc/poc.c     # real PE, built on Linux
```

Every template proves the boundary crossing and nothing else — it writes a file containing the
token the code ran under. Run them only in a VM you own, and only when
`scope/authorized_actions.txt` grants the matching verb.
