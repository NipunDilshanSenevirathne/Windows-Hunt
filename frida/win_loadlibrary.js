/* win_loadlibrary.js — confirm a phantom/side-load candidate at runtime.
 *
 * dll_hijack.md predicts which DLLs the loader will look for and not find. This shows the
 * truth: every LoadLibrary attempt, the resolved path, and whether it failed.
 */
function W(p) { try { return p.isNull() ? '(null)' : p.readUtf16String(); } catch (e) { return '?'; } }
function A(p) { try { return p.isNull() ? '(null)' : p.readAnsiString(); } catch (e) { return '?'; } }

[['LoadLibraryW', W], ['LoadLibraryA', A], ['LoadLibraryExW', W], ['LoadLibraryExA', A]]
.forEach(function (e) {
  const p = Module.findExportByName('kernel32.dll', e[0]);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter(args) { this.name = e[1](args[0]); },
    onLeave(ret) {
      const ok = !ret.isNull();
      let resolved = '';
      if (ok) {
        try { const m = Process.findModuleByAddress(ret); resolved = m ? m.path : ''; } catch (err) {}
      }
      const rel = this.name && !/[\\/]|^[A-Za-z]:/.test(this.name);
      console.log(`${ok ? '[+]' : '[!]'} ${e[0]}("${this.name}")` +
                  (ok ? ` -> ${resolved}` : '  FAILED (this is a PHANTOM — drop a DLL here)') +
                  (rel ? '   [relative name: resolved through the SEARCH ORDER]' : ''));
    }
  });
});

const sdd = Module.findExportByName('kernel32.dll', 'SetDefaultDllDirectories');
if (sdd) Interceptor.attach(sdd, {
  onEnter(args) {
    console.log(`[+] SetDefaultDllDirectories(0x${args[0].toUInt32().toString(16)}) — hardening present.`);
    console.log('    Check WHEN: if it runs after an early load, the early load is still hijackable.');
  }
});
const sdl = Module.findExportByName('kernel32.dll', 'SetDllDirectoryW');
if (sdl) Interceptor.attach(sdl, { onEnter(args) { console.log(`[*] SetDllDirectoryW("${W(args[0])}")`); } });

console.log('[win_loadlibrary] hooked. [!] lines are your hijack candidates, confirmed live.');
