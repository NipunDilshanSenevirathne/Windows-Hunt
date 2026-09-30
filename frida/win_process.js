/* win_process.js — every process the product creates, exactly as the OS sees it.
 *
 * Catches: unquoted command lines (lpApplicationName == NULL), handle inheritance, the
 * environment block handed to a privileged child, and ShellExecute verb resolution.
 */
function W(p) { try { return p.isNull() ? null : p.readUtf16String(); } catch (e) { return '?'; } }
function stack(ctx) {
  try {
    return Thread.backtrace(ctx, Backtracer.ACCURATE).slice(0, 6)
      .map(DebugSymbol.fromAddress).map(s => '    ' + s).join('\n');
  } catch (e) { return '    (no stack)'; }
}

['CreateProcessW', 'CreateProcessAsUserW', 'CreateProcessWithTokenW',
 'CreateProcessWithLogonW'].forEach(function (fn) {
  const p = Module.findExportByName('kernel32.dll', fn) ||
            Module.findExportByName('advapi32.dll', fn);
  if (!p) return;
  const shift = fn === 'CreateProcessW' ? 0 : (fn === 'CreateProcessAsUserW' ? 1 : 2);
  Interceptor.attach(p, {
    onEnter(args) {
      const app = W(args[0 + shift]);
      const cmd = W(args[1 + shift]);
      const inherit = args[4 + shift].toInt32();
      console.log(`\n[*] ${fn}`);
      console.log(`    lpApplicationName : ${app === null ? 'NULL' : app}`);
      console.log(`    lpCommandLine     : ${cmd}`);
      console.log(`    bInheritHandles   : ${inherit}`);
      if (app === null && cmd && / /.test(cmd) && !/^\s*"/.test(cmd)) {
        console.log('    *** UNQUOTED COMMAND LINE with NULL lpApplicationName.');
        console.log('        The loader will try each space-separated prefix in turn:');
        const m = cmd.match(/^([A-Za-z]:\\[^"]*?\.exe)/);
        if (m) {
          const parts = m[1].split(' ');
          let acc = '';
          for (let i = 0; i < parts.length - 1; i++) {
            acc += (i ? ' ' : '') + parts[i];
            console.log(`          ${acc}.exe`);
          }
        }
      }
      if (inherit) console.log('    *** bInheritHandles=TRUE — the child gets every inheritable handle');
      console.log(stack(this.context));
    }
  });
});

['ShellExecuteW', 'ShellExecuteExW'].forEach(function (fn) {
  const p = Module.findExportByName('shell32.dll', fn);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter(args) {
      if (fn === 'ShellExecuteW') {
        console.log(`\n[*] ShellExecuteW verb=${W(args[1])} file=${W(args[2])} params=${W(args[3])}`);
      } else {
        try {
          console.log(`\n[*] ShellExecuteExW verb=${W(args[0].add(Process.pointerSize * 3))} ` +
                      `file=${W(args[0].add(Process.pointerSize * 4))}`);
        } catch (e) { console.log('[*] ShellExecuteExW'); }
      }
      console.log('    ^ the target is resolved through the registry; HKCU associations are user-writable');
      console.log(stack(this.context));
    }
  });
});

const ge = Module.findExportByName('kernel32.dll', 'GetEnvironmentVariableW');
if (ge) Interceptor.attach(ge, {
  onEnter(args) {
    const n = W(args[0]);
    if (/^(PATH|NODE_OPTIONS|PYTHONPATH|CLASSPATH|COR_PROFILER|COR_ENABLE_PROFILING|DOTNET_STARTUP_HOOKS|ELECTRON_RUN_AS_NODE|_NT_SYMBOL_PATH)$/i.test(n || '')) {
      console.log(`[!] reads env ${n} — a code-execution vector if the caller's environment is influenceable`);
    }
  }
});

console.log('[win_process] hooked.');
