/* win_fileops.js — every file operation, with the ones that matter flagged.
 *
 * The TOCTOU/LPE question is never "does it open files" — it is "does a privileged process
 * open a path a standard user controls, and what does it do between checking and using it".
 * This prints the path, the disposition, the reparse flag, and a stack for the flagged ones.
 */
const WRITABLE = /programdata|\\users\\public|\\public\\|\\windows\\temp|\\temp\\|appdata|localappdata/i;
const seen = new Set();

function W(p) { try { return p.isNull() ? '(null)' : p.readUtf16String(); } catch (e) { return '?'; } }
function A(p) { try { return p.isNull() ? '(null)' : p.readAnsiString(); } catch (e) { return '?'; } }

function stack(ctx) {
  try {
    return Thread.backtrace(ctx, Backtracer.ACCURATE)
      .slice(0, 8).map(DebugSymbol.fromAddress).map(s => '    ' + s).join('\n');
  } catch (e) { return '    (no stack)'; }
}

function flag(path, what, ctx) {
  if (!path || path === '?' ) return;
  const hot = WRITABLE.test(path);
  const key = what + '|' + path;
  if (!hot && seen.has(key)) return;
  seen.add(key);
  if (hot) {
    console.log(`\n[!] ${what}  ${path}`);
    console.log('    ^ USER-WRITABLE LOCATION — this is the shape an LPE needs');
    console.log(stack(ctx));
  } else {
    console.log(`[ ] ${what}  ${path}`);
  }
}

// --- CreateFile: disposition + reparse flag decide the symlink story -------------------
const DISP = { 1: 'CREATE_NEW', 2: 'CREATE_ALWAYS', 3: 'OPEN_EXISTING', 4: 'OPEN_ALWAYS', 5: 'TRUNCATE' };
['CreateFileW', 'CreateFileA'].forEach(function (fn) {
  const p = Module.findExportByName('kernel32.dll', fn);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter(args) {
      this.path = fn.endsWith('W') ? W(args[0]) : A(args[0]);
      this.disp = DISP[args[4].toInt32()] || args[4].toInt32();
      this.flags = args[5].toUInt32();
      this.write = (args[1].toUInt32() & 0x40000000) !== 0;   // GENERIC_WRITE
      this.reparse = (this.flags & 0x00200000) !== 0;         // FILE_FLAG_OPEN_REPARSE_POINT
    },
    onLeave(ret) {
      const bad = ret.toInt32() === -1;
      let what = `CreateFile ${this.disp}${this.write ? ' WRITE' : ''}` +
                 `${this.reparse ? '' : ' [follows reparse points]'}${bad ? ' FAILED' : ''}`;
      flag(this.path, what, this.context);
    }
  });
});

// --- the move/delete/copy family: the arbitrary-write and arbitrary-delete primitives ----
[['MoveFileExW', 2], ['MoveFileW', 2], ['DeleteFileW', 1], ['CopyFileW', 2],
 ['ReplaceFileW', 2], ['RemoveDirectoryW', 1], ['CreateDirectoryW', 1]].forEach(function (e) {
  const p = Module.findExportByName('kernel32.dll', e[0]);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter(args) {
      const a = W(args[0]);
      const b = e[1] > 1 ? W(args[1]) : null;
      flag(a, e[0] + (b ? ` -> ${b}` : ''), this.context);
      if (e[0] === 'MoveFileExW' && (args[2].toUInt32() & 4)) {
        console.log('    ^ MOVEFILE_DELAY_UNTIL_REBOOT — this becomes a SYSTEM write at boot');
      }
    }
  });
});

// --- temp paths: predictable names in a shared directory ---------------------------------
['GetTempPathW', 'GetTempFileNameW'].forEach(function (fn) {
  const p = Module.findExportByName('kernel32.dll', fn);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter(args) { this.out = fn === 'GetTempPathW' ? args[1] : args[3]; },
    onLeave() {
      const v = W(this.out);
      console.log(`[!] ${fn} -> ${v}`);
      if (/windows\\temp/i.test(v || '')) {
        console.log('    ^ C:\\Windows\\Temp: every user can CREATE files here. Predictable names '
                    + 'plus create permission is a classic LPE.');
      }
    }
  });
});

console.log('[win_fileops] hooked. [!] = worth reading, [ ] = noise.');
