/* win_registry.js — registry writes, with the ones that matter flagged. */
function W(p) { try { return p.isNull() ? '(null)' : p.readUtf16String(); } catch (e) { return '?'; } }
const HOT = new RegExp(
  ['currentversion\\\\run', 'currentcontrolset\\\\services', 'appinit_dlls', 'appcertdlls',
   'image file execution options', 'winlogon', '\\blsa\\b', 'shellex', 'clsid', 'appid',
   'print\\\\monitors', 'print\\\\providers', 'session manager\\\\environment',
   'shelliconoverlayidentifiers', 'credential providers', 'windows error reporting'].join('|'),
  'i');

['RegCreateKeyExW', 'RegOpenKeyExW'].forEach(function (fn) {
  const p = Module.findExportByName('advapi32.dll', fn);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter(args) {
      const sub = W(args[1]);
      const hive = args[0].toUInt32() === 0x80000002 ? 'HKLM' :
                   args[0].toUInt32() === 0x80000001 ? 'HKCU' :
                   args[0].toUInt32() === 0x80000000 ? 'HKCR' : '0x' + args[0].toString(16);
      if (sub && sub !== '(null)') {
        const hot = HOT.test(sub);
        console.log(`${hot ? '[!]' : '[ ]'} ${fn} ${hive}\\${sub}`);
        if (hot) console.log('    ^ this key changes what OTHER processes load or run');
      }
    }
  });
});

const rsv = Module.findExportByName('advapi32.dll', 'RegSetValueExW');
if (rsv) Interceptor.attach(rsv, {
  onEnter(args) {
    const name = W(args[0 + 1]);
    const type = args[3].toUInt32();
    let data = '(binary)';
    try {
      if (type === 1 || type === 2) data = args[4].readUtf16String();
      else if (type === 4) data = args[4].readU32();
    } catch (e) {}
    console.log(`[*] RegSetValueEx "${name}" type=${type} = ${data}`);
  }
});

console.log('[win_registry] hooked.');
