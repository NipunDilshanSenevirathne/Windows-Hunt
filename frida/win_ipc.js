/* win_ipc.js — pipes, impersonation and COM activation.
 *
 * The two questions this settles:
 *   1. what DACL does the server put on its pipe? (a NULL DACL means every user can connect)
 *   2. does it impersonate the caller before acting — on EVERY path, including errors?
 */
function W(p) { try { return p.isNull() ? '(null)' : p.readUtf16String(); } catch (e) { return '?'; } }
let imp = 0, rev = 0;

const cnp = Module.findExportByName('kernel32.dll', 'CreateNamedPipeW');
if (cnp) Interceptor.attach(cnp, {
  onEnter(args) {
    this.name = W(args[0]);
    this.sa = args[7];
  },
  onLeave() {
    console.log(`\n[*] CreateNamedPipe ${this.name}`);
    if (this.sa.isNull()) {
      console.log('    lpSecurityAttributes = NULL -> the pipe gets the DEFAULT DACL for the');
      console.log('    creating token. For a SYSTEM service that is usually SYSTEM+Administrators,');
      console.log('    which is fine. Confirm with: (Get-Acl \\\\.\\pipe\\<name>).Sddl');
    } else {
      try {
        const sd = this.sa.add(Process.pointerSize).readPointer();
        console.log(`    explicit security descriptor at ${sd}`);
        const f = Module.findExportByName('advapi32.dll',
                  'ConvertSecurityDescriptorToStringSecurityDescriptorW');
        if (f && !sd.isNull()) {
          const out = Memory.alloc(Process.pointerSize);
          const fn = new NativeFunction(f, 'int', ['pointer', 'uint32', 'uint32', 'pointer', 'pointer']);
          if (fn(sd, 1, 0xF, out, NULL)) {
            const s = W(out.readPointer());
            console.log(`    SDDL: ${s}`);
            if (/\(A;[^)]*;;;(WD|AU|BU|IU)\)/.test(s || '')) {
              console.log('    *** grants access to Everyone/Users/Authenticated Users —');
              console.log('        any logged-on user can connect to this pipe.');
            }
          }
        }
      } catch (e) { console.log('    (could not decode the SD: ' + e + ')'); }
    }
  }
});

['ImpersonateNamedPipeClient', 'ImpersonateLoggedOnUser', 'RpcImpersonateClient',
 'CoImpersonateClient', 'SetThreadToken'].forEach(function (fn) {
  const p = Module.findExportByName('advapi32.dll', fn) ||
            Module.findExportByName('rpcrt4.dll', fn) ||
            Module.findExportByName('ole32.dll', fn) ||
            Module.findExportByName('kernel32.dll', fn);
  if (!p) return;
  Interceptor.attach(p, { onLeave() { imp++; console.log(`[+] ${fn}  (impersonations=${imp} reverts=${rev})`); } });
});
['RevertToSelf', 'RpcRevertToSelf', 'CoRevertToSelf'].forEach(function (fn) {
  const p = Module.findExportByName('advapi32.dll', fn) ||
            Module.findExportByName('rpcrt4.dll', fn) ||
            Module.findExportByName('ole32.dll', fn);
  if (!p) return;
  Interceptor.attach(p, { onLeave() { rev++; console.log(`[-] ${fn}  (impersonations=${imp} reverts=${rev})`); } });
});

const cci = Module.findExportByName('ole32.dll', 'CoCreateInstance');
if (cci) Interceptor.attach(cci, {
  onEnter(args) {
    try {
      const g = args[0];
      const d1 = g.readU32(), d2 = g.add(4).readU16(), d3 = g.add(6).readU16();
      const rest = Array.from(g.add(8).readByteArray(8) ? new Uint8Array(g.add(8).readByteArray(8)) : [])
        .map(b => ('0' + b.toString(16)).slice(-2)).join('');
      console.log(`[*] CoCreateInstance {${('00000000'+d1.toString(16)).slice(-8)}-` +
                  `${('0000'+d2.toString(16)).slice(-4)}-${('0000'+d3.toString(16)).slice(-4)}-` +
                  `${rest.slice(0,4)}-${rest.slice(4)}}  ctx=${args[2].toUInt32()}`);
    } catch (e) {}
  }
});

console.log('[win_ipc] hooked. Watch the impersonation/revert counters: if a privileged');
console.log('          operation happens while they are equal, the server acted as ITSELF.');
