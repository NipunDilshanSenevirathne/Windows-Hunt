/* win_verify.js — is the signature check load-bearing?
 *
 * Two modes:
 *   observe (default)  log every WinVerifyTrust call, the file, and the result
 *   --flip             force every verification to SUCCESS
 *
 * The flip is the decisive test for an update channel or a plugin loader. If the product
 * behaves identically with verification forced to success, then either it never checked the
 * result, or the check is the only thing standing between an attacker and code execution —
 * and you have just proved which.
 *
 *   frida -n Acme.exe -l win_verify.js                      # observe
 *   frida -n Acme.exe -l win_verify.js -- --flip            # coerce
 */
const FLIP = (typeof Process !== 'undefined') &&
             (Process.argv || []).some(a => String(a).indexOf('flip') >= 0);

function W(p) { try { return p.isNull() ? '(null)' : p.readUtf16String(); } catch (e) { return '?'; } }

const wvt = Module.findExportByName('wintrust.dll', 'WinVerifyTrust');
if (wvt) {
  Interceptor.attach(wvt, {
    onEnter(args) {
      this.data = args[2];
      try {
        // WINTRUST_DATA.pFile -> WINTRUST_FILE_INFO.pcwszFilePath
        const pFile = this.data.add(Process.pointerSize === 8 ? 24 : 16).readPointer();
        this.file = pFile.isNull() ? '(not a file)' : W(pFile.add(Process.pointerSize).readPointer());
      } catch (e) { this.file = '?'; }
      try {
        const flags = this.data.add(Process.pointerSize === 8 ? 40 : 28).readU32();
        this.revoke = this.data.add(Process.pointerSize === 8 ? 8 : 8).readU32();
      } catch (e) {}
    },
    onLeave(ret) {
      const r = ret.toInt32();
      const name = r === 0 ? 'TRUST_E_OK' :
                   (r >>> 0) === 0x800B0100 ? 'TRUST_E_NOSIGNATURE' :
                   (r >>> 0) === 0x800B0109 ? 'CERT_E_UNTRUSTEDROOT' :
                   (r >>> 0) === 0x80096010 ? 'TRUST_E_BAD_DIGEST' :
                   (r >>> 0) === 0x800B010A ? 'CERT_E_CHAINING' : '0x' + (r >>> 0).toString(16);
      console.log(`[*] WinVerifyTrust("${this.file}") -> ${name}`);
      if (FLIP && r !== 0) {
        ret.replace(ptr(0));
        console.log('    *** FLIPPED to TRUST_E_OK. If the product now proceeds, the signature');
        console.log('        check was the ONLY control on this path.');
      }
    }
  });
  console.log('[win_verify] WinVerifyTrust hooked' + (FLIP ? ' (FLIP MODE — results forced to success)' : ''));
} else {
  console.log('[win_verify] wintrust.dll not loaded yet — start with -f and --no-pause,');
  console.log('             or the product verifies signatures some other way (check signing.md).');
}

const cat = Module.findExportByName('wintrust.dll', 'CryptCATAdminCalcHashFromFileHandle');
if (cat) Interceptor.attach(cat, { onLeave() { console.log('[*] catalog hash computed'); } });

/* .NET path: Authenticode via X509Certificate2 / SignedCms is NOT hooked here — use
   `frida-trace -i "*Verify*"` or read the IL (dotnet_il.md) instead. */
