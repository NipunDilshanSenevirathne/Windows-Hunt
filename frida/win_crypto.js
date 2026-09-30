/* win_crypto.js — recover the keys.
 *
 * The point is not to observe that the product encrypts. It is to DUMP the key material so you
 * can decrypt what it stored, which is what turns "hardcoded key" from a code-quality note into
 * a credential-theft finding.
 */
function hex(p, n) {
  try { return Array.from(new Uint8Array(p.readByteArray(Math.min(n, 64))))
    .map(b => ('0' + b.toString(16)).slice(-2)).join(''); } catch (e) { return '?'; }
}

['CryptProtectData', 'CryptUnprotectData'].forEach(function (fn) {
  const p = Module.findExportByName('crypt32.dll', fn);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter(args) {
      const flags = args[6] ? args[6].toUInt32() : 0;
      console.log(`\n[*] ${fn} flags=0x${flags.toString(16)}`);
      if (flags & 0x4) console.log('    *** CRYPTPROTECT_LOCAL_MACHINE — ANY process on this machine can unprotect it');
      const ent = args[2];
      console.log(`    optional entropy: ${ent.isNull() ? 'NONE (any code as this user can unprotect)' : 'present'}`);
      try {
        const blob = args[0];
        const len = blob.readU32();
        console.log(`    data (${len} bytes): ${hex(blob.add(Process.pointerSize).readPointer(), len)}`);
      } catch (e) {}
    }
  });
});

['BCryptGenerateSymmetricKey', 'BCryptImportKey', 'BCryptImportKeyPair'].forEach(function (fn) {
  const p = Module.findExportByName('bcrypt.dll', fn);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter(args) {
      // BCryptGenerateSymmetricKey(hAlg, phKey, pbKeyObject, cbKeyObject, pbSecret, cbSecret, flags)
      try {
        const secret = args[4], len = args[5].toUInt32();
        console.log(`\n[!] ${fn} KEY (${len} bytes): ${hex(secret, len)}`);
        console.log('    ^ if this is the same on every run and every machine, it is HARDCODED.');
      } catch (e) {}
    }
  });
});

['CryptImportKey', 'CryptDeriveKey', 'CryptSetKeyParam'].forEach(function (fn) {
  const p = Module.findExportByName('advapi32.dll', fn);
  if (!p) return;
  Interceptor.attach(p, {
    onEnter(args) { console.log(`[*] ${fn}`); }
  });
});

const be = Module.findExportByName('bcrypt.dll', 'BCryptEncrypt');
if (be) Interceptor.attach(be, {
  onEnter(args) {
    try {
      const iv = args[4], ivlen = args[5].toUInt32();
      if (!iv.isNull() && ivlen) {
        console.log(`[!] BCryptEncrypt IV (${ivlen}): ${hex(iv, ivlen)}`);
        console.log('    ^ a CONSTANT IV across runs destroys CBC/CTR security');
      }
    } catch (e) {}
  }
});

console.log('[win_crypto] hooked. Run the product twice and diff the key/IV output:');
console.log('             identical bytes across runs = hardcoded.');
