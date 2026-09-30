#!/usr/bin/env python3
"""
sign_audit.py — Authenticode depth: not "is it signed" but "does the signature mean anything".

`pe_triage.py` answers presence. This answers the questions that actually produce findings:

  * which digest algorithm? SHA-1 Authenticode is not trusted for code signed after 2016 and a
    product still signing with it has a real problem
  * is there a trusted TIMESTAMP? without one the signature dies the day the cert expires
  * is the certificate expired, or expiring inside the support window?
  * is the whole package signed by ONE publisher, or are there third-party and unsigned
    binaries mixed in? every unsigned DLL beside a signed EXE is a hijack and supply-chain
    question
  * are there PAGE HASHES? without them the signature covers the file, not the mapped pages
  * does the product VERIFY signatures itself, and how? `WinVerifyTrust` with
    `WTD_REVOKE_NONE`, or without checking the returned publisher, is a verification that
    proves nothing — this is the root cause behind most "our updater is secure" claims
  * is data appended after the signed region? the Authenticode format leaves the certificate
    table's trailing space unhashed, which is how signed installers get repackaged with a
    payload while keeping a valid signature

Usage:  sign_audit.py --loot loot/<name>
Writes: <loot>/signing.json, <loot>/signing.md
"""
import argparse, json, os, re, shutil, struct, subprocess
from collections import Counter

try:
    import pefile
except ImportError:
    pefile = None

VERIFY_APIS = {
    'WinVerifyTrust': ('the standard signature check — the details decide whether it means '
                       'anything: which action GUID, is revocation checked, and is the resulting '
                       'publisher compared against an expected one?'),
    'WTGetSignatureInfo': ('lighter-weight check; on its own it does not pin the publisher'),
    'CryptCATAdminCalcHashFromFileHandle': ('catalog-based verification'),
    'CertGetCertificateChain': ('chain building — check the policy parameters'),
    'CertVerifyCertificateChainPolicy': ('policy check — the good sign; read which policy'),
    'CryptQueryObject': ('pulls the signer out of a file — usually a prelude to a real check'),
    'CertCompareCertificateName': ('publisher pinning — this is what you want to see'),
    'X509Certificate2': ('.NET certificate handling'),
    'SignedCms': ('.NET CMS verification'),
    'Verify': (''),
}
WEAK_FLAGS = {
    'WTD_REVOKE_NONE': 'revocation checking disabled — a revoked signing cert still passes',
    'WTD_STATEACTION_IGNORE': 'state not retained',
    'WTD_SAFER_FLAG': 'legacy',
    'WTD_HASH_ONLY_FLAG': 'hash compared without validating the chain — proves nothing about who signed it',
    'WTD_NO_POLICY_USAGE_FLAG': 'policy usage check skipped',
    'CERT_CHAIN_POLICY_IGNORE_ALL_NOT_TIME_VALID_FLAGS': 'expiry ignored',
    'CERT_CHAIN_POLICY_ALLOW_UNKNOWN_CA_FLAG': 'unknown CA accepted — verification is cosmetic',
}


def sh(cmd, timeout=120):
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).decode('utf-8', 'replace')
    except Exception as e:
        return 1, str(e)


def sig_region(path):
    """Return (cert_table_offset, cert_table_size, file_size) — to spot appended data."""
    if not pefile:
        return None
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']])
        d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        off, size = d.VirtualAddress, d.Size
        pe.close()
        return off, size, os.path.getsize(path)
    except Exception:
        return None


def parse_with_signify(path):
    out = {}
    try:
        from signify.authenticode import AuthenticodeFile
        with open(path, 'rb') as f:
            af = AuthenticodeFile.from_stream(f)
            sigs = list(af.iter_signatures())
            if not sigs:
                return out
            sd = sigs[0]
            out['signature_count'] = len(sigs)
            da = getattr(sd, 'digest_algorithm', None)
            out['digest_algorithm'] = getattr(da, '__name__', str(da)).replace('openssl_', '')
            si = sd.signer_info
            cert = None
            for c in (sd.certificates or []):
                try:
                    if c.serial_number == si.serial_number:
                        cert = c
                        break
                except Exception:
                    pass
            cert = cert or ((sd.certificates or [None])[0])
            if cert is not None:
                out['subject'] = str(getattr(cert, 'subject', ''))[:220]
                out['issuer'] = str(getattr(cert, 'issuer', ''))[:220]
                out['valid_from'] = str(getattr(cert, 'valid_from', ''))[:32]
                out['valid_to'] = str(getattr(cert, 'valid_to', ''))[:32]
                out['serial'] = str(getattr(cert, 'serial_number', ''))[:44]
            cs = getattr(si, 'countersigner', None)
            out['timestamped'] = cs is not None
            if cs is not None:
                out['timestamp'] = str(getattr(cs, 'signing_time', ''))[:32]
            out['program_name'] = str(getattr(si, 'program_name', '') or '')[:120]
            out['more_info'] = str(getattr(si, 'more_info', '') or '')[:160]
            try:
                out['page_hashes'] = b'1.3.6.1.4.1.311.2.3.1' in bytes(sd.asn1.dump()) \
                    if hasattr(sd, 'asn1') else None
            except Exception:
                out['page_hashes'] = None
            # nested signatures: a second, usually stronger, digest
            try:
                out['nested'] = len(list(sd.iter_recursive_nested())) - 1
            except Exception:
                pass
            try:
                ok, err = af.explain_verify()
                out['signify_verified'] = str(ok).split('.')[-1]
                if err:
                    out['signify_reason'] = str(err)[:200]
            except Exception as e:
                out['signify_reason'] = str(e)[:160]
    except Exception as e:
        out['signify_error'] = f'{type(e).__name__}: {e}'[:180]
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--loot', required=True)
    a = ap.parse_args()
    loot = a.loot
    tri = json.load(open(os.path.join(loot, 'pe_triage.json')))
    man = {f['path']: f for f in json.load(open(os.path.join(loot, 'unwrap.json')))['files']}

    rows, issues = [], []
    publishers = Counter()
    for b in tri['binaries']:
        if not b.get('ok'):
            continue
        rel = b['path']
        p = man.get(rel, {}).get('abs')
        if not p or not os.path.isfile(p):
            continue
        r = {'path': rel, 'arch': b.get('arch'), 'is_dll': b.get('is_dll'),
             'signed': (b.get('signature') or {}).get('has_security_dir'),
             'verified': (b.get('signature') or {}).get('verified')}
        if r['signed']:
            r.update(parse_with_signify(p))
            sr = sig_region(p)
            if sr:
                off, size, fsz = sr
                r['cert_table'] = {'offset': off, 'size': size, 'file_size': fsz,
                                   'trailing_bytes': max(0, fsz - (off + size))}
            subj = r.get('subject') or ((b.get('signature') or {}).get('signer') or '')
            cn = re.search(r'(?i)CN=([^,/]+)', subj)
            publishers[(cn.group(1) if cn else subj)[:80]] += 1
        rows.append(r)

    total = len(rows)
    signed = [r for r in rows if r['signed']]
    unsigned = [r for r in rows if not r['signed']]
    if unsigned:
        issues.append({'kind': 'unsigned-binaries-in-a-signed-package', 'severity': 6,
                       'count': len(unsigned),
                       'detail': f"{len(unsigned)} of {total} PE files carry no Authenticode signature",
                       'why': 'an unsigned DLL beside signed first-party binaries is both a DLL-hijack '
                              'candidate and a supply-chain question: if an attacker replaces it, '
                              'nothing on the host notices',
                       'examples': [r['path'] for r in unsigned[:12]]})
    sha1 = [r for r in signed if 'sha1' in str(r.get('digest_algorithm', '')).lower()]
    if sha1:
        issues.append({'kind': 'sha1-authenticode', 'severity': 5, 'count': len(sha1),
                       'detail': f"{len(sha1)} binaries signed with SHA-1",
                       'why': 'SHA-1 Authenticode is deprecated and untrusted for anything signed '
                              'after 2016; collision attacks against it are practical',
                       'examples': [r['path'] for r in sha1[:10]]})
    nots = [r for r in signed if r.get('timestamped') is False]
    if nots:
        issues.append({'kind': 'no-trusted-timestamp', 'severity': 4, 'count': len(nots),
                       'detail': f"{len(nots)} signatures carry no countersignature/timestamp",
                       'why': 'the signature becomes invalid the moment the signing certificate '
                              'expires, which turns into a support incident and trains users to '
                              'ignore signature warnings',
                       'examples': [r['path'] for r in nots[:10]]})
    trailing = [r for r in signed if (r.get('cert_table') or {}).get('trailing_bytes', 0) > 16]
    if trailing:
        issues.append({'kind': 'data-after-signed-region', 'severity': 7, 'count': len(trailing),
                       'detail': f"{len(trailing)} signed files carry bytes after the certificate table",
                       'why': 'the Authenticode digest does not cover this region. Appended data is a '
                              'known repackaging vector: a valid signature on a file whose trailing '
                              'content an attacker controls. Check whether the product reads that '
                              'appended data (installers and SFX archives frequently do)',
                       'examples': [f"{r['path']} (+{r['cert_table']['trailing_bytes']} bytes)"
                                    for r in trailing[:10]]})
    failed = [r for r in signed if r.get('verified') is False]
    if failed:
        issues.append({'kind': 'signature-verification-failed', 'severity': 8, 'count': len(failed),
                       'detail': f"{len(failed)} signatures do not verify",
                       'why': 'either the file was modified after signing, or the chain is broken. '
                              'Both are reportable; confirm with `osslsigncode verify` and on the host',
                       'examples': [r['path'] for r in failed[:10]]})
    import datetime as _dt
    expired = []
    for r in signed:
        vt = r.get('valid_to') or ''
        m = re.match(r'(\d{4})-(\d{2})-(\d{2})', vt)
        if m:
            d = _dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
            if d < _dt.date.today():
                r['cert_expired'] = True
                expired.append(r)
    if expired:
        issues.append({'kind': 'signing-certificate-expired', 'severity': 4, 'count': len(expired),
                       'detail': f"{len(expired)} signatures use a certificate that has expired",
                       'why': 'harmless IF the signature is timestamped (the timestamp fixes the '
                              'signing moment). Without a timestamp the signature is now invalid and '
                              'Windows will warn — check the `no-trusted-timestamp` issue too',
                       'examples': [f"{r['path']} (expired {r.get('valid_to')})" for r in expired[:10]]})
    if len(publishers) > 2:
        issues.append({'kind': 'multiple-publishers', 'severity': 3, 'count': len(publishers),
                       'detail': 'signed by: ' + ', '.join(f'{k} ({v})' for k, v in publishers.most_common(8)),
                       'why': 'third-party signed binaries inside the package are the supply-chain '
                              'surface; match each against the SBOM and check for known-vulnerable '
                              'versions or abusable signed helpers (LOLbins)',
                       'examples': []})

    # --- does the product verify signatures, and how? -------------------------------
    verifiers = []
    for b in tri['binaries']:
        if not b.get('ok'):
            continue
        imps = {f for v in (b.get('imports') or {}).values() for f in v}
        got = sorted({k for k in VERIFY_APIS if any(k.lower() in f.lower() for f in imps)})
        if got:
            verifiers.append({'path': b['path'], 'apis': got})
    weak_flag_hits = []
    for rel, f in man.items():
        if f.get('kind') != 'pe' or f['size'] == 0:
            continue
        try:
            d = open(f['abs'], 'rb').read(24 << 20)
        except Exception:
            continue
        s = b'\n'.join(re.findall(rb'[\x20-\x7e]{5,}', d)).decode('latin1')
        hits = [k for k in WEAK_FLAGS if k in s]
        if hits:
            weak_flag_hits.append({'path': rel, 'flags': hits})

    out = {'total': total, 'signed': len(signed), 'unsigned': len(unsigned),
           'publishers': publishers.most_common(20), 'issues': issues,
           'verifiers': verifiers, 'weak_verification_flags': weak_flag_hits, 'binaries': rows}
    json.dump(out, open(os.path.join(loot, 'signing.json'), 'w'), indent=1)

    L = ['# Code signing', '',
         f'- PE files: **{total}** · signed: **{len(signed)}** · unsigned: **{len(unsigned)}**',
         f"- distinct publishers: **{len(publishers)}**", '']
    if publishers:
        L += ['| publisher | files |', '|---|---|']
        for k, v in publishers.most_common(12):
            L.append(f'| {k} | {v} |')
        L.append('')
    L += [f'## Issues ({len(issues)})', '']
    if not issues:
        L.append('_the package is consistently and correctly signed_\n')
    for i in sorted(issues, key=lambda x: -x['severity']):
        L += [f"### {i['kind']} ({i['severity']}/10)", '', f"- {i['detail']}", f"- {i['why']}"]
        if i['examples']:
            L.append('- examples:')
            for e in i['examples']:
                L.append(f'  - `{e}`')
        L.append('')
    L += [f'## Does the product verify signatures itself? ({len(verifiers)} binaries)', '']
    if not verifiers:
        L += ['**No signature-verification API is imported by any binary in this package.**', '',
              'If this product downloads and executes anything — an update, a plugin, a helper — '
              'and verifies nothing, that is the finding. Trace the download-to-execute path in '
              '`surface.md` (update endpoints) and prove it.', '']
    for v in verifiers[:25]:
        L.append(f"- `{v['path']}` — {', '.join(v['apis'])}")
    if verifiers:
        L += ['', 'For each: verification is only as good as its parameters. Read the call and answer:',
              '', '1. Is revocation checked, or is `WTD_REVOKE_NONE` passed?',
              '2. Is the **publisher** compared against an expected name/thumbprint, or does any '
              'valid Authenticode signature pass? (The second is the common bug: an attacker signs '
              'their own payload with any $200 certificate and it verifies.)',
              '3. Is the check done on the file that is later executed, or on a copy? (TOCTOU: '
              'verify, then the file is replaced before `CreateProcess`.)',
              '4. Is the return value actually acted on?', '']
    if weak_flag_hits:
        L += [f'## Weak verification flags referenced ({len(weak_flag_hits)})', '']
        for w in weak_flag_hits[:20]:
            L.append(f"- `{w['path']}`")
            for fl in w['flags']:
                L.append(f"  - **{fl}** — {WEAK_FLAGS[fl]}")
        L.append('')
    L += ['## Reportability', '',
          '- Unsigned/SHA-1/no-timestamp alone are usually **Low or informational** — file them as '
          'hardening, or fold them into a chain.',
          '- A verification that **passes any valid signature** on an update or plugin is **High to '
          'Critical**: it is the control the vendor believes protects the code path that executes.',
          '- Data after the signed region is only a finding once you show the product **reads** it.']
    open(os.path.join(loot, 'signing.md'), 'w').write('\n'.join(L))
    print(f"[sign_audit] {len(signed)}/{total} signed, {len(issues)} issues, "
          f"{len(verifiers)} binaries verify signatures")
    print(f'[sign_audit] -> {loot}/signing.json + signing.md')


if __name__ == '__main__':
    main()
