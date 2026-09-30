#!/usr/bin/env python3
"""
secrets_hunt.py — credentials, keys and tokens, with shape validation and a live-check plan.

Desktop apps leak differently from web apps: the secret is usually in a config beside the exe,
in a resource, in an obfuscated blob the app itself decrypts, or in an installer property. This
scans the WHOLE extracted tree (text and binary, ASCII and UTF-16) with format-specific
patterns, filters the noise that makes secret scanners useless, and tells you exactly how to
prove each one is live — without sending anything anywhere on its own.

Design choices that matter:
  * high-confidence formats (AKIA…, ghp_…, xox…, -----BEGIN … KEY-----, JWT, connection
    strings with a password) are reported even at low entropy — the format IS the proof.
  * generic high-entropy strings are only reported when a nearby key name says what they are.
  * every hit records file, offset, the surrounding assignment, and a validation command that
    the operator runs deliberately (live validation is gated by scope/authorized_hosts.txt).

Usage:  secrets_hunt.py --loot loot/<name> [--max-mb 512] [--context 60]
Writes: <loot>/secrets.json, <loot>/secrets.md
"""
import argparse, base64, json, math, os, re, sys

PATTERNS = [
    # name, regex, confidence, how to validate
    ('AWS access key id', r'\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b', 0.95,
     'aws sts get-caller-identity (needs the paired secret)'),
    ('AWS secret access key', r'(?i)aws.{0,20}?(?:secret|private).{0,20}?[\'"\s:=]([A-Za-z0-9/+=]{40})\b', 0.8,
     'pair with the access key id, then aws sts get-caller-identity'),
    ('Azure storage connection string', r'(DefaultEndpointsProtocol=https?;AccountName=[^;]{3,64};AccountKey=[A-Za-z0-9+/=]{60,100})', 0.95,
     'az storage container list --connection-string ...'),
    ('Azure AD client secret', r'(?i)(?:client[_-]?secret|AZURE_CLIENT_SECRET)\s*[:=]\s*[\'"]?([A-Za-z0-9~._\-]{32,50})', 0.7,
     'POST to login.microsoftonline.com/<tenant>/oauth2/v2.0/token'),
    ('Google API key', r'\b(AIza[0-9A-Za-z_\-]{35})\b', 0.95,
     'GET https://www.googleapis.com/customsearch/v1?key=...  (check which API it unlocks)'),
    ('GCP service account JSON', r'("type"\s*:\s*"service_account")', 0.9,
     'gcloud auth activate-service-account --key-file'),
    ('GitHub token', r'\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,255})\b', 0.97,
     'curl -H "Authorization: token <t>" https://api.github.com/user'),
    ('Slack token', r'\b(xox[baprs]-[A-Za-z0-9\-]{10,72})\b', 0.95,
     'curl -d token=<t> https://slack.com/api/auth.test'),
    ('Stripe key', r'\b((?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,99})\b', 0.97,
     'curl https://api.stripe.com/v1/charges -u <key>:'),
    ('Twilio', r'\b(SK[0-9a-fA-F]{32}|AC[0-9a-fA-F]{32})\b', 0.8, 'Twilio API auth check'),
    ('SendGrid', r'\b(SG\.[A-Za-z0-9_\-]{16,32}\.[A-Za-z0-9_\-]{16,64})\b', 0.95, 'sendgrid /v3/scopes'),
    ('Firebase/GCM server key', r'\b(AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,})', 0.9, 'FCM send dry_run'),
    ('Private key block', r'(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)', 0.99,
     'openssl rsa -in <file> -check   (then: what does it sign or decrypt?)'),
    ('PKCS#12 / PFX reference', r'(?i)([A-Za-z0-9_\-./\\]{1,80}\.p(?:fx|12))\b', 0.5,
     'openssl pkcs12 -info -in <file> — and look for its password nearby'),
    ('JWT', r'\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})\b', 0.9,
     'decode the payload: exp, aud, scope. Then try it against the API it names.'),
    ('SQL connection string w/ password', r'(?i)((?:Server|Data Source)\s*=[^;\n]{1,80};(?:[^;\n]{0,80};){0,4}?(?:Password|Pwd)\s*=\s*[^;\n"\']{3,64})', 0.9,
     'sqlcmd / DBeaver against the host — only if the host is in scope'),
    ('MongoDB URI', r'\b(mongodb(?:\+srv)?://[^\s:@"\']{2,64}:[^\s:@"\']{2,64}@[^\s"\'/]{3,120})', 0.95, 'mongosh <uri> --eval "db.stats()"'),
    ('Postgres/MySQL URI', r'\b((?:postgres(?:ql)?|mysql)://[^\s:@"\']{2,64}:[^\s:@"\']{2,64}@[^\s"\'/]{3,120})', 0.95, 'psql/mysql client'),
    ('AMQP/Redis URI', r'\b((?:amqps?|redis(?:s)?)://[^\s:@"\']{0,64}:[^\s:@"\']{3,64}@[^\s"\'/]{3,120})', 0.9, 'redis-cli -u <uri> ping'),
    ('Basic auth in URL', r'\b(https?://[A-Za-z0-9._%\-]{2,64}:[^\s@"\'/]{3,64}@[A-Za-z0-9.\-]{3,120})', 0.9,
     'the credential is in the URL — replay the request'),
    ('Generic assignment', r'(?i)\b(?:api[_-]?key|apikey|secret|password|passwd|pwd|token|auth[_-]?key|'
     r'access[_-]?token|client[_-]?secret|encryption[_-]?key|private[_-]?key|licen[cs]e[_-]?key)\b'
     r'\s*[:=]\s*[\'"]([^\'"\s]{8,120})[\'"]', 0.45,
     'identify the service from context, then authenticate against it'),
    ('.NET config appSetting', r'(?i)<add\s+key\s*=\s*"[^"]{0,60}(?:api[_-]?key|secret|password|pwd|token|licen[cs]e)[^"]{0,30}"\s+value\s*=\s*"([^"]{8,160})"', 0.6,
     'the key name says what service it is — authenticate against that service'),
    ('JSON secret field', r'(?i)"(?:api[_-]?key|apikey|secret|client[_-]?secret|password|passwd|token|access[_-]?token|private[_-]?key)"\s*:\s*"([^"\s]{8,160})"', 0.6,
     'identify the service from the surrounding object, then authenticate'),
    ('Registry/INI secret', r'(?i)^\s*(?:\"?[A-Za-z_]{0,20}(?:password|pwd|secret|apikey|token)[A-Za-z_]{0,20}\"?)\s*=\s*\"?([^\r\n\"]{8,160})\"?\s*$', 0.5,
     'INI/.reg style assignment'),
    ('Hardcoded AES/DES key bytes', r'(?i)\b(?:key|iv)\s*=\s*(?:new\s+byte\[\]\s*)?\{\s*((?:0x[0-9a-fA-F]{2}\s*,\s*){7,63}0x[0-9a-fA-F]{2})\s*\}', 0.8,
     'decrypt the app\'s own stored blobs with it'),
    ('Windows credential (net use / runas)', r'(?i)\b(?:net\s+use|runas|psexec)[^\n]{0,120}?/(?:user|u)\s*:\s*(\S{2,64})[^\n]{0,60}', 0.6,
     'check whether the password follows on the same line'),
    ('Unattend/sysprep password', r'(?i)<(AdministratorPassword|Password)>\s*<Value>([^<]{3,120})</Value>', 0.9,
     'base64-decoded plaintext if PlainText=false'),
]

DENY = re.compile(r'(?i)(example|sample|dummy|changeme|your[_-]?(api|key|token)|xxxx+|placeholder|'
                  r'lorem|test[_-]?key|0{8,}|1234567|abcdef123|<[^>]{2,30}>|\$\{[^}]{2,40}\}|'
                  r'%[A-Za-z_]{2,30}%|\{\{[^}]{2,40}\}\}|null|none|undefined|redacted)')
MAX_TEXT = 12 << 20          # per-blob cap; beyond this the tail is noise anyway
NOISE_EXT = {'.png', '.jpg', '.gif', '.ico', '.ttf', '.woff', '.woff2', '.pak', '.bin', '.dat',
             '.map', '.pdb', '.mui', '.res'}


# One combined pass instead of 24 passes over every blob: a multi-MB binary times 24
# patterns times 3 encodings is minutes of CPU for nothing. Named groups keep attribution.
_COMBINED = None
_SINGLES = None


def _build():
    global _COMBINED, _SINGLES
    if _COMBINED is not None:
        return
    parts, singles = [], {}
    for i, (name, rx, conf, how) in enumerate(PATTERNS):
        g = f'p{i}'
        body = rx.replace('(?i)', '')
        parts.append(f'(?P<{g}>(?i:{body}))' if '(?i)' in rx else f'(?P<{g}>{body})')
        singles[g] = (name, re.compile(rx), conf, how)
    _COMBINED = re.compile('|'.join(parts))
    _SINGLES = singles


def entropy(s):
    if not s:
        return 0
    c = {}
    for ch in s:
        c[ch] = c.get(ch, 0) + 1
    n = len(s)
    return -sum((k / n) * math.log2(k / n) for k in c.values())


def texts(path, size, cap):
    """yield (label, text) — ascii strings and utf-16 strings for binaries, raw for text."""
    try:
        with open(path, 'rb') as f:
            data = f.read(min(size, cap))
    except Exception:
        return
    try:
        t = data.decode('utf-8')
        yield 'text', t
        return
    except Exception:
        pass
    yield 'ascii', b'\n'.join(re.findall(rb'[\x20-\x7e]{6,}', data)).decode('latin1')
    try:
        u = data.decode('utf-16-le', 'ignore')
        if u:
            yield 'utf16', '\n'.join(re.findall(r'[\x20-\x7e]{6,}', u))
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--loot', required=True)
    ap.add_argument('--max-mb', type=int, default=512)
    ap.add_argument('--context', type=int, default=60)
    a = ap.parse_args()
    man = json.load(open(os.path.join(a.loot, 'unwrap.json')))
    _build()
    cap = 48 << 20
    budget = a.max_mb << 20
    used = 0
    hits = []
    seen = set()
    for f in man['files']:
        if f['ext'] in NOISE_EXT or f['size'] == 0:
            continue
        if used > budget:
            break
        used += min(f['size'], cap)
        for label, t in texts(f['abs'], f['size'], cap):
            if not t:
                continue
            if len(t) > MAX_TEXT:
                t = t[:MAX_TEXT]
            for M in _COMBINED.finditer(t):
                g = M.lastgroup
                while g and g not in _SINGLES:          # inner group of a pattern
                    g = None
                if not g:
                    for gn in _SINGLES:
                        if M.group(gn) is not None:
                            g = gn
                            break
                if not g:
                    continue
                name, srx, conf, how = _SINGLES[g]
                sm = srx.search(M.group(g))
                val = (sm.group(sm.lastindex) if (sm and sm.lastindex) else M.group(g))
                # A generic container pattern (a config <add>, a JSON field) often wins the
                # alternation simply because it starts earlier in the line. Re-test the value
                # against the self-proving formats and keep the most specific classification —
                # "GitHub token" is worth far more to a triager than "config appSetting".
                if val and conf < 0.85:
                    for gn2, (n2, rx2, c2, h2) in _SINGLES.items():
                        if c2 < 0.85 or n2 == name:
                            continue
                        m2 = rx2.search(val)
                        if m2 and (m2.group(m2.lastindex) if m2.lastindex else m2.group(0)) == val:
                            name, conf, how = n2, c2, h2
                            break
                if not val or len(val) < 6:
                    continue
                if DENY.search(val):
                    continue
                if name == 'Generic assignment':
                    if entropy(val) < 3.0 or len(set(val)) < 6:
                        continue
                    if re.fullmatch(r'[A-Za-z .]{8,}', val):
                        continue
                k = (name, val[:80])
                if k in seen:
                    continue
                seen.add(k)
                st = max(0, M.start() - a.context)
                ctx = t[st:M.end() + a.context].replace('\n', ' ')[:260]
                hits.append({'type': name, 'value': val[:200], 'confidence': conf,
                             'file': f['path'], 'encoding': label, 'offset': M.start(),
                             'context': ctx, 'entropy': round(entropy(val), 2),
                             'validate': how})
    hits.sort(key=lambda h: (-h['confidence'], h['type']))
    json.dump({'count': len(hits), 'hits': hits}, open(os.path.join(a.loot, 'secrets.json'), 'w'), indent=1)

    high = [h for h in hits if h['confidence'] >= 0.85]
    med = [h for h in hits if 0.6 <= h['confidence'] < 0.85]
    low = [h for h in hits if h['confidence'] < 0.6]
    L = ['# Secrets', '', f'- high-confidence (format is self-proving): **{len(high)}**',
         f'- medium: **{len(med)}**  ·  low/heuristic: **{len(low)}**', '',
         '> A secret is a finding when it is **live** and **grants something**. Validate before',
         '> reporting, and validate only against hosts in `scope/authorized_hosts.txt`.', '']
    for title, rows in (('High confidence', high), ('Medium', med), ('Low / needs judgement', low)):
        L += [f'## {title} ({len(rows)})', '']
        if not rows:
            L.append('_none_\n')
            continue
        for h in rows[:80]:
            L += [f"- **{h['type']}** — `{h['value'][:120]}`",
                  f"  - file: `{h['file']}` (@{h['offset']}, {h['encoding']}, entropy {h['entropy']})",
                  f"  - context: `{h['context']}`",
                  f"  - validate: {h['validate']}"]
        if len(rows) > 80:
            L.append(f'- … {len(rows)-80} more in secrets.json')
        L.append('')
    L += ['## Severity guidance', '',
          '| what it unlocks | typical severity |', '|---|---|',
          '| cloud account / CI / source | Critical |',
          '| a backend API holding other users\' data | High |',
          '| a per-tenant or per-device key with no cross-user reach | Medium |',
          '| a third-party key with a free tier and no user data | Low, often informative |',
          '| a key the app is *supposed* to ship (public client id, licence check) | not a finding — say so and move on |',
          '', 'Ship the decrypt path too: a key is far stronger when you also show what it opens.']
    open(os.path.join(a.loot, 'secrets.md'), 'w').write('\n'.join(L))
    print(f'[secrets_hunt] {len(hits)} hits ({len(high)} high-confidence)')
    print(f"[secrets_hunt] -> {a.loot}/secrets.json + secrets.md")


if __name__ == '__main__':
    main()
