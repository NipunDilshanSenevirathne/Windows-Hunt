#!/usr/bin/env python3
"""
dotnet_il.py — IL-level sink analysis for every managed assembly in the loot.

Pure python (dnfile + dncil): no dotnet SDK, no Windows, no ILSpy required. For each method
body it walks the CIL, resolves every call/newobj target to `Namespace.Type::Method`, and
matches against a sink table built from what actually gets exploited in .NET desktop apps —
then attaches the `ldstr` operands that flow into the call as evidence, because a sink with
an attacker-influenced string beside it is a lead and a sink with a constant is usually not.

Sink families: command/process execution, unsafe deserialization (the .NET RCE workhorse),
TLS validation disabled, dynamic code load, SQL string concatenation, registry and filesystem
writes into shared paths, P/Invoke into dangerous Win32, impersonation, weak crypto and
hardcoded keys, WebView/browser hosting, and update/download-then-execute.

Usage:  dotnet_il.py --loot loot/<name> [--max-assemblies 400] [--decompile <Type::Method>]
Writes: <loot>/dotnet_il.json, <loot>/dotnet_il.md
"""
import argparse, json, os, re, sys
from collections import defaultdict

try:
    import dnfile
    from dncil.cil.body import CilMethodBody
    from dncil.cil.body.reader import CilMethodBodyReaderBase
    from dncil.cil.error import MethodBodyFormatError
    from dncil.clr.token import Token, StringToken, InvalidToken
except ImportError:
    sys.exit('dotnet_il: dnfile/dncil missing — run scripts/provision.sh --tier dotnet')

# sink -> (family, severity_hint, why)
SINKS = {
    # --- execution -------------------------------------------------------------
    'System.Diagnostics.Process::Start': ('exec', 8, 'process creation — check the filename and arguments are not attacker-influenced and the path is absolute+quoted'),
    'System.Diagnostics.ProcessStartInfo::set_FileName': ('exec', 7, 'process image chosen at runtime'),
    'System.Diagnostics.ProcessStartInfo::set_Arguments': ('exec', 7, 'argument string built at runtime — argument injection'),
    'System.Diagnostics.ProcessStartInfo::set_UseShellExecute': ('exec', 5, 'ShellExecute semantics: the OS resolves the verb/handler, widening what can run'),
    'Microsoft.VisualBasic.Interaction::Shell': ('exec', 8, 'VB Shell()'),
    # --- deserialization (the .NET RCE workhorse) -------------------------------
    'System.Runtime.Serialization.Formatters.Binary.BinaryFormatter::Deserialize': ('deser', 10, 'BinaryFormatter is unsafe by design and removed in .NET 9; any attacker-controlled stream is RCE'),
    'System.Runtime.Serialization.NetDataContractSerializer::ReadObject': ('deser', 10, 'NetDataContractSerializer carries type info — RCE'),
    'System.Web.UI.LosFormatter::Deserialize': ('deser', 10, 'LosFormatter — RCE'),
    'System.Web.UI.ObjectStateFormatter::Deserialize': ('deser', 10, 'ObjectStateFormatter — RCE'),
    'System.Runtime.Serialization.Formatters.Soap.SoapFormatter::Deserialize': ('deser', 10, 'SoapFormatter — RCE'),
    'Newtonsoft.Json.JsonSerializerSettings::set_TypeNameHandling': ('deser', 9, 'TypeNameHandling != None turns JSON into a type-instantiation primitive — RCE with a gadget'),
    'Newtonsoft.Json.JsonConvert::DeserializeObject': ('deser', 5, 'safe unless TypeNameHandling is set or a custom SerializationBinder is absent — check the settings object'),
    'System.Xml.Serialization.XmlSerializer::.ctor': ('deser', 6, 'XmlSerializer is safe only when the type is fixed at compile time; a runtime Type argument is a gadget primitive'),
    'System.Web.Script.Serialization.JavaScriptSerializer::Deserialize': ('deser', 7, 'unsafe with a SimpleTypeResolver'),
    'System.Resources.ResourceReader::.ctor': ('deser', 6, 'ResourceReader deserializes BinaryFormatter payloads from .resources'),
    'YamlDotNet.Serialization.Deserializer::Deserialize': ('deser', 7, 'YamlDotNet with a permissive type resolver instantiates arbitrary types'),
    # --- dynamic code ----------------------------------------------------------
    'System.Reflection.Assembly::Load': ('dyncode', 8, 'assembly loaded at runtime — where from, and is it verified?'),
    'System.Reflection.Assembly::LoadFrom': ('dyncode', 9, 'LoadFrom a path — if that path is user-writable this is code execution at this process privilege'),
    'System.Reflection.Assembly::LoadFile': ('dyncode', 9, 'LoadFile a path — same'),
    'System.Reflection.Assembly::UnsafeLoadFrom': ('dyncode', 9, 'UnsafeLoadFrom skips the zone check entirely'),
    'System.Activator::CreateInstance': ('dyncode', 6, 'type instantiated by name — with attacker-chosen type this is a gadget trigger'),
    'System.Activator::CreateInstanceFrom': ('dyncode', 8, 'instantiate from a path'),
    'System.AppDomain::ExecuteAssembly': ('dyncode', 9, 'executes an assembly by path'),
    'System.CodeDom.Compiler.CodeDomProvider::CompileAssemblyFromSource': ('dyncode', 8, 'compiles source at runtime'),
    'System.Reflection.Emit.AssemblyBuilder::DefineDynamicAssembly': ('dyncode', 4, 'dynamic assembly emission'),
    # --- transport security ----------------------------------------------------
    'System.Net.ServicePointManager::set_ServerCertificateValidationCallback': ('tls', 8, 'custom certificate validation — if the callback returns true unconditionally, every TLS connection in the process is MITM-able, including the update channel'),
    'System.Net.Http.HttpClientHandler::set_ServerCertificateCustomValidationCallback': ('tls', 8, 'per-client certificate validation override'),
    'System.Net.ServicePointManager::set_CertificatePolicy': ('tls', 8, 'legacy certificate policy override'),
    'System.Net.ServicePointManager::set_SecurityProtocol': ('tls', 4, 'protocol pinning — check SSL3/TLS1.0 are not being forced back on'),
    # --- download / update -----------------------------------------------------
    'System.Net.WebClient::DownloadFile': ('update', 7, 'download to disk — transport and signature verification decide whether this is an update-channel RCE'),
    'System.Net.WebClient::DownloadString': ('update', 5, 'remote content into the process'),
    'System.Net.Http.HttpClient::GetAsync': ('update', 3, 'HTTP request'),
    'System.Net.WebRequest::Create': ('update', 3, 'HTTP request'),
    # --- sql -------------------------------------------------------------------
    'System.Data.SqlClient.SqlCommand::.ctor': ('sql', 6, 'command text — concatenated input is SQLi'),
    'System.Data.SqlClient.SqlCommand::set_CommandText': ('sql', 6, 'command text assigned at runtime'),
    'System.Data.SQLite.SQLiteCommand::.ctor': ('sql', 5, 'local SQLite command'),
    # --- filesystem / registry (LPE-relevant) ----------------------------------
    'System.IO.File::WriteAllText': ('fs', 5, 'file write — where? a shared path (ProgramData/Public/Temp) written by a privileged process is an LPE primitive'),
    'System.IO.File::WriteAllBytes': ('fs', 5, 'file write'),
    'System.IO.File::Copy': ('fs', 5, 'file copy — target path control matters'),
    'System.IO.File::Move': ('fs', 6, 'file move — with a symlink/junction on the source this becomes arbitrary file write/delete'),
    'System.IO.File::Delete': ('fs', 6, 'arbitrary file delete is an LPE primitive when the deleter is privileged'),
    'System.IO.Directory::CreateDirectory': ('fs', 3, 'directory creation — check the inherited ACL'),
    'System.IO.Compression.ZipFile::ExtractToDirectory': ('fs', 7, 'zip extraction — pre-.NET-4.5.1 and hand-rolled loops are Zip-Slip (path traversal via ../ in entry names)'),
    'System.IO.Compression.ZipFileExtensions::ExtractToFile': ('fs', 7, 'per-entry extraction — the classic Zip-Slip sink'),
    'Microsoft.Win32.RegistryKey::SetValue': ('registry', 5, 'registry write — under HKLM from a privileged process, check who can influence the value'),
    'Microsoft.Win32.Registry::SetValue': ('registry', 5, 'registry write'),
    'System.Security.AccessControl.FileSystemSecurity::AddAccessRule': ('acl', 8, 'ACL being widened in code — read the rule: an Everyone/Users FullControl ACE on a privileged path is the finding'),
    'System.Security.AccessControl.FileSystemSecurity::SetAccessRule': ('acl', 8, 'ACL replaced in code'),
    'System.IO.FileSystemAclExtensions::SetAccessControl': ('acl', 8, 'ACL applied'),
    # --- identity / privilege ---------------------------------------------------
    'System.Security.Principal.WindowsIdentity::Impersonate': ('token', 6, 'impersonation — check RevertToSelf on every path incl. exceptions'),
    'System.Security.Principal.WindowsImpersonationContext::Undo': ('token', 2, 'impersonation undo'),
    'System.Diagnostics.Process::get_Handle': ('token', 3, 'process handle'),
    # --- crypto ------------------------------------------------------------------
    'System.Security.Cryptography.MD5::Create': ('crypto', 4, 'MD5 — broken for integrity/signature use'),
    'System.Security.Cryptography.SHA1::Create': ('crypto', 3, 'SHA1 — deprecated for signatures'),
    'System.Security.Cryptography.DES::Create': ('crypto', 6, 'DES — 56-bit, broken'),
    'System.Security.Cryptography.TripleDES::Create': ('crypto', 4, '3DES — legacy'),
    'System.Security.Cryptography.RC2::Create': ('crypto', 6, 'RC2 — broken'),
    'System.Security.Cryptography.SymmetricAlgorithm::set_Mode': ('crypto', 5, 'cipher mode set — ECB leaks structure; CBC without a MAC is malleable'),
    'System.Security.Cryptography.SymmetricAlgorithm::set_Key': ('crypto', 7, 'key assigned — if it comes from a literal byte array or a constant string, it is hardcoded'),
    'System.Security.Cryptography.SymmetricAlgorithm::set_IV': ('crypto', 6, 'IV assigned — a constant IV destroys CBC/CTR security'),
    'System.Security.Cryptography.Rfc2898DeriveBytes::.ctor': ('crypto', 3, 'PBKDF2 — check iteration count and salt'),
    'System.Security.Cryptography.ProtectedData::Unprotect': ('crypto', 4, 'DPAPI unprotect — with CurrentUser scope any code as that user can also unprotect it'),
    'System.Random::.ctor': ('crypto', 4, 'System.Random is not cryptographically secure — fatal if it produces tokens, passwords or nonces'),
    # --- P/Invoke into the dangerous half of Win32 -------------------------------
    'PINVOKE': ('pinvoke', 5, 'native interop'),
}
PINVOKE_HOT = re.compile(r'(?i)^(CreateProcess|ShellExecute|WinExec|LoadLibrary|CreateService|'
                         r'OpenSCManager|ChangeServiceConfig|SetNamedSecurityInfo|SetSecurityInfo|'
                         r'ImpersonateNamedPipeClient|CreateNamedPipe|DeviceIoControl|'
                         r'WriteProcessMemory|VirtualAllocEx|CreateRemoteThread|AdjustTokenPrivileges|'
                         r'LogonUser|DuplicateTokenEx|CreateProcessAsUser|CreateProcessWithLogonW|'
                         r'MoveFileEx|CreateSymbolicLink|RegSetValue|NtSetInformation)')

SECRET_RX = re.compile(r'(?i)(api[_-]?key|secret|passw|pwd|token|bearer|client[_-]?secret|'
                       r'connectionstring|AccountKey=|private[_-]?key|-----BEGIN)')


class Reader(CilMethodBodyReaderBase):
    def __init__(self, pe, row):
        self.pe = pe
        self.rva = row.Rva
        self.offset = pe.get_offset_from_rva(row.Rva)

    def read(self, n):
        d = self.pe.get_data(self.pe.get_rva_from_offset(self.offset), n)
        self.offset += n
        return d

    def tell(self):
        return self.offset

    def seek(self, o):
        self.offset = o
        return self.offset


def resolve(pe, tok):
    """token -> 'Namespace.Type::Method' or a string literal."""
    try:
        if isinstance(tok, StringToken):
            return 'ldstr', pe.net.user_strings.get_us(tok.rid).value
        t = pe.net.mdtables.tables_list_by_index.get(tok.table) if hasattr(pe.net.mdtables, 'tables_list_by_index') else None
        table = pe.net.mdtables
        row = None
        name = None
        if tok.table == 0x0A:      # MemberRef
            row = table.MemberRef.rows[tok.rid - 1]
            cls = row.Class.row
            ns = getattr(cls, 'TypeNamespace', None)
            tn = getattr(cls, 'TypeName', None)
            ns = ns.value if hasattr(ns, 'value') else (ns or '')
            tn = tn.value if hasattr(tn, 'value') else (tn or '')
            nm = row.Name.value if hasattr(row.Name, 'value') else str(row.Name)
            name = f"{ns + '.' if ns else ''}{tn}::{nm}"
        elif tok.table == 0x06:    # MethodDef
            row = table.MethodDef.rows[tok.rid - 1]
            nm = row.Name.value if hasattr(row.Name, 'value') else str(row.Name)
            name = f"(local)::{nm}"
        elif tok.table == 0x2B:    # MethodSpec
            row = table.MethodSpec.rows[tok.rid - 1]
            m = row.Method.row
            nm = getattr(m, 'Name', None)
            nm = nm.value if hasattr(nm, 'value') else str(nm)
            name = f"(generic)::{nm}"
        elif tok.table == 0x01:    # TypeRef
            row = table.TypeRef.rows[tok.rid - 1]
            ns = row.TypeNamespace.value if hasattr(row.TypeNamespace, 'value') else ''
            tn = row.TypeName.value if hasattr(row.TypeName, 'value') else ''
            name = f"{ns}.{tn}"
        if name:
            return 'call', name
    except Exception:
        pass
    return None, None


def method_name(pe, mrow, tdmap, idx):
    nm = mrow.Name.value if hasattr(mrow.Name, 'value') else str(mrow.Name)
    return f'{tdmap.get(id(mrow), "?")}::{nm}'


def analyze(path, rel, max_methods=40000):
    out = {'path': rel, 'ok': False, 'hits': [], 'refs': [], 'pinvokes': [], 'strings_of_interest': []}
    try:
        pe = dnfile.dnPE(path)
        if not pe.net:
            return out
    except Exception as e:
        out['error'] = str(e)[:160]
        return out
    out['ok'] = True
    try:
        asm = pe.net.mdtables.Assembly
        if asm and asm.rows:
            r = asm.rows[0]
            out['assembly'] = f"{r.Name.value if hasattr(r.Name,'value') else r.Name} " \
                              f"{r.MajorVersion}.{r.MinorVersion}.{r.BuildNumber}.{r.RevisionNumber}"
    except Exception:
        pass
    try:
        for r in (pe.net.mdtables.AssemblyRef.rows if pe.net.mdtables.AssemblyRef else []):
            nm = r.Name.value if hasattr(r.Name, 'value') else str(r.Name)
            out['refs'].append(f'{nm} {r.MajorVersion}.{r.MinorVersion}.{r.BuildNumber}.{r.RevisionNumber}')
    except Exception:
        pass
    # method -> owning type (dnfile resolves MethodList to a list of MethodDef rows)
    tdmap = {}
    try:
        for td in pe.net.mdtables.TypeDef.rows:
            ns = td.TypeNamespace.value if hasattr(td.TypeNamespace, 'value') else ''
            tn = td.TypeName.value if hasattr(td.TypeName, 'value') else ''
            full = f"{ns + '.' if ns else ''}{tn}"
            ml = td.MethodList
            if isinstance(ml, list):
                for m in ml:
                    row = getattr(m, 'row', m)
                    if row is not None:
                        tdmap[id(row)] = full
    except Exception:
        pass
    # P/Invoke table
    try:
        for r in (pe.net.mdtables.ImplMap.rows if pe.net.mdtables.ImplMap else []):
            nm = r.ImportName.value if hasattr(r.ImportName, 'value') else str(r.ImportName)
            mod = ''
            try:
                mod = r.ImportScope.row.Name.value
            except Exception:
                pass
            hot = bool(PINVOKE_HOT.match(nm))
            out['pinvokes'].append({'fn': nm, 'module': mod, 'hot': hot})
    except Exception:
        pass

    mds = pe.net.mdtables.MethodDef.rows if pe.net.mdtables.MethodDef else []
    for idx, mrow in enumerate(mds[:max_methods]):
        if not mrow.Rva:
            continue
        try:
            body = CilMethodBody(Reader(pe, mrow))
        except (MethodBodyFormatError, Exception):
            continue
        recent = []
        mname = method_name(pe, mrow, tdmap, idx)
        for ins in body.instructions:
            op = str(ins.opcode).lower()
            tok = getattr(ins, 'operand', None)
            if isinstance(tok, StringToken):
                kind, val = resolve(pe, tok)
                if val:
                    recent.append(val)
                    recent[:] = recent[-6:]
                    if SECRET_RX.search(val) and 4 < len(val) < 400:
                        out['strings_of_interest'].append({'method': mname, 'value': val[:200]})
                continue
            if op.startswith(('call', 'newobj', 'ldftn', 'jmp')) and isinstance(tok, Token):
                kind, name = resolve(pe, tok)
                if kind != 'call' or not name:
                    continue
                sink = SINKS.get(name)
                if not sink and name.endswith('::.ctor'):
                    sink = SINKS.get(name)
                if sink:
                    fam, sev, why = sink
                    out['hits'].append({'method': mname, 'sink': name, 'family': fam,
                                        'severity_hint': sev, 'why': why,
                                        'nearby_strings': recent[-4:], 'offset': hex(ins.offset)})
    try:
        pe.close()
    except Exception:
        pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--loot', required=True)
    ap.add_argument('--max-assemblies', type=int, default=400)
    a = ap.parse_args()
    loot = a.loot
    man = json.load(open(os.path.join(loot, 'unwrap.json')))
    tri = {}
    tp = os.path.join(loot, 'pe_triage.json')
    if os.path.isfile(tp):
        tri = {b['path']: b for b in json.load(open(tp))['binaries']}
    cands = [f for f in man['files']
             if f['kind'] == 'pe' and (tri.get(f['path'], {}).get('is_dotnet') or
                                       f['ext'] in ('.dll', '.exe'))]
    results, n = [], 0
    for f in cands:
        if n >= a.max_assemblies:
            break
        r = analyze(f['abs'], f['path'])
        if r.get('ok'):
            n += 1
            results.append(r)
    allhits = [(r['path'], h) for r in results for h in r['hits']]
    fam = defaultdict(list)
    for p, h in allhits:
        fam[h['family']].append((p, h))
    json.dump({'assemblies': len(results), 'results': results},
              open(os.path.join(loot, 'dotnet_il.json'), 'w'), indent=1)

    L = ['# .NET IL analysis', '', f'- managed assemblies analysed: **{len(results)}**',
         f'- sink hits: **{len(allhits)}**', '']
    if not results:
        L.append('_no managed assemblies in this target_')
    order = ['deser', 'dyncode', 'exec', 'tls', 'acl', 'update', 'fs', 'registry', 'sql',
             'token', 'crypto', 'pinvoke']
    for f in order:
        rows = fam.get(f, [])
        if not rows:
            continue
        rows.sort(key=lambda x: -x[1]['severity_hint'])
        L += [f'## {f} ({len(rows)})', '']
        for p, h in rows[:40]:
            L.append(f"- **{h['sink']}** in `{h['method']}`  \n"
                     f"  _{h['why']}_  \n"
                     f"  assembly: `{p}` @ {h['offset']}"
                     + (f"  \n  nearby literals: {', '.join(repr(s)[:70] for s in h['nearby_strings'])}"
                        if h['nearby_strings'] else ''))
        if len(rows) > 40:
            L.append(f'- … {len(rows)-40} more')
        L.append('')
    hotpi = [(r['path'], p) for r in results for p in r['pinvokes'] if p['hot']]
    if hotpi:
        L += [f'## Dangerous P/Invoke ({len(hotpi)})', '']
        for p, pi in hotpi[:50]:
            L.append(f"- `{pi['module']}!{pi['fn']}` in `{p}`")
        L.append('')
    sec = [(r['path'], s) for r in results for s in r['strings_of_interest']]
    if sec:
        L += [f'## Literals that look like credentials ({len(sec)})', '',
              '> Confirm each against `scripts/secrets_hunt.py` — a literal named "token" is not', '> a secret until its shape or a live check says so.', '']
        for p, s in sec[:60]:
            L.append(f"- `{s['value']}`  \n  in `{s['method']}` (`{p}`)")
        L.append('')
    refs = defaultdict(set)
    for r in results:
        for x in r['refs']:
            refs[x.split(' ')[0]].add(x.split(' ')[1] if ' ' in x else '?')
    if refs:
        L += ['## Referenced assemblies (CVE-matching input)', '']
        for k in sorted(refs):
            L.append(f'- {k} {", ".join(sorted(refs[k]))}')
    open(os.path.join(loot, 'dotnet_il.md'), 'w').write('\n'.join(L))
    print(f'[dotnet_il] {len(results)} assemblies, {len(allhits)} sink hits')
    print(f'[dotnet_il] -> {loot}/dotnet_il.json + dotnet_il.md')


if __name__ == '__main__':
    main()
