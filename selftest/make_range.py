#!/usr/bin/env python3
"""
make_range.py — build the self-test range: a deliberately vulnerable Windows app tree and a
hardened twin that is identical in shape and correct in every control.

Detection is measured against the vulnerable tree; FALSE POSITIVES are measured against the
hardened twin. A skill that only reports its hit rate is telling you half the story.

  make_range.py --out selftest/range
"""
import argparse, os, shutil, subprocess, sys, textwrap

VULN_MAIN_JS = r'''
const { app, BrowserWindow, ipcMain, shell, protocol } = require('electron');
const cp = require('child_process');
const path = require('path');

function createWindow (startUrl) {
  const win = new BrowserWindow({
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      webSecurity: false,
      sandbox: false,
      enableRemoteModule: true,
      nodeIntegrationInSubFrames: true,
      allowRunningInsecureContent: true,
      preload: path.join(__dirname, 'preload.js')
    }
  });
  win.loadURL(startUrl);
  return win;
}

ipcMain.handle('acme:openFile', async (e, p) => { return shell.openPath(p); });
ipcMain.handle('acme:run', async (e, cmd) => { return cp.execSync(cmd).toString(); });
ipcMain.on('acme:browse', (e, url) => { shell.openExternal(url); });

protocol.registerFileProtocol('acme', (req, cb) => {
  cb({ path: path.join(__dirname, 'www', req.url.substr(7)) });
});

app.whenReady().then(() => {
  const target = process.argv[2] || 'https://app.acme.example/';
  createWindow(target);
});
'''

HARD_MAIN_JS = r'''
const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');

const ALLOWED = new Set(['https://app.acme.example/']);

function createWindow () {
  const win = new BrowserWindow({
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      webSecurity: true,
      sandbox: true,
      preload: path.join(__dirname, 'preload.js')
    }
  });
  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', (e, url) => { if (!ALLOWED.has(url)) e.preventDefault(); });
  win.loadURL('https://app.acme.example/');
  return win;
}

ipcMain.handle('acme:getVersion', async () => app.getVersion());
app.whenReady().then(createWindow);
'''

VULN_PRELOAD = r'''
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('acmeApi', {
  openFile: (p) => ipcRenderer.invoke('acme:openFile', p),
  run:      (c) => ipcRenderer.invoke('acme:run', c),
  browse:   (u) => ipcRenderer.send('acme:browse', u),
});
'''
HARD_PRELOAD = r'''
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('acmeApi', {
  getVersion: () => ipcRenderer.invoke('acme:getVersion'),
});
'''

VULN_CONFIG = '''<?xml version="1.0"?>
<configuration>
  <appSettings>
    <add key="UpdateUrl" value="http://updates.acme.example/feed/latest.xml" />
    <add key="TelemetryUrl" value="https://telemetry.acme.example/v1/events" />
    <add key="github_token" value="ghp_16C7e42F292c6912E7710c838347Ae178B4a" />
    <add key="StorageConn" value="DefaultEndpointsProtocol=https;AccountName=acmeprod;AccountKey=bXlzdXBlcnNlY3JldGF6dXJlc3RvcmFnZWFjY291bnRrZXl2YWx1ZTEyMzQ1Njc4OTA=;" />
    <add key="ApiKey" value="AIzaSyD9fK2mQ8xZ1pLvR7tN4bW6cY0aE3sHjKm" />
    <add key="DataDir" value="C:\\ProgramData\\AcmeDesktop\\work" />
    <add key="PluginDir" value="C:\\ProgramData\\AcmeDesktop\\plugins" />
    <add key="PipeName" value="\\\\.\\pipe\\AcmeSvcControl" />
    <add key="LocalApi" value="http://127.0.0.1:17632/api/v1" />
    <add key="SqlConn" value="Server=db.acme.local;Database=acme;User Id=sa;Password=Pr0dP4ssw0rd!;" />
  </appSettings>
</configuration>
'''
HARD_CONFIG = '''<?xml version="1.0"?>
<configuration>
  <appSettings>
    <add key="UpdateUrl" value="https://updates.acme.example/feed/latest.xml" />
    <add key="TelemetryUrl" value="https://telemetry.acme.example/v1/events" />
    <add key="DataDir" value="%LOCALAPPDATA%\\AcmeDesktop\\work" />
  </appSettings>
</configuration>
'''

VULN_REG = r'''Windows Registry Editor Version 5.00

[HKEY_CLASSES_ROOT\acmedesktop]
"URL Protocol"=""
@="URL:AcmeDesktop Protocol"

[HKEY_CLASSES_ROOT\acmedesktop\shell\open\command]
@="C:\\Program Files\\AcmeDesktop\\Acme.exe %1"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run]
"AcmeAgent"="C:\\ProgramData\\AcmeDesktop\\agent.exe"
'''
HARD_REG = r'''Windows Registry Editor Version 5.00

[HKEY_CLASSES_ROOT\acmedesktop]
"URL Protocol"=""

[HKEY_CLASSES_ROOT\acmedesktop\shell\open\command]
@="\"C:\\Program Files\\AcmeDesktop\\Acme.exe\" \"%1\""
'''

VULN_INSTALL_PS = r'''
# install helper (vulnerable twin)
sc.exe create AcmeSvc binPath= C:\Program Files\AcmeDesktop\Acme Service\AcmeSvc.exe start= auto
schtasks /create /tn "AcmeUpdate" /tr "C:\ProgramData\AcmeDesktop\update.exe" /sc hourly /ru SYSTEM
icacls "C:\ProgramData\AcmeDesktop" /grant Everyone:(OI)(CI)F
# SDDL applied to the control pipe
$sddl = "D:(A;;GA;;;WD)(A;;GA;;;BU)"
'''
HARD_INSTALL_PS = r'''
# install helper (hardened twin)
sc.exe create AcmeSvc binPath= "C:\Program Files\AcmeDesktop\AcmeSvc.exe" start= auto
$sddl = "D:(A;;GRGW;;;BA)(A;;GA;;;SY)"
'''

VULN_BANNER = 'OpenSSL 1.0.2k  26 Jan 2017\nzlib version 1.2.8\njQuery JavaScript Library v1.7.2\n'
HARD_BANNER = 'OpenSSL 3.2.1 30 Jan 2024\nzlib version 1.3.1\njQuery JavaScript Library v3.7.1\n'

MANIFEST_ADMIN = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security><requestedPrivileges>
      <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
    </requestedPrivileges></security>
  </trustInfo>
</assembly>
'''
MANIFEST_USER = MANIFEST_ADMIN.replace('requireAdministrator', 'asInvoker')

PHANTOM_C = r'''
#include <windows.h>
#ifndef HELPER_PATH
#define HELPER_PATH "C:\\ProgramData\\AcmeDesktop\\work\\helper.exe"
#endif
__declspec(dllimport) int AcmeTlsInit(int);
__declspec(dllimport) int AcmeTlsSend(const char*);
int main(void) {
    /* service-style host that resolves wintls.dll through the DLL search order */
    AcmeTlsInit(1);
    AcmeTlsSend("hello");
#ifdef VULN
    ShellExecuteA(NULL, "open", HELPER_PATH, NULL, NULL, SW_HIDE);
#else
    {   /* hardened: an absolute, quoted image path and no shell verb resolution */
        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        char cmd[] = "\"" HELPER_PATH "\"";
        CreateProcessA(HELPER_PATH, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    }
#endif
    return 0;
}
'''
PHANTOM_DLL_C = r'''
#include <windows.h>
__declspec(dllexport) int AcmeTlsInit(int x){ return x; }
__declspec(dllexport) int AcmeTlsSend(const char* s){ return (int)lstrlenA(s); }
BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID l){ return TRUE; }
'''


# ---------------------------------------------------------------- new-engine fixtures

VULN_COM_REG = r'''Windows Registry Editor Version 5.00

[HKEY_CLASSES_ROOT\CLSID\{A1B2C3D4-1111-2222-3333-444455556666}]
@="Acme Update Broker"
"AppID"="{A1B2C3D4-1111-2222-3333-444455556666}"

[HKEY_CLASSES_ROOT\CLSID\{A1B2C3D4-1111-2222-3333-444455556666}\InprocServer32]
@="C:\\ProgramData\\AcmeDesktop\\bin\\AcmeBroker.dll"
"ThreadingModel"="Both"

[HKEY_CLASSES_ROOT\CLSID\{A1B2C3D4-1111-2222-3333-444455556666}\Elevation]
"Enabled"=dword:00000001
"LocalizedString"="@AcmeBroker.dll,-100"

[HKEY_CLASSES_ROOT\AppID\{A1B2C3D4-1111-2222-3333-444455556666}]
"RunAs"="LocalSystem"
"DllSurrogate"=""
'''
HARD_COM_REG = r'''Windows Registry Editor Version 5.00

[HKEY_CLASSES_ROOT\CLSID\{A1B2C3D4-1111-2222-3333-444455556666}]
@="Acme Update Broker"

[HKEY_CLASSES_ROOT\CLSID\{A1B2C3D4-1111-2222-3333-444455556666}\InprocServer32]
@="C:\\Program Files\\AcmeDesktop\\AcmeBroker.dll"
"ThreadingModel"="Apartment"
'''

VULN_HOOKS_REG = r'''Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows]
"AppInit_DLLs"="C:\\ProgramData\\AcmeDesktop\\bin\\acmehook.dll"
"LoadAppInit_DLLs"=dword:00000001

[HKEY_CLASSES_ROOT\AcmeDoc\shell\open\command]
@="C:\\Program Files\\AcmeDesktop\\Acme.exe --open %1"

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{99998888-7777-6666-5555-444433332222}\InprocServer32]
@="C:\\ProgramData\\AcmeDesktop\\bin\\acmeshell.dll"

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\AcmeSync]
@="{99998888-7777-6666-5555-444433332222}"
'''
HARD_HOOKS_REG = r'''Windows Registry Editor Version 5.00

[HKEY_CLASSES_ROOT\AcmeDoc\shell\open\command]
@="\"C:\\Program Files\\AcmeDesktop\\Acme.exe\" --open \"%1\""
'''

VULN_NMH = '''{
  "name": "com.acme.desktop.bridge",
  "description": "Acme native messaging host",
  "path": "C:\\\\ProgramData\\\\AcmeDesktop\\\\bin\\\\AcmeBridge.exe",
  "type": "stdio",
  "allowed_origins": [ "chrome-extension://*/", "chrome-extension://abcdefghijklmnopabcdefghijklmnop/" ]
}
'''
HARD_NMH = '''{
  "name": "com.acme.desktop.bridge",
  "description": "Acme native messaging host",
  "path": "C:\\\\Program Files\\\\AcmeDesktop\\\\AcmeBridge.exe",
  "type": "stdio",
  "allowed_origins": [ "chrome-extension://abcdefghijklmnopabcdefghijklmnop/" ]
}
'''

VULN_TASK = '''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>Acme</Author><URI>\\AcmeUpdate</URI></RegistrationInfo>
  <Triggers><TimeTrigger><Repetition><Interval>PT1H</Interval></Repetition>
    <StartBoundary>2024-01-01T00:00:00</StartBoundary><Enabled>true</Enabled></TimeTrigger></Triggers>
  <Principals><Principal id="Author">
    <UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel><LogonType>ServiceAccount</LogonType>
  </Principal></Principals>
  <Actions Context="Author">
    <Exec><Command>C:\\ProgramData\\AcmeDesktop\\update.exe</Command><Arguments>/silent</Arguments></Exec>
  </Actions>
</Task>
'''
HARD_TASK = VULN_TASK.replace('ProgramData', 'Program Files')

VULN_RUNTIMECFG = '''{
  "runtimeOptions": {
    "tfm": "net8.0",
    "framework": { "name": "Microsoft.NETCore.App", "version": "8.0.0" },
    "additionalProbingPaths": [ "C:\\\\ProgramData\\\\AcmeDesktop\\\\plugins" ]
  }
}
'''
HARD_RUNTIMECFG = '''{
  "runtimeOptions": {
    "tfm": "net8.0",
    "framework": { "name": "Microsoft.NETCore.App", "version": "8.0.0" }
  }
}
'''

VULN_PY = r'''import pickle, os, subprocess, sys, yaml
sys.path.append(r"C:\ProgramData\AcmeDesktop\plugins")

def load_state(blob):
    return pickle.loads(blob)

def run_helper(name):
    subprocess.call("helper.exe " + name, shell=True)

def load_cfg(text):
    return yaml.load(text)
'''
HARD_PY = '''import json, subprocess, sys, yaml

def load_state(blob):
    return json.loads(blob)

def run_helper(name):
    subprocess.run(["helper.exe", name], shell=False)

def load_cfg(text):
    return yaml.load(text, Loader=yaml.SafeLoader)
'''

VULN_APPX = '''<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
         xmlns:desktop="http://schemas.microsoft.com/appx/manifest/desktop/windows10">
  <Identity Name="Acme.Desktop" Version="4.2.0.0" Publisher="CN=Acme" />
  <Capabilities>
    <rescap:Capability Name="runFullTrust" />
    <rescap:Capability Name="broadFileSystemAccess" />
    <rescap:Capability Name="allowElevation" />
    <Capability Name="internetClient" />
  </Capabilities>
  <Applications><Application Id="App">
    <Extensions>
      <uap:Extension Category="windows.protocol"><uap:Protocol Name="acmedesktop" /></uap:Extension>
      <desktop:Extension Category="windows.fullTrustProcess" Executable="bin\\AcmeSvc.exe" />
    </Extensions>
  </Application></Applications>
</Package>
'''
HARD_APPX = VULN_APPX.replace(
    '    <rescap:Capability Name="broadFileSystemAccess" />\n', '').replace(
    '    <rescap:Capability Name="allowElevation" />\n', '')

VULN_JAR_ENTRIES = {'org/apache/logging/log4j/core/lookup/JndiLookup.class': b'\xca\xfe\xba\xbe',
                    'META-INF/MANIFEST.MF': b'Manifest-Version: 1.0\nImplementation-Version: 2.14.1\n'}

# --------------------------------------------------- pass-3 fixtures (RPC/TOCTOU/proc/cred)

HELPER_C = r'''
/* AcmeHelper.exe — deliberately exercises the pass-3 engines. */
#include <windows.h>
#include <wincrypt.h>
#include <rpc.h>
#include <aclapi.h>
#include <stdio.h>

#pragma pack(push,1)
typedef struct { unsigned int Length; GUID Id; unsigned short vmaj, vmin;
                 GUID Xfer; unsigned short xmaj, xmin;
                 void* DispatchTable; unsigned int EpCount; void* Ep;
                 void* Epv; void* Interp; unsigned int Flags; unsigned int pad; } WH_RSI;
#pragma pack(pop)

static const unsigned int g_dispatch[4] = { 11, 0, 0, 0 };
#ifdef VULN
/* an RPC server interface the static parser must recover */
const WH_RSI g_iface = {
  0x60,
  { 0xACE00001, 0x1111, 0x2222, {0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA} }, 1, 0,
  { 0x8a885d04, 0x1ceb, 0x11c9, {0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60} }, 2, 0,
  (void*)g_dispatch, 0, 0, 0, 0, 0, 0
};
static const char *g_endpoint = "ncalrpc:AcmeSvcEndpoint";
static const unsigned char g_key[16] = {
  0x41,0x63,0x6d,0x65,0x53,0x65,0x63,0x72,0x65,0x74,0x4b,0x65,0x79,0x31,0x32,0x33 };
#endif

static void do_work(void) {
    wchar_t tmp[MAX_PATH], name[MAX_PATH];
    HANDLE hPipe;
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    DATA_BLOB in, out;
    unsigned char buf[16] = {0};

#ifdef VULN
    /* TEMP-AS-SYSTEM + CHECK-THEN-USE + CREATE-THEN-ACL */
    GetTempPathW(MAX_PATH, tmp);
    GetTempFileNameW(tmp, L"acm", 0, name);
    if (GetFileAttributesW(name) != INVALID_FILE_ATTRIBUTES) {
        CopyFileW(L"C:\\ProgramData\\AcmeDesktop\\stage.dat", name, FALSE);
    }
    CreateDirectoryW(L"C:\\ProgramData\\AcmeDesktop\\work", NULL);
    SetNamedSecurityInfoW(L"C:\\ProgramData\\AcmeDesktop\\work", SE_FILE_OBJECT,
                          DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL);
    MoveFileExW(name, L"C:\\ProgramData\\AcmeDesktop\\work\\staged.dll",
                MOVEFILE_DELAY_UNTIL_REBOOT);

    /* IMPERSONATION-GAP: impersonate, never revert */
    hPipe = CreateNamedPipeW(L"\\\\.\\pipe\\AcmeSvcControl", PIPE_ACCESS_DUPLEX,
                             PIPE_TYPE_BYTE, 4, 4096, 4096, 0, NULL);
    if (hPipe != INVALID_HANDLE_VALUE) {
        ConnectNamedPipe(hPipe, NULL);
        ImpersonateNamedPipeClient(hPipe);
    }

    /* UNQUOTED-COMMANDLINE + HANDLE-INHERITANCE */
    {
        wchar_t cmd[] = L"C:\\Program Files\\AcmeDesktop\\Acme Service\\AcmeSvc.exe -k run";
        CreateProcessW(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    }
    ShellExecuteW(NULL, L"open", L"C:\\ProgramData\\AcmeDesktop\\work\\helper.exe",
                  NULL, NULL, SW_HIDE);

    /* credential storage: machine-scope DPAPI + a hardcoded key */
    in.pbData = (BYTE*)g_key; in.cbData = sizeof(g_key);
    CryptProtectData(&in, L"acme", NULL, NULL, NULL, CRYPTPROTECT_LOCAL_MACHINE, &out);
    CryptEncrypt(0, 0, TRUE, 0, buf, NULL, sizeof(buf));
    printf("%s\n", g_endpoint);
#else
    /* hardened: no temp, canonicalised copy, impersonate+revert, quoted command line,
       user-scope DPAPI with entropy, CSPRNG-generated key */
    hPipe = CreateNamedPipeW(L"\\\\.\\pipe\\AcmeSvcControl", PIPE_ACCESS_DUPLEX,
                             PIPE_TYPE_BYTE, 4, 4096, 4096, 0, NULL);
    if (hPipe != INVALID_HANDLE_VALUE) {
        ConnectNamedPipe(hPipe, NULL);
        ImpersonateNamedPipeClient(hPipe);
        RevertToSelf();
    }
    {
        wchar_t cmd[] = L"\"C:\\Program Files\\AcmeDesktop\\AcmeSvc.exe\" -k run";
        CreateProcessW(L"C:\\Program Files\\AcmeDesktop\\AcmeSvc.exe", cmd,
                       NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    }
    in.pbData = (BYTE*)"x"; in.cbData = 1;
    CryptProtectData(&in, L"acme", &in, NULL, NULL, 0, &out);
    CryptGenRandom(0, sizeof(buf), buf);
#endif
    (void)tmp; (void)name; (void)hPipe; (void)si; (void)pi; (void)buf;
}

int main(void) { do_work(); return 0; }
'''

def build_pe(outdir, vulnerable, mingw='x86_64-w64-mingw32-gcc'):
    """Build AcmeSvc.exe that imports wintls.dll. In the vulnerable tree wintls.dll is NOT
    shipped (phantom); in the hardened tree it is shipped beside the exe."""
    if not shutil.which(mingw):
        return False, 'mingw absent'
    tmp = os.path.join(outdir, '_build')
    os.makedirs(tmp, exist_ok=True)
    open(os.path.join(tmp, 'dll.c'), 'w').write(PHANTOM_DLL_C)
    open(os.path.join(tmp, 'app.c'), 'w').write(PHANTOM_C)
    open(os.path.join(tmp, 'app.manifest'), 'w').write(MANIFEST_ADMIN if vulnerable else MANIFEST_USER)
    open(os.path.join(tmp, 'app.rc'), 'w').write('1 24 "app.manifest"\n')
    r = subprocess.run([mingw, '-shared', '-o', os.path.join(tmp, 'wintls.dll'),
                        os.path.join(tmp, 'dll.c'),
                        '-Wl,--out-implib,' + os.path.join(tmp, 'libwintls.a')],
                       capture_output=True)
    if r.returncode:
        return False, r.stderr.decode()[-200:]
    rc = shutil.which('x86_64-w64-mingw32-windres')
    if rc:
        subprocess.run([rc, os.path.join(tmp, 'app.rc'), '-O', 'coff',
                        '-o', os.path.join(tmp, 'app.res')], capture_output=True)
    objs = [os.path.join(tmp, 'app.c')]
    if os.path.isfile(os.path.join(tmp, 'app.res')):
        objs.append(os.path.join(tmp, 'app.res'))
    helper = ('C:\\\\ProgramData\\\\AcmeDesktop\\\\work\\\\helper.exe' if vulnerable
              else '%LOCALAPPDATA%\\\\AcmeDesktop\\\\work\\\\helper.exe')
    svc_cmd = [mingw, f'-DHELPER_PATH="{helper}"']
    if vulnerable:
        svc_cmd.append('-DVULN')
    r = subprocess.run(svc_cmd + ['-o', os.path.join(outdir, 'AcmeSvc.exe')] + objs +
                       ['-L' + tmp, '-lwintls', '-lshell32'], capture_output=True)
    if r.returncode:
        return False, r.stderr.decode()[-200:]
    if not vulnerable:
        shutil.copy2(os.path.join(tmp, 'wintls.dll'), os.path.join(outdir, 'wintls.dll'))
    # second binary: exercises rpc_audit / toctou_audit / process_audit / credstore_audit
    open(os.path.join(tmp, 'helper.c'), 'w').write(HELPER_C)
    cmd = [mingw, '-o', os.path.join(outdir, 'AcmeHelper.exe'), os.path.join(tmp, 'helper.c'),
           '-lcrypt32', '-ladvapi32', '-lshell32', '-lrpcrt4']
    if vulnerable:
        cmd.insert(1, '-DVULN')
    r2 = subprocess.run(cmd, capture_output=True)
    note = 'ok' if r2.returncode == 0 else 'helper: ' + r2.stderr.decode()[-200:]
    shutil.rmtree(tmp, ignore_errors=True)
    return True, note


def build(root, vulnerable):
    out = os.path.join(root, 'vuln' if vulnerable else 'hardened')
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(os.path.join(out, 'resources', 'app'), exist_ok=True)
    os.makedirs(os.path.join(out, 'bin'), exist_ok=True)
    os.makedirs(os.path.join(out, 'tasks'), exist_ok=True)
    os.makedirs(os.path.join(out, 'nmh'), exist_ok=True)
    W = lambda p, c: open(os.path.join(out, p), 'w', encoding='utf-8').write(c)
    W('resources/app/main.js', VULN_MAIN_JS if vulnerable else HARD_MAIN_JS)
    W('resources/app/preload.js', VULN_PRELOAD if vulnerable else HARD_PRELOAD)
    W('resources/app/package.json',
      '{"name":"acme-desktop","version":"4.2.0","main":"main.js",'
      '"devDependencies":{"electron":"%s"}}' % ('10.4.7' if vulnerable else '31.3.1'))
    W('Acme.exe.config', VULN_CONFIG if vulnerable else HARD_CONFIG)
    W('handlers.reg', VULN_REG if vulnerable else HARD_REG)
    W('install.ps1', VULN_INSTALL_PS if vulnerable else HARD_INSTALL_PS)
    W('thirdparty.txt', VULN_BANNER if vulnerable else HARD_BANNER)
    # --- new-engine fixtures -------------------------------------------------
    W('com.reg', VULN_COM_REG if vulnerable else HARD_COM_REG)
    W('hooks.reg', VULN_HOOKS_REG if vulnerable else HARD_HOOKS_REG)
    W('nmh/com.acme.desktop.bridge.json', VULN_NMH if vulnerable else HARD_NMH)
    W('tasks/AcmeUpdate.xml', VULN_TASK if vulnerable else HARD_TASK)
    W('Acme.runtimeconfig.json', VULN_RUNTIMECFG if vulnerable else HARD_RUNTIMECFG)
    W('plugins_loader.py', VULN_PY if vulnerable else HARD_PY)
    W('AppxManifest.xml', VULN_APPX if vulnerable else HARD_APPX)
    import zipfile
    jar = os.path.join(out, 'bin', ('log4j-core-2.14.1.jar' if vulnerable else 'log4j-core-2.24.1.jar'))
    with zipfile.ZipFile(jar, 'w') as z:
        if vulnerable:
            for n, c in VULN_JAR_ENTRIES.items():
                z.writestr(n, c)
        else:
            z.writestr('META-INF/MANIFEST.MF', b'Manifest-Version: 1.0\nImplementation-Version: 2.24.1\n')
            z.writestr('org/apache/logging/log4j/core/Logger.class', b'\xca\xfe\xba\xbe')
    W('bin/launch.cmd',
      ('java -javaagent:C:\\ProgramData\\AcmeDesktop\\agent.jar -cp '
       'C:\\ProgramData\\AcmeDesktop\\bin\\*;acme.jar com.acme.Main\r\n')
      if vulnerable else
      ('java -cp "C:\\Program Files\\AcmeDesktop\\acme.jar" com.acme.Main\r\n'))
    ok, note = build_pe(out, vulnerable)
    return out, ok, note


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'range'))
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    for v in (True, False):
        d, ok, note = build(a.out, v)
        print(f"[range] {'vulnerable' if v else 'hardened '} -> {d}   PE build: {note}")
    print('[range] now run:  scripts/corpus_check.py')


if __name__ == '__main__':
    main()
