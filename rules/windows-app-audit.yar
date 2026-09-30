/*
  windows-app-audit.yar — signals that matter when AUDITING a Windows application.

  Not malware rules. These fire on things a legitimate product does that create or reveal a
  privilege boundary problem. Run with:
      yara -r rules/windows-app-audit.yar loot/<name>/
*/

rule WH_SDDL_Everyone_FullControl {
  meta:
    description = "SDDL granting GENERIC_ALL/FULL to Everyone, Users or Authenticated Users"
    why = "On a service, pipe, file or registry object owned by SYSTEM this is the finding itself"
    severity = "high"
  strings:
    $wd_ga = "(A;;GA;;;WD)" ascii wide nocase
    $wd_fa = "(A;;FA;;;WD)" ascii wide nocase
    $bu_ga = "(A;;GA;;;BU)" ascii wide nocase
    $au_ga = "(A;;GA;;;AU)" ascii wide nocase
    $iu_ga = "(A;;GA;;;IU)" ascii wide nocase
    $nullacl = "D:NO_ACCESS_CONTROL" ascii wide nocase
  condition: any of them
}

rule WH_Service_Change_Config_For_Users {
  meta:
    description = "Service SDDL granting SERVICE_CHANGE_CONFIG (DC) to a non-admin principal"
    why = "sc config binPath + restart = code execution as the service account"
    severity = "high"
  strings:
    $a = /A;;[A-Z]{0,12}DC[A-Z]{0,12};;;(BU|AU|IU|WD)/ ascii wide
  condition: $a
}

rule WH_Icacls_Grant_Everyone {
  meta:
    description = "Install script granting Everyone/Users write access"
    severity = "high"
  strings:
    $a = /icacls[^\r\n]{1,200}\/grant[^\r\n]{0,60}(Everyone|Users|Authenticated Users)[^\r\n]{0,20}:\(?(OI\)\(CI\))?\(?(F|M|W)\)?/ nocase ascii wide
    $b = "cacls" nocase ascii wide
    $c = "/grant Everyone" nocase ascii wide
  condition: $a or ($b and $c)
}

rule WH_Unquoted_Service_Path {
  meta:
    description = "sc create with an unquoted binPath containing spaces"
    severity = "high"
  strings:
    $a = /sc(\.exe)?\s+create\s+\S{1,64}\s+binPath=\s*[A-Za-z]:\\[^"\r\n]{1,120}\s[^"\r\n]{1,80}/ nocase ascii wide
  condition: $a
}

rule WH_ProgramData_Executable_Path {
  meta:
    description = "An executable, DLL or script path under ProgramData/Public/Temp"
    why = "Default-writable by standard users; if a privileged process reads it, that is the LPE"
    severity = "medium"
  strings:
    $a = /C:\\ProgramData\\[^"\r\n<>|*?]{1,120}\.(exe|dll|ps1|bat|cmd|vbs|js|jar|py|node)/ nocase ascii wide
    $b = /C:\\Users\\Public\\[^"\r\n<>|*?]{1,120}\.(exe|dll|ps1|bat|cmd)/ nocase ascii wide
    $c = /C:\\(Windows\\)?Temp\\[^"\r\n<>|*?]{1,120}\.(exe|dll|ps1|bat|cmd)/ nocase ascii wide
  condition: any of them
}

rule WH_Electron_Insecure_WebPreferences {
  meta:
    description = "Electron window created with a security switch disabled"
    severity = "high"
  strings:
    $a = /nodeIntegration\s*:\s*true/ ascii wide
    $b = /contextIsolation\s*:\s*false/ ascii wide
    $c = /webSecurity\s*:\s*false/ ascii wide
    $d = /enableRemoteModule\s*:\s*true/ ascii wide
    $e = /nodeIntegrationInSubFrames\s*:\s*true/ ascii wide
  condition: any of them
}

rule WH_Electron_RunAsNode_Enabled {
  meta:
    description = "ELECTRON_RUN_AS_NODE / node CLI fuses referenced"
    why = "Any local process can restart the signed binary as a Node interpreter"
    severity = "medium"
  strings:
    $a = "ELECTRON_RUN_AS_NODE" ascii wide
    $b = "enableNodeCliInspectArguments" ascii wide
    $c = "runAsNode" ascii wide
  condition: any of them
}

rule WH_Dotnet_Unsafe_Deserializer {
  meta:
    description = ".NET deserializer that is unsafe with attacker-controlled input"
    severity = "critical"
  strings:
    $a = "BinaryFormatter" ascii wide
    $b = "NetDataContractSerializer" ascii wide
    $c = "LosFormatter" ascii wide
    $d = "ObjectStateFormatter" ascii wide
    $e = "SoapFormatter" ascii wide
    $f = "TypeNameHandling" ascii wide
  condition: any of them
}

rule WH_TLS_Validation_Disabled {
  meta:
    description = "Certificate validation overridden"
    severity = "high"
  strings:
    $a = "ServerCertificateValidationCallback" ascii wide
    $b = "ServerCertificateCustomValidationCallback" ascii wide
    $c = "CERT_IGNORE_CERT_CN_INVALID" ascii wide
    $d = "SECURITY_FLAG_IGNORE_UNKNOWN_CA" ascii wide
    $e = "INTERNET_FLAG_IGNORE_CERT_CN_INVALID" ascii wide
    $f = "CURLOPT_SSL_VERIFYPEER" ascii wide
  condition: any of them
}

rule WH_Cleartext_Update_Endpoint {
  meta:
    description = "http:// URL that looks like an update or download endpoint"
    severity = "high"
  strings:
    $a = /http:\/\/[a-z0-9.\-]{4,80}\/[^\s"'<>]{0,120}(update|upgrade|latest|release|appcast|RELEASES|manifest|setup|installer|\.msi|\.exe|\.nupkg)/ nocase ascii wide
  condition: $a
}

rule WH_Named_Pipe_Server {
  meta:
    description = "Named pipe endpoint"
    why = "Enumerate the protocol and check the DACL and impersonation"
    severity = "info"
  strings:
    $a = /\\\\\.\\pipe\\[A-Za-z0-9_.\-{}]{2,64}/ ascii wide
  condition: $a
}

rule WH_Localhost_Listener {
  meta:
    description = "Loopback HTTP/WebSocket endpoint"
    why = "Reachable from any web page unless it validates Origin AND authenticates"
    severity = "medium"
  strings:
    $a = /(https?|wss?):\/\/(127\.0\.0\.1|localhost|\[::1\]):\d{2,5}/ nocase ascii wide
    $b = /0\.0\.0\.0:\d{2,5}/ ascii wide
  condition: any of them
}

rule WH_Chromium_Exec_Flags {
  meta:
    description = "Chromium/Node flags that turn argument injection into code execution"
    severity = "high"
  strings:
    $a = "--gpu-launcher" ascii wide
    $b = "--utility-cmd-prefix" ascii wide
    $c = "--renderer-cmd-prefix" ascii wide
    $d = "--inspect-brk" ascii wide
    $e = "--remote-debugging-port" ascii wide
    $f = "--no-sandbox" ascii wide
  condition: any of them
}

rule WH_MSI_SystemCustomAction_Hint {
  meta:
    description = "Installer strings indicating deferred/no-impersonate execution"
    severity = "medium"
  strings:
    $a = "msidbCustomActionTypeNoImpersonate" ascii wide
    $b = "msidbCustomActionTypeInScript" ascii wide
    $c = "CustomActionData" ascii wide
  condition: any of them
}

rule WH_Hardcoded_Symmetric_Key {
  meta:
    description = "Literal key/IV byte array feeding a symmetric cipher"
    severity = "medium"
  strings:
    $a = /(Key|IV)\s*=\s*new\s+byte\[\]\s*\{\s*(0x[0-9A-Fa-f]{2}\s*,\s*){7,}/ ascii wide
    $b = "CipherMode.ECB" ascii wide
    $c = "PaddingMode.None" ascii wide
  condition: any of them
}
