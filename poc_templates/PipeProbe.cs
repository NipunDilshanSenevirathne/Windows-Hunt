// pipe-client PoC — can a STANDARD USER open \\.\pipe\TargetPipe, and what does the server accept?
//
// Build: csc /nologo /out:PipeProbe.exe PipeProbe.cs      (or: dotnet build)
// Run as the LOWEST-privileged account you can. That is the whole point: if this connects
// and the server runs as SYSTEM, the protocol behind it is a privilege boundary.
using System;
using System.IO;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;

class PipeProbe {
    static void Main(string[] args) {
        string pipe = args.Length > 0 ? args[0] : "TargetPipe";
        Console.WriteLine("[*] running as: " + WindowsIdentity.GetCurrent().Name);
        Console.WriteLine("[*] connecting to \\\\.\\pipe\\" + pipe);
        try {
            using (var c = new NamedPipeClientStream(".", pipe, PipeDirection.InOut,
                                                     PipeOptions.None,
                                                     TokenImpersonationLevel.Anonymous)) {
                c.Connect(3000);
                Console.WriteLine("[+] CONNECTED as a non-privileged caller");
                // Identify the server side. Never send anything destructive.
                string probe = args.Length > 1 ? args[1] : "{\"method\":\"version\"}";
                var b = Encoding.UTF8.GetBytes(probe);
                c.Write(b, 0, b.Length);
                c.Flush();
                var buf = new byte[8192];
                c.ReadTimeout = 3000;
                int n = c.Read(buf, 0, buf.Length);
                Console.WriteLine("[+] server replied {0} bytes:", n);
                Console.WriteLine(Encoding.UTF8.GetString(buf, 0, n));
                File.AppendAllText(@"C:\Users\Public\wh_pipe_proof.txt",
                    DateTime.Now + " connected to " + pipe + " as " +
                    WindowsIdentity.GetCurrent().Name + " reply=" +
                    Encoding.UTF8.GetString(buf, 0, Math.Max(n,0)) + Environment.NewLine);
            }
        } catch (Exception e) {
            Console.WriteLine("[-] " + e.GetType().Name + ": " + e.Message);
        }
    }
}
