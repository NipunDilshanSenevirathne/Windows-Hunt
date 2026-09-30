// acl-check — does a NON-ADMIN principal have write access to C:\ProgramData\Target?
// Build: csc /nologo AclCheck.cs     Run: AclCheck.exe "C:\ProgramData\Target"
using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

class AclCheck {
    static void Main(string[] a) {
        string p = a.Length > 0 ? a[0] : @"C:\ProgramData\Target";
        Console.WriteLine("target : " + p);
        Console.WriteLine("running: " + WindowsIdentity.GetCurrent().Name);
        try {
            var ds = Directory.Exists(p)
                ? (FileSystemSecurity)new DirectoryInfo(p).GetAccessControl()
                : new FileInfo(p).GetAccessControl();
            Console.WriteLine("owner  : " + ds.GetOwner(typeof(NTAccount)));
            foreach (FileSystemAccessRule r in ds.GetAccessRules(true, true, typeof(NTAccount))) {
                string id = r.IdentityReference.Value;
                bool low = id.EndsWith(@"\Users") || id.Contains("Authenticated Users")
                        || id == "Everyone" || id.Contains("INTERACTIVE");
                bool w = (r.FileSystemRights & (FileSystemRights.Write | FileSystemRights.Modify
                        | FileSystemRights.FullControl | FileSystemRights.CreateFiles
                        | FileSystemRights.WriteData | FileSystemRights.ChangePermissions
                        | FileSystemRights.TakeOwnership)) != 0;
                if (low && w && r.AccessControlType == AccessControlType.Allow)
                    Console.WriteLine("  *** USER-WRITABLE: " + id + " => " + r.FileSystemRights);
            }
        } catch (Exception e) { Console.WriteLine("acl read failed: " + e.Message); }
        // ACLs can lie. Prove it.
        try {
            string t = Path.Combine(Directory.Exists(p) ? p : Path.GetDirectoryName(p),
                                    "wh_" + Guid.NewGuid().ToString("N").Substring(0,8) + ".tmp");
            File.WriteAllText(t, "");
            File.Delete(t);
            Console.WriteLine("  *** REAL WRITE SUCCEEDED as " + WindowsIdentity.GetCurrent().Name);
        } catch (Exception e) { Console.WriteLine("  real write failed: " + e.Message); }
    }
}
