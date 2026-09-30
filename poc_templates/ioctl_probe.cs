// ioctl_probe.cs — open a driver device as a standard user and walk its IOCTL surface.
//
// DO NOT RUN THIS WITHOUT A KERNEL DEBUGGER ATTACHED. A bugcheck with no debugger is a lost
// bug, and an unattended host will just reboot.
//
// Build: csc /nologo /unsafe ioctl_probe.cs
// Run:   ioctl_probe.exe \\.\TargetDevice [codes.txt]
using System;
using System.IO;
using System.Runtime.InteropServices;

class IoctlProbe {
    const uint GENERIC_READ = 0x80000000, GENERIC_WRITE = 0x40000000, OPEN_EXISTING = 3;
    [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateFile(string name, uint access, uint share, IntPtr sa,
                                    uint disp, uint flags, IntPtr tmpl);
    [DllImport("kernel32", SetLastError = true)]
    static extern bool DeviceIoControl(IntPtr h, uint code, byte[] inBuf, int inLen,
                                       byte[] outBuf, int outLen, out int ret, IntPtr ov);

    static void Main(string[] a) {
        string dev = a.Length > 0 ? a[0] : @"\\.\TargetDevice";
        Console.WriteLine("running as: " + System.Security.Principal.WindowsIdentity.GetCurrent().Name);
        IntPtr h = CreateFile(dev, GENERIC_READ | GENERIC_WRITE, 0, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
        if (h == (IntPtr)(-1)) {
            Console.WriteLine("[-] CreateFile failed: " + Marshal.GetLastWin32Error()
                              + "  (5 = access denied -> the device has a real DACL)");
            return;
        }
        Console.WriteLine("[+] DEVICE OPENED BY A STANDARD USER — the IOCTL surface is reachable");

        uint[] codes;
        if (a.Length > 1 && File.Exists(a[1])) {
            var lines = File.ReadAllLines(a[1]);
            codes = Array.ConvertAll(lines, l => Convert.ToUInt32(l.Trim(), 16));
        } else {
            codes = new uint[] { 0x22E000, 0x22E004, 0x22E008 };
        }
        var inBuf = new byte[0x40];
        var outBuf = new byte[0x40];
        foreach (var c in codes) {
            int ret;
            bool ok = DeviceIoControl(h, c, inBuf, inBuf.Length, outBuf, outBuf.Length, out ret, IntPtr.Zero);
            int err = Marshal.GetLastWin32Error();
            // 1 = ERROR_INVALID_FUNCTION (no such handler), 87 = INVALID_PARAMETER (handler EXISTS
            // and validated), 122 = INSUFFICIENT_BUFFER (handler exists, wants more)
            string note = ok ? "SUCCESS" : (err == 1 ? "no handler" : "HANDLER PRESENT (err " + err + ")");
            Console.WriteLine($"  0x{c:X8}  {note}  ret={ret}");
        }
    }
}
