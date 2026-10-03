Write-Host "Hello, World!"

$popup = New-Object -ComObject WScript.Shell
$popup.Popup("Hello, World!", 0, "payload", 0) | Out-Null
