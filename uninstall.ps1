# steam-tunnel uninstaller (Windows)
#   irm https://raw.githubusercontent.com/nobodys-tools/steam-tunnel/main/uninstall.ps1 | iex
$ErrorActionPreference = 'SilentlyContinue'

Stop-Process -Name 'steam-tunnel' -Force
Start-Sleep -Milliseconds 500

$Dir = Join-Path $env:LOCALAPPDATA 'steam-tunnel'
Remove-Item -Recurse -Force $Dir
Remove-Item -Force (Join-Path ([Environment]::GetFolderPath('Programs')) 'steam-tunnel.lnk')
Remove-Item -Force (Join-Path ([Environment]::GetFolderPath('Desktop')) 'steam-tunnel.lnk')
Remove-Item -Force (Join-Path ([Environment]::GetFolderPath('Startup')) 'steam-tunnel.lnk')

# drop the install dir from the user PATH again
$UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($UserPath) {
    $NewPath = ($UserPath -split ';' | Where-Object { $_ -and $_ -ne $Dir }) -join ';'
    [Environment]::SetEnvironmentVariable('Path', $NewPath, 'User')
}

Write-Host "steam-tunnel removed ($Dir, shortcuts, PATH entry, including its config)."
