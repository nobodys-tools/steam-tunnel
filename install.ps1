# steam-tunnel installer (Windows x86_64)
#   irm https://raw.githubusercontent.com/nobodys-tools/steam-tunnel/main/install.ps1 | iex
$ErrorActionPreference = 'Stop'

$Repo = if ($env:STEAM_TUNNEL_REPO) { $env:STEAM_TUNNEL_REPO } else { 'nobodys-tools/steam-tunnel' }

$Asset = 'steam-tunnel-x86_64-windows.zip'
$Url = "https://github.com/$Repo/releases/latest/download/$Asset"
$Dir = Join-Path $env:LOCALAPPDATA 'steam-tunnel'
$Zip = Join-Path $env:TEMP $Asset

Write-Host "Downloading $Url ..."
Invoke-WebRequest -Uri $Url -OutFile $Zip

# also works as an updater: stop a running instance so the exe can be replaced
Stop-Process -Name 'steam-tunnel' -Force -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 500

New-Item -ItemType Directory -Force -Path $Dir | Out-Null
Expand-Archive -Path $Zip -DestinationPath $Dir -Force
Remove-Item $Zip

# Start Menu + Desktop shortcuts (working dir matters: steam_appid.txt + config live there)
$Shell = New-Object -ComObject WScript.Shell
foreach ($Folder in @([Environment]::GetFolderPath('Programs'), [Environment]::GetFolderPath('Desktop'))) {
    $Lnk = $Shell.CreateShortcut((Join-Path $Folder 'steam-tunnel.lnk'))
    $Lnk.TargetPath = Join-Path $Dir 'steam-tunnel.exe'
    $Lnk.WorkingDirectory = $Dir
    $Lnk.Description = 'Tunnel local ports to Steam friends'
    $Lnk.Save()
}

# autostart is opt-in: $env:STEAM_TUNNEL_AUTOSTART=1; irm ... | iex
if ($env:STEAM_TUNNEL_AUTOSTART -eq '1') {
    $Startup = [Environment]::GetFolderPath('Startup')
    $Lnk = $Shell.CreateShortcut((Join-Path $Startup 'steam-tunnel.lnk'))
    $Lnk.TargetPath = Join-Path $Dir 'steam-tunnel.exe'
    $Lnk.WorkingDirectory = $Dir
    $Lnk.Save()
    Write-Host "Autostart enabled (remove the Startup shortcut to undo)."
}

# put the install dir on the user PATH so `steam-tunnel` works in terminals
$UserPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not $UserPath) { $UserPath = '' }
if (($UserPath -split ';') -notcontains $Dir) {
    [Environment]::SetEnvironmentVariable('Path', ($UserPath.TrimEnd(';') + ';' + $Dir), 'User')
    Write-Host "Added $Dir to your user PATH — open a NEW terminal for 'steam-tunnel' to work."
}

Write-Host "Installed to $Dir (shortcuts: Start Menu and Desktop)"
Write-Host "Start Steam, then launch steam-tunnel."
Write-Host "Web UI: http://127.0.0.1:7788"
