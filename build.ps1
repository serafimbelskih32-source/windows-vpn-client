# Downloads the sing-box core (not stored in git) and builds dist\FimaVPN.exe.
# Needs a full Python 3.12+ with tkinter (python.org installer) and pip.
$ErrorActionPreference = "Stop"
$ver = "1.13.14"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $here

if (-not (Test-Path "core\sing-box.exe")) {
    $zip = Join-Path $env:TEMP "sing-box-$ver.zip"
    Invoke-WebRequest "https://github.com/SagerNet/sing-box/releases/download/v$ver/sing-box-$ver-windows-amd64.zip" -OutFile $zip
    $tmp = Join-Path $env:TEMP "sing-box-$ver"
    Expand-Archive $zip -DestinationPath $tmp -Force
    Copy-Item "$tmp\sing-box-$ver-windows-amd64\*" core -Force
}

python -m pip install pyinstaller pillow pystray certifi pyyaml
python make_icon.py
python -m PyInstaller --noconfirm --onefile --windowed --uac-admin --name FimaVPN --icon icon.ico `
    --collect-submodules pystray --collect-data certifi --add-data "core;core" --add-data "icon.ico;." --add-data "icon.png;." vpn.py
Write-Host "Done: dist\FimaVPN.exe"
