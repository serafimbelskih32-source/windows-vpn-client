#!/bin/sh
# Builds the program on Linux or macOS: downloads the sing-box core (not stored in git) and runs PyInstaller.
# Needs Python 3.12+ with tkinter (Linux: python3-tk; macOS: the python.org installer or Homebrew python-tk).
set -e
V="1.13.14"
cd "$(dirname "$0")"
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)               CORE=linux-amd64 ;;
  Linux-aarch64|Linux-arm64)  CORE=linux-arm64 ;;
  Darwin-arm64)               CORE=darwin-arm64 ;;
  Darwin-x86_64)              CORE=darwin-amd64 ;;
  *) echo "unsupported system: $(uname -sm)"; exit 1 ;;
esac
if [ ! -x core/sing-box ]; then
  N="sing-box-$V-$CORE"
  TMP="$(mktemp -d)"
  mkdir -p core
  curl -sSL --fail -o "$TMP/sb.tgz" "https://github.com/SagerNet/sing-box/releases/download/v$V/$N.tar.gz"
  tar -xzf "$TMP/sb.tgz" -C "$TMP"
  cp "$TMP/$N/sing-box" core/sing-box
  chmod +x core/sing-box
  rm -rf "$TMP"
fi
python3 -m pip install pyinstaller pillow pystray
python3 make_icon.py
if [ "$(uname -s)" = "Darwin" ]; then
  python3 -m PyInstaller --noconfirm --windowed --name FimaVPN --icon icon.icns --collect-submodules pystray \
    --add-data "core:core" --add-data "icon.png:." vpn.py
  find dist/FimaVPN.app -name sing-box -type f -exec codesign --force -s - {} \;
  codesign --force --deep -s - dist/FimaVPN.app
  echo "Done: dist/FimaVPN.app"
else
  python3 -m PyInstaller --noconfirm --onefile --name FimaVPN --collect-submodules pystray \
    --add-data "core:core" --add-data "icon.png:." vpn.py
  echo "Done: dist/FimaVPN"
fi
