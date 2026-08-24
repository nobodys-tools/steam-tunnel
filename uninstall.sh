#!/bin/sh
# steam-tunnel uninstaller (Linux)
#   curl -fsSL https://raw.githubusercontent.com/nobodys-tools/steam-tunnel/main/uninstall.sh | sh
set -eu

DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/steam-tunnel"
BIN="$HOME/.local/bin/steam-tunnel"

pkill -x steam-tunnel 2>/dev/null || true
rm -rf "$DATA_DIR"
rm -f "$BIN"
rm -f "${XDG_DATA_HOME:-$HOME/.local/share}/applications/steam-tunnel.desktop"
rm -f "$HOME/.config/autostart/steam-tunnel.desktop"

echo "steam-tunnel removed ($DATA_DIR and $BIN, including its config)."
