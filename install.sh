#!/bin/sh
# steam-tunnel installer (Linux x86_64)
#   curl -fsSL https://raw.githubusercontent.com/nobodys-tools/steam-tunnel/main/install.sh | sh
set -eu

REPO="${STEAM_TUNNEL_REPO:-nobodys-tools/steam-tunnel}"
ASSET="steam-tunnel-x86_64-linux.tar.gz"
DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/steam-tunnel"
BIN_DIR="$HOME/.local/bin"
URL="https://github.com/$REPO/releases/latest/download/$ASSET"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading $URL ..."
if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$tmp/$ASSET" "$URL"
elif command -v wget >/dev/null 2>&1; then
    wget -qO "$tmp/$ASSET" "$URL"
else
    echo "error: need curl or wget" >&2
    exit 1
fi

# also works as an updater: stop a running instance so the binary can be replaced
pkill -x steam-tunnel 2>/dev/null && echo "Stopped running steam-tunnel for the update." || true

mkdir -p "$DATA_DIR" "$BIN_DIR"
tar -xzf "$tmp/$ASSET" -C "$DATA_DIR"
chmod +x "$DATA_DIR/steam-tunnel"

# Launcher: run from the data dir so steam_appid.txt, libsteam_api.so and the
# saved config are found. On NixOS the binary needs an FHS env -> steam-run.
cat > "$BIN_DIR/steam-tunnel" <<EOF
#!/bin/sh
cd "$DATA_DIR"
if command -v steam-run >/dev/null 2>&1; then
    # NixOS: run inside the Steam FHS env (glibc, libdbus, ...)
    exec steam-run env LD_LIBRARY_PATH="$DATA_DIR" "$DATA_DIR/steam-tunnel" "\$@"
fi
LD_LIBRARY_PATH="$DATA_DIR" exec "$DATA_DIR/steam-tunnel" "\$@"
EOF
chmod +x "$BIN_DIR/steam-tunnel"

# app-menu entry, so no terminal is ever needed
APPS_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
mkdir -p "$APPS_DIR"
cat > "$APPS_DIR/steam-tunnel.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=steam-tunnel
Comment=Play LAN games with Steam friends over Steam networking
Exec=$BIN_DIR/steam-tunnel
Icon=network-workgroup
Terminal=false
Categories=Network;Game;
EOF

# autostart is opt-in: STEAM_TUNNEL_AUTOSTART=1 curl ... | sh
if [ "${STEAM_TUNNEL_AUTOSTART:-}" = "1" ]; then
    mkdir -p "$HOME/.config/autostart"
    cp "$APPS_DIR/steam-tunnel.desktop" "$HOME/.config/autostart/steam-tunnel.desktop"
    echo "Autostart enabled (remove ~/.config/autostart/steam-tunnel.desktop to undo)."
fi

echo "Installed to $DATA_DIR"
echo "Launch 'steam-tunnel' from your app menu (it opens the web UI on first start)."
case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) echo "note: $BIN_DIR is not on your PATH — add it, or run $BIN_DIR/steam-tunnel" ;;
esac
echo "Start Steam, then run: steam-tunnel"
echo "Web UI: http://127.0.0.1:7788"
