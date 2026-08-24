# steam-tunnel

<p align="center">
  <a href="https://github.com/nobodys-tools/steam-tunnel/releases/latest"><img src="https://img.shields.io/github/v/release/nobodys-tools/steam-tunnel?color=2ea44f" alt="Latest release"></a>
  <a href="https://github.com/nobodys-tools/steam-tunnel/actions/workflows/release.yml"><img src="https://github.com/nobodys-tools/steam-tunnel/actions/workflows/release.yml/badge.svg" alt="Build"></a>
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License: Apache-2.0">
  <img src="https://img.shields.io/badge/platforms-Linux%20%7C%20Windows-informational" alt="Platforms">
  <img src="https://img.shields.io/badge/Rust-2021-B7410E?logo=rust&logoColor=white" alt="Rust 2021">
  <img src="https://img.shields.io/badge/code-AI%20authored-8A2BE2" alt="AI authored">
</p>

**Tunnel local TCP ports to Steam friends — no port forwarding, no public IP,
no VPN setup.**

steam-tunnel makes a port on your machine (a game server, a web app, SSH, …)
reachable for your Steam friends. Traffic travels over Steam's peer-to-peer
networking and falls back to Valve's relay network (SDR) when a direct
connection isn't possible, so it works behind NAT and CGNAT without touching
your router.

- 🌐 **Web UI** on `http://127.0.0.1:7788` — share ports, connect to friends,
  live per-connection bandwidth, adjustable send-rate limit
- 🔀 **TCP and UDP** — stream tunnels for servers/SSH/web, datagram tunnels
  for game and voice traffic
- 📨 **Steam invites** — send a friend an invite for a shared port; an accept
  prompt pops up in their steam-tunnel
- 🔒 **Two auth layers** — Steam-authenticated SteamID gating (friends-only or
  explicit allowlist) plus an optional WireGuard-style pre-shared key
- 🖥️ **Tray icon** — open the UI or quit from the system tray
- 🪟🐧 Windows x86_64 and Linux x86_64 (NixOS supported via `steam-run`)

Both sides need the Steam client running & signed in, plus steam-tunnel.
Nobody needs to own any particular game (it uses Steam's shared test App ID
480).

## Install

**Windows** (PowerShell):

```powershell
irm https://raw.githubusercontent.com/nobodys-tools/steam-tunnel/main/install.ps1 | iex
```

**Linux**:

```sh
curl -fsSL https://raw.githubusercontent.com/nobodys-tools/steam-tunnel/main/install.sh | sh
```

The installers fetch the latest [release](https://github.com/nobodys-tools/steam-tunnel/releases),
install to `%LOCALAPPDATA%\steam-tunnel` (Start Menu shortcut) or
`~/.local/share/steam-tunnel` (`steam-tunnel` launcher in `~/.local/bin`,
auto-wrapped with `steam-run` on NixOS).

**Update**: just re-run the same install one-liner — it stops a running
instance, replaces the binaries with the latest release, and keeps your
config.

**Uninstall** just as easily:

```powershell
irm https://raw.githubusercontent.com/nobodys-tools/steam-tunnel/main/uninstall.ps1 | iex
```

```sh
curl -fsSL https://raw.githubusercontent.com/nobodys-tools/steam-tunnel/main/uninstall.sh | sh
```

## Quick start

1. Start Steam, then start steam-tunnel (both friends). The web UI opens at
   **http://127.0.0.1:7788** (also from the tray icon).
2. **Host:** *Share a local port* → e.g. `25565`. Optionally pick a friend and
   press **invite**. A share can also forward to another device on your
   network — set *forward to* to e.g. `192.168.1.50:8096` to share your NAS's
   Jellyfin under whatever port number you choose.
3. **Friend:** accept the invite banner in their web UI — or manually pick you
   under *Connect to a friend's port* and enter the port.
4. The friend points their program at `localhost:<port>` and lands on your
   service. The Connections table shows live up/down rates per connection.

*Their port* = the number the host shared on their machine. *Local port* =
where it appears on the guest's machine (defaults to the same number).

## Security

- **SteamID gating (always on).** Steam cryptographically authenticates the
  SteamID behind every P2P connection — identities can't be spoofed. By
  default only your Steam friends may connect; set a SteamID64 allowlist to
  restrict further (or to allow specific non-friends).
- **Pre-shared key (optional).** Generate one in the UI, share it with your
  friend over a private channel, and both enter it. Verified with a
  keyed-BLAKE3 nonce challenge–response — the key never travels over the
  wire. Transport encryption itself is provided by Steam's networking layer.
- Whatever port you share, allowed peers get full access to that service —
  treat it like giving them LAN access to that one port.

## Limitations

- UDP tunnels forward one local program per mapping (the last source address
  seen), and datagrams larger than ~1150 bytes fall back to Steam's reliable
  channel, which can add latency for oversized packets.
- Steam's default per-connection send-rate ceiling is ~1 MB/s; raise or lower
  it under *Security → Max send rate* (applies to new connections).
- App ID 480 is Valve's shared test ID; invites show up as "Spacewar" in
  Steam chat, and the invite's accept prompt only appears if the friend's
  steam-tunnel is already running.
- Dedicated/headless Steam setups and macOS are untested.

## Build from source

Needs docker/podman with compose:

```sh
docker compose run --rm builder
```

Output lands in `dist/` (binary, `libsteam_api.so`, `steam_appid.txt`). Run
it next to a running Steam client:

```sh
cd dist
LD_LIBRARY_PATH=. ./steam-tunnel          # regular Linux
LD_LIBRARY_PATH=. steam-run ./steam-tunnel  # NixOS
```

Config persists to `steam-tunnel.json` in the working directory (`ui_port`
configurable there). Releases are built by GitHub Actions on `v*` tags.

## How it works

One Steam P2P connection per TCP connection; the shared TCP port doubles as
the Steam "virtual port". The host accepts a connection (SteamID check),
challenges for the PSK if configured, then splices bytes between the Steam
connection and `127.0.0.1:<port>`. Invites ride on Steam's
`InviteUserToGame` / rich-presence-join mechanism with a
`steam-tunnel-v1:<port>` connect string.

## License

[Apache-2.0](LICENSE). The Steamworks redistributable libraries
(`libsteam_api.so` / `steam_api64.dll`) included in release archives are
proprietary Valve software distributed under the Steamworks SDK terms.
