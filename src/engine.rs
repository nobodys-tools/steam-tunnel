use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use steamworks::networking_sockets::{ListenSocket, NetConnection, NetworkingSockets};
use steamworks::networking_types::{
    AppNetConnectionEnd,
    ListenSocketEvent, NetConnectionEnd, NetworkingConfigEntry, NetworkingConfigValue,
    NetworkingConnectionState, NetworkingIdentity, SendFlags,
};
use steamworks::{Client, FriendFlags, SteamId};

use crate::detect;
use crate::state::{
    append_history, AppRow, Command, ConnRow, FriendRow, HistoryRow, InviteRow, MappingRow,
    Shared, ShareRow, HISTORY_KEEP,
};

const CHUNK: usize = 16 * 1024;
const UDP_BUF: usize = 65536;
const MAX_READS_PER_TICK: usize = 8;
const MAX_DGRAMS_PER_TICK: usize = 64;
/// Steam unreliable messages must fit in one packet (~1200 bytes incl. overhead)
const MAX_UNRELIABLE: usize = 1150;
const PRE_BUF_CAP: usize = 4 * 1024 * 1024;
const TCP_OUT_CAP: usize = 64 * 1024 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const UDP_RESPAWN_DELAY: Duration = Duration::from_secs(3);
/// An outgoing tunnel with no streams left is kept warm this long so the next
/// local connection skips the Steam connect + handshake round-trips.
const TUNNEL_LINGER: Duration = Duration::from_secs(120);
/// UDP flows (one per local source address) die after this much silence;
/// the next datagram from that source transparently re-opens one.
const UDP_FLOW_IDLE: Duration = Duration::from_secs(120);
/// per mapping — a runaway program cycling source ports must not open
/// unbounded Steam streams
const MAX_UDP_FLOWS: usize = 64;

const INVITE_PREFIX: &str = "steam-tunnel-v1:";

// Protocol v3: one Steam connection ("tunnel") per peer and port, carrying any
// number of streams — TCP connections or UDP flows — so only the first
// connection to a peer pays the connect + handshake round-trips. The Steam
// virtual port is just the port number (values above 65535 are rejected by
// Steam), so the client declares its protocol in the auth frame and the host
// verifies it against what the share expects.
const M_HELLO: &[u8; 4] = b"STH3"; // host -> client: magic + flags(1) + nonce(32)
const M_AUTH: &[u8; 4] = b"STA3"; // client -> host: magic + mac(32) + proto(1)
const M_NOAUTH: &[u8; 4] = b"STN3"; // client -> host: magic + proto(1)
const M_OK: &[u8; 4] = b"STK3"; // host -> client: tunnel open

// Handshake frames carry the sender's version as trailing UTF-8 bytes so both
// sides can show what the peer runs and diagnose mismatches.
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

// After the handshake every message is [type, stream id (u32 BE), payload].
// Streams are opened by the client (F_OPEN), carry data (F_DATA), half-close
// per direction (F_EOF, so TCP shutdown works), and are torn down with
// F_CLOSE when they end abnormally. A stream that finishes cleanly (both
// sides sent F_EOF and drained) is dropped by both ends without F_CLOSE.
const F_DATA: u8 = 0;
const F_EOF: u8 = 1;
const F_OPEN: u8 = 2;
const F_CLOSE: u8 = 3;
/// frame header: type byte + stream id
const HDR: usize = 5;

fn frame(ftype: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(HDR + payload.len());
    f.push(ftype);
    f.extend_from_slice(&sid.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// Send a reliable frame, queueing it if Steam's send buffer is full. Queued
/// frames are retried in order every pump; while any are queued no local
/// sockets are read (backpressure), so the queue stays small.
fn send_rel(steam: &NetConnection, pending: &mut VecDeque<Vec<u8>>, f: Vec<u8>) {
    if !pending.is_empty() {
        pending.push_back(f);
        return;
    }
    if steam.send_message(&f, SendFlags::RELIABLE).is_err() {
        pending.push_back(f);
    }
}

fn conn_options(send_rate_kib: u32) -> Vec<NetworkingConfigEntry> {
    if send_rate_kib == 0 {
        return Vec::new();
    }
    let rate = (send_rate_kib as i32).saturating_mul(1024);
    vec![
        NetworkingConfigEntry::new_int32(NetworkingConfigValue::SendRateMin, rate.min(128 * 1024)),
        NetworkingConfigEntry::new_int32(NetworkingConfigValue::SendRateMax, rate),
    ]
}

/// Resolve "host:port" to a socket address (first result).
fn resolve_target(target: &str) -> Option<SocketAddr> {
    use std::net::ToSocketAddrs;
    target.to_socket_addrs().ok()?.next()
}

/// Fresh random nonce; None if the OS RNG is unavailable (then the caller
/// must refuse the operation rather than fall back to a predictable value).
fn fresh_nonce() -> Option<[u8; 32]> {
    let mut n = [0u8; 32];
    getrandom::getrandom(&mut n).ok().map(|_| n)
}

fn psk_key(psk: &str) -> [u8; 32] {
    blake3::derive_key("steam-tunnel psk v1", psk.as_bytes())
}

fn psk_mac(psk: &str, nonce: &[u8; 32]) -> [u8; 32] {
    *blake3::keyed_hash(&psk_key(psk), nonce).as_bytes()
}

/// GameRichPresenceJoinRequested_t — fired in the *running* app when a friend
/// accepts a Steam invite we sent with `invite_user_to_game`. The steamworks
/// crate doesn't wrap this one, so implement the Callback trait over the raw
/// sys struct (same pattern the crate uses for GameLobbyJoinRequested).
struct RichPresenceJoinRequested {
    friend: SteamId,
    connect: String,
}

unsafe impl steamworks::Callback for RichPresenceJoinRequested {
    const ID: i32 = steamworks::sys::GameRichPresenceJoinRequested_t_k_iCallback as i32;

    unsafe fn from_raw(raw: *mut std::ffi::c_void) -> Self {
        let val = &*(raw as *const steamworks::sys::GameRichPresenceJoinRequested_t);
        RichPresenceJoinRequested {
            friend: SteamId::from_raw(val.m_steamIDFriend.m_steamid.m_unAll64Bits),
            connect: std::ffi::CStr::from_ptr(val.m_rgchConnect.as_ptr())
                .to_string_lossy()
                .into_owned(),
        }
    }
}

enum ConnState {
    /// host side: HELLO sent, waiting for AUTH/NOAUTH
    AwaitAuth,
    /// client side: waiting for HELLO
    AwaitHello,
    /// client side: AUTH sent, waiting for OK
    AwaitOk,
    Active,
}

#[derive(Clone, Copy, PartialEq)]
enum Dir {
    In,
    Out,
}

enum LocalSock {
    Tcp(TcpStream),
    /// Host side: socket `connect()`ed to the local service, one per flow
    /// (peer None). Client side: a clone of the mapping's bound socket used
    /// for replies only; peer = the flow's local source address. Client
    /// reads happen at the mapping level, which dispatches to flows.
    Udp { sock: UdpSocket, peer: Option<SocketAddr> },
}

/// One TCP connection or UDP flow, multiplexed over a tunnel's Steam
/// connection. Stream ids are allocated by the client side.
struct Stream {
    id: u32,
    /// client side: the mapping this stream belongs to
    mapping_id: Option<u64>,
    local: Option<LocalSock>,
    /// TCP only: bytes received over Steam, waiting for the local socket
    tcp_out: VecDeque<u8>,
    /// client TCP only: bytes read before the tunnel handshake finished
    pre_buf: Vec<u8>,
    /// client side: F_OPEN sent (false while the tunnel is still handshaking)
    open_sent: bool,
    /// local side stopped sending (we sent F_EOF)
    tcp_eof: bool,
    /// peer sent F_EOF (no more incoming data)
    remote_eof: bool,
    /// we already shutdown the write half of the local socket
    wr_shutdown: bool,
    /// peer sent F_CLOSE: stop reading, flush what's buffered, then drop
    reset: bool,
    /// UDP only: last datagram seen in either direction (flow expiry)
    last_activity: Instant,
    tx_bytes: u64,
    rx_bytes: u64,
    dead: Option<String>,
}

fn new_stream(id: u32, mapping_id: Option<u64>, local: Option<LocalSock>) -> Stream {
    Stream {
        id,
        mapping_id,
        local,
        tcp_out: VecDeque::new(),
        pre_buf: Vec::new(),
        open_sent: false,
        tcp_eof: false,
        remote_eof: false,
        wr_shutdown: false,
        reset: false,
        last_activity: Instant::now(),
        tx_bytes: 0,
        rx_bytes: 0,
        dead: None,
    }
}

impl Stream {
    fn mark_dead(&mut self, why: &str) {
        if self.dead.is_none() {
            self.dead = Some(why.to_string());
        }
    }
}

/// One Steam connection to a peer for one shared port, carrying all streams.
struct Tunnel {
    id: u64,
    dir: Dir,
    peer: SteamId,
    port: u16,
    udp: bool,
    steam: NetConnection,
    state: ConnState,
    created: Instant,
    /// host side: the random challenge sent in HELLO; None on client tunnels
    nonce: Option<[u8; 32]>,
    /// host side: where this share forwards to ("host:port")
    target: String,
    /// version string the peer sent in the handshake
    peer_version: String,
    /// client side: next stream id to hand out
    next_stream_id: u32,
    streams: Vec<Stream>,
    /// total streams this tunnel has carried (for history)
    streams_served: u64,
    /// reliable frames Steam refused (send buffer full), retried in order
    pending: VecDeque<Vec<u8>>,
    /// refreshed while streams exist; when empty for TUNNEL_LINGER the
    /// client side closes the tunnel
    idle_since: Instant,
    /// from Steam's realtime connection status; -1 = not measured yet
    ping_ms: i32,
    /// worst of local/remote packet delivery rate, 0..1; -1 = unknown
    quality: f32,
    tx_bytes: u64,
    rx_bytes: u64,
    tx_rate: u64,
    rx_rate: u64,
    last_tx: u64,
    last_rx: u64,
    dead: Option<String>,
}

impl Tunnel {
    fn mark_dead(&mut self, why: &str) {
        if self.dead.is_none() {
            self.dead = Some(why.to_string());
        }
    }

    fn alloc_stream_id(&mut self) -> u32 {
        let id = self.next_stream_id;
        self.next_stream_id += 1;
        id
    }
}

fn new_tunnel(
    id: u64,
    dir: Dir,
    peer: SteamId,
    port: u16,
    udp: bool,
    steam: NetConnection,
    state: ConnState,
    nonce: Option<[u8; 32]>,
    target: String,
) -> Tunnel {
    Tunnel {
        id,
        dir,
        peer,
        port,
        udp,
        steam,
        state,
        created: Instant::now(),
        nonce,
        target,
        peer_version: String::new(),
        next_stream_id: 1,
        streams: Vec::new(),
        streams_served: 0,
        pending: VecDeque::new(),
        idle_since: Instant::now(),
        ping_ms: -1,
        quality: -1.0,
        tx_bytes: 0,
        rx_bytes: 0,
        tx_rate: 0,
        rx_rate: 0,
        last_tx: 0,
        last_rx: 0,
        dead: None,
    }
}

struct Share {
    port: u16,
    udp: bool,
    /// forward target ("host:port"); resolved per stream so DNS/mDNS
    /// names keep working when addresses change
    target: String,
    listen: ListenSocket,
}

struct Mapping {
    id: u64,
    peer: SteamId,
    peer_name: String,
    remote_port: u16,
    local_port: u16,
    udp: bool,
    /// TCP: local listener
    listener: Option<TcpListener>,
    /// UDP: the bound local socket; every flow replies through a clone of it
    sock: Option<UdpSocket>,
    last_spawn: Instant,
}

pub fn run(shared: Shared) {
    loop {
        match Client::init_app(480) {
            Ok(client) => {
                {
                    let mut s = shared.lock().unwrap();
                    s.snapshot.steam_ok = true;
                    s.snapshot.steam_error.clear();
                }
                run_engine(client, &shared);
            }
            Err(e) => {
                let mut s = shared.lock().unwrap();
                s.snapshot.steam_ok = false;
                s.snapshot.steam_error =
                    format!("Steam init failed: {e}. Is the Steam client running and signed in?");
            }
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}

fn log(shared: &Shared, msg: String) {
    let mut s = shared.lock().unwrap();
    s.snapshot.log.push(msg);
    let len = s.snapshot.log.len();
    if len > 200 {
        s.snapshot.log.drain(0..len - 200);
    }
}

/// Find or create the outgoing tunnel to (peer, port, proto); returns its
/// index in `tunnels`, or None when connect_p2p fails.
fn ensure_out_tunnel(
    tunnels: &mut Vec<Tunnel>,
    sockets: &NetworkingSockets,
    peer: SteamId,
    port: u16,
    udp: bool,
    rate: u32,
    next_id: &mut u64,
) -> Option<usize> {
    if let Some(i) = tunnels.iter().position(|t| {
        t.dead.is_none() && t.dir == Dir::Out && t.peer == peer && t.port == port && t.udp == udp
    }) {
        return Some(i);
    }
    match sockets.connect_p2p(
        NetworkingIdentity::new_steam_id(peer),
        port as i32,
        conn_options(rate),
    ) {
        Ok(steam) => {
            tunnels.push(new_tunnel(
                *next_id,
                Dir::Out,
                peer,
                port,
                udp,
                steam,
                ConnState::AwaitHello,
                None,
                String::new(),
            ));
            *next_id += 1;
            Some(tunnels.len() - 1)
        }
        Err(_) => None,
    }
}

fn run_engine(client: Client, shared: &Shared) {
    client.networking_utils().init_relay_network_access();

    let sockets = client.networking_sockets();
    let mut shares: Vec<Share> = Vec::new();
    let mut mappings: Vec<Mapping> = Vec::new();
    let mut tunnels: Vec<Tunnel> = Vec::new();
    let mut invites: Vec<InviteRow> = Vec::new();
    let mut next_id: u64 = 1;

    // queue filled by the Steam callback (runs inside run_callbacks below)
    let invite_queue: std::sync::Arc<std::sync::Mutex<Vec<RichPresenceJoinRequested>>> =
        Default::default();
    let _invite_cb = {
        let queue = invite_queue.clone();
        client.register_callback(move |req: RichPresenceJoinRequested| {
            queue.lock().unwrap().push(req);
        })
    };

    let (ui_port, games) = {
        let s = shared.lock().unwrap();
        (s.config.ui_port, s.snapshot.games.clone())
    };

    let me_id = client.user().steam_id();
    let me_name = client.friends().name();
    {
        let mut s = shared.lock().unwrap();
        s.snapshot.me.name = me_name;
        s.snapshot.me.steam_id = me_id.raw().to_string();
    }

    let mut last_friends = Instant::now() - Duration::from_secs(60);
    let mut last_stats = Instant::now();
    let mut last_health = Instant::now();

    loop {
        client.run_callbacks();

        // ---- commands from the web UI ----
        let (cmds, psk, allowlist, rate) = {
            let mut s = shared.lock().unwrap();
            (
                std::mem::take(&mut s.commands),
                s.config.psk.clone(),
                s.config.allowlist_ids(),
                s.config.send_rate_kib,
            )
        };
        for cmd in cmds {
            match cmd {
                Command::Share { port, udp, target } => {
                    let target = target.unwrap_or_else(|| format!("127.0.0.1:{port}"));
                    if let Some(existing) = shares.iter().find(|sh| sh.port == port) {
                        if existing.udp != udp {
                            let p = if existing.udp { "udp" } else { "tcp" };
                            log(shared, format!("Port {port} is already shared as {p} — one protocol per port"));
                        }
                        continue;
                    }
                    match sockets.create_listen_socket_p2p(port as i32, conn_options(rate)) {
                        Ok(listen) => {
                            let proto = if udp { "udp" } else { "tcp" };
                            log(shared, format!("Sharing {proto} port {port} -> {target}"));
                            shares.push(Share { port, udp, target, listen });
                        }
                        Err(_) => log(shared, format!("Failed to open listen socket for port {port}")),
                    }
                }
                Command::Unshare { port, udp } => {
                    shares.retain(|sh| !(sh.port == port && sh.udp == udp));
                    for t in tunnels.iter_mut() {
                        if t.dir == Dir::In && t.port == port && t.udp == udp {
                            t.mark_dead("share removed");
                        }
                    }
                    log(shared, format!("Stopped sharing port {port}"));
                }
                Command::Connect { peer, remote_port, local_port, udp } => {
                    let peer_id = SteamId::from_raw(peer);
                    let peer_name = client.friends().get_friend(peer_id).name();
                    if udp {
                        // socket + tunnel are created lazily by the spawn pass below
                        log(
                            shared,
                            format!("Mapping localhost:{local_port} -> {peer_name}:{remote_port} (udp)"),
                        );
                        mappings.push(Mapping {
                            id: next_id,
                            peer: peer_id,
                            peer_name,
                            remote_port,
                            local_port,
                            udp: true,
                            listener: None,
                            sock: None,
                            last_spawn: Instant::now() - UDP_RESPAWN_DELAY,
                        });
                        next_id += 1;
                    } else {
                        let addr: SocketAddr = ([127, 0, 0, 1], local_port).into();
                        match TcpListener::bind(addr) {
                            Ok(listener) => {
                                listener.set_nonblocking(true).ok();
                                log(
                                    shared,
                                    format!("Mapping localhost:{local_port} -> {peer_name}:{remote_port}"),
                                );
                                mappings.push(Mapping {
                                    id: next_id,
                                    peer: peer_id,
                                    peer_name,
                                    remote_port,
                                    local_port,
                                    udp: false,
                                    listener: Some(listener),
                                    sock: None,
                                    last_spawn: Instant::now(),
                                });
                                next_id += 1;
                            }
                            Err(e) => log(shared, format!("Cannot bind localhost:{local_port}: {e}")),
                        }
                    }
                }
                Command::StopMapping { id } => {
                    for t in tunnels.iter_mut() {
                        for st in t.streams.iter_mut() {
                            if st.mapping_id == Some(id) {
                                st.mark_dead("mapping removed");
                            }
                        }
                    }
                    mappings.retain(|m| m.id != id);
                    log(shared, format!("Mapping {id} removed"));
                }
                Command::Invite { peer, port, udp } => {
                    let peer_id = SteamId::from_raw(peer);
                    let friend = client.friends().get_friend(peer_id);
                    let name = friend.name();
                    let connect = if udp {
                        format!("{INVITE_PREFIX}{port}:udp")
                    } else {
                        format!("{INVITE_PREFIX}{port}")
                    };
                    friend.invite_user_to_game(&connect);
                    log(shared, format!("Steam invite for port {port} sent to {name}"));
                }
                Command::DismissInvite { id } => {
                    invites.retain(|i| i.id != id);
                }
                Command::SetSettings { psk, allowlist, send_rate_kib } => {
                    let rate_changed = {
                        let mut s = shared.lock().unwrap();
                        let changed = s.config.send_rate_kib != send_rate_kib;
                        if let Some(psk) = psk {
                            s.config.psk = psk;
                        }
                        s.config.allowlist = allowlist;
                        s.config.send_rate_kib = send_rate_kib;
                        s.config.save();
                        s.snapshot.psk_set = !s.config.psk.is_empty();
                        s.snapshot.allowlist = s.config.allowlist.clone();
                        s.snapshot.send_rate_kib = send_rate_kib;
                        changed
                    };
                    // listen sockets carry the rate config; recreate them so
                    // new incoming tunnels pick up the new rate
                    if rate_changed {
                        let old: Vec<(u16, bool, String)> = shares
                            .iter()
                            .map(|sh| (sh.port, sh.udp, sh.target.clone()))
                            .collect();
                        shares.clear();
                        for (port, udp, target) in old {
                            if let Ok(listen) = sockets
                                .create_listen_socket_p2p(port as i32, conn_options(send_rate_kib))
                            {
                                shares.push(Share { port, udp, target, listen });
                            }
                        }
                        log(shared, "Send rate updated (applies to new tunnels)".into());
                    }
                }
            }
        }

        // ---- incoming Steam invites (friend sent us one) ----
        for req in invite_queue.lock().unwrap().drain(..) {
            if let Some(rest) = req.connect.strip_prefix(INVITE_PREFIX) {
                let (port_str, udp) = match rest.strip_suffix(":udp") {
                    Some(p) => (p, true),
                    None => (rest, false),
                };
                if let Ok(port) = port_str.trim().parse::<u16>() {
                    let from = req.friend.raw().to_string();
                    let from_name = client.friends().get_friend(req.friend).name();
                    log(
                        shared,
                        format!("{from_name} invites you to connect to their port {port}"),
                    );
                    invites.retain(|i| !(i.from == from && i.port == port && i.udp == udp));
                    invites.push(InviteRow { id: next_id, from, from_name, port, udp });
                    next_id += 1;
                }
            }
        }

        // ---- incoming Steam connections on shared ports ----
        for share in &shares {
            while let Some(event) = share.listen.try_receive_event() {
                match event {
                    ListenSocketEvent::Connecting(req) => {
                        let sid = req.remote().steam_id();
                        let ok = match sid {
                            Some(sid) => peer_allowed(&client, sid, &allowlist),
                            None => false,
                        };
                        if ok {
                            if req.accept().is_err() {
                                log(shared, "Failed to accept connection".into());
                            }
                        } else {
                            let who = sid.map(|s| s.raw().to_string()).unwrap_or_default();
                            log(shared, format!("Rejected connection from {who} (not allowed)"));
                            req.reject(NetConnectionEnd::App(AppNetConnectionEnd::generic_normal()), Some("not allowed"));
                        }
                    }
                    ListenSocketEvent::Connected(ev) => {
                        if let Some(sid) = ev.remote().steam_id() {
                            let steam = ev.take_connection();
                            let nonce = match fresh_nonce() {
                                Some(n) => n,
                                None => {
                                    // never hand out a predictable challenge
                                    log(shared, "OS random generator unavailable, dropping connection".into());
                                    continue;
                                }
                            };
                            let mut hello = Vec::with_capacity(37 + APP_VERSION.len());
                            hello.extend_from_slice(M_HELLO);
                            hello.push(if psk.is_empty() { 0 } else { 1 });
                            hello.extend_from_slice(&nonce);
                            hello.extend_from_slice(APP_VERSION.as_bytes());
                            let _ = steam.send_message(&hello, SendFlags::RELIABLE);
                            let peer_name = client.friends().get_friend(sid).name();
                            log(shared, format!("Incoming tunnel from {peer_name} to port {}", share.port));
                            tunnels.push(new_tunnel(
                                next_id,
                                Dir::In,
                                sid,
                                share.port,
                                share.udp,
                                steam,
                                ConnState::AwaitAuth,
                                Some(nonce),
                                share.target.clone(),
                            ));
                            next_id += 1;
                        }
                    }
                    ListenSocketEvent::Disconnected(ev) => {
                        if let Some(sid) = ev.remote().steam_id() {
                            for t in tunnels.iter_mut() {
                                if t.dir == Dir::In
                                    && t.peer == sid
                                    && t.port == share.port
                                    && t.dead.is_none()
                                {
                                    t.mark_dead("peer disconnected");
                                }
                            }
                        }
                    }
                }
            }
        }

        // ---- local TCP accepts / UDP stream (re)spawn for outgoing mappings ----
        for m in mappings.iter_mut() {
            if m.udp {
                // bind the local socket once; retry with a delay on failure
                if m.sock.is_none() && m.last_spawn.elapsed() >= UDP_RESPAWN_DELAY {
                    m.last_spawn = Instant::now();
                    let addr: SocketAddr = ([127, 0, 0, 1], m.local_port).into();
                    match UdpSocket::bind(addr) {
                        Ok(sock) => {
                            sock.set_nonblocking(true).ok();
                            m.sock = Some(sock);
                        }
                        Err(e) => {
                            log(shared, format!("Cannot bind udp localhost:{}: {e}", m.local_port))
                        }
                    }
                }
                // keep a tunnel warm so the handshake is already done when
                // the local program starts talking
                let have_tunnel = tunnels.iter().any(|t| {
                    t.dead.is_none()
                        && t.dir == Dir::Out
                        && t.peer == m.peer
                        && t.port == m.remote_port
                        && t.udp
                });
                if m.sock.is_some() && !have_tunnel && m.last_spawn.elapsed() >= UDP_RESPAWN_DELAY {
                    m.last_spawn = Instant::now();
                    if ensure_out_tunnel(
                        &mut tunnels,
                        &sockets,
                        m.peer,
                        m.remote_port,
                        true,
                        rate,
                        &mut next_id,
                    )
                    .is_none()
                    {
                        log(shared, "connect_p2p failed".into());
                    }
                }
                // dispatch datagrams: one stream ("flow") per local source
                // address, so several programs — or several players' game
                // instances — can use the same mapping at once
                if let Some(sock) = &m.sock {
                    let mut buf = [0u8; UDP_BUF + HDR];
                    buf[0] = F_DATA;
                    for _ in 0..MAX_DGRAMS_PER_TICK {
                        let (n, src) = match sock.recv_from(&mut buf[HDR..]) {
                            Ok(v) => v,
                            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                            Err(_) => break,
                        };
                        let Some(ti) = tunnels.iter().position(|t| {
                            t.dead.is_none()
                                && t.dir == Dir::Out
                                && t.peer == m.peer
                                && t.port == m.remote_port
                                && t.udp
                        }) else {
                            continue; // no tunnel yet — UDP tolerates loss
                        };
                        let t = &mut tunnels[ti];
                        let found = t.streams.iter().position(|st| {
                            st.dead.is_none()
                                && st.mapping_id == Some(m.id)
                                && matches!(&st.local,
                                    Some(LocalSock::Udp { peer: Some(p), .. }) if *p == src)
                        });
                        let si = match found {
                            Some(i) => i,
                            None => {
                                let flows = t
                                    .streams
                                    .iter()
                                    .filter(|st| st.mapping_id == Some(m.id))
                                    .count();
                                if flows >= MAX_UDP_FLOWS {
                                    continue;
                                }
                                let Ok(clone) = sock.try_clone() else { continue };
                                let sid = t.alloc_stream_id();
                                let mut st = new_stream(
                                    sid,
                                    Some(m.id),
                                    Some(LocalSock::Udp { sock: clone, peer: Some(src) }),
                                );
                                if matches!(t.state, ConnState::Active) {
                                    send_rel(&t.steam, &mut t.pending, frame(F_OPEN, sid, &[]));
                                    st.open_sent = true;
                                }
                                t.streams.push(st);
                                t.streams_served += 1;
                                t.streams.len() - 1
                            }
                        };
                        let st = &mut t.streams[si];
                        st.last_activity = Instant::now();
                        if st.open_sent {
                            buf[1..HDR].copy_from_slice(&st.id.to_be_bytes());
                            if t.steam
                                .send_message(&buf[..n + HDR], data_flags(true, n + HDR))
                                .is_ok()
                            {
                                st.tx_bytes += n as u64;
                                t.tx_bytes += n as u64;
                            }
                        }
                        // pre-handshake datagrams are dropped — UDP tolerates loss
                    }
                }
                continue;
            }
            let listener = match &m.listener {
                Some(l) => l,
                None => continue,
            };
            loop {
                match listener.accept() {
                    Ok((tcp, _)) => {
                        tcp.set_nonblocking(true).ok();
                        tcp.set_nodelay(true).ok();
                        match ensure_out_tunnel(
                            &mut tunnels,
                            &sockets,
                            m.peer,
                            m.remote_port,
                            false,
                            rate,
                            &mut next_id,
                        ) {
                            Some(ti) => {
                                let t = &mut tunnels[ti];
                                let sid = t.alloc_stream_id();
                                let mut st =
                                    new_stream(sid, Some(m.id), Some(LocalSock::Tcp(tcp)));
                                if matches!(t.state, ConnState::Active) {
                                    send_rel(&t.steam, &mut t.pending, frame(F_OPEN, sid, &[]));
                                    st.open_sent = true;
                                } else {
                                    log(
                                        shared,
                                        format!(
                                            "Opening tunnel to {}:{} for local client",
                                            m.peer_name, m.remote_port
                                        ),
                                    );
                                }
                                t.streams.push(st);
                                t.streams_served += 1;
                            }
                            None => log(shared, "connect_p2p failed".into()),
                        }
                    }
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }

        // ---- pump every tunnel ----
        let mut log_msgs: Vec<String> = Vec::new();
        for t in tunnels.iter_mut() {
            if t.dead.is_some() {
                continue;
            }
            pump_tunnel(t, &psk, &mut log_msgs);
            if !matches!(t.state, ConnState::Active) && t.created.elapsed() > HANDSHAKE_TIMEOUT {
                t.mark_dead("handshake timeout");
            }
            if !t.streams.is_empty() {
                t.idle_since = Instant::now();
            } else if t.dir == Dir::Out
                && matches!(t.state, ConnState::Active)
                && t.idle_since.elapsed() > TUNNEL_LINGER
            {
                t.mark_dead("idle");
            }
        }
        for m in log_msgs {
            log(shared, m);
        }

        // ---- tunnel health check + ping/quality (every 500ms) ----
        if last_health.elapsed() > Duration::from_millis(500) {
            last_health = Instant::now();
            for t in tunnels.iter_mut() {
                if t.dead.is_some() {
                    continue;
                }
                if let Ok(info) = sockets.get_connection_info(&t.steam) {
                    match info.state() {
                        Ok(NetworkingConnectionState::ClosedByPeer) => t.mark_dead("closed by peer"),
                        Ok(NetworkingConnectionState::ProblemDetectedLocally) => {
                            t.mark_dead("connection problem")
                        }
                        Ok(NetworkingConnectionState::None) => t.mark_dead("connection gone"),
                        _ => {}
                    }
                }
                if let Ok((rt, _)) = sockets.get_realtime_connection_status(&t.steam, 0) {
                    t.ping_ms = rt.ping();
                    t.quality = rt
                        .connection_quality_local()
                        .min(rt.connection_quality_remote());
                }
            }
        }

        // ---- reap dead tunnels ----
        let mut i = 0;
        while i < tunnels.len() {
            if tunnels[i].dead.is_some() {
                let t = tunnels.remove(i);
                let reason = t.dead.as_deref().unwrap_or("").to_string();
                // idle-closed reusable tunnels are routine, keep the log for real ends
                if reason != "idle" || t.streams_served > 0 {
                    log(shared, format!("Tunnel {} closed: {reason}", t.id));
                }
                let row = HistoryRow {
                    ts: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                    dir: match t.dir {
                        Dir::In => "in".into(),
                        Dir::Out => "out".into(),
                    },
                    udp: t.udp,
                    peer: t.peer.raw().to_string(),
                    peer_name: client.friends().get_friend(t.peer).name(),
                    port: t.port,
                    duration_secs: t.created.elapsed().as_secs(),
                    tx_bytes: t.tx_bytes,
                    rx_bytes: t.rx_bytes,
                    streams: t.streams_served,
                    reason,
                };
                append_history(&row);
                {
                    let mut s = shared.lock().unwrap();
                    s.snapshot.history.push(row);
                    let over = s.snapshot.history.len().saturating_sub(HISTORY_KEEP);
                    if over > 0 {
                        s.snapshot.history.drain(0..over);
                    }
                }
                // linger so anything still in Steam's send buffer is delivered
                t.steam.close(NetConnectionEnd::App(AppNetConnectionEnd::generic_normal()), None, true);
            } else {
                i += 1;
            }
        }

        // ---- stats + snapshot (every second) ----
        if last_stats.elapsed() > Duration::from_secs(1) {
            let dt = last_stats.elapsed().as_secs_f64();
            last_stats = Instant::now();
            for t in tunnels.iter_mut() {
                t.tx_rate = ((t.tx_bytes - t.last_tx) as f64 / dt) as u64;
                t.rx_rate = ((t.rx_bytes - t.last_rx) as f64 / dt) as u64;
                t.last_tx = t.tx_bytes;
                t.last_rx = t.rx_bytes;
            }

            let refresh_friends = last_friends.elapsed() > Duration::from_secs(5);
            let mut friends_rows = Vec::new();
            let mut app_rows: Vec<AppRow> = Vec::new();
            if refresh_friends {
                last_friends = Instant::now();
                for a in detect::listening_ports() {
                    if a.port == ui_port {
                        continue;
                    }
                    let game = games
                        .iter()
                        .find(|g| g.ports.iter().any(|p| p.port == a.port && p.udp == a.udp))
                        .map(|g| g.name.clone());
                    app_rows.push(AppRow { process: a.process, port: a.port, udp: a.udp, game });
                }
                // games first, then named processes, nameless noise last
                app_rows.sort_by(|a, b| {
                    (a.game.is_none(), a.process.is_empty(), &a.process, a.port)
                        .cmp(&(b.game.is_none(), b.process.is_empty(), &b.process, b.port))
                });
                for f in client.friends().get_friends(FriendFlags::IMMEDIATE) {
                    let in_tunnel = f
                        .game_played()
                        .map(|g| g.game.app_id().0 == 480)
                        .unwrap_or(false);
                    friends_rows.push(FriendRow {
                        name: f.name(),
                        steam_id: f.id().raw().to_string(),
                        online: !matches!(f.state(), steamworks::FriendState::Offline),
                        in_tunnel,
                    });
                }
                friends_rows.sort_by(|a, b| {
                    (!a.in_tunnel, !a.online, &a.name).cmp(&(!b.in_tunnel, !b.online, &b.name))
                });
            }

            let mut s = shared.lock().unwrap();
            if refresh_friends {
                s.snapshot.friends = friends_rows;
                s.snapshot.apps = app_rows;
            }
            s.snapshot.relay_status = "relay access requested".into();
            s.snapshot.invites = invites.clone();
            s.snapshot.shares = shares
                .iter()
                .map(|sh| ShareRow {
                    port: sh.port,
                    udp: sh.udp,
                    target: sh.target.clone(),
                })
                .collect();
            s.snapshot.mappings = mappings
                .iter()
                .map(|m| MappingRow {
                    id: m.id,
                    peer: m.peer.raw().to_string(),
                    peer_name: m.peer_name.clone(),
                    remote_port: m.remote_port,
                    local_port: m.local_port,
                    udp: m.udp,
                })
                .collect();
            s.snapshot.conns = tunnels
                .iter()
                .map(|t| ConnRow {
                    id: t.id,
                    dir: match t.dir {
                        Dir::In => "in".into(),
                        Dir::Out => "out".into(),
                    },
                    udp: t.udp,
                    peer: t.peer.raw().to_string(),
                    peer_name: client.friends().get_friend(t.peer).name(),
                    peer_version: t.peer_version.clone(),
                    port: t.port,
                    state: match t.state {
                        ConnState::Active => "active".into(),
                        _ => "handshake".into(),
                    },
                    streams: t.streams.len() as u64,
                    ping_ms: t.ping_ms,
                    quality: t.quality,
                    tx_bytes: t.tx_bytes,
                    rx_bytes: t.rx_bytes,
                    tx_rate: t.tx_rate,
                    rx_rate: t.rx_rate,
                    age_secs: t.created.elapsed().as_secs(),
                })
                .collect();
        }

        std::thread::sleep(Duration::from_millis(4));
    }
}

fn peer_allowed(client: &Client, sid: SteamId, allowlist: &[u64]) -> bool {
    if !allowlist.is_empty() {
        return allowlist.contains(&sid.raw());
    }
    client
        .friends()
        .get_friends(FriendFlags::IMMEDIATE)
        .iter()
        .any(|f| f.id() == sid)
}

fn data_flags(udp: bool, len: usize) -> SendFlags {
    if udp && len <= MAX_UNRELIABLE {
        SendFlags::UNRELIABLE | SendFlags::NO_NAGLE
    } else {
        SendFlags::RELIABLE
    }
}

/// Open the local side for a stream on the host: connect to the share's
/// target per stream so DNS changes keep working.
fn open_local(target: &str, udp: bool) -> Result<LocalSock, String> {
    let addr = resolve_target(target).ok_or_else(|| format!("cannot resolve target {target}"))?;
    if udp {
        // wildcard bind: the target may be another machine
        let bound: SocketAddr = ([0, 0, 0, 0], 0).into();
        UdpSocket::bind(bound)
            .and_then(|s| {
                s.set_nonblocking(true)?;
                s.connect(addr)?;
                Ok(LocalSock::Udp { sock: s, peer: None })
            })
            .map_err(|e| format!("udp socket error: {e}"))
    } else {
        TcpStream::connect_timeout(&addr, Duration::from_secs(3))
            .map(|tcp| {
                tcp.set_nonblocking(true).ok();
                tcp.set_nodelay(true).ok();
                LocalSock::Tcp(tcp)
            })
            .map_err(|e| format!("target {target} unreachable: {e}"))
    }
}

/// Client side, tunnel just became Active: open every stream that queued up
/// during the handshake and flush what its local socket already sent.
fn activate_streams(t: &mut Tunnel) {
    for st in t.streams.iter_mut() {
        if st.open_sent || st.dead.is_some() {
            continue;
        }
        send_rel(&t.steam, &mut t.pending, frame(F_OPEN, st.id, &[]));
        st.open_sent = true;
        let buf = std::mem::take(&mut st.pre_buf);
        for chunk in buf.chunks(CHUNK) {
            send_rel(&t.steam, &mut t.pending, frame(F_DATA, st.id, chunk));
            st.tx_bytes += chunk.len() as u64;
            t.tx_bytes += chunk.len() as u64;
        }
        if st.tcp_eof {
            send_rel(&t.steam, &mut t.pending, frame(F_EOF, st.id, &[]));
        }
    }
}

fn pump_tunnel(t: &mut Tunnel, psk: &str, log_msgs: &mut Vec<String>) {
    // retry frames Steam previously refused, in order
    while let Some(f) = t.pending.front() {
        match t.steam.send_message(f, SendFlags::RELIABLE) {
            Ok(_) => {
                t.pending.pop_front();
            }
            Err(_) => break,
        }
    }

    // ---- Steam -> local ----
    if let Ok(messages) = t.steam.receive_messages(64) {
        for msg in messages {
            let data = msg.data();
            match t.state {
                ConnState::Active => {
                    if data.len() < HDR {
                        continue;
                    }
                    let ftype = data[0];
                    let sid = u32::from_be_bytes(data[1..HDR].try_into().unwrap());
                    let payload = &data[HDR..];
                    match ftype {
                        F_OPEN => {
                            // host side: client opens a new stream
                            if t.dir != Dir::In
                                || t.streams.iter().any(|st| st.id == sid)
                            {
                                continue;
                            }
                            match open_local(&t.target, t.udp) {
                                Ok(local) => {
                                    let mut st = new_stream(sid, None, Some(local));
                                    // the peer's F_OPEN created it: already open
                                    st.open_sent = true;
                                    t.streams.push(st);
                                    t.streams_served += 1;
                                    log_msgs.push(format!(
                                        "Tunnel {}: stream {sid} -> {} open",
                                        t.id, t.target
                                    ));
                                }
                                Err(e) => {
                                    log_msgs.push(format!(
                                        "Tunnel {}: stream {sid} failed: {e}",
                                        t.id
                                    ));
                                    send_rel(
                                        &t.steam,
                                        &mut t.pending,
                                        frame(F_CLOSE, sid, &[]),
                                    );
                                }
                            }
                        }
                        F_DATA => {
                            // unreliable UDP datagrams can outrun the reliable
                            // F_OPEN — open the flow implicitly on the host
                            if t.udp
                                && t.dir == Dir::In
                                && !t.streams.iter().any(|st| st.id == sid)
                            {
                                if let Ok(local) = open_local(&t.target, true) {
                                    let mut st = new_stream(sid, None, Some(local));
                                    st.open_sent = true;
                                    t.streams.push(st);
                                    t.streams_served += 1;
                                }
                            }
                            let tunnel_rx = &mut t.rx_bytes;
                            if let Some(st) =
                                t.streams.iter_mut().find(|st| st.id == sid && st.dead.is_none())
                            {
                                st.rx_bytes += payload.len() as u64;
                                *tunnel_rx += payload.len() as u64;
                                st.last_activity = Instant::now();
                                match st.local.as_mut() {
                                    Some(LocalSock::Tcp(_)) => {
                                        if st.tcp_out.len() + payload.len() > TCP_OUT_CAP {
                                            st.mark_dead("local socket too slow, buffer overflow");
                                        } else {
                                            st.tcp_out.extend(payload);
                                        }
                                    }
                                    Some(LocalSock::Udp { sock, peer }) => {
                                        // datagram passthrough; drop on any transient error
                                        let _ = match peer {
                                            None => sock.send(payload),
                                            Some(addr) => sock.send_to(payload, *addr),
                                        };
                                    }
                                    None => {}
                                }
                            }
                        }
                        F_EOF => {
                            if let Some(st) =
                                t.streams.iter_mut().find(|st| st.id == sid && st.dead.is_none())
                            {
                                st.remote_eof = true;
                            }
                        }
                        F_CLOSE => {
                            if let Some(st) =
                                t.streams.iter_mut().find(|st| st.id == sid && st.dead.is_none())
                            {
                                // flush what already arrived, then drop silently
                                st.reset = true;
                                st.tcp_eof = true;
                            }
                        }
                        _ => {
                            t.mark_dead("bad frame");
                            return;
                        }
                    }
                }
                ConnState::AwaitAuth => {
                    // host side: verify psk (if set) and that the client asks
                    // for the protocol this share actually carries
                    let (authed, proto) = if data.len() >= 37 && &data[0..4] == M_AUTH {
                        let ok = !psk.is_empty()
                            && match &t.nonce {
                                Some(nonce) => {
                                    let mac: [u8; 32] =
                                        data[4..36].try_into().unwrap_or_default();
                                    // constant-time compare via blake3 hash equality
                                    blake3::hash(&mac) == blake3::hash(&psk_mac(psk, nonce))
                                }
                                None => false,
                            };
                        t.peer_version = String::from_utf8_lossy(&data[37..]).into_owned();
                        (ok, Some(data[36]))
                    } else if data.len() >= 5 && &data[0..4] == M_NOAUTH {
                        t.peer_version = String::from_utf8_lossy(&data[5..]).into_owned();
                        (psk.is_empty(), Some(data[4]))
                    } else {
                        (false, None)
                    };
                    if !t.peer_version.is_empty() && t.peer_version != APP_VERSION {
                        log_msgs.push(format!(
                            "Tunnel {}: peer runs v{} (this side: v{APP_VERSION})",
                            t.id, t.peer_version
                        ));
                    }
                    if !authed {
                        log_msgs.push(format!("Tunnel {}: auth failed, dropping", t.id));
                        t.mark_dead("auth failed");
                        return;
                    }
                    if proto != Some(t.udp as u8) {
                        log_msgs.push(format!(
                            "Tunnel {}: protocol mismatch — port {} is {} here",
                            t.id,
                            t.port,
                            if t.udp { "udp" } else { "tcp" }
                        ));
                        t.mark_dead("protocol mismatch");
                        return;
                    }
                    // auth ok — streams open on demand via F_OPEN
                    let _ = t.steam.send_message(M_OK, SendFlags::RELIABLE);
                    t.state = ConnState::Active;
                    log_msgs.push(format!("Tunnel {}: open, forwarding to {}", t.id, t.target));
                }
                ConnState::AwaitHello => {
                    // client side
                    if data.len() < 37 || &data[0..4] != M_HELLO {
                        t.mark_dead("bad hello (version mismatch? both sides need the same steam-tunnel release)");
                        return;
                    }
                    t.peer_version = String::from_utf8_lossy(&data[37..]).into_owned();
                    if !t.peer_version.is_empty() && t.peer_version != APP_VERSION {
                        log_msgs.push(format!(
                            "Tunnel {}: peer runs v{} (this side: v{APP_VERSION})",
                            t.id, t.peer_version
                        ));
                    }
                    let auth_required = data[4] == 1;
                    if auth_required {
                        if psk.is_empty() {
                            log_msgs.push(format!(
                                "Tunnel {}: host requires a pre-shared key, none configured",
                                t.id
                            ));
                            t.mark_dead("psk required");
                            return;
                        }
                        let nonce: [u8; 32] = match data[5..37].try_into() {
                            Ok(n) => n,
                            Err(_) => {
                                t.mark_dead("bad hello");
                                return;
                            }
                        };
                        let mut auth = Vec::with_capacity(37 + APP_VERSION.len());
                        auth.extend_from_slice(M_AUTH);
                        auth.extend_from_slice(&psk_mac(psk, &nonce));
                        auth.push(t.udp as u8);
                        auth.extend_from_slice(APP_VERSION.as_bytes());
                        let _ = t.steam.send_message(&auth, SendFlags::RELIABLE);
                    } else {
                        let mut noauth = Vec::with_capacity(5 + APP_VERSION.len());
                        noauth.extend_from_slice(M_NOAUTH);
                        noauth.push(t.udp as u8);
                        noauth.extend_from_slice(APP_VERSION.as_bytes());
                        let _ = t.steam.send_message(&noauth, SendFlags::RELIABLE);
                    }
                    t.state = ConnState::AwaitOk;
                }
                ConnState::AwaitOk => {
                    if data.len() == 4 && &data[0..4] == M_OK {
                        t.state = ConnState::Active;
                        log_msgs.push(format!("Tunnel {}: established", t.id));
                        activate_streams(t);
                    } else {
                        t.mark_dead("handshake rejected");
                        return;
                    }
                }
            }
        }
    }

    // ---- pump every stream: flush to local, read from local ----
    let pending_empty = t.pending.is_empty();
    for st in t.streams.iter_mut() {
        if st.dead.is_some() {
            continue;
        }

        // flush buffered bytes to the local TCP socket
        if let Some(LocalSock::Tcp(tcp)) = st.local.as_mut() {
            while !st.tcp_out.is_empty() {
                let (front, _) = st.tcp_out.as_slices();
                match tcp.write(front) {
                    Ok(0) => {
                        // direct field write: mark_dead(&mut self) would
                        // conflict with the live borrow of st.local
                        st.dead = Some("local socket closed".into());
                        break;
                    }
                    Ok(n) => {
                        st.tcp_out.drain(0..n);
                    }
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(_) => {
                        st.dead = Some("local socket write error".into());
                        break;
                    }
                }
            }
            if st.dead.is_some() {
                continue;
            }
            // peer finished sending and everything is delivered -> half-close
            if st.remote_eof && st.tcp_out.is_empty() && !st.wr_shutdown && !st.reset {
                let _ = tcp.shutdown(std::net::Shutdown::Write);
                st.wr_shutdown = true;
            }
        }

        // peer reset the stream: once the buffer is drained, drop it
        if st.reset && st.tcp_out.is_empty() {
            st.mark_dead("closed by peer");
            continue;
        }

        // local -> Steam
        match st.local.as_mut() {
            Some(LocalSock::Tcp(tcp)) if !st.tcp_eof && pending_empty => {
                // frame buffer: [F_DATA, stream id, payload...]
                let mut buf = [0u8; CHUNK + HDR];
                buf[0] = F_DATA;
                buf[1..HDR].copy_from_slice(&st.id.to_be_bytes());
                for _ in 0..MAX_READS_PER_TICK {
                    match tcp.read(&mut buf[HDR..]) {
                        Ok(0) => {
                            st.tcp_eof = true;
                            if st.open_sent {
                                // our direction is done; the peer keeps sending
                                send_rel(&t.steam, &mut t.pending, frame(F_EOF, st.id, &[]));
                            }
                            break;
                        }
                        Ok(n) => {
                            if st.open_sent {
                                match t.steam.send_message(&buf[..n + HDR], SendFlags::RELIABLE)
                                {
                                    Ok(_) => {
                                        st.tx_bytes += n as u64;
                                        t.tx_bytes += n as u64;
                                    }
                                    Err(_) => {
                                        t.pending.push_back(buf[..n + HDR].to_vec());
                                        st.tx_bytes += n as u64;
                                        t.tx_bytes += n as u64;
                                        break;
                                    }
                                }
                            } else {
                                if st.pre_buf.len() + n > PRE_BUF_CAP {
                                    st.mark_dead("handshake buffer overflow");
                                    break;
                                }
                                st.pre_buf.extend_from_slice(&buf[HDR..n + HDR]);
                            }
                        }
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(_) => {
                            st.mark_dead("local socket read error");
                            break;
                        }
                    }
                }
            }
            // host side only: per-flow socket connected to the target.
            // Client-side UDP reads happen at the mapping level.
            Some(LocalSock::Udp { sock, .. }) if t.dir == Dir::In => {
                let mut buf = [0u8; UDP_BUF + HDR];
                buf[0] = F_DATA;
                buf[1..HDR].copy_from_slice(&st.id.to_be_bytes());
                for _ in 0..MAX_DGRAMS_PER_TICK {
                    let n = match sock.recv(&mut buf[HDR..]) {
                        Ok(n) => n,
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                        // ICMP-unreachable surfaces here on connected sockets;
                        // the service may just not be up yet
                        Err(_) => break,
                    };
                    st.last_activity = Instant::now();
                    if t.steam
                        .send_message(&buf[..n + HDR], data_flags(true, n + HDR))
                        .is_ok()
                    {
                        st.tx_bytes += n as u64;
                        t.tx_bytes += n as u64;
                    }
                }
            }
            _ => {}
        }

        // silent UDP flows expire; the next datagram re-opens one
        if t.udp && st.dead.is_none() && st.last_activity.elapsed() > UDP_FLOW_IDLE {
            st.mark_dead("flow idle");
        }

        // both directions finished and fully flushed -> clean close, no
        // F_CLOSE needed: the peer reaches the same state on its own
        if !t.udp && st.tcp_eof && st.remote_eof && st.tcp_out.is_empty() && st.dead.is_none() {
            st.mark_dead("finished");
        }
    }

    // ---- drop dead streams, telling the peer when it can't know ----
    let mut closed: Vec<(u32, String, bool)> = Vec::new();
    t.streams.retain(|st| {
        if let Some(reason) = &st.dead {
            let notify = !st.reset && reason != "finished";
            closed.push((st.id, reason.clone(), notify));
            false
        } else {
            true
        }
    });
    for (sid, reason, notify) in closed {
        if notify {
            send_rel(&t.steam, &mut t.pending, frame(F_CLOSE, sid, &[]));
        }
        log_msgs.push(format!("Tunnel {}: stream {sid} closed: {reason}", t.id));
    }
}
