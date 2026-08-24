use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use steamworks::networking_sockets::{ListenSocket, NetConnection};
use steamworks::networking_types::{
    AppNetConnectionEnd,
    ListenSocketEvent, NetConnectionEnd, NetworkingConfigEntry, NetworkingConfigValue,
    NetworkingConnectionState, NetworkingIdentity, SendFlags,
};
use steamworks::{Client, FriendFlags, SteamId};

use crate::state::{Command, ConnRow, FriendRow, InviteRow, MappingRow, Shared, ShareRow};

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

const INVITE_PREFIX: &str = "steam-tunnel-v1:";

// Handshake frames. One Steam connection == one local TCP stream or UDP flow.
// The Steam virtual port is just the port number (values above 65535 are
// rejected by Steam), so the client declares its protocol in the auth frame
// and the host verifies it against what the share expects.
const M_HELLO: &[u8; 4] = b"STH2"; // host -> client: magic + flags(1) + nonce(32)
const M_AUTH: &[u8; 4] = b"STA2"; // client -> host: magic + mac(32) + proto(1)
const M_NOAUTH: &[u8; 4] = b"STN2"; // client -> host: magic + proto(1)
const M_OK: &[u8; 4] = b"STK2"; // host -> client: tunnel open

// Handshake frames carry the sender's version as trailing UTF-8 bytes so both
// sides can show what the peer runs and diagnose mismatches.
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

// After the handshake every message is [type byte, payload...]. The EOF frame
// makes TCP half-close work: one side finishing its writes must not tear down
// the other direction, and the connection only closes once both are done.
const F_DATA: u8 = 0;
const F_EOF: u8 = 1;

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

enum Dir {
    In,
    Out,
}

enum LocalSock {
    Tcp(TcpStream),
    /// Host side: socket `connect()`ed to the local service (peer None).
    /// Client side: socket bound on the local port; peer = the local
    /// program's address, learned from its first datagram.
    Udp { sock: UdpSocket, peer: Option<SocketAddr> },
}

struct Conn {
    id: u64,
    dir: Dir,
    peer: SteamId,
    port: u16,
    udp: bool,
    steam: NetConnection,
    local: Option<LocalSock>,
    state: ConnState,
    created: Instant,
    /// host side: the random challenge sent in HELLO; None on client conns
    nonce: Option<[u8; 32]>,
    /// host side: where this share forwards to ("host:port")
    target: String,
    /// TCP only: bytes received over Steam, waiting for the local socket
    tcp_out: VecDeque<u8>,
    /// TCP only: chunk Steam refused (send buffer full), retried next tick
    steam_pending: Option<Vec<u8>>,
    /// client TCP only: bytes read before the handshake finished
    pre_buf: Vec<u8>,
    /// local side stopped sending (we sent F_EOF)
    tcp_eof: bool,
    /// peer sent F_EOF (no more incoming data)
    remote_eof: bool,
    /// we already shutdown the write half of the local socket
    wr_shutdown: bool,
    /// version string the peer sent in the handshake
    peer_version: String,
    /// client UDP only: the mapping this conn belongs to (for respawn)
    mapping_id: Option<u64>,
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

impl Conn {
    fn mark_dead(&mut self, why: &str) {
        if self.dead.is_none() {
            self.dead = Some(why.to_string());
        }
    }
}

fn new_conn(
    id: u64,
    dir: Dir,
    peer: SteamId,
    port: u16,
    udp: bool,
    steam: NetConnection,
    local: Option<LocalSock>,
    state: ConnState,
    nonce: Option<[u8; 32]>,
    target: String,
    mapping_id: Option<u64>,
) -> Conn {
    Conn {
        id,
        dir,
        peer,
        port,
        udp,
        steam,
        local,
        state,
        created: Instant::now(),
        nonce,
        target,
        tcp_out: VecDeque::new(),
        steam_pending: None,
        pre_buf: Vec::new(),
        tcp_eof: false,
        remote_eof: false,
        wr_shutdown: false,
        peer_version: String::new(),
        mapping_id,
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
    /// forward target ("host:port"); resolved per connection so DNS/mDNS
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
    /// TCP: local listener. UDP: none — the socket lives in the connection.
    listener: Option<TcpListener>,
    /// UDP: id of the live connection, respawned when it dies
    udp_conn: Option<u64>,
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

fn run_engine(client: Client, shared: &Shared) {
    client.networking_utils().init_relay_network_access();

    let sockets = client.networking_sockets();
    let mut shares: Vec<Share> = Vec::new();
    let mut mappings: Vec<Mapping> = Vec::new();
    let mut conns: Vec<Conn> = Vec::new();
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
                    for c in conns.iter_mut() {
                        if matches!(c.dir, Dir::In) && c.port == port && c.udp == udp {
                            c.mark_dead("share removed");
                        }
                    }
                    log(shared, format!("Stopped sharing port {port}"));
                }
                Command::Connect { peer, remote_port, local_port, udp } => {
                    let peer_id = SteamId::from_raw(peer);
                    let peer_name = client.friends().get_friend(peer_id).name();
                    if udp {
                        // socket is created lazily by the respawn pass below
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
                            udp_conn: None,
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
                                    udp_conn: None,
                                    last_spawn: Instant::now(),
                                });
                                next_id += 1;
                            }
                            Err(e) => log(shared, format!("Cannot bind localhost:{local_port}: {e}")),
                        }
                    }
                }
                Command::StopMapping { id } => {
                    if let Some(m) = mappings.iter().find(|m| m.id == id) {
                        let conn_id = m.udp_conn;
                        for c in conns.iter_mut() {
                            if Some(c.id) == conn_id || c.mapping_id == Some(id) {
                                c.mark_dead("mapping removed");
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
                    // new incoming connections pick up the new rate
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
                        log(shared, "Send rate updated (applies to new connections)".into());
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
                            conns.push(new_conn(
                                next_id,
                                Dir::In,
                                sid,
                                share.port,
                                share.udp,
                                steam,
                                None,
                                ConnState::AwaitAuth,
                                Some(nonce),
                                share.target.clone(),
                                None,
                            ));
                            next_id += 1;
                        }
                    }
                    ListenSocketEvent::Disconnected(ev) => {
                        if let Some(sid) = ev.remote().steam_id() {
                            for c in conns.iter_mut() {
                                if matches!(c.dir, Dir::In) && c.peer == sid && c.dead.is_none() {
                                    c.mark_dead("peer disconnected");
                                }
                            }
                        }
                    }
                }
            }
        }

        // ---- local TCP accepts / UDP conn (re)spawn for outgoing mappings ----
        for m in mappings.iter_mut() {
            if m.udp {
                let live = m
                    .udp_conn
                    .map(|id| conns.iter().any(|c| c.id == id && c.dead.is_none()))
                    .unwrap_or(false);
                if !live && m.last_spawn.elapsed() >= UDP_RESPAWN_DELAY {
                    m.last_spawn = Instant::now();
                    let addr: SocketAddr = ([127, 0, 0, 1], m.local_port).into();
                    match UdpSocket::bind(addr) {
                        Ok(sock) => {
                            sock.set_nonblocking(true).ok();
                            match sockets.connect_p2p(
                                NetworkingIdentity::new_steam_id(m.peer),
                                m.remote_port as i32,
                                conn_options(rate),
                            ) {
                                Ok(steam) => {
                                    conns.push(new_conn(
                                        next_id,
                                        Dir::Out,
                                        m.peer,
                                        m.remote_port,
                                        true,
                                        steam,
                                        Some(LocalSock::Udp { sock, peer: None }),
                                        ConnState::AwaitHello,
                                        None,
                                        String::new(),
                                        Some(m.id),
                                    ));
                                    m.udp_conn = Some(next_id);
                                    next_id += 1;
                                }
                                Err(_) => log(shared, "connect_p2p failed".into()),
                            }
                        }
                        Err(e) => {
                            log(shared, format!("Cannot bind udp localhost:{}: {e}", m.local_port))
                        }
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
                        match sockets.connect_p2p(
                            NetworkingIdentity::new_steam_id(m.peer),
                            m.remote_port as i32,
                            conn_options(rate),
                        ) {
                            Ok(steam) => {
                                log(
                                    shared,
                                    format!(
                                        "Opening tunnel to {}:{} for local client",
                                        m.peer_name, m.remote_port
                                    ),
                                );
                                conns.push(new_conn(
                                    next_id,
                                    Dir::Out,
                                    m.peer,
                                    m.remote_port,
                                    false,
                                    steam,
                                    Some(LocalSock::Tcp(tcp)),
                                    ConnState::AwaitHello,
                                    None,
                                    String::new(),
                                    Some(m.id),
                                ));
                                next_id += 1;
                            }
                            Err(_) => log(shared, "connect_p2p failed".into()),
                        }
                    }
                    Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }

        // ---- pump every connection ----
        let mut log_msgs: Vec<String> = Vec::new();
        for c in conns.iter_mut() {
            if c.dead.is_some() {
                continue;
            }
            pump_conn(c, &psk, &mut log_msgs);
            if !matches!(c.state, ConnState::Active) && c.created.elapsed() > HANDSHAKE_TIMEOUT {
                c.mark_dead("handshake timeout");
            }
        }
        for m in log_msgs {
            log(shared, m);
        }

        // ---- connection health check (every 500ms) ----
        if last_health.elapsed() > Duration::from_millis(500) {
            last_health = Instant::now();
            for c in conns.iter_mut() {
                if c.dead.is_some() {
                    continue;
                }
                if let Ok(info) = sockets.get_connection_info(&c.steam) {
                    match info.state() {
                        Ok(NetworkingConnectionState::ClosedByPeer) => c.mark_dead("closed by peer"),
                        Ok(NetworkingConnectionState::ProblemDetectedLocally) => {
                            c.mark_dead("connection problem")
                        }
                        Ok(NetworkingConnectionState::None) => c.mark_dead("connection gone"),
                        _ => {}
                    }
                }
                if let Ok((rt, _)) = sockets.get_realtime_connection_status(&c.steam, 0) {
                    c.ping_ms = rt.ping();
                    c.quality = rt
                        .connection_quality_local()
                        .min(rt.connection_quality_remote());
                }
            }
        }

        // ---- reap dead connections ----
        let mut i = 0;
        while i < conns.len() {
            if conns[i].dead.is_some() {
                let c = conns.remove(i);
                log(shared, format!("Conn {} closed: {}", c.id, c.dead.as_deref().unwrap_or("")));
                // linger so anything still in Steam's send buffer is delivered
                c.steam.close(NetConnectionEnd::App(AppNetConnectionEnd::generic_normal()), None, true);
            } else {
                i += 1;
            }
        }
        for m in mappings.iter_mut() {
            if let Some(id) = m.udp_conn {
                if !conns.iter().any(|c| c.id == id) {
                    m.udp_conn = None;
                }
            }
        }

        // ---- stats + snapshot (every second) ----
        if last_stats.elapsed() > Duration::from_secs(1) {
            let dt = last_stats.elapsed().as_secs_f64();
            last_stats = Instant::now();
            for c in conns.iter_mut() {
                c.tx_rate = ((c.tx_bytes - c.last_tx) as f64 / dt) as u64;
                c.rx_rate = ((c.rx_bytes - c.last_rx) as f64 / dt) as u64;
                c.last_tx = c.tx_bytes;
                c.last_rx = c.rx_bytes;
            }

            let refresh_friends = last_friends.elapsed() > Duration::from_secs(5);
            let mut friends_rows = Vec::new();
            if refresh_friends {
                last_friends = Instant::now();
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
            s.snapshot.conns = conns
                .iter()
                .map(|c| ConnRow {
                    id: c.id,
                    dir: match c.dir {
                        Dir::In => "in".into(),
                        Dir::Out => "out".into(),
                    },
                    udp: c.udp,
                    peer: c.peer.raw().to_string(),
                    peer_name: client.friends().get_friend(c.peer).name(),
                    peer_version: c.peer_version.clone(),
                    port: c.port,
                    state: match c.state {
                        ConnState::Active => "active".into(),
                        _ => "handshake".into(),
                    },
                    ping_ms: c.ping_ms,
                    quality: c.quality,
                    tx_bytes: c.tx_bytes,
                    rx_bytes: c.rx_bytes,
                    tx_rate: c.tx_rate,
                    rx_rate: c.rx_rate,
                    age_secs: c.created.elapsed().as_secs(),
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

fn pump_conn(c: &mut Conn, psk: &str, log_msgs: &mut Vec<String>) {
    // retry a chunk Steam previously refused (TCP only)
    if let Some(chunk) = c.steam_pending.take() {
        match c.steam.send_message(&chunk, SendFlags::RELIABLE) {
            Ok(_) => c.tx_bytes += chunk.len() as u64,
            Err(_) => c.steam_pending = Some(chunk),
        }
    }

    // ---- Steam -> local ----
    if let Ok(messages) = c.steam.receive_messages(64) {
        for msg in messages {
            let data = msg.data();
            match c.state {
                ConnState::Active => {
                    if data.is_empty() {
                        continue;
                    }
                    if data[0] == F_EOF {
                        c.remote_eof = true;
                        continue;
                    }
                    if data[0] != F_DATA {
                        c.mark_dead("bad frame");
                        return;
                    }
                    let payload = &data[1..];
                    c.rx_bytes += payload.len() as u64;
                    match c.local.as_mut() {
                        Some(LocalSock::Tcp(_)) => {
                            if c.tcp_out.len() + payload.len() > TCP_OUT_CAP {
                                c.mark_dead("local socket too slow, buffer overflow");
                                return;
                            }
                            c.tcp_out.extend(payload);
                        }
                        Some(LocalSock::Udp { sock, peer }) => {
                            // datagram passthrough; drop on any transient error
                            let _ = match (&c.dir, &peer) {
                                (Dir::In, _) => sock.send(payload),
                                (Dir::Out, Some(addr)) => sock.send_to(payload, addr),
                                (Dir::Out, None) => Ok(0), // no local program yet
                            };
                        }
                        None => {}
                    }
                }
                ConnState::AwaitAuth => {
                    // host side: verify psk (if set) and that the client asks
                    // for the protocol this share actually carries
                    let (authed, proto) = if data.len() >= 37 && &data[0..4] == M_AUTH {
                        let ok = !psk.is_empty()
                            && match &c.nonce {
                                Some(nonce) => {
                                    let mac: [u8; 32] =
                                        data[4..36].try_into().unwrap_or_default();
                                    // constant-time compare via blake3 hash equality
                                    blake3::hash(&mac) == blake3::hash(&psk_mac(psk, nonce))
                                }
                                None => false,
                            };
                        c.peer_version = String::from_utf8_lossy(&data[37..]).into_owned();
                        (ok, Some(data[36]))
                    } else if data.len() >= 5 && &data[0..4] == M_NOAUTH {
                        c.peer_version = String::from_utf8_lossy(&data[5..]).into_owned();
                        (psk.is_empty(), Some(data[4]))
                    } else {
                        (false, None)
                    };
                    if !c.peer_version.is_empty() && c.peer_version != APP_VERSION {
                        log_msgs.push(format!(
                            "Conn {}: peer runs v{} (this side: v{APP_VERSION})",
                            c.id, c.peer_version
                        ));
                    }
                    if !authed {
                        log_msgs.push(format!("Conn {}: auth failed, dropping", c.id));
                        c.mark_dead("auth failed");
                        return;
                    }
                    if proto != Some(c.udp as u8) {
                        log_msgs.push(format!(
                            "Conn {}: protocol mismatch — port {} is {} here",
                            c.id,
                            c.port,
                            if c.udp { "udp" } else { "tcp" }
                        ));
                        c.mark_dead("protocol mismatch");
                        return;
                    }
                    // auth ok -> connect to the share's target
                    let addr = match resolve_target(&c.target) {
                        Some(a) => a,
                        None => {
                            log_msgs.push(format!(
                                "Conn {}: cannot resolve target {}",
                                c.id, c.target
                            ));
                            c.mark_dead("target unresolvable");
                            return;
                        }
                    };
                    if c.udp {
                        // wildcard bind: the target may be another machine
                        let bound: SocketAddr = ([0, 0, 0, 0], 0).into();
                        match UdpSocket::bind(bound).and_then(|s| {
                            s.set_nonblocking(true)?;
                            s.connect(addr)?;
                            Ok(s)
                        }) {
                            Ok(sock) => {
                                c.local = Some(LocalSock::Udp { sock, peer: None });
                                let _ = c.steam.send_message(M_OK, SendFlags::RELIABLE);
                                c.state = ConnState::Active;
                                log_msgs.push(format!(
                                    "Conn {}: udp tunnel to {} open",
                                    c.id, c.target
                                ));
                            }
                            Err(e) => {
                                log_msgs.push(format!("Conn {}: udp socket error: {e}", c.id));
                                c.mark_dead("udp socket error");
                                return;
                            }
                        }
                    } else {
                        match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
                            Ok(tcp) => {
                                tcp.set_nonblocking(true).ok();
                                tcp.set_nodelay(true).ok();
                                c.local = Some(LocalSock::Tcp(tcp));
                                let _ = c.steam.send_message(M_OK, SendFlags::RELIABLE);
                                c.state = ConnState::Active;
                                log_msgs.push(format!(
                                    "Conn {}: tunnel to {} open",
                                    c.id, c.target
                                ));
                            }
                            Err(e) => {
                                log_msgs.push(format!(
                                    "Conn {}: target {} unreachable: {e}",
                                    c.id, c.target
                                ));
                                c.mark_dead("target unreachable");
                                return;
                            }
                        }
                    }
                }
                ConnState::AwaitHello => {
                    // client side
                    if data.len() < 37 || &data[0..4] != M_HELLO {
                        c.mark_dead("bad hello (version mismatch? both sides need the same steam-tunnel release)");
                        return;
                    }
                    c.peer_version = String::from_utf8_lossy(&data[37..]).into_owned();
                    if !c.peer_version.is_empty() && c.peer_version != APP_VERSION {
                        log_msgs.push(format!(
                            "Conn {}: peer runs v{} (this side: v{APP_VERSION})",
                            c.id, c.peer_version
                        ));
                    }
                    let auth_required = data[4] == 1;
                    if auth_required {
                        if psk.is_empty() {
                            log_msgs.push(format!(
                                "Conn {}: host requires a pre-shared key, none configured",
                                c.id
                            ));
                            c.mark_dead("psk required");
                            return;
                        }
                        let nonce: [u8; 32] = match data[5..37].try_into() {
                            Ok(n) => n,
                            Err(_) => {
                                c.mark_dead("bad hello");
                                return;
                            }
                        };
                        let mut auth = Vec::with_capacity(37 + APP_VERSION.len());
                        auth.extend_from_slice(M_AUTH);
                        auth.extend_from_slice(&psk_mac(psk, &nonce));
                        auth.push(c.udp as u8);
                        auth.extend_from_slice(APP_VERSION.as_bytes());
                        let _ = c.steam.send_message(&auth, SendFlags::RELIABLE);
                    } else {
                        let mut noauth = Vec::with_capacity(5 + APP_VERSION.len());
                        noauth.extend_from_slice(M_NOAUTH);
                        noauth.push(c.udp as u8);
                        noauth.extend_from_slice(APP_VERSION.as_bytes());
                        let _ = c.steam.send_message(&noauth, SendFlags::RELIABLE);
                    }
                    c.state = ConnState::AwaitOk;
                }
                ConnState::AwaitOk => {
                    if data.len() == 4 && &data[0..4] == M_OK {
                        c.state = ConnState::Active;
                        log_msgs.push(format!("Conn {}: tunnel established", c.id));
                        if !c.pre_buf.is_empty() {
                            let buf = std::mem::take(&mut c.pre_buf);
                            for chunk in buf.chunks(CHUNK) {
                                let mut framed = Vec::with_capacity(chunk.len() + 1);
                                framed.push(F_DATA);
                                framed.extend_from_slice(chunk);
                                match c.steam.send_message(&framed, SendFlags::RELIABLE) {
                                    Ok(_) => c.tx_bytes += chunk.len() as u64,
                                    Err(_) => {
                                        c.steam_pending = Some(framed);
                                        break;
                                    }
                                }
                            }
                        }
                        if c.tcp_eof && c.steam_pending.is_none() {
                            let _ = c.steam.send_message(&[F_EOF], SendFlags::RELIABLE);
                        }
                    } else {
                        c.mark_dead("handshake rejected");
                        return;
                    }
                }
            }
        }
    }

    // ---- flush buffered bytes to the local TCP socket ----
    if let Some(LocalSock::Tcp(tcp)) = c.local.as_mut() {
        while !c.tcp_out.is_empty() {
            let (front, _) = c.tcp_out.as_slices();
            match tcp.write(front) {
                Ok(0) => {
                    c.mark_dead("local socket closed");
                    return;
                }
                Ok(n) => {
                    c.tcp_out.drain(0..n);
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(_) => {
                    c.mark_dead("local socket write error");
                    return;
                }
            }
        }
        // peer finished sending and everything is delivered -> half-close
        if c.remote_eof && c.tcp_out.is_empty() && !c.wr_shutdown {
            let _ = tcp.shutdown(std::net::Shutdown::Write);
            c.wr_shutdown = true;
        }
    }

    // ---- local -> Steam ----
    if c.steam_pending.is_none() {
        match c.local.as_mut() {
            Some(LocalSock::Tcp(tcp)) if !c.tcp_eof => {
                // frame buffer: [F_DATA, payload...]
                let mut buf = [0u8; CHUNK + 1];
                buf[0] = F_DATA;
                for _ in 0..MAX_READS_PER_TICK {
                    match tcp.read(&mut buf[1..]) {
                        Ok(0) => {
                            c.tcp_eof = true;
                            if matches!(c.state, ConnState::Active) {
                                // our direction is done; the peer keeps sending
                                if c.steam.send_message(&[F_EOF], SendFlags::RELIABLE).is_err() {
                                    c.steam_pending = Some(vec![F_EOF]);
                                }
                            }
                            break;
                        }
                        Ok(n) => match c.state {
                            ConnState::Active => {
                                match c.steam.send_message(&buf[..n + 1], SendFlags::RELIABLE) {
                                    Ok(_) => c.tx_bytes += n as u64,
                                    Err(_) => {
                                        c.steam_pending = Some(buf[..n + 1].to_vec());
                                        break;
                                    }
                                }
                            }
                            _ => {
                                if c.pre_buf.len() + n > PRE_BUF_CAP {
                                    c.mark_dead("handshake buffer overflow");
                                    return;
                                }
                                c.pre_buf.extend_from_slice(&buf[1..n + 1]);
                            }
                        },
                        Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(_) => {
                            c.mark_dead("local socket read error");
                            return;
                        }
                    }
                }
            }
            Some(LocalSock::Udp { sock, peer }) => {
                let mut buf = [0u8; UDP_BUF + 1];
                buf[0] = F_DATA;
                for _ in 0..MAX_DGRAMS_PER_TICK {
                    let (n, src) = match c.dir {
                        Dir::In => match sock.recv(&mut buf[1..]) {
                            Ok(n) => (n, None),
                            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                            // ICMP-unreachable surfaces here on connected sockets;
                            // the service may just not be up yet
                            Err(_) => break,
                        },
                        Dir::Out => match sock.recv_from(&mut buf[1..]) {
                            Ok((n, src)) => (n, Some(src)),
                            Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                            Err(_) => break,
                        },
                    };
                    if let Some(src) = src {
                        *peer = Some(src);
                    }
                    if matches!(c.state, ConnState::Active) {
                        if c.steam.send_message(&buf[..n + 1], data_flags(true, n + 1)).is_ok() {
                            c.tx_bytes += n as u64;
                        }
                    }
                    // pre-handshake datagrams are dropped — UDP tolerates loss
                }
            }
            _ => {}
        }
    }

    // ---- both directions finished and fully flushed -> graceful close ----
    if c.tcp_eof
        && c.remote_eof
        && c.tcp_out.is_empty()
        && c.steam_pending.is_none()
        && c.dead.is_none()
    {
        c.mark_dead("finished");
    }
}
