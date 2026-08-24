use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

pub const CONFIG_PATH: &str = "steam-tunnel.json";

#[derive(Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub psk: String,
    /// SteamID64 allowlist, one raw line each ("7656... # name" comments
    /// allowed). Empty = accept Steam friends only.
    #[serde(default)]
    pub allowlist: Vec<String>,
    #[serde(default = "default_ui_port")]
    pub ui_port: u16,
    /// Max Steam send rate per connection in KiB/s. 0 = Steam default (~1 MB/s).
    #[serde(default)]
    pub send_rate_kib: u32,
}

fn default_ui_port() -> u16 {
    7788
}

impl Default for Config {
    fn default() -> Self {
        Config {
            psk: String::new(),
            allowlist: Vec::new(),
            ui_port: default_ui_port(),
            send_rate_kib: 0,
        }
    }
}

impl Config {
    /// Parse the allowlist lines into SteamID64s (leading digits per line).
    pub fn allowlist_ids(&self) -> Vec<u64> {
        self.allowlist
            .iter()
            .filter_map(|line| {
                let digits: String = line
                    .trim()
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect();
                digits.parse().ok()
            })
            .collect()
    }

    pub fn load() -> Config {
        std::fs::read_to_string(CONFIG_PATH)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) {
        if let Ok(s) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(CONFIG_PATH, s);
        }
    }
}

#[derive(Clone, Serialize, Default)]
pub struct SelfInfo {
    pub name: String,
    pub steam_id: String,
}

#[derive(Clone, Serialize)]
pub struct FriendRow {
    pub name: String,
    pub steam_id: String,
    pub online: bool,
    /// currently in App ID 480, i.e. very likely running steam-tunnel
    pub in_tunnel: bool,
}

#[derive(Clone, Serialize)]
pub struct ShareRow {
    pub port: u16,
    pub udp: bool,
    /// where incoming tunnels are forwarded, e.g. "192.168.1.50:8096"
    pub target: String,
}

#[derive(Clone, Serialize)]
pub struct MappingRow {
    pub id: u64,
    pub peer: String,
    pub peer_name: String,
    pub remote_port: u16,
    pub local_port: u16,
    pub udp: bool,
}

#[derive(Clone, Serialize)]
pub struct ConnRow {
    pub id: u64,
    /// "in" = someone connected to a port we share, "out" = our outgoing mapping
    pub dir: String,
    pub udp: bool,
    pub peer: String,
    pub peer_name: String,
    pub peer_version: String,
    pub port: u16,
    pub state: String,
    /// Steam round-trip time in ms; -1 = not measured yet
    pub ping_ms: i32,
    /// worst-direction packet delivery rate, 0..1; -1 = unknown
    pub quality: f32,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_rate: u64,
    pub rx_rate: u64,
    pub age_secs: u64,
}

#[derive(Clone, Serialize)]
pub struct InviteRow {
    pub id: u64,
    pub from: String,
    pub from_name: String,
    pub port: u16,
    pub udp: bool,
}

#[derive(Clone, Serialize, Default)]
pub struct Snapshot {
    pub version: String,
    pub steam_ok: bool,
    pub steam_error: String,
    pub relay_status: String,
    pub me: SelfInfo,
    pub friends: Vec<FriendRow>,
    pub shares: Vec<ShareRow>,
    pub mappings: Vec<MappingRow>,
    pub conns: Vec<ConnRow>,
    pub invites: Vec<InviteRow>,
    pub psk_set: bool,
    pub allowlist: Vec<String>,
    pub send_rate_kib: u32,
    pub log: Vec<String>,
}

impl Snapshot {
    fn default_with(cfg: &Config) -> Snapshot {
        Snapshot {
            version: env!("CARGO_PKG_VERSION").to_string(),
            psk_set: !cfg.psk.is_empty(),
            allowlist: cfg.allowlist.clone(),
            send_rate_kib: cfg.send_rate_kib,
            ..Default::default()
        }
    }
}

pub enum Command {
    Share { port: u16, udp: bool, target: Option<String> },
    Unshare { port: u16, udp: bool },
    Connect { peer: u64, remote_port: u16, local_port: u16, udp: bool },
    StopMapping { id: u64 },
    Invite { peer: u64, port: u16, udp: bool },
    DismissInvite { id: u64 },
    /// psk: None = keep the current key, Some("") = clear, Some(k) = set
    SetSettings { psk: Option<String>, allowlist: Vec<String>, send_rate_kib: u32 },
}

pub struct SharedInner {
    pub snapshot: Snapshot,
    pub commands: Vec<Command>,
    pub config: Config,
}

pub type Shared = Arc<Mutex<SharedInner>>;

pub fn new_shared(config: Config) -> Shared {
    Arc::new(Mutex::new(SharedInner {
        snapshot: Snapshot::default_with(&config),
        commands: Vec::new(),
        config,
    }))
}
