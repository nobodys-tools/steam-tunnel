use serde_json::Value;
use tiny_http::{Header, Method, Response, Server};

use crate::state::{Command, Shared};

const INDEX_HTML: &str = include_str!("ui/index.html");

fn json_header() -> Header {
    Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap()
}

fn html_header() -> Header {
    Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap()
}

pub fn serve(shared: Shared) {
    let port = shared.lock().unwrap().config.ui_port;
    let server = match Server::http(("127.0.0.1", port)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Cannot bind web UI on 127.0.0.1:{port}: {e}");
            std::process::exit(1);
        }
    };
    println!("steam-tunnel web UI: http://127.0.0.1:{port}");

    for mut request in server.incoming_requests() {
        let mut body = String::new();
        let _ = request.as_reader().read_to_string(&mut body);
        let url = request.url().to_string();
        let method = request.method().clone();

        // DNS-rebinding guard: a malicious page can point its own hostname at
        // 127.0.0.1 and read our API from the browser unless we pin the Host.
        let host_ok = request
            .headers()
            .iter()
            .find(|h| h.field.equiv("Host"))
            .map(|h| {
                let v = h.value.as_str().trim();
                let bare = v
                    .strip_suffix(&format!(":{port}"))
                    .unwrap_or(v);
                matches!(bare, "127.0.0.1" | "localhost" | "[::1]")
            })
            .unwrap_or(false);
        // CSRF guard: browsers send cross-origin POSTs with "simple" content
        // types without a preflight — the response is unreadable but the
        // action would still run. A custom header forces a preflight, which
        // we never answer, so cross-origin writes die in the browser.
        let xst_ok = request.headers().iter().any(|h| h.field.equiv("X-ST"));

        let response = if !host_ok {
            Response::from_string("{\"ok\":false,\"error\":\"bad host\"}")
                .with_status_code(403)
                .with_header(json_header())
        } else if method == Method::Post && !xst_ok {
            Response::from_string("{\"ok\":false,\"error\":\"missing X-ST header\"}")
                .with_status_code(403)
                .with_header(json_header())
        } else {
            match (method, url.as_str()) {
            (Method::Get, "/") => Response::from_string(INDEX_HTML).with_header(html_header()),
            (Method::Get, "/api/state") => {
                let s = shared.lock().unwrap();
                let json = serde_json::to_string(&s.snapshot).unwrap_or_else(|_| "{}".into());
                Response::from_string(json).with_header(json_header())
            }
            (Method::Post, path) => {
                let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
                let result = handle_post(&shared, path, &v);
                match result {
                    Ok(()) => Response::from_string("{\"ok\":true}").with_header(json_header()),
                    Err(msg) => Response::from_string(format!("{{\"ok\":false,\"error\":\"{msg}\"}}"))
                        .with_status_code(400)
                        .with_header(json_header()),
                }
            }
                _ => Response::from_string("not found").with_status_code(404),
            }
        };
        let _ = request.respond(response);
    }
}

fn get_u64(v: &Value, key: &str) -> Option<u64> {
    match &v[key] {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

fn get_port(v: &Value, key: &str) -> Option<u16> {
    get_u64(v, key).and_then(|p| u16::try_from(p).ok()).filter(|p| *p > 0)
}

fn get_bool(v: &Value, key: &str) -> bool {
    v[key].as_bool().unwrap_or(false)
}

fn handle_post(shared: &Shared, path: &str, v: &Value) -> Result<(), &'static str> {
    let cmd = match path {
        "/api/share" => {
            let target = match v["target"].as_str().map(str::trim) {
                Some(t) if !t.is_empty() => {
                    // loose host:port validation; supports names and IPv6 [..]:port
                    let port_ok = t
                        .rsplit_once(':')
                        .and_then(|(host, p)| {
                            (!host.is_empty()).then(|| p.parse::<u16>().ok()).flatten()
                        })
                        .is_some();
                    if !port_ok {
                        return Err("target must be host:port");
                    }
                    Some(t.to_string())
                }
                _ => None,
            };
            Command::Share {
                port: get_port(v, "port").ok_or("invalid port")?,
                udp: get_bool(v, "udp"),
                target,
                label: v["label"].as_str().unwrap_or("").trim().to_string(),
            }
        }
        "/api/unshare" => Command::Unshare {
            port: get_port(v, "port").ok_or("invalid port")?,
            udp: get_bool(v, "udp"),
        },
        "/api/connect" => {
            let remote_port = get_port(v, "remote_port").ok_or("invalid remote port")?;
            Command::Connect {
                peer: get_u64(v, "peer").ok_or("invalid steam id")?,
                remote_port,
                local_port: get_port(v, "local_port").unwrap_or(remote_port),
                udp: get_bool(v, "udp"),
            }
        }
        "/api/stop_mapping" => Command::StopMapping {
            id: get_u64(v, "id").ok_or("invalid id")?,
        },
        "/api/invite" => {
            // either a single {port, udp} or {ports: [{port, udp}, ...]}
            let mut ports = Vec::new();
            if let Value::Array(items) = &v["ports"] {
                for i in items {
                    let port = get_port(i, "port").ok_or("invalid port in ports")?;
                    ports.push(crate::state::PortSpec { port, udp: get_bool(i, "udp") });
                }
            } else {
                ports.push(crate::state::PortSpec {
                    port: get_port(v, "port").ok_or("invalid port")?,
                    udp: get_bool(v, "udp"),
                });
            }
            Command::Invite {
                peer: get_u64(v, "peer").ok_or("invalid steam id")?,
                ports,
                label: v["label"].as_str().unwrap_or("").trim().to_string(),
            }
        }
        "/api/dismiss_invite" => Command::DismissInvite {
            id: get_u64(v, "id").ok_or("invalid id")?,
        },
        "/api/settings" => {
            // absent/empty psk keeps the stored key; clear_psk wipes it
            let psk = if get_bool(v, "clear_psk") {
                Some(String::new())
            } else {
                match v["psk"].as_str() {
                    Some(s) if !s.is_empty() => Some(s.to_string()),
                    _ => None,
                }
            };
            let allowlist = match &v["allowlist"] {
                Value::Array(items) => items
                    .iter()
                    .filter_map(|i| match i {
                        Value::Number(n) => n.as_u64().map(|n| n.to_string()),
                        Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            };
            Command::SetSettings {
                psk,
                allowlist,
                send_rate_kib: get_u64(v, "send_rate_kib").unwrap_or(0) as u32,
                notify_events: v["notify_events"].as_bool().unwrap_or(true),
                notify_idle_shares: v["notify_idle_shares"].as_bool().unwrap_or(true),
            }
        }
        _ => return Err("unknown endpoint"),
    };
    shared.lock().unwrap().commands.push(cmd);
    Ok(())
}
