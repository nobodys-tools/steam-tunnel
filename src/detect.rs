//! Detect programs listening on local ports, so the UI can offer
//! "share what's already running" instead of asking for a port number.

/// One listening socket: which process, which port, which protocol.
#[derive(Clone, PartialEq)]
pub struct AppPort {
    pub process: String,
    pub port: u16,
    pub udp: bool,
}

/// Snapshot of listening TCP sockets and bound, unconnected UDP sockets,
/// with owning process names where readable. Own process is excluded;
/// well-known system ports (<1024) are skipped as noise.
pub fn listening_ports() -> Vec<AppPort> {
    let mut out = scan();
    let me = std::process::id();
    let _ = me; // used in the platform impls
    out.retain(|a| a.port >= 1024);
    out.sort_by(|a, b| (&a.process, a.port, a.udp).cmp(&(&b.process, b.port, b.udp)));
    out.dedup_by(|a, b| a.process == b.process && a.port == b.port && a.udp == b.udp);
    out
}

#[cfg(target_os = "linux")]
fn scan() -> Vec<AppPort> {
    use std::collections::HashMap;

    // /proc/net/{tcp,tcp6}: st 0A = LISTEN; /proc/net/{udp,udp6}: st 07 =
    // unconnected (bound). Column 9 is the socket inode.
    let mut inode_port: HashMap<u64, (u16, bool)> = HashMap::new();
    for (file, udp, want_st) in [
        ("/proc/net/tcp", false, "0A"),
        ("/proc/net/tcp6", false, "0A"),
        ("/proc/net/udp", true, "07"),
        ("/proc/net/udp6", true, "07"),
    ] {
        let Ok(data) = std::fs::read_to_string(file) else { continue };
        for line in data.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 10 || cols[3] != want_st {
                continue;
            }
            let Some((_, port_hex)) = cols[1].rsplit_once(':') else { continue };
            let Ok(port) = u16::from_str_radix(port_hex, 16) else { continue };
            let Ok(inode) = cols[9].parse::<u64>() else { continue };
            if port > 0 && inode > 0 {
                inode_port.insert(inode, (port, udp));
            }
        }
    }

    // our own sockets (mapping listeners, web UI) are not "apps" — drop them
    // via /proc/self/fd, which is readable even inside sandboxes
    if let Ok(fds) = std::fs::read_dir("/proc/self/fd") {
        for fd in fds.flatten() {
            if let Ok(link) = std::fs::read_link(fd.path()) {
                if let Some(inode) = link
                    .to_string_lossy()
                    .strip_prefix("socket:[")
                    .and_then(|r| r.strip_suffix(']'))
                    .and_then(|n| n.parse::<u64>().ok())
                {
                    inode_port.remove(&inode);
                }
            }
        }
    }

    // Map socket inodes to processes via /proc/*/fd symlinks. Best-effort:
    // inside bwrap sandboxes (steam-run on NixOS) reading other processes'
    // fd links is denied, so entries fall back to nameless — port-based
    // game matching still works there.
    let me = std::process::id() as u64;
    let mut out = Vec::new();
    let mut seen: std::collections::HashSet<u64> = Default::default();
    if let Ok(procs) = std::fs::read_dir("/proc") {
        for p in procs.flatten() {
            let Ok(pid) = p.file_name().to_string_lossy().parse::<u64>() else { continue };
            if pid == me {
                continue;
            }
            let Ok(fds) = std::fs::read_dir(p.path().join("fd")) else { continue };
            let mut name: Option<String> = None;
            for fd in fds.flatten() {
                let Ok(link) = std::fs::read_link(fd.path()) else { continue };
                let s = link.to_string_lossy();
                let Some(inode) = s
                    .strip_prefix("socket:[")
                    .and_then(|r| r.strip_suffix(']'))
                    .and_then(|n| n.parse::<u64>().ok())
                else {
                    continue;
                };
                let Some(&(port, udp)) = inode_port.get(&inode) else { continue };
                if !seen.insert(inode) {
                    continue;
                }
                let process = name
                    .get_or_insert_with(|| {
                        std::fs::read_to_string(p.path().join("comm"))
                            .map(|c| c.trim().to_string())
                            .unwrap_or_default()
                    })
                    .clone();
                out.push(AppPort { process, port, udp });
            }
        }
    }
    // sockets whose owner we couldn't read still get listed, nameless
    for (inode, (port, udp)) in inode_port {
        if !seen.contains(&inode) {
            out.push(AppPort { process: String::new(), port, udp });
        }
    }
    out
}

#[cfg(windows)]
fn scan() -> Vec<AppPort> {
    use std::collections::HashMap;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCPROW_OWNER_PID, MIB_UDPROW_OWNER_PID,
        TCP_TABLE_OWNER_PID_LISTENER, UDP_TABLE_OWNER_PID,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };

    const AF_INET: u32 = 2;

    // pid -> exe name
    let mut names: HashMap<u32, String> = HashMap::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap != INVALID_HANDLE_VALUE {
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            if Process32FirstW(snap, &mut entry) != 0 {
                loop {
                    let len = entry
                        .szExeFile
                        .iter()
                        .position(|&c| c == 0)
                        .unwrap_or(entry.szExeFile.len());
                    names.insert(
                        entry.th32ProcessID,
                        String::from_utf16_lossy(&entry.szExeFile[..len]),
                    );
                    if Process32NextW(snap, &mut entry) == 0 {
                        break;
                    }
                }
            }
            windows_sys::Win32::Foundation::CloseHandle(snap);
        }
    }

    let me = std::process::id();
    let mut out = Vec::new();

    // both calls follow the same ask-size-then-fill pattern
    unsafe {
        let mut size: u32 = 0;
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );
        let mut buf = vec![0u8; size as usize];
        if size > 4
            && GetExtendedTcpTable(
                buf.as_mut_ptr() as *mut _,
                &mut size,
                0,
                AF_INET,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            ) == 0
        {
            let count = *(buf.as_ptr() as *const u32) as usize;
            let rows = buf.as_ptr().add(4) as *const MIB_TCPROW_OWNER_PID;
            for i in 0..count {
                let row = &*rows.add(i);
                if row.dwOwningPid == me {
                    continue;
                }
                out.push(AppPort {
                    process: names.get(&row.dwOwningPid).cloned().unwrap_or_default(),
                    port: u16::from_be((row.dwLocalPort & 0xffff) as u16),
                    udp: false,
                });
            }
        }

        let mut size: u32 = 0;
        GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET,
            UDP_TABLE_OWNER_PID,
            0,
        );
        let mut buf = vec![0u8; size as usize];
        if size > 4
            && GetExtendedUdpTable(
                buf.as_mut_ptr() as *mut _,
                &mut size,
                0,
                AF_INET,
                UDP_TABLE_OWNER_PID,
                0,
            ) == 0
        {
            let count = *(buf.as_ptr() as *const u32) as usize;
            let rows = buf.as_ptr().add(4) as *const MIB_UDPROW_OWNER_PID;
            for i in 0..count {
                let row = &*rows.add(i);
                if row.dwOwningPid == me {
                    continue;
                }
                out.push(AppPort {
                    process: names.get(&row.dwOwningPid).cloned().unwrap_or_default(),
                    port: u16::from_be((row.dwLocalPort & 0xffff) as u16),
                    udp: true,
                });
            }
        }
    }
    out
}

#[cfg(not(any(target_os = "linux", windows)))]
fn scan() -> Vec<AppPort> {
    Vec::new()
}
