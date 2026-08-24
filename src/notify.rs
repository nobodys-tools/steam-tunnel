//! Native desktop notifications — non-intrusive, fire-and-forget.
//! Linux: org.freedesktop.Notifications over D-Bus (X11 and Wayland).
//! Windows: toast notifications.

pub fn notify(summary: &str, body: &str) {
    let s = summary.to_string();
    let b = body.to_string();
    // notification daemons can block; never stall the engine for them
    std::thread::spawn(move || show(&s, &b));
}

#[cfg(target_os = "linux")]
fn show(summary: &str, body: &str) {
    let _ = notify_rust::Notification::new()
        .appname("steam-tunnel")
        .summary(summary)
        .body(body)
        .icon("network-workgroup")
        .timeout(notify_rust::Timeout::Milliseconds(6000))
        .show();
}

#[cfg(windows)]
fn show(summary: &str, body: &str) {
    use tauri_winrt_notification::Toast;
    // the PowerShell AppUserModelID works without registering our own
    let _ = Toast::new(Toast::POWERSHELL_APP_ID)
        .title(summary)
        .text1(body)
        .show();
}

#[cfg(not(any(target_os = "linux", windows)))]
fn show(_summary: &str, _body: &str) {}
