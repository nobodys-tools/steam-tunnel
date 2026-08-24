pub fn spawn(url: String) {
    std::thread::spawn(move || run(url));
}

#[cfg(target_os = "linux")]
fn run(url: String) {
    struct TunnelTray {
        url: String,
    }
    impl ksni::Tray for TunnelTray {
        fn id(&self) -> String {
            "steam-tunnel".into()
        }
        fn title(&self) -> String {
            "steam-tunnel".into()
        }
        fn icon_name(&self) -> String {
            "network-workgroup".into()
        }
        fn activate(&mut self, _x: i32, _y: i32) {
            let _ = open::that(self.url.clone());
        }
        fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
            use ksni::menu::{MenuItem, StandardItem};
            vec![
                StandardItem {
                    label: "Open web UI".into(),
                    activate: Box::new(|t: &mut TunnelTray| {
                        let _ = open::that(t.url.clone());
                    }),
                    ..Default::default()
                }
                .into(),
                MenuItem::Separator,
                StandardItem {
                    label: "Quit steam-tunnel".into(),
                    activate: Box::new(|_| std::process::exit(0)),
                    ..Default::default()
                }
                .into(),
            ]
        }
    }
    use ksni::blocking::TrayMethods;
    match (TunnelTray { url }).spawn() {
        // the handle keeps the tray alive; park this thread for the app's lifetime
        Ok(_handle) => loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        },
        Err(e) => eprintln!("tray icon unavailable: {e}"),
    }
}

#[cfg(windows)]
fn run(url: String) {
    use tray_icon::menu::{Menu, MenuEvent, MenuItem};
    use tray_icon::{Icon, TrayIconBuilder};

    // simple solid 16x16 Steam-blue square
    let mut rgba = Vec::with_capacity(16 * 16 * 4);
    for _ in 0..(16 * 16) {
        rgba.extend_from_slice(&[0x66, 0xc0, 0xf4, 0xff]);
    }
    let icon = match Icon::from_rgba(rgba, 16, 16) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("tray icon unavailable: {e}");
            return;
        }
    };

    let menu = Menu::new();
    let open_item = MenuItem::new("Open web UI", true, None);
    let quit_item = MenuItem::new("Quit steam-tunnel", true, None);
    let _ = menu.append(&open_item);
    let _ = menu.append(&quit_item);
    let open_id = open_item.id().clone();
    let quit_id = quit_item.id().clone();

    let _tray = match TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_tooltip("steam-tunnel")
        .with_icon(icon)
        .build()
    {
        Ok(t) => t,
        Err(e) => {
            eprintln!("tray icon unavailable: {e}");
            return;
        }
    };

    // tray-icon needs a win32 message pump on this thread
    let rx = MenuEvent::receiver();
    unsafe {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            DispatchMessageW, PeekMessageW, TranslateMessage, MSG, PM_REMOVE,
        };
        let mut msg: MSG = std::mem::zeroed();
        loop {
            while PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            while let Ok(ev) = rx.try_recv() {
                if ev.id == open_id {
                    let _ = open::that(url.clone());
                } else if ev.id == quit_id {
                    std::process::exit(0);
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
fn run(_url: String) {}
