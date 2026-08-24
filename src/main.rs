#![cfg_attr(windows, windows_subsystem = "windows")]

mod detect;
mod engine;
mod http;
mod notify;
mod state;
mod tray;

fn main() {
    let first_run = !std::path::Path::new(state::CONFIG_PATH).exists();
    let config = state::Config::load();
    let ui_port = config.ui_port;
    let shared = state::new_shared(config);

    // first start: open the web UI so nobody has to know the address
    if first_run {
        let url = format!("http://127.0.0.1:{ui_port}");
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(800));
            let _ = open::that(url);
        });
    }

    let engine_shared = shared.clone();
    std::thread::spawn(move || engine::run(engine_shared));

    tray::spawn(format!("http://127.0.0.1:{ui_port}"));

    http::serve(shared);
}
