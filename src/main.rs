#![cfg_attr(windows, windows_subsystem = "windows")]

mod engine;
mod http;
mod state;
mod tray;

fn main() {
    let config = state::Config::load();
    let ui_port = config.ui_port;
    let shared = state::new_shared(config);

    let engine_shared = shared.clone();
    std::thread::spawn(move || engine::run(engine_shared));

    tray::spawn(format!("http://127.0.0.1:{ui_port}"));

    http::serve(shared);
}
