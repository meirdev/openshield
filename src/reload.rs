use std::path::PathBuf;

use log::{error, info};

/// Listen for SIGHUP and perform a graceful upgrade:
/// 1. Spawn new process with `--upgrade` flag
/// 2. Send SIGQUIT to ourselves to trigger pingora's FD transfer
/// 3. Pingora sends listening sockets to new process, then drains and exits
pub fn start_reload_listener(config_path: PathBuf) {
    std::thread::spawn(move || {
        use signal_hook::iterator::Signals;
        let mut signals =
            Signals::new([signal_hook::consts::SIGHUP]).expect("Failed to register SIGHUP handler");

        info!("Send SIGHUP to reload (graceful upgrade)");

        let exe = std::env::current_exe().expect("Failed to get current executable path");
        let my_pid = std::process::id();

        for _ in signals.forever() {
            info!("SIGHUP received, starting graceful upgrade...");

            // Spawn new process with --upgrade flag
            match std::process::Command::new(&exe)
                .arg("--config")
                .arg(&config_path)
                .arg("--upgrade")
                .spawn()
            {
                Ok(child) => {
                    info!(
                        "New process spawned (pid={}), sending SIGQUIT to self",
                        child.id()
                    );
                    // Tell pingora to transfer FDs and gracefully shut down
                    unsafe {
                        libc::kill(my_pid as i32, libc::SIGQUIT);
                    }
                }
                Err(e) => error!("Failed to spawn upgrade process: {}", e),
            }
        }
    });
}
