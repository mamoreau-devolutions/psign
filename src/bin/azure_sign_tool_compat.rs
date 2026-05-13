//! Thin compatibility entry point: sets Azure-style HRESULT batch defaults (`PSIGN_EXIT_CODES`).

#[cfg(not(windows))]
fn main() {
    eprintln!("psign-azure-sign-tool-compat requires Microsoft Windows.");
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    // SAFETY: single-threaded process startup before spawning workers; sets HRESULT-style defaults for scripts.
    unsafe {
        std::env::set_var("PSIGN_EXIT_CODES", "azure");
    }
    psign::run_windows_cli();
}
