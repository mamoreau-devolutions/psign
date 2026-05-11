#[cfg(not(windows))]
fn main() {
    eprintln!(
        "psign-tool-windows requires Microsoft Windows (WinVerifyTrust, SignerSignEx3, registered CryptSIP)."
    );
    eprintln!(
        "Portable CLI: install `psign-tool-portable` (`cargo install --path crates/psign-digest-cli --locked`) or run `cargo test -p psign-sip-digest --lib`."
    );
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    psign::run_windows_cli();
}
