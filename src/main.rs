#[cfg(not(windows))]
fn main() {
    eprintln!(
        "signtool-windows requires Microsoft Windows (WinVerifyTrust, SignerSignEx3, registered CryptSIP)."
    );
    eprintln!(
        "Portable CLI: install `signtool-portable` (`cargo install --path crates/signtool-digest-cli --locked`) or run `cargo test -p signtool-sip-digest --lib`."
    );
    std::process::exit(1);
}

#[cfg(windows)]
fn main() {
    signtool_rs::run_windows_cli();
}
