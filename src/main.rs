#[cfg(not(windows))]
fn main() {
    eprintln!(
        "signtool-rs requires Microsoft Windows (WinVerifyTrust, SignerSignEx3, registered CryptSIP)."
    );
    eprintln!(
        "Portable Authenticode digest implementations: `cargo test -p signtool-sip-digest --lib`"
    );
    std::process::exit(1);
}

#[cfg(windows)]
mod windows_main {
    use clap::Parser;
    use signtool_rs::CommandOutput;
    use signtool_rs::cli::{Cli, Command};

    fn print_output(global: &signtool_rs::cli::GlobalOpts, out: &CommandOutput) {
        if global.debug {
            eprintln!(
                "[debug] exit_code={} stdout_len={}",
                out.exit_code,
                out.stdout.len()
            );
        }
        if !global.quiet || out.exit_code != 0 {
            print!("{}", out.stdout);
        }
    }

    fn execute(cli: &Cli) -> anyhow::Result<CommandOutput> {
        match &cli.command {
            Command::Verify(args) => signtool_rs::win::verify::verify_file(args, &cli.global),
            Command::Sign(args) => signtool_rs::win::sign::sign_file(args, &cli.global),
            Command::Timestamp(args) => {
                signtool_rs::win::timestamp::timestamp_file(args, &cli.global)
            }
            Command::Catdb(args) => signtool_rs::win::catdb::catdb_command(args, &cli.global),
            Command::Remove(args) => {
                signtool_rs::win::remove_signature::remove_command(args, &cli.global)
            }
        }
    }

    pub fn main() {
        let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
        let Some((executable, tail)) = argv.split_first().map(|(e, t)| (e.clone(), t.to_vec()))
        else {
            return;
        };

        let invocations = match signtool_rs::response_argv::expand_invocations(executable, tail) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("{e:#}");
                std::process::exit(1);
            }
        };

        let mut batch_exit = 0i32;
        for invocation in invocations {
            let argv = signtool_rs::native_argv::normalize_native_signtool_argv(invocation);
            let cli = match Cli::try_parse_from(argv) {
                Ok(c) => c,
                Err(e) => e.exit(),
            };

            match execute(&cli) {
                Ok(out) => {
                    print_output(&cli.global, &out);
                    batch_exit = signtool_rs::response_argv::combine_batch_exit_codes(
                        batch_exit,
                        out.exit_code,
                    );
                }
                Err(e) => {
                    if !cli.global.quiet {
                        eprintln!("{e:#}");
                    }
                    batch_exit =
                        signtool_rs::response_argv::combine_batch_exit_codes(batch_exit, 1);
                }
            }
        }

        std::process::exit(batch_exit);
    }
}

#[cfg(windows)]
fn main() {
    windows_main::main();
}
