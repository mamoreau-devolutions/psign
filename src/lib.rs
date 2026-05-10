//! Windows Authenticode / Cryptography helpers call many FFI entry points with raw pointers (`PCCERT_CONTEXT`,
//! etc.). Those wrappers stay safe at the Rust abstraction boundary; Clippy's `not_unsafe_ptr_arg_deref` lint does not
//! apply cleanly across the entire Win32 surface.
//!
//! The **`win`** module is **`cfg(windows)`** only; non-Windows builds expose CLI parsing (`cli`, `native_argv`,
//! `response_argv`) and depend on **`signtool-sip-digest`** for portable digest code.
#![allow(clippy::not_unsafe_ptr_arg_deref)]

pub mod cli;
pub mod native_argv;
pub mod response_argv;
#[cfg(windows)]
pub mod win;

/// Process-oriented result matching native `signtool` exit semantics (`0` ok, `2` warning).
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub stdout: String,
    pub exit_code: i32,
}

impl CommandOutput {
    pub fn ok(stdout: String) -> Self {
        Self {
            stdout,
            exit_code: 0,
        }
    }

    pub fn with_exit(stdout: String, exit_code: i32) -> Self {
        Self { stdout, exit_code }
    }

    pub fn warning(stdout: String) -> Self {
        Self {
            stdout,
            exit_code: 2,
        }
    }
}

/// AzureSignTool-style HRESULT batch outcomes ([documented here](https://github.com/vcsjones/AzureSignTool/blob/main/README.md#exit-codes)).
pub const AZURE_SIGN_EXIT_PARTIAL_SUCCESS: i32 = 0x2000_0001_u32 as i32;
pub const AZURE_SIGN_EXIT_ALL_FAILED: i32 = 0xA000_0002_u32 as i32;

#[cfg(windows)]
pub fn run_windows_cli() -> ! {
    use crate::cli::{Cli, Command};
    use clap::Parser;

    fn print_output(global: &crate::cli::GlobalOpts, out: &CommandOutput) {
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
            Command::Verify(args) => crate::win::verify::verify_file(args, &cli.global),
            Command::Sign(args) => crate::win::sign::sign_file(args, &cli.global),
            Command::Timestamp(args) => crate::win::timestamp::timestamp_file(args, &cli.global),
            Command::Catdb(args) => crate::win::catdb::catdb_command(args, &cli.global),
            Command::Remove(args) => {
                crate::win::remove_signature::remove_command(args, &cli.global)
            }
            Command::InspectSignature(args) => {
                crate::win::inspect_signature::inspect_signature_command(args, &cli.global)
            }
            #[cfg(feature = "artifact-signing-rest")]
            Command::ArtifactSigningSubmit(args) => {
                crate::win::artifact_signing_rest::artifact_signing_submit_command(
                    args,
                    &cli.global,
                )
            }
        }
    }

    let argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    let Some((executable, tail)) = argv.split_first().map(|(e, t)| (e.clone(), t.to_vec())) else {
        std::process::exit(0);
    };

    let invocations = match crate::response_argv::expand_invocations(executable, tail) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e:#}");
            std::process::exit(1);
        }
    };

    let mut batch_exit = 0i32;
    for invocation in invocations {
        let argv = crate::native_argv::normalize_native_signtool_argv(invocation);
        let cli = match Cli::try_parse_from(argv) {
            Ok(c) => c,
            Err(e) => e.exit(),
        };

        match execute(&cli) {
            Ok(out) => {
                print_output(&cli.global, &out);
                batch_exit =
                    crate::response_argv::combine_batch_exit_codes(batch_exit, out.exit_code);
            }
            Err(e) => {
                if !cli.global.quiet {
                    eprintln!("{e:#}");
                }
                batch_exit = crate::response_argv::combine_batch_exit_codes(batch_exit, 1);
            }
        }
    }

    std::process::exit(batch_exit);
}
