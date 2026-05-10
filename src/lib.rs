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

    pub fn warning(stdout: String) -> Self {
        Self {
            stdout,
            exit_code: 2,
        }
    }
}
