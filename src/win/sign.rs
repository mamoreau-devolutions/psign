use crate::CommandOutput;
use crate::cli::{GlobalOpts, RustSipBackend, SignArgs};
use crate::win::code_sign_format::CodeSignFormat;
use crate::win::sign_core::sign_with_mssign32;
use crate::win::sign_digest_pipeline::reject_split_digest_flags;
use anyhow::{Result, anyhow};
use std::path::Path;

fn rust_sip_backend(args: &SignArgs) -> Option<RustSipBackend> {
    use RustSipBackend::*;
    if matches!(args.rust_sip, Some(Off)) {
        return None;
    }
    if let Some(b) = args.rust_sip {
        return match b {
            Off => None,
            Pe | Script | Msi | Esd | Msix | Cab | Catalog => Some(b),
        };
    }
    if std::env::var("SIGNTOOL_RS_RUST_SIP")
        .map(|v| v.eq_ignore_ascii_case("off"))
        .unwrap_or(false)
    {
        return None;
    }
    match std::env::var("SIGNTOOL_RS_RUST_SIP") {
        Ok(v) => {
            let t = v.trim();
            if t.eq_ignore_ascii_case("pe") {
                Some(Pe)
            } else if t.eq_ignore_ascii_case("script") {
                Some(Script)
            } else if t.eq_ignore_ascii_case("msi") {
                Some(Msi)
            } else if t.eq_ignore_ascii_case("esd") {
                Some(Esd)
            } else if t.eq_ignore_ascii_case("msix") {
                Some(Msix)
            } else if t.eq_ignore_ascii_case("cab") {
                Some(Cab)
            } else if t.eq_ignore_ascii_case("catalog") {
                Some(Catalog)
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

fn extension_lower(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|x| x.to_str())
        .map(|s| s.to_ascii_lowercase())
}

fn script_extensions_detected(path: &Path) -> bool {
    use CodeSignFormat::*;
    match crate::win::code_sign_format::detect(path) {
        PowerShellScript | PowerShellModule | PowerShellManifest | WindowsScriptHost => true,
        _ => extension_lower(path)
            .map(|e| {
                #[cfg(windows)]
                {
                    crate::win::sip_rust::ps_script::extension_supported(&e)
                        || crate::win::sip_rust::ps_script::is_wsh_extension(&e)
                }
                #[cfg(not(windows))]
                {
                    matches!(
                        e.as_str(),
                        "ps1"
                            | "psd1"
                            | "psm1"
                            | "ps1xml"
                            | "psc1"
                            | "cdxml"
                            | "mof"
                            | "js"
                            | "vbs"
                            | "wsf"
                    )
                }
            })
            .unwrap_or(false),
    }
}

fn ensure_rust_sip_pe_allowed_for_format(path: &Path) -> Result<()> {
    use CodeSignFormat::*;
    match crate::win::code_sign_format::detect(path) {
        PortableExecutable | WindowsMetadata => Ok(()),
        MsixFamily => Err(anyhow!(
            "--rust-sip pe (or SIGNTOOL_RS_RUST_SIP=pe) does not apply to MSIX/AppX packages; \
             use the OS AppX SIP / native signtool — disable Rust SIP with `--rust-sip off`"
        )),
        PowerShellScript | PowerShellModule | PowerShellManifest => Err(anyhow!(
            "use `--rust-sip script` (or SIGNTOOL_RS_RUST_SIP=script) for PowerShell-class files, not `--rust-sip pe`"
        )),
        WindowsInstaller | Catalog | Cabinet | WimImage => Err(anyhow!(
            "--rust-sip pe applies only to PE-based portable executables (.exe, .dll, .winmd, …); \
             got a non-PE SIP format for {}",
            path.display()
        )),
        WindowsScriptHost => Err(anyhow!(
            "use `--rust-sip script` for WSH scripts — PE Rust SIP does not apply to {}",
            path.display()
        )),
        Unknown => Err(anyhow!(
            "--rust-sip pe requires a PE-backed format; extension unknown for {}",
            path.display()
        )),
    }
}

fn ensure_rust_sip_msi_allowed_for_format(path: &Path) -> Result<()> {
    use CodeSignFormat::*;
    match crate::win::code_sign_format::detect(path) {
        WindowsInstaller => Ok(()),
        _ => Err(anyhow!(
            "`--rust-sip msi` applies only to Windows Installer `.msi` packages; got {}",
            path.display()
        )),
    }
}

fn ensure_rust_sip_esd_allowed_for_format(path: &Path) -> Result<()> {
    use CodeSignFormat::*;
    match crate::win::code_sign_format::detect(path) {
        WimImage => Ok(()),
        _ => Err(anyhow!(
            "`--rust-sip esd` applies only to WIM/ESD images (.wim, .esd); got {}",
            path.display()
        )),
    }
}

fn ensure_rust_sip_msix_allowed_for_format(path: &Path) -> Result<()> {
    let ext = extension_lower(path).unwrap_or_default();
    if matches!(ext.as_str(), "msix" | "appx" | "msixbundle" | "appxbundle") {
        return Ok(());
    }
    Err(anyhow!(
        "`--rust-sip msix` applies only to MSIX / APPX packages (`.msix`, `.appx`, `.msixbundle`, `.appxbundle`); got {}",
        path.display()
    ))
}

fn ensure_rust_sip_cab_allowed_for_format(path: &Path) -> Result<()> {
    use CodeSignFormat::*;
    match crate::win::code_sign_format::detect(path) {
        Cabinet => Ok(()),
        _ => Err(anyhow!(
            "`--rust-sip cab` applies only to `.cab` files; got {}",
            path.display()
        )),
    }
}

fn ensure_rust_sip_catalog_allowed_for_format(path: &Path) -> Result<()> {
    use CodeSignFormat::*;
    match crate::win::code_sign_format::detect(path) {
        Catalog => Ok(()),
        _ => Err(anyhow!(
            "`--rust-sip catalog` applies only to `.cat` files; got {}",
            path.display()
        )),
    }
}

fn ensure_rust_sip_script_allowed_for_format(path: &Path) -> Result<()> {
    use CodeSignFormat::*;
    if !script_extensions_detected(path) {
        return Err(anyhow!(
            "--rust-sip script applies only to PowerShell-class or WSH script files; got {}",
            path.display()
        ));
    }
    match crate::win::code_sign_format::detect(path) {
        PortableExecutable | WindowsMetadata | MsixFamily | WindowsInstaller | Catalog
        | Cabinet | WimImage => Err(anyhow!(
            "--rust-sip script does not apply to {}",
            path.display()
        )),
        _ => Ok(()),
    }
}

pub fn sign_file(args: &SignArgs, global: &GlobalOpts) -> Result<CommandOutput> {
    reject_split_digest_flags(args)?;
    if args.files.is_empty() {
        return Err(anyhow!("sign requires at least one file"));
    }
    let backend = rust_sip_backend(args);
    if matches!(backend, Some(RustSipBackend::Pe)) {
        for p in &args.files {
            ensure_rust_sip_pe_allowed_for_format(p)?;
        }
    }
    if matches!(backend, Some(RustSipBackend::Script)) {
        for p in &args.files {
            ensure_rust_sip_script_allowed_for_format(p)?;
        }
    }
    if matches!(backend, Some(RustSipBackend::Msi)) {
        for p in &args.files {
            ensure_rust_sip_msi_allowed_for_format(p)?;
        }
    }
    if matches!(backend, Some(RustSipBackend::Esd)) {
        for p in &args.files {
            ensure_rust_sip_esd_allowed_for_format(p)?;
        }
    }
    if matches!(backend, Some(RustSipBackend::Msix)) {
        for p in &args.files {
            ensure_rust_sip_msix_allowed_for_format(p)?;
        }
    }
    if matches!(backend, Some(RustSipBackend::Cab)) {
        for p in &args.files {
            ensure_rust_sip_cab_allowed_for_format(p)?;
        }
    }
    if matches!(backend, Some(RustSipBackend::Catalog)) {
        for p in &args.files {
            ensure_rust_sip_catalog_allowed_for_format(p)?;
        }
    }

    let mut combined = String::new();
    for (i, target) in args.files.iter().enumerate() {
        let block = sign_with_mssign32(args, target, global)?;
        #[cfg(windows)]
        match backend {
            Some(RustSipBackend::Pe) => {
                if matches!(
                    crate::win::code_sign_format::detect(target),
                    CodeSignFormat::PortableExecutable | CodeSignFormat::WindowsMetadata
                ) {
                    crate::win::sip_rust::sign_pe::post_sign_digest_parity_check(target, global)?;
                }
            }
            Some(RustSipBackend::Script) => {
                let ext = extension_lower(target).unwrap_or_default();
                if crate::win::sip_rust::ps_script::extension_supported(&ext)
                    || crate::win::sip_rust::ps_script::is_wsh_extension(&ext)
                {
                    crate::win::sip_rust::sign_script::post_sign_script_digest_parity_check(
                        target, global,
                    )?;
                }
            }
            Some(RustSipBackend::Msi) => {
                if matches!(
                    crate::win::code_sign_format::detect(target),
                    CodeSignFormat::WindowsInstaller
                ) {
                    crate::win::sip_rust::sign_msi::post_sign_msi_digest_parity_check(
                        target, global,
                    )?;
                }
            }
            Some(RustSipBackend::Esd) => {
                if matches!(
                    crate::win::code_sign_format::detect(target),
                    CodeSignFormat::WimImage
                ) {
                    crate::win::sip_rust::sign_esd::post_sign_wim_esd_digest_parity_check(
                        target, global,
                    )?;
                }
            }
            Some(RustSipBackend::Msix) => {
                let ext = extension_lower(target).unwrap_or_default();
                if matches!(ext.as_str(), "msix" | "appx" | "msixbundle" | "appxbundle") {
                    crate::win::sip_rust::sign_msix::post_sign_msix_digest_parity_check(
                        target, global,
                    )?;
                }
            }
            Some(RustSipBackend::Cab) => {
                if matches!(
                    crate::win::code_sign_format::detect(target),
                    CodeSignFormat::Cabinet
                ) {
                    crate::win::sip_rust::sign_cab::post_sign_cab_digest_parity_check(
                        target, global,
                    )?;
                }
            }
            Some(RustSipBackend::Catalog) => {
                if matches!(
                    crate::win::code_sign_format::detect(target),
                    CodeSignFormat::Catalog
                ) {
                    crate::win::sip_rust::sign_catalog::post_sign_catalog_digest_parity_check(
                        target, global,
                    )?;
                }
            }
            _ => {}
        }
        if i > 0 {
            combined.push('\n');
        }
        combined.push_str(&block);
    }
    Ok(CommandOutput::ok(combined))
}
