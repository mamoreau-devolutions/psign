//! Azure Key Vault REST signing for Authenticode (`SignerSignEx3` + `AuthenticodeDigestSign` callback).

use crate::cli::{DigestAlgorithm, GlobalOpts, SignArgs};
use crate::win::sign_core::{
    adopt_cert, authenticode_sign_embedded, encoding, infer_digest_for_cert, merge_additional_cert_file,
    open_memory_cert_store, validate_cert_constraints,
};
use crate::win::sealing::validate_sign_constraints_paths;
use anyhow::{Context as _, Result, anyhow};
use base64::Engine as _;
use serde::Deserialize;
use std::cell::RefCell;
use std::mem::size_of;
use url::Url;
use windows::Win32::Foundation::{E_FAIL, S_OK};
use windows::Win32::Security::Cryptography::{
    CALG_SHA_256, CALG_SHA_384, CALG_SHA_512, CERT_CONTEXT, CRYPT_INTEGER_BLOB,
    CERT_STORE_ADD_REPLACE_EXISTING, CertAddCertificateContextToStore,
    CertCreateCertificateContext, CertFreeCertificateContext, SIGNER_DIGEST_SIGN_INFO,
    SIGNER_DIGEST_SIGN_INFO_0,
};
use windows::Win32::System::Memory::{LocalAlloc, LMEM_FIXED};
use windows::core::HRESULT;
use windows::Win32::Security::Cryptography::ALG_ID;

thread_local! {
    static KV_HTTP: RefCell<Option<KvCallbackState>> = const { RefCell::new(None) };
}

struct KvCallbackState {
    client: reqwest::blocking::Client,
    token: String,
    sign_url: String,
}

#[derive(Deserialize)]
struct KeyVaultCertificate {
    kid: String,
    cer: String,
}

#[derive(Deserialize)]
struct KeyVaultSignResponse {
    value: String,
}

fn normalize_vault_base(url: &str) -> Result<String> {
    let u = url.trim();
    if u.is_empty() {
        return Err(anyhow!("--azure-key-vault-url must not be empty"));
    }
    Ok(u.trim_end_matches('/').to_string())
}

fn acquire_access_token(args: &SignArgs) -> Result<String> {
    if let Some(tok) = args.azure_key_vault_access_token.as_ref().map(|s| s.trim()) {
        if tok.is_empty() {
            return Err(anyhow!("--azure-key-vault-accesstoken must not be empty"));
        }
        return Ok(tok.to_string());
    }
    if args.azure_key_vault_managed_identity {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .map_err(|e| anyhow!("HTTP client: {e}"))?;
        let rsp = client
            .get("http://169.254.169.254/metadata/identity/oauth2/token")
            .query(&[
                ("api-version", "2018-02-01"),
                ("resource", "https://vault.azure.net"),
            ])
            .header("Metadata", "true")
            .send()
            .context("managed identity token request (IMDS)")?;
        if !rsp.status().is_success() {
            return Err(anyhow!(
                "managed identity token HTTP {}: {}",
                rsp.status(),
                rsp.text().unwrap_or_default()
            ));
        }
        #[derive(Deserialize)]
        struct MiJson {
            access_token: String,
        }
        let j: MiJson = rsp.json().context("managed identity token JSON")?;
        return Ok(j.access_token);
    }

    let tenant = args
        .azure_key_vault_tenant_id
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            anyhow!(
                "Azure Key Vault client credentials require --azure-key-vault-tenant-id (-kvt)"
            )
        })?;
    let client_id = args
        .azure_key_vault_client_id
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            anyhow!(
                "Azure Key Vault client credentials require --azure-key-vault-client-id (-kvi)"
            )
        })?;
    let secret = args
        .azure_key_vault_client_secret
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| {
            anyhow!(
                "Azure Key Vault client credentials require --azure-key-vault-client-secret (-kvs)"
            )
        })?;

    let authority = args
        .azure_authority
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("https://login.microsoftonline.com");
    let token_url = format!("{authority}/{tenant}/oauth2/v2.0/token");

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| anyhow!("HTTP client: {e}"))?;
    let rsp = client
        .post(token_url)
        .form(&[
            ("client_id", client_id),
            ("client_secret", secret),
            ("scope", "https://vault.azure.net/.default"),
            ("grant_type", "client_credentials"),
        ])
        .send()
        .context("Azure AD token request")?;
    if !rsp.status().is_success() {
        return Err(anyhow!(
            "Azure AD token HTTP {}: {}",
            rsp.status(),
            rsp.text().unwrap_or_default()
        ));
    }
    #[derive(Deserialize)]
    struct TokenJson {
        access_token: String,
    }
    let j: TokenJson = rsp.json().context("Azure AD token JSON")?;
    Ok(j.access_token)
}

fn fetch_certificate(args: &SignArgs, token: &str, http: &reqwest::blocking::Client) -> Result<KeyVaultCertificate> {
    let base = normalize_vault_base(
        args.azure_key_vault_url
            .as_deref()
            .ok_or_else(|| anyhow!("internal: missing vault URL"))?,
    )?;
    let cert_name = args
        .azure_key_vault_certificate
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| anyhow!("--azure-key-vault-certificate (-kvc) is required"))?;

    let mut url =
        Url::parse(&base).map_err(|e| anyhow!("invalid --azure-key-vault-url: {e}"))?;
    url.path_segments_mut()
        .map_err(|_| anyhow!("--azure-key-vault-url must be a hierarchical https URL"))?
        .push("certificates")
        .push(cert_name.trim());
    if let Some(v) = args
        .azure_key_vault_certificate_version
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    {
        url.path_segments_mut()
            .map_err(|_| anyhow!("vault URL cannot be a base"))?
            .push(v.trim());
    }
    url.query_pairs_mut().append_pair("api-version", "7.4");

    let rsp = http
        .get(url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .context("Key Vault GET certificate")?;
    if !rsp.status().is_success() {
        return Err(anyhow!(
            "Key Vault certificate HTTP {}: {}",
            rsp.status(),
            rsp.text().unwrap_or_default()
        ));
    }
    rsp.json().context("Key Vault certificate JSON")
}

fn kv_rsa_alg(alg_id: ALG_ID) -> Result<&'static str> {
    if alg_id == CALG_SHA_256 {
        Ok("RS256")
    } else if alg_id == CALG_SHA_384 {
        Ok("RS384")
    } else if alg_id == CALG_SHA_512 {
        Ok("RS512")
    } else {
        Err(anyhow!(
            "unsupported digest algorithm for Azure Key Vault PKCS#1 signing (try SHA256/384/512)"
        ))
    }
}

unsafe extern "system" fn azure_kv_digest_callback(
    _p_cert: *const CERT_CONTEXT,
    _p_metadata: *const CRYPT_INTEGER_BLOB,
    algid_hash: ALG_ID,
    pb_digest: *const u8,
    cb_digest: u32,
    p_signature_blob: *mut CRYPT_INTEGER_BLOB,
) -> HRESULT {
    if pb_digest.is_null() || p_signature_blob.is_null() {
        return E_FAIL;
    }
    let digest = unsafe { std::slice::from_raw_parts(pb_digest, cb_digest as usize) };
    let alg = match kv_rsa_alg(algid_hash) {
        Ok(a) => a,
        Err(_) => return E_FAIL,
    };

    let outcome = KV_HTTP.with(|slot| {
        let borrowed = slot.borrow();
        let Some(state) = borrowed.as_ref() else {
            return Err(anyhow!("Azure KV signing thread-local state was not installed"));
        };
        let body = serde_json::json!({
            "alg": alg,
            "value": base64::engine::general_purpose::STANDARD.encode(digest),
        });
        let rsp = state
            .client
            .post(&state.sign_url)
            .header("Authorization", format!("Bearer {}", state.token))
            .json(&body)
            .send()
            .context("Key Vault POST sign")?;
        if !rsp.status().is_success() {
            return Err(anyhow!(
                "Key Vault sign HTTP {}: {}",
                rsp.status(),
                rsp.text().unwrap_or_default()
            ));
        }
        let parsed: KeyVaultSignResponse = rsp.json().context("Key Vault sign JSON")?;
        base64::engine::general_purpose::STANDARD
            .decode(parsed.value.trim())
            .context("signature base64 decode")
    });

    let sig = match outcome {
        Ok(b) => b,
        Err(_) => return E_FAIL,
    };

    // SAFETY: `LocalAlloc` matches native Authenticode expectations for out-of-band digest callbacks.
    let raw = match unsafe { LocalAlloc(LMEM_FIXED, sig.len()) } {
        Ok(h) => h,
        Err(_) => return E_FAIL,
    };
    if raw.is_invalid() {
        return E_FAIL;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(sig.as_ptr(), raw.0 as *mut u8, sig.len());
        (*p_signature_blob).cbData = sig.len() as u32;
        (*p_signature_blob).pbData = raw.0 as *mut u8;
    }
    S_OK
}

pub(crate) fn validate_azure_kv_mutex(args: &SignArgs) -> Result<()> {
    let has_url = args
        .azure_key_vault_url
        .as_deref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    if !has_url {
        let mut any = false;
        macro_rules! flag {
            ($($f:ident),*) => {
                $( any |= args.$f.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false); )*
            };
        }
        flag!(
            azure_key_vault_certificate,
            azure_key_vault_certificate_version,
            azure_key_vault_client_id,
            azure_key_vault_client_secret,
            azure_key_vault_tenant_id,
            azure_key_vault_access_token
        );
        any |= args.azure_key_vault_managed_identity;
        if any {
            return Err(anyhow!(
                "Azure Key Vault options require --azure-key-vault-url (-kvu)"
            ));
        }
        return Ok(());
    }

    if args.pfx.is_some() {
        return Err(anyhow!(
            "Azure Key Vault signing cannot be combined with --pfx (-f)"
        ));
    }
    if args.csp.is_some() || args.key_container.is_some() {
        return Err(anyhow!(
            "Azure Key Vault signing cannot be combined with --csp / --key-container"
        ));
    }
    if args.dlib.is_some()
        || args.dmdf.is_some()
        || args.trusted_signing_dlib_root.is_some()
    {
        return Err(anyhow!(
            "Azure Key Vault signing cannot be combined with --dlib / --dmdf / --trusted-signing-dlib-root"
        ));
    }
    if args.subject_name.is_some()
        || args.issuer_name.is_some()
        || args.cert_sha1.is_some()
        || args.auto_select
    {
        return Err(anyhow!(
            "Azure Key Vault signing does not use store certificate selection; omit --n/--i/--sha1/--a"
        ));
    }

    let has_sp = args.azure_key_vault_client_secret.as_ref().map(|s| !s.trim().is_empty()) == Some(true);
    let has_tenant =
        args.azure_key_vault_tenant_id.as_ref().map(|s| !s.trim().is_empty()) == Some(true);
    let has_client =
        args.azure_key_vault_client_id.as_ref().map(|s| !s.trim().is_empty()) == Some(true);
    let has_token = args
        .azure_key_vault_access_token
        .as_ref()
        .map(|s| !s.trim().is_empty())
        == Some(true);

    let sp_count = has_sp as u8 + has_tenant as u8 + has_client as u8;
    if sp_count != 0 && sp_count != 3 {
        return Err(anyhow!(
            "Azure AD client credentials require all of --azure-key-vault-client-id, --azure-key-vault-client-secret, and --azure-key-vault-tenant-id"
        ));
    }

    if has_token && (args.azure_key_vault_managed_identity || sp_count == 3) {
        return Err(anyhow!(
            "use either --azure-key-vault-accesstoken or managed identity / client credentials, not multiple"
        ));
    }
    if args.azure_key_vault_managed_identity && (has_token || sp_count == 3) {
        return Err(anyhow!(
            "--azure-key-vault-managed-identity cannot be combined with access tokens or client secrets"
        ));
    }
    if !has_token && !args.azure_key_vault_managed_identity && sp_count != 3 {
        return Err(anyhow!(
            "choose Azure Key Vault authentication: --azure-key-vault-accesstoken, --azure-key-vault-managed-identity, or client id/secret/tenant"
        ));
    }

    Ok(())
}

pub(crate) fn sign_with_azure_key_vault(
    args: &SignArgs,
    target: &std::path::Path,
    global: &GlobalOpts,
) -> Result<String> {
    validate_azure_kv_mutex(args)?;
    validate_sign_constraints_paths(args, std::iter::once(target))?;
    if args.page_hashes {
        return Err(anyhow!(
            "--page-hashes with Azure Key Vault is not supported in this implementation"
        ));
    }

    let http = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .map_err(|e| anyhow!("HTTP client: {e}"))?;
    let token = acquire_access_token(args)?;
    let cert = fetch_certificate(args, &token, &http)?;

    let mut sign_url =
        Url::parse(cert.kid.trim()).map_err(|e| anyhow!("invalid certificate kid URL: {e}"))?;
    sign_url
        .path_segments_mut()
        .map_err(|_| anyhow!("kid URL cannot be a base"))?
        .pop_if_empty()
        .push("sign");
    sign_url.query_pairs_mut().append_pair("api-version", "7.4");

    let cer_der = base64::engine::general_purpose::STANDARD
        .decode(cert.cer.trim())
        .context("decode certificate cer (base64)")?;

    let store = open_memory_cert_store()?;
    // SAFETY: `cer_der` is valid DER for the duration of import.
    let leaf = unsafe { CertCreateCertificateContext(encoding(), &cer_der) };
    if leaf.is_null() {
        return Err(anyhow!("CertCreateCertificateContext failed for Key Vault certificate"));
    }
    unsafe {
        CertAddCertificateContextToStore(
            Some(store.0),
            leaf.cast_const(),
            CERT_STORE_ADD_REPLACE_EXISTING,
            None,
        )
        .map_err(|e| {
            let _ = CertFreeCertificateContext(Some(leaf.cast_const()));
            anyhow!("CertAddCertificateContextToStore: {e}")
        })?;
    }
    let signing = adopt_cert(leaf)?;
    unsafe {
        let _ = CertFreeCertificateContext(Some(leaf.cast_const()));
    }

    validate_cert_constraints(signing.0 as *const CERT_CONTEXT, args)?;

    for ac in &args.additional_certs {
        merge_additional_cert_file(store.0, ac)?;
    }

    let resolved_digest = match args.digest {
        DigestAlgorithm::CertHash => infer_digest_for_cert(signing.0 as *const CERT_CONTEXT)?,
        other => other,
    };

    let mut empty_blob = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let mut anon = SIGNER_DIGEST_SIGN_INFO_0::default();
    anon.pfnAuthenticodeDigestSign = Some(azure_kv_digest_callback);
    let digest_info = SIGNER_DIGEST_SIGN_INFO {
        cbSize: size_of::<SIGNER_DIGEST_SIGN_INFO>() as u32,
        dwDigestSignChoice: 1,
        Anonymous: anon,
        pMetadataBlob: std::ptr::addr_of_mut!(empty_blob),
        dwReserved: 0,
        dwReserved2: 0,
        dwReserved3: 0,
    };
    let digest_ptr = std::ptr::addr_of!(digest_info);

    KV_HTTP.with(|slot| {
        *slot.borrow_mut() = Some(KvCallbackState {
            client: http,
            token,
            sign_url: sign_url.to_string(),
        });
    });

    let report = authenticode_sign_embedded(
        args,
        target,
        global,
        store.0,
        &signing,
        resolved_digest,
        None,
        Some(digest_ptr),
        "azure-key-vault",
        "MEMORY",
        None,
        None,
    );

    KV_HTTP.with(|slot| {
        slot.borrow_mut().take();
    });

    report
}
