//! Azure Code Signing **data-plane** REST client (`CertificateProfileOperations_Sign` LRO).
//!
//! Swagger: Azure REST API specs  
//! `specification/codesigning/data-plane/Azure.CodeSigning/preview/2023-06-15-preview/azure.codesigning.json`.

use crate::cli::{ArtifactSigningSubmitArgs, GlobalOpts};
use crate::CommandOutput;
use anyhow::{Context as _, Result, anyhow};
use base64::Engine as _;
use serde::Deserialize;
use serde_json::Value;
use std::thread;
use std::time::Duration;

const DEFAULT_SCOPE: &str = "https://codesigning.azure.net/.default";
const MI_RESOURCE: &str = "https://codesigning.azure.net";

fn normalize_authority(args: &ArtifactSigningSubmitArgs) -> String {
    args.authority
        .as_deref()
        .unwrap_or("https://login.microsoftonline.com")
        .trim_end_matches('/')
        .to_string()
}

fn acquire_codesigning_token(args: &ArtifactSigningSubmitArgs) -> Result<String> {
    if let Some(tok) = args.access_token.as_ref().map(|s| s.trim()) {
        if tok.is_empty() {
            return Err(anyhow!("--access-token must not be empty"));
        }
        return Ok(tok.to_string());
    }
    let http = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| anyhow!("HTTP client: {e}"))?;

    if args.managed_identity {
        let rsp = http
            .get("http://169.254.169.254/metadata/identity/oauth2/token")
            .query(&[
                ("api-version", "2018-02-01"),
                ("resource", MI_RESOURCE),
            ])
            .header("Metadata", "true")
            .send()
            .context("managed identity token (IMDS) for codesigning.azure.net")?;
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
        let j: MiJson = rsp.json().context("managed identity JSON")?;
        return Ok(j.access_token);
    }

    let tenant = args
        .tenant_id
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| anyhow!("client credentials require --tenant-id"))?;
    let client_id = args
        .client_id
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| anyhow!("client credentials require --client-id"))?;
    let secret = args
        .client_secret
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| anyhow!("client credentials require --client-secret"))?;

    let token_url = format!("{}/{tenant}/oauth2/v2.0/token", normalize_authority(args));
    let rsp = http
        .post(token_url)
        .form(&[
            ("client_id", client_id),
            ("client_secret", secret),
            ("grant_type", "client_credentials"),
            ("scope", DEFAULT_SCOPE),
        ])
        .send()
        .context("OAuth token request (codesigning.azure.net)")?;
    if !rsp.status().is_success() {
        return Err(anyhow!(
            "OAuth HTTP {}: {}",
            rsp.status(),
            rsp.text().unwrap_or_default()
        ));
    }
    #[derive(Deserialize)]
    struct TokenJson {
        access_token: String,
    }
    let j: TokenJson = rsp.json().context("OAuth JSON")?;
    Ok(j.access_token)
}

fn poll_operation(http: &reqwest::blocking::Client, token: &str, poll_url: &str) -> Result<Value> {
    let url_str = poll_url.to_string();
    for _ in 0..90 {
        let rsp = http
            .get(&url_str)
            .header("Authorization", format!("Bearer {token}"))
            .send()
            .context("poll codesign operation")?;
        if !rsp.status().is_success() {
            return Err(anyhow!(
                "poll HTTP {}: {}",
                rsp.status(),
                rsp.text().unwrap_or_default()
            ));
        }
        let v: Value = rsp.json().context("poll JSON")?;
        let status = v
            .get("status")
            .and_then(|s| s.as_str())
            .unwrap_or_default();
        match status {
            "Succeeded" => return Ok(v),
            "Failed" => {
                return Err(anyhow!(
                    "codesign operation failed: {}",
                    serde_json::to_string(&v).unwrap_or_default()
                ));
            }
            "Canceled" => return Err(anyhow!("codesign operation canceled")),
            _ => thread::sleep(Duration::from_secs(2)),
        }
    }
    Err(anyhow!(
        "codesign operation timed out polling {url_str}"
    ))
}

pub fn artifact_signing_submit_command(
    args: &ArtifactSigningSubmitArgs,
    global: &GlobalOpts,
) -> Result<CommandOutput> {
    validate_submit_args(args)?;

    let digest = std::fs::read(&args.digest_file)
        .with_context(|| format!("read digest file {}", args.digest_file.display()))?;
    if digest.is_empty() {
        return Err(anyhow!("digest file is empty"));
    }

    let token = acquire_codesigning_token(args)?;
    let http = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()
        .map_err(|e| anyhow!("HTTP client: {e}"))?;

    let region = args.region.trim();
    let account = args.account_name.trim();
    let profile = args.profile_name.trim();
    let api = args.api_version.trim();
    let submit_url = format!(
        "https://{region}.codesigning.azure.net/codesigningaccounts/{account}/certificateprofiles/{profile}:sign?api-version={api}",
    );

    let body = serde_json::json!({
        "signatureAlgorithm": args.signature_algorithm.trim(),
        "digest": base64::engine::general_purpose::STANDARD.encode(&digest),
    });

    let mut req = http
        .post(&submit_url)
        .header("Authorization", format!("Bearer {token}"))
        .json(&body);
    if let Some(c) = args.correlation_id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        req = req.header("x-ms-correlation-id", c);
    }

    let rsp = req.send().context("codesign :sign POST")?;
    let status = rsp.status();
    let op_location = rsp
        .headers()
        .get("Operation-Location")
        .or_else(|| rsp.headers().get("operation-location"))
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let body_bytes = rsp.bytes().context(":sign body")?;
    let accept_json: Value = serde_json::from_slice(&body_bytes).unwrap_or(Value::Null);

    if !status.is_success() {
        return Err(anyhow!(
            ":sign HTTP {}: {}",
            status,
            String::from_utf8_lossy(&body_bytes)
        ));
    }

    let poll_url = if let Some(loc) = op_location {
        loc
    } else if let Some(id) = accept_json.get("id").and_then(|v| v.as_str()) {
        format!(
            "https://{region}.codesigning.azure.net/codesigningaccounts/{account}/certificateprofiles/{profile}/sign/{id}?api-version={api}",
        )
    } else {
        let out = serde_json::to_string_pretty(&accept_json)?;
        return Ok(CommandOutput::ok(format!("{out}\n")));
    };

    if global.debug {
        eprintln!("[debug] artifact-signing poll URL={poll_url}");
    }

    let final_json = poll_operation(&http, &token, &poll_url)?;
    let out = serde_json::to_string_pretty(&final_json)?;
    Ok(CommandOutput::ok(format!("{out}\n")))
}

fn validate_submit_args(args: &ArtifactSigningSubmitArgs) -> Result<()> {
    let has_tok = args
        .access_token
        .as_ref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    let sp_count = (args.tenant_id.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false) as u8)
        + (args.client_id.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false) as u8)
        + (args.client_secret.as_ref().map(|s| !s.trim().is_empty()).unwrap_or(false) as u8);
    if args.managed_identity {
        if has_tok || sp_count != 0 {
            return Err(anyhow!(
                "use either --managed-identity or access token / client credentials, not multiple"
            ));
        }
        return Ok(());
    }
    if has_tok {
        if sp_count != 0 {
            return Err(anyhow!(
                "use either --access-token or client credentials tenant/id/secret, not both"
            ));
        }
        return Ok(());
    }
    if sp_count != 0 && sp_count != 3 {
        return Err(anyhow!(
            "client credentials require all of --tenant-id, --client-id, and --client-secret"
        ));
    }
    if sp_count == 0 {
        return Err(anyhow!(
            "choose authentication: --managed-identity, --access-token, or tenant/client-id/client-secret"
        ));
    }
    Ok(())
}
