//! Mock Azure Code Signing `:sign` POST + LRO GET (no real `codesigning.azure.net`).

use mockito::{Matcher, Server};
use signtool_codesigning_rest::{
    CodesigningAuth, CodesigningSubmitParams, submit_codesign_hash_blocking,
};

#[test]
fn submit_poll_via_operation_location_header() {
    let mut server = Server::new();
    let base = server.url().trim_end_matches('/').to_string();
    let poll_url = format!("{base}/operations/abc123");

    let post_mock = server
        .mock(
            "POST",
            Matcher::Regex(
                r"/codesigningaccounts/theacct/certificateprofiles/theprof:sign(\?.*)?$"
                    .to_string(),
            ),
        )
        .with_status(202)
        .with_header("Operation-Location", &poll_url)
        .with_body("{}")
        .create();

    let poll_mock = server
        .mock(
            "GET",
            Matcher::Regex(r"/operations/abc123(\?.*)?$".to_string()),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"status":"Succeeded","signature":"mock-sig-field"}"#)
        .create();

    let params = CodesigningSubmitParams {
        region: "unused-for-mock".into(),
        account_name: "theacct".into(),
        profile_name: "theprof".into(),
        digest: vec![0x01, 0x02, 0x03],
        signature_algorithm: "RS256".into(),
        api_version: "2023-06-15-preview".into(),
        correlation_id: None,
        authority: None,
        auth: CodesigningAuth::Bearer("fake-token".into()),
        endpoint_base_url: Some(base),
    };

    let out = submit_codesign_hash_blocking(&params, |_| {}).expect("submit");
    assert_eq!(
        out.get("status").and_then(|v| v.as_str()),
        Some("Succeeded")
    );
    assert_eq!(
        out.get("signature").and_then(|v| v.as_str()),
        Some("mock-sig-field")
    );

    post_mock.assert();
    poll_mock.assert();
}

#[test]
fn submit_poll_via_accept_body_id_field() {
    let mut server = Server::new();
    let base = server.url().trim_end_matches('/').to_string();

    let post_mock = server
        .mock(
            "POST",
            Matcher::Regex(
                r"/codesigningaccounts/acct/certificateprofiles/prof:sign(\?.*)?$".to_string(),
            ),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"id":"job-from-body"}"#)
        .create();

    let poll_mock = server
        .mock(
            "GET",
            Matcher::Regex(
                r"/codesigningaccounts/acct/certificateprofiles/prof/sign/job-from-body(\?.*)?$"
                    .to_string(),
            ),
        )
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(r#"{"status":"Succeeded","done":true}"#)
        .create();

    let params = CodesigningSubmitParams {
        region: "unused-for-mock".into(),
        account_name: "acct".into(),
        profile_name: "prof".into(),
        digest: vec![0xff],
        signature_algorithm: "RS256".into(),
        api_version: "2023-06-15-preview".into(),
        correlation_id: None,
        authority: None,
        auth: CodesigningAuth::Bearer("tok".into()),
        endpoint_base_url: Some(base),
    };

    let out = submit_codesign_hash_blocking(&params, |_| {}).expect("submit");
    assert_eq!(
        out.get("status").and_then(|v| v.as_str()),
        Some("Succeeded")
    );
    assert_eq!(out.get("done").and_then(|v| v.as_bool()), Some(true));

    post_mock.assert();
    poll_mock.assert();
}
