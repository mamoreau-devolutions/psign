use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::Path;

#[test]
fn code_signing_vector_manifest_committed_entries_are_current() {
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/code-signing-vectors.json"))
            .expect("code-signing vector manifest JSON");
    assert_eq!(manifest["schema_version"], 1);

    let vectors = manifest["vectors"]
        .as_array()
        .expect("vectors must be an array");
    assert!(
        !vectors.is_empty(),
        "code-signing vector manifest must not be empty"
    );

    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut ids = HashSet::new();
    let mut committed_count = 0usize;

    for vector in vectors {
        let id = vector["id"].as_str().expect("vector id");
        assert!(ids.insert(id.to_owned()), "duplicate vector id: {id}");

        let family = vector["family"].as_str().expect("vector family");
        assert!(!family.trim().is_empty(), "empty family for {id}");

        let extensions = vector["extensions"]
            .as_array()
            .expect("extensions must be an array");
        assert!(!extensions.is_empty(), "missing extensions for {id}");

        let operations = vector["operations"]
            .as_array()
            .expect("operations must be an array");
        assert!(!operations.is_empty(), "missing operations for {id}");

        let storage = vector["storage"].as_str().expect("vector storage");
        if storage != "committed" {
            continue;
        }

        committed_count += 1;
        let rel = vector["path"].as_str().expect("committed vector path");
        let path = repo_root.join(rel);
        assert!(path.is_file(), "committed vector missing: {rel}");

        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {rel}: {e}"));
        let expected_size = vector["size_bytes"].as_u64().expect("size_bytes");
        assert_eq!(bytes.len() as u64, expected_size, "size mismatch for {rel}");

        let actual_hash = hex_lower(Sha256::digest(&bytes).as_slice());
        let expected_hash = vector["sha256"].as_str().expect("sha256");
        assert_eq!(actual_hash, expected_hash, "sha256 mismatch for {rel}");
    }

    assert!(
        committed_count >= 10,
        "expected manifest to describe the existing committed fixture corpus"
    );
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
