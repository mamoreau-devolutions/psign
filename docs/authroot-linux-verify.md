# AuthRoot-style anchors on Linux

Windows resolves Authenticode chains against machine/user certificate stores plus **Microsoft Authenticode roots**. On Linux, **`psign-tool portable trust-verify-pe`** requires you to supply **explicit roots** (and optionally intermediates embedded in the PE PKCS#7).

## Phase A — anchor directory (recommended first ship)

1. On a Windows machine with updates, sync roots you trust, for example:
   - **`certutil -generateSSTFromWU roots.sst`** then export, or  
   - Copy known **`.crt`** / **`.cer`** files into a folder (repo-local or CI cache).
2. Pass **`--anchor-dir /path/to/certs`** to **`trust-verify-pe`**.  
   Non-recursive: only **`*.crt`**, **`*.cer`**, **`*.pem`** in that directory are loaded.
3. Thumbprints are **SHA-1 over full certificate DER** (same convention as many Windows tools), not TBSCertificate-only.

Keep separate what you **trust as an anchor** vs what happens to be embedded in the PE (intermediates are usually present in the signature).

## Phase B — `authrootstl.cab` extraction

`psign-authenticode-trust` reads a Microsoft **`authrootstl.cab`**, walks **`*.stl`** entries, and:

1. Harvests **X.509 certificates** from PKCS#7 blobs (`Pkcs7::from_der` on each member).
2. Parses PKCS#7 **`ContentInfo` → `SignedData`** when present and extracts CTL **`eContent`** **TrustedSubject** SHA-1 **`SubjectIdentifier`** octets into the anchor thumbprint set (alongside cert-derived thumbs).

Pass **`--authroot-cab /path/to/authrootstl.cab`** on any **`trust-verify-*`** subcommand.

### Bootstrap integrity

- **CI / reproducibility:** pin a **SHA-256** of the CAB; pass **`--expect-authroot-cab-sha256 <64-hex>`** so ingest aborts on mismatch.
- **Future hardening:** verify the **outer** Authenticode signature / CTL semantics on the STL (see technical plan).

## Example

```bash
psign-tool portable trust-verify-pe \
  --anchor-dir ./my-trusted-roots \
  ./signed.exe
```

With Microsoft root harvest from CAB:

```bash
psign-tool portable trust-verify-pe \
  --authroot-cab ./authrootstl.cab \
  --anchor-dir ./extra-enterprise-roots \
  --verbose-chain \
  ./signed.exe
```

Strict **code signing** EKU is default; for diagnostics only:

```bash
psign-tool portable trust-verify-pe --allow-loose-signing-cert ...
```

Expired corpora / reproducible CI: pin verification instant:

```bash
psign-tool portable trust-verify-pe --anchor-dir ./roots --as-of 2023-07-01 ./fixture.exe
```

## Related docs

- **[authenticode-trust-stack.md](authenticode-trust-stack.md)** — crate split and verification order.
- **[plan-linux-authenticode-trust-verify.md](plan-linux-authenticode-trust-verify.md)** — full design / risks / test matrix.
