# Reversing playbook: signtool, AzureSignTool, signing DLLs

Use this when you need **internals beyond MSDN**—for example mapping CLI switches to **`SignerSignEx3`** parameters or comparing Key Vault REST shapes to **`azure_kv_sign.rs`**.

## IDA Pro (native PE binaries)

**Important:** IDA’s MCP helper often writes a sidecar database (e.g. **`.imcp`**) next to the input PE. Binaries under **`C:\Program Files (x86)\Windows Kits\...`** are usually **not writable**, so **`Access is denied`** is expected. Copy the target first:

```powershell
New-Item -ItemType Directory -Force parity-output\idb-targets | Out-Null
Copy-Item "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe" parity-output\idb-targets\
Copy-Item "$env:SystemRoot\System32\mssign32.dll" parity-output\idb-targets\
Copy-Item "$env:SystemRoot\System32\WINTRUST.dll" parity-output\idb-targets\
```

Then open **`parity-output\idb-targets\signtool.exe`** (or the copied DLLs) in IDA / IDA MCP. Release locks with **`close_idb`** when using the MCP server.

**High-value symbols / imports to xref from `signtool.exe`:**

| Import / concept | Why |
|------------------|-----|
| **`SignerSignEx3`** (`mssign32.dll`) | Core Authenticode sign |
| **`SignerTimeStampEx3`** | RFC3161 timestamp |
| **`WinVerifyTrust`**, **`WTHelperGetProvSignerFromChain`** | Verify path |
| **`CryptSIP*`**, **`Softpub*`** | SIP / trust glue |

Cross-check findings with [`windows-signing-components.md`](windows-signing-components.md) and [`rust-sip-spec-refs.md`](rust-sip-spec-refs.md).

**Artifact Signing dlib:**

```powershell
# After extracting Microsoft.ArtifactSigning.Client NuGet:
Copy-Item "D:\path\to\extracted\bin\x64\Azure.CodeSigning.Dlib.dll" parity-output\idb-targets\
```

Use **`dumpbin /exports`** on the copy first—exports align with **`SIGNER_DIGEST_SIGN_INFO`** / decoupled signing docs.

## ilspycmd / ILSpy (.NET AzureSignTool)

AzureSignTool is .NET; **ilspycmd** gives readable C# without attaching a debugger.

```powershell
dotnet tool install -g ilspycmd   # once per machine
# From a folder containing AzureSignTool.dll (NuGet or publish output):
ilspycmd -p -o .\ast-decompiled AzureSignTool.dll
```

Map decompiled types to this repo:

| Likely AzureSignTool concern | Rust analogue |
|------------------------------|---------------|
| Key Vault **`keys/sign`** HTTP / auth | [`src/win/azure_kv_sign.rs`](../src/win/azure_kv_sign.rs) |
| Digest algorithms / JWS alg (**RS256** / **ES256**, …) | [`signtool-azure-kv-rest`](../crates/signtool-azure-kv-rest/src/lib.rs) **`kv_jws_alg`**, RSA vs EC from **`cer`** DER |
| Batch / HRESULT exits | `SignArgs`, `--exit-codes azuresigntool` |

## ilspycmd (.NET Artifact Signing client libraries)

NuGet packages such as **`Microsoft.ArtifactSigning.Client`** ship managed DLLs (REST LRO, metadata helpers). Extract the package, then:

```powershell
ilspycmd -p -o .\artifact-client-decompiled Microsoft.ArtifactSigning.Client.dll
```

Compare HTTP shapes and JSON models to [`crates/signtool-codesigning-rest`](../crates/signtool-codesigning-rest/) (**`:sign`** LRO, OAuth scope **`https://codesigning.azure.net/.default`**). Native **`Azure.CodeSigning.Dlib.dll`** remains PE — use **IDA** on a writable copy (above).

## Relating reversing work to Linux signing

Neither **`signtool.exe`** nor **`mssign32.dll`** runs on Linux. Reversing clarifies **what** must be reproduced (CMS fields, SIP indirect data, PE certificate directory layout). **PE image checksum:** Native **`CheckSumMappedFile`** / loader verification skips the **`Optional Header.CheckSum`** DWORD while summing 16-bit words, then folds and adds **`FileLength`**. Portable parity: **`signtool-portable pe-checksum`** / **`pe_embed::pe_compute_image_checksum`** (see **`crates/signtool-sip-digest/src/pe_embed.rs`**).

When tracing **`ImageAddCertificate`** / attribute-directory walks in **`imagehlp`**, note **certificate-table iteration order**: **`signtool-portable`** **`list-pe-pkcs7`**, **`extract-pe-pkcs7 --index`**, and **`inspect-pe-spc-indirect --index`** all use the same sequential **`WIN_CERT_TYPE_PKCS_SIGNED_DATA`** row index (not arbitrary Win32 attribute-table indices). Portable work stays in **`signtool-sip-digest`** (digests + future PKCS#7 encode in [`pkcs7.rs`](../crates/signtool-sip-digest/src/pkcs7.rs), [`pe_embed.rs`](../crates/signtool-sip-digest/src/pe_embed.rs)).

See also [`gap-analysis-signing-platforms.md`](gap-analysis-signing-platforms.md).
