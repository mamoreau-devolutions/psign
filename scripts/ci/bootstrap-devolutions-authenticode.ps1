# Download Devolutions public test CA + code-signing PFX, trust the CA, export env vars for parity CI.
# See https://github.com/Devolutions/devolutions-authenticode — test-only PKI; password is public (CodeSign123!).
param(
    [string]$CommitSha = "df20875f2935645a007a4fdc12bf8900f8316362",
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [switch]$EmitGithubEnv
)

$ErrorActionPreference = "Stop"
$baseUrl = "https://raw.githubusercontent.com/Devolutions/devolutions-authenticode/$CommitSha/data/certs"
$rt = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { $env:TEMP }
$destRoot = Join-Path $rt "devolutions-authenticode-ci"
New-Item -ItemType Directory -Force -Path $destRoot | Out-Null

$caPath = Join-Path $destRoot "authenticode-test-ca.crt"
$pfxPath = Join-Path $destRoot "authenticode-test-cert.pfx"

Invoke-WebRequest -Uri "$baseUrl/authenticode-test-ca.crt" -OutFile $caPath -UseBasicParsing
Invoke-WebRequest -Uri "$baseUrl/authenticode-test-cert.pfx" -OutFile $pfxPath -UseBasicParsing

try {
    Import-Certificate -FilePath $caPath -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
}
catch {
    Write-Warning "LocalMachine\Root import failed ($($_.Exception.Message)); trying CurrentUser\Root."
    Import-Certificate -FilePath $caPath -CertStoreLocation "Cert:\CurrentUser\Root" | Out-Null
}

$pfxPassword = "CodeSign123!"
$lines = @(
    "SIGNTOOL_RS_TEST_PFX=$pfxPath",
    "SIGNTOOL_RS_TEST_PFX_PASSWORD=$pfxPassword",
    "SIGNTOOL_RS_TIMESTAMP_URL=$TimestampUrl",
    "SIGNTOOL_RS_MSIX_TEST_PFX=$pfxPath",
    "SIGNTOOL_RS_MSIX_TEST_PFX_PASSWORD=$pfxPassword",
    "SIGNTOOL_RS_MSIX_TIMESTAMP_URL=$TimestampUrl"
)

# Rust signer signs from store via --cert-sha1 reliably for this PKI; native signtool keeps using /f PFX.
$secure = ConvertTo-SecureString -String $pfxPassword -AsPlainText -Force
try {
    $imported = Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation "Cert:\CurrentUser\My" -Password $secure -Exportable
    $thumb = $imported.Thumbprint
    $lines += @(
        "SIGNTOOL_RS_TEST_CERT_SHA1=$thumb",
        "SIGNTOOL_RS_MSIX_TEST_CERT_SHA1=$thumb"
    )
    Write-Host "Imported test signing cert to CurrentUser\My (thumbprint $thumb)."
}
catch {
    Write-Warning "Import-PfxCertificate to CurrentUser\My failed ($($_.Exception.Message)); set SIGNTOOL_RS_TEST_CERT_SHA1 manually if Rust --pfx signing fails."
}

foreach ($line in $lines) {
    $name, $value = $line.Split("=", 2)
    Set-Item -Path "Env:$name" -Value $value
}

if ($EmitGithubEnv -and $env:GITHUB_ENV) {
    Add-Content -LiteralPath $env:GITHUB_ENV -Value ($lines -join "`n")
}

Write-Host "Devolutions Authenticode bootstrap OK; PFX at $pfxPath"
