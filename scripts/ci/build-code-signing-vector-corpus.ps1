# Build a persistent unsigned + signed test-vector corpus.
#
# This script writes files under tests/fixtures/generated-unsigned and
# tests/fixtures/generated-signed, plus per-tree manifests. It uses the vendored
# Devolutions public test PFX by default.
param(
    [string]$WorkspaceRoot = "",
    [string]$UnsignedDir = "",
    [string]$SignedDir = "",
    [string]$UnsignedArchivePath = "",
    [string]$SignedArchivePath = "",
    [string]$SignToolPath = "",
    [string]$PfxPath = "",
    [string]$PfxPassword = "CodeSign123!",
    [string]$TimestampUrl = "",
    [switch]$IncludeSdkPackages,
    [switch]$SignProbeRows,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if (-not $WorkspaceRoot) {
    $WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}
$WorkspaceRoot = (Resolve-Path -LiteralPath $WorkspaceRoot).Path

if (-not $UnsignedDir) { $UnsignedDir = Join-Path $WorkspaceRoot "tests\fixtures\generated-unsigned" }
elseif (-not [System.IO.Path]::IsPathRooted($UnsignedDir)) { $UnsignedDir = Join-Path $WorkspaceRoot $UnsignedDir }

if (-not $SignedDir) { $SignedDir = Join-Path $WorkspaceRoot "tests\fixtures\generated-signed" }
elseif (-not [System.IO.Path]::IsPathRooted($SignedDir)) { $SignedDir = Join-Path $WorkspaceRoot $SignedDir }

if (-not $UnsignedArchivePath) { $UnsignedArchivePath = Join-Path $WorkspaceRoot "tests\fixtures\generated-unsigned.zip" }
elseif (-not [System.IO.Path]::IsPathRooted($UnsignedArchivePath)) { $UnsignedArchivePath = Join-Path $WorkspaceRoot $UnsignedArchivePath }

if (-not $SignedArchivePath) { $SignedArchivePath = Join-Path $WorkspaceRoot "tests\fixtures\generated-signed.zip" }
elseif (-not [System.IO.Path]::IsPathRooted($SignedArchivePath)) { $SignedArchivePath = Join-Path $WorkspaceRoot $SignedArchivePath }

function Resolve-File {
    param([string[]]$Candidates, [string]$Name)
    foreach ($candidate in $Candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate)) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

if (-not $SignToolPath) {
    $SignToolPath = Resolve-File -Name "signtool.exe" -Candidates @(
        (Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\App Certification Kit\signtool.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Microsoft SDKs\ClickOnce\SignTool\signtool.exe")
    )
}
if (-not $SignToolPath) { throw "signtool.exe not found." }

if (-not $PfxPath) {
    $PfxPath = Join-Path $WorkspaceRoot "tests\fixtures\devolutions-authenticode\authenticode-test-cert.pfx"
}
elseif (-not [System.IO.Path]::IsPathRooted($PfxPath)) {
    $PfxPath = Join-Path $WorkspaceRoot $PfxPath
}
if (-not (Test-Path -LiteralPath $PfxPath)) { throw "PFX not found: $PfxPath" }

$buildUnsigned = Join-Path $PSScriptRoot "build-code-signing-vector-samples.ps1"
$unsignedArgs = @{
    WorkspaceRoot = $WorkspaceRoot
    OutputDir = $UnsignedDir
    ArchivePath = $UnsignedArchivePath
    Force = $Force
}
if ($IncludeSdkPackages) { $unsignedArgs.IncludeSdkPackages = $true }
& $buildUnsigned @unsignedArgs

if ((Test-Path -LiteralPath $SignedDir) -and -not $Force) {
    throw "Signed output directory already exists: $SignedDir. Pass -Force to replace it."
}
if (Test-Path -LiteralPath $SignedDir) {
    Remove-Item -LiteralPath $SignedDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $SignedDir | Out-Null

$unsignedManifest = Join-Path $UnsignedDir "generated-vectors.json"
$unsigned = Get-Content -LiteralPath $unsignedManifest -Raw | ConvertFrom-Json
$signedEntries = New-Object System.Collections.Generic.List[object]
$skippedEntries = New-Object System.Collections.Generic.List[object]
$failedEntries = New-Object System.Collections.Generic.List[object]

function Add-ReportEntry {
    param(
        [Parameter(Mandatory)]$List,
        [Parameter(Mandatory)]$Vector,
        [string]$Status,
        [string]$Path = "",
        [string]$Message = ""
    )
    $entry = [ordered]@{
        id = $Vector.id
        family = $Vector.family
        extension = $Vector.extension
        state = $Status
        source_path = $Vector.path
    }
    if ($Path) {
        $file = Get-Item -LiteralPath $Path
        $entry.path = (Resolve-Path -LiteralPath $file.FullName -Relative).TrimStart('.', '\')
        $entry.size_bytes = $file.Length
        $entry.sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
    }
    if ($Message) { $entry.message = $Message }
    $List.Add($entry)
}

function Should-SignEmbedded {
    param($Vector)
    if ($Vector.state -match "negative|placeholder|content|ci-generated-signature|probe" -and -not $SignProbeRows) {
        return $false
    }
    switch ($Vector.family) {
        "pe" { return $Vector.state -ne "negative" }
        "winmd" { return $true }
        "cab" { return $true }
        "powershell-script" { return $true }
        "wsh-script" {
            return @(".js", ".vbs", ".wsf") -contains [string]$Vector.extension
        }
        "msix" {
            return @(".msix", ".appx", ".msixbundle", ".appxbundle") -contains [string]$Vector.extension
        }
        "installer" {
            return @(".msi", ".msp", ".mst") -contains [string]$Vector.extension
        }
        default { return $false }
    }
}

function Is-ExpectedNativeSignReject {
    param($Vector, [string]$Output)
    if (($Vector.family -eq "powershell-script") -and ($Vector.encoding -eq "utf16be-bom")) {
        return $Output -match "SignerSign\(\) failed" -and $Output -match "0x8007000d"
    }
    return $false
}

function Invoke-SignTool {
    param([string[]]$Arguments)
    $saved = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $output = & $SignToolPath @Arguments 2>&1
    $code = $LASTEXITCODE
    $ErrorActionPreference = $saved
    [pscustomobject]@{
        ExitCode = $code
        Output = ($output -join "`n")
    }
}

foreach ($vector in $unsigned.vectors) {
    $src = Join-Path $WorkspaceRoot $vector.path
    if (-not (Test-Path -LiteralPath $src)) {
        Add-ReportEntry -List $failedEntries -Vector $vector -Status "missing-source" -Message "Source file not found."
        continue
    }

    if (Should-SignEmbedded -Vector $vector) {
        $rel = [string]$vector.path
        $prefix = (Resolve-Path -LiteralPath $UnsignedDir -Relative).TrimStart('.', '\').TrimEnd('\')
        if ($rel.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            $rel = $rel.Substring($prefix.Length).TrimStart('\')
        }
        $dest = Join-Path $SignedDir $rel
        New-Item -ItemType Directory -Force -Path (Split-Path $dest -Parent) | Out-Null
        Copy-Item -LiteralPath $src -Destination $dest -Force

        $args = @("sign", "/fd", "SHA256", "/f", $PfxPath, "/p", $PfxPassword)
        if (($vector.family -eq "msix") -and $TimestampUrl) {
            $args += @("/tr", $TimestampUrl, "/td", "SHA256")
        }
        $args += @($dest)
        $result = Invoke-SignTool -Arguments $args
        if ($result.ExitCode -eq 0) {
            Add-ReportEntry -List $signedEntries -Vector $vector -Status "signed" -Path $dest
        }
        elseif (Is-ExpectedNativeSignReject -Vector $vector -Output $result.Output) {
            Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue
            Add-ReportEntry -List $skippedEntries -Vector $vector -Status "native-sign-rejected" -Message $result.Output
        }
        else {
            Remove-Item -LiteralPath $dest -Force -ErrorAction SilentlyContinue
            Add-ReportEntry -List $failedEntries -Vector $vector -Status "sign-failed" -Message $result.Output
        }
    }
    else {
        Add-ReportEntry -List $skippedEntries -Vector $vector -Status "skipped"
    }
}

$detachedDir = Join-Path $SignedDir "detached"
New-Item -ItemType Directory -Force -Path $detachedDir | Out-Null
foreach ($content in $unsigned.vectors | Where-Object { $_.family -eq "detached-pkcs7" -and $_.state -eq "content" }) {
    $src = Join-Path $WorkspaceRoot $content.path
    $outDir = Join-Path $detachedDir ([System.IO.Path]::GetFileNameWithoutExtension([string]$content.path))
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    $args = @("sign", "/fd", "SHA256", "/f", $PfxPath, "/p", $PfxPassword, "/p7", $outDir, "/p7ce", "DetachedSignedData", "/p7co", "1.2.840.113549.1.7.2", $src)
    $result = Invoke-SignTool -Arguments $args
    $p7 = Get-ChildItem -LiteralPath $outDir -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($result.ExitCode -eq 0 -and $p7) {
        Add-ReportEntry -List $signedEntries -Vector $content -Status "detached-signed" -Path $p7.FullName
    }
    else {
        Add-ReportEntry -List $failedEntries -Vector $content -Status "detached-sign-failed" -Message $result.Output
    }
}

$signedManifest = Join-Path $SignedDir "generated-signed-vectors.json"
[ordered]@{
    generated_by = "scripts/ci/build-code-signing-vector-corpus.ps1"
    signing_tool = "signtool.exe"
    pfx = (Resolve-Path -LiteralPath $PfxPath -Relative)
    timestamp_url = $TimestampUrl
    signed = $signedEntries
    skipped = $skippedEntries
    failed = $failedEntries
} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $signedManifest -Encoding utf8

if (Test-Path -LiteralPath $SignedArchivePath) {
    Remove-Item -LiteralPath $SignedArchivePath -Force
}
$archiveItems = Get-ChildItem -LiteralPath $SignedDir -Force
if ($archiveItems.Count -gt 0) {
    Compress-Archive -LiteralPath $archiveItems.FullName -DestinationPath $SignedArchivePath -Force
}

Write-Host "Unsigned vectors: $($unsigned.vectors.Count)"
Write-Host "Signed vectors:   $($signedEntries.Count)"
Write-Host "Skipped vectors:  $($skippedEntries.Count)"
Write-Host "Failed vectors:   $($failedEntries.Count)"
Write-Host "Signed manifest:  $signedManifest"
