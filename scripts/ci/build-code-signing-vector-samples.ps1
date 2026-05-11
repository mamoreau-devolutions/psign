# Generate small unsigned inputs for code-signing parity tests.
#
# The default output directory is gitignored. Commit the zip only after reviewing
# size, hashes, and provenance in tests/fixtures/code-signing-vectors.json.
param(
    [string]$WorkspaceRoot = "",
    [string]$OutputDir = "",
    [string]$ArchivePath = "",
    [string]$PeSource = "",
    [switch]$IncludeSdkPackages,
    [switch]$RequireSdkTools,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

if (-not $WorkspaceRoot) {
    $WorkspaceRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}
$WorkspaceRoot = (Resolve-Path -LiteralPath $WorkspaceRoot).Path

if (-not $OutputDir) {
    $OutputDir = Join-Path $WorkspaceRoot "tests\fixtures\generated-unsigned"
}
elseif (-not [System.IO.Path]::IsPathRooted($OutputDir)) {
    $OutputDir = Join-Path $WorkspaceRoot $OutputDir
}

if (-not $ArchivePath) {
    $ArchivePath = Join-Path $WorkspaceRoot "tests\fixtures\generated-unsigned.zip"
}
elseif (-not [System.IO.Path]::IsPathRooted($ArchivePath)) {
    $ArchivePath = Join-Path $WorkspaceRoot $ArchivePath
}

if (-not $PeSource) {
    $PeSource = Join-Path $WorkspaceRoot "tests\fixtures\pe-authenticode-upstream\tiny64.efi"
}
elseif (-not [System.IO.Path]::IsPathRooted($PeSource)) {
    $PeSource = Join-Path $WorkspaceRoot $PeSource
}
if (-not (Test-Path -LiteralPath $PeSource)) {
    throw "PE source not found: $PeSource"
}

if ((Test-Path -LiteralPath $OutputDir) -and -not $Force) {
    throw "Output directory already exists: $OutputDir. Pass -Force to replace it."
}
if (Test-Path -LiteralPath $OutputDir) {
    Remove-Item -LiteralPath $OutputDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$entries = New-Object System.Collections.Generic.List[object]

function Add-GeneratedEntry {
    param(
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Family,
        [Parameter(Mandatory)][string]$Path,
        [string[]]$Extensions = @()
    )
    $file = Get-Item -LiteralPath $Path
    $rel = Resolve-Path -LiteralPath $file.FullName -Relative
    $entries.Add([ordered]@{
            id          = $Id
            family      = $Family
            extensions  = $Extensions
            path        = $rel.TrimStart('.', '\')
            size_bytes  = $file.Length
            sha256      = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
        })
}

function Copy-Vector {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Family,
        [string[]]$Extensions = @()
    )
    $dest = Join-Path $OutputDir $RelativePath
    New-Item -ItemType Directory -Force -Path (Split-Path $dest -Parent) | Out-Null
    Copy-Item -LiteralPath $Source -Destination $dest -Force
    Add-GeneratedEntry -Id $Id -Family $Family -Path $dest -Extensions $Extensions
}

function Write-AsciiVector {
    param(
        [Parameter(Mandatory)][string]$RelativePath,
        [Parameter(Mandatory)][string]$Content,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Family,
        [string[]]$Extensions = @()
    )
    $dest = Join-Path $OutputDir $RelativePath
    New-Item -ItemType Directory -Force -Path (Split-Path $dest -Parent) | Out-Null
    Set-Content -LiteralPath $dest -Value $Content -Encoding ascii -NoNewline
    Add-GeneratedEntry -Id $Id -Family $Family -Path $dest -Extensions $Extensions
}

$peAliases = @(".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl", ".efi", ".mui")
foreach ($ext in $peAliases) {
    $name = "tiny64-pe-alias$ext"
    Copy-Vector -Source $PeSource -RelativePath "pe\$name" -Id "generated-pe-$($ext.TrimStart('.'))" -Family "pe" -Extensions @($ext)
}
Copy-Vector -Source $PeSource -RelativePath "winmd\tiny64-pe-copy.winmd" -Id "generated-winmd-pe-copy" -Family "winmd" -Extensions @(".winmd")

$scriptSamples = @(
    @{ Source = "unsigned-sample.ps1"; Id = "generated-script-ps1"; Family = "powershell-script"; Ext = ".ps1" },
    @{ Source = "unsigned-sample.psm1"; Id = "generated-script-psm1"; Family = "powershell-script"; Ext = ".psm1" },
    @{ Source = "unsigned-sample.psd1"; Id = "generated-script-psd1"; Family = "powershell-script"; Ext = ".psd1" },
    @{ Source = "unsigned-sample.js"; Id = "generated-script-js"; Family = "wsh-script"; Ext = ".js" },
    @{ Source = "unsigned-sample.vbs"; Id = "generated-script-vbs"; Family = "wsh-script"; Ext = ".vbs" },
    @{ Source = "unsigned-sample.wsf"; Id = "generated-script-wsf"; Family = "wsh-script"; Ext = ".wsf" }
)
foreach ($sample in $scriptSamples) {
    $src = Join-Path $WorkspaceRoot ("tests\fixtures\" + $sample.Source)
    Copy-Vector -Source $src -RelativePath ("scripts\" + $sample.Source) -Id $sample.Id -Family $sample.Family -Extensions @($sample.Ext)
}

$makecab = Get-Command makecab.exe -ErrorAction SilentlyContinue
if ($makecab) {
    $cabWork = Join-Path $OutputDir "_cab-work"
    New-Item -ItemType Directory -Force -Path $cabWork | Out-Null
    $payload = Join-Path $cabWork "hello.txt"
    Set-Content -LiteralPath $payload -Value "psign cab unsigned fixture`n" -Encoding ascii
    $ddf = Join-Path $cabWork "sample.ddf"
    $cabPath = Join-Path $OutputDir "cab\sample.cab"
    New-Item -ItemType Directory -Force -Path (Split-Path $cabPath -Parent) | Out-Null
    @"
.Set CabinetNameTemplate=$cabPath
.Set DiskDirectoryTemplate=
.Set CompressionType=MSZIP
.Set UniqueFiles=on
.Set Cabinet=on
.Set DiskDirectory1=
$payload
"@ | Set-Content -LiteralPath $ddf -Encoding ascii
    Push-Location $cabWork
    try {
        & $makecab.Source /f (Split-Path $ddf -Leaf) | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "makecab.exe failed with exit $LASTEXITCODE" }
    }
    finally {
        Pop-Location
    }
    Add-GeneratedEntry -Id "generated-cab-unsigned" -Family "cab" -Path $cabPath -Extensions @(".cab")
    Remove-Item -LiteralPath $cabWork -Recurse -Force
}
elseif ($RequireSdkTools) {
    throw "makecab.exe not found."
}

if ($IncludeSdkPackages) {
    $makeAppx = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter MakeAppx.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\x64\\|\\amd64\\' } |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if (-not $makeAppx) {
        if ($RequireSdkTools) { throw "MakeAppx.exe not found under Windows Kits." }
    }
    else {
        $layoutSrc = Join-Path $WorkspaceRoot "tests\fixtures\msix-minimal"
        foreach ($packageExt in @(".msix", ".appx")) {
            $stage = Join-Path $OutputDir ("_appx-stage-" + $packageExt.TrimStart('.'))
            if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
            New-Item -ItemType Directory -Path $stage | Out-Null
            Get-ChildItem -LiteralPath $layoutSrc -Force | Copy-Item -Destination $stage -Recurse -Force
            Copy-Item -LiteralPath $PeSource -Destination (Join-Path $stage "noop.exe") -Force
            $assetsDir = Join-Path $stage "Assets"
            New-Item -ItemType Directory -Force -Path $assetsDir | Out-Null
            $logoPath = Join-Path $assetsDir "StoreLogo.png"
            $pngB64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
            [IO.File]::WriteAllBytes($logoPath, [Convert]::FromBase64String($pngB64))
            $packagePath = Join-Path $OutputDir ("msix\sample" + $packageExt)
            New-Item -ItemType Directory -Force -Path (Split-Path $packagePath -Parent) | Out-Null
            & $makeAppx.FullName pack /h sha256 /d $stage /p $packagePath /o 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "MakeAppx pack failed for $packageExt with exit $LASTEXITCODE" }
            Add-GeneratedEntry -Id ("generated-msix-" + $packageExt.TrimStart('.')) -Family "msix" -Path $packagePath -Extensions @($packageExt)
            Remove-Item -LiteralPath $stage -Recurse -Force
        }
    }
}

Write-AsciiVector -RelativePath "detached\content.bin" -Content "psign detached content fixture`n" -Id "generated-detached-content" -Family "detached-pkcs7" -Extensions @(".bin")

$generatedManifest = Join-Path $OutputDir "generated-vectors.json"
@{
    generated_by = "scripts/ci/build-code-signing-vector-samples.ps1"
    source_pe    = (Resolve-Path -LiteralPath $PeSource -Relative)
    vectors      = $entries
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $generatedManifest -Encoding utf8

if (Test-Path -LiteralPath $ArchivePath) {
    Remove-Item -LiteralPath $ArchivePath -Force
}
New-Item -ItemType Directory -Force -Path (Split-Path $ArchivePath -Parent) | Out-Null
$archiveItems = Get-ChildItem -LiteralPath $OutputDir -Force
if ($archiveItems.Count -eq 0) {
    throw "No generated vector files found under $OutputDir"
}
Compress-Archive -LiteralPath $archiveItems.FullName -DestinationPath $ArchivePath -Force

Write-Host "Generated $($entries.Count) unsigned vector file(s): $OutputDir"
Write-Host "Wrote archive: $ArchivePath"
Write-Host "Wrote generated manifest: $generatedManifest"
