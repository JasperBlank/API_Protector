param(
    [string]$Owner = "",
    [string]$Repo = "",
    [string]$Branch = "main",
    [string]$InstallDir = ""
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $InstallDir = Join-Path $HOME ".api-key-guard"
}

if ([string]::IsNullOrWhiteSpace($Owner) -or [string]::IsNullOrWhiteSpace($Repo)) {
    throw "Provide -Owner and -Repo. Example: .\install.ps1 -Owner yourname -Repo api-key-guard"
}

$base = "https://raw.githubusercontent.com/$Owner/$Repo/$Branch"
$files = @(
    "api_key_guard.py",
    "install_pre_commit_hook.ps1",
    "README.md"
)

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

foreach ($f in $files) {
    $url = "$base/$f"
    $out = Join-Path $InstallDir $f
    Invoke-WebRequest -Uri $url -OutFile $out
}

Write-Host "Installed API Key Guard to: $InstallDir"
Write-Host "Run scanner:"
Write-Host "  python `"$InstallDir\api_key_guard.py`" ."
Write-Host ""
Write-Host "Install git pre-commit hook in a repo:"
Write-Host "  powershell -ExecutionPolicy Bypass -File `"$InstallDir\install_pre_commit_hook.ps1`" -RepoPath C:\path\to\repo -FailOn high"
