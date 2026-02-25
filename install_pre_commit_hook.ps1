param(
    [Parameter(Mandatory = $true)]
    [string]$RepoPath,
    [string]$FailOn = "high"
)

$ErrorActionPreference = "Stop"

$resolvedRepo = (Resolve-Path $RepoPath).Path
$gitDir = Join-Path $resolvedRepo ".git"
if (-not (Test-Path $gitDir)) {
    throw "Target is not a git repository: $resolvedRepo"
}

$allowed = @("clean", "low", "medium", "high", "critical")
if ($allowed -notcontains $FailOn) {
    throw "Invalid -FailOn value '$FailOn'. Allowed: $($allowed -join ', ')"
}

$hookPath = Join-Path $gitDir "hooks\pre-commit"
$scannerPath = (Resolve-Path "$PSScriptRoot\api_key_guard.py").Path.Replace("\", "/")

$hookContent = @"
#!/bin/sh
python "$scannerPath" "." --fail-on $FailOn
status=$?
if [ $status -ne 0 ]; then
  echo "Commit blocked by API Key Guard."
  exit $status
fi
"@

Set-Content -Path $hookPath -Value $hookContent -NoNewline
Write-Host "Installed pre-commit hook at: $hookPath"
Write-Host "Scanner: $scannerPath"
Write-Host "Fail threshold: $FailOn"
