# API Protector: Full Setup Guide

This guide explains the complete workflow for installing, using, and testing API Protector.

## What This Tool Does

API Protector scans repositories for likely leaked secrets, with focused coverage for LLM providers.

It can:
- Scan any folder from the terminal.
- Return JSON output for automation.
- Block `git commit` with a pre-commit hook when severity crosses your threshold.
- Show remediation guidance for each finding.

## Detection Coverage

Current key/signature coverage includes:
- OpenAI (`sk-...`, `sk-proj-...`)
- Anthropic (`sk-ant-...`)
- Groq (`gsk_...`)
- Perplexity (`pplx-...`)
- Cohere (`co_...`)
- Mistral-like (`mistral_...`, `mis_...`)
- AWS access key IDs (`AKIA...`)
- GitHub PAT (`ghp_...`)
- Slack tokens (`xox...`)
- Stripe live keys (`sk_live_...`)
- Google API keys (`AIza...`)
- Suspicious env variable assignments such as `OPENAI_API_KEY=...`

## Install From Terminal

Run:

```powershell
$p="$env:TEMP\api_protector_install.ps1"; irm https://raw.githubusercontent.com/JasperBlank/API_Protector/main/install.ps1 -OutFile $p; powershell -ExecutionPolicy Bypass -File $p -Owner JasperBlank -Repo API_Protector
```

Default install location:
- `C:\Users\<you>\.api-key-guard`

## Run A Scan

Scan a repo:

```powershell
python "$HOME\.api-key-guard\api_key_guard.py" "$HOME\API_Protector"
```

JSON output:

```powershell
python "$HOME\.api-key-guard\api_key_guard.py" "$HOME\API_Protector" --json
```

Fail when severity is high or above:

```powershell
python "$HOME\.api-key-guard\api_key_guard.py" "$HOME\API_Protector" --fail-on high
```

## Enable Pre-Commit Protection

Install hook in a target git repo:

```powershell
powershell -ExecutionPolicy Bypass -File "$HOME\.api-key-guard\install_pre_commit_hook.ps1" -RepoPath "$HOME\API_Protector" -FailOn high
```

After this, every `git commit` in that repo will run the scanner first.

## Verify Hook Works

Create a safe fake test leak:

```powershell
"OPENAI_API_KEY=EXAMPLE_NOT_A_REAL_KEY" | Out-File .\_hook_test_leak.env -Encoding ascii
git add .\_hook_test_leak.env
git commit -m "hook test"
```

Expected result:
- Commit is blocked.
- Output shows severity `high` and remediation steps.

Cleanup test file:

```powershell
Remove-Item .\_hook_test_leak.env -Force
git reset HEAD .\_hook_test_leak.env
```

## Severity Model

- `clean`: no findings
- `low`: only a small number of suspicious env assignments
- `medium`: many suspicious env assignments
- `high`: at least one direct key/token leak
- `critical`: multiple direct key/token leaks

## Daily Workflow Recommendation

1. Keep pre-commit enabled on active repos.
2. Run ad-hoc scans before opening pull requests.
3. If a leak is found, rotate/revoke immediately.
4. Replace hardcoded secrets with secret manager references.
5. Re-scan and confirm `Severity: clean`.

## Troubleshooting

If you see:
- `Missing an argument for parameter 'Repo'`
Use:
- `-Repo API_Protector` on the same line.

If you see:
- `detected dubious ownership in repository`
Run:

```powershell
git config --global --add safe.directory C:/Users/jjbla/API_Protector
```

If a commit is not blocked even though findings appear:
- Reinstall the hook to refresh script contents:

```powershell
powershell -ExecutionPolicy Bypass -File "$HOME\.api-key-guard\install_pre_commit_hook.ps1" -RepoPath "$HOME\API_Protector" -FailOn high
```

## Project Files

- `api_key_guard.py` scanner
- `install.ps1` terminal installer
- `install_pre_commit_hook.ps1` git hook installer
- `README.md` short project overview
- `FULL_SETUP_GUIDE.md` complete operations guide
