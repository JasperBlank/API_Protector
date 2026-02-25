# Codex MVP: API Key Guard

Executed idea from Claude doc: **"1Password for API Keys"**.

This is a tiny, local-first MVP that scans a codebase for likely leaked credentials and risky env keys.
It now includes an **LLM API key policy pack** with provider-specific remediation guidance.

## Files

- `api_key_guard.py` - CLI scanner
- `install.ps1` - terminal installer/updater from GitHub raw
- `install_pre_commit_hook.ps1` - installs git pre-commit hook
- `FULL_SETUP_GUIDE.md` - complete setup + troubleshooting guide

## Quick Start

```powershell
cd C:\Users\jjbla\API_Protector
python .\api_key_guard.py C:\path\to\repo
```

## One-Line Terminal Install (after GitHub publish)

```powershell
$p="$env:TEMP\api_protector_install.ps1"; irm https://raw.githubusercontent.com/JasperBlank/API_Protector/main/install.ps1 -OutFile $p; powershell -ExecutionPolicy Bypass -File $p -Owner JasperBlank -Repo API_Protector
```

JSON output:

```powershell
python .\api_key_guard.py C:\path\to\repo --json
```

Fail build/commit when severity is high or worse:

```powershell
python .\api_key_guard.py C:\path\to\repo --fail-on high
```

## What It Detects (MVP)

- OpenAI keys (`sk-...`, `sk-proj-...`)
- Anthropic keys (`sk-ant-...`)
- Groq keys (`gsk_...`)
- Perplexity keys (`pplx-...`)
- Cohere keys (`co_...`)
- Mistral-like keys (`mistral_...` / `mis_...`)
- AWS access keys (`AKIA...`)
- GitHub PATs (`ghp_...`)
- Slack tokens (`xox...`)
- Stripe live secrets (`sk_live_...`)
- Google API keys (`AIza...`)
- High-risk env key assignments (`OPENAI_API_KEY=...`, etc.)

For each finding, JSON output includes `remediation` and a deduplicated `playbook` section with rotate/revoke actions.

## Why This Is A Good First Slice

- Matches the startup thesis: find API key sprawl before it becomes a breach.
- Simple enough to validate quickly with developers.
- Easy next step: wire into pre-commit/CI and add secret revocation workflows.

## Install Git Pre-Commit Hook

Install into any local git repo:

```powershell
cd C:\Users\jjbla\API_Protector
.\install_pre_commit_hook.ps1 -RepoPath C:\path\to\your\repo -FailOn high
```

After install, every `git commit` in that repo runs the scanner and blocks commit if threshold is met.
