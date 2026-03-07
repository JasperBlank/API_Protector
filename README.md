# API Key Guard

A local CLI scanner that detects leaked credentials and risky API key assignments in your codebase, with provider-specific remediation guidance.

## Quick Start

```bash
# Clone and run directly
git clone https://github.com/JasperBlank/API_Protector.git
cd API_Protector
python api_key_guard.py /path/to/your/repo
```

Windows (PowerShell):
```powershell
python .\api_key_guard.py C:\path\to\your\repo
```

JSON output:
```powershell
python .\api_key_guard.py C:\path\to\your\repo --json
```

Fail build/commit when severity is high or worse:
```powershell
python .\api_key_guard.py C:\path\to\your\repo --fail-on high
```

## One-Line Install (PowerShell)

```powershell
$p="$env:TEMP\api_protector_install.ps1"; irm https://raw.githubusercontent.com/JasperBlank/API_Protector/main/install.ps1 -OutFile $p; powershell -ExecutionPolicy Bypass -File $p -Owner JasperBlank -Repo API_Protector
```

## What It Detects

- OpenAI keys (`sk-...`, `sk-proj-...`)
- Anthropic keys (`sk-ant-...`)
- Groq keys (`gsk_...`)
- Perplexity keys (`pplx-...`)
- Cohere keys (`co_...`)
- Mistral keys (`mistral_...` / `mis_...`)
- AWS access keys (`AKIA...`)
- GitHub PATs (`ghp_...`)
- Slack tokens (`xox...`)
- Stripe live secrets (`sk_live_...`)
- Google API keys (`AIza...`)
- High-risk env key assignments (`OPENAI_API_KEY=...`, etc.)

For each finding, output includes a `remediation` note and a deduplicated `playbook` with rotate/revoke steps.

## Install as Git Pre-Commit Hook

Blocks commits automatically when leaked credentials are found:

```powershell
.\install_pre_commit_hook.ps1 -RepoPath C:\path\to\your\repo -FailOn high
```

After install, every `git commit` in that repo runs the scanner and blocks if the threshold is met.

## Files

- `api_key_guard.py` — CLI scanner
- `install.ps1` — one-line terminal installer
- `install_pre_commit_hook.ps1` — git pre-commit hook installer
- `FULL_SETUP_GUIDE.md` — full setup and troubleshooting guide
