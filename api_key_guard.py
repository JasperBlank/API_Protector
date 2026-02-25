#!/usr/bin/env python3
"""
Lightweight API-key leak scanner MVP.

Scans a target directory for common credential patterns and high-risk env names.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_EXCLUDES = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    "dist",
    "build",
    ".next",
    ".idea",
    ".vscode",
}

# Purposefully conservative patterns to reduce noisy false positives.
# Includes a focused LLM/API-provider policy pack.
PATTERNS = {
    "openai_api_key": re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9\-_]{20,}\b"),
    "anthropic_api_key": re.compile(r"\bsk-ant-(?:api03-)?[A-Za-z0-9\-_]{20,}\b"),
    "groq_api_key": re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b"),
    "perplexity_api_key": re.compile(r"\bpplx-[A-Za-z0-9]{20,}\b"),
    "cohere_api_key": re.compile(r"\bco_[A-Za-z0-9]{20,}\b"),
    "mistral_api_key": re.compile(r"\b(?:mistral|mis)_[A-Za-z0-9]{20,}\b"),
    "aws_access_key_id": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_pat": re.compile(r"\bghp_[A-Za-z0-9]{30,}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "stripe_secret": re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
}

SUSPICIOUS_ENV_KEYS = {
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GROQ_API_KEY",
    "PERPLEXITY_API_KEY",
    "COHERE_API_KEY",
    "MISTRAL_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "XAI_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN",
    "STRIPE_SECRET_KEY",
    "SLACK_BOT_TOKEN",
    "DATABASE_URL",
}

REMEDIATION_GUIDE = {
    "openai_api_key": {
        "provider": "OpenAI",
        "action": "Revoke key in OpenAI dashboard, issue a new scoped key, and update environment secrets.",
        "url": "https://platform.openai.com/api-keys",
    },
    "anthropic_api_key": {
        "provider": "Anthropic",
        "action": "Disable the exposed key, create a replacement key, and redeploy secret storage.",
        "url": "https://console.anthropic.com/settings/keys",
    },
    "groq_api_key": {
        "provider": "Groq",
        "action": "Delete the leaked key and rotate credentials in service configs.",
        "url": "https://console.groq.com/keys",
    },
    "perplexity_api_key": {
        "provider": "Perplexity",
        "action": "Revoke and replace the key, then invalidate cached copies in CI/CD variables.",
        "url": "https://www.perplexity.ai/settings/api",
    },
    "cohere_api_key": {
        "provider": "Cohere",
        "action": "Rotate key in Cohere console and redeploy downstream services using secret manager.",
        "url": "https://dashboard.cohere.com/api-keys",
    },
    "mistral_api_key": {
        "provider": "Mistral",
        "action": "Disable compromised token and create a replacement with least privilege.",
        "url": "https://console.mistral.ai/api-keys/",
    },
    "suspicious_env_key": {
        "provider": "Environment variable",
        "action": "Move literal secrets from tracked files into a secret store and commit sanitized values only.",
        "url": "https://12factor.net/config",
    },
}


@dataclass
class Finding:
    file_path: str
    line_no: int
    finding_type: str
    preview: str


def is_binary(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            chunk = f.read(1024)
        return b"\x00" in chunk
    except OSError:
        return True


def redacted_preview(line: str) -> str:
    compact = " ".join(line.strip().split())
    if len(compact) <= 120:
        return compact
    return compact[:117] + "..."


def iter_files(root: Path, excludes: set[str]) -> Iterable[Path]:
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in excludes]
        for file_name in files:
            yield Path(current) / file_name


def scan_file(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    if is_binary(path):
        return findings

    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return findings

    for idx, line in enumerate(lines, start=1):
        for name, pattern in PATTERNS.items():
            if pattern.search(line):
                findings.append(
                    Finding(
                        file_path=str(path),
                        line_no=idx,
                        finding_type=name,
                        preview=redacted_preview(line),
                    )
                )

        if "=" in line:
            key = line.split("=", 1)[0].strip()
            if key in SUSPICIOUS_ENV_KEYS and not line.strip().startswith("#"):
                findings.append(
                    Finding(
                        file_path=str(path),
                        line_no=idx,
                        finding_type="suspicious_env_key",
                        preview=redacted_preview(line),
                    )
                )
    return findings


def score(findings: list[Finding]) -> str:
    direct_leaks = sum(1 for f in findings if f.finding_type != "suspicious_env_key")
    env_refs = sum(1 for f in findings if f.finding_type == "suspicious_env_key")

    if direct_leaks >= 3:
        return "critical"
    if direct_leaks >= 1:
        return "high"
    if env_refs >= 5:
        return "medium"
    if env_refs >= 1:
        return "low"
    return "clean"


def severity_rank(level: str) -> int:
    ranks = {"clean": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return ranks[level]


def remediation_for(finding_type: str) -> dict[str, str]:
    default = {
        "provider": "Credential",
        "action": "Rotate the exposed credential and replace it using a secret manager.",
        "url": "",
    }
    return REMEDIATION_GUIDE.get(finding_type, default)


def unique_playbook(findings: list[Finding]) -> list[dict[str, str]]:
    seen: set[str] = set()
    actions: list[dict[str, str]] = []
    for finding in findings:
        if finding.finding_type in seen:
            continue
        seen.add(finding.finding_type)
        guide = remediation_for(finding.finding_type)
        actions.append(
            {
                "type": finding.finding_type,
                "provider": guide["provider"],
                "action": guide["action"],
                "url": guide["url"],
            }
        )
    return actions


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan a repo for likely API key leaks.")
    parser.add_argument("target", nargs="?", default=".", help="Directory to scan")
    parser.add_argument(
        "--json", action="store_true", help="Emit machine-readable JSON output"
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Additional folder name to exclude (repeatable)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["clean", "low", "medium", "high", "critical"],
        help=(
            "Exit with code 1 when detected severity is this level or higher. "
            "Useful for pre-commit/CI."
        ),
    )
    args = parser.parse_args()

    root = Path(args.target).resolve()
    if not root.exists() or not root.is_dir():
        raise SystemExit(f"Target is not a directory: {root}")

    excludes = set(DEFAULT_EXCLUDES)
    excludes.update(args.exclude)

    all_findings: list[Finding] = []
    for file_path in iter_files(root, excludes):
        all_findings.extend(scan_file(file_path))

    result = {
        "target": str(root),
        "severity": score(all_findings),
        "total_findings": len(all_findings),
        "findings": [
            {
                "file": f.file_path,
                "line": f.line_no,
                "type": f.finding_type,
                "preview": f.preview,
                "remediation": remediation_for(f.finding_type),
            }
            for f in all_findings
        ],
        "playbook": unique_playbook(all_findings),
    }

    if args.json:
        print(json.dumps(result, indent=2))
        if args.fail_on and severity_rank(result["severity"]) >= severity_rank(args.fail_on):
            return 1
        return 0

    print(f"Target: {result['target']}")
    print(f"Severity: {result['severity']}")
    print(f"Findings: {result['total_findings']}")
    if not all_findings:
        print("No likely leaks found.")
        return 0

    print("\nTop findings:")
    for finding in all_findings[:25]:
        print(
            f"- {finding.finding_type}: {finding.file_path}:{finding.line_no} | "
            f"{finding.preview}"
        )
    if len(all_findings) > 25:
        print(f"... {len(all_findings) - 25} more")
    if result["playbook"]:
        print("\nRecommended actions:")
        for item in result["playbook"]:
            suffix = f" ({item['url']})" if item["url"] else ""
            print(f"- [{item['provider']}] {item['action']}{suffix}")
    if args.fail_on and severity_rank(result["severity"]) >= severity_rank(args.fail_on):
        print(f"\nFailing due to --fail-on={args.fail_on}.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
