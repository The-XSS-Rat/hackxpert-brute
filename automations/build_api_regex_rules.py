"""Utility for generating bulk API regex scanning templates."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_PATH = REPO_ROOT / "automations" / "templates.json"


BASE_SEVERITY = {
    "critical": ["critical", "high", "high", "medium"],
    "high": ["high", "high", "medium", "medium"],
    "medium": ["medium", "medium", "low", "medium"],
}

CATEGORIES = [
    "access-management",
    "accounting",
    "analytics",
    "audit",
    "billing",
    "business-intelligence",
    "cloud-ops",
    "collaboration",
    "commerce",
    "compliance",
    "customer-success",
    "devops",
    "finance",
    "governance",
    "identity",
    "infrastructure",
    "logistics",
    "marketing",
    "operations",
    "product",
]

EXPOSURES = [
    {
        "slug": "token-cache",
        "title": "Token Cache Dump",
        "path_template": "/api/{category_slug}/token-cache-{index_padded}.json",
        "description": "Detects exposed {category_title} token cache exports leaking bearer secrets.",
        "severity": "high",
        "regex_terms": ["token", "secret", "bearer"],
        "tags": ["api", "credentials", "{category_slug}"],
    },
    {
        "slug": "session-ledger",
        "title": "Session Ledger Leak",
        "path_template": "/api/{category_slug}/sessions-ledger-{index_padded}.log",
        "description": "Catches leaked {category_title} session ledgers disclosing JWTs and expirations.",
        "severity": "high",
        "regex_terms": ["session", "jwt", "exp"],
        "tags": ["api", "sessions", "{category_slug}"],
    },
    {
        "slug": "config-export",
        "title": "Config Export Exposure",
        "path_template": "/api/{category_slug}/config-export-{index_padded}.yaml",
        "description": "Finds world-readable {category_title} configuration exports exposing environment secrets.",
        "severity": "high",
        "regex_terms": ["config", "environment", "secret"],
        "tags": ["api", "config", "{category_slug}"],
    },
    {
        "slug": "user-dump",
        "title": "User Dump Exposure",
        "path_template": "/api/{category_slug}/user-dump-{index_padded}.csv",
        "description": "Detects exposed {category_title} user exports leaking directory records.",
        "severity": "medium",
        "regex_terms": ["email", "user", "id"],
        "tags": ["api", "intel", "{category_slug}"],
    },
    {
        "slug": "billing-export",
        "title": "Billing Export Exposure",
        "path_template": "/api/{category_slug}/billing-export-{index_padded}.csv",
        "description": "Identifies {category_title} billing exports containing transaction data.",
        "severity": "medium",
        "regex_terms": ["invoice", "amount", "currency"],
        "tags": ["api", "billing", "{category_slug}"],
    },
    {
        "slug": "webhook-registry",
        "title": "Webhook Registry Leak",
        "path_template": "/api/{category_slug}/webhooks-registry-{index_padded}.json",
        "description": "Detects leaked {category_title} webhook registries exposing callback secrets.",
        "severity": "high",
        "regex_terms": ["webhook", "callback", "signature"],
        "tags": ["api", "integrations", "{category_slug}"],
    },
    {
        "slug": "telemetry-snapshot",
        "title": "Telemetry Snapshot Exposure",
        "path_template": "/api/{category_slug}/telemetry-snapshot-{index_padded}.json",
        "description": "Surfaces exposed {category_title} telemetry snapshots leaking internal metrics.",
        "severity": "medium",
        "regex_terms": ["telemetry", "metric", "timestamp"],
        "tags": ["api", "telemetry", "{category_slug}"],
    },
    {
        "slug": "debug-trace",
        "title": "Debug Trace Log Leak",
        "path_template": "/api/{category_slug}/debug-trace-{index_padded}.log",
        "description": "Detects leaked {category_title} debug traces revealing stack data.",
        "severity": "medium",
        "regex_terms": ["trace", "exception", "stack"],
        "tags": ["api", "debug", "{category_slug}"],
    },
    {
        "slug": "database-backup",
        "title": "Database Backup Exposure",
        "path_template": "/api/{category_slug}/db-backup-{index_padded}.sql",
        "description": "Finds exposed {category_title} database backups with raw records.",
        "severity": "high",
        "regex_terms": ["insert", "password", "api_key"],
        "tags": ["api", "database", "{category_slug}"],
    },
    {
        "slug": "compliance-report",
        "title": "Compliance Report Leak",
        "path_template": "/api/{category_slug}/compliance-report-{index_padded}.pdf",
        "description": "Detects leaked {category_title} compliance reports disclosing control evidence.",
        "severity": "medium",
        "regex_terms": ["compliance", "control", "finding"],
        "tags": ["api", "compliance", "{category_slug}"],
    },
]


def slugify(value: str) -> str:
    """Return a filesystem and URL friendly slug."""
    cleaned = "".join(ch if ch.isalnum() else "-" for ch in value.lower())
    cleaned = "-".join(filter(None, cleaned.split("-")))
    return cleaned or "category"


def build_templates(existing_ids: Iterable[str]) -> list[dict[str, object]]:
    templates: list[dict[str, object]] = []
    for category in CATEGORIES:
        category_slug = slugify(category)
        category_title = category.replace("-", " ").title()
        for exposure in EXPOSURES:
            severity_cycle = BASE_SEVERITY[exposure["severity"]]
            for index in range(1, 6):
                severity = severity_cycle[(index - 1) % len(severity_cycle)]
                context = {
                    "category": category,
                    "category_slug": category_slug,
                    "category_title": category_title,
                    "index": index,
                    "index_padded": f"{index:02d}",
                }
                template_id = f"api-regex-{exposure['slug']}-{category_slug}-{index:02d}"
                if template_id in existing_ids:
                    continue
                template = {
                    "id": template_id,
                    "name": f"{category_title} {exposure['title']} #{index}",
                    "description": exposure["description"].format(**context),
                    "severity": severity,
                    "method": "GET",
                    "path": exposure["path_template"].format(**context),
                    "matchers": {
                        "status": [200],
                        "regex": [f"(?i){term}" for term in exposure["regex_terms"]],
                    },
                    "tags": [tag.format(**context) for tag in exposure["tags"]],
                }
                templates.append(template)
    return templates


def main() -> None:
    payload = json.loads(TEMPLATE_PATH.read_text())
    existing_ids = {entry.get("id") for entry in payload if isinstance(entry, dict)}
    additions = build_templates(existing_ids)
    payload.extend(additions)
    TEMPLATE_PATH.write_text(json.dumps(payload, indent=2))
    print(f"Added {len(additions)} templates. Total now {len(payload)}")


if __name__ == "__main__":
    main()
