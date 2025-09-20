import argparse
import json
import os
import queue
import random
import re
import socket
import ssl
import threading
import time
import urllib.parse
import webbrowser
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

import requests
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText
from PIL import Image, ImageTk

REPO_ROOT = Path(__file__).resolve().parent


def _read_wordlist_lines(path: Path) -> list[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return [line.strip() for line in fh if line.strip() and not line.strip().startswith("#")]
    except FileNotFoundError:
        return []
    except Exception:
        return []


DEFAULT_CUSTOM_ENDPOINT_WORDS = [
    "admin",
    "admin/dashboard",
    "admin/login",
    "api",
    "api/internal",
    "api/v1",
    "api/v2",
    "auth",
    "config",
    "config/feature-flags",
    "debug",
    "_docs",
    "docs",
    "feature-flags",
    "health",
    "internal",
    "internal/tools",
    "login",
    "logout",
    "manage",
    "metrics",
    "monitoring",
    "openapi",
    "reports",
    "reports/export",
    "reports/import",
    "reset-password",
    "services",
    "status",
    "status/health",
    "tasks",
    "users",
    "users/export",
    "users/import",
]

DEFAULT_CUSTOM_PARAMETER_WORDS = [
    "access_token",
    "admin",
    "apikey",
    "as",
    "beta",
    "callback",
    "config",
    "debug",
    "detail",
    "disabled",
    "email",
    "env",
    "feature",
    "filter",
    "flag",
    "id",
    "impersonate",
    "include",
    "lang",
    "limit",
    "locale",
    "mode",
    "offset",
    "order",
    "page",
    "preview",
    "redirect",
    "reset",
    "role",
    "search",
    "secret",
    "session",
    "signature",
    "sort",
    "source",
    "stage",
    "state",
    "token",
    "toggle",
    "user",
]

CUSTOM_ENDPOINT_WORDLIST = REPO_ROOT / "wordlists" / "hackxpert_endpoints.txt"
CUSTOM_PARAMETER_WORDLIST = REPO_ROOT / "wordlists" / "hackxpert_parameters.txt"

CUSTOM_ENDPOINT_WORDS = _read_wordlist_lines(CUSTOM_ENDPOINT_WORDLIST) or DEFAULT_CUSTOM_ENDPOINT_WORDS
CUSTOM_PARAMETER_WORDS = _read_wordlist_lines(CUSTOM_PARAMETER_WORDLIST) or DEFAULT_CUSTOM_PARAMETER_WORDS

WORDLIST_CATALOG = {
    "HackXpert Essentials (custom)": {
        "kind": "builtin",
        "path": CUSTOM_ENDPOINT_WORDLIST,
        "words": CUSTOM_ENDPOINT_WORDS,
    },
    "API Recon - Mega": {
        "kind": "remote",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt",
    },
    "API Recon - Minimal": {
        "kind": "remote",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/objects.txt",
    },
    "Web Content - Common": {
        "kind": "remote",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
    },
    "Fuzz - Directory quickhit": {
        "kind": "remote",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/quickhits.txt",
    },
    "WordPress API": {
        "kind": "remote",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt",
    },
}

PARAMETER_WORDLISTS = {
    "HackXpert Essentials (custom)": CUSTOM_PARAMETER_WORDS,
    "Authentication": [
        "access_token",
        "auth",
        "auth_token",
        "authorization",
        "jwt",
        "key",
        "refresh_token",
        "secret",
        "session",
        "token",
        "user",
    ],
    "Filtering & Sorting": [
        "active",
        "direction",
        "filter",
        "include",
        "limit",
        "offset",
        "order",
        "page",
        "q",
        "search",
        "sort",
    ],
    "Injection Primitives": [
        "callback",
        "command",
        "file",
        "id",
        "path",
        "query",
        "redirect",
        "target",
        "template",
        "url",
    ],
}

AUTOMATIONS_DIR = REPO_ROOT / "automations"
AUTOMATION_TEMPLATE_FILE = AUTOMATIONS_DIR / "templates.json"
AUTOMATION_LIBRARY_STORE = Path.home() / ".hackxpert_automations.json"

DEFAULT_AUTOMATION_TEMPLATES = [
    {
        "id": "git-config-exposure",
        "name": "Git Config Exposure",
        "description": "Checks if the /.git/config file is publicly accessible.",
        "severity": "high",
        "method": "GET",
        "path": "/.git/config",
        "matchers": {"status": [200], "regex": ["(?im)^\\[core\\]"]},
        "tags": ["git", "source"],
    },
    {
        "id": "dotenv-exposure",
        "name": "Environment File Exposure",
        "description": "Detects leaked Laravel/Node style .env configuration files.",
        "severity": "high",
        "method": "GET",
        "path": "/.env",
        "matchers": {"status": [200], "regex": ["(?i)(APP_KEY|DB_PASSWORD|MAIL_HOST)="]},
        "tags": ["config", "secrets"],
    },
    {
        "id": "swagger-ui",
        "name": "Swagger UI Exposure",
        "description": "Finds public Swagger UI consoles that may reveal API schemas.",
        "severity": "medium",
        "method": "GET",
        "path": "/swagger-ui.html",
        "matchers": {"status": [200, 401], "regex": ["(?i)swagger\\s*ui"]},
        "tags": ["documentation", "intel"],
    },
    {
        "id": "graphql-introspection",
        "name": "GraphQL Introspection Enabled",
        "description": "Uses an introspection query to detect unrestricted GraphQL schemas.",
        "severity": "medium",
        "method": "POST",
        "path": "/graphql",
        "headers": {"Content-Type": "application/json"},
        "body": (
            "{\n"
            "  \"query\": \"query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { name kind } } }\"\n"
            "}"
        ),
        "matchers": {"status": [200], "regex": ["__schema"]},
        "tags": ["graphql", "intel"],
    },
    {
        "id": "spring-actuator-env",
        "name": "Spring Boot Actuator Env Exposure",
        "description": "Detects open Spring Boot actuator /env endpoints leaking sensitive data.",
        "severity": "high",
        "method": "GET",
        "path": "/actuator/env",
        "matchers": {"status": [200], "regex": ["(?i)propertysources"]},
        "tags": ["spring", "config"],
    },
    {
        "id": "config-json",
        "name": "Config JSON Exposure",
        "description": "Looks for config.json files leaking API keys or secrets.",
        "severity": "medium",
        "method": "GET",
        "path": "/config.json",
        "matchers": {"status": [200], "regex": ["(?i)(api_key|authToken|clientSecret)"]},
        "tags": ["config", "secrets"],
    },
]


BULK_TEMPLATE_BLUEPRINTS = [
    {
        "id_prefix": "framework-config-leak",
        "name_template": "{variant_title} Framework Config Exposure #{index}",
        "description_template": "Detects leaked {variant_title} framework configuration files that may expose secrets.",
        "severity_cycle": ["high", "medium"],
        "method": "GET",
        "path_template": "/{variant_slug}/config/app-settings-{index_padded}.yaml",
        "matchers": {"status": [200], "regex": ["(?i)(password|secret|token)"]},
        "tags": ["config", "intel", "{variant_slug}"],
        "variants": [
            "laravel",
            "django",
            "rails",
            "express",
            "symfony",
            "spring",
            "angular",
            "react",
            "nextjs",
            "nuxt",
            "fastapi",
            "flask",
        ],
        "count": 8,
    },
    {
        "id_prefix": "environment-snapshot-leak",
        "name_template": "{variant_title} Environment Snapshot #{index}",
        "description_template": "Detects leaked {variant} environment snapshot exports that may reveal credentials and secrets.",
        "severity_cycle": ["high", "medium", "medium", "low"],
        "method": "GET",
        "path_template": "/snapshots/{variant_slug}-env-{index_padded}.json",
        "matchers": {"status": [200], "regex": ["(?i)(environment|secret|key|database)"]},
        "tags": ["environment", "intel", "{variant_slug}"],
        "variants": [
            "production",
            "staging",
            "qa",
            "dev",
            "sandbox",
            "training",
            "demo",
            "integration",
        ],
        "count": 12,
    },
    {
        "id_prefix": "pipeline-log-exposure",
        "name_template": "{variant_title} Pipeline Log Archive #{index}",
        "description_template": "Scans for {variant} pipeline logs that often contain leaked tokens and build metadata.",
        "severity_cycle": ["medium", "high"],
        "method": "GET",
        "path_template": "/.ci/{variant_slug}/logs-{index_padded}.txt",
        "matchers": {"status": [200], "regex": ["(?i)(pipeline|job|token|secret)"]},
        "tags": ["ci", "logs", "{variant_slug}"],
        "variants": [
            "github-actions",
            "gitlab-ci",
            "bitbucket-pipelines",
            "azure-devops",
            "circleci",
            "jenkins",
            "travis-ci",
            "teamcity",
            "bamboo",
            "buddy",
        ],
        "count": 10,
    },
    {
        "id_prefix": "backup-archive-exposure",
        "name_template": "{variant_title} Backup Archive Exposure #{index}",
        "description_template": "Locates exposed {variant} backup archives that commonly contain raw database dumps.",
        "severity_cycle": ["high"],
        "method": "GET",
        "path_template": "/backups/{variant_slug}-backup-{index_padded}.zip",
        "matchers": {"status": [200], "regex": ["(?i)pk"]},
        "tags": ["backup", "database", "{variant_slug}"],
        "variants": [
            "mysql",
            "postgresql",
            "mongodb",
            "redis",
            "elasticsearch",
        ],
        "count": 20,
    },
    {
        "id_prefix": "credential-export-leak",
        "name_template": "{variant_title} Credential Export Exposure #{index}",
        "description_template": "Checks for exposed {variant} credential export files that may leak API keys or tokens.",
        "severity_cycle": ["high", "medium"],
        "method": "GET",
        "path_template": "/exports/{variant_slug}/credentials-{index_padded}.csv",
        "matchers": {"status": [200], "regex": ["(?i)(api_key|client_secret|token)"]},
        "tags": ["credentials", "intel", "{variant_slug}"],
        "variants": [
            "salesforce",
            "workday",
            "sap",
            "zendesk",
            "okta",
            "pagerduty",
            "slack",
            "atlassian",
            "servicenow",
            "office365",
        ],
        "count": 10,
    },
    {
        "id_prefix": "debug-portal-dump",
        "name_template": "{variant_title} Debug Portal Dump #{index}",
        "description_template": "Detects exposed debug dumps for the {variant} deployment branch that may leak stack traces.",
        "severity_cycle": ["medium", "low"],
        "method": "GET",
        "path_template": "/debug/{variant_slug}/dump-{index_padded}.log",
        "matchers": {"status": [200], "regex": ["(?i)(stacktrace|debug|exception)"]},
        "tags": ["debug", "logs", "{variant_slug}"],
        "variants": [
            "beta",
            "gamma",
            "delta",
            "epsilon",
            "theta",
            "lambda",
            "omega",
            "sigma",
        ],
        "count": 12,
    },
    {
        "id_prefix": "feature-flag-export",
        "name_template": "{variant_title} Feature Flag Export #{index}",
        "description_template": "Looks for exposed {variant} feature flag exports disclosing rollout status and kill-switches.",
        "severity_cycle": ["medium", "low"],
        "method": "GET",
        "path_template": "/feature-flags/{variant_slug}/flags-{index_padded}.json",
        "matchers": {"status": [200], "regex": ["(?i)(flag|enabled|toggle)"]},
        "tags": ["feature-flags", "intel", "{variant_slug}"],
        "variants": [
            "mobile-app",
            "web-app",
            "admin-portal",
            "internal-tools",
            "edge-services",
            "platform",
        ],
        "count": 15,
    },
    {
        "id_prefix": "dataset-export-leak",
        "name_template": "{variant_title} Dataset Export Exposure #{index}",
        "description_template": "Detects world-readable {variant} dataset exports that may disclose sensitive records.",
        "severity_cycle": ["medium", "high", "medium"],
        "method": "GET",
        "path_template": "/datasets/{variant_slug}/export-{index_padded}.csv",
        "matchers": {"status": [200], "regex": ["(?i)(id,|email|user|amount)"]},
        "tags": ["datasets", "intel", "{variant_slug}"],
        "variants": [
            "customers",
            "transactions",
            "analytics",
            "telemetry",
            "inventory",
            "audit",
            "compliance",
            "operations",
            "marketing",
            "support",
        ],
        "count": 12,
    },
    {
        "id_prefix": "admin-report-exposure",
        "name_template": "{variant_title} Admin Report Exposure #{index}",
        "description_template": "Checks for exposed administrative {variant} reports that may leak strategic insights.",
        "severity_cycle": ["medium"],
        "method": "GET",
        "path_template": "/admin/reports/{variant_slug}-{index_padded}.pdf",
        "matchers": {"status": [200], "regex": ["%PDF"]},
        "tags": ["reports", "intel", "{variant_slug}"],
        "variants": [
            "usage",
            "security",
            "billing",
            "onboarding",
            "growth",
            "accounts",
            "quality",
            "risk",
            "latency",
            "availability",
            "product",
            "feedback",
        ],
        "count": 8,
    },
    {
        "id_prefix": "integration-token-leak",
        "name_template": "{variant_title} Integration Token Cache #{index}",
        "description_template": "Detects exposed {variant} integration token caches leaking credentials.",
        "severity_cycle": ["high", "medium"],
        "method": "GET",
        "path_template": "/integrations/{variant_slug}/tokens-{index_padded}.json",
        "matchers": {"status": [200], "regex": ["(?i)(token|secret|client_id)"]},
        "tags": ["integrations", "credentials", "{variant_slug}"],
        "variants": [
            "github",
            "gitlab",
            "bitbucket",
            "slack",
            "teams",
            "zoom",
            "zendesk",
            "pagerduty",
            "jira",
        ],
        "count": 12,
    },
    {
        "id_prefix": "diagnostic-dump-leak",
        "name_template": "{variant_title} Diagnostic Dump Exposure #{index}",
        "description_template": "Detects exposed {variant} diagnostic dumps that may leak infrastructure details.",
        "severity_cycle": ["medium", "high", "medium", "low"],
        "method": "GET",
        "path_template": "/diagnostics/{variant_slug}/diag-{index_padded}.log",
        "matchers": {"status": [200], "regex": ["(?i)(error|warning|stack|trace)"]},
        "tags": ["diagnostics", "logs", "{variant_slug}"],
        "variants": [
            "kernel",
            "database",
            "cache",
            "queue",
            "search",
            "proxy",
            "api",
        ],
        "count": 14,
    },
    {
        "id_prefix": "compliance-report-leak",
        "name_template": "{variant_upper} Compliance Report Exposure #{index}",
        "description_template": "Looks for exposed {variant_upper} compliance audit reports that may disclose regulatory findings.",
        "severity_cycle": ["medium", "high"],
        "method": "GET",
        "path_template": "/compliance/{variant_slug}/report-{index_padded}.xlsx",
        "matchers": {"status": [200], "regex": ["(?i)pk"]},
        "tags": ["compliance", "reports", "{variant_slug}"],
        "variants": ["gdpr", "hipaa", "pci", "sox", "iso27001"],
        "count": 14,
    },
]


def _normalize_matchers(matchers: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(matchers, dict):
        return {}
    normalized = deepcopy(matchers)
    contains_rules = normalized.pop("contains", None)
    regex_rules = [pattern for pattern in normalized.get("regex", []) if isinstance(pattern, str)]
    if contains_rules:
        for needle in contains_rules:
            if not isinstance(needle, str):
                continue
            regex_rules.append(f"(?i){re.escape(needle)}")
    if regex_rules:
        normalized["regex"] = regex_rules
    else:
        normalized.pop("regex", None)
    return normalized


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "variant"


def _generate_bulk_automation_templates(target: int = 1000) -> list[dict[str, Any]]:
    templates: list[dict[str, Any]] = []
    for blueprint in BULK_TEMPLATE_BLUEPRINTS:
        severity_cycle = blueprint.get("severity_cycle") or [blueprint.get("severity", "medium")]
        for variant_index, variant in enumerate(blueprint["variants"]):
            variant_slug = _slugify(variant)
            format_base = {
                "variant": variant,
                "variant_lower": variant.lower(),
                "variant_slug": variant_slug,
                "variant_title": variant.replace("-", " ").title(),
                "variant_upper": variant.upper(),
            }
            for index in range(1, blueprint["count"] + 1):
                if len(templates) >= target:
                    return templates
                cycle_index = (variant_index * blueprint["count"] + (index - 1)) % len(severity_cycle)
                severity = severity_cycle[cycle_index]
                format_values = {
                    **format_base,
                    "index": index,
                    "index_padded": f"{index:02d}",
                }
                template: dict[str, Any] = {
                    "id": f"{blueprint['id_prefix']}-{variant_slug}-{index:02d}",
                    "name": blueprint["name_template"].format(**format_values),
                    "description": blueprint["description_template"].format(**format_values),
                    "severity": severity,
                    "method": blueprint["method"],
                    "path": blueprint["path_template"].format(**format_values),
                    "matchers": _normalize_matchers(blueprint.get("matchers")),
                    "tags": [tag.format(**format_values) for tag in blueprint["tags"]],
                }
                if "headers" in blueprint:
                    template["headers"] = {
                        key: value.format(**format_values)
                        for key, value in blueprint["headers"].items()
                    }
                if "body_template" in blueprint:
                    template["body"] = blueprint["body_template"].format(**format_values)
                templates.append(template)
    return templates


DEFAULT_AUTOMATION_TEMPLATES.extend(_generate_bulk_automation_templates(1000))


def _load_automation_templates_from_disk(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
    except Exception:
        return []
    return []


def _load_automation_library() -> dict[str, Any]:
    if not AUTOMATION_LIBRARY_STORE.exists():
        return {"custom_templates": [], "rulesets": {}}
    try:
        with open(AUTOMATION_LIBRARY_STORE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            data.setdefault("custom_templates", [])
            data.setdefault("rulesets", {})
            return data
    except Exception:
        pass
    return {"custom_templates": [], "rulesets": {}}


def _save_automation_library(payload: dict[str, Any]) -> None:
    try:
        with open(AUTOMATION_LIBRARY_STORE, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
    except Exception:
        pass

CONFIG_PATH = Path.home() / ".dir_bruteforce_config.json"
BASELINE_PATH = Path.home() / ".hackxpert_surface_baselines.json"


class Settings:
    DEFAULTS = {
        "threads": 10,
        "timeout": 5,
        "user_agent": "DirBruteForcer/1.0",
        "recursion_depth": 5,
        "include_status_codes": "<400",
        "file_extensions": "",
        "follow_redirects": True,
        "http_methods": "GET",
        "extra_headers": "",
        "delay_jitter": 0.0,
        "intel_paths": "/robots.txt,/.well-known/security.txt,/openapi.json,/swagger.json,/graphql",
        "enable_preflight": True,
        "probe_cors": True,
        "burp_proxy_enabled": False,
        "burp_proxy_host": "127.0.0.1",
        "burp_proxy_port": 8080,
    }

    def __init__(self, path: Path = CONFIG_PATH):
        self.path = path
        self.data: dict = {}
        self.load()

    def load(self) -> None:
        if self.path.exists():
            try:
                with open(self.path, "r", encoding="utf-8") as fh:
                    stored = json.load(fh)
            except Exception:
                stored = {}
        else:
            stored = {}
        self.data = {**Settings.DEFAULTS, **stored}

    def save(self) -> None:
        try:
            with open(self.path, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, indent=2)
        except Exception as exc:
            messagebox.showerror("Save Error", f"Failed to save settings: {exc}")


class APISurfaceReport:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.lock = threading.Lock()
        self.endpoints: dict[str, dict[str, dict[str, Any]]] = {}
        self.technologies: set[str] = set()
        self.auth_schemes: set[str] = set()
        self.graphql_operations: set[str] = set()
        self.spec_documents: set[str] = set()
        self.asset_links: set[str] = set()
        self.form_targets: set[str] = set()
        self.json_links: set[str] = set()
        self.passive_hosts: set[str] = set()
        self.robots_paths: set[str] = set()
        self.sitemap_urls: set[str] = set()
        self.websocket_links: set[str] = set()
        self.link_relations: set[str] = set()
        self.csp_report_uris: set[str] = set()
        self.well_known_links: set[str] = set()
        self.config_endpoints: set[str] = set()
        self.certificate: Optional[dict[str, Any]] = None

    def _safe_json(self, response) -> Any:
        try:
            return response.json()
        except Exception:
            return None

    def attach_certificate(self, data: dict[str, Any]) -> None:
        if not data:
            return
        with self.lock:
            self.certificate = data
            alt_names = data.get("alt_names")
            if isinstance(alt_names, (list, tuple, set)):
                self.passive_hosts.update(str(name) for name in alt_names if name)

    def _walk_json_fields(self, data: Any) -> set[str]:
        fields: set[str] = set()
        if isinstance(data, dict):
            for key, value in data.items():
                try:
                    fields.add(str(key))
                except Exception:
                    continue
                fields.update(self._walk_json_fields(value))
        elif isinstance(data, list):
            for item in data:
                fields.update(self._walk_json_fields(item))
        return fields

    def _extract_parameters(self, url: str) -> set[str]:
        params = set()
        parsed = urllib.parse.urlsplit(url)
        for key, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
            params.add(key)
        return params

    def _extract_request_body_parameters(self, response) -> set[str]:
        req = getattr(response, "request", None)
        if not req:
            return set()
        params: set[str] = set()
        body = getattr(req, "body", None)
        if not body:
            return params
        if isinstance(body, bytes):
            try:
                body_text = body.decode("utf-8", "ignore")
            except Exception:
                body_text = ""
        else:
            body_text = str(body)
        text = body_text.strip()
        if not text:
            return params
        if text.startswith("{") or text.startswith("["):
            try:
                payload = json.loads(text)
            except Exception:
                payload = None
            if payload is not None:
                params.update(self._walk_json_fields(payload))
                return params
        for piece in text.split("&"):
            if "=" in piece:
                key = piece.split("=", 1)[0]
                if key:
                    params.add(key)
        return params

    def _infer_technologies(self, headers: dict[str, str], body_text: str) -> set[str]:
        hints: set[str] = set()
        server = headers.get("Server")
        powered = headers.get("X-Powered-By")
        if server:
            hints.add(server.split(" ")[0])
        if powered:
            hints.add(powered.split(" ")[0])
        if headers.get("X-AspNet-Version"):
            hints.add("ASP.NET")
        if headers.get("CF-Ray") or headers.get("CF-Cache-Status"):
            hints.add("Cloudflare")
        if headers.get("X-Served-By") and "varnish" in headers.get("X-Served-By", "").lower():
            hints.add("Varnish")
        if headers.get("Via"):
            hints.add("Via Proxy")
        sample = (body_text or "").lower()
        if "wordpress" in sample:
            hints.add("WordPress")
        if "drupal" in sample:
            hints.add("Drupal")
        return hints

    def _parse_auth_schemes(self, headers: dict[str, str]) -> set[str]:
        value = headers.get("WWW-Authenticate")
        if not value:
            return set()
        schemes = set()
        for part in value.split(","):
            scheme = part.strip().split(" ", 1)[0]
            if scheme:
                schemes.add(scheme)
        return schemes

    def _extract_rate_limits(self, headers: dict[str, str]) -> list[str]:
        hits = []
        for key in [
            "RateLimit-Limit",
            "RateLimit-Remaining",
            "RateLimit-Reset",
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
        ]:
            if headers.get(key):
                hits.append(f"{key}={headers[key]}")
        return hits

    def _spec_hints(self, content_type: str, json_payload: Any, body_text: str) -> set[str]:
        hints: set[str] = set()
        lowered_type = (content_type or "").lower()
        lowered_body = (body_text or "").lower()
        if "openapi" in lowered_type or "application/vnd.oai.openapi" in lowered_type:
            hints.add("OpenAPI specification")
        if "swagger" in lowered_body and "paths" in lowered_body:
            hints.add("Swagger definition")
        if "openapi" in lowered_body and "info" in lowered_body and "paths" in lowered_body:
            hints.add("OpenAPI-like document")
        if json_payload and isinstance(json_payload, dict):
            if "openapi" in json_payload:
                hints.add(f"OpenAPI {json_payload.get('openapi')}")
            if "swagger" in json_payload:
                hints.add(f"Swagger {json_payload.get('swagger')}")
            data_block = json_payload.get("data")
            if isinstance(data_block, dict) and "__schema" in data_block:
                hints.add("GraphQL introspection data")
        if "graphql" in lowered_type or "graphql" in lowered_body:
            hints.add("GraphQL endpoint")
        return hints

    def _normalize_discoveries(self, origin: str, discoveries: set[str]) -> set[str]:
        normalized: set[str] = set()
        if not discoveries:
            return normalized
        base = origin or self.base_url
        if base:
            base = base.rstrip("/") + "/"
        for item in discoveries:
            if not item:
                continue
            if item.startswith("http://") or item.startswith("https://"):
                normalized.add(item)
            else:
                normalized.add(urllib.parse.urljoin(base, item.lstrip("/")))
        return normalized

    def ingest(
        self,
        url: str,
        method: str,
        response,
        body_text: str,
        intel_notes: list[str],
        secret_hits: list[str],
        discovered_paths: set[str],
        asset_links: Optional[set[str]] = None,
        form_targets: Optional[set[str]] = None,
        json_links: Optional[set[str]] = None,
        host_hints: Optional[set[str]] = None,
        robots_paths: Optional[set[str]] = None,
        sitemap_urls: Optional[set[str]] = None,
        websocket_links: Optional[set[str]] = None,
        link_relations: Optional[set[str]] = None,
        csp_reports: Optional[set[str]] = None,
        well_known_links: Optional[set[str]] = None,
        config_endpoints: Optional[set[str]] = None,
        json_payload: Any = None,
    ) -> dict[str, Any]:
        if json_payload is None:
            json_payload = self._safe_json(response)
        json_fields = self._walk_json_fields(json_payload) if json_payload is not None else set()
        parameters = self._extract_parameters(url)
        parameters.update(self._extract_request_body_parameters(response))
        technologies = self._infer_technologies(response.headers, body_text)
        auth_schemes = self._parse_auth_schemes(response.headers)
        rate_limits = self._extract_rate_limits(response.headers)
        spec_hints = self._spec_hints(response.headers.get("Content-Type", ""), json_payload, body_text)
        discoveries = self._normalize_discoveries(url, discovered_paths)
        normalized_assets = self._normalize_discoveries(url, set(asset_links or set()))
        normalized_forms = self._normalize_discoveries(url, set(form_targets or set()))
        normalized_json = self._normalize_discoveries(url, set(json_links or set()))
        normalized_robots = self._normalize_discoveries(url, set(robots_paths or set()))
        normalized_sitemaps = self._normalize_discoveries(url, set(sitemap_urls or set()))
        normalized_websocket = self._normalize_discoveries(url, set(websocket_links or set()))
        normalized_link_relations = self._normalize_discoveries(url, set(link_relations or set()))
        normalized_csp_reports = self._normalize_discoveries(url, set(csp_reports or set()))
        normalized_well_known = self._normalize_discoveries(url, set(well_known_links or set()))
        normalized_config = self._normalize_discoveries(url, set(config_endpoints or set()))
        host_hints = set(host_hints or set())

        graphql_flag = False
        graphql_ops: set[str] = set()
        if isinstance(json_payload, dict):
            if {"data", "errors"}.issubset(json_payload.keys()):
                graphql_flag = True
            data_block = json_payload.get("data")
            if isinstance(data_block, dict):
                graphql_ops.update(str(key) for key in data_block.keys() if key)
                if "__schema" in data_block:
                    graphql_flag = True
            errors = json_payload.get("errors")
            if isinstance(errors, list) and errors:
                graphql_flag = True
        content_type = response.headers.get("Content-Type", "")
        if "graphql" in content_type.lower():
            graphql_flag = True
        if body_text and "graphql" in body_text.lower():
            graphql_flag = True
        if not graphql_flag:
            graphql_ops.clear()

        with self.lock:
            endpoint = self.endpoints.setdefault(url, {})
            record = endpoint.setdefault(
                method,
                {
                    "last_status": None,
                    "status_history": [],
                    "content_types": set(),
                    "parameters": set(),
                    "json_fields": set(),
                    "linked_paths": set(),
                    "asset_links": set(),
                    "form_targets": set(),
                    "json_links": set(),
                    "host_hints": set(),
                    "robots_paths": set(),
                    "sitemap_urls": set(),
                    "websocket_links": set(),
                    "link_relations": set(),
                    "csp_reports": set(),
                    "well_known_links": set(),
                    "config_endpoints": set(),
                    "intel": set(),
                    "secrets": set(),
                    "technologies": set(),
                    "auth_schemes": set(),
                    "graphql": False,
                    "graphql_operations": set(),
                    "spec_hints": set(),
                    "rate_limits": set(),
                },
            )
            record["last_status"] = response.status_code
            history = record["status_history"]
            history.append(response.status_code)
            if len(history) > 20:
                del history[:-20]
            if content_type:
                record["content_types"].add(content_type.split(";")[0])
            record["parameters"].update(parameters)
            record["json_fields"].update(json_fields)
            record["linked_paths"].update(discoveries)
            record["asset_links"].update(normalized_assets)
            record["form_targets"].update(normalized_forms)
            record["json_links"].update(normalized_json)
            record["host_hints"].update(host_hints)
            record["robots_paths"].update(normalized_robots)
            record["sitemap_urls"].update(normalized_sitemaps)
            record["websocket_links"].update(normalized_websocket)
            record["link_relations"].update(normalized_link_relations)
            record["csp_reports"].update(normalized_csp_reports)
            record["well_known_links"].update(normalized_well_known)
            record["config_endpoints"].update(normalized_config)
            record["intel"].update(intel_notes)
            record["secrets"].update(secret_hits)
            record["technologies"].update(technologies)
            record["auth_schemes"].update(auth_schemes)
            record["spec_hints"].update(spec_hints)
            if rate_limits:
                record["rate_limits"].update(rate_limits)
            if graphql_flag:
                record["graphql"] = True
                record["graphql_operations"].update(graphql_ops)
            self.technologies.update(technologies)
            self.auth_schemes.update(auth_schemes)
            self.graphql_operations.update(graphql_ops)
            self.spec_documents.update(spec_hints)
            self.asset_links.update(normalized_assets)
            self.form_targets.update(normalized_forms)
            self.json_links.update(normalized_json)
            self.passive_hosts.update(host_hints)
            self.robots_paths.update(normalized_robots)
            self.sitemap_urls.update(normalized_sitemaps)
            self.websocket_links.update(normalized_websocket)
            self.link_relations.update(normalized_link_relations)
            self.csp_report_uris.update(normalized_csp_reports)
            self.well_known_links.update(normalized_well_known)
            self.config_endpoints.update(normalized_config)

            snapshot = {
                "parameters": sorted(record["parameters"]),
                "json_fields": sorted(record["json_fields"])[:40],
                "linked_paths": sorted(record["linked_paths"])[:40],
                "asset_links": sorted(record["asset_links"])[:40],
                "form_targets": sorted(record["form_targets"])[:40],
                "json_links": sorted(record["json_links"])[:40],
                "host_hints": sorted(record["host_hints"])[:40],
                "robots_paths": sorted(record["robots_paths"])[:40],
                "sitemap_urls": sorted(record["sitemap_urls"])[:40],
                "websocket_links": sorted(record["websocket_links"])[:40],
                "link_relations": sorted(record["link_relations"])[:40],
                "csp_reports": sorted(record["csp_reports"])[:40],
                "well_known_links": sorted(record["well_known_links"])[:40],
                "config_endpoints": sorted(record["config_endpoints"])[:40],
                "technologies": sorted(record["technologies"]),
                "intel": sorted(record["intel"])[:20],
                "secrets": sorted(record["secrets"]),
                "auth_schemes": sorted(record["auth_schemes"]),
                "graphql": record["graphql"],
                "graphql_operations": sorted(record["graphql_operations"])[:20],
                "spec_hints": sorted(record["spec_hints"]),
                "rate_limits": sorted(record["rate_limits"]),
                "global_technologies": sorted(self.technologies),
                "global_auth_schemes": sorted(self.auth_schemes),
                "global_spec_documents": sorted(self.spec_documents),
                "global_asset_links": sorted(self.asset_links)[:60],
                "global_form_targets": sorted(self.form_targets)[:60],
                "global_json_links": sorted(self.json_links)[:60],
                "global_host_hints": sorted(self.passive_hosts)[:60],
                "global_robots_paths": sorted(self.robots_paths)[:60],
                "global_sitemap_urls": sorted(self.sitemap_urls)[:60],
                "global_websocket_links": sorted(self.websocket_links)[:60],
                "global_link_relations": sorted(self.link_relations)[:60],
                "global_csp_reports": sorted(self.csp_report_uris)[:60],
                "global_well_known_links": sorted(self.well_known_links)[:60],
                "global_config_endpoints": sorted(self.config_endpoints)[:60],
                "certificate": self.certificate,
            }

        return snapshot

    def to_dict(self) -> dict[str, Any]:
        with self.lock:
            endpoints: dict[str, dict[str, Any]] = {}
            for url, methods in self.endpoints.items():
                endpoint_entry: dict[str, Any] = {}
                for method, record in methods.items():
                    endpoint_entry[method] = {
                        "last_status": record["last_status"],
                        "status_history": list(record["status_history"]),
                        "content_types": sorted(record["content_types"]),
                        "parameters": sorted(record["parameters"]),
                        "json_fields": sorted(record["json_fields"]),
                        "linked_paths": sorted(record["linked_paths"]),
                        "asset_links": sorted(record["asset_links"]),
                        "form_targets": sorted(record["form_targets"]),
                        "json_links": sorted(record["json_links"]),
                        "host_hints": sorted(record["host_hints"]),
                        "robots_paths": sorted(record["robots_paths"]),
                        "sitemap_urls": sorted(record["sitemap_urls"]),
                        "websocket_links": sorted(record["websocket_links"]),
                        "link_relations": sorted(record["link_relations"]),
                        "csp_reports": sorted(record["csp_reports"]),
                        "well_known_links": sorted(record["well_known_links"]),
                        "config_endpoints": sorted(record["config_endpoints"]),
                        "intel": sorted(record["intel"]),
                        "secrets": sorted(record["secrets"]),
                        "technologies": sorted(record["technologies"]),
                        "auth_schemes": sorted(record["auth_schemes"]),
                        "graphql": record["graphql"],
                        "graphql_operations": sorted(record["graphql_operations"]),
                        "spec_hints": sorted(record["spec_hints"]),
                        "rate_limits": sorted(record["rate_limits"]),
                    }
                endpoints[url] = endpoint_entry
            return {
                "base_url": self.base_url,
                "generated_at": time.time(),
                "technologies": sorted(self.technologies),
                "auth_schemes": sorted(self.auth_schemes),
                "graphql_operations": sorted(self.graphql_operations),
                "spec_documents": sorted(self.spec_documents),
                "asset_links": sorted(self.asset_links),
                "form_targets": sorted(self.form_targets),
                "json_links": sorted(self.json_links),
                "host_hints": sorted(self.passive_hosts),
                "robots_paths": sorted(self.robots_paths),
                "sitemap_urls": sorted(self.sitemap_urls),
                "websocket_links": sorted(self.websocket_links),
                "link_relations": sorted(self.link_relations),
                "csp_reports": sorted(self.csp_report_uris),
                "well_known_links": sorted(self.well_known_links),
                "config_endpoints": sorted(self.config_endpoints),
                "certificate": self.certificate,
                "endpoints": endpoints,
            }

    def render_highlights(self) -> str:
        with self.lock:
            highlights = []
            if self.technologies:
                highlights.append(f"Technologies: {', '.join(sorted(self.technologies))}")
            if self.auth_schemes:
                highlights.append(f"Auth schemes: {', '.join(sorted(self.auth_schemes))}")
            if self.graphql_operations:
                highlights.append(
                    "GraphQL operations: " + ", ".join(sorted(list(self.graphql_operations))[:6])
                )
            if self.spec_documents:
                highlights.append(f"Spec clues: {', '.join(sorted(self.spec_documents))}")
            if self.websocket_links:
                highlights.append(f"WebSocket hints: {len(self.websocket_links)}")
            if self.link_relations:
                highlights.append(f"Link headers: {len(self.link_relations)} targets")
            if self.csp_report_uris:
                previews = ", ".join(sorted(list(self.csp_report_uris))[:3])
                highlights.append(f"CSP reporting: {previews}")
            if self.well_known_links:
                highlights.append(f"Well-known paths: {len(self.well_known_links)}")
            if self.config_endpoints:
                highlights.append(f"Config endpoints: {len(self.config_endpoints)}")
            if self.certificate:
                subject = self.certificate.get("subject") if isinstance(self.certificate, dict) else None
                if subject:
                    highlights.append(f"TLS subject: {subject}")
                expiry = self.certificate.get("expires") if isinstance(self.certificate, dict) else None
                if expiry:
                    highlights.append(f"TLS expires: {expiry}")
            if self.passive_hosts:
                highlights.append(
                    "Passive hosts: "
                    + ", ".join(sorted(list(self.passive_hosts))[:4])
                    + ("…" if len(self.passive_hosts) > 4 else "")
                )
            if self.robots_paths:
                highlights.append(
                    "Robots hints: "
                    + ", ".join(sorted(list(self.robots_paths))[:3])
                    + ("…" if len(self.robots_paths) > 3 else "")
                )
            if self.sitemap_urls:
                highlights.append(
                    "Sitemap URLs: "
                    + ", ".join(sorted(list(self.sitemap_urls))[:3])
                    + ("…" if len(self.sitemap_urls) > 3 else "")
                )
        if not highlights:
            return ""
        return "Forensics highlights:\n  • " + "\n  • ".join(highlights)


class DirBruteForcer:
    def __init__(
        self,
        base_url,
        wordlist_file,
        settings,
        on_found,
        on_finish,
        on_progress=None,
        on_certificate=None,
    ):
        self.base_url = base_url.rstrip("/")
        self.wordlist_file = wordlist_file
        self.settings = settings
        self.on_found = on_found
        self.on_finish = on_finish
        self.on_progress = on_progress or (lambda p: None)
        self.on_certificate = on_certificate
        self.to_scan: queue.Queue = queue.Queue()
        self.seen = set()
        self.path_seen = set()
        self.running = False
        self.total = 0
        self.processed = 0
        self.threads = []
        self.word_variants = []
        self.lock = threading.Lock()
        self.method_list = ["GET"]
        self.method_count = 1
        self.delay_jitter = 0.0
        self.base_headers: dict[str, str] = {}
        self.enable_preflight = True
        self.preflight_thread = None
        self.cors_origin = "https://offsec.hackxpert"
        self.preflight_targets = []
        self.intel_paths = []
        self.secret_patterns = [
            ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}")),
            ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
            ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,48}")),
            (
                "JWT",
                re.compile(r"eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}"),
            ),
        ]
        self.base_key = self._normalize(self.base_url)
        self.baseline_snapshot: dict[str, int] = {}
        self.current_snapshot: dict[str, int] = {}
        self.baseline_highlights = {"new": 0, "changed": 0, "retired": 0, "retired_items": []}
        self.forensics = APISurfaceReport(self.base_url)
        self.proxies: Optional[dict[str, str]] = None
        self.certificate_info: Optional[dict[str, Any]] = None
        base_reference = self.base_url if "://" in self.base_url else f"http://{self.base_url}"
        self.base_host = urllib.parse.urlsplit(base_reference).netloc

    def load_wordlist(self):
        with open(self.wordlist_file, "r", encoding="utf-8", errors="ignore") as fh:
            return [line.strip() for line in fh if line.strip()]

    def _expand_words(self, words):
        exts = [ext.strip().lstrip(".") for ext in str(self.settings.data.get("file_extensions", "")).split(",") if ext.strip()]
        if not exts:
            return words
        expanded = []
        for word in words:
            expanded.append(word)
            expanded.extend(f"{word}.{ext}" for ext in exts)
        return expanded

    def _parse_methods(self):
        raw = str(self.settings.data.get("http_methods", "GET"))
        methods = [part.strip().upper() for part in raw.split(",") if part.strip()]
        return methods or ["GET"]

    def _normalize(self, url):
        stripped = url.rstrip("/")
        return stripped or url

    def _build_headers(self, user_agent):
        headers = {}
        extra = str(self.settings.data.get("extra_headers", ""))
        for line in extra.splitlines():
            if not line.strip() or ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
        headers.setdefault("User-Agent", user_agent)
        if self.settings.data.get("probe_cors", True):
            headers.setdefault("Origin", self.cors_origin)
        return headers

    def _build_proxies(self) -> Optional[dict[str, str]]:
        enabled = self.settings.data.get("burp_proxy_enabled")
        if isinstance(enabled, str):
            enabled = enabled.lower() in {"1", "true", "yes", "on"}
        if not enabled:
            return None
        host = str(self.settings.data.get("burp_proxy_host", "")).strip()
        port_value = self.settings.data.get("burp_proxy_port", 0)
        try:
            port = int(port_value)
        except (TypeError, ValueError):
            return None
        if not host or port <= 0:
            return None
        address = f"http://{host}:{port}"
        return {"http": address, "https": address}

    def _fetch_certificate(self, target_url: str) -> Optional[dict[str, Any]]:
        try:
            parsed = urllib.parse.urlsplit(target_url)
        except Exception:
            return None
        if parsed.scheme.lower() != "https":
            return None
        host = parsed.hostname
        if not host:
            return None
        port = parsed.port or 443
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=min(10, self._get_timeout() + 5)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as wrapped:
                    cert = wrapped.getpeercert()
        except Exception:
            return None
        subject = dict(x[0] for x in cert.get("subject", [])).get("commonName")
        issuer = dict(x[0] for x in cert.get("issuer", [])).get("commonName")
        not_after = cert.get("notAfter")
        expires = None
        if not_after:
            try:
                expires_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                expires = expires_dt.isoformat()
            except Exception:
                expires = not_after
        alt_names = [
            entry[1]
            for entry in cert.get("subjectAltName", [])
            if isinstance(entry, tuple) and len(entry) == 2 and entry[0].lower() == "dns"
        ]
        return {
            "subject": subject or host,
            "issuer": issuer,
            "expires": expires,
            "alt_names": alt_names,
        }

    def _looks_like_url(self, value: str) -> bool:
        if not value or not isinstance(value, str):
            return False
        if value.startswith(("mailto:", "javascript:")):
            return False
        if value.startswith("//"):
            return True
        parsed = urllib.parse.urlparse(value)
        if parsed.scheme and parsed.netloc:
            return True
        if value.startswith("/"):
            return True
        return False

    def _extract_links_from_json(self, payload: Any) -> set[str]:
        hits: set[str] = set()
        if isinstance(payload, dict):
            for key, value in payload.items():
                if isinstance(value, str) and self._looks_like_url(value):
                    hits.add(value)
                elif isinstance(value, (dict, list)):
                    hits.update(self._extract_links_from_json(value))
        elif isinstance(payload, list):
            for item in payload:
                hits.update(self._extract_links_from_json(item))
        return hits

    def _passive_discovery(
        self,
        target: str,
        body_text: str,
        content_type: str,
        json_payload: Any,
    ) -> dict[str, set[str]]:
        findings: dict[str, set[str]] = {
            "paths": set(),
            "asset_links": set(),
            "form_targets": set(),
            "json_links": set(),
            "host_hints": set(),
            "robots_paths": set(),
            "sitemap_urls": set(),
            "websocket_links": set(),
            "config_endpoints": set(),
            "well_known_links": set(),
            "link_relations": set(),
            "csp_reports": set(),
        }
        if not body_text:
            return findings
        lowered = body_text.lower()
        lower_type = (content_type or "").lower()
        base_reference = self.base_url if "://" in self.base_url else f"http://{self.base_url}"
        base_host = urllib.parse.urlsplit(base_reference).netloc

        def register(value: str, bucket: str, allow_external: bool = False) -> None:
            if not value:
                return
            candidate = value.strip()
            if not candidate or candidate.startswith("#"):
                return
            if candidate.startswith("//"):
                candidate = f"https:{candidate}"
            if candidate.startswith(("mailto:", "javascript:")):
                return
            parsed = urllib.parse.urlparse(candidate)
            if parsed.scheme and parsed.netloc:
                host = parsed.netloc
                if host == base_host:
                    findings[bucket].add(candidate)
                elif allow_external:
                    findings[bucket].add(candidate)
                else:
                    findings["host_hints"].add(host)
            else:
                findings[bucket].add(candidate)

        if "html" in lower_type or "<html" in lowered:
            for href in re.findall(r'href=["\']([^"\']+)["\']', body_text, flags=re.IGNORECASE):
                register(href, "paths")
            for action in re.findall(r'action=["\']([^"\']+)["\']', body_text, flags=re.IGNORECASE):
                register(action, "form_targets")
            for script in re.findall(r'src=["\']([^"\']+\.js)["\']', body_text, flags=re.IGNORECASE):
                register(script, "asset_links")
            for fetch_call in re.findall(r'fetch\((?:"|\')([^"\']+)', body_text, flags=re.IGNORECASE):
                register(fetch_call, "json_links")
            for ajax_call in re.findall(r'axios\.[a-z]+\((?:"|\')([^"\']+)', body_text, flags=re.IGNORECASE):
                register(ajax_call, "json_links")

        if isinstance(json_payload, (dict, list)):
            extracted = self._extract_links_from_json(json_payload)
            for link in extracted:
                register(link, "json_links", allow_external=True)
                if ".well-known/" in link:
                    register(link, "well_known_links", allow_external=True)

        for quoted in re.findall(r'"(/[A-Za-z0-9_\-\./]{3,})"', body_text):
            if quoted.startswith("//"):
                continue
            register(quoted, "paths")

        for ws_link in re.findall(r'wss?://[^"\'\s<>]+', body_text, flags=re.IGNORECASE):
            register(ws_link, "websocket_links", allow_external=True)

        for config_hit in re.findall(
            r"(?i)(?:api|endpoint|base)[-_]?(?:url|uri)\s*(?:[:=]|=>)\s*[\"']([^\"']+)",
            body_text,
        ):
            register(config_hit, "config_endpoints", allow_external=True)

        for well_known in re.findall(r"[\"'](/\.well-known/[^\"'\s<>]+)", body_text):
            register(well_known, "well_known_links")

        if target.lower().endswith("robots.txt"):
            for line in body_text.splitlines():
                parts = line.split(":", 1)
                if len(parts) != 2:
                    continue
                directive, value = parts[0].strip().lower(), parts[1].strip()
                if directive in {"disallow", "allow"} and value:
                    register(value, "robots_paths")

        if "<urlset" in lowered or "<sitemapindex" in lowered:
            for match in re.findall(r"<loc>([^<]+)</loc>", body_text, flags=re.IGNORECASE):
                register(match.strip(), "sitemap_urls", allow_external=True)

        return findings

    def _parse_link_header(self, header: str) -> set[str]:
        if not header:
            return set()
        parts = re.split(r",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)", header)
        links: set[str] = set()
        for part in parts:
            fragment = part.strip()
            if not fragment or not fragment.startswith("<"):
                continue
            closing = fragment.find(">")
            if closing == -1:
                continue
            url = fragment[1:closing].strip()
            if url:
                links.add(url)
        return links

    def _extract_csp_reports(self, header: str) -> set[str]:
        reports: set[str] = set()
        if not header:
            return reports
        for directive in header.split(";"):
            cleaned = directive.strip()
            if not cleaned:
                continue
            lower = cleaned.lower()
            if lower.startswith("report-uri"):
                tokens = cleaned.split(None, 1)
                if len(tokens) == 2:
                    for candidate in tokens[1].split():
                        clean = candidate.strip()
                        if clean and (
                            clean.startswith("http://")
                            or clean.startswith("https://")
                            or clean.startswith("/")
                        ):
                            reports.add(clean)
        return reports

    def _extract_report_to_header(self, header: str) -> set[str]:
        endpoints: set[str] = set()
        if not header:
            return endpoints
        candidates = []
        try:
            parsed = json.loads(header)
            candidates = parsed if isinstance(parsed, list) else [parsed]
        except Exception:
            try:
                parsed = json.loads(f"[{header}]")
                candidates = parsed if isinstance(parsed, list) else []
            except Exception:
                return endpoints
        for item in candidates:
            if not isinstance(item, dict):
                continue
            reports = item.get("endpoints")
            if not isinstance(reports, list):
                continue
            for entry in reports:
                if isinstance(entry, dict):
                    url = entry.get("url")
                    if url:
                        endpoints.add(str(url))
        return endpoints

    def _get_delay_jitter(self):
        try:
            return max(0.0, float(self.settings.data.get("delay_jitter", 0.0)))
        except (TypeError, ValueError):
            return 0.0

    def _parse_intel_paths(self):
        raw = str(self.settings.data.get("intel_paths", ""))
        paths = []
        for part in re.split(r"[\n,]", raw):
            cleaned = part.strip()
            if not cleaned:
                continue
            if not cleaned.startswith("/"):
                cleaned = f"/{cleaned}"
            paths.append(cleaned)
        return paths

    def _maybe_delay(self):
        if self.delay_jitter > 0:
            time.sleep(random.uniform(0, self.delay_jitter))

    def _get_timeout(self):
        try:
            return max(0.1, float(self.settings.data.get("timeout", 5)))
        except (TypeError, ValueError):
            return 5.0

    def _get_thread_count(self):
        try:
            return max(1, int(self.settings.data.get("threads", 1)))
        except (TypeError, ValueError):
            return 1

    def _get_recursion_depth(self):
        try:
            return max(0, int(self.settings.data.get("recursion_depth", 0)))
        except (TypeError, ValueError):
            return 0

    def _should_follow_redirects(self):
        value = self.settings.data.get("follow_redirects", True)
        if isinstance(value, str):
            return value.lower() in {"1", "true", "yes", "on"}
        return bool(value)

    def _status_allowed(self, code):
        cond = str(self.settings.data.get("include_status_codes", "")).strip()
        if not cond:
            return True
        try:
            if cond.startswith("<="):
                return code <= int(cond[2:])
            if cond.startswith("<"):
                return code < int(cond[1:])
            if cond.startswith(">="):
                return code >= int(cond[2:])
            if cond.startswith(">"):
                return code > int(cond[1:])
            if "," in cond:
                allowed = [int(part.strip()) for part in cond.split(",") if part.strip()]
                return code in allowed
            return code == int(cond)
        except (TypeError, ValueError):
            return False

    def start(self):
        if self.running:
            return
        if not urllib.parse.urlsplit(self.base_url).scheme:
            self.base_url = f"http://{self.base_url}"
            self.forensics.base_url = self.base_url.rstrip("/")
        try:
            words = self.load_wordlist()
        except FileNotFoundError:
            self.on_finish()
            return
        if not words:
            self.on_finish()
            return

        self.running = True
        self.to_scan = queue.Queue()
        self.seen = set()
        normalized_base = self._normalize(self.base_url)
        self.base_key = normalized_base
        self.path_seen = {normalized_base}
        self.threads = []
        self.word_variants = self._expand_words(words) or words
        self.processed = 0
        self.method_list = self._parse_methods()
        self.method_count = max(1, len(self.method_list))
        self.delay_jitter = self._get_delay_jitter()
        self.enable_preflight = bool(self.settings.data.get("enable_preflight", True))
        self.user_agent = self.settings.data.get("user_agent", Settings.DEFAULTS["user_agent"])
        self.base_headers = self._build_headers(self.user_agent)
        self.proxies = self._build_proxies()
        base_reference = self.base_url if "://" in self.base_url else f"http://{self.base_url}"
        self.base_host = urllib.parse.urlsplit(base_reference).netloc
        self.total = len(self.word_variants) * self.method_count
        self.intel_paths = self._parse_intel_paths()
        store = self._read_baseline_store()
        snapshot = store.get(self.base_key, {}) if isinstance(store, dict) else {}
        if not isinstance(snapshot, dict):
            snapshot = {}
        self.baseline_snapshot = snapshot
        self.current_snapshot = {}
        self.baseline_highlights = {"new": 0, "changed": 0, "retired": 0, "retired_items": []}
        self.preflight_targets = [
            urllib.parse.urljoin(f"{self.base_url}/", path.lstrip("/"))
            for path in self.intel_paths
        ]
        if self.enable_preflight:
            self.total += len(self.preflight_targets) * self.method_count
        self.to_scan.put((normalized_base, 0))

        def gather_certificate():
            info = self._fetch_certificate(base_reference)
            if info:
                self.certificate_info = info
                self.forensics.attach_certificate(info)
                if callable(self.on_certificate):
                    try:
                        self.on_certificate(dict(info))
                    except Exception:
                        pass

        threading.Thread(target=gather_certificate, daemon=True).start()

        if self.enable_preflight and self.preflight_targets:
            self.preflight_thread = threading.Thread(target=self._run_preflight, daemon=True)
            self.preflight_thread.start()
        else:
            self.preflight_thread = None

        for _ in range(self._get_thread_count()):
            thread = threading.Thread(target=self.worker, daemon=True)
            thread.start()
            self.threads.append(thread)

        monitor = threading.Thread(target=self._monitor, daemon=True)
        monitor.start()

    def stop(self):
        self.running = False
        while not self.to_scan.empty():
            try:
                self.to_scan.get_nowait()
                self.to_scan.task_done()
            except queue.Empty:
                break

    def worker(self):
        timeout = self._get_timeout()
        recursion_depth = self._get_recursion_depth()
        follow_redirects = self._should_follow_redirects()

        while self.running:
            try:
                url, depth = self.to_scan.get(timeout=0.5)
            except queue.Empty:
                continue

            try:
                if depth > recursion_depth:
                    self._advance_batch(len(self.word_variants) * self.method_count)
                    continue

                for word in self.word_variants:
                    if not self.running:
                        break

                    target = f"{url}/{word}" if not url.endswith('/') else f"{url}{word}"
                    for method in self.method_list:
                        if not self.running:
                            break

                        normalized_target = self._normalize(target)
                        key = (method, normalized_target)
                        with self.lock:
                            if key in self.seen:
                                already_seen = True
                            else:
                                self.seen.add(key)
                                already_seen = False

                        if already_seen:
                            self._update_progress()
                            continue

                        headers = dict(self.base_headers)
                        try:
                            response = requests.request(
                                method,
                                target,
                                timeout=timeout,
                                allow_redirects=follow_redirects,
                                headers=headers,
                                proxies=self.proxies,
                            )
                        except requests.RequestException:
                            self._update_progress()
                            self._maybe_delay()
                            continue

                        self._handle_response(target, method, response, depth)
                        self._update_progress()
                        self._maybe_delay()
            finally:
                self.to_scan.task_done()

    def _run_preflight(self):
        timeout = self._get_timeout()
        follow_redirects = self._should_follow_redirects()
        for target in self.preflight_targets:
            if not self.running:
                break
            for method in self.method_list:
                if not self.running:
                    break
                normalized_target = self._normalize(target)
                key = (method, normalized_target)
                with self.lock:
                    if key in self.seen:
                        already_seen = True
                    else:
                        self.seen.add(key)
                        already_seen = False
                if already_seen:
                    self._update_progress()
                    continue
                headers = dict(self.base_headers)
                try:
                    response = requests.request(
                        method,
                        target,
                        timeout=timeout,
                        allow_redirects=follow_redirects,
                        headers=headers,
                        proxies=self.proxies,
                    )
                except requests.RequestException:
                    self._update_progress()
                    self._maybe_delay()
                    continue

                self._handle_response(target, method, response, 0)
                self._update_progress()
                self._maybe_delay()

    def _build_preview(self, response, content_type):
        try:
            if "application/json" in content_type:
                data = response.json()
                return json.dumps(data, indent=2)[:800]
            if "text" in content_type:
                text = response.text
                return text[:800] if text else "<empty response>"
            return f"<{len(response.content)} bytes>"
        except Exception:
            try:
                text = response.text
                return text[:400] if text else "<unable to decode>"
            except Exception:
                return "<unable to decode>"

    def _assess_cors(self, response):
        if not self.settings.data.get("probe_cors", True):
            return None
        allow_origin = response.headers.get("Access-Control-Allow-Origin")
        if not allow_origin:
            return None
        origin = self.cors_origin
        if allow_origin == "*":
            allow_creds = response.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
            if allow_creds:
                return "CORS: wildcard origin with credentials"
            return "CORS: wildcard origin"
        if allow_origin == origin:
            return f"CORS: reflects Origin {origin}"
        return None

    def _discover_paths(self, response):
        try:
            text = response.text
        except Exception:
            return set()
        candidates = set()
        for match in re.findall(r'"(/[A-Za-z0-9_\-\./]{3,})"', text):
            if match.startswith("//"):
                continue
            candidates.add(match.split("?")[0])
        return candidates

    def _highlight_latency(self, response):
        latency = getattr(response, "elapsed", None)
        if not latency:
            return None, False
        try:
            latency_ms = max(0.0, latency.total_seconds() * 1000.0)
        except Exception:
            return None, False
        return latency_ms, latency_ms >= 1200

    def _header_intel(self, response):
        notes = []
        headers = response.headers
        server = headers.get("Server")
        powered = headers.get("X-Powered-By")
        if server:
            notes.append(f"Tech fingerprint: Server={server}")
        if powered:
            notes.append(f"Powered by {powered}")
        if headers.get("X-AspNet-Version"):
            notes.append("ASP.NET version leaked")
        if headers.get("X-Amzn-RequestId") and "AWS" not in "".join(notes):
            notes.append("AWS stack identifier exposed")
        if headers.get("X-Forwarded-For"):
            notes.append("Reverse proxy reveals origin hint")
        if headers.get("WWW-Authenticate"):
            notes.append("Authentication realm advertised")
        if (
            headers.get("Access-Control-Allow-Origin") == "*"
            and headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        ):
            notes.append("CORS allows credentials for wildcard origin")
        if headers.get("Retry-After"):
            notes.append("Rate limiting hinted via Retry-After")
        if not headers.get("X-Frame-Options"):
            notes.append("Missing clickjacking protection header")
        return notes

    def _detect_directory_listing(self, response, body_text):
        if not body_text:
            return False
        lowered = body_text.lower()
        return "index of /" in lowered or "directory listing" in lowered

    def _body_secrets(self, body_text):
        hits = []
        if not body_text:
            return hits
        sample = body_text[:5000]
        for label, pattern in self.secret_patterns:
            if pattern.search(sample):
                hits.append(f"{label} detected")
        if re.search(r"(?i)(api[_-]?key|auth[_-]?token)\s*[:=]\s*[\'\"]?[A-Za-z0-9\-_]{16,}", sample):
            hits.append("Generic API token keyword + value")
        return hits

    def _read_baseline_store(self):
        if not BASELINE_PATH.exists():
            return {}
        try:
            with open(BASELINE_PATH, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                return data
        except Exception:
            pass
        return {}

    def _write_baseline_store(self, store):
        try:
            with open(BASELINE_PATH, "w", encoding="utf-8") as fh:
                json.dump(store, fh, indent=2, sort_keys=True)
        except Exception:
            pass

    def _signature(self, method, url):
        return f"{method} {url}"

    def _status_intel(self, status):
        if status in {401, 403}:
            return "Restricted resource discovered"
        if status == 429:
            return "Rate limiting endpoint"
        if status == 500:
            return "Server error surface"
        if status == 302:
            return "Redirect trap"  # highlight potential auth bounce
        return None

    def _handle_response(self, target, method, response, depth):
        code = response.status_code
        if not self._status_allowed(code):
            return
        content_type = response.headers.get("Content-Type", "")
        preview = self._build_preview(response, content_type)
        cors_note = self._assess_cors(response)
        latency_ms, slow_hit = self._highlight_latency(response)
        try:
            body_text = response.text
        except Exception:
            body_text = ""

        intel_notes = []
        if cors_note:
            intel_notes.append(cors_note)
        intel_notes.extend(self._header_intel(response))
        status_insight = self._status_intel(code)
        if status_insight:
            intel_notes.append(status_insight)
        if slow_hit:
            intel_notes.append("Slow response (≥1.2s)")
        if self._detect_directory_listing(response, body_text):
            intel_notes.append("Directory listing exposure")
        secret_hits = self._body_secrets(body_text)
        intel_notes.extend(secret_hits)
        normalized_target = self._normalize(target)
        signature = self._signature(method, normalized_target)
        previous_status = self.baseline_snapshot.get(signature)
        if previous_status is None:
            delta = "NEW"
            intel_notes.append("Surface drift: brand new endpoint")
            self.baseline_highlights["new"] = self.baseline_highlights.get("new", 0) + 1
        elif previous_status != code:
            delta = f"CHANGED ({previous_status}->{code})"
            intel_notes.append("Surface drift: status changed since last run")
            self.baseline_highlights["changed"] = self.baseline_highlights.get("changed", 0) + 1
        else:
            delta = "BASELINE"
        intel_notes = [note for note in intel_notes if note]
        if getattr(response, "url", None):
            parsed_final = urllib.parse.urlsplit(response.url)
            aggregator_url = urllib.parse.urlunsplit(
                (parsed_final.scheme, parsed_final.netloc, parsed_final.path, "", parsed_final.fragment)
            )
        else:
            aggregator_url = normalized_target
        json_payload = None
        if "json" in content_type.lower():
            try:
                json_payload = response.json()
            except Exception:
                json_payload = None
        passive = self._passive_discovery(aggregator_url, body_text, content_type, json_payload)
        header_links = self._parse_link_header(response.headers.get("Link", ""))
        location = response.headers.get("Location")
        if location:
            header_links.add(location)
        if header_links:
            passive["link_relations"].update(header_links)
        csp_reports = self._extract_csp_reports(response.headers.get("Content-Security-Policy", ""))
        csp_reports.update(self._extract_report_to_header(response.headers.get("Report-To", "")))
        if csp_reports:
            passive["csp_reports"].update(csp_reports)
        if passive["form_targets"]:
            intel_notes.append(f"Passive forms → {len(passive['form_targets'])}")
        if passive["asset_links"]:
            intel_notes.append(f"JavaScript assets → {len(passive['asset_links'])}")
        if passive["json_links"]:
            intel_notes.append(f"Inline endpoints → {len(passive['json_links'])}")
        if passive["robots_paths"]:
            intel_notes.append(f"Robots intel → {len(passive['robots_paths'])}")
        if passive["sitemap_urls"]:
            intel_notes.append(f"Sitemap intel → {len(passive['sitemap_urls'])}")
        if passive["host_hints"]:
            intel_notes.append(f"Alt hosts hinted → {len(passive['host_hints'])}")
        if passive["websocket_links"]:
            intel_notes.append(f"WebSockets → {len(passive['websocket_links'])}")
        if passive["config_endpoints"]:
            intel_notes.append(f"Config endpoints → {len(passive['config_endpoints'])}")
        if passive["well_known_links"]:
            intel_notes.append(f".well-known intel → {len(passive['well_known_links'])}")
        if passive["link_relations"]:
            intel_notes.append(f"Header links → {len(passive['link_relations'])}")
        if passive["csp_reports"]:
            intel_notes.append(f"CSP reporting → {len(passive['csp_reports'])}")
        forensics_snapshot = self.forensics.ingest(
            aggregator_url,
            method,
            response,
            body_text,
            list(intel_notes),
            list(secret_hits),
            passive["paths"],
            asset_links=passive["asset_links"],
            form_targets=passive["form_targets"],
            json_links=passive["json_links"],
            host_hints=passive["host_hints"],
            robots_paths=passive["robots_paths"],
            sitemap_urls=passive["sitemap_urls"],
            websocket_links=passive["websocket_links"],
            link_relations=passive["link_relations"],
            csp_reports=passive["csp_reports"],
            well_known_links=passive["well_known_links"],
            config_endpoints=passive["config_endpoints"],
            json_payload=json_payload,
        )
        info = {
            "url": target,
            "method": method,
            "status": code,
            "type": content_type,
            "length": len(response.content),
            "preview": preview,
            "cors": cors_note,
            "notes": " | ".join(intel_notes),
            "signals": intel_notes,
            "latency": latency_ms,
            "slow": slow_hit,
            "secrets": len(secret_hits),
            "delta": delta,
            "previous_status": previous_status,
            "forensics": forensics_snapshot,
        }
        self.on_found(info)

        self.current_snapshot[signature] = code
        queue_candidates: set[str] = set()
        if "text/html" in content_type:
            queue_candidates.add(normalized_target)
        for bucket in [
            "paths",
            "form_targets",
            "json_links",
            "robots_paths",
            "sitemap_urls",
            "config_endpoints",
            "well_known_links",
            "link_relations",
        ]:
            queue_candidates.update(passive[bucket])
        for script in passive["asset_links"]:
            queue_candidates.add(script)
        for item in queue_candidates:
            if item == normalized_target:
                absolute = normalized_target
            elif item.startswith("http://") or item.startswith("https://"):
                absolute = item
            else:
                absolute = urllib.parse.urljoin(f"{self.base_url}/", item.lstrip("/"))
            parsed_candidate = urllib.parse.urlsplit(absolute)
            if parsed_candidate.netloc and self.base_host and parsed_candidate.netloc != self.base_host:
                continue
            normalized = self._normalize(absolute)
            with self.lock:
                if normalized not in self.path_seen:
                    self.path_seen.add(normalized)
                    self.total += len(self.word_variants) * self.method_count
                    self.to_scan.put((normalized, depth + 1))

    def _update_progress(self):
        with self.lock:
            self.processed += 1
            total = max(self.total, 1)
            progress = min(100.0, (self.processed / total) * 100)
        self.on_progress(progress)

    def _advance_batch(self, count):
        with self.lock:
            self.processed += count
            total = max(self.total, 1)
            progress = min(100.0, (self.processed / total) * 100)
        self.on_progress(progress)

    def _finalize_baseline(self):
        store = self._read_baseline_store()
        retired = [
            signature
            for signature in self.baseline_snapshot
            if signature not in self.current_snapshot
        ]
        self.baseline_highlights["retired"] = len(retired)
        self.baseline_highlights["retired_items"] = retired
        store[self.base_key] = self.current_snapshot
        self._write_baseline_store(store)

    def _monitor(self):
        self.to_scan.join()
        if self.preflight_thread:
            self.preflight_thread.join()
        self.running = False
        for thread in self.threads:
            thread.join()
        self._finalize_baseline()
        self.on_finish()


class AutomationEngine:
    def __init__(
        self,
        base_url: str,
        templates: list[dict[str, Any]],
        timeout: float,
        follow_redirects: bool,
        base_headers: Optional[dict[str, str]] = None,
        proxies: Optional[dict[str, str]] = None,
        on_result: Optional[Callable[[dict[str, Any]], None]] = None,
        on_finish: Optional[Callable[[], None]] = None,
        on_status: Optional[Callable[[str], None]] = None,
        on_progress: Optional[Callable[[float], None]] = None,
    ):
        self.base_url = base_url.rstrip("/") or base_url
        self.templates = [template for template in templates if isinstance(template, dict)]
        self.timeout = max(0.5, float(timeout)) if timeout else 5.0
        self.follow_redirects = bool(follow_redirects)
        self.base_headers = dict(base_headers or {})
        self.proxies = proxies
        self.on_result = on_result or (lambda info: None)
        self.on_finish = on_finish or (lambda: None)
        self.on_status = on_status or (lambda status: None)
        self.on_progress = on_progress or (lambda pct: None)
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        total = max(1, len(self.templates))
        for idx, template in enumerate(self.templates, start=1):
            name = template.get("name") or template.get("id") or f"Template {idx}"
            path = template.get("path") or "/"
            url = template.get("url")
            if not url:
                url = urllib.parse.urljoin(f"{self.base_url}/", path.lstrip("/"))
            method = str(template.get("method", "GET")).upper() or "GET"
            headers = dict(self.base_headers)
            for key, value in (template.get("headers") or {}).items():
                if isinstance(key, str):
                    headers[key] = str(value)
            body = template.get("body")
            status_message = f"{name}: firing {method} {url}"
            self.on_status(status_message)
            start = time.time()
            response = None
            error = None
            try:
                response = requests.request(
                    method,
                    url,
                    headers=headers if headers else None,
                    data=body,
                    timeout=self.timeout,
                    allow_redirects=self.follow_redirects,
                    proxies=self.proxies,
                )
            except requests.RequestException as exc:
                error = str(exc)

            elapsed_ms = (time.time() - start) * 1000.0
            result = self._build_result(template, url, response, error, elapsed_ms)
            try:
                self.on_result(result)
            except Exception:
                pass
            self.on_progress(min(100.0, (idx / total) * 100.0))
        try:
            self.on_finish()
        finally:
            self.on_status("Automations idle.")
            self.on_progress(0.0)

    def _build_result(self, template, url, response, error, elapsed_ms) -> dict[str, Any]:
        matchers = template.get("matchers") or {}
        severity = template.get("severity", "info")
        body_text = ""
        status_code = None
        headers = {}
        matched = False
        evidence: list[str] = []
        preview = ""
        if response is not None:
            status_code = response.status_code
            headers = dict(response.headers)
            try:
                body_text = response.text
            except Exception:
                try:
                    body_text = response.content.decode("utf-8", "ignore")
                except Exception:
                    body_text = ""
            preview = body_text[:800] if body_text else ""
            matched, evidence = self._evaluate_matchers(matchers, response, body_text)
        else:
            evidence = [error or "Request failed"]

        return {
            "template_id": template.get("id"),
            "template_name": template.get("name"),
            "description": template.get("description", ""),
            "severity": severity,
            "url": url,
            "status": status_code if status_code is not None else "ERR",
            "matched": matched,
            "evidence": evidence,
            "response_preview": preview,
            "headers": headers,
            "error": error,
            "elapsed_ms": elapsed_ms,
            "tags": template.get("tags", []),
        }

    def _evaluate_matchers(self, matchers: dict[str, Any], response, body_text: str) -> tuple[bool, list[str]]:
        if not matchers:
            return True, ["No matchers defined — recorded response for manual review."]
        evidence: list[str] = []
        status_rules = matchers.get("status")
        status_ok = True
        if status_rules and isinstance(status_rules, list):
            try:
                allowed = {int(code) for code in status_rules}
            except Exception:
                allowed = set()
                for code in status_rules:
                    try:
                        allowed.add(int(code))
                    except Exception:
                        continue
            status_ok = response.status_code in allowed if allowed else True
            if status_ok:
                evidence.append(f"Status {response.status_code} matched rule")
        contains_rules = matchers.get("contains")
        contains_ok = True
        lowered_body = body_text.lower() if body_text else ""
        if contains_rules:
            for needle in contains_rules:
                if not isinstance(needle, str):
                    continue
                if needle.lower() in lowered_body:
                    evidence.append(f"Contains '{needle}'")
                else:
                    contains_ok = False
                    break
        regex_rules = matchers.get("regex")
        regex_ok = True
        if regex_rules:
            for pattern in regex_rules:
                try:
                    if re.search(pattern, body_text or ""):
                        evidence.append(f"Regex {pattern} matched")
                    else:
                        regex_ok = False
                        break
                except re.error:
                    regex_ok = False
                    break
        negative_contains = matchers.get("negative_contains")
        negative_ok = True
        if negative_contains:
            for needle in negative_contains:
                if not isinstance(needle, str):
                    continue
                if needle.lower() in lowered_body:
                    negative_ok = False
                    evidence.append(f"Unexpected token '{needle}' present")
                    break
        header_rules = matchers.get("headers")
        headers_ok = True
        if header_rules and isinstance(header_rules, dict):
            for key, expected in header_rules.items():
                if not isinstance(key, str):
                    continue
                actual = response.headers.get(key)
                if actual is None:
                    headers_ok = False
                    break
                if isinstance(expected, str):
                    if expected.lower() not in actual.lower():
                        headers_ok = False
                        break
                    evidence.append(f"Header {key} contains '{expected}'")
                elif isinstance(expected, list):
                    match_any = False
                    for candidate in expected:
                        if isinstance(candidate, str) and candidate.lower() in actual.lower():
                            match_any = True
                            evidence.append(f"Header {key} contains '{candidate}'")
                            break
                    if not match_any:
                        headers_ok = False
                        break
        outcome = status_ok and contains_ok and regex_ok and negative_ok and headers_ok
        if outcome and not evidence:
            evidence.append("Matchers satisfied")
        return outcome, evidence


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("HackXpert API Surface Explorer")
        self.geometry("960x720")
        self.configure(bg="#020617")
        self.settings = Settings()
        self.forcers = {}
        self.scan_count = 0
        self.wordlist_store = Path.home() / ".hackxpert_wordlists"
        self.wordlist_store.mkdir(parents=True, exist_ok=True)
        self._wordlist_helpers = []
        self.api_tree_results = {}
        self.console: Optional[ScrolledText] = None
        self.certificate_vars: dict[str, tk.StringVar] = {}
        self.latest_certificate: Optional[dict[str, Any]] = None
        self.proxy_status_var = tk.StringVar(value="Proxy: direct")
        self.automation_templates: dict[str, dict[str, Any]] = {}
        self.automation_custom_templates: list[dict[str, Any]] = []
        self.automation_rulesets: dict[str, list[str]] = {}
        self._automation_library_payload: dict[str, Any] = {}
        self.automation_engine: Optional[AutomationEngine] = None
        self.automation_results_lookup: dict[str, dict[str, Any]] = {}

        self._init_style()
        self._load_automation_assets()
        self._build_header()
        self._build_notebook()

    def _init_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        primary = "#020617"
        panel = "#050b18"
        accent = "#3bff95"
        highlight = "#5eead4"
        style.configure("TFrame", background=primary)
        style.configure("Header.TFrame", background=primary)
        style.configure("Card.TFrame", background=panel, relief="ridge", borderwidth=1)
        style.configure("ConsoleFrame.TFrame", background=panel, relief="ridge", borderwidth=1)
        style.configure("TNotebook", background=primary, borderwidth=0)
        style.configure("TNotebook.Tab", padding=(14, 6), background="#0b162d", foreground="#9ca3af")
        style.map("TNotebook.Tab", background=[("selected", accent)], foreground=[("selected", "#02111b")])
        style.configure("TLabel", background=primary, foreground="#e2e8f0")
        style.configure("Accent.TLabel", background=primary, foreground=accent, font=("Share Tech Mono", 18, "bold"))
        style.configure("Glitch.TLabel", background=primary, foreground=highlight, font=("Share Tech Mono", 14, "bold"))
        style.configure("TButton", background="#0b162d", foreground="#e2e8f0", padding=(12, 6))
        style.map("TButton", background=[("active", accent)], foreground=[("active", "#02111b")])
        style.configure(
            "Treeview",
            background="#030b16",
            fieldbackground="#030b16",
            foreground="#9ca3af",
            bordercolor=accent,
            rowheight=26,
        )
        style.configure("Treeview.Heading", background="#041024", foreground=accent, font=("Share Tech Mono", 11, "bold"))
        style.configure("HUDCard.TFrame", background="#071127", relief="ridge", borderwidth=1)
        style.configure("StatLabel.TLabel", background="#071127", foreground=highlight, font=("Share Tech Mono", 10, "bold"))
        style.configure("StatValuePrimary.TLabel", background="#071127", foreground=accent, font=("Share Tech Mono", 20, "bold"))
        style.configure("StatValueAlert.TLabel", background="#071127", foreground="#f97316", font=("Share Tech Mono", 20, "bold"))
        style.configure("StatValueSuccess.TLabel", background="#071127", foreground="#4ade80", font=("Share Tech Mono", 20, "bold"))
        style.configure("StatValueFocus.TLabel", background="#071127", foreground="#f472b6", font=("Share Tech Mono", 20, "bold"))
        style.configure("StatusBadge.TLabel", background=panel, foreground="#fbbf24", font=("Share Tech Mono", 12, "bold"))
        style.configure("TLSValue.TLabel", background=panel, foreground=accent, font=("Share Tech Mono", 11, "bold"))
        style.configure("ConsoleTitle.TLabel", background=panel, foreground=accent, font=("Share Tech Mono", 12, "bold"))
        style.configure("AutomationHit.TLabel", background=panel, foreground="#facc15", font=("Share Tech Mono", 12, "bold"))
        style.configure("AutomationMiss.TLabel", background=panel, foreground="#94a3b8", font=("Share Tech Mono", 12, "bold"))

    def _load_automation_assets(self) -> None:
        builtin = _load_automation_templates_from_disk(AUTOMATION_TEMPLATE_FILE)
        if not builtin:
            builtin = list(DEFAULT_AUTOMATION_TEMPLATES)
        normalized_builtin: dict[str, dict[str, Any]] = {}
        for entry in builtin:
            if not isinstance(entry, dict):
                continue
            identifier = str(entry.get("id") or self._sanitize_wordlist_name(entry.get("name", "template")))
            entry = dict(entry)
            entry["id"] = identifier
            normalized_builtin[identifier] = entry
        payload = _load_automation_library()
        custom: list[dict[str, Any]] = []
        combined = dict(normalized_builtin)
        for entry in payload.get("custom_templates", []):
            if not isinstance(entry, dict):
                continue
            identifier = str(entry.get("id") or self._sanitize_wordlist_name(entry.get("name", "template")))
            clone = dict(entry)
            clone["id"] = identifier
            combined[identifier] = clone
            custom.append(clone)
        rulesets: dict[str, list[str]] = {}
        for name, template_ids in payload.get("rulesets", {}).items():
            if not isinstance(template_ids, list):
                continue
            filtered = [tid for tid in template_ids if tid in combined]
            if filtered:
                rulesets[str(name)] = filtered
        self.automation_templates = combined
        self.automation_custom_templates = custom
        self.automation_rulesets = rulesets
        self._automation_library_payload = {"custom_templates": custom, "rulesets": rulesets}

    def _persist_automation_library(self) -> None:
        payload = {
            "custom_templates": self.automation_custom_templates,
            "rulesets": self.automation_rulesets,
        }
        self._automation_library_payload = payload
        _save_automation_library(payload)

    def _sanitize_wordlist_name(self, name: str) -> str:
        cleaned = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
        return cleaned or "wordlist"

    def _ensure_wordlist(self, name: str) -> Optional[Path]:
        entry = WORDLIST_CATALOG.get(name)
        if not entry:
            return None
        if entry.get("kind") == "builtin":
            path = Path(entry.get("path", ""))
            if path.exists():
                return path
            fallback_words = entry.get("words") or []
            if fallback_words:
                destination = self.wordlist_store / f"{self._sanitize_wordlist_name(name)}.txt"
                try:
                    destination.write_text("\n".join(fallback_words) + "\n", encoding="utf-8")
                    return destination
                except Exception as exc:
                    messagebox.showerror("Wordlist Save Failed", f"Could not materialise {name}: {exc}")
                    return None
            messagebox.showerror("Wordlist Missing", f"Custom wordlist for {name} is unavailable.")
            return None
        url = entry.get("url")
        if not url:
            return None
        path = self.wordlist_store / f"{self._sanitize_wordlist_name(name)}.txt"
        if not path.exists():
            return self._download_wordlist(name, url, path)
        return path

    def _download_wordlist(self, name: str, url: str, path: Optional[Path] = None) -> Optional[Path]:
        destination = path or self.wordlist_store / f"{self._sanitize_wordlist_name(name)}.txt"
        try:
            response = requests.get(url, timeout=30, proxies=self._current_proxies())
            response.raise_for_status()
        except Exception as exc:
            messagebox.showerror("Wordlist Download Failed", f"Could not fetch {name}: {exc}")
            return None
        try:
            destination.write_bytes(response.content)
        except Exception as exc:  # pragma: no cover - IO failure
            messagebox.showerror("Wordlist Save Failed", f"Could not store {name}: {exc}")
            return None
        self.status_var.set(f"Downloaded {name} ({len(response.content)} bytes)") if hasattr(
            self, "status_var"
        ) else None
        return destination

    def _attach_wordlist_autocomplete(self, entry: ttk.Entry, variable: tk.StringVar) -> None:
        popup = tk.Toplevel(self)
        popup.withdraw()
        popup.overrideredirect(True)
        popup.configure(bg="#0f172a")
        listbox = tk.Listbox(
            popup,
            bg="#0b1120",
            fg="#38bdf8",
            selectbackground="#22d3ee",
            selectforeground="#0f172a",
            highlightthickness=0,
            relief="flat",
        )
        listbox.pack(fill="both", expand=True)

        helper = {"popup": popup, "listbox": listbox, "entry": entry, "variable": variable}
        self._wordlist_helpers.append(helper)

        def hide_popup():
            popup.withdraw()

        def select_current(_event=None):
            selection = listbox.curselection()
            if not selection:
                hide_popup()
                return
            name = listbox.get(selection[0])
            path = self._ensure_wordlist(name)
            if path:
                variable.set(str(path))
            hide_popup()

        def update_suggestions(_event=None):
            text = variable.get()
            matches = [name for name in WORDLIST_CATALOG if text.lower() in name.lower()] if text else []
            listbox.delete(0, "end")
            if not matches:
                hide_popup()
                return
            for name in matches[:8]:
                listbox.insert("end", name)
            listbox.selection_clear(0, "end")
            listbox.selection_set(0)
            listbox.activate(0)
            entry_x = entry.winfo_rootx()
            entry_y = entry.winfo_rooty() + entry.winfo_height()
            popup.geometry(f"240x180+{entry_x}+{entry_y}")
            popup.deiconify()
            popup.lift()

        def focus_list(_event=None):
            if listbox.size() > 0:
                listbox.focus_set()

        entry.bind("<KeyRelease>", update_suggestions, add="+")
        entry.bind("<FocusOut>", lambda _e: self.after(150, hide_popup), add="+")
        entry.bind("<Down>", focus_list, add="+")
        listbox.bind("<ButtonRelease-1>", select_current)
        listbox.bind("<Return>", select_current)
        listbox.bind("<Escape>", lambda _e: hide_popup())

    def _apply_wordlist_selection(self, target_var: tk.StringVar, selection_var: tk.StringVar) -> None:
        name = selection_var.get()
        if not name:
            return
        path = self._ensure_wordlist(name)
        if path:
            target_var.set(str(path))

    def _materialise_wordlist(self, selected_path: str, include_custom: bool, flavour: str) -> Optional[str]:
        path = Path(selected_path)
        if not path.is_file():
            return None
        if not include_custom or not CUSTOM_ENDPOINT_WORDS:
            return str(path)
        base_entries = _read_wordlist_lines(path)
        combined: list[str] = []
        seen = set()
        for word in CUSTOM_ENDPOINT_WORDS + base_entries:
            if not word or word in seen:
                continue
            combined.append(word)
            seen.add(word)
        destination = self.wordlist_store / f"{self._sanitize_wordlist_name(path.stem or 'wordlist')}-{flavour}.txt"
        try:
            destination.write_text("\n".join(combined) + "\n", encoding="utf-8")
        except Exception as exc:
            messagebox.showerror("Wordlist Save Failed", f"Could not compose merged wordlist: {exc}")
            return None
        return str(destination)

    def _resolve_parameter_payloads(self, selected_name: str, include_custom: bool) -> list[str]:
        payloads = list(PARAMETER_WORDLISTS.get(selected_name, []))
        if not include_custom or not CUSTOM_PARAMETER_WORDS:
            return payloads
        combined: list[str] = []
        seen = set()
        for word in CUSTOM_PARAMETER_WORDS + payloads:
            if not word or word in seen:
                continue
            combined.append(word)
            seen.add(word)
        return combined

    def _attach_tree_context_menu(self, tree: ttk.Treeview, lookup: Callable[[str], Optional[dict]]):
        menu = tk.Menu(tree, tearoff=0, bg="#0b1120", fg="#38bdf8", activebackground="#22d3ee", activeforeground="#0f172a")
        menu.add_command(
            label="Send to Parameter Explorer",
            command=lambda: self._tree_to_parameter_explorer(tree, lookup),
        )

        def show_menu(event):
            row = tree.identify_row(event.y)
            if not row:
                return
            tree.selection_set(row)
            try:
                menu.tk_popup(event.x_root, event.y_root)
            finally:
                menu.grab_release()

        tree.bind("<Button-3>", show_menu)

    def _tree_to_parameter_explorer(self, tree: ttk.Treeview, lookup):
        selection = tree.selection()
        if not selection:
            return
        info = lookup(selection[0]) if callable(lookup) else None
        if not info:
            return
        self._send_to_parameter_explorer(info)

    def _compose_headers_from_settings(self) -> dict[str, str]:
        headers = {}
        extra = str(self.settings.data.get("extra_headers", ""))
        for line in extra.splitlines():
            if not line.strip() or ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
        headers.setdefault("User-Agent", self.settings.data.get("user_agent", Settings.DEFAULTS["user_agent"]))
        return headers

    def _build_header(self):
        header = ttk.Frame(self, style="Header.TFrame")
        header.pack(fill="x", pady=5)

        try:
            image = Image.open("logo.png")
            self.update_idletasks()
            max_width = max(80, int(self.winfo_width() * 0.1))
            ratio = max_width / image.width
            resample = getattr(getattr(Image, "Resampling", Image), "LANCZOS", Image.BILINEAR)
            resized = image.resize((max_width, int(image.height * ratio)), resample)
            logo_image = ImageTk.PhotoImage(resized)
            logo_label = ttk.Label(header, image=logo_image, style="Header.TFrame")
            logo_label.image = logo_image
            logo_label.pack(side="left", padx=10)
        except Exception:
            pass

        text_frame = ttk.Frame(header, style="Header.TFrame")
        text_frame.pack(side="left", padx=10)
        ttk.Label(text_frame, text="HACKXPERT // API RECON LAB", style="Accent.TLabel").pack(anchor="w")
        ttk.Label(text_frame, text="Neon forensics, passive intel, Burp chaining", style="Glitch.TLabel").pack(anchor="w")

        links_frame = ttk.Frame(header, style="Header.TFrame")
        links_frame.pack(side="right", padx=10)
        for text, url in [
            ("Docs", "https://github.com/thexssrat/hackxpert"),
            ("Hackxpert Labs", "https://labs.hackxpert.com/"),
            ("@theXSSrat", "https://x.com/theXSSrat"),
        ]:
            link = ttk.Label(links_frame, text=text, style="Glitch.TLabel", cursor="hand2")
            link.pack(side="right", padx=6)
            link.bind("<Button-1>", lambda _e, target=url: webbrowser.open(target))

        ttk.Label(header, textvariable=self.proxy_status_var, style="Glitch.TLabel").pack(side="right", padx=10)

        progress_frame = ttk.Frame(header, style="Header.TFrame")
        progress_frame.pack(side="right", padx=10)
        ttk.Label(progress_frame, text="Recon Progress", style="Glitch.TLabel").pack(anchor="e")
        self.progress = ttk.Progressbar(progress_frame, mode="determinate", length=260)
        self.progress.pack(anchor="e", pady=2)
        self._update_proxy_status()

    def _build_notebook(self):
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=10, pady=10)
        self.nb.bind("<Double-1>", self._rename_tab)
        self._build_instructions_tab()
        self._build_scan_tab()
        self._build_endpoint_explorer()
        self._build_parameter_explorer()
        self._build_automations_tab()
        self._build_settings_tab()

    def _build_instructions_tab(self):
        frame = ttk.Frame(self.nb, style="Card.TFrame")
        self.nb.add(frame, text="Briefing")
        text = ScrolledText(
            frame,
            wrap="word",
            font=("Consolas", 11),
            bg="#0f172a",
            fg="#22d3ee",
            insertbackground="#22d3ee",
            relief="flat",
        )
        text.pack(fill="both", expand=True, padx=10, pady=10)
        briefing = (
            "Welcome to the HackXpert API Surface Explorer!\n\n"
            "Step 1 — Stage the target:\n"
            "  • Feed an API base URL and pick a brutal wordlist (the entry box autocompletes SecLists for you).\n"
            "  • Tweak threading, recursion, methods and headers in the Settings tab if you need stealth.\n\n"
            "Step 2 — Recon like a menace:\n"
            "  • Launch a classic surface scan from the Recon Lab tab to map directories, files and intel paths.\n"
            "  • Jump into the API Endpoint Explorer to auto-hunt specs, Swagger docs and hidden endpoints.\n\n"
            "Step 3 — Weaponise the findings:\n"
            "  • Double click any request to open the request workbench and replay or mutate it.\n"
            "  • Right click requests anywhere to sling them into the Parameter Explorer for focused fuzzing.\n\n"
            "Step 4 — Export proof:\n"
            "  • Save hits as JSON or CSV, or copy URLs directly for follow-up exploitation.\n"
            "  • Baseline drift detection highlights new, changed and retired surfaces automatically.\n\n"
            "Step 5 — Automate exploitation:\n"
            "  • Load curated rulesets or select templates in the Automations tab to mimic nuclei-style probes.\n"
            "  • Import JSON templates, craft your own exploits, then review evidence, previews and response headers.\n\n"
            "Need help? Hover labels for hints, and watch the status HUD for live telemetry while you hack stylishly."
        )
        text.insert("1.0", briefing)
        text.configure(state="disabled")

    def _build_scan_tab(self):
        frame = ttk.Frame(self.nb, style="Card.TFrame")
        self.nb.add(frame, text="Recon Lab")

        ttk.Label(
            frame,
            text="Stack HackXpert's bespoke API lists with OSINT mega packs for full-spectrum recon.",
            style="Glitch.TLabel",
        ).grid(row=0, column=0, columnspan=3, padx=5, pady=(8, 2), sticky="w")

        ttk.Label(frame, text="API Base URL:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.url = tk.StringVar()
        ttk.Entry(frame, textvariable=self.url, width=60).grid(row=1, column=1, padx=5, pady=5, sticky="w")

        ttk.Label(frame, text="Wordlist:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.wordlist_path = tk.StringVar()
        wordlist_entry = ttk.Entry(frame, textvariable=self.wordlist_path, width=50)
        wordlist_entry.grid(row=2, column=1, padx=5, pady=5, sticky="w")
        self._attach_wordlist_autocomplete(wordlist_entry, self.wordlist_path)
        default_list = self._ensure_wordlist("HackXpert Essentials (custom)")
        if default_list:
            self.wordlist_path.set(str(default_list))
        ttk.Button(frame, text="Browse", command=self._browse_wordlist).grid(row=2, column=2, padx=5, pady=5)

        ttk.Label(frame, text="Load from catalog:").grid(row=3, column=0, padx=5, pady=5, sticky="e")
        self.scan_wordlist_choice = tk.StringVar(value="HackXpert Essentials (custom)")
        catalog_combo = ttk.Combobox(
            frame,
            textvariable=self.scan_wordlist_choice,
            values=list(WORDLIST_CATALOG.keys()),
            width=40,
            state="readonly",
        )
        catalog_combo.grid(row=3, column=1, padx=5, pady=5, sticky="w")
        catalog_combo.bind(
            "<<ComboboxSelected>>",
            lambda _e: self._apply_wordlist_selection(self.wordlist_path, self.scan_wordlist_choice),
        )

        self.scan_use_custom_wordlist = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            frame,
            text="Use custom wordlist",
            variable=self.scan_use_custom_wordlist,
        ).grid(row=4, column=1, padx=5, pady=(0, 10), sticky="w")

        ttk.Button(frame, text="Launch Scan", command=self._new_scan).grid(row=5, column=1, pady=10)

        hud = ttk.Frame(frame, style="Card.TFrame")
        hud.grid(row=6, column=0, columnspan=3, sticky="ew", padx=5, pady=(0, 10))
        for idx in range(6):
            hud.grid_columnconfigure(idx, weight=1)

        self.hud_metrics = {
            "total": tk.StringVar(value="0"),
            "success": tk.StringVar(value="0"),
            "alerts": tk.StringVar(value="0"),
            "secrets": tk.StringVar(value="0"),
            "slow": tk.StringVar(value="0"),
            "drift": tk.StringVar(value="0"),
        }
        cards = [
            ("Total Hits", "total", "StatValuePrimary.TLabel"),
            ("2xx Wins", "success", "StatValueSuccess.TLabel"),
            ("Intel Alerts", "alerts", "StatValueAlert.TLabel"),
            ("Secrets Flagged", "secrets", "StatValueFocus.TLabel"),
            ("Slow Endpoints", "slow", "StatValueAlert.TLabel"),
            ("Surface Drift", "drift", "StatValueFocus.TLabel"),
        ]
        for idx, (label, key, style_name) in enumerate(cards):
            card = ttk.Frame(hud, style="HUDCard.TFrame", padding=10)
            card.grid(row=0, column=idx, padx=6, pady=6, sticky="nsew")
            ttk.Label(card, text=label, style="StatLabel.TLabel").pack(anchor="w")
            ttk.Label(card, textvariable=self.hud_metrics[key], style=style_name).pack(anchor="w")

        tls_frame = ttk.Frame(frame, style="Card.TFrame")
        tls_frame.grid(row=7, column=0, columnspan=3, sticky="ew", padx=5, pady=(0, 10))
        ttk.Label(tls_frame, text="TLS Reconnaissance", style="Glitch.TLabel").grid(row=0, column=0, padx=12, pady=(8, 2), sticky="w")
        labels = [
            ("Subject", "subject"),
            ("Issuer", "issuer"),
            ("Expires", "expires"),
            ("Alt Names", "alt"),
        ]
        self.certificate_vars = {key: tk.StringVar(value="-") for _, key in labels}
        for idx, (label, key) in enumerate(labels, start=1):
            ttk.Label(tls_frame, text=f"{label}:", style="StatLabel.TLabel").grid(row=idx, column=0, padx=16, pady=2, sticky="w")
            ttk.Label(tls_frame, textvariable=self.certificate_vars[key], style="TLSValue.TLabel").grid(
                row=idx, column=1, padx=6, pady=2, sticky="w"
            )

        status_frame = ttk.Frame(frame, style="Card.TFrame")
        status_frame.grid(row=8, column=0, columnspan=3, sticky="ew", padx=5, pady=(0, 10))
        self.status_var = tk.StringVar(value="Awaiting mission launch…")
        ttk.Label(status_frame, textvariable=self.status_var, style="StatusBadge.TLabel").pack(
            anchor="w", padx=12, pady=8
        )

        console_frame = ttk.Frame(frame, style="ConsoleFrame.TFrame")
        console_frame.grid(row=9, column=0, columnspan=3, sticky="nsew", padx=5, pady=(0, 12))
        ttk.Label(console_frame, text="Recon Console", style="ConsoleTitle.TLabel").pack(anchor="w", padx=12, pady=(8, 0))
        self.console = ScrolledText(
            console_frame,
            height=8,
            bg="#010409",
            fg="#3bff95",
            insertbackground="#3bff95",
            font=("Share Tech Mono", 10),
        )
        self.console.pack(fill="both", expand=True, padx=10, pady=(4, 10))
        self.console.configure(state="disabled")
        frame.grid_rowconfigure(9, weight=1)

    def _build_endpoint_explorer(self):
        frame = ttk.Frame(self.nb, style="Card.TFrame")
        self.endpoint_frame = frame
        self.nb.add(frame, text="API Endpoint Explorer")

        ttk.Label(
            frame,
            text="Endpoint sweeps can stack the HackXpert custom list with familiar open-source collections.",
        ).grid(row=0, column=0, columnspan=3, padx=6, pady=(8, 2), sticky="w")

        ttk.Label(frame, text="Target Base URL:").grid(row=1, column=0, padx=6, pady=6, sticky="e")
        self.endpoint_url = tk.StringVar()
        ttk.Entry(frame, textvariable=self.endpoint_url, width=60).grid(row=1, column=1, padx=6, pady=6, sticky="w")

        ttk.Label(frame, text="Wordlist:").grid(row=2, column=0, padx=6, pady=6, sticky="e")
        self.endpoint_wordlist = tk.StringVar()
        endpoint_entry = ttk.Entry(frame, textvariable=self.endpoint_wordlist, width=50)
        endpoint_entry.grid(row=2, column=1, padx=6, pady=6, sticky="w")
        self._attach_wordlist_autocomplete(endpoint_entry, self.endpoint_wordlist)
        endpoint_default = self._ensure_wordlist("HackXpert Essentials (custom)")
        if endpoint_default:
            self.endpoint_wordlist.set(str(endpoint_default))
        ttk.Button(frame, text="Browse", command=lambda: self._browse_generic_wordlist(self.endpoint_wordlist)).grid(
            row=2, column=2, padx=6, pady=6
        )

        ttk.Label(frame, text="Load from catalog:").grid(row=3, column=0, padx=6, pady=6, sticky="e")
        self.endpoint_wordlist_choice = tk.StringVar(value="HackXpert Essentials (custom)")
        endpoint_combo = ttk.Combobox(
            frame,
            textvariable=self.endpoint_wordlist_choice,
            values=list(WORDLIST_CATALOG.keys()),
            width=40,
            state="readonly",
        )
        endpoint_combo.grid(row=3, column=1, padx=6, pady=6, sticky="w")
        endpoint_combo.bind(
            "<<ComboboxSelected>>",
            lambda _e: self._apply_wordlist_selection(self.endpoint_wordlist, self.endpoint_wordlist_choice),
        )

        self.endpoint_use_custom = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            frame,
            text="Use custom wordlist",
            variable=self.endpoint_use_custom,
        ).grid(row=4, column=1, padx=6, pady=(0, 10), sticky="w")

        ttk.Button(frame, text="Run Discovery", command=self._start_api_endpoint_explorer).grid(
            row=5, column=1, pady=8
        )

        columns = ("status", "detail")
        tree = ttk.Treeview(
            frame,
            columns=columns,
            show="tree headings",
            height=14,
        )
        tree.heading("status", text="STATUS")
        tree.heading("detail", text="DETAIL")
        tree.column("#0", width=320, stretch=True)
        tree.column("status", width=100, anchor="center")
        tree.column("detail", width=360, anchor="w")
        tree.grid(row=6, column=0, columnspan=3, sticky="nsew", padx=10, pady=10)
        frame.grid_rowconfigure(6, weight=1)
        frame.grid_columnconfigure(1, weight=1)

        self.api_tree = tree
        self.api_specs_node = tree.insert("", "end", text="Specification Hunts", values=("", ""), open=True)
        self.api_endpoints_node = tree.insert("", "end", text="Endpoint Hits", values=("", ""), open=True)
        self.api_tree_results = {}
        tree.bind("<Double-1>", self._on_api_tree_double)
        self._attach_tree_context_menu(tree, lambda iid: self.api_tree_results.get(iid))

        status_frame = ttk.Frame(frame, style="Card.TFrame")
        status_frame.grid(row=7, column=0, columnspan=3, sticky="ew", padx=10, pady=(0, 10))
        self.api_status_var = tk.StringVar(value="Idle — feed the explorer a target and wordlist.")
        ttk.Label(status_frame, textvariable=self.api_status_var, style="StatusBadge.TLabel").pack(anchor="w", padx=4, pady=4)

    def _log_console(self, message: str) -> None:
        if not self.console:
            return
        timestamp = time.strftime("%H:%M:%S")
        self.console.configure(state="normal")
        self.console.insert("end", f"[{timestamp}] {message}\n")
        self.console.see("end")
        self.console.configure(state="disabled")

    def _current_proxies(self) -> Optional[dict[str, str]]:
        enabled = self.settings.data.get("burp_proxy_enabled")
        if isinstance(enabled, str):
            enabled = enabled.lower() in {"1", "true", "yes", "on"}
        if not enabled:
            return None
        host = str(self.settings.data.get("burp_proxy_host", "")).strip()
        port_value = self.settings.data.get("burp_proxy_port", 0)
        try:
            port = int(port_value)
        except (TypeError, ValueError):
            return None
        if not host or port <= 0:
            return None
        address = f"http://{host}:{port}"
        return {"http": address, "https": address}

    def _update_proxy_status(self) -> None:
        proxies = self._current_proxies()
        if proxies:
            host = str(self.settings.data.get("burp_proxy_host", "127.0.0.1")).strip() or "127.0.0.1"
            port = self.settings.data.get("burp_proxy_port", 8080)
            self.proxy_status_var.set(f"Proxy: Burp {host}:{port}")
        else:
            self.proxy_status_var.set("Proxy: direct")

    def _on_certificate_ready(self, info: dict[str, Any]) -> None:
        self.latest_certificate = info
        subject = info.get("subject") or "-"
        issuer = info.get("issuer") or "-"
        expires = info.get("expires") or "-"
        alt_names = info.get("alt_names") or []
        alt_display = ", ".join(str(name) for name in alt_names[:4])
        if len(alt_names) > 4:
            alt_display += ", …"
        if "subject" in self.certificate_vars:
            self.certificate_vars["subject"].set(subject)
        if "issuer" in self.certificate_vars:
            self.certificate_vars["issuer"].set(issuer)
        if "expires" in self.certificate_vars:
            self.certificate_vars["expires"].set(expires)
        if "alt" in self.certificate_vars:
            self.certificate_vars["alt"].set(alt_display or "-")
        self._log_console(f"[TLS] {subject} issued by {issuer}, expires {expires}")

    def _build_parameter_explorer(self):
        frame = ttk.Frame(self.nb, style="Card.TFrame")
        self.parameter_frame = frame
        self.nb.add(frame, text="API Parameter Explorer")

        ttk.Label(
            frame,
            text="Parameter fuzzing can stack HackXpert's custom list with themed payload packs.",
        ).grid(row=0, column=0, columnspan=4, padx=6, pady=(8, 2), sticky="w")

        ttk.Label(frame, text="Request URL:").grid(row=1, column=0, padx=6, pady=6, sticky="e")
        self.param_url = tk.StringVar()
        ttk.Entry(frame, textvariable=self.param_url, width=70).grid(row=1, column=1, columnspan=2, padx=6, pady=6, sticky="we")

        ttk.Label(frame, text="Method:").grid(row=2, column=0, padx=6, pady=6, sticky="e")
        self.param_method = tk.StringVar(value="GET")
        self.param_method_combo = ttk.Combobox(
            frame,
            textvariable=self.param_method,
            values=["GET", "POST", "PUT", "PATCH", "DELETE"],
            width=8,
            state="readonly",
        )
        self.param_method_combo.grid(row=2, column=1, padx=6, pady=6, sticky="w")

        ttk.Label(frame, text="Parameter Wordlist:").grid(row=2, column=2, padx=6, pady=6, sticky="e")
        self.param_wordlist = tk.StringVar(value="HackXpert Essentials (custom)")
        ttk.Combobox(
            frame,
            textvariable=self.param_wordlist,
            values=list(PARAMETER_WORDLISTS.keys()),
            state="readonly",
            width=24,
        ).grid(row=2, column=3, padx=6, pady=6, sticky="w")

        self.param_use_custom = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            frame,
            text="Use custom wordlist",
            variable=self.param_use_custom,
        ).grid(row=3, column=3, padx=6, pady=(0, 10), sticky="w")

        ttk.Label(frame, text="Headers (Key: Value per line):").grid(row=4, column=0, padx=6, pady=6, sticky="ne")
        self.param_headers = ScrolledText(frame, height=6, width=40, bg="#0b1120", fg="#e2e8f0", insertbackground="#22d3ee")
        self.param_headers.grid(row=4, column=1, padx=6, pady=6, sticky="we")

        ttk.Label(frame, text="Body (optional):").grid(row=4, column=2, padx=6, pady=6, sticky="ne")
        self.param_body = ScrolledText(frame, height=6, width=40, bg="#0b1120", fg="#e2e8f0", insertbackground="#22d3ee")
        self.param_body.grid(row=4, column=3, padx=6, pady=6, sticky="we")

        ttk.Button(frame, text="Launch Parameter Fuzz", command=self._start_parameter_explorer).grid(
            row=5, column=0, columnspan=4, pady=10
        )

        columns = ("parameter", "status", "delta", "length")
        tree = ttk.Treeview(frame, columns=columns, show="headings", height=12)
        tree.heading("parameter", text="PARAMETER")
        tree.heading("status", text="STATUS")
        tree.heading("delta", text="DELTA")
        tree.heading("length", text="LENGTH")
        tree.column("parameter", width=200, anchor="w")
        tree.column("status", width=90, anchor="center")
        tree.column("delta", width=240, anchor="w")
        tree.column("length", width=120, anchor="center")
        tree.grid(row=6, column=0, columnspan=4, sticky="nsew", padx=10, pady=10)
        frame.grid_rowconfigure(6, weight=1)
        for idx in range(4):
            frame.grid_columnconfigure(idx, weight=1)

        self.param_tree = tree
        self.parameter_results = {}
        tree.bind("<Double-1>", self._on_parameter_double)

        status_frame = ttk.Frame(frame, style="Card.TFrame")
        status_frame.grid(row=7, column=0, columnspan=4, sticky="ew", padx=10, pady=(0, 10))
        self.param_status_var = tk.StringVar(value="Awaiting a request to probe.")
        ttk.Label(status_frame, textvariable=self.param_status_var, style="StatusBadge.TLabel").pack(anchor="w", padx=4, pady=4)

    def _build_automations_tab(self) -> None:
        frame = ttk.Frame(self.nb, style="Card.TFrame")
        self.nb.add(frame, text="Automations")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_rowconfigure(3, weight=3)
        frame.grid_rowconfigure(4, weight=2)

        ttk.Label(
            frame,
            text="Automations // Launch nuclei-style exploit templates with curated rulesets.",
            style="Glitch.TLabel",
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=8, pady=(8, 2))

        ttk.Label(frame, text="Base URL:").grid(row=1, column=0, sticky="e", padx=8, pady=4)
        self.automation_base_url = tk.StringVar()
        self.automation_base_entry = ttk.Entry(frame, textvariable=self.automation_base_url, width=60)
        self.automation_base_entry.grid(row=1, column=1, sticky="we", padx=8, pady=4)

        controls = ttk.Frame(frame, style="Card.TFrame")
        controls.grid(row=2, column=0, columnspan=2, sticky="ew", padx=8, pady=(4, 6))
        controls.columnconfigure(6, weight=1)

        self.automation_run_button = ttk.Button(
            controls,
            text="Run Selected Templates",
            command=self._run_selected_automations,
        )
        self.automation_run_button.grid(row=0, column=0, padx=4, pady=4)

        self.automation_ruleset_var = tk.StringVar()
        self.automation_ruleset_combo = ttk.Combobox(
            controls,
            textvariable=self.automation_ruleset_var,
            state="readonly",
            width=26,
            values=sorted(self.automation_rulesets.keys()),
        )
        self.automation_ruleset_combo.grid(row=0, column=1, padx=4, pady=4)

        self.automation_ruleset_button = ttk.Button(
            controls,
            text="Run Ruleset",
            command=self._run_automation_ruleset,
        )
        self.automation_ruleset_button.grid(row=0, column=2, padx=4, pady=4)

        self.automation_save_ruleset_button = ttk.Button(
            controls,
            text="Save Selection as Ruleset",
            command=self._save_automation_ruleset,
        )
        self.automation_save_ruleset_button.grid(row=0, column=3, padx=4, pady=4)

        self.automation_load_button = ttk.Button(
            controls,
            text="Import Template File",
            command=self._import_automation_templates,
        )
        self.automation_load_button.grid(row=0, column=4, padx=4, pady=4)

        self.automation_new_button = ttk.Button(
            controls,
            text="Build New Template",
            command=self._open_template_builder,
        )
        self.automation_new_button.grid(row=0, column=5, padx=4, pady=4)

        template_container = ttk.Frame(frame, style="Card.TFrame")
        template_container.grid(row=3, column=0, sticky="nsew", padx=(8, 4), pady=6)
        template_container.grid_columnconfigure(0, weight=1)
        template_container.grid_rowconfigure(1, weight=1)
        ttk.Label(template_container, text="Template Catalog", style="Glitch.TLabel").grid(
            row=0, column=0, sticky="w", padx=6, pady=(6, 0)
        )
        template_columns = ("name", "severity", "target", "tags")
        self.automation_template_tree = ttk.Treeview(
            template_container,
            columns=template_columns,
            show="headings",
            selectmode="extended",
            height=14,
        )
        self.automation_template_tree.heading("name", text="TEMPLATE")
        self.automation_template_tree.heading("severity", text="SEVERITY")
        self.automation_template_tree.heading("target", text="TARGET")
        self.automation_template_tree.heading("tags", text="TAGS")
        self.automation_template_tree.column("name", width=200, anchor="w")
        self.automation_template_tree.column("severity", width=90, anchor="center")
        self.automation_template_tree.column("target", width=200, anchor="w")
        self.automation_template_tree.column("tags", width=140, anchor="w")
        self.automation_template_tree.grid(row=1, column=0, sticky="nsew", padx=6, pady=6)
        template_scroll = ttk.Scrollbar(template_container, orient="vertical", command=self.automation_template_tree.yview)
        template_scroll.grid(row=1, column=1, sticky="ns", pady=6)
        self.automation_template_tree.configure(yscrollcommand=template_scroll.set)

        results_container = ttk.Frame(frame, style="Card.TFrame")
        results_container.grid(row=3, column=1, sticky="nsew", padx=(4, 8), pady=6)
        results_container.grid_columnconfigure(0, weight=1)
        results_container.grid_rowconfigure(1, weight=1)
        ttk.Label(results_container, text="Automation Findings", style="Glitch.TLabel").grid(
            row=0, column=0, sticky="w", padx=6, pady=(6, 0)
        )
        results_columns = ("template", "severity", "status", "match", "evidence", "ms")
        self.automation_results_tree = ttk.Treeview(
            results_container,
            columns=results_columns,
            show="headings",
            height=14,
        )
        self.automation_results_tree.heading("template", text="TEMPLATE")
        self.automation_results_tree.heading("severity", text="SEVERITY")
        self.automation_results_tree.heading("status", text="STATUS")
        self.automation_results_tree.heading("match", text="MATCH")
        self.automation_results_tree.heading("evidence", text="EVIDENCE")
        self.automation_results_tree.heading("ms", text="TIME (MS)")
        self.automation_results_tree.column("template", width=200, anchor="w")
        self.automation_results_tree.column("severity", width=90, anchor="center")
        self.automation_results_tree.column("status", width=80, anchor="center")
        self.automation_results_tree.column("match", width=80, anchor="center")
        self.automation_results_tree.column("evidence", width=220, anchor="w")
        self.automation_results_tree.column("ms", width=90, anchor="center")
        self.automation_results_tree.grid(row=1, column=0, sticky="nsew", padx=6, pady=6)
        results_scroll = ttk.Scrollbar(results_container, orient="vertical", command=self.automation_results_tree.yview)
        results_scroll.grid(row=1, column=1, sticky="ns", pady=6)
        self.automation_results_tree.configure(yscrollcommand=results_scroll.set)
        self.automation_results_tree.tag_configure("hit", background="#0f172a", foreground="#facc15")
        self.automation_results_tree.tag_configure("miss", background="#111827", foreground="#94a3b8")
        self.automation_results_tree.tag_configure("error", background="#450a0a", foreground="#fca5a5")
        self.automation_results_tree.bind("<<TreeviewSelect>>", self._on_automation_result_select)

        self.automation_results_lookup: dict[str, dict[str, Any]] = {}

        self.automation_detail = ScrolledText(
            frame,
            height=8,
            bg="#0b1120",
            fg="#e2e8f0",
            insertbackground="#22d3ee",
            font=("Consolas", 10),
        )
        self.automation_detail.grid(row=4, column=0, columnspan=2, sticky="nsew", padx=8, pady=(0, 6))
        self.automation_detail.configure(state="disabled")

        status_frame = ttk.Frame(frame, style="Card.TFrame")
        status_frame.grid(row=5, column=0, columnspan=2, sticky="ew", padx=8, pady=(0, 8))
        self.automation_status_var = tk.StringVar(value="Automations idle.")
        ttk.Label(status_frame, textvariable=self.automation_status_var, style="StatusBadge.TLabel").pack(
            side="left", padx=6, pady=6
        )
        self.automation_progress = ttk.Progressbar(status_frame, mode="determinate", length=260)
        self.automation_progress.pack(side="right", padx=6, pady=6)

        self._update_automation_ruleset_combo()
        self._refresh_automation_template_tree()

    def _update_automation_ruleset_combo(self) -> None:
        if not hasattr(self, "automation_ruleset_combo"):
            return
        names = sorted(self.automation_rulesets.keys())
        self.automation_ruleset_combo.configure(values=names)
        if names:
            if self.automation_ruleset_var.get() not in names:
                self.automation_ruleset_var.set(names[0])
        else:
            self.automation_ruleset_var.set("")

    def _refresh_automation_template_tree(self) -> None:
        tree = getattr(self, "automation_template_tree", None)
        if not tree:
            return
        for child in tree.get_children():
            tree.delete(child)
        entries = sorted(
            self.automation_templates.values(),
            key=lambda item: (str(item.get("severity", "info")), item.get("name", "")),
        )
        for template in entries:
            identifier = template.get("id")
            target = template.get("url") or template.get("path") or "/"
            tags = ", ".join(template.get("tags", []))
            tree.insert(
                "",
                "end",
                iid=identifier,
                values=(
                    template.get("name", identifier),
                    str(template.get("severity", "info")).upper(),
                    target,
                    tags,
                ),
            )

    def _set_automation_controls_enabled(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        combo_state = "readonly" if enabled else "disabled"
        for widget in [
            self.automation_run_button,
            self.automation_ruleset_button,
            self.automation_save_ruleset_button,
            self.automation_load_button,
            self.automation_new_button,
        ]:
            try:
                widget.configure(state=state)
            except tk.TclError:
                continue
        try:
            self.automation_ruleset_combo.configure(state=combo_state)
        except tk.TclError:
            pass
        try:
            self.automation_base_entry.configure(state="normal" if enabled else "disabled")
        except tk.TclError:
            pass
        self.automation_template_tree.configure(selectmode="extended" if enabled else "none")

    def _reset_automation_results(self) -> None:
        for child in self.automation_results_tree.get_children():
            self.automation_results_tree.delete(child)
        self.automation_results_lookup.clear()
        self.automation_detail.configure(state="normal")
        self.automation_detail.delete("1.0", "end")
        self.automation_detail.configure(state="disabled")
        self.automation_progress.configure(value=0)

    def _selected_automation_templates(self) -> list[str]:
        selection = list(self.automation_template_tree.selection())
        return selection

    def _run_selected_automations(self) -> None:
        template_ids = self._selected_automation_templates()
        if not template_ids:
            messagebox.showinfo("Automations", "Select one or more templates to run.")
            return
        self._launch_automation_run(template_ids)

    def _run_automation_ruleset(self) -> None:
        name = self.automation_ruleset_var.get().strip()
        if not name:
            messagebox.showinfo("Automations", "Choose a ruleset to run.")
            return
        template_ids = self.automation_rulesets.get(name)
        if not template_ids:
            messagebox.showerror("Automations", f"Ruleset '{name}' has no templates.")
            return
        self._launch_automation_run(template_ids)

    def _launch_automation_run(self, template_ids: list[str]) -> None:
        base = self.automation_base_url.get().strip()
        if not base:
            messagebox.showerror("Automations", "Set a base URL for the automation run.")
            return
        templates = [self.automation_templates.get(tid) for tid in template_ids if tid in self.automation_templates]
        templates = [tpl for tpl in templates if tpl]
        if not templates:
            messagebox.showerror("Automations", "Selected templates could not be resolved.")
            return
        base_url = base if "://" in base else f"http://{base}"
        self._reset_automation_results()
        self._set_automation_controls_enabled(False)
        self.automation_status_var.set(f"Running {len(templates)} templates against {base_url}…")
        headers = self._compose_headers_from_settings()
        timeout = self.settings.data.get("timeout", 5)
        follow = self.settings.data.get("follow_redirects", True)
        engine = AutomationEngine(
            base_url,
            templates,
            timeout=timeout,
            follow_redirects=follow,
            base_headers=headers,
            proxies=self._current_proxies(),
            on_result=lambda info: self.after(0, lambda data=info: self._add_automation_result(data)),
            on_finish=lambda: self.after(0, self._automation_run_finished),
            on_status=lambda status: self.after(0, lambda text=status: self.automation_status_var.set(text)),
            on_progress=lambda pct: self.after(0, lambda value=pct: self.automation_progress.configure(value=value)),
        )
        self.automation_engine = engine
        engine.start()

    def _automation_run_finished(self) -> None:
        hits = sum(1 for info in self.automation_results_lookup.values() if info.get("matched"))
        total = len(self.automation_results_lookup)
        summary = f"Automations finished — {hits} hit(s) across {total} templates."
        if total == 0:
            summary = "Automations finished — no responses logged."
        self.automation_status_var.set(summary)
        self._set_automation_controls_enabled(True)
        self.automation_engine = None

    def _add_automation_result(self, info: dict[str, Any]) -> None:
        template_name = info.get("template_name") or info.get("template_id") or "Template"
        severity = str(info.get("severity", "info")).upper()
        status = info.get("status")
        matched = bool(info.get("matched"))
        error = info.get("error")
        evidence = ", ".join(info.get("evidence", [])) if info.get("evidence") else (error or "")
        elapsed = info.get("elapsed_ms")
        elapsed_display = f"{elapsed:.0f}" if isinstance(elapsed, (int, float)) else "-"
        match_label = "HIT" if matched else ("ERROR" if error else "MISS")
        tag = "hit" if matched else ("error" if error else "miss")
        item_id = self.automation_results_tree.insert(
            "",
            "end",
            values=(template_name, severity, status, match_label, evidence[:120], elapsed_display),
            tags=(tag,),
        )
        self.automation_results_lookup[item_id] = info
        if matched:
            self._log_console(f"[AUTO] {template_name} matched {info.get('url')}")
        elif error:
            self._log_console(f"[AUTO] {template_name} error: {error}")

    def _on_automation_result_select(self, _event=None) -> None:
        selection = self.automation_results_tree.selection()
        if not selection:
            return
        info = self.automation_results_lookup.get(selection[0])
        if not info:
            return
        lines = [
            f"Template: {info.get('template_name') or info.get('template_id')}",
            f"Severity: {info.get('severity', 'info')}",
            f"URL: {info.get('url')}",
            f"Status: {info.get('status')}",
            f"Match: {'yes' if info.get('matched') else 'no'}",
        ]
        tags = info.get("tags")
        if tags:
            lines.append("Tags: " + ", ".join(map(str, tags)))
        description = info.get("description")
        if description:
            lines.append("")
            lines.append(description)
        evidence = info.get("evidence") or []
        if evidence:
            lines.append("")
            lines.append("Evidence:")
            for item in evidence[:10]:
                lines.append(f"  • {item}")
        headers = info.get("headers") or {}
        if headers:
            lines.append("")
            lines.append("Response headers:")
            for key, value in list(headers.items())[:12]:
                lines.append(f"  {key}: {value}")
        preview = info.get("response_preview")
        if preview:
            lines.append("")
            lines.append("Preview:")
            lines.append(preview)
        self.automation_detail.configure(state="normal")
        self.automation_detail.delete("1.0", "end")
        self.automation_detail.insert("1.0", "\n".join(lines))
        self.automation_detail.configure(state="disabled")

    def _save_automation_ruleset(self) -> None:
        template_ids = self._selected_automation_templates()
        if not template_ids:
            messagebox.showinfo("Automations", "Select at least one template before saving a ruleset.")
            return
        name = simpledialog.askstring("Ruleset Name", "Name your ruleset")
        if not name:
            return
        sanitized = name.strip()
        if not sanitized:
            messagebox.showerror("Automations", "Ruleset name cannot be blank.")
            return
        self.automation_rulesets[sanitized] = template_ids
        self._persist_automation_library()
        self._update_automation_ruleset_combo()
        self.automation_status_var.set(f"Ruleset '{sanitized}' saved.")

    def _import_automation_templates(self) -> None:
        path = filedialog.askopenfilename(
            title="Import automation templates",
            filetypes=[("JSON", "*.json"), ("All", "*.*")],
        )
        if not path:
            return
        templates = _load_automation_templates_from_disk(Path(path))
        if not templates:
            messagebox.showerror("Automations", "No templates found in the selected file.")
            return
        added = 0
        for entry in templates:
            if not isinstance(entry, dict):
                continue
            identifier = str(entry.get("id") or self._sanitize_wordlist_name(entry.get("name", "template")))
            entry = dict(entry)
            entry["id"] = identifier
            existing = next(
                (idx for idx, item in enumerate(self.automation_custom_templates) if item.get("id") == identifier),
                None,
            )
            if existing is not None:
                self.automation_custom_templates[existing] = entry
            else:
                self.automation_custom_templates.append(entry)
            self.automation_templates[identifier] = entry
            added += 1
        if added:
            self._persist_automation_library()
            self._refresh_automation_template_tree()
            messagebox.showinfo("Automations", f"Imported {added} template(s).")
        else:
            messagebox.showinfo("Automations", "Templates already existed — nothing new imported.")

    def _open_template_builder(self) -> None:
        builder = tk.Toplevel(self)
        builder.title("Automation Template Builder")
        builder.configure(bg="#020617")
        builder.transient(self)
        builder.grab_set()

        container = ttk.Frame(builder, padding=10)
        container.pack(fill="both", expand=True)
        for idx in range(2):
            container.grid_columnconfigure(idx, weight=1 if idx == 1 else 0)

        ttk.Label(container, text="Template Name:").grid(row=0, column=0, sticky="e", padx=4, pady=4)
        name_var = tk.StringVar()
        ttk.Entry(container, textvariable=name_var, width=40).grid(row=0, column=1, sticky="we", padx=4, pady=4)

        ttk.Label(container, text="Relative Path:").grid(row=1, column=0, sticky="e", padx=4, pady=4)
        path_var = tk.StringVar()
        ttk.Entry(container, textvariable=path_var, width=40).grid(row=1, column=1, sticky="we", padx=4, pady=4)

        ttk.Label(container, text="Full URL (optional):").grid(row=2, column=0, sticky="e", padx=4, pady=4)
        url_var = tk.StringVar()
        ttk.Entry(container, textvariable=url_var, width=40).grid(row=2, column=1, sticky="we", padx=4, pady=4)

        ttk.Label(container, text="HTTP Method:").grid(row=3, column=0, sticky="e", padx=4, pady=4)
        method_var = tk.StringVar(value="GET")
        ttk.Combobox(container, textvariable=method_var, values=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"], state="readonly").grid(
            row=3, column=1, sticky="w", padx=4, pady=4
        )

        ttk.Label(container, text="Severity:").grid(row=4, column=0, sticky="e", padx=4, pady=4)
        severity_var = tk.StringVar(value="medium")
        ttk.Combobox(container, textvariable=severity_var, values=["info", "low", "medium", "high", "critical"], state="readonly").grid(
            row=4, column=1, sticky="w", padx=4, pady=4
        )

        ttk.Label(container, text="Status codes (comma separated):").grid(row=5, column=0, sticky="e", padx=4, pady=4)
        status_var = tk.StringVar(value="200")
        ttk.Entry(container, textvariable=status_var, width=40).grid(row=5, column=1, sticky="we", padx=4, pady=4)

        ttk.Label(container, text="Body contains (comma/newline separated):").grid(row=6, column=0, sticky="e", padx=4, pady=4)
        contains_text = ScrolledText(container, height=3, width=40)
        contains_text.grid(row=6, column=1, sticky="we", padx=4, pady=4)

        ttk.Label(container, text="Body regex (comma/newline separated):").grid(row=7, column=0, sticky="e", padx=4, pady=4)
        regex_text = ScrolledText(container, height=3, width=40)
        regex_text.grid(row=7, column=1, sticky="we", padx=4, pady=4)

        ttk.Label(container, text="Negative contains (optional):").grid(row=8, column=0, sticky="e", padx=4, pady=4)
        negative_text = ScrolledText(container, height=2, width=40)
        negative_text.grid(row=8, column=1, sticky="we", padx=4, pady=4)

        ttk.Label(container, text="Header matchers (Header: value substring)").grid(row=9, column=0, sticky="e", padx=4, pady=4)
        header_match_text = ScrolledText(container, height=3, width=40)
        header_match_text.grid(row=9, column=1, sticky="we", padx=4, pady=4)

        ttk.Label(container, text="Request headers (Header: value)").grid(row=10, column=0, sticky="e", padx=4, pady=4)
        headers_text = ScrolledText(container, height=3, width=40)
        headers_text.grid(row=10, column=1, sticky="we", padx=4, pady=4)

        ttk.Label(container, text="Request body (optional)").grid(row=11, column=0, sticky="e", padx=4, pady=4)
        body_text = ScrolledText(container, height=4, width=40)
        body_text.grid(row=11, column=1, sticky="we", padx=4, pady=4)

        ttk.Label(container, text="Tags (comma separated)").grid(row=12, column=0, sticky="e", padx=4, pady=4)
        tags_var = tk.StringVar()
        ttk.Entry(container, textvariable=tags_var, width=40).grid(row=12, column=1, sticky="we", padx=4, pady=4)

        ttk.Label(container, text="Description").grid(row=13, column=0, sticky="ne", padx=4, pady=4)
        description_text = ScrolledText(container, height=4, width=40)
        description_text.grid(row=13, column=1, sticky="we", padx=4, pady=4)

        def parse_list(text_value: str) -> list[str]:
            items = []
            for token in re.split(r"[,\n]", text_value or ""):
                token = token.strip()
                if token:
                    items.append(token)
            return items

        def parse_status_list(value: str) -> list[int]:
            codes: list[int] = []
            for token in re.split(r"[,\s]", value or ""):
                token = token.strip()
                if not token:
                    continue
                try:
                    codes.append(int(token))
                except ValueError:
                    continue
            return codes

        def parse_header_expectations(raw: str) -> dict[str, Any]:
            expectations: dict[str, Any] = {}
            for line in raw.splitlines():
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                key = key.strip()
                value = value.strip()
                if key:
                    expectations[key] = value
            return expectations

        def save_template():
            name = name_var.get().strip()
            if not name:
                messagebox.showerror("Automations", "Template name is required.")
                return
            path_value = path_var.get().strip()
            url_value = url_var.get().strip()
            if not path_value and not url_value:
                messagebox.showerror("Automations", "Provide a relative path or full URL.")
                return
            template_id = self._sanitize_wordlist_name(name)
            if not template_id:
                template_id = f"template-{int(time.time())}"
            matchers: dict[str, Any] = {}
            statuses = parse_status_list(status_var.get())
            if statuses:
                matchers["status"] = statuses
            contains = parse_list(contains_text.get("1.0", "end"))
            if contains:
                matchers["contains"] = contains
            regex_rules = parse_list(regex_text.get("1.0", "end"))
            if regex_rules:
                matchers["regex"] = regex_rules
            negative_rules = parse_list(negative_text.get("1.0", "end"))
            if negative_rules:
                matchers["negative_contains"] = negative_rules
            header_expect = parse_header_expectations(header_match_text.get("1.0", "end"))
            if header_expect:
                matchers["headers"] = header_expect
            headers = self._parse_headers_text(headers_text.get("1.0", "end"))
            body_value = body_text.get("1.0", "end").strip()
            tags_value = [tag.strip() for tag in tags_var.get().split(",") if tag.strip()]
            template = {
                "id": template_id,
                "name": name,
                "description": description_text.get("1.0", "end").strip(),
                "severity": severity_var.get().strip() or "info",
                "method": method_var.get().strip().upper() or "GET",
                "matchers": matchers,
            }
            if path_value:
                template["path"] = path_value
            if url_value:
                template["url"] = url_value
            if headers:
                template["headers"] = headers
            if body_value:
                template["body"] = body_value
            if tags_value:
                template["tags"] = tags_value
            existing = next(
                (idx for idx, item in enumerate(self.automation_custom_templates) if item.get("id") == template_id),
                None,
            )
            if existing is not None:
                self.automation_custom_templates[existing] = template
            else:
                self.automation_custom_templates.append(template)
            self.automation_templates[template_id] = template
            self._persist_automation_library()
            self._refresh_automation_template_tree()
            self.automation_status_var.set(f"Template '{name}' saved.")
            builder.destroy()

        button_row = ttk.Frame(container)
        button_row.grid(row=14, column=0, columnspan=2, sticky="e", padx=4, pady=10)
        ttk.Button(button_row, text="Cancel", command=builder.destroy).pack(side="right", padx=4)
        ttk.Button(button_row, text="Save Template", command=save_template).pack(side="right", padx=4)

    def _browse_generic_wordlist(self, variable: tk.StringVar) -> None:
        path = filedialog.askopenfilename(
            title="Choose wordlist",
            filetypes=[("Wordlists", "*.txt"), ("All files", "*.*")],
        )
        if path:
            variable.set(path)

    def _start_api_endpoint_explorer(self) -> None:
        base = self.endpoint_url.get().strip()
        if not base:
            messagebox.showerror("API Explorer", "Provide a base URL to explore.")
            return
        wordlist_path = self.endpoint_wordlist.get().strip()
        if not wordlist_path or not os.path.isfile(wordlist_path):
            fallback = self._ensure_wordlist("HackXpert Essentials (custom)")
            if fallback:
                wordlist_path = str(fallback)
                self.endpoint_wordlist.set(wordlist_path)
                if hasattr(self, "endpoint_wordlist_choice"):
                    self.endpoint_wordlist_choice.set("HackXpert Essentials (custom)")
            else:
                messagebox.showerror("API Explorer", "Select or download a valid wordlist first.")
                return
        prepared = self._materialise_wordlist(
            wordlist_path,
            include_custom=self.endpoint_use_custom.get(),
            flavour="api-explorer",
        )
        if not prepared or not os.path.isfile(prepared):
            messagebox.showerror("API Explorer", "Unable to prepare the endpoint wordlist.")
            return
        wordlist_path = prepared
        if self.endpoint_use_custom.get():
            self.api_status_var.set(
                f"Reconning {base} — stacking HackXpert essentials with the selected catalog…"
            )
        else:
            self.api_status_var.set(f"Reconning {base} — hunting specifications and endpoints…")
        for node in (self.api_specs_node, self.api_endpoints_node):
            for child in self.api_tree.get_children(node):
                self.api_tree.delete(child)
        self.api_tree_results.clear()
        thread = threading.Thread(
            target=self._run_api_endpoint_explorer,
            args=(base, wordlist_path),
            daemon=True,
        )
        thread.start()

    def _run_api_endpoint_explorer(self, base_url: str, wordlist_path: str) -> None:
        parsed = urllib.parse.urlparse(base_url)
        if not parsed.scheme:
            base_url = f"http://{base_url}"
        headers = self._compose_headers_from_settings()
        self._log_console(f"[*] API explorer scanning {base_url}")
        specs = [
            "/openapi.json",
            "/swagger.json",
            "/swagger/v1/swagger.json",
            "/v3/api-docs",
            "/api-docs",
            "/docs",
            "/redoc",
        ]
        timeout = self.settings.data.get("timeout", 5)
        spec_hits = 0
        for path in specs:
            target = urllib.parse.urljoin(f"{base_url.rstrip('/')}/", path.lstrip("/"))
            try:
                response = requests.get(
                    target,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=True,
                    proxies=self._current_proxies(),
                )
                length = len(response.content)
                info = {
                    "url": target,
                    "method": "GET",
                    "status": response.status_code,
                    "detail": f"{length} bytes",
                    "label": path,
                    "headers": dict(response.headers),
                    "body": response.text if length < 50_000 else response.content[:2000].decode("utf-8", "ignore"),
                }
                if response.status_code < 400:
                    spec_hits += 1
                    self._log_console(f"[+] Spec hit {path} -> {response.status_code}")
                self.after(0, lambda data=info: self._insert_api_result(self.api_specs_node, data))
            except Exception as exc:
                note = {
                    "url": target,
                    "method": "GET",
                    "status": "ERR",
                    "detail": str(exc),
                    "label": path,
                    "headers": headers,
                    "body": "",
                }
                self.after(0, lambda data=note: self._insert_api_result(self.api_specs_node, data))

        if spec_hits == 0:
            self.after(0, lambda: self.api_status_var.set("No live specs detected — brute forcing endpoints."))
        else:
            self.after(0, lambda: self.api_status_var.set(f"Captured {spec_hits} spec artefacts — sweeping endpoints next."))

        def on_found(info):
            self.after(0, lambda data=info: self._insert_api_result(self.api_endpoints_node, data))

        def on_finish():
            self.after(0, lambda: self.api_status_var.set("API endpoint sweep complete."))

        def on_progress(pct):
            self.after(0, lambda: self.progress.configure(value=pct))

        forcer = DirBruteForcer(base_url, wordlist_path, self.settings, on_found=on_found, on_finish=on_finish, on_progress=on_progress)
        self.api_forcer = forcer
        forcer.start()

    def _insert_api_result(self, parent, info):
        label = info.get("label") or info.get("url", "")
        status = info.get("status", "-")
        detail = info.get("detail") or info.get("notes") or info.get("type", "")
        item = self.api_tree.insert(parent, "end", text=label, values=(status, detail))
        enriched = dict(info)
        enriched.setdefault("headers", self._compose_headers_from_settings())
        self.api_tree_results[item] = enriched
        self.api_tree.see(item)
        if isinstance(status, int):
            self.api_status_var.set(f"Hit {label} — status {status}")

    def _on_api_tree_double(self, _event):
        selection = self.api_tree.selection()
        if not selection:
            return
        info = self.api_tree_results.get(selection[0])
        if not info:
            return
        self._open_request_workbench(info)

    def _open_request_workbench(self, info):
        tab = ttk.Frame(self.nb, style="Card.TFrame")
        title = info.get("url", "Request")
        short = urllib.parse.urlparse(title).path or title
        self.nb.add(tab, text=f"Request ▶ {short[-16:]}" if short else "Request")
        self.nb.select(tab)

        method_var = tk.StringVar(value=info.get("method", "GET"))
        url_var = tk.StringVar(value=info.get("url", ""))
        params = info.get("params")
        headers_text = "\n".join(f"{k}: {v}" for k, v in (info.get("headers") or {}).items())
        body_seed = info.get("body") or info.get("preview") or ""

        top_row = ttk.Frame(tab, style="Card.TFrame")
        top_row.pack(fill="x", padx=10, pady=8)
        ttk.Label(top_row, text="Method:").pack(side="left")
        method_box = ttk.Combobox(top_row, textvariable=method_var, values=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"], width=10, state="readonly")
        method_box.pack(side="left", padx=4)
        ttk.Label(top_row, text="URL:").pack(side="left", padx=(12, 2))
        url_entry = ttk.Entry(top_row, textvariable=url_var, width=70)
        url_entry.pack(side="left", fill="x", expand=True)

        button_row = ttk.Frame(tab, style="Card.TFrame")
        button_row.pack(fill="x", padx=10)

        headers_label = ttk.Label(button_row, text="Headers")
        headers_label.pack(anchor="w")
        headers_box = ScrolledText(tab, height=8, bg="#0b1120", fg="#e2e8f0", insertbackground="#22d3ee")
        headers_box.pack(fill="x", padx=10, pady=(0, 6))
        if headers_text:
            headers_box.insert("1.0", headers_text)

        ttk.Label(tab, text="Body").pack(anchor="w", padx=10)
        body_box = ScrolledText(tab, height=8, bg="#0b1120", fg="#e2e8f0", insertbackground="#22d3ee")
        body_box.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        if body_seed:
            body_box.insert("1.0", body_seed)

        response_label = ttk.Label(tab, text="Response")
        response_label.pack(anchor="w", padx=10)
        response_box = ScrolledText(tab, height=14, bg="#030712", fg="#38bdf8", insertbackground="#22d3ee")
        response_box.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        response_box.configure(state="disabled")

        def send_request():
            method = method_var.get().strip().upper() or "GET"
            target_url = url_var.get().strip()
            if not target_url:
                messagebox.showerror("Request", "Set a target URL first.")
                return
            header_data = self._parse_headers_text(headers_box.get("1.0", "end"))
            merged_headers = self._compose_headers_from_settings()
            merged_headers.update(header_data)
            body = body_box.get("1.0", "end").strip()
            use_body = body if method in {"POST", "PUT", "PATCH", "DELETE"} else None
            query_params = dict(params or {})
            timeout = self.settings.data.get("timeout", 5)
            try:
                response = requests.request(
                    method,
                    target_url,
                    params=query_params if query_params else None,
                    data=use_body,
                    headers=merged_headers,
                    timeout=timeout,
                    allow_redirects=self.settings.data.get("follow_redirects", True),
                    proxies=self._current_proxies(),
                )
            except Exception as exc:
                messagebox.showerror("Request", f"Request failed: {exc}")
                return
            display = [
                f"Status: {response.status_code}",
                f"URL: {response.url}",
                "Headers:",
            ]
            for key, value in response.headers.items():
                display.append(f"  {key}: {value}")
            display.append("\nBody:\n")
            try:
                text = response.text
            except Exception:
                text = response.content.decode("utf-8", "ignore")
            display.append(text)
            response_box.configure(state="normal")
            response_box.delete("1.0", "end")
            response_box.insert("end", "\n".join(display))
            response_box.configure(state="disabled")

        ttk.Button(button_row, text="Send Request", command=send_request).pack(side="left", padx=4, pady=4)
        ttk.Button(button_row, text="Send to Parameter Explorer", command=lambda: self._send_to_parameter_explorer({
            "url": url_var.get(),
            "method": method_var.get(),
            "headers": self._parse_headers_text(headers_box.get("1.0", "end")),
            "body": body_box.get("1.0", "end").strip(),
        })).pack(side="left", padx=4, pady=4)

    def _parse_headers_text(self, text: str) -> dict[str, str]:
        headers = {}
        for line in text.splitlines():
            if not line.strip() or ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()
        return headers

    def _on_parameter_double(self, _event):
        selection = self.param_tree.selection()
        if not selection:
            return
        info = self.parameter_results.get(selection[0])
        if not info:
            return
        self._open_request_workbench(info)

    def _start_parameter_explorer(self):
        target = self.param_url.get().strip()
        if not target:
            messagebox.showerror("Parameter Explorer", "Provide a request URL to fuzz.")
            return
        method = self.param_method.get().strip().upper() or "GET"
        wordlist_name = self.param_wordlist.get()
        payloads = self._resolve_parameter_payloads(wordlist_name, self.param_use_custom.get())
        if not payloads:
            messagebox.showerror("Parameter Explorer", "Select a valid parameter wordlist.")
            return
        headers = self._compose_headers_from_settings()
        headers.update(self._parse_headers_text(self.param_headers.get("1.0", "end")))
        body = self.param_body.get("1.0", "end").strip()
        for child in self.param_tree.get_children():
            self.param_tree.delete(child)
        self.parameter_results.clear()
        if self.param_use_custom.get():
            self.param_status_var.set(
                f"Fuzzing {len(payloads)} parameters against {target} — HackXpert custom list stacked with {wordlist_name}."
            )
        else:
            self.param_status_var.set(f"Fuzzing {len(payloads)} parameters against {target}…")
        self._log_console(f"[*] Parameter fuzzing {len(payloads)} payloads against {target}")
        thread = threading.Thread(
            target=self._run_parameter_fuzzer,
            args=(target, method, payloads, headers, body),
            daemon=True,
        )
        thread.start()

    def _run_parameter_fuzzer(self, url: str, method: str, payloads: list[str], headers: dict[str, str], body: str) -> None:
        parsed = urllib.parse.urlsplit(url)
        if not parsed.scheme:
            url = f"http://{url}"
            parsed = urllib.parse.urlsplit(url)
        base_params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        base_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", parsed.fragment))
        timeout = self.settings.data.get("timeout", 5)
        redirect_flag = self.settings.data.get("follow_redirects", True)
        baseline_status = None
        baseline_length = None
        use_body = body if method in {"POST", "PUT", "PATCH", "DELETE"} and body else None
        try:
            baseline_resp = requests.request(
                method,
                base_url,
                params=base_params if base_params else None,
                data=use_body,
                headers=headers,
                timeout=timeout,
                allow_redirects=redirect_flag,
                proxies=self._current_proxies(),
            )
            baseline_status = baseline_resp.status_code
            baseline_length = len(baseline_resp.content)
        except Exception as exc:
            self.after(0, lambda: self.param_status_var.set(f"Baseline request failed: {exc}"))

        for name in payloads:
            params = dict(base_params)
            params[name] = "FUZZ"
            try:
                response = requests.request(
                    method,
                    base_url,
                    params=params,
                    data=use_body,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=redirect_flag,
                    proxies=self._current_proxies(),
                )
                status = response.status_code
                length = len(response.content)
                delta_status = ""
                if baseline_status is not None and status != baseline_status:
                    delta_status = f"Status drift {baseline_status}->{status}"
                delta_length = ""
                if baseline_length is not None:
                    diff = length - baseline_length
                    if diff:
                        delta_length = f"Length Δ{diff:+}"
                delta = ", ".join(filter(None, [delta_status, delta_length])) or "No change"
                length_display = f"{length} bytes"
                info = {
                    "url": base_url,
                    "method": method,
                    "status": status,
                    "detail": delta,
                    "label": f"?{name}=FUZZ",
                    "headers": headers,
                    "params": params,
                    "body": use_body or "",
                }
                self.after(
                    0,
                    lambda data=info, length_display=length_display, delta=delta, status=status: self._add_parameter_result(
                        data, status, delta, length_display
                    ),
                )
                self.after(0, lambda param=name, code=status: self.param_status_var.set(f"{param} → {code}"))
            except Exception as exc:
                info = {
                    "url": base_url,
                    "method": method,
                    "status": "ERR",
                    "detail": str(exc),
                    "label": f"?{name}=FUZZ",
                    "headers": headers,
                    "params": params,
                    "body": use_body or "",
                }
                self.after(0, lambda data=info: self._add_parameter_result(data, "ERR", str(exc), "-"))
                self.after(0, lambda param=name, err=exc: self.param_status_var.set(f"{param} failed: {err}"))

        self.after(0, lambda: self.param_status_var.set("Parameter fuzzing complete."))

    def _add_parameter_result(self, info, status, delta, length_display):
        item = self.param_tree.insert("", "end", values=(info.get("label", ""), status, delta, length_display))
        self.parameter_results[item] = info
        self.param_tree.see(item)

    def _send_to_parameter_explorer(self, info):
        self.nb.select(self.parameter_frame)
        if info.get("url"):
            self.param_url.set(info["url"])
        method = info.get("method")
        if method:
            method_upper = method.upper()
            existing = list(self.param_method_combo["values"])
            if method_upper not in existing:
                existing.append(method_upper)
                self.param_method_combo.configure(values=existing)
            self.param_method.set(method_upper)
        headers_text = "\n".join(f"{k}: {v}" for k, v in (info.get("headers") or {}).items())
        self.param_headers.delete("1.0", "end")
        if headers_text:
            self.param_headers.insert("1.0", headers_text)
        body = info.get("body") or info.get("preview") or ""
        self.param_body.delete("1.0", "end")
        if body:
            self.param_body.insert("1.0", body)
        self.param_status_var.set("Loaded request from recon — ready to fuzz parameters.")

    def _build_settings_tab(self):
        frame = ttk.Frame(self.nb, style="Card.TFrame")
        self.nb.add(frame, text="Settings")

        frame.grid_columnconfigure(1, weight=1)

        options = [
            ("Threads", "threads"),
            ("Timeout", "timeout"),
            ("User Agent", "user_agent"),
            ("Depth", "recursion_depth"),
            ("Status Filter", "include_status_codes"),
            ("Extensions", "file_extensions"),
            ("HTTP Methods", "http_methods"),
            ("Delay Jitter (s)", "delay_jitter"),
        ]
        self._setting_vars = {}
        for idx, (label, key) in enumerate(options):
            ttk.Label(frame, text=f"{label}:").grid(row=idx, column=0, sticky="w", padx=5, pady=5)
            var = tk.StringVar(value=str(self.settings.data.get(key, Settings.DEFAULTS.get(key, ""))))
            self._setting_vars[key] = var
            ttk.Entry(frame, textvariable=var, width=30).grid(row=idx, column=1, padx=5, pady=5, sticky="w")

        row_offset = len(options)

        self.follow_redirects = tk.BooleanVar(value=bool(self.settings.data.get("follow_redirects", True)))
        ttk.Checkbutton(frame, text="Follow Redirects", variable=self.follow_redirects).grid(
            row=row_offset, column=1, sticky="w", padx=5, pady=5
        )

        self.enable_preflight = tk.BooleanVar(value=bool(self.settings.data.get("enable_preflight", True)))
        ttk.Checkbutton(frame, text="Run intel preflight", variable=self.enable_preflight).grid(
            row=row_offset + 1, column=1, sticky="w", padx=5, pady=5
        )

        self.probe_cors = tk.BooleanVar(value=bool(self.settings.data.get("probe_cors", True)))
        ttk.Checkbutton(frame, text="Probe permissive CORS", variable=self.probe_cors).grid(
            row=row_offset + 2, column=1, sticky="w", padx=5, pady=5
        )

        self.burp_enabled = tk.BooleanVar(value=bool(self.settings.data.get("burp_proxy_enabled", False)))
        ttk.Checkbutton(
            frame,
            text="Route traffic through Burp Suite",
            variable=self.burp_enabled,
        ).grid(row=row_offset + 3, column=1, sticky="w", padx=5, pady=5)

        ttk.Label(frame, text="Burp host:").grid(row=row_offset + 4, column=0, sticky="w", padx=5, pady=2)
        self.burp_host_var = tk.StringVar(value=str(self.settings.data.get("burp_proxy_host", "127.0.0.1")))
        ttk.Entry(frame, textvariable=self.burp_host_var, width=24).grid(row=row_offset + 4, column=1, sticky="w", padx=5, pady=2)
        ttk.Label(frame, text="Burp port:").grid(row=row_offset + 5, column=0, sticky="w", padx=5, pady=2)
        self.burp_port_var = tk.StringVar(value=str(self.settings.data.get("burp_proxy_port", 8080)))
        ttk.Entry(frame, textvariable=self.burp_port_var, width=12).grid(row=row_offset + 5, column=1, sticky="w", padx=5, pady=2)

        ttk.Label(frame, text="Custom Headers (Header: value)").grid(
            row=row_offset + 6, column=0, columnspan=2, sticky="w", padx=5
        )
        self._headers_text = ScrolledText(frame, height=4, width=40)
        self._headers_text.grid(row=row_offset + 7, column=0, columnspan=2, padx=5, pady=5, sticky="we")
        self._headers_text.insert("1.0", str(self.settings.data.get("extra_headers", "")))

        ttk.Label(frame, text="Intel Paths (comma or newline separated)").grid(
            row=row_offset + 8, column=0, columnspan=2, sticky="w", padx=5
        )
        self._intel_text = ScrolledText(frame, height=3, width=40)
        self._intel_text.grid(row=row_offset + 9, column=0, columnspan=2, padx=5, pady=5, sticky="we")
        self._intel_text.insert("1.0", str(self.settings.data.get("intel_paths", "")))

        ttk.Button(frame, text="Save", command=self._save_settings).grid(
            row=row_offset + 10, column=1, pady=10, sticky="e"
        )

    def _browse_wordlist(self):
        path = filedialog.askopenfilename(filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if path:
            self.wordlist_path.set(path)

    def _new_scan(self):
        url = self.url.get().strip()
        if not url:
            messagebox.showerror("Scan Error", "Provide a valid API base URL.")
            return
        wordlist = self.wordlist_path.get().strip()
        if not wordlist or not os.path.isfile(wordlist):
            fallback = self._ensure_wordlist("HackXpert Essentials (custom)")
            if fallback:
                wordlist = str(fallback)
                self.wordlist_path.set(wordlist)
                if hasattr(self, "scan_wordlist_choice"):
                    self.scan_wordlist_choice.set("HackXpert Essentials (custom)")
            else:
                messagebox.showerror("Scan Error", "Provide a valid wordlist file.")
                return
        prepared_wordlist = self._materialise_wordlist(
            wordlist,
            include_custom=self.scan_use_custom_wordlist.get(),
            flavour="recon",
        )
        if not prepared_wordlist or not os.path.isfile(prepared_wordlist):
            messagebox.showerror("Scan Error", "Unable to prepare the selected wordlist.")
            return
        wordlist = prepared_wordlist

        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme:
            url = f"http://{url}"

        self._apply_setting_values()
        self.latest_certificate = None
        for var in self.certificate_vars.values():
            var.set("-")
        wordlist_name = os.path.basename(wordlist)
        self._log_console(f"[*] Launching recon on {url} using {wordlist_name}")

        if self.scan_use_custom_wordlist.get():
            self.status_var.set(f"Deploying recon on {url} with HackXpert custom blend…")
        else:
            self.status_var.set(f"Deploying recon on {url}…")
        for key in self.hud_metrics:
            self.hud_metrics[key].set("0")

        self.scan_count += 1
        scan_id = self.scan_count

        tab = ttk.Frame(self.nb, style="Card.TFrame")
        self.nb.add(tab, text=f"Scan #{scan_id}")
        self.nb.select(tab)

        columns = ("url", "method", "status", "delta", "latency", "type", "length", "notes")
        tree = ttk.Treeview(
            tab,
            columns=columns,
            show="headings",
            displaycolumns=("url", "method", "status", "delta", "latency", "type"),
            height=12,
        )
        tree.heading("url", text="URL")
        tree.heading("method", text="METHOD")
        tree.heading("status", text="STATUS")
        tree.heading("delta", text="DRIFT")
        tree.heading("latency", text="LATENCY")
        tree.heading("type", text="TYPE")
        tree.column("url", width=320, anchor="w")
        tree.column("method", width=90, anchor="center")
        tree.column("status", width=90, anchor="center")
        tree.column("delta", width=140, anchor="center")
        tree.column("latency", width=110, anchor="center")
        tree.column("type", width=220, anchor="w")
        tree.column("length", width=0, stretch=False)
        tree.column("notes", width=0, stretch=False)
        tree.pack(fill="both", expand=True, padx=10, pady=10)

        tree.tag_configure("success", background="#064e3b", foreground="#22d3ee")
        tree.tag_configure("redirect", background="#7c2d12", foreground="#fbbf24")
        tree.tag_configure("client", background="#1f2937", foreground="#f87171")
        tree.tag_configure("server", background="#450a0a", foreground="#f87171")
        tree.tag_configure("cors", background="#7c3aed", foreground="#fde68a")
        tree.tag_configure("intel", background="#1e3a8a", foreground="#f8fafc")
        tree.tag_configure("secret", background="#831843", foreground="#fdf2f8")
        tree.tag_configure("slow", background="#1f2937", foreground="#fde047")
        tree.tag_configure("delta-new", background="#0f172a", foreground="#facc15")
        tree.tag_configure("delta-changed", background="#0f172a", foreground="#c084fc")

        detail = ScrolledText(tab, height=10, font=("Consolas", 10), bg="#111827", fg="#e2e8f0", insertbackground="#22d3ee")
        detail.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        detail.configure(state="disabled")

        btn_frame = ttk.Frame(tab, style="Card.TFrame")
        btn_frame.pack(fill="x", padx=10, pady=5)
        ttk.Button(
            btn_frame,
            text="Export CSV",
            command=lambda t=tree, r=results: self._export_csv(t, r),
        ).pack(side="left", padx=5)
        ttk.Button(
            btn_frame,
            text="Export JSON",
            command=lambda t=tree, r=results: self._export_json(t, r),
        ).pack(side="left", padx=5)
        ttk.Button(
            btn_frame,
            text="Copy URL",
            command=lambda t=tree: self._copy_selected(t),
        ).pack(side="left", padx=5)
        ttk.Button(
            btn_frame,
            text="Export Forensics Map",
            command=lambda sid=scan_id: self._export_forensics_map_for_scan(sid),
        ).pack(side="left", padx=5)

        results = {}
        metrics = {
            "total": 0,
            "success": 0,
            "alerts": 0,
            "secrets": 0,
            "slow": 0,
            "drift": 0,
            "drift_new": 0,
            "drift_changed": 0,
        }
        self._attach_tree_context_menu(tree, lambda iid: results.get(iid))

        def refresh_hud():
            for key in ["total", "success", "alerts", "secrets", "slow", "drift"]:
                self.hud_metrics[key].set(str(metrics[key]))

        def render_info(info):
            status = info["status"]
            if 200 <= status < 300:
                tag = "success"
            elif 300 <= status < 400:
                tag = "redirect"
            elif 400 <= status < 500:
                tag = "client"
            else:
                tag = "server"

            tags = [tag]
            if info.get("cors"):
                tags.append("cors")
            if info.get("signals"):
                tags.append("intel")
            if info.get("secrets"):
                tags.append("secret")
            if info.get("slow"):
                tags.append("slow")
            delta_label = info.get("delta")
            if delta_label == "NEW":
                tags.append("delta-new")
            elif isinstance(delta_label, str) and delta_label.startswith("CHANGED"):
                tags.append("delta-changed")
            latency_display = "-"
            if info.get("latency") is not None:
                latency_display = f"{info['latency']:.0f} ms"
            item_id = tree.insert(
                "",
                "end",
                values=(
                    info["url"],
                    info["method"],
                    info["status"],
                    info.get("delta", "-"),
                    latency_display,
                    info["type"],
                    info["length"],
                    info.get("notes", ""),
                ),
                tags=tuple(tags),
            )
            results[item_id] = info
            metrics["total"] += 1
            if 200 <= status < 300:
                metrics["success"] += 1
            if info.get("signals"):
                metrics["alerts"] += len(info["signals"])
            status_message = None
            if info.get("secrets"):
                metrics["secrets"] += info.get("secrets", 0)
                status_message = "Secret material detected! Review intel panel."
            if info.get("slow"):
                metrics["slow"] += 1
            if delta_label == "NEW":
                metrics["drift"] += 1
                metrics["drift_new"] += 1
                status_message = status_message or f"Surface drift: NEW endpoint {info['url']}"
            elif isinstance(delta_label, str) and delta_label.startswith("CHANGED"):
                metrics["drift"] += 1
                metrics["drift_changed"] += 1
                status_message = status_message or f"Surface drift: {delta_label} @ {info['url']}"
            if status_message is None:
                status_message = f"Latest hit: {info['url']} ({info['status']})"
            self.status_var.set(status_message)
            if (
                info.get("secrets")
                or delta_label == "NEW"
                or (isinstance(delta_label, str) and delta_label.startswith("CHANGED"))
                or info.get("signals")
            ):
                self._log_console(status_message)
            refresh_hud()
            if len(results) == 1:
                tree.selection_set(item_id)
                update_detail(item_id)

        def update_detail(item_id):
            info = results.get(item_id)
            if not info:
                return
            detail.configure(state="normal")
            detail.delete("1.0", "end")
            sections = [
                f"URL: {info['url']}",
                f"Method: {info['method']}",
                f"Status: {info['status']}",
                f"Baseline Delta: {info.get('delta', '-')}",
                f"Type: {info['type']}",
                f"Length: {info['length']} bytes",
            ]
            if info.get("previous_status") is not None:
                sections.append(f"Baseline Status: {info['previous_status']}")
            if info.get("latency") is not None:
                sections.append(f"Latency: {info['latency']:.1f} ms")
            detail.insert("end", "\n".join(sections) + "\n\n")
            if info.get("signals"):
                detail.insert("end", "Intel Signals:\n")
                for note in info["signals"]:
                    detail.insert("end", f"  • {note}\n")
                detail.insert("end", "\n")
            forensic = info.get("forensics") or {}
            if forensic:
                detail.insert("end", "Forensics Summary:\n")

                def write_section(title: str, values: list[str], limit: int = 8):
                    items = [str(v) for v in (values or []) if v]
                    if not items:
                        return
                    display = items[:limit]
                    if len(items) > limit:
                        display.append("…")
                    detail.insert("end", f"  {title}: {', '.join(display)}\n")

                write_section("Parameters", forensic.get("parameters", []))
                write_section("JSON Fields", forensic.get("json_fields", []))
                write_section("Linked Paths", forensic.get("linked_paths", []))
                write_section("Form Targets", forensic.get("form_targets", []))
                write_section("JS Assets", forensic.get("asset_links", []))
                write_section("Inline URLs", forensic.get("json_links", []))
                write_section("WebSocket Links", forensic.get("websocket_links", []))
                write_section("Header Link Targets", forensic.get("link_relations", []))
                write_section("Robots Hints", forensic.get("robots_paths", []))
                write_section("Sitemap URLs", forensic.get("sitemap_urls", []))
                write_section("Well-known Paths", forensic.get("well_known_links", []))
                write_section("Config Endpoints", forensic.get("config_endpoints", []))
                write_section("CSP Reports", forensic.get("csp_reports", []))
                write_section("Host Hints", forensic.get("host_hints", []))
                write_section("Tech Hints", forensic.get("technologies", []))
                write_section("Intel Notes", forensic.get("intel", []))
                write_section("Secrets", forensic.get("secrets", []))
                write_section("Rate Limits", forensic.get("rate_limits", []))
                write_section("Auth Schemes", forensic.get("auth_schemes", []))
                if forensic.get("graphql"):
                    ops = forensic.get("graphql_operations", [])
                    if ops:
                        write_section("GraphQL Operations", ops, limit=10)
                    else:
                        detail.insert("end", "  GraphQL endpoint detected\n")
                write_section("Global Stack", forensic.get("global_technologies", []))
                write_section("Global Auth", forensic.get("global_auth_schemes", []))
                write_section("Spec Clues", forensic.get("global_spec_documents", []))
                write_section("Global JS Assets", forensic.get("global_asset_links", []))
                write_section("Global Form Targets", forensic.get("global_form_targets", []))
                write_section("Global Inline URLs", forensic.get("global_json_links", []))
                write_section("Global WebSockets", forensic.get("global_websocket_links", []))
                write_section("Global Link Targets", forensic.get("global_link_relations", []))
                write_section("Global Host Hints", forensic.get("global_host_hints", []))
                write_section("Global Robots Hints", forensic.get("global_robots_paths", []))
                write_section("Global Sitemap URLs", forensic.get("global_sitemap_urls", []))
                write_section("Global Well-known", forensic.get("global_well_known_links", []))
                write_section("Global Config Endpoints", forensic.get("global_config_endpoints", []))
                write_section("Global CSP Reports", forensic.get("global_csp_reports", []))
                cert = forensic.get("certificate")
                if isinstance(cert, dict) and cert:
                    subject = cert.get("subject") or "-"
                    issuer = cert.get("issuer") or "-"
                    expires = cert.get("expires") or "-"
                    alt_names = cert.get("alt_names") or []
                    display_alt = ", ".join(alt_names[:4])
                    if len(alt_names) > 4:
                        display_alt += ", …"
                    detail.insert("end", f"  TLS Subject: {subject}\n")
                    detail.insert("end", f"  TLS Issuer: {issuer}\n")
                    detail.insert("end", f"  TLS Expires: {expires}\n")
                    if display_alt:
                        detail.insert("end", f"  TLS Alt Names: {display_alt}\n")
                detail.insert("end", "\n")
            detail.insert("end", info["preview"])
            detail.configure(state="disabled")

        def on_select(_event):
            selected = tree.selection()
            if selected:
                update_detail(selected[0])

        tree.bind("<<TreeviewSelect>>", on_select)

        def finish_message():
            drift_total = metrics.get("drift", 0)
            drift_new = metrics.get("drift_new", 0)
            drift_changed = metrics.get("drift_changed", 0)
            retired = forcer.baseline_highlights.get("retired", 0)
            summary = (
                f"Scan #{scan_id} complete — {metrics['alerts']} intel alerts, {metrics['secrets']} secrets, "
                f"{metrics['slow']} slow endpoints, {drift_total} surface drift alerts "
                f"({drift_new} new / {drift_changed} changed, {retired} retired)"
            )
            self.status_var.set(summary)
            self._log_console(summary)
            retired_items = forcer.baseline_highlights.get("retired_items") or []
            if retired_items:
                retired_block = "\n\nRetired endpoints since last baseline:\n" + "\n".join(retired_items[:10])
                if len(retired_items) > 10:
                    retired_block += "\n…"
            else:
                retired_block = ""
            forensic_highlights = forcer.forensics.render_highlights()
            message = summary + retired_block
            if forensic_highlights:
                message += "\n\n" + forensic_highlights
                for line in forensic_highlights.splitlines():
                    self._log_console(line)
            messagebox.showinfo("Scan Complete", message)

        def handle_certificate(data):
            self.after(0, lambda payload=data: self._on_certificate_ready(payload))

        forcer = DirBruteForcer(
            url,
            wordlist,
            self.settings,
            on_found=lambda info: self.after(0, lambda: render_info(info)),
            on_finish=lambda: self.after(0, finish_message),
            on_progress=lambda pct: self.after(0, lambda: self.progress.configure(value=pct)),
            on_certificate=handle_certificate,
        )
        self.forcers[scan_id] = forcer
        self.progress.configure(value=0)
        forcer.start()

    def _apply_setting_values(self):
        for key, var in self._setting_vars.items():
            value = var.get()
            if key in {"threads", "recursion_depth"}:
                try:
                    self.settings.data[key] = int(value)
                except ValueError:
                    self.settings.data[key] = Settings.DEFAULTS.get(key)
            elif key == "timeout":
                try:
                    self.settings.data[key] = float(value)
                except ValueError:
                    self.settings.data[key] = Settings.DEFAULTS.get(key)
            elif key == "delay_jitter":
                try:
                    self.settings.data[key] = float(value)
                except ValueError:
                    self.settings.data[key] = Settings.DEFAULTS.get(key)
            else:
                self.settings.data[key] = value
        self.settings.data["follow_redirects"] = self.follow_redirects.get()
        self.settings.data["enable_preflight"] = self.enable_preflight.get()
        self.settings.data["probe_cors"] = self.probe_cors.get()
        self.settings.data["burp_proxy_enabled"] = self.burp_enabled.get()
        self.settings.data["burp_proxy_host"] = self.burp_host_var.get().strip()
        try:
            self.settings.data["burp_proxy_port"] = int(self.burp_port_var.get())
        except ValueError:
            self.settings.data["burp_proxy_port"] = Settings.DEFAULTS.get("burp_proxy_port", 8080)
        self.settings.data["extra_headers"] = self._headers_text.get("1.0", "end").strip()
        self.settings.data["intel_paths"] = self._intel_text.get("1.0", "end").strip()
        self._update_proxy_status()
        self.settings.save()

    def _save_settings(self):
        self._apply_setting_values()
        messagebox.showinfo("Settings", "Settings saved successfully.")

    def _export_csv(self, tree, results):
        path = filedialog.asksaveasfilename(defaultextension=".csv")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("URL,Method,Status,Delta,PreviousStatus,Latency(ms),Type,Length,Notes,Signals\n")
            for item in tree.get_children():
                info = results.get(item)
                if not info:
                    continue
                url = info["url"].replace('"', '""')
                ctype = (info.get("type") or "").replace('"', '""')
                notes = info.get("notes", "").replace('"', '""')
                latency = info.get("latency")
                latency_val = f"{latency:.1f}" if latency is not None else ""
                signals = ";".join(info.get("signals", []))
                signals = signals.replace('"', '""')
                delta = (info.get("delta") or "").replace('"', '""')
                previous = "" if info.get("previous_status") is None else str(info["previous_status"])
                fh.write(
                    f'"{url}",{info["method"]},{info["status"]},"{delta}",{previous},{latency_val},'
                    f'"{ctype}",{info["length"]},"{notes}","{signals}"\n'
                )

    def _export_json(self, tree, results):
        path = filedialog.asksaveasfilename(defaultextension=".json")
        if not path:
            return
        data = []
        for item in tree.get_children():
            info = results.get(item)
            if not info:
                continue
            data.append(
                {
                    "url": info["url"],
                    "method": info["method"],
                    "status": info["status"],
                    "latency_ms": info.get("latency"),
                    "type": info["type"],
                    "length": info["length"],
                    "notes": info.get("notes", ""),
                    "signals": info.get("signals", []),
                    "baseline_delta": info.get("delta"),
                    "previous_status": info.get("previous_status"),
                    "forensics": info.get("forensics"),
                }
            )
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)

    def _copy_selected(self, tree):
        selection = tree.selection()
        if not selection:
            messagebox.showinfo("Copy URL", "Select a result to copy its URL.")
            return
        url = tree.item(selection[0])["values"][0]
        self.clipboard_clear()
        self.clipboard_append(url)
        messagebox.showinfo("Copied", f"URL copied to clipboard:\n{url}")

    def _export_forensics_map_for_scan(self, scan_id: int) -> None:
        forcer = self.forcers.get(scan_id)
        if not forcer:
            messagebox.showerror("Export", "Scan not found or still running.")
            return
        self._export_forensics_map(forcer.forensics)

    def _export_forensics_map(self, report: APISurfaceReport) -> None:
        if not report:
            messagebox.showerror("Export", "No forensics data available yet.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json")
        if not path:
            return
        try:
            payload = report.to_dict()
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
        except Exception as exc:
            messagebox.showerror("Export", f"Failed to export forensics map: {exc}")
            return
        messagebox.showinfo("Export", f"Forensics map saved to:\n{path}")

    def _rename_tab(self, event):
        if self.nb.identify(event.x, event.y) != "label":
            return
        index = self.nb.index(f"@{event.x},{event.y}")
        current = self.nb.tab(index, "text")
        new_title = simpledialog.askstring("Rename", "Rename tab", initialvalue=current)
        if new_title:
            self.nb.tab(index, text=new_title)

    def on_close(self):
        for forcer in self.forcers.values():
            forcer.stop()
        self.destroy()


def cli_mode():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--wordlist", required=True)
    parser.add_argument("--threads", type=int)
    parser.add_argument("--timeout", type=float)
    parser.add_argument("--depth", type=int)
    parser.add_argument("--codes", type=str)
    parser.add_argument("--exts", type=str)
    parser.add_argument("--no-redirect", action="store_true")
    parser.add_argument("--methods", type=str)
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument("--intel-paths", type=str)
    parser.add_argument("--jitter", type=float)
    parser.add_argument("--no-preflight", action="store_true")
    parser.add_argument("--no-cors-probe", action="store_true")
    parser.add_argument("--output", required=True)
    parser.add_argument("--format", choices=["csv", "json"], default="json")
    parser.add_argument("--forensics-map", type=str)
    args = parser.parse_args()

    settings = Settings()
    if args.threads is not None:
        settings.data["threads"] = args.threads
    if args.timeout is not None:
        settings.data["timeout"] = args.timeout
    if args.depth is not None:
        settings.data["recursion_depth"] = args.depth
    if args.codes is not None:
        settings.data["include_status_codes"] = args.codes
    if args.exts is not None:
        settings.data["file_extensions"] = args.exts
    if args.methods is not None:
        settings.data["http_methods"] = args.methods
    if args.header:
        settings.data["extra_headers"] = "\n".join(args.header)
    if args.intel_paths is not None:
        settings.data["intel_paths"] = args.intel_paths
    if args.jitter is not None:
        settings.data["delay_jitter"] = args.jitter
    settings.data["follow_redirects"] = not args.no_redirect
    settings.data["enable_preflight"] = not args.no_preflight
    settings.data["probe_cors"] = not args.no_cors_probe

    results = []
    finished = threading.Event()

    def on_found(info):
        results.append(info)

    def on_finish():
        finished.set()

    forcer = DirBruteForcer(args.url, args.wordlist, settings, on_found, on_finish)
    forcer.start()
    finished.wait()

    if args.format == "json":
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(results, fh, indent=2)
    else:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write("URL,Method,Status,Delta,PreviousStatus,Latency(ms),Type,Length,Notes,Signals\n")
            for item in results:
                url = item["url"].replace('"', '""')
                ctype = (item.get("type") or "").replace('"', '""')
                notes = item.get("notes", "").replace('"', '""')
                latency = item.get("latency")
                latency_val = f"{latency:.1f}" if latency is not None else ""
                signals = ";".join(item.get("signals", []))
                signals = signals.replace('"', '""')
                delta = (item.get("delta") or "").replace('"', '""')
                previous = "" if item.get("previous_status") is None else str(item["previous_status"])
                fh.write(
                    f'"{url}",{item["method"]},{item["status"]},"{delta}",{previous},{latency_val},'
                    f'"{ctype}",{item["length"]},"{notes}","{signals}"\n'
                )
    if args.forensics_map:
        try:
            with open(args.forensics_map, "w", encoding="utf-8") as fh:
                json.dump(forcer.forensics.to_dict(), fh, indent=2)
            print(f"Forensics map saved to {args.forensics_map}")
        except Exception as exc:
            print(f"Failed to write forensics map: {exc}")
    drift_new = sum(1 for entry in results if entry.get("delta") == "NEW")
    drift_changed = sum(
        1 for entry in results if isinstance(entry.get("delta"), str) and entry["delta"].startswith("CHANGED")
    )
    retired = forcer.baseline_highlights.get("retired", 0)
    print(
        f"Saved {len(results)} entries to {args.output} (drift: {drift_new} new / {drift_changed} changed / {retired} retired)"
    )
    highlights = forcer.forensics.render_highlights()
    if highlights:
        print(highlights)


if __name__ == "__main__":
    import sys

    if "--cli" in sys.argv:
        cli_mode()
    else:
        app = App()
        app.protocol("WM_DELETE_WINDOW", app.on_close)
        app.mainloop()
