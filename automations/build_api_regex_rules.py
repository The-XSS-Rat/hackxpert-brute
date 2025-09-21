"""Utility for generating bulk API regex scanning templates."""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path
from typing import Iterable, List

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_PATH = REPO_ROOT / "automations" / "templates.json"
REGEX_SET_DIR = REPO_ROOT / "automations" / "regex_sets"

STUB_MODULES = {
    "requests",
    "tkinter",
    "tkinter.ttk",
    "tkinter.filedialog",
    "tkinter.messagebox",
    "tkinter.simpledialog",
    "tkinter.scrolledtext",
    "PIL",
    "PIL.Image",
    "PIL.ImageTk",
}

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


INDEX_COUNT = 15


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


def _install_gui_stubs() -> None:
    """Install lightweight stubs so ``main`` can be imported headlessly."""

    dummy_modules: dict[str, types.ModuleType] = {}

    class DummyModule(types.ModuleType):
        def __getattr__(self, name: str) -> object:  # pragma: no cover - helper
            value = type(name, (), {})
            setattr(self, name, value)
            return value

    def ensure_module(name: str) -> types.ModuleType:
        module = dummy_modules.get(name)
        if module is None:
            module = DummyModule(name)
            dummy_modules[name] = module
            sys.modules[name] = module
        return module

    requests_mod = ensure_module("requests")

    class _StubSession:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def get(self, *args: object, **kwargs: object) -> object:  # pragma: no cover - helper
            raise RuntimeError("requests stub invoked")

    requests_mod.Session = _StubSession  # type: ignore[attr-defined]
    requests_mod.get = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("requests stub invoked"))
    requests_mod.exceptions = types.SimpleNamespace(RequestException=Exception)

    tk_mod = ensure_module("tkinter")
    tk_mod.END = "end"  # type: ignore[attr-defined]

    ttk_mod = ensure_module("tkinter.ttk")
    filedialog_mod = ensure_module("tkinter.filedialog")
    messagebox_mod = ensure_module("tkinter.messagebox")
    simpledialog_mod = ensure_module("tkinter.simpledialog")
    scrolled_mod = ensure_module("tkinter.scrolledtext")

    scrolled_mod.ScrolledText = type("ScrolledText", (), {})  # type: ignore[attr-defined]

    def _dummy_return(*_args: object, **_kwargs: object) -> str:
        return ""

    def _dummy_none(*_args: object, **_kwargs: object) -> None:
        return None

    filedialog_mod.askopenfilename = _dummy_return  # type: ignore[attr-defined]
    filedialog_mod.asksaveasfilename = _dummy_return  # type: ignore[attr-defined]
    messagebox_mod.showinfo = _dummy_none  # type: ignore[attr-defined]
    messagebox_mod.showwarning = _dummy_none  # type: ignore[attr-defined]
    messagebox_mod.showerror = _dummy_none  # type: ignore[attr-defined]
    messagebox_mod.askyesno = lambda *_args, **_kwargs: True  # type: ignore[attr-defined]
    simpledialog_mod.askstring = _dummy_return  # type: ignore[attr-defined]
    simpledialog_mod.askinteger = lambda *_args, **_kwargs: 0  # type: ignore[attr-defined]

    for attr in [
        "Tk",
        "Toplevel",
        "Frame",
        "Label",
        "Button",
        "Menu",
        "Scrollbar",
        "Canvas",
        "StringVar",
        "BooleanVar",
        "IntVar",
    ]:
        setattr(tk_mod, attr, type(attr, (), {}))

    tk_mod.ttk = ttk_mod  # type: ignore[attr-defined]
    tk_mod.filedialog = filedialog_mod  # type: ignore[attr-defined]
    tk_mod.messagebox = messagebox_mod  # type: ignore[attr-defined]
    tk_mod.simpledialog = simpledialog_mod  # type: ignore[attr-defined]
    tk_mod.ScrolledText = scrolled_mod.ScrolledText  # type: ignore[attr-defined]

    pil_mod = ensure_module("PIL")
    image_mod = ensure_module("PIL.Image")
    imagetk_mod = ensure_module("PIL.ImageTk")

    image_mod.open = _dummy_none  # type: ignore[attr-defined]
    image_mod.new = _dummy_none  # type: ignore[attr-defined]
    image_mod.ANTIALIAS = 0  # type: ignore[attr-defined]
    image_mod.LANCZOS = 0  # type: ignore[attr-defined]
    imagetk_mod.PhotoImage = type("PhotoImage", (), {})  # type: ignore[attr-defined]

    pil_mod.Image = image_mod  # type: ignore[attr-defined]
    pil_mod.ImageTk = imagetk_mod  # type: ignore[attr-defined]


def _load_default_templates() -> list[dict[str, object]]:
    import importlib

    try:
        main_module = importlib.import_module("main")
    except ImportError as exc:  # pragma: no cover - fallback path
        missing = getattr(exc, "name", "")
        if missing in STUB_MODULES:
            _install_gui_stubs()
            main_module = importlib.import_module("main")
        else:
            raise
    templates = getattr(main_module, "DEFAULT_AUTOMATION_TEMPLATES", [])
    return json.loads(json.dumps(list(templates)))


def load_existing_templates() -> list[dict[str, object]]:
    """Load persisted templates, falling back to the runtime defaults."""

    def _copy_templates(templates: Iterable[dict[str, object]]) -> list[dict[str, object]]:
        return json.loads(json.dumps(list(templates)))

    if TEMPLATE_PATH.exists():
        try:
            payload = json.loads(TEMPLATE_PATH.read_text())
        except json.JSONDecodeError:
            payload = None
        else:
            if isinstance(payload, list):
                return [entry for entry in payload if isinstance(entry, dict)]

    return _copy_templates(_load_default_templates())


def slugify(value: str) -> str:
    """Return a filesystem and URL friendly slug."""
    cleaned = "".join(ch if ch.isalnum() else "-" for ch in value.lower())
    cleaned = "-".join(filter(None, cleaned.split("-")))
    return cleaned or "category"


def iter_template_definitions() -> Iterable[tuple[str, dict[str, object], str, list[str]]]:
    for category in CATEGORIES:
        category_slug = slugify(category)
        category_title = category.replace("-", " ").title()
        base_context = {
            "category": category,
            "category_slug": category_slug,
            "category_title": category_title,
        }
        for exposure in EXPOSURES:
            severity_cycle = BASE_SEVERITY[exposure["severity"]]
            for index in range(1, INDEX_COUNT + 1):
                context = {
                    **base_context,
                    "index": index,
                    "index_padded": f"{index:02d}",
                }
                severity = severity_cycle[(index - 1) % len(severity_cycle)]
                template_id = f"api-regex-{exposure['slug']}-{category_slug}-{index:02d}"
                regex_terms = [f"(?i){term}" for term in exposure["regex_terms"]]
                template = {
                    "id": template_id,
                    "name": f"{category_title} {exposure['title']} #{index}",
                    "description": exposure["description"].format(**context),
                    "severity": severity,
                    "method": "GET",
                    "path": exposure["path_template"].format(**context),
                    "matchers": {"status": [200], "regex": regex_terms},
                    "tags": [tag.format(**context) for tag in exposure["tags"]],
                }
                yield template_id, template, exposure["slug"], regex_terms


def build_templates(existing_ids: Iterable[str]) -> list[dict[str, object]]:
    templates: list[dict[str, object]] = []
    for template_id, template, _, _ in iter_template_definitions():
        if template_id in existing_ids:
            continue
        templates.append(template)
    return templates


def build_regex_sets() -> dict[str, list[dict[str, object]]]:
    regex_sets: dict[str, list[dict[str, object]]] = {}
    for template_id, _, slug, regex_terms in iter_template_definitions():
        entries = regex_sets.setdefault(slug, [])
        entries.append({"template_id": template_id, "regex": regex_terms})
    return regex_sets


def main() -> None:
    payload: List[dict[str, object]] = load_existing_templates()
    existing_ids = {entry.get("id") for entry in payload if isinstance(entry, dict)}
    additions = build_templates(existing_ids)
    payload.extend(additions)
    TEMPLATE_PATH.write_text(json.dumps(payload, indent=2) + "\n")

    regex_sets = build_regex_sets()
    updated_sets = 0
    for exposure in EXPOSURES:
        slug = exposure["slug"]
        regex_path = REGEX_SET_DIR / f"{slug}.json"
        if slug not in regex_sets:
            continue
        templates = regex_sets[slug]
        if regex_path.exists():
            payload_set = json.loads(regex_path.read_text())
            payload_set["templates"] = templates
        else:
            payload_set = {
                "category": slug,
                "title": exposure["title"],
                "description": f"Regex collection for {exposure['title']} automation templates.",
                "templates": templates,
            }
        regex_path.write_text(json.dumps(payload_set, indent=2) + "\n")
        updated_sets += 1

    print(f"Added {len(additions)} templates. Total now {len(payload)}")
    print(f"Updated {updated_sets} regex set definitions with {INDEX_COUNT} variants each.")


if __name__ == "__main__":
    main()
