import argparse
import json
import os
import queue
import random
import re
import threading
import time
import urllib.parse
import webbrowser
from pathlib import Path
from typing import Callable, Optional

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


class DirBruteForcer:
    def __init__(self, base_url, wordlist_file, settings, on_found, on_finish, on_progress=None):
        self.base_url = base_url.rstrip("/")
        self.wordlist_file = wordlist_file
        self.settings = settings
        self.on_found = on_found
        self.on_finish = on_finish
        self.on_progress = on_progress or (lambda p: None)
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
        }
        self.on_found(info)

        self.current_snapshot[signature] = code
        if "text/html" in content_type:
            with self.lock:
                if normalized_target not in self.path_seen:
                    self.path_seen.add(normalized_target)
                    self.total += len(self.word_variants) * self.method_count
                    self.to_scan.put((normalized_target, depth + 1))

        if "application/json" in content_type or "text" in content_type:
            for path in self._discover_paths(response):
                absolute = urllib.parse.urljoin(f"{self.base_url}/", path.lstrip("/"))
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


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("HackXpert API Surface Explorer")
        self.geometry("960x720")
        self.configure(bg="#0f172a")
        self.settings = Settings()
        self.forcers = {}
        self.scan_count = 0
        self.wordlist_store = Path.home() / ".hackxpert_wordlists"
        self.wordlist_store.mkdir(parents=True, exist_ok=True)
        self._wordlist_helpers = []
        self.api_tree_results = {}

        self._init_style()
        self._build_header()
        self._build_notebook()

    def _init_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        primary = "#0f172a"
        accent = "#22d3ee"
        style.configure("TFrame", background=primary)
        style.configure("Header.TFrame", background=primary)
        style.configure("Card.TFrame", background="#111827", relief="ridge", borderwidth=1)
        style.configure("TNotebook", background=primary, borderwidth=0)
        style.configure("TNotebook.Tab", padding=(12, 6), background="#1f2937", foreground="#e2e8f0")
        style.map("TNotebook.Tab", background=[("selected", "#22d3ee")], foreground=[("selected", "#0f172a")])
        style.configure("TLabel", background=primary, foreground="#e2e8f0")
        style.configure("Accent.TLabel", background=primary, foreground=accent, font=("Helvetica", 16, "bold"))
        style.configure("TButton", background="#1f2937", foreground="#e2e8f0", padding=(10, 5))
        style.map("TButton", background=[("active", accent)], foreground=[("active", "#0f172a")])
        style.configure("Treeview", background="#0f172a", fieldbackground="#0f172a", foreground="#e2e8f0", bordercolor="#22d3ee", rowheight=26)
        style.configure("Treeview.Heading", background="#1e293b", foreground="#38bdf8", font=("Helvetica", 11, "bold"))
        style.configure("HUDCard.TFrame", background="#1e293b", relief="ridge", borderwidth=1)
        style.configure("StatLabel.TLabel", background="#1e293b", foreground="#38bdf8", font=("Helvetica", 10, "bold"))
        style.configure("StatValuePrimary.TLabel", background="#1e293b", foreground="#22d3ee", font=("Helvetica", 20, "bold"))
        style.configure("StatValueAlert.TLabel", background="#1e293b", foreground="#f87171", font=("Helvetica", 20, "bold"))
        style.configure("StatValueSuccess.TLabel", background="#1e293b", foreground="#4ade80", font=("Helvetica", 20, "bold"))
        style.configure("StatValueFocus.TLabel", background="#1e293b", foreground="#f472b6", font=("Helvetica", 20, "bold"))
        style.configure("StatusBadge.TLabel", background="#111827", foreground="#fbbf24", font=("Helvetica", 12, "bold"))

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
            response = requests.get(url, timeout=30)
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

        tagline = ttk.Label(header, text="Discover hidden API endpoints with style ✨", style="Accent.TLabel")
        tagline.pack(side="left", padx=10)

        self.progress = ttk.Progressbar(header, mode="determinate", length=240)
        self.progress.pack(side="right", padx=10)

        for text, url in [
            ("Hackxpert Labs", "https://labs.hackxpert.com/"),
            ("X", "https://x.com/theXSSrat"),
            ("Courses", "https://thexssrat.com/"),
        ]:
            link = ttk.Label(header, text=text, foreground="#38bdf8", cursor="hand2")
            link.pack(side="right", padx=5)
            link.bind("<Button-1>", lambda _e, target=url: webbrowser.open(target))

    def _build_notebook(self):
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=10, pady=10)
        self.nb.bind("<Double-1>", self._rename_tab)
        self._build_instructions_tab()
        self._build_scan_tab()
        self._build_endpoint_explorer()
        self._build_parameter_explorer()
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
            "Need help? Hover labels for hints, and watch the status HUD for live telemetry while you hack stylishly."
        )
        text.insert("1.0", briefing)
        text.configure(state="disabled")

    def _build_scan_tab(self):
        frame = ttk.Frame(self.nb, style="Card.TFrame")
        self.nb.add(frame, text="Recon Lab")

        ttk.Label(
            frame,
            text="HackXpert merges its custom essentials with open-source wordlists when you opt in.",
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

        status_frame = ttk.Frame(frame, style="Card.TFrame")
        status_frame.grid(row=7, column=0, columnspan=3, sticky="ew", padx=5, pady=(0, 15))
        self.status_var = tk.StringVar(value="Awaiting mission launch…")
        ttk.Label(status_frame, textvariable=self.status_var, style="StatusBadge.TLabel").pack(
            anchor="w", padx=12, pady=8
        )

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
                response = requests.get(target, headers=headers, timeout=timeout, allow_redirects=True)
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

        ttk.Label(frame, text="Custom Headers (Header: value)").grid(
            row=row_offset + 3, column=0, columnspan=2, sticky="w", padx=5
        )
        self._headers_text = ScrolledText(frame, height=4, width=40)
        self._headers_text.grid(row=row_offset + 4, column=0, columnspan=2, padx=5, pady=5, sticky="we")
        self._headers_text.insert("1.0", str(self.settings.data.get("extra_headers", "")))

        ttk.Label(frame, text="Intel Paths (comma or newline separated)").grid(
            row=row_offset + 5, column=0, columnspan=2, sticky="w", padx=5
        )
        self._intel_text = ScrolledText(frame, height=3, width=40)
        self._intel_text.grid(row=row_offset + 6, column=0, columnspan=2, padx=5, pady=5, sticky="we")
        self._intel_text.insert("1.0", str(self.settings.data.get("intel_paths", "")))

        ttk.Button(frame, text="Save", command=self._save_settings).grid(
            row=row_offset + 7, column=1, pady=10, sticky="e"
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
            retired_items = forcer.baseline_highlights.get("retired_items") or []
            if retired_items:
                retired_block = "\n\nRetired endpoints since last baseline:\n" + "\n".join(retired_items[:10])
                if len(retired_items) > 10:
                    retired_block += "\n…"
            else:
                retired_block = ""
            messagebox.showinfo("Scan Complete", summary + retired_block)

        forcer = DirBruteForcer(
            url,
            wordlist,
            self.settings,
            on_found=lambda info: self.after(0, lambda: render_info(info)),
            on_finish=lambda: self.after(0, finish_message),
            on_progress=lambda pct: self.after(0, lambda: self.progress.configure(value=pct)),
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
        self.settings.data["extra_headers"] = self._headers_text.get("1.0", "end").strip()
        self.settings.data["intel_paths"] = self._intel_text.get("1.0", "end").strip()
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
    drift_new = sum(1 for entry in results if entry.get("delta") == "NEW")
    drift_changed = sum(
        1 for entry in results if isinstance(entry.get("delta"), str) and entry["delta"].startswith("CHANGED")
    )
    retired = forcer.baseline_highlights.get("retired", 0)
    print(
        f"Saved {len(results)} entries to {args.output} (drift: {drift_new} new / {drift_changed} changed / {retired} retired)"
    )


if __name__ == "__main__":
    import sys

    if "--cli" in sys.argv:
        cli_mode()
    else:
        app = App()
        app.protocol("WM_DELETE_WINDOW", app.on_close)
        app.mainloop()
