# HackXpert API Surface Explorer

HackXpert API Surface Explorer is a hybrid GUI/CLI recon assistant purpose-built for quickly enumerating API endpoints, collecting live response context, and exporting results in formats your blueprints or reports can use. It fuses the speed of threaded brute-forcing with recursive discovery smarts inside a polished dark UI, while still offering a scriptable command line for pipelines and servers.

<img width="946" height="736" alt="image" src="https://github.com/user-attachments/assets/cd73ac17-fa15-4643-9b02-9202c7dcf8be" />


## Why choose HackXpert over other API discovery tools?

* **Surface Drift Radar** – HackXpert baselines every environment locally, then live-flags brand new, status-changed, or vanished endpoints so you spot release drift before it lands in prod.
* <img width="1613" height="1053" alt="image" src="https://github.com/user-attachments/assets/e44c43fa-3e5d-4c0d-b5f6-0e7a07358e8e" />
* **High-signal previews** – Every hit in the GUI streams a syntax-aware preview, letting you triage JSON/text responses in seconds without juggling a separate HTTP client.
* **Recursive intelligence** – Responses that look like HTML get parsed automatically so newly uncovered paths, forms, scripts, and inline URLs are scheduled without you lifting a finger.
* **Rapid iteration controls** – Fine-tune threads, timeouts, recursion depth, status filters, and extension permutations, then persist the profile for your next engagement.
* **Command center workflow** – Run multiple scans at once, rename tabs, monitor the neon recon HUD and console feed, colour-code statuses at a glance, export to CSV/JSON, or copy hits directly for follow-up testing.
* **Headless ready** – The CLI mirrors the GUI logic so you can bake recon sweeps into CI, cron jobs, or containerised playbooks with identical output.
* **OffSec preflight** – The engine auto-hunts `robots.txt`, `.well-known/security.txt`, Swagger/OpenAPI docs, and GraphQL introspection targets before the main brute-force wave so you never miss low-hanging intel.

## Ten power features ethical hackers asked for
<img width="1898" height="1051" alt="image" src="https://github.com/user-attachments/assets/ccf00845-8b21-45de-a3c8-30b0bfc1fd92" />

1. **Multi-method blasting** – Supply `GET,HEAD,POST` (or any combo) and the explorer will cycle through each verb per path so you can spot sneaky behaviour differences or method-specific exposures.
2. **Header loadouts** – Drop custom headers (auth tokens, API keys, experimental Origins) into the Settings tab once and every request—GUI, CLI, and preflight—will reuse them.
3. **Recon jitter control** – Add a random delay between requests to mimic human traffic and side-step fragile rate-limiters while still leveraging concurrency.
4. **CORS misconfiguration radar** – Optional probing highlights endpoints that reflect hostile Origins or serve wildcard CORS policies, surfacing juicy pivot points immediately.
5. **Intel path extraction** – JSON and text previews are parsed for `/api/...` style paths, JavaScript asset calls, and inline `fetch`/`axios` endpoints which are automatically queued for follow-up enumeration inside scope and depth limits.
6. **Latency radar** – Each response is timed, highlighted, and graphed in the HUD so lethargic endpoints (≥1.2s) stand out for DoS and performance investigations.
7. **Header intel analyzer** – Server, X-Powered-By, authentication, and proxy headers are called out automatically to accelerate tech fingerprinting and perimeter mapping.
8. **Secret sniffer** – The preview pane flags JWTs, AWS keys, API tokens, and other credential patterns as soon as they appear so you can escalate quickly.
9. **Directory exposure watch** – Classic “Index of /” listings and other directory disclosures are labelled the moment they appear.
10. **Rate-limit and auth mapping** – 401/403/429/500 responses receive contextual notes so you can chart the access boundaries while the scan runs.
<img width="1889" height="1053" alt="image" src="https://github.com/user-attachments/assets/1847bec8-a272-4ec1-9a04-c36769acfe81" />
<img width="1897" height="1037" alt="image" src="https://github.com/user-attachments/assets/ef586d23-890c-4edf-92da-8624c663b3f3" />

### New: API forensics engine

HackXpert now ships with a deep API forensics engine to map the entire surface effortlessly:

* **Automatic parameter harvesting** – Query strings, JSON bodies, and form payloads are analysed to build living parameter dictionaries per endpoint.
* **Response schema mining** – JSON field names, discovered paths, and nested objects are catalogued so you can understand entity relationships instantly.
* **Tech fingerprinting & auth intelligence** – Stack hints, auth schemes, rate-limit headers, and other signals are compiled into per-endpoint dossiers.
* **GraphQL & spec detection** – GraphQL operations, introspection data, Swagger/OpenAPI documents, and other spec artefacts are highlighted as soon as they surface.
* **One-click export** – Every scan tab exposes an **Export Forensics Map** action that saves a structured JSON map of all observations for reporting or replay.

### New: Burp chaining & passive discovery arsenal

* **Burp Suite proxy chaining** – Route every GUI/CLI request (preflight, recon sweeps, parameter fuzzing, manual requests) through your Burp listener via the Settings toggle. The neon header surfaces a live proxy status badge so you know when traffic is flowing through Burp.
* **TLS intelligence hub** – HTTPS targets now stream certificate subject, issuer, expiry, and SAN inventory into the Recon Lab panel and console so you can pivot to alternate hostnames instantly.
* **Form & action miner** – HTML forms are harvested for action URLs and queued automatically, building out parameter dictionaries along the way.
* **JavaScript signal hunter** – Script tags plus inline `fetch`/`axios` calls are parsed to surface hidden API routes and JavaScript assets ready for deeper inspection.
* **Robots & sitemap ingestion** – `robots.txt` directives and XML sitemaps feed directly into the discovery queue and forensics map, ensuring crawler-only endpoints are captured.
* **Live recon console** – A hacker-style console streams high-value events (spec captures, TLS intel, drift, secrets) so you have an auditable recon timeline without leaving the app.
* **WebSocket sweeper** – Inline `ws://` / `wss://` references are harvested, recorded in the forensics map, and surfaced in the console for rapid socket pivoting.
* **Header link mapper** – `Link` and `Location` headers are normalised into follow-up candidates so pagination, prefetch, and redirect chains never go unseen.
* **Config leak detector** – JavaScript configuration blobs (`apiUrl`, `endpointUri`, etc.) and JSON payloads leaking service URLs are lifted automatically into the recon queue.
* **Well-known hunter** – Any `/\.well-known/...` references discovered in HTML, JSON, or configs are promoted to first-class targets and highlighted in the forensics view.
* **CSP report radar** – `Content-Security-Policy` and `Report-To` directives are parsed for reporting endpoints, exposing monitoring infrastructure and alternate ingestion hosts.

  <img width="1889" height="1040" alt="image" src="https://github.com/user-attachments/assets/a8090d65-84e2-402e-a8ff-715cfcb50327" />
<img width="1887" height="951" alt="image" src="https://github.com/user-attachments/assets/16eb6c56-f99b-48f2-a5b0-eb1d313244a5" />


## Requirements

* Python 3.9+
* `requests`
* `pillow`

Install dependencies:

```bash
pip install -r requirements.txt  # or pip install requests pillow
```

> ℹ️ The UI optionally loads `logo.png` from the repository root to brand the header. If you drop in your own image, it will be scaled automatically.

## Curated wordlists

HackXpert now ships with hand-tuned discovery wordlists for both endpoints and parameters:

* `wordlists/hackxpert_endpoints.txt`
* `wordlists/hackxpert_endpoints_25000.txt` – Extended 25k-entry API endpoint list for exhaustive sweeps.
* `wordlists/hackxpert_parameters.txt`

Each scan surface (Recon Lab, API Endpoint Explorer, and API Parameter Explorer) exposes a **Use custom wordlist** checkbox and a catalog dropdown. When enabled, the custom HackXpert essentials are merged with any open-source list you select (SecLists entries download automatically when first used). Leave the box unchecked to run with the open-source list alone.

## Quickstart (GUI)

1. **Launch the explorer**
   ```bash
   python main.py
   ```
2. **Briefing tab** – Read the high-level workflow primer and tips.
3. **Settings tab** – Adjust threads, timeout, recursion depth, status-code filter, extension permutations, HTTP methods, jitter, custom headers, and CORS/preflight toggles. Click **Save** to persist to `~/.dir_bruteforce_config.json`.
4. **Recon Lab tab**
   * Enter the target base URL (protocol optional; `https://` is auto-assumed when supplied).
   * Select a wordlist (any newline-delimited list of directories/files).
   * Hit **Launch Scan** to start a new tabbed session.
5. **During the scan**
   * Watch coloured status rows (plus highlights for CORS, intel hits, secrets, slow endpoints, and drift states) stream in with their HTTP method and latency.
   * Track the neon recon HUD for totals, 2xx wins, intel count, secret hits, slow endpoints, and live surface drift counts.
   * Select any row to see the response preview rendered beneath the table, including intel notes, latency, and pre-parsed follow-up paths.
   * Track progress with the global header bar and mission status badge.
6. **After discovery**
   * Export hits (URL, method, status, drift delta, previous status, latency, length, notes, intel signals) from the active scan tab via **Export CSV** or **Export JSON**.
   * Use **Copy URL** to grab a single endpoint for manual testing.
   * Double-click a tab title to rename it (e.g., to the environment or scope being tested).

## Quickstart (CLI)

Run in headless mode with the same engine used by the GUI:

```bash
python main.py --cli --url https://target.tld/api --wordlist wordlist.txt \
  --output findings.json --format json \
  --threads 20 --timeout 8 --depth 3 --codes "<400" --exts "json,php" \
  --forensics-map forensics.json
```

* `--threads` – Worker count (default 10).
* `--timeout` – Per-request timeout in seconds (default 5).
* `--depth` – Maximum recursion depth from the base URL (default 5).
* `--codes` – Status filter (`<400`, `200,302`, etc.).
* `--exts` – Comma-separated list of extensions to append to each wordlist entry.
* `--methods` – Comma-separated HTTP verbs to attempt per path (default `GET`).
* `--header` – Repeatable flag for custom headers (`--header "Authorization: Bearer …"`).
* `--intel-paths` – Custom list of passive intel endpoints (comma/newline separated).
* `--jitter` – Maximum random delay (seconds) inserted after each request.
* `--no-redirect` – Disable following HTTP redirects.
* `--no-preflight` – Skip the passive intel sweep (default enabled).
* `--no-cors-probe` – Disable CORS origin testing.
* `--format` – Output file format (`json` default, or `csv`).
* `--forensics-map` – Optional path to write the structured forensics map captured during the run.

CLI exports now include latency, intel signals, and baseline drift deltas so dashboards can visualise hotspots instantly. The tool prints a summary line once the scan finishes showing new/changed/retired endpoints and writes the structured results to the chosen file, ready for dashboards, diffing, or replay scripts.

## Field guide: maximising signal

1. **Curate your wordlists** – Blend general discovery lists (e.g. SecLists API directories) with project-specific artefacts such as OpenAPI specs or repo paths.
2. **Layer extension combos** – Populate the **Extensions** setting with `json,xml,bak` to automatically test API variants and backup files in one pass.
3. **Start broad, then tighten filters** – Begin with a permissive status filter like `<500` to observe the surface, then switch to `200,204,301,302` when reporting only meaningful assets.
4. **Use response previews as triage** – The preview pane clips responses to fit, ideal for spotting credentials, error traces, or feature flags without issuing new requests.
5. **Arm headers once** – Set bearer tokens, custom Origins, or testing headers in the Settings tab so every method and preflight request carries them.
6. **Parallelise environments** – Run multiple scans (dev/staging/prod) simultaneously in separate tabs, rename them, and export each dataset for comparison.
7. **Export early** – CSV exports feed spreadsheets or BI tools; JSON exports drop straight into Postman collections or follow-on scripts.
8. **Lean on forensics** – Use the forensics summary in each hit to spot stack technologies, auth boundaries, GraphQL operations, rate limiting and linked paths without leaving the HUD.
9. **Tread lightly** – When probing sensitive targets, add a small jitter (e.g. `0.4`) to keep concurrency but soften traffic bursts.

## Configuration storage

Settings persist between sessions inside:

```text
~/.dir_bruteforce_config.json
```

You can edit this file directly or rely on the Settings tab controls. Deleting it resets the explorer to the built-in defaults.

The Surface Drift Radar feature stores per-base-URL baselines here:

```text
~/.hackxpert_surface_baselines.json
```

Remove the file if you want to reset the drift history for all targets.

## Troubleshooting

* **GUI won’t start?** Ensure you have a display environment (X11/Wayland) or use the CLI mode when operating on servers.
* **SSL errors?** Supply the full `https://` URL and consider exporting `REQUESTS_CA_BUNDLE` if a custom CA is required.
* **Slow scans?** Reduce recursion depth, adjust thread count based on target stability, or trim wordlists for higher-value paths.

Happy hunting! 🎯
