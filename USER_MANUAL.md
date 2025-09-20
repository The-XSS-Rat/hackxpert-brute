# HackXpert API Surface Explorer — User Manual

Welcome to the neon recon lab. This manual walks you through the complete HackXpert desktop toolkit, highlighting the fresh Automations feature and all the supporting workflows that supercharge API reconnaissance.

## 1. Launching the Application

1. Ensure Python 3.10+ is available.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   *(If a requirements file is not shipped, install `requests`, `Pillow`, and any optional libraries you rely on.)*
3. Start the GUI:
   ```bash
   python main.py
   ```
4. To run in CLI mode (headless scans), append `--cli` followed by the arguments described near the end of this guide.

## 2. Interface Overview

The interface is organised into modular tabs inside a neon-styled notebook:

- **Briefing** – Mission overview, quick tips, and workflow reminders.
- **Recon Lab** – Primary directory/API surface brute forcing with live HUD metrics.
- **API Endpoint Explorer** – Lightweight spec and endpoint enumerator built for API-first targets.
- **API Parameter Explorer** – Focused parameter fuzzing with baseline diffing.
- **Automations** – Nuclei-style exploit templates and rulesets to rapidly validate exposures.
- **Settings** – Threading, recursion, proxy, header, and intel path controls.

## 3. Recon Lab Workflow

1. **Base URL & Wordlist** – Enter the target root URL and browse to a wordlist. The input autocompletes from bundled SecLists catalogues.
2. **Catalog Picker** – Swap to any curated list (API specific, common quick hits, WordPress, etc.). Enable the “Use custom wordlist” checkbox to merge HackXpert’s bespoke additions.
3. **Launch Scan** – Hit *Launch Scan* to spin up threaded reconnaissance. A dedicated results tab is created per scan with export controls.
4. **HUD Telemetry** – Monitor total hits, HTTP status distribution, intel hits, secret detections, slow endpoints, and surface drift stats in real time.
5. **Forensics Panel** – Selecting an entry shows previews, intel signals, TLS data, discovered assets, and baseline deltas.

### Exporting Recon Data

- **CSV / JSON** – Buttons under each scan tab export condensed or full records.
- **Forensics Map** – Saves the APISurfaceReport JSON (endpoints, technologies, passive intel, TLS certificate snapshot).
- **Copy URL** – Quickly copy the highlighted request for escalation in other tooling.

## 4. API Endpoint Explorer

1. Provide a **Target Base URL** and optional custom wordlist.
2. Start the run to sweep OpenAPI/Swagger definitions, `/docs`, GraphQL docs, and endpoints derived from the selected wordlist.
3. Double-click results to open the **Request Workbench** for replaying or mutating calls.
4. Right-click to send hits into the Parameter Explorer for deeper fuzzing.

## 5. API Parameter Explorer

1. Feed the **Request URL** and choose the HTTP method.
2. Stack parameter payloads by combining HackXpert’s list with themed packs (auth, filtering, injection primitives).
3. Supply optional headers and body payloads.
4. Launch the fuzz – baseline diffs and content-length changes are highlighted. Double-click rows to send them back to the Request Workbench.

## 6. Automations (New!)

The Automations tab delivers a nuclei-inspired engine for executing exploit templates and reusable rulesets.

### 6.1 Running Templates

1. Enter the **Base URL** for the target (schemas will auto-normalise if omitted).
2. Select one or more templates from the **Template Catalog**. Each entry shows severity, target path/URL, and tags.
3. Click **Run Selected Templates** to fire the requests sequentially. Results stream into the findings panel with HIT/MISS/ERROR tags, evidence, and response time.

### 6.2 Rulesets

- Use **Save Selection as Ruleset** to capture your current template selection under a friendly name (e.g. “Common Exposures”).
- Choose a ruleset from the dropdown and hit **Run Ruleset** for repeatable assessments. Rulesets are persisted in `~/.hackxpert_automations.json`.

### 6.3 Importing Templates

- Click **Import Template File** and select a JSON file containing templates. The format matches `automations/templates.json` in the repo.
- Imported templates are stored in the automation library and immediately available for selection.

### 6.4 Building Templates

1. Click **Build New Template** to open the builder dialog.
2. Provide either a relative path (e.g. `/.git/config`) or a full URL, method, severity, and optional tags.
3. Configure matchers:
   - **Status codes** (comma separated integers).
   - **Body contains / regex** matchers for string or regex detection.
   - **Negative contains** to ensure certain tokens are absent.
   - **Header matchers** to assert header substrings.
4. Supply optional request headers and body payloads.
5. Save the template – it is persisted and listed alongside built-ins.

### 6.5 Reviewing Results

- Selecting a finding displays description, evidence, response headers, and a preview of the body.
- Hits and errors are logged to the console for timeline context.
- Automations respect global headers, proxies, and timeout settings from the Settings tab.

## 7. Settings & Integrations

- **Threading & Recursion** – Control concurrency, recursion depth, HTTP methods, and response filters.
- **Timeout & Jitter** – Tune for stealth or speed.
- **Headers & Intel Paths** – Persist custom headers and preflight intel endpoints.
- **CORS Probing & Burp Proxy** – Toggle passive checks and chain requests through Burp for interception.

## 8. Console & Telemetry

The lower console logs major events: recon discoveries, TLS certificate insights, automation hits, and drift summaries. Use it as a quick audit trail during engagements.

## 9. Command-line Mode

Run HackXpert without the GUI:

```bash
python main.py --cli \
  --url https://target.tld \
  --wordlist /path/to/wordlist.txt \
  --threads 20 \
  --timeout 6 \
  --depth 3 \
  --methods GET,HEAD \
  --output results.json \
  --format json \
  --forensics-map forensics.json
```

All GUI settings have CLI equivalents (`--no-redirect`, `--jitter`, `--intel-paths`, etc.). Results mirror the GUI exports.

## 10. Tips & Best Practices

- **Baseline Storage** – Drift detection persists per base URL in `~/.hackxpert_surface_baselines.json`. Keep it for change tracking between assessments.
- **Template Hygiene** – Store shared automation templates in version control. The import/export flow keeps teams in sync.
- **Proxies & VPNs** – Configure the Burp proxy toggle when testing via interception proxies or VPN tunnels.
- **Responsible Usage** – Ensure you have authorisation before running aggressive scans or exploit templates.

Happy hunting – may your recon stay stylish and your automations strike gold.
