# Recon Helper (The XSS Rat)

**Recon Helper** is a Python‐based GUI application developed by The XSS Rat to automate DNS brute‐forcing and directory/file discovery against a target domain. It provides a clean, tabbed interface for configuring scans, viewing progress, browsing results, and inspecting raw database tables. Built with Tkinter, it also offers real‐time pop‐up feedback at each phase of the scan.

---

## Table of Contents

1. [Features](#features)  
2. [Architecture & Modules](#architecture--modules)  
3. [Installation](#installation)  
4. [Configuration](#configuration)  
5. [Usage](#usage)  
6. [Command‐Line Interface](#command‐line‐interface)  
7. [Database Schema](#database‐schema)  
8. [Pop‐Up Feedback](#pop‐up-feedback)  
9. [Contributing](#contributing)  
10. [License](#license)  

---

## Features

- **DNS Brute‐Force**  
  Incrementally brute‐forces subdomains using a custom wordlist, inserting discovered subdomains into an SQLite database.

- **Directory & File Discovery**  
  For each discovered subdomain, performs recursive path fuzzing against a configurable directory wordlist and (optionally) file extensions. Stores directories and files (with HTTP status codes) in the database.

- **Real‐Time Progress & Pop‐Ups**  
  Displays pop‐up notifications (“Starting DNS phase”, “Directory phase completed”, etc.) at each major step (DNS, directory discovery, completion). Progress bars in the “Scans” tab update in real time.

- **Tabbed Interface**  
  - **Config**: Enter target domain, select subdomain & directory wordlists, set timeouts, thread counts, max depth, and toggle DNS / dir stages.  
  - **Scans**: View all past scans, see live progress, and cancel/pause/resume.  
  - **Overview**: Interactive charts & statistics (e.g., total subdomains found, top directories).  
  - **Logs**: Stream of real‐time log messages from each scan, plus a global “catch‐all” logger.  
  - **Database**: Browse raw SQLite tables (domains, subdomains, directories, files, logs, etc.).

- **Pause / Resume / Stop**  
  Users can pause or resume a running scan at any time. Stopping will terminate cleanly and mark the scan as “stopped.”

- **CLI Mode**  
  A minimal command‐line interface (`run_cli.py`) is also provided for headless environments.

---

## Architecture & Modules

This project is organized into several modular Python files:

- **main.py**  
  - Entry point for the GUI application.  
  - Defines `ReconApp` (Tkinter root window) with all tabs, controls, and the background scan worker.  
  - Handles pop‐up notifications via `ui_utils.show_timed_popup()`.

- **scanner.py**  
  - Contains core scanning logic:  
    - `dns_bruteforce_incremental(domain, wordlist, threads, timeout, delay, pause_event, stop_event, log_queue, on_host_found, dns_progress_cb)`  
    - `discover_paths_for_host(subdomain, scan_id, dir_words, exts, max_depth, threads, timeout, delay, pause_event, stop_event, log_queue, progress_cb, db_conn, on_directory_found, on_file_found)`  
    - `load_wordlist(path)` (loads lines into a Python list).  

- **database.py**  
  - SQLite3 schema initialization (`init_database()` automatically migrates missing columns).  
  - CRUD functions for:  
    - `create_scan(conn, name)`  
    - `update_scan_status(conn, scan_id, status)`  
    - `insert_domain(conn, scan_id, domain_name, metadata)`  
    - `insert_subdomain(conn, scan_id, domain_id, subdomain, metadata)`  
    - `insert_directory(conn, scan_id, subdomain_id, path, status_code)`  
    - `insert_file(conn, scan_id, subdomain_id, file_url, status_code)`  
    - Logging: `log_message(conn, scan_id, message)`  
    - Fetch functions: `fetch_scans()`, `fetch_logs()`, `fetch_subdomains_by_scan()`, `fetch_directories_by_scan()`, `fetch_files_by_scan()`, `fetch_domains()` (for Overview).

- **run_cli.py**  
  - Provides a simple text‐based interface when `main.py` is invoked with arguments.  
  - Example usage: `python main.py --domain example.com --subwl subs.txt --dirwl dirs.txt`.

- **ui_utils.py**  
  - Contains helper functions for pop‐up notifications:  
    - `show_timed_popup(root, message, kind, duration=2000)`  
    - Automatically destroys itself after the specified `duration` (in milliseconds).  
  - Utility functions for standardizing pop‐up styles (info, warning, error, confirm).

- **ui_config.py**  
  - `ConfigTab(ttk.Frame)`:  
    - Domain entry box, “Browse…” buttons for subdomain & directory wordlists.  
    - Entry fields for:  
      - Number of threads (`spin_threads`)  
      - Request timeout (`spin_timeout`)  
      - Delay between requests (`scale_delay`)  
      - Max directory recursion depth (`spin_maxdepth`)  
      - Comma‐separated file extensions (`entry_exts`)  
    - Checkboxes to enable/disable DNS (`var_dns`), directory discovery (`var_dir`), file extension fuzzing (`var_content`).  
    - “Save Settings” & “Load Settings” automatically serialize to JSON.

- **ui_scans.py**  
  - `ScansTab(ttk.Frame)`:  
    - Displays an `ttk.Treeview` of all scans (ID, name, status, timestamp).  
    - Real‐time progress bars per scan (updated via `update_progress(scan_id, processed, total)`).  
    - “View Details” button to drill down into subdomain‐level progress.  
    - Implements `_catchall_append()` to append to log tab.

- **ui_overview_interactive.py**  
  - `InteractiveOverviewTab(ttk.Frame)`:  
    - Uses `matplotlib` embedded in Tkinter to show charts:  
      - Total subdomains discovered over time  
      - Top 10 directories (by count)  
      - Status code distribution (pie chart)  
    - Auto‐refreshes when the user switches to the “Overview” tab.

- **ui_logs.py**  
  - `LogsTab(ttk.Frame)`:  
    - Scrollable `Text` widget showing all log messages for the selected scan.  
    - Includes a global “Catch‐All” section (scan_id=None) for uncategorized logs.  
    - Supports filtering by log level (INFO, WARNING, ERROR).

- **ui_database.py**  
  - `DatabaseTab(ttk.Frame)`:  
    - Allows browsing any SQLite table via a dropdown selection.  
    - Renders table contents in a read‐only `ttk.Treeview`.  
    - Useful for power users to inspect raw data.

---

## Installation

1. **Clone the repository**  
   ```bash
   git clone https://github.com/TheXSSRat/recon-helper.git
   cd recon-helper
   ```

2. **Python & Virtual Environment**  
   Ensure you’re using Python 3.8+ (tested on Python 3.10). It’s recommended to create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Dependencies**  
   The `requirements.txt` includes all required packages:
   ```bash
   pip install -r requirements.txt
   ```
   - Key dependencies:  
     - `tkinter` (usually bundled with Python; if missing, install via your OS package manager)  
     - `Pillow` (for loading & resizing the logo)  
     - `matplotlib` (for charts in Overview tab)  
     - `requests` / `urllib3` (used internally for HTTP requests)

4. **Directory Structure**  
   ```text
   recon-helper/
   ├── database.py
   ├── main.py
   ├── requirements.txt
   ├── run_cli.py
   ├── scanner.py
   ├── ui_config.py
   ├── ui_database.py
   ├── ui_logs.py
   ├── ui_overview_interactive.py
   ├── ui_scans.py
   ├── ui_utils.py
   ├── ui_wordgen.py
   ├── ui_overview.py
   └── logo.png      ← Optional logo file (60×60 px recommended)
   ```

---

## Configuration

All scan parameters can be set via the **Config** tab in the GUI:

1. **Target Domain**  
   - Enter the base domain (e.g., `example.com`).

2. **Subdomain Wordlist**  
   - Click “Browse…” to select a newline‐delimited text file (e.g., `subs.txt`).  
   - If left empty, the DNS stage will still run (but with an empty list).

3. **Directory Wordlist**  
   - Click “Browse…” to select a newline‐delimited text file (e.g., `dirs.txt`).  
   - If directory discovery is enabled but no wordlist is provided, it will run against an empty list (no paths).

4. **File Extensions (Optional)**  
   - A comma‐separated list (e.g., `php,html,js,txt`).  
   - If “Enable content‐type fuzzing” is checked, the scanner will append `.<ext>` to each directory test.

5. **Threads & Timeouts**  
   - **Spin Threads**: Number of parallel worker threads (default: 10).  
   - **Spin Timeout**: Timeout per HTTP request in seconds (default: 5).  
   - **Scale Delay**: Milliseconds to wait between requests (default: 100).

6. **Max Recursion Depth**  
   - Maximum directory nesting depth (default: 3).

7. **Enable/Disable Stages**  
   - **DNS Stage** (checkbox): Toggle DNS brute forcing.  
   - **Directory Stage** (checkbox): Toggle directory discovery.  
   - **Content‐Type Fuzzing** (checkbox): Toggle appending extensions during directory discovery.

8. **Save & Load Settings**  
   - Settings automatically save to a JSON file (e.g., `~/.rec
Helper_settings.json`).  
   - On startup, the last used settings are loaded automatically.

---

## Usage

### Running the GUI

From the project root:
```bash
python main.py
```
1. **Click “Start Scan”** (Scan name is auto‐generated as `domain‐wordlistbasename‐timestamp`).  
2. Monitor progress in the **Scans** tab:  
   - Each active scan shows a progress bar for DNS / directory stages.  
   - Pause/Resume/Stop controls are enabled once a scan starts.  
3. View detailed logs in the **Logs** tab.  
4. Inspect high‐level statistics in **Overview**.  
5. Browse raw data tables in **Database**.

---

## Command‐Line Interface

A minimal CLI is provided via `run_cli.py` for headless or automated environments.

Example:
```bash
python main.py --domain example.com                --subwl path/to/subs.txt                --dirwl path/to/dirs.txt                --threads 20                --timeout 5                --delay 100                --maxdepth 4                --extensions php,html                --no‐dns False                --no‐dir False
```

- **Required**: `--domain`  
- **Optional**:  
  - `--subwl <file>` (subdomain wordlist)  
  - `--dirwl <file>` (directory wordlist)  
  - `--threads <int>`  
  - `--timeout <seconds>`  
  - `--delay <ms>`  
  - `--maxdepth <int>`  
  - `--extensions <comma‐sep‐list>`  
  - `--no‐dns` (skip DNS stage)  
  - `--no‐dir` (skip directory stage)

> **Note:** CLI mode will print progress & results to stdout and still populate the same SQLite database.

---

## Database Schema

Recon Helper uses an SQLite database (`recon.db` by default) with the following high‐level tables:

- **scans**  
  - `id` INTEGER PRIMARY KEY  
  - `name` TEXT UNIQUE  
  - `status` TEXT (`pending`, `running`, `paused`, `stopped`, `completed`)  
  - `created_at` TIMESTAMP  
  - `updated_at` TIMESTAMP

- **domains**  
  - `id` INTEGER PRIMARY KEY  
  - `scan_id` INTEGER REFERENCES `scans(id)`  
  - `domain` TEXT  
  - `metadata` JSON

- **subdomains**  
  - `id` INTEGER PRIMARY KEY  
  - `scan_id` INTEGER REFERENCES `scans(id)`  
  - `domain_id` INTEGER REFERENCES `domains(id)`  
  - `subdomain` TEXT  
  - `metadata` JSON

- **directories**  
  - `id` INTEGER PRIMARY KEY  
  - `scan_id` INTEGER REFERENCES `scans(id)`  
  - `subdomain_id` INTEGER REFERENCES `subdomains(id)`  
  - `path` TEXT  
  - `status_code` INTEGER

- **files**  
  - `id` INTEGER PRIMARY KEY  
  - `scan_id` INTEGER REFERENCES `scans(id)`  
  - `subdomain_id` INTEGER REFERENCES `subdomains(id)`  
  - `file_url` TEXT  
  - `status_code` INTEGER

- **logs**  
  - `id` INTEGER PRIMARY KEY  
  - `scan_id` INTEGER NULLABLE (NULL = catch‐all)  
  - `timestamp` TIMESTAMP  
  - `message` TEXT

All insert/update timestamps are set automatically.

---

## Pop‐Up Feedback

Recon Helper leverages Tkinter‐based “timed pop‐ups” to inform the user whenever the scan transitions phases:

1. **Scan Started**  
   - Pop‐up: “Scan ‘<scan_name>’ started” (✔️ confirm style)  
2. **Starting DNS Phase**  
   - Pop‐up: “Starting DNS brute‐force phase” (ℹ️ info style)  
3. **DNS Phase Completed**  
   - Pop‐up: “DNS brute‐force phase completed” (✔️ confirm style)  
4. **Skipping DNS Phase** (if disabled)  
   - Pop‐up: “DNS phase skipped” (ℹ️ info style)  
5. **Starting Directory Discovery**  
   - Pop‐up: “Starting directory discovery phase” (ℹ️ info style)  
6. **Directory Phase Completed**  
   - Pop‐up: “Directory discovery phase completed” (✔️ confirm style)  
7. **Skipping Directory Phase** (if disabled or no subdomains found)  
   - Pop‐up: “Directory phase skipped” or “No subdomains to scan for directories” (⚠️ warning style)  
8. **Scan Completed**  
   - Pop‐up: “Scan completed successfully” (✔️ confirm style)  
9. **Scan Paused / Resumed / Stopped**  
   - Pop‐up: “Scan paused” / “Scan resumed” / “Scan stopped by user” (ℹ️ info / ❌ error)

Each pop‐up auto‐closes after 2 seconds (configurable in `ui_utils.show_timed_popup`).

---

## Contributing

1. Fork the repository.  
2. Create a feature branch (`git checkout -b feature/xyz`).  
3. Commit your changes (`git commit -m "Add feature xyz"`).  
4. Push to the branch (`git push origin feature/xyz`).  
5. Open a pull request with a clear description of the changes.

Please adhere to PEP 8 style guidelines and keep features modular. When modifying existing modules, return the full updated file content in your pull request.

---

## License

This project is released under the **MIT License**. See [LICENSE](LICENSE) for details.
