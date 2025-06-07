# FileDirBrute

A Python-based tool combining recursive directory brute-forcing and content discovery with both a graphical interface (Tkinter) and a command-line mode.

## Features

- **Integrated GUI & CLI**  
  - GUI with multiple scan tabs, logo, links, progress bar, and configurable settings.  
  - CLI mode for headless scanning and output to JSON/CSV.

- **Recursive Discovery**  
  - Brute-force directories using customizable wordlists.  
  - Automatically parse `text/html` responses to enqueue discovered links.

- **Configurable Settings**  
  - Threads, timeout, recursion depth, status code filters, file extensions, and redirect handling.  
  - Persisted across runs via `~/.dir_bruteforce_config.json`.

- **Results Management**  
  - Multiple result tabs with renamable labels.  
  - Export results per tab to CSV or JSON.  
  - CLI output supports both JSON and CSV formats.

- **Convenience Links & Branding**  
  - Top-right clickable links to Hackxpert Labs, X, and course page.  
  - Proportional `logo.png` display in header.

## Installation

1. **Clone or download** this repository.
2. **Install dependencies**:
   ```bash
   pip install requests pillow
   ```
3. **Ensure** `logo.png` is placed alongside the script if you want the branded header.

## Usage

### GUI Mode
```bash
python recursive_dir_bruteforce_gui.py
```
- Interact with tabs:
  - **Instructions**: Overview and comparison to wfuzz/ZAP Spider/pure brute-forcing.
  - **Scan**: Start new scans.
  - **Settings**: Adjust and persist scan parameters.
  - **Results**: View and rename results, export data.

### CLI Mode
```bash
python recursive_dir_bruteforce_gui.py --cli --url <URL> --wordlist <WORDLIST> --output <FILE> [--format csv|json]
```
- **Options**:
  - `--threads`: Number of parallel workers.
  - `--timeout`: HTTP request timeout in seconds.
  - `--depth`: Recursion depth limit.
  - `--codes`: Status code filter (e.g. `<400`, `200,301`).
  - `--exts`: Comma-separated file extensions to include.
  - `--no-redirect`: Disable following HTTP redirects.
  - `--output`: Path to write results.
  - `--format`: `json` (default) or `csv`.

## Configuration

Settings are saved in:
```
~/.dir_bruteforce_config.json
```
You can edit this file manually or via the **Settings** tab in the GUI.

## License

[MIT License](LICENSE)

---

© 2025 The XSS Rat
