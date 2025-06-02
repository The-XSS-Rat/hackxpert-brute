import sys
import threading
import time
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import webbrowser
from queue import Queue

# Scanner and Database functions
from scanner import (
    dns_bruteforce_incremental,
    discover_paths_for_host,
    load_wordlist
)
from database import (
    init_database,
    create_scan,
    update_scan_status,
    log_message,
    insert_domain,
    insert_subdomain,
    insert_directory,
    insert_file,
    insert_custom_wordlist,
    fetch_scans,
    fetch_logs,
    fetch_subdomains_by_scan,
    fetch_directories_by_scan,
    fetch_files_by_scan,
    fetch_domains             # ← newly added helper
)
from ui_utils import show_timed_popup
from ui_config import ConfigTab
from ui_scans import ScansTab
from ui_overview_interactive import InteractiveOverviewTab
from ui_logs import LogsTab
from ui_database import DatabaseTab
from ui_wordgen import WordGenTab


class ReconApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("The XSS Rat – Recon Helper")
        self.geometry("1100x800")
        self.minsize(1100, 800)

        # Shared state
        self.log_queue = Queue()
        self.pause_event = threading.Event()
        self.stop_event = threading.Event()

        # Database connection (migrates missing columns automatically)
        self.db_conn = init_database()

        # Build all tabs and widgets
        self._build_widgets()

        # Start polling the log queue for real‐time updates
        self.after(100, self._poll_log_queue)

        # When the user clicks “X” on the window, ensure settings are saved
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_widgets(self):
        # ─── Top bar: logo & social links ─────────────────────────────────────────
        top_frame = ttk.Frame(self)
        top_frame.pack(fill="x", pady=(10, 5))

        logo_path = os.path.join(os.path.dirname(__file__), "logo.png")
        if os.path.isfile(logo_path):
            try:
                from PIL import Image, ImageTk
                img = Image.open(logo_path)
                img_resized = img.resize((60, 60), Image.Resampling.LANCZOS)
                self.logo_img = ImageTk.PhotoImage(img_resized)
                lbl_logo = ttk.Label(top_frame, image=self.logo_img)
                lbl_logo.pack(side="left", padx=(10, 5))
            except:
                pass

        credits = tk.Label(
            top_frame,
            text="The XSS Rat – Ethical Hacker",
            font=("Arial", 12, "bold"),
            fg="white", bg="#333333"
        )
        credits.pack(side="left", anchor="n")

        links_frame = ttk.Frame(top_frame)
        links_frame.pack(side="right", padx=10)
        link_info = [
            ("Labs", "https://labs.hackxpert.com"),
            ("Blog", "https://blog.hackxpert.com"),
            ("Shop", "https://thexssrat.com"),
            ("Twitter", "https://x.com/theXSSRat"),
            ("LinkedIn", "https://www.linkedin.com/in/wesley-thijs-8b384828a/")
        ]
        for idx, (label, url) in enumerate(link_info):
            lbl = tk.Label(
                links_frame,
                text=label,
                fg="white",
                cursor="hand2",
                font=("Segoe UI", 9, "underline"),
                bg="#333333"
            )
            lbl.grid(row=0, column=idx, padx=5)
            lbl.bind("<Button-1>", lambda e, link=url: webbrowser.open(link))

        # ─── Control buttons (Start / Pause / Resume / Stop) ─────────────────────
        ctrl_frame = ttk.Frame(self)
        ctrl_frame.pack(fill="x", padx=10, pady=(0, 5))

        self.btn_start = ttk.Button(
            ctrl_frame,
            text="Start Scan",
            command=self._on_start_scan
        )
        self.btn_start.pack(side="left", padx=5)

        self.btn_pause = ttk.Button(
            ctrl_frame,
            text="Pause",
            state="disabled",
            command=self._toggle_pause
        )
        self.btn_pause.pack(side="left", padx=5)

        self.btn_resume = ttk.Button(
            ctrl_frame,
            text="Resume",
            state="disabled",
            command=self._toggle_pause
        )
        self.btn_resume.pack(side="left", padx=5)

        self.btn_stop = ttk.Button(
            ctrl_frame,
            text="Stop",
            state="disabled",
            command=self._on_stop
        )
        self.btn_stop.pack(side="left", padx=5)

        # ─── Notebook with tabs ───────────────────────────────────────────────────
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # 1) Config tab
        self.tab_config = ConfigTab(self.notebook)

        # 2) Scans tab
        self.tab_scans = ScansTab(
            self.notebook,
            self.db_conn,
            fetch_scans,
            fetch_logs
        )

        # 3) Interactive Overview tab
        self.tab_overview = InteractiveOverviewTab(self.notebook, self.db_conn)

        # 4) Logs tab
        self.tab_logs = LogsTab(
            self.notebook,
            self.db_conn,
            fetch_scans,
            fetch_logs
        )

        # 5) Database tab (browse any table)
        from database import fetch_table
        self.tab_database = DatabaseTab(
            self.notebook,
            self.db_conn,
            fetch_table
        )

        # 6) Wordlist Generator tab (now using fetch_domains)
        self.tab_wordgen = WordGenTab(
            self.notebook,
            self.db_conn,
            fetch_domains,            # ← use newly added helper
            insert_custom_wordlist,
            self.log_queue,
            lambda msg, kind: show_timed_popup(self, msg, kind=kind)
        )

        # Add tabs in order
        self.notebook.add(self.tab_config, text="Config")
        self.notebook.add(self.tab_scans, text="Scans")
        self.notebook.add(self.tab_overview, text="Overview")
        self.notebook.add(self.tab_logs, text="Logs")
        self.notebook.add(self.tab_database, text="Database")
        self.notebook.add(self.tab_wordgen, text="Wordlist Generator")

        # ─── Auto‐refresh on tab change ────────────────────────────────────────────
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

    def _on_tab_changed(self, event):
        """
        Whenever the user switches to a new tab, call that tab’s refresh method if it exists.
        This triggers auto‐refresh for Scans, Overview, and Logs.
        """
        selected = self.notebook.select()
        widget = self.nametowidget(selected)
        # If the widget has a 'refresh_scans' method, call it
        if hasattr(widget, "refresh_scans"):
            widget.refresh_scans()
        # If it has '_reload_scans' (Overview or Logs), call that:
        elif hasattr(widget, "_reload_scans"):
            widget._reload_scans()

    def _toggle_pause(self):
        if not self.pause_event.is_set():
            self.pause_event.set()
            self.btn_pause.config(state="disabled")
            self.btn_resume.config(state="normal")
            log_message(self.db_conn, None, "[⋯] User pressed “Pause”")
            self.tab_logs._catchall_append("[⋯] Paused by user")
            show_timed_popup(self, "Scan paused", kind="info")
        else:
            self.pause_event.clear()
            self.btn_resume.config(state="disabled")
            self.btn_pause.config(state="normal")
            log_message(self.db_conn, None, "[⋯] User pressed “Resume”")
            self.tab_logs._catchall_append("[⋯] Resumed by user")
            show_timed_popup(self, "Scan resumed", kind="info")

    def _on_stop(self):
        if not self.stop_event.is_set():
            self.stop_event.set()
            log_message(self.db_conn, None, "[!] User pressed “Stop”")
            self.tab_logs._catchall_append("[!] Stopping scan…")
            show_timed_popup(self, "Scan stopped by user", kind="error")
            self.btn_stop.config(state="disabled")
            self.btn_pause.config(state="disabled")
            self.btn_resume.config(state="disabled")
            self.btn_start.config(state="normal")

    def _on_start_scan(self):
        """
        Called when the user clicks 'Start Scan'.
        Builds a scan name = domain-wordlistbasename-timestamp,
        inserts it into the DB, then kicks off the background worker.
        """
        cfg = self.tab_config
        domain = cfg.entry_domain.get().strip()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain before starting a scan.")
            return

        subwl_path = cfg.entry_subwl.get().strip()
        wl_basename = os.path.basename(subwl_path) if subwl_path else "no-subwl"
        timestamp = int(time.time())
        scan_name = f"{domain}-{wl_basename}-{timestamp}"

        # Insert new scan
        scan_id = create_scan(self.db_conn, scan_name)
        log_message(self.db_conn, scan_id, f"[+] Scan '{scan_name}' created (ID={scan_id})")

        # Enable Pause/Stop, disable Start
        self.btn_start.config(state="disabled")
        self.btn_pause.config(state="normal")
        self.btn_stop.config(state="normal")

        # Refresh across all relevant tabs
        self.tab_scans.refresh_scans()
        self.tab_overview._reload_scans()
        self.tab_logs._reload_scans()

        # Start the background thread for this scan
        t = threading.Thread(
            target=self._scan_worker,
            args=(scan_id, domain, subwl_path),
            daemon=True
        )
        t.start()

    def _scan_worker(self, scan_id, domain, subwl_path):
        """
        Background worker that performs:
          1) DNS brute‐force (if enabled)
          2) Directory + File discovery (if enabled)
          3) Updates the DB and logs at each stage.
        """
        cfg = self.tab_config

        # --- DNS Brute‐Force Stage ---
        log_message(self.db_conn, scan_id, "[⋯] Starting DNS brute‐force stage…")
        try:
            sub_words = load_wordlist(subwl_path)
            log_message(self.db_conn, scan_id, f"[⋯] Loaded {len(sub_words)} subdomain words from '{subwl_path}'")
        except Exception as e:
            sub_words = []
            log_message(self.db_conn, scan_id, f"[!] Failed to load subdomain wordlist '{subwl_path}': {e}")

        if cfg.var_dns.get():
            def dns_cb(processed, total):
                log_message(self.db_conn, scan_id, f"[⋯] DNS progress: {processed}/{total}")
                self.tab_scans.update_progress(scan_id, processed, total)

            def on_host_found(hostname):
                # Insert into subdomains table, then log
                domain_id = insert_domain(self.db_conn, scan_id, domain, {})
                sub_id = insert_subdomain(self.db_conn, scan_id, domain_id, hostname, None)
                log_message(self.db_conn, scan_id, f"[+] Found subdomain: {hostname}")
                return sub_id

            dns_bruteforce_incremental(
                domain,
                sub_words,
                int(cfg.spin_threads.get()),
                float(cfg.spin_timeout.get()),
                int(cfg.scale_delay.get()),
                self.pause_event,
                self.stop_event,
                self.log_queue,
                on_host_found=on_host_found,
                dns_progress_cb=dns_cb
            )
            log_message(self.db_conn, scan_id, "[⋯] DNS brute‐force stage completed.")
        else:
            log_message(self.db_conn, scan_id, "[⋯] Skipping DNS stage (disabled).")

        # --- Directory + File Discovery Stage ---
        if cfg.var_dir.get():
            subs = fetch_subdomains_by_scan(self.db_conn, scan_id)
            log_message(self.db_conn, scan_id, f"[⋯] Starting directory discovery on {len(subs)} subdomains…")

            for subdomain, _ in subs:
                domain_id = insert_domain(self.db_conn, scan_id, domain, {})
                sub_id = insert_subdomain(self.db_conn, scan_id, domain_id, subdomain, None)
                log_message(self.db_conn, scan_id, f"[⋯] Beginning directory discovery for '{subdomain}'")

                # Load directory wordlist
                dirwl_path = cfg.entry_dirwl.get().strip()
                try:
                    dir_words = load_wordlist(dirwl_path)
                    log_message(self.db_conn, scan_id, f"[⋯] Loaded {len(dir_words)} directory words from '{dirwl_path}'")
                except Exception as e:
                    dir_words = []
                    log_message(self.db_conn, scan_id, f"[!] Failed to load directory wordlist '{dirwl_path}': {e}")

                # Kick off recursive discovery for this host
                for path, status in discover_paths_for_host(
                    subdomain,
                    scan_id,
                    dir_words,
                    [e.strip() for e in cfg.entry_exts.get().split(",") if e.strip()] if cfg.var_content.get() else [],
                    int(cfg.spin_maxdepth.get()),
                    int(cfg.spin_threads.get()),
                    float(cfg.spin_timeout.get()),
                    int(cfg.scale_delay.get()),
                    self.pause_event,
                    self.stop_event,
                    self.log_queue,
                    lambda p, t, h=subdomain: self.tab_scans.update_subdomain_progress(scan_id, h, p, t),
                    self.db_conn,
                    lambda conn, sid, directory, code: (
                        insert_directory(conn, scan_id, sub_id, directory, code),
                        log_message(conn, scan_id, f"[+] Directory found on '{subdomain}': {directory} (status={code})")
                    ),
                    lambda conn, sid, file_url, code: (
                        insert_file(conn, scan_id, sub_id, file_url, code),
                        log_message(conn, scan_id, f"[+] File found on '{subdomain}': {file_url} (status={code})")
                    )
                ):
                    pass  # loop fully drives recursion

                log_message(self.db_conn, scan_id, f"[⋯] Completed directory discovery for '{subdomain}'")

            log_message(self.db_conn, scan_id, "[⋯] Directory & file discovery stage completed.")
        else:
            log_message(self.db_conn, scan_id, "[⋯] Skipping directory discovery (disabled).")

        # --- Finalize scan ---
        update_scan_status(self.db_conn, scan_id, "completed")
        log_message(self.db_conn, scan_id, "[★] Scan completed.")
        self.btn_start.config(state="normal")
        self.btn_pause.config(state="disabled")
        self.btn_resume.config(state="disabled")
        self.btn_stop.config(state="disabled")

        # Refresh relevant tabs
        self.tab_scans.refresh_scans()
        self.tab_overview._reload_scans()
        self.tab_logs._reload_scans()

    def _poll_log_queue(self):
        """
        Drain the log_queue (sent by background threads) and:
          1) Persist each message into logging table (scan_id=None) as a catch‐all.
          2) Append it in the Logs tab if that scan is currently selected.
        """
        try:
            while True:
                msg = self.log_queue.get_nowait()
                if msg:
                    log_message(self.db_conn, None, msg)
                    self.tab_logs._catchall_append(msg)
        except:
            pass
        self.after(100, self._poll_log_queue)

    def _on_close(self):
        """
        Called when the user clicks the window’s “X”:
          - Ensure ConfigTab saves its settings.json
          - Then destroy the root window.
        """
        try:
            self.tab_config._save_settings()
        except:
            pass
        self.destroy()


def main():
    if len(sys.argv) > 1:
        from run_cli import run_cli
        run_cli()
    else:
        app = ReconApp()
        app.mainloop()


if __name__ == "__main__":
    main()
