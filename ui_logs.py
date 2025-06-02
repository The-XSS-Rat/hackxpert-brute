import tkinter as tk
from tkinter import ttk, scrolledtext

class LogsTab(ttk.Frame):
    """
    “Logs” tab: per‐scan dropdown + full history of all log lines for that scan.
    Includes a manual “Refresh” button + auto‐refresh on tab change.
    """
    def __init__(self, parent, db_conn, fetch_scans_fn, fetch_logs_fn):
        super().__init__(parent)
        self.db_conn = db_conn
        self.fetch_scans = fetch_scans_fn
        self.fetch_logs = fetch_logs_fn
        pad = {"padx": 5, "pady": 5}

        # 1) Combobox of all scans + Refresh button
        ttk.Label(self, text="Select Scan:", font=("Segoe UI", 10, "bold")).grid(
            row=0, column=0, sticky="w", **pad
        )
        self.combo_scans = ttk.Combobox(self, values=[], state="readonly", width=50)
        self.combo_scans.grid(row=0, column=1, sticky="w", **pad)
        self.combo_scans.bind("<<ComboboxSelected>>", self._on_scan_select)

        self.btn_refresh = ttk.Button(self, text="Refresh", command=self._reload_scans)
        self.btn_refresh.grid(row=0, column=2, sticky="w", **pad)

        # 2) ScrolledText with all log lines (for whichever scan is chosen)
        self.txt_log = scrolledtext.ScrolledText(self, wrap="word", state="disabled", height=20)
        self.txt_log.grid(row=1, column=0, columnspan=3, sticky="nsew", **pad)

        # Configure resizing
        self.rowconfigure(1, weight=1)
        self.columnconfigure(2, weight=1)

        # Load scan list initially
        self._reload_scans()

    def _reload_scans(self):
        """
        Fetch all scans, then populate combo_scans with “id: name” labels.
        Called on tab‐change or Refresh click.
        """
        self.combo_scans.set("")  # clear
        all_scans = self.fetch_scans(self.db_conn)
        # Each scan row is (id, name, status, start_time)
        display = [f"{s[0]}: {s[1]}" for s in all_scans]
        self.combo_scans["values"] = display
        if display:
            # auto‐select the most recent
            self.combo_scans.current(0)
            self._on_scan_select()

    def _on_scan_select(self, event=None):
        """
        Load logs from the selected scan_id, display them in txt_log.
        """
        sel = self.combo_scans.get()
        if not sel:
            return
        scan_id = int(sel.split(":")[0])

        # Fetch all log lines for that scan_id
        logs = self.fetch_logs(self.db_conn, scan_id)

        self.txt_log.config(state="normal")
        self.txt_log.delete("1.0", tk.END)
        for ts, msg in logs:
            self.txt_log.insert(tk.END, f"[{ts}] {msg}\n")
        self.txt_log.config(state="disabled")

    def _catchall_append(self, text):
        """
        Append to whichever scan is currently selected so the user sees real‐time updates.
        """
        sel = self.combo_scans.get()
        if not sel:
            return
        # We assume 'text' has already been log_message()‐ed to the DB,
        # so just append it here in real time.
        self.txt_log.config(state="normal")
        self.txt_log.insert(tk.END, text + "\n")
        self.txt_log.see("end")
        self.txt_log.config(state="disabled")
