import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pandas as pd
from database import fetch_subdomains_by_scan, fetch_directories_by_scan, fetch_files_by_scan, fetch_scans

class InteractiveOverviewTab(ttk.Frame):
    """
    “Overview” tab: choose a scan, then see all subdomains / directories / files.
    Includes a manual “Refresh” button + auto‐refresh when tab is opened.
    """
    def __init__(self, parent, db_conn):
        super().__init__(parent)
        self.db_conn = db_conn
        pad = {"padx": 5, "pady": 5}

        # 1) Scan dropdown + Refresh button
        ttk.Label(self, text="Select Scan:", font=("Segoe UI", 10, "bold")).grid(
            row=0, column=0, sticky="w", **pad
        )
        self.combo_scans = ttk.Combobox(self, values=[], state="readonly", width=50)
        self.combo_scans.grid(row=0, column=1, sticky="w", **pad)
        self.combo_scans.bind("<<ComboboxSelected>>", lambda e: self._load_scan_data())

        self.btn_refresh = ttk.Button(self, text="Refresh", command=self._reload_scans)
        self.btn_refresh.grid(row=0, column=2, sticky="w", **pad)

        # 2) Filter by status code (optional)
        ttk.Label(self, text="Filter HTTP Status:", font=("Segoe UI", 10)).grid(
            row=1, column=0, sticky="w", **pad
        )
        self.entry_status = ttk.Entry(self, width=10)
        self.entry_status.grid(row=1, column=1, sticky="w", **pad)

        # 3) Treeview to list “type / host / path / status”
        self.tree = ttk.Treeview(
            self,
            columns=("type", "host", "path", "status"),
            show="headings",
            height=20
        )
        self.tree.heading("type", text="Type")
        self.tree.heading("host", text="Host/Subdomain")
        self.tree.heading("path", text="Directory/File")
        self.tree.heading("status", text="HTTP Status")
        self.tree.column("type", width=100)
        self.tree.column("host", width=200)
        self.tree.column("path", width=300)
        self.tree.column("status", width=100)
        self.tree.grid(row=2, column=0, columnspan=3, sticky="nsew", **pad)

        # Vertical scrollbar
        vsb = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.grid(row=2, column=3, sticky="ns", **pad)

        # 4) “Export CSV” button
        self.btn_export = ttk.Button(self, text="Export as CSV", state="disabled", command=self._export_csv)
        self.btn_export.grid(row=3, column=0, columnspan=2, sticky="w", **pad)

        # Configure resizing
        self.rowconfigure(2, weight=1)
        self.columnconfigure(2, weight=1)

        # Initial load
        self._reload_scans()

    def _reload_scans(self):
        """
        Populate combobox with all scans (id: name). Called on tab‐change or Refresh click.
        """
        scans = fetch_scans(self.db_conn)
        display = [f"{s[0]}: {s[1]}" for s in scans]
        self.combo_scans["values"] = display
        if display:
            # auto‐select the most recent
            self.combo_scans.current(0)
            self._load_scan_data()
        else:
            # Clear tree & disable export if no scans
            self.tree.delete(*self.tree.get_children())
            self.btn_export.config(state="disabled")

    def _load_scan_data(self):
        """
        For the selected scan, fetch its subdomains / directories / files and list them.
        """
        sel = self.combo_scans.get()
        if not sel:
            return
        scan_id = int(sel.split(":")[0])
        status_filter = self.entry_status.get().strip()
        status_val = int(status_filter) if status_filter.isdigit() else None

        # Clear previous rows
        self.tree.delete(*self.tree.get_children())

        # 1) Subdomains
        subs = fetch_subdomains_by_scan(self.db_conn, scan_id)
        for sub, code in subs:
            if status_val is not None and code == status_val:
                continue
            self.tree.insert("", "end", values=("subdomain", sub, "", code))

        # 2) Directories
        dirs = fetch_directories_by_scan(self.db_conn, scan_id, status_filter=status_val)
        for sub, directory, code in dirs:
            if status_val is not None and code == status_val:
                continue
            self.tree.insert("", "end", values=("directory", sub, directory, code))

        # 3) Files
        files = fetch_files_by_scan(self.db_conn, scan_id, status_filter=status_val)
        for sub, file_url, code in files:
            if status_val is not None and code == status_val:
                continue
            self.tree.insert("", "end", values=("file", sub, file_url, code))

        self.btn_export.config(state="normal")

    def _export_csv(self):
        sel = self.combo_scans.get()
        if not sel:
            return
        scan_id = int(sel.split(":")[0])
        status_filter = self.entry_status.get().strip()
        status_val = int(status_filter) if status_filter.isdigit() else None

        rows = []
        subs = fetch_subdomains_by_scan(self.db_conn, scan_id)
        for sub, code in subs:
            if status_val is not None and code == status_val:
                continue
            rows.append({"type": "subdomain", "host": sub, "path": "", "status": code})
        dirs = fetch_directories_by_scan(self.db_conn, scan_id, status_filter=status_val)
        for sub, directory, code in dirs:
            if status_val is not None and code == status_val:
                continue
            rows.append({"type": "directory", "host": sub, "path": directory, "status": code})
        files = fetch_files_by_scan(self.db_conn, scan_id, status_filter=status_val)
        for sub, file_url, code in files:
            if status_val is not None and code == status_val:
                continue
            rows.append({"type": "file", "host": sub, "path": file_url, "status": code})

        df = pd.DataFrame(rows)
        path = filedialog.asksaveasfilename(
            title="Save Overview CSV",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*")],
            defaultextension=".csv"
        )
        if not path:
            return
        try:
            df.to_csv(path, index=False)
            messagebox.showinfo("Export Successful", f"Overview exported to {path}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export: {e}")
