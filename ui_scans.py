import tkinter as tk
from tkinter import ttk, scrolledtext

class ScansTab(ttk.Frame):
    """
    "Scans" tab:
      - List all scans in a Treeview (id, name, status, start_time).
      - Selecting a scan shows its logs in a scrolled text box.
      - Show DNS + Subdomain progress bars.
      - Manual "Refresh" button + auto‐refresh on tab change (handled by ReconApp).
    """
    def __init__(self, parent, db_conn, fetch_scans_fn, fetch_logs_fn):
        super().__init__(parent)
        self.db_conn = db_conn
        self.fetch_scans = fetch_scans_fn
        self.fetch_logs   = fetch_logs_fn
        pad = {"padx": 5, "pady": 5}

        # 1) Refresh button
        self.btn_refresh = ttk.Button(self, text="Refresh", command=self.refresh_scans)
        self.btn_refresh.grid(row=0, column=0, sticky="w", **pad)

        # 1a) DNS Progress Label & Progressbar
        self.lbl_dns = ttk.Label(self, text="DNS Progress:")
        self.lbl_dns.grid(row=0, column=1, sticky="e", **pad)
        self.dns_prog = ttk.Progressbar(self,
                                        orient="horizontal",
                                        mode="determinate",
                                        length=200)
        self.dns_prog.grid(row=0, column=2, sticky="w", **pad)

        # 1b) Subdomain Progress Label & Progressbar
        self.lbl_sub = ttk.Label(self, text="Subdomain Progress:")
        self.lbl_sub.grid(row=1, column=1, sticky="e", **pad)
        self.sub_prog = ttk.Progressbar(self,
                                        orient="horizontal",
                                        mode="determinate",
                                        length=200)
        self.sub_prog.grid(row=1, column=2, sticky="w", **pad)

        # 2) Treeview of scans (id, name, status, start_time)
        self.tree_scans = ttk.Treeview(
            self,
            columns=("id", "name", "status", "start_time"),
            show="headings"
        )
        self.tree_scans.heading("id", text="ID")
        self.tree_scans.heading("name", text="Name")
        self.tree_scans.heading("status", text="Status")
        self.tree_scans.heading("start_time", text="Started At")
        self.tree_scans.column("id", width=40)
        self.tree_scans.column("name", width=300)
        self.tree_scans.column("status", width=100)
        self.tree_scans.column("start_time", width=150)
        self.tree_scans.grid(row=2, column=0, columnspan=3, sticky="nsew", **pad)

        # Vertical scrollbar for the Treeview
        vsb_scans = ttk.Scrollbar(self, orient="vertical", command=self.tree_scans.yview)
        self.tree_scans.configure(yscrollcommand=vsb_scans.set)
        vsb_scans.grid(row=2, column=3, sticky="ns", **pad)

        # 3) Logs for selected scan
        ttk.Label(self, text="Logs for Selected Scan:").grid(
            row=3, column=0, columnspan=1, sticky="w", **pad
        )
        self.txt_logs = scrolledtext.ScrolledText(
            self,
            wrap="word",
            state="disabled",
            height=10
        )
        self.txt_logs.grid(row=4, column=0, columnspan=3, sticky="nsew", **pad)

        # Configure resizing behavior
        self.rowconfigure(2, weight=1)
        self.rowconfigure(4, weight=1)
        self.columnconfigure(2, weight=1)

        # Bind selection event so that when a user clicks a scan, its logs load
        self.tree_scans.bind("<<TreeviewSelect>>", self._on_scan_select)

        # Initial population of scans and logs
        self.refresh_scans()

    def refresh_scans(self):
        """
        Populate the scans Treeview and clear logs/ reset progress bars.
        Called manually (Refresh button) or via auto‐refresh from ReconApp.
        """
        # Clear existing items
        for item in self.tree_scans.get_children():
            self.tree_scans.delete(item)

        # Fetch scans and insert into Treeview
        scans = self.fetch_scans(self.db_conn)
        for s in scans:
            self.tree_scans.insert(
                "",
                "end",
                values=(s[0], s[1], s[2], s[3])
            )

        # Reset progress bars and logs area
        self.dns_prog["value"] = 0
        self.sub_prog["value"] = 0
        self.txt_logs.config(state="normal")
        self.txt_logs.delete("1.0", tk.END)
        self.txt_logs.config(state="disabled")

    def _on_scan_select(self, event):
        """
        Load and display all logs for the selected scan_id in the ScrolledText.
        """
        selected = self.tree_scans.selection()
        if not selected:
            return
        scan_id = int(self.tree_scans.item(selected[0], "values")[0])
        logs = self.fetch_logs(self.db_conn, scan_id)

        self.txt_logs.config(state="normal")
        self.txt_logs.delete("1.0", tk.END)
        for ts, msg in logs:
            self.txt_logs.insert(tk.END, f"[{ts}] {msg}\n")
        self.txt_logs.config(state="disabled")

    def update_progress(self, scan_id, processed, total):
        """
        Update DNS progress bar based on how many subdomain words have been processed.
        Called by dns_progress_cb from the scan worker.
        """
        if total:
            self.dns_prog["maximum"] = total
            self.dns_prog["value"] = processed

    def update_subdomain_progress(self, scan_id, host, processed, total):
        """
        Update Subdomain progress bar based on how many directory paths have been checked for a given host.
        Called by host‐level callback in the discovery worker.
        """
        if total:
            self.sub_prog["maximum"] = total
            self.sub_prog["value"] = processed
