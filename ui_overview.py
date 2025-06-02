import tkinter as tk
from tkinter import ttk

class HostFrame(ttk.Frame):
    """
    Represents one discovered host’s progress:
      • Hostname label
      • Progress bar
      • Status label
    """
    def __init__(self, parent, host, total_paths):
        super().__init__(parent)
        self.host = host
        self.total_paths = total_paths
        self.columnconfigure(1, weight=1)

        self.lbl = ttk.Label(self, text=host, font=("Segoe UI", 10, "bold"))
        self.lbl.grid(row=0, column=0, sticky="w", padx=5)

        self.prog = ttk.Progressbar(
            self, orient="horizontal", mode="determinate",
            maximum=total_paths, length=200
        )
        self.prog.grid(row=0, column=1, sticky="ew", padx=5)

        self.status = ttk.Label(self, text="Queued", font=("Segoe UI", 9))
        self.status.grid(row=0, column=2, sticky="e", padx=5)

    def update_progress(self, processed, total):
        self.prog["maximum"] = total
        self.prog["value"] = processed
        self.status.config(text=f"{processed}/{total}")

    def mark_scanning(self):
        self.status.config(text="Scanning…")

    def mark_done(self, count):
        self.prog["value"] = self.total_paths
        self.status.config(text=f"Done ({count} items)")

class OverviewTab(ttk.Frame):
    """
    “Overview” tab: dynamic list of HostFrame entries
    """
    def __init__(self, parent):
        super().__init__(parent)
        pad = {"padx": 5, "pady": 5}
        ttk.Label(self, text="Hosts Scanning Status:", font=("Segoe UI", 11, "bold")).pack(anchor="w", **pad)

        hosts_container = ttk.LabelFrame(self, text="Hosts")
        hosts_container.pack(fill="both", expand=True, padx=10, pady=5)

        canvas = tk.Canvas(hosts_container)
        scrollbar = ttk.Scrollbar(hosts_container, orient="vertical", command=canvas.yview)
        self.hosts_frame = ttk.Frame(canvas)

        self.hosts_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=self.hosts_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
