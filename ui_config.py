import tkinter as tk
from tkinter import ttk, filedialog
import json
import os


class ConfigTab(ttk.Frame):
    """
    “Config” tab: all scan parameters
    Remembers last-used domain, subdomain-wordlist path, and dir-wordlist path in settings.json.
    """
    SETTINGS_PATH = os.path.join(os.path.dirname(__file__), "settings.json")

    def __init__(self, parent):
        super().__init__(parent)
        pad = {"padx": 5, "pady": 5}

        # Domain
        ttk.Label(self, text="Domain (e.g. sub.example.com):").grid(
            row=0, column=0, sticky="e", **pad
        )
        self.entry_domain = ttk.Entry(self, width=40)
        self.entry_domain.grid(row=0, column=1, columnspan=2, sticky="w", **pad)
        note = ttk.Label(
            self,
            text="(Enter only domain/subdomain, no URLs)",
            foreground="gray",
        )
        note.grid(row=1, column=1, columnspan=2, sticky="w", **pad)

        # Subdomain wordlist
        ttk.Label(self, text="Subdomain Wordlist:").grid(
            row=2, column=0, sticky="e", **pad
        )
        self.entry_subwl = ttk.Entry(self, width=30)
        self.entry_subwl.grid(row=2, column=1, sticky="w", **pad)
        self.btn_browse_sub = ttk.Button(
            self, text="Browse…", command=self._browse_subwl
        )
        self.btn_browse_sub.grid(row=2, column=2, **pad)

        # Directory wordlist
        ttk.Label(self, text="Dir/File Wordlist:").grid(
            row=3, column=0, sticky="e", **pad
        )
        self.entry_dirwl = ttk.Entry(self, width=30)
        self.entry_dirwl.grid(row=3, column=1, sticky="w", **pad)
        self.btn_browse_dir = ttk.Button(
            self, text="Browse…", command=self._browse_dirwl
        )
        self.btn_browse_dir.grid(row=3, column=2, **pad)

        # Extensions
        ttk.Label(self, text="Extensions:").grid(row=4, column=0, sticky="e", **pad)
        self.entry_exts = ttk.Entry(self, width=30)
        self.entry_exts.insert(0, ".php,.html")
        self.entry_exts.grid(row=4, column=1, columnspan=2, sticky="w", **pad)

        # Max depth (lower bound back to 1)
        ttk.Label(self, text="Max Depth:").grid(row=5, column=0, sticky="e", **pad)
        self.spin_maxdepth = ttk.Spinbox(self, from_=1, to=10, width=5)
        self.spin_maxdepth.set("3")
        self.spin_maxdepth.grid(row=5, column=1, sticky="w", **pad)

        # Threads
        ttk.Label(self, text="Threads:").grid(row=5, column=2, sticky="e", **pad)
        self.spin_threads = ttk.Spinbox(self, from_=1, to=100, width=5)
        self.spin_threads.set("20")
        self.spin_threads.grid(row=5, column=3, sticky="w", **pad)

        # Timeout
        ttk.Label(self, text="Timeout (sec):").grid(row=6, column=0, sticky="e", **pad)
        self.spin_timeout = ttk.Spinbox(self, from_=1, to=60, width=5)
        self.spin_timeout.set("5")
        self.spin_timeout.grid(row=6, column=1, sticky="w", **pad)

        # Delay slider
        ttk.Label(self, text="Delay (ms):").grid(row=6, column=2, sticky="e", **pad)
        self.scale_delay = ttk.Scale(self, from_=0, to=2000, orient="horizontal")
        self.scale_delay.set(100)
        self.scale_delay.grid(row=6, column=3, sticky="ew", **pad)

        # Checkboxes
        self.var_dns = tk.BooleanVar(value=True)
        self.var_dir = tk.BooleanVar(value=True)
        self.var_content = tk.BooleanVar(value=True)
        chk_dns = ttk.Checkbutton(
            self, text="Enable DNS Brute-Force", variable=self.var_dns
        )
        chk_dns.grid(row=7, column=0, columnspan=2, sticky="w", **pad)
        chk_dir = ttk.Checkbutton(
            self, text="Enable Directory Discovery", variable=self.var_dir
        )
        chk_dir.grid(row=7, column=2, columnspan=2, sticky="w", **pad)
        chk_content = ttk.Checkbutton(
            self, text="Enable File/Content Checks", variable=self.var_content
        )
        chk_content.grid(row=8, column=0, columnspan=2, sticky="w", **pad)

        # Load any existing settings from disk
        self._load_settings()

        # Whenever any of these three change, immediately re-save to disk
        self.entry_domain.bind("<FocusOut>", lambda e: self._save_settings())
        self.entry_subwl.bind("<FocusOut>", lambda e: self._save_settings())
        self.entry_dirwl.bind("<FocusOut>", lambda e: self._save_settings())

    def _browse_subwl(self):
        """
        Open a file dialog to select a subdomain wordlist file,
        then insert the chosen path into entry_subwl and save settings.
        """
        path = filedialog.askopenfilename(
            title="Select Subdomain Wordlist",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
        )
        if path:
            self.entry_subwl.delete(0, tk.END)
            self.entry_subwl.insert(0, path)
            self._save_settings()

    def _browse_dirwl(self):
        """
        Open a file dialog to select a directory/file wordlist file,
        then insert the chosen path into entry_dirwl and save settings.
        """
        path = filedialog.askopenfilename(
            title="Select Directory/File Wordlist",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
        )
        if path:
            self.entry_dirwl.delete(0, tk.END)
            self.entry_dirwl.insert(0, path)
            self._save_settings()

    def _load_settings(self):
        """
        Load previous domain, subwl path, and dirwl path from settings.json.
        """
        try:
            with open(self.SETTINGS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            if "domain" in data:
                self.entry_domain.delete(0, tk.END)
                self.entry_domain.insert(0, data["domain"])
            if "subwl" in data:
                self.entry_subwl.delete(0, tk.END)
                self.entry_subwl.insert(0, data["subwl"])
            if "dirwl" in data:
                self.entry_dirwl.delete(0, tk.END)
                self.entry_dirwl.insert(0, data["dirwl"])
        except Exception:
            pass  # silently ignore if no file or malformed

    def _save_settings(self):
        """
        Write current domain, subwl path, and dirwl path to settings.json.
        """
        data = {
            "domain": self.entry_domain.get().strip(),
            "subwl": self.entry_subwl.get().strip(),
            "dirwl": self.entry_dirwl.get().strip(),
        }
        try:
            with open(self.SETTINGS_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass  # silently ignore if write fails
