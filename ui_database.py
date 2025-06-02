import tkinter as tk
from tkinter import ttk

class DatabaseTab(ttk.Frame):
    """
    “Database” tab: dropdown of all tables + Treeview to display contents
    """
    def __init__(self, parent, db_conn, fetch_table_fn):
        super().__init__(parent)
        self.db_conn = db_conn
        pad = {"padx": 5, "pady": 5}

        ttk.Label(
            self,
            text="Select Table:",
            font=("Segoe UI", 10, "bold")
        ).grid(row=0, column=0, sticky="w", **pad)

        # Expose every table in the dropdown
        self.combo_tables = ttk.Combobox(
            self,
            values=[
                "scans",
                "logging",
                "domains",
                "subdomains",
                "directories",
                "files",
                "customWordlists"
            ],
            state="readonly"
        )
        self.combo_tables.grid(row=0, column=1, sticky="w", **pad)
        self.combo_tables.bind("<<ComboboxSelected>>", self._update_db_view)

        # Treeview to show selected table’s contents
        self.tree_db = ttk.Treeview(self)
        self.tree_db.grid(row=1, column=0, columnspan=2, sticky="nsew", **pad)
        self.rowconfigure(1, weight=1)
        self.columnconfigure(1, weight=1)

        # Vertical scrollbar
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.tree_db.yview)
        self.tree_db.configure(yscrollcommand=scrollbar.set)
        scrollbar.grid(row=1, column=2, sticky="ns", **pad)

        self.fetch_table_fn = fetch_table_fn

    def _update_db_view(self, event):
        table = self.combo_tables.get()
        colnames, rows = self.fetch_table_fn(self.db_conn, table)

        # Clear any existing rows & columns
        for item in self.tree_db.get_children():
            self.tree_db.delete(item)

        self.tree_db["columns"] = colnames
        self.tree_db["show"] = "headings"

        for col in colnames:
            self.tree_db.heading(col, text=col)
            self.tree_db.column(col, width=100, anchor="w")

        for row in rows:
            self.tree_db.insert("", "end", values=row)
