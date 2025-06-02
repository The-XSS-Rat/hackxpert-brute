import tkinter as tk
from tkinter import ttk, scrolledtext

class WordGenTab(ttk.Frame):
    """
    “Wordlist Generator” tab: let user pick a domain, enter keywords,
    insert into customWordlists table, and display them.
    """
    def __init__(self, parent, db_conn, fetch_domains_fn, insert_custom_fn, log_queue, popup_fn):
        super().__init__(parent)
        self.db_conn = db_conn
        pad = {"padx": 5, "pady": 5}

        ttk.Label(self, text="Select Domain:", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="e", **pad)
        self.combo_domains = ttk.Combobox(self, state="readonly")
        self.combo_domains.grid(row=0, column=1, sticky="w", **pad)

        ttk.Label(self, text="Enter Keywords (space-separated):").grid(row=1, column=0, sticky="e", **pad)
        self.entry_keywords = ttk.Entry(self, width=40)
        self.entry_keywords.grid(row=1, column=1, sticky="w", **pad)

        self.btn_generate = ttk.Button(self, text="Generate Wordlist")
        self.btn_generate.grid(row=2, column=0, columnspan=2, pady=10)

        ttk.Label(self, text="Generated Words:", font=("Segoe UI", 10, "bold")).grid(row=3, column=0, columnspan=2, sticky="w", **pad)
        self.txt_wordlist = scrolledtext.ScrolledText(self, wrap="word", state="disabled", height=10)
        self.txt_wordlist.grid(row=4, column=0, columnspan=2, sticky="nsew", **pad)
        self.rowconfigure(4, weight=1)
        self.columnconfigure(1, weight=1)

        self.fetch_domains_fn = fetch_domains_fn
        self.insert_custom_fn = insert_custom_fn
        self.log_queue = log_queue
        self.popup_fn = popup_fn

        self._refresh_domains()
        self.btn_generate.config(command=self._on_generate)

    def _refresh_domains(self):
        domains = self.fetch_domains_fn(self.db_conn)
        domain_names = [d[1] for d in domains]
        self.combo_domains["values"] = domain_names
        if domain_names:
            self.combo_domains.current(0)

    def _on_generate(self):
        domain_name = self.combo_domains.get()
        if not domain_name:
            self.log_queue.put("[!] No domain selected for wordlist generation.")
            self.popup_fn("Select a domain first.", "error")
            return
        entry = self.entry_keywords.get().strip()
        if not entry:
            self.log_queue.put("[!] No keywords entered.")
            self.popup_fn("Enter keywords first.", "error")
            return
        c = self.db_conn.cursor()
        c.execute("SELECT id FROM domains WHERE domain = ?", (domain_name,))
        row = c.fetchone()
        if not row:
            self.log_queue.put(f"[!] Domain '{domain_name}' not found in DB.")
            self.popup_fn("Domain not in database.", "error")
            return
        domain_id = row[0]
        keywords = entry.split()
        inserted = 0
        for kw in keywords:
            self.insert_custom_fn(self.db_conn, domain_id, kw)
            inserted += 1
        self.txt_wordlist.config(state="normal")
        self.txt_wordlist.delete("1.0", tk.END)
        self.txt_wordlist.insert("end", "\n".join(keywords))
        self.txt_wordlist.config(state="disabled")
        self.log_queue.put(f"[+] Generated and inserted {inserted} keywords for '{domain_name}'.")
        self.popup_fn(f"{inserted} keywords inserted", "confirm")
