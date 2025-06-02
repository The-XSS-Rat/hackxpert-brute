import sqlite3
import json
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "recon.db")


def init_database():
    """
    Initialize (or migrate) SQLite database with tables:
      - scans: id, name, start_time, status
      - logging: id, scan_id, timestamp, message
      - domains: id, scan_id, domain, params_json, timestamp
      - subdomains: id, scan_id, domain_id, subdomain, status_code, timestamp
      - directories: id, scan_id, subdomain_id, directory, status_code, timestamp
      - files: id, scan_id, subdomain_id, file_url, status_code, timestamp
      - customWordlists: id, domain_id, keyword, timestamp

    Any missing columns (scan_id or status_code) in older tables are added via ALTER TABLE.
    """
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    c = conn.cursor()

    # ─── Create tables if they don't exist ──────────────────────────────────────

    # scans table
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT
        )
        """
    )

    # logging table
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS logging (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            message TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
        """
    )

    # domains table (per scan)
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            domain TEXT,
            params_json TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
        """
    )

    # subdomains table (may exist missing scan_id or status_code)
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS subdomains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            domain_id INTEGER,
            subdomain TEXT,
            status_code INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(scan_id) REFERENCES scans(id),
            FOREIGN KEY(domain_id) REFERENCES domains(id)
        )
        """
    )

    # directories table (may exist missing scan_id or status_code)
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS directories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            subdomain_id INTEGER,
            directory TEXT,
            status_code INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(scan_id) REFERENCES scans(id),
            FOREIGN KEY(subdomain_id) REFERENCES subdomains(id)
        )
        """
    )

    # files table (may exist missing scan_id or status_code)
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            subdomain_id INTEGER,
            file_url TEXT,
            status_code INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(scan_id) REFERENCES scans(id),
            FOREIGN KEY(subdomain_id) REFERENCES subdomains(id)
        )
        """
    )

    # customWordlists table
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS customWordlists (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER,
            keyword TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(domain_id) REFERENCES domains(id)
        )
        """
    )

    conn.commit()

    # ─── Migrate missing columns if needed ────────────────────────────────────

    def _column_exists(table_name: str, column_name: str) -> bool:
        c.execute(f"PRAGMA table_info({table_name})")
        return any(row[1] == column_name for row in c.fetchall())

    # Ensure "status_code" exists on subdomains, directories, files
    if not _column_exists("subdomains", "status_code"):
        try:
            c.execute("ALTER TABLE subdomains ADD COLUMN status_code INTEGER")
        except sqlite3.OperationalError:
            pass
    if not _column_exists("directories", "status_code"):
        try:
            c.execute("ALTER TABLE directories ADD COLUMN status_code INTEGER")
        except sqlite3.OperationalError:
            pass
    if not _column_exists("files", "status_code"):
        try:
            c.execute("ALTER TABLE files ADD COLUMN status_code INTEGER")
        except sqlite3.OperationalError:
            pass

    conn.commit()
    return conn


def create_scan(conn, name):
    """
    Insert a new scan into scans (status defaults to NULL). Returns scan_id.
    """
    c = conn.cursor()
    c.execute("INSERT INTO scans (name, status) VALUES (?, NULL)", (name,))
    conn.commit()
    return c.lastrowid


def update_scan_status(conn, scan_id, status):
    """
    Update the status column for the given scan_id.
    """
    c = conn.cursor()
    c.execute("UPDATE scans SET status = ? WHERE id = ?", (status, scan_id))
    conn.commit()


def log_message(conn, scan_id, message):
    """
    Insert a new log line for a given scan_id (or NULL for catch‐all).
    """
    c = conn.cursor()
    c.execute(
        "INSERT INTO logging (scan_id, message) VALUES (?, ?)",
        (scan_id, message)
    )
    conn.commit()


def insert_domain(conn, scan_id, domain, params):
    """
    Insert a domain under a specific scan. Returns domain_id.
    If the same (scan_id, domain) pair already exists, returns the existing id.
    """
    c = conn.cursor()
    params_json = json.dumps(params)
    c.execute(
        "SELECT id FROM domains WHERE scan_id = ? AND domain = ?",
        (scan_id, domain)
    )
    row = c.fetchone()
    if row:
        return row[0]
    c.execute(
        "INSERT INTO domains (scan_id, domain, params_json) VALUES (?, ?, ?)",
        (scan_id, domain, params_json)
    )
    conn.commit()
    return c.lastrowid


def insert_subdomain(conn, scan_id, domain_id, subdomain, status_code=None):
    """
    Insert a discovered subdomain under a scan. Returns subdomain_id.
    Prevents duplicates (case-insensitive).
    """
    c = conn.cursor()
    c.execute(
        "SELECT id FROM subdomains WHERE scan_id = ? AND domain_id = ? AND LOWER(subdomain) = LOWER(?)",
        (scan_id, domain_id, subdomain)
    )
    row = c.fetchone()
    if row:
        return row[0]
    c.execute(
        "INSERT INTO subdomains (scan_id, domain_id, subdomain, status_code) VALUES (?, ?, ?, ?)",
        (scan_id, domain_id, subdomain, status_code)
    )
    conn.commit()
    return c.lastrowid


def insert_directory(conn, scan_id, subdomain_id, directory, status_code=None):
    """
    Insert a discovered directory under a subdomain.
    """
    c = conn.cursor()
    c.execute(
        "INSERT INTO directories (scan_id, subdomain_id, directory, status_code) VALUES (?, ?, ?, ?)",
        (scan_id, subdomain_id, directory, status_code)
    )
    conn.commit()


def insert_file(conn, scan_id, subdomain_id, file_url, status_code=None):
    """
    Insert a discovered file under a subdomain.
    """
    c = conn.cursor()
    c.execute(
        "INSERT INTO files (scan_id, subdomain_id, file_url, status_code) VALUES (?, ?, ?, ?)",
        (scan_id, subdomain_id, file_url, status_code)
    )
    conn.commit()


def insert_custom_wordlist(conn, domain_id, keyword):
    """
    Insert a custom keyword under a particular domain.
    """
    c = conn.cursor()
    c.execute(
        "INSERT INTO customWordlists (domain_id, keyword) VALUES (?, ?)",
        (domain_id, keyword)
    )
    conn.commit()


def fetch_scans(conn):
    """
    Return a list of (id, name, status, start_time) for all scans.
    """
    c = conn.cursor()
    c.execute(
        "SELECT id, name, status, start_time FROM scans ORDER BY start_time DESC"
    )
    return c.fetchall()


def fetch_logs(conn, scan_id):
    """
    Return a list of (timestamp, message) log lines for a given scan_id.
    """
    c = conn.cursor()
    c.execute(
        "SELECT timestamp, message FROM logging WHERE scan_id = ? ORDER BY id",
        (scan_id,)
    )
    return c.fetchall()


def fetch_subdomains_by_scan(conn, scan_id):
    """
    Return a list of (subdomain, status_code) tuples for a given scan.
    """
    c = conn.cursor()
    c.execute(
        "SELECT subdomain, status_code FROM subdomains WHERE scan_id = ? ORDER BY LOWER(subdomain)",
        (scan_id,)
    )
    return c.fetchall()


def fetch_directories_by_scan(conn, scan_id, status_filter=None):
    """
    Return a list of (subdomain, directory, status_code) for a scan,
    optionally filtering by status_code.
    """
    c = conn.cursor()
    if status_filter is not None:
        c.execute(
            "SELECT s.subdomain, d.directory, d.status_code "
            "FROM directories d JOIN subdomains s ON d.subdomain_id = s.id "
            "WHERE d.scan_id = ? AND d.status_code != ?",
            (scan_id, status_filter)
        )
    else:
        c.execute(
            "SELECT s.subdomain, d.directory, d.status_code "
            "FROM directories d JOIN subdomains s ON d.subdomain_id = s.id "
            "WHERE d.scan_id = ?",
            (scan_id,)
        )
    return c.fetchall()


def fetch_files_by_scan(conn, scan_id, status_filter=None):
    """
    Return a list of (subdomain, file_url, status_code) for a scan,
    optionally filtering by status_code.
    """
    c = conn.cursor()
    if status_filter is not None:
        c.execute(
            "SELECT s.subdomain, f.file_url, f.status_code "
            "FROM files f JOIN subdomains s ON f.subdomain_id = s.id "
            "WHERE f.scan_id = ? AND f.status_code != ?",
            (scan_id, status_filter)
        )
    else:
        c.execute(
            "SELECT s.subdomain, f.file_url, f.status_code "
            "FROM files f JOIN subdomains s ON f.subdomain_id = s.id "
            "WHERE f.scan_id = ?",
            (scan_id,)
        )
    return c.fetchall()


def fetch_domains(conn):
    """
    Return a list of (id, domain) for every domain in the domains table,
    so that the Wordlist Generator can populate its dropdown.
    """
    c = conn.cursor()
    c.execute(
        "SELECT id, domain FROM domains ORDER BY LOWER(domain)"
    )
    return c.fetchall()


def fetch_table(conn, table_name):
    """
    Generic function to fetch all columns & rows from any table.
    Returns: (list_of_column_names, list_of_row-tuples).

    WARNING: table_name is interpolated directly—ensure it comes from a trusted source (e.g. a predefined dropdown).
    """
    c = conn.cursor()
    c.execute(f"SELECT * FROM {table_name}")
    rows = c.fetchall()
    colnames = [desc[0] for desc in c.description]
    return colnames, rows
