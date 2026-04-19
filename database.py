import logging
import sqlite3
from pathlib import Path

log = logging.getLogger(__name__)


# ========================
# CONNECTION
# ========================
def get_connection(db_path: Path) -> sqlite3.Connection:
    """Create and return a SQLite connection with recommended PRAGMAs set."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    log.debug(f"Using DB: {db_path.resolve()}")
    return conn


# ========================
# SCHEMA INIT
# ========================
def init_db(conn: sqlite3.Connection) -> None:
    """Initialize all tables and indexes. Safe to call on an existing database."""
    cursor = conn.cursor()

    try:
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS subdomains (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                subdomain TEXT UNIQUE NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS live_hosts (
                id   INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT UNIQUE NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS endpoints (
                id  INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS parameters (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                url       TEXT NOT NULL,
                parameter TEXT NOT NULL,
                UNIQUE(url, parameter)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                type     TEXT NOT NULL,
                target   TEXT NOT NULL,
                severity TEXT,
                tool     TEXT NOT NULL,
                details  TEXT,
                UNIQUE(type, target, tool)
            )
        """)

        # Index for fast duplicate checks in vulnerabilities
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_vuln_lookup
            ON vulnerabilities(type, target, tool)
        """)

        conn.commit()
        log.debug("Database schema initialized.")

    except sqlite3.Error as e:
        log.error(f"Database initialization failed: {e}")
        raise


# ========================
# INSERT HELPERS
# ========================
def insert_subdomains(conn: sqlite3.Connection, subs: set) -> int:
    """Insert subdomains, ignoring duplicates. Returns count of newly inserted rows."""
    cursor = conn.cursor()
    count = 0
    for sub in subs:
        cursor.execute(
            "INSERT OR IGNORE INTO subdomains(subdomain) VALUES (?)",
            (sub,)
        )
        count += cursor.rowcount
    return count


def insert_live_hosts(conn: sqlite3.Connection, hosts: set) -> int:
    """Insert live hosts, ignoring duplicates. Returns count of newly inserted rows."""
    cursor = conn.cursor()
    count = 0
    for host in hosts:
        cursor.execute(
            "INSERT OR IGNORE INTO live_hosts(host) VALUES (?)",
            (host,)
        )
        count += cursor.rowcount
    return count


def insert_endpoints(conn: sqlite3.Connection, urls: set) -> int:
    """Insert endpoints, ignoring duplicates. Returns count of newly inserted rows."""
    cursor = conn.cursor()
    count = 0
    for url in urls:
        cursor.execute(
            "INSERT OR IGNORE INTO endpoints(url) VALUES (?)",
            (url,)
        )
        count += cursor.rowcount
    return count


def insert_parameter(conn: sqlite3.Connection, url: str, parameter: str) -> int:
    """Insert a single parameter row, ignoring duplicates. Returns 1 if inserted, 0 if duplicate."""
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR IGNORE INTO parameters(url, parameter) VALUES (?, ?)",
        (url, parameter)
    )
    return cursor.rowcount


def insert_vulnerability(
    conn: sqlite3.Connection,
    vuln_type: str,
    target: str,
    severity: str,
    tool: str,
    details: dict
) -> int:
    """
    Insert a vulnerability, ignoring duplicates (matched on type + target + tool).
    Returns 1 if inserted, 0 if duplicate.
    """
    import json
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT OR IGNORE INTO vulnerabilities(type, target, severity, tool, details)
        VALUES (?, ?, ?, ?, ?)
        """,
        (vuln_type, target, severity, tool, json.dumps(details))
    )
    return cursor.rowcount