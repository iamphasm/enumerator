#!/usr/bin/env python3
"""Local software database for vscan.

Stores, for every known piece of software, where to find its current release
versions (a URL plus a regex), which distro packages provide it, and which
systemd units run it. Also caches fetched release lists.

CLI:
    python3 swdb.py init [--force]      create data/software.db from data/seed.json
    python3 swdb.py list                list all entries
    python3 swdb.py show NAME           show one entry
    python3 swdb.py check [NAME ...]    fetch and print the newest release(s)
    python3 swdb.py add NAME --url URL --regex RE [--alias A ...] [...]
    python3 swdb.py remove NAME
    python3 swdb.py export [FILE]       dump the database back to seed JSON
"""
import argparse
import json
import os
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "data", "software.db")
SEED_PATH = os.path.join(BASE_DIR, "data", "seed.json")
CACHE_TTL = 12 * 3600          # seconds a fetched release list stays valid
USER_AGENT = "vscan/1.0 (software version checker)"
PKG_MANAGERS = ("apt", "dnf", "pacman", "zypper", "apk")

SCHEMA = """
CREATE TABLE IF NOT EXISTS software (
    name         TEXT PRIMARY KEY,
    aliases      TEXT NOT NULL,              -- JSON list of lowercase match strings
    url          TEXT NOT NULL,              -- page that lists releases
    regex        TEXT NOT NULL,              -- exactly one capture group = version
    branch_depth INTEGER NOT NULL DEFAULT 0, -- 0 overall, 1 same major, 2 same major.minor
    packages     TEXT NOT NULL DEFAULT '{}', -- JSON {"apt": [...], "dnf": [...], ...}
    services     TEXT NOT NULL DEFAULT '[]', -- JSON list of systemd units
    notes        TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS version_cache (
    name       TEXT PRIMARY KEY,
    versions   TEXT NOT NULL,                -- JSON list of version strings
    fetched_at REAL NOT NULL
);
"""


# --------------------------------------------------------------------------
# Version helpers
# --------------------------------------------------------------------------
_VERSION_CORE = re.compile(r"\d+(?:[._]\d+)*(?:p\d+|[a-z](?![a-z0-9]))?", re.I)


def parse_version(text):
    """'9.6p1 Ubuntu 3' -> (9, 6, 1); '1.3.5e' -> (1, 3, 5, 5); None if no version."""
    if not text:
        return None
    m = _VERSION_CORE.search(str(text))
    if not m:
        return None
    parts = []
    for tok in re.findall(r"\d+|[a-z]", m.group(0).lower()):
        if tok.isdigit():
            parts.append(int(tok))
        elif tok != "p":            # OpenSSH "p1" is just a separator
            parts.append(ord(tok) - 96)
    return tuple(parts)


def clean_version(text):
    """Return the version token itself, e.g. '2.4.41 (Ubuntu)' -> '2.4.41'."""
    m = _VERSION_CORE.search(str(text or ""))
    return m.group(0).replace("_", ".") if m else None


def _key(parts):
    return tuple(parts) + (0,) * (12 - len(parts))


def compare_versions(a, b):
    """-1 if a<b, 0 if equal, 1 if a>b. Arguments are strings."""
    pa, pb = parse_version(a), parse_version(b)
    if pa is None or pb is None:
        raise ValueError(f"cannot compare {a!r} and {b!r}")
    ka, kb = _key(pa), _key(pb)
    return (ka > kb) - (ka < kb)


def pick_latest(installed, candidates, branch_depth=0):
    """Return (latest_in_branch, newest_overall) from a list of version strings."""
    parsed = [(parse_version(v), v) for v in candidates]
    parsed = [p for p in parsed if p[0]]
    if not parsed:
        return None, None
    newest = max(parsed, key=lambda p: _key(p[0]))[1]
    inst = parse_version(installed) if installed else None
    if inst and branch_depth > 0 and len(inst) >= branch_depth:
        same = [p for p in parsed if p[0][:branch_depth] == inst[:branch_depth]]
        if same:
            return max(same, key=lambda p: _key(p[0]))[1], newest
    return newest, newest


# --------------------------------------------------------------------------
# Database access
# --------------------------------------------------------------------------
def connect(path=DB_PATH):
    new = not os.path.exists(path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    if new:
        seed(conn)
    return conn


def _validate(entry):
    rx = re.compile(entry["regex"])
    if rx.groups != 1:
        raise ValueError(f"{entry['name']}: regex must have exactly one capture group")
    if not entry.get("aliases"):
        raise ValueError(f"{entry['name']}: at least one alias is required")


def upsert(conn, entry):
    _validate(entry)
    conn.execute(
        """INSERT INTO software (name, aliases, url, regex, branch_depth, packages, services, notes)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(name) DO UPDATE SET aliases=excluded.aliases, url=excluded.url,
             regex=excluded.regex, branch_depth=excluded.branch_depth,
             packages=excluded.packages, services=excluded.services, notes=excluded.notes""",
        (entry["name"].lower(),
         json.dumps([a.lower() for a in entry["aliases"]]),
         entry["url"], entry["regex"], int(entry.get("branch_depth", 0)),
         json.dumps(entry.get("packages", {})), json.dumps(entry.get("services", [])),
         entry.get("notes", "")))
    conn.execute("DELETE FROM version_cache WHERE name = ?", (entry["name"].lower(),))
    conn.commit()


def seed(conn, seed_path=SEED_PATH):
    with open(seed_path, encoding="utf-8") as fh:
        data = json.load(fh)
    for entry in data["software"]:
        upsert(conn, entry)
    return len(data["software"])


def _row_to_entry(row):
    return {
        "name": row["name"], "aliases": json.loads(row["aliases"]), "url": row["url"],
        "regex": row["regex"], "branch_depth": row["branch_depth"],
        "packages": json.loads(row["packages"]), "services": json.loads(row["services"]),
        "notes": row["notes"],
    }


def all_entries(conn):
    return [_row_to_entry(r) for r in conn.execute("SELECT * FROM software ORDER BY name")]


def get_entry(conn, name):
    row = conn.execute("SELECT * FROM software WHERE name = ?", (name.lower(),)).fetchone()
    return _row_to_entry(row) if row else None


class Matcher:
    """Maps a free-text product name (from nmap or nikto) to a database entry."""

    def __init__(self, conn):
        self.rules = []
        for e in all_entries(conn):
            for alias in e["aliases"]:
                pat = re.compile(r"(?<![a-z0-9])" + re.escape(alias) + r"(?![a-z0-9])")
                self.rules.append((len(alias), pat, e))
        self.rules.sort(key=lambda r: -r[0])     # longest alias wins

    def match(self, *texts):
        hay = " | ".join(t.lower() for t in texts if t)
        for _, pat, entry in self.rules:
            if pat.search(hay):
                return entry
        return None

    def match_cpe(self, vendor_product):
        """Exact match for a CPE 'vendor:product': aliases containing ':' must equal it,
        other aliases must equal the product part (spaces treated as underscores)."""
        vp = vendor_product.lower()
        product = vp.split(":", 1)[-1]
        for _, _, entry in self.rules:
            for alias in entry["aliases"]:
                if (":" in alias and alias == vp) or (":" not in alias and alias.replace(" ", "_") == product):
                    return entry
        return None


# --------------------------------------------------------------------------
# Fetching release versions
# --------------------------------------------------------------------------
def fetch_url(url, timeout=25, retries=3):
    headers = {"User-Agent": USER_AGENT}
    token = os.environ.get("GITHUB_TOKEN")
    if token and "api.github.com" in url:
        headers["Authorization"] = f"Bearer {token}"
    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read(20_000_000).decode("utf-8", "replace")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = exc
            if isinstance(exc, urllib.error.HTTPError) and exc.code in (403, 404):
                break
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"fetch failed for {url}: {last}")


def release_versions(conn, entry, refresh=False):
    """List of release version strings for an entry, cached for CACHE_TTL."""
    if not refresh:
        row = conn.execute("SELECT versions, fetched_at FROM version_cache WHERE name = ?",
                           (entry["name"],)).fetchone()
        if row and time.time() - row["fetched_at"] < CACHE_TTL:
            return json.loads(row["versions"])
    text = fetch_url(entry["url"])
    found = sorted({v.replace("_", ".") for v in re.findall(entry["regex"], text)},
                   key=lambda v: _key(parse_version(v) or ()))
    if not found:
        raise RuntimeError(f"no versions matched on {entry['url']} (regex may be stale)")
    conn.execute("INSERT OR REPLACE INTO version_cache (name, versions, fetched_at) VALUES (?, ?, ?)",
                 (entry["name"], json.dumps(found), time.time()))
    conn.commit()
    return found


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def _cli():
    ap = argparse.ArgumentParser(description="Manage the vscan software/version database.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init", help="create the database from data/seed.json")
    p.add_argument("--force", action="store_true", help="delete and rebuild an existing database")
    sub.add_parser("list", help="list entries")
    p = sub.add_parser("show", help="show one entry")
    p.add_argument("name")
    p = sub.add_parser("check", help="fetch newest release versions")
    p.add_argument("names", nargs="*")
    p = sub.add_parser("add", help="add or replace an entry")
    p.add_argument("name")
    p.add_argument("--url", required=True)
    p.add_argument("--regex", required=True, help="one capture group matching a version")
    p.add_argument("--alias", action="append", default=[], help="repeatable; name itself is always an alias")
    p.add_argument("--branch-depth", type=int, default=0, choices=(0, 1, 2))
    for pm in PKG_MANAGERS:
        p.add_argument(f"--{pm}", action="append", default=[], help=f"{pm} package name (repeatable)")
    p.add_argument("--service", action="append", default=[], help="systemd unit (repeatable)")
    p.add_argument("--notes", default="")
    p = sub.add_parser("remove", help="remove an entry")
    p.add_argument("name")
    p = sub.add_parser("export", help="write the database as seed JSON")
    p.add_argument("file", nargs="?", default="-")
    args = ap.parse_args()

    if args.cmd == "init":
        if os.path.exists(DB_PATH):
            if not args.force:
                sys.exit(f"{DB_PATH} already exists; use --force to rebuild it")
            os.remove(DB_PATH)
        conn = connect()
        n = conn.execute("SELECT COUNT(*) FROM software").fetchone()[0]
        print(f"Created {DB_PATH} with {n} entries")
        return

    conn = connect()
    if args.cmd == "list":
        for e in all_entries(conn):
            print(f"{e['name']:16} depth={e['branch_depth']}  aliases={', '.join(e['aliases'])}")
    elif args.cmd == "show":
        e = get_entry(conn, args.name)
        if not e:
            sys.exit(f"no entry named {args.name}")
        print(json.dumps(e, indent=2))
    elif args.cmd == "check":
        entries = [get_entry(conn, n) for n in args.names] if args.names else all_entries(conn)
        bad = 0
        for e in entries:
            if e is None:
                print("unknown name"); bad += 1; continue
            try:
                vs = release_versions(conn, e, refresh=True)
                print(f"{e['name']:16} OK    newest={pick_latest(None, vs)[1]:12} ({len(vs)} releases found)")
            except Exception as exc:
                bad += 1
                print(f"{e['name']:16} FAIL  {exc}")
        sys.exit(1 if bad else 0)
    elif args.cmd == "add":
        entry = {
            "name": args.name, "aliases": sorted({args.name.lower(), *args.alias}),
            "url": args.url, "regex": args.regex, "branch_depth": args.branch_depth,
            "packages": {pm: getattr(args, pm) for pm in PKG_MANAGERS if getattr(args, pm)},
            "services": args.service, "notes": args.notes,
        }
        try:
            upsert(conn, entry)
        except (ValueError, re.error) as exc:
            sys.exit(f"not saved: {exc}")
        try:
            vs = release_versions(conn, entry, refresh=True)
            print(f"Saved {args.name}; newest release found: {pick_latest(None, vs)[1]}")
        except Exception as exc:
            sys.exit(f"Saved {args.name}, but the version lookup failed: {exc}")
    elif args.cmd == "remove":
        n = conn.execute("DELETE FROM software WHERE name = ?", (args.name.lower(),)).rowcount
        conn.execute("DELETE FROM version_cache WHERE name = ?", (args.name.lower(),))
        conn.commit()
        print("removed" if n else "no such entry")
    elif args.cmd == "export":
        out = json.dumps({"software": all_entries(conn)}, indent=2)
        if args.file == "-":
            print(out)
        else:
            with open(args.file, "w", encoding="utf-8") as fh:
                fh.write(out + "\n")
            print(f"wrote {args.file}")


if __name__ == "__main__":
    _cli()
