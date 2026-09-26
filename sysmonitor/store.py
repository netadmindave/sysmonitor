"""SQLite schema and the issue lifecycle (open -> refreshed -> auto-resolved)."""
import time

from .common import SEV

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, ts REAL, src_ip TEXT, source TEXT, app TEXT,
  level INTEGER, facility INTEGER, template_id TEXT, rule_id TEXT, msg TEXT);
CREATE INDEX IF NOT EXISTS ev_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ev_tpl ON events(template_id, ts);
CREATE TABLE IF NOT EXISTS templates (
  id TEXT PRIMARY KEY, template TEXT, example TEXT, source TEXT, app TEXT, level INTEGER,
  first_seen REAL, last_seen REAL, count INTEGER);
CREATE TABLE IF NOT EXISTS sources (
  ip TEXT PRIMARY KEY, name TEXT, first_seen REAL, last_seen REAL, count INTEGER);
CREATE TABLE IF NOT EXISTS issues (
  key TEXT PRIMARY KEY, rule_id TEXT, origin TEXT, category TEXT, severity TEXT, title TEXT,
  detail TEXT, source TEXT, status TEXT, count INTEGER, first_seen REAL, last_seen REAL,
  resolved_at REAL);
CREATE INDEX IF NOT EXISTS is_status ON issues(status);
CREATE TABLE IF NOT EXISTS digests (ts REAL PRIMARY KEY, kind TEXT, text TEXT);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
"""


def init(c):
    c.executescript(SCHEMA)
    c.commit()


def meta_get(c, k, default=None):
    r = c.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
    return r[0] if r else default


def meta_set(c, k, v):
    c.execute("INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))


def upsert_issue(c, key, *, rule_id, origin, category, severity, title, detail="", source="",
                 hits=1, initial_count=None, now=None):
    now = now or time.time()
    row = c.execute("SELECT status FROM issues WHERE key=?", (key,)).fetchone()
    first = max(initial_count or hits, 1)
    if row is None:
        c.execute("""INSERT INTO issues (key, rule_id, origin, category, severity, title, detail, source,
                     status, count, first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,'open',?,?,?)""",
                  (key, rule_id, origin, category, severity, title, detail, source, first, now, now))
        return "opened"
    if row["status"] == "resolved":
        c.execute("""UPDATE issues SET status='open', severity=?, title=?, detail=?, source=?, count=?,
                     first_seen=?, last_seen=?, resolved_at=NULL WHERE key=?""",
                  (severity, title, detail, source, first, now, now, key))
        return "reopened"
    c.execute("""UPDATE issues SET severity=?, title=?, detail=?, source=?, count=count+?, last_seen=?
                 WHERE key=?""", (severity, title, detail, source, hits, now, key))
    return "refreshed"


def sync_poller(c, origin, items):
    """Make the open issues from one poller exactly `items`: upsert those, resolve the rest."""
    now = time.time()
    keys = []
    for it in items:
        keys.append(it["key"])
        upsert_issue(c, it["key"], rule_id=it.get("rule_id", origin), origin=origin,
                     category=it.get("category", origin), severity=it["severity"], title=it["title"],
                     detail=it.get("detail", ""), source=it.get("source", ""), hits=0, now=now)
    marks = ",".join("?" * len(keys))
    q = "UPDATE issues SET status='resolved', resolved_at=? WHERE origin=? AND status='open'"
    if keys:
        q += f" AND key NOT IN ({marks})"
    c.execute(q, (now, origin, *keys))
    c.commit()


def resolve_stale(c, default_minutes, per_rule=None):
    """Log-driven issues resolve once their events have been quiet long enough."""
    now = time.time()
    per_rule = per_rule or {}
    for r in c.execute("SELECT key, rule_id, last_seen FROM issues WHERE origin='log' AND status='open'").fetchall():
        minutes = per_rule.get(r["rule_id"], default_minutes)
        if r["last_seen"] < now - minutes * 60:
            c.execute("UPDATE issues SET status='resolved', resolved_at=? WHERE key=?", (now, r["key"]))
    c.commit()


def open_issues(c):
    rows = [dict(r) for r in c.execute("SELECT * FROM issues WHERE status='open'")]
    rows.sort(key=lambda r: (SEV.get(r["severity"], 0), r["last_seen"]), reverse=True)
    return rows
