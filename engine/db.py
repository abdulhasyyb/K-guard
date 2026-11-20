import json
import pathlib
import sqlite3

DB_PATH = pathlib.Path("out/kguard.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT, rule_id TEXT, severity TEXT, workload TEXT,
  category TEXT, message TEXT, extra TEXT, ts REAL
);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  rule TEXT, priority TEXT, workload TEXT, output TEXT, ts REAL
);
CREATE TABLE IF NOT EXISTS snapshots(
  label TEXT PRIMARY KEY, ts REAL, data TEXT
);
"""


def conn():
    DB_PATH.parent.mkdir(exist_ok=True)
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init():
    with conn() as c:
        c.executescript(SCHEMA)


def replace_findings(source, rows, ts):
    with conn() as c:
        c.execute("DELETE FROM findings WHERE source=?", (source,))
        c.executemany(
            "INSERT INTO findings(source,rule_id,severity,workload,category,message,extra,ts) "
            "VALUES(?,?,?,?,?,?,?,?)",
            [(source, r["rule_id"], r["severity"], r["workload"], r["category"],
              r["message"], json.dumps(r.get("extra", {})), ts) for r in rows],
        )


def add_event(rule, priority, workload, output, ts):
    with conn() as c:
        c.execute(
            "INSERT INTO events(rule,priority,workload,output,ts) VALUES(?,?,?,?,?)",
            (rule, priority, workload, output, ts),
        )
