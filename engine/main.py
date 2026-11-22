import csv
import io
import json
import re
import subprocess
import time

from fastapi import FastAPI, HTTPException, Request
import pathlib
from fastapi.responses import HTMLResponse, PlainTextResponse

from . import db, scoring
from .parsers import PARSERS

app = FastAPI(title="K-Guard")
db.init()


def _pick(fields, output, keys, pattern):
    for k in keys:
        v = fields.get(k)
        if v and v != "<NA>":
            return v
    m = re.search(pattern, output or "")
    if m and m.group(1) != "<NA>":
        return m.group(1)
    return None


@app.post("/falco")
async def falco(request: Request):
    body = await request.json()
    f = body.get("output_fields") or {}
    out = body.get("output") or ""
    ns = _pick(f, out, ["k8s.ns.name", "k8s_ns_name", "k8smeta.ns.name", "k8smeta_ns_name"],
               r"k8s(?:meta)?[._]ns[._]name=(\S+)") or "unknown"
    pod = _pick(f, out, ["k8s.pod.name", "k8s_pod_name", "k8smeta.pod.name", "k8smeta_pod_name"],
                r"k8s(?:meta)?[._]pod[._]name=(\S+)") or "unknown"
    workload = f"{ns}/{pod}"
    db.add_event(body.get("rule"), body.get("priority"), workload, out, time.time())
    print(f"[FALCO] {body.get('priority')} | {body.get('rule')} -> {workload}", flush=True)
    return {"ok": True}


@app.get("/api/events")
def events(limit: int = 100):
    with db.conn() as c:
        rows = c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in rows]


def _ingest(source):
    path, fn = PARSERS[source]
    if source == "gatekeeper":  # refresh the audit live
        try:
            out = subprocess.run(["kubectl", "get", "constraints", "-o", "json"],
                                 capture_output=True, text=True, timeout=20)
            if out.returncode == 0 and out.stdout.strip():
                open(path, "w").write(out.stdout)
        except Exception:
            pass
    rows = fn(path)
    db.replace_findings(source, rows, time.time())
    return len(rows)


@app.post("/ingest/{source}")
def ingest(source: str):
    if source == "all":
        res = {}
        for s in PARSERS:
            try:
                res[s] = _ingest(s)
            except FileNotFoundError:
                res[s] = "missing file"
        return res
    if source not in PARSERS:
        raise HTTPException(404, f"unknown source {source}; use {list(PARSERS)} or all")
    try:
        return {source: _ingest(source)}
    except FileNotFoundError:
        raise HTTPException(404, f"{PARSERS[source][0]} not found")


@app.get("/api/risks")
def risks():
    return scoring.compute()


@app.get("/api/findings")
def findings(workload: str = ""):
    with db.conn() as c:
        if workload:
            rows = c.execute("SELECT * FROM findings WHERE workload=?", (workload,))
        else:
            rows = c.execute("SELECT * FROM findings")
        return [dict(r) for r in rows]


@app.post("/snapshot/{label}")
def snapshot(label: str):
    data = scoring.compute()
    with db.conn() as c:
        c.execute("INSERT OR REPLACE INTO snapshots(label,ts,data) VALUES(?,?,?)",
                  (label, time.time(), json.dumps(data)))
    return {"label": label, "assets": len(data)}


def _snap(label):
    with db.conn() as c:
        row = c.execute("SELECT data FROM snapshots WHERE label=?", (label,)).fetchone()
    return {r["workload"]: r for r in json.loads(row["data"])} if row else {}


@app.get("/api/compare")
def compare(a: str = "baseline", b: str = "after"):
    A, B = _snap(a), _snap(b)
    out = []
    for w in sorted(set(A) | set(B)):
        sa, sb = A.get(w), B.get(w)
        out.append({"workload": w,
                    "before": sa["score"] if sa else None,
                    "before_band": sa["band"] if sa else None,
                    "after": sb["score"] if sb else None,
                    "after_band": sb["band"] if sb else None})
    return out


@app.get("/export/risk-register.csv", response_class=PlainTextResponse)
def export_csv():
    cur = scoring.compute()
    base, after = _snap("baseline"), _snap("after")
    buf = io.StringIO()
    wr = csv.writer(buf)
    wr.writerow(["Risk ID", "Asset", "Impact", "Likelihood", "Score", "Rating",
                 "Key findings", "NIST 800-53", "ISO 27001:2022", "Treatment",
                 "Policy enforced", "Baseline score", "Residual score (after)"])
    for i, r in enumerate(cur, 1):
        wr.writerow([f"R-{i:02d}", r["workload"], r["impact"], r["likelihood"], r["score"],
                     r["band"], " | ".join(r["top_findings"]), ", ".join(r["nist"]),
                     ", ".join(r["iso"]), r["treatment"],
                     "yes" if r["enforced"] else ("n/a" if not r["violated_constraints"] else "no"),
                     base.get(r["workload"], {}).get("score", ""),
                     after.get(r["workload"], {}).get("score", "")])
    return buf.getvalue()


@app.post("/reset/{what}")
def reset(what: str):
    with db.conn() as c:
        if what == "events":
            c.execute("DELETE FROM events")
        elif what == "snapshots":
            c.execute("DELETE FROM snapshots")
        else:
            raise HTTPException(404, "use events or snapshots")
    return {"reset": what}


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return (pathlib.Path(__file__).parent / "templates" / "dashboard.html").read_text()
