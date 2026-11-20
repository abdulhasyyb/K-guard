import json, re, time, pathlib
from fastapi import FastAPI, Request

app = FastAPI()
EVENTS = pathlib.Path("out/events.jsonl")


def pick(fields, output, keys, pattern):
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
    ns = pick(f, out,
              ["k8s.ns.name", "k8s_ns_name", "k8smeta.ns.name", "k8smeta_ns_name"],
              r"k8s(?:meta)?[._]ns[._]name=(\S+)") or "unknown"
    pod = pick(f, out,
               ["k8s.pod.name", "k8s_pod_name", "k8smeta.pod.name", "k8smeta_pod_name"],
               r"k8s(?:meta)?[._]pod[._]name=(\S+)") or "unknown"
    ev = {
        "received": time.time(),
        "rule": body.get("rule"),
        "priority": body.get("priority"),
        "workload": f"{ns}/{pod}",
        "output": out,
        "fields": f,
    }
    with EVENTS.open("a") as fh:
        fh.write(json.dumps(ev) + "\n")
    print(f"[FALCO] {ev['priority']} | {ev['rule']} -> {ev['workload']}", flush=True)
    return {"ok": True}


@app.get("/api/events")
def events():
    if not EVENTS.exists():
        return []
    return [json.loads(line) for line in EVENTS.read_text().splitlines()][-200:]
