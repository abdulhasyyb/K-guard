import json
import pathlib
import subprocess
import time

from . import db

CONTROLS = json.loads((pathlib.Path(__file__).parent / "controls.json").read_text())
FALLBACK_IMPACT = {"payments": 5, "web": 3}
CLUSTER_IMPACT = 5
EVENT_WINDOW = 15 * 60  # seconds a runtime event keeps likelihood at 5


def band(score):
    if score >= 17:
        return "Critical"
    if score >= 10:
        return "High"
    if score >= 5:
        return "Medium"
    return "Low"


def _load_impacts_uncached():
    """Impact (1-5) per namespace from the kguard.io/impact label."""
    try:
        out = subprocess.run(["kubectl", "get", "ns", "-o", "json"],
                             capture_output=True, text=True, timeout=10)
        res = {}
        for it in json.loads(out.stdout)["items"]:
            lab = it["metadata"].get("labels") or {}
            if "kguard.io/impact" in lab:
                res[it["metadata"]["name"]] = int(lab["kguard.io/impact"])
        if res:
            return res
    except Exception:
        pass
    return dict(FALLBACK_IMPACT)


def _controls_for(categories):
    nist, iso = set(), set()
    for cat in categories:
        m = CONTROLS.get(cat) or CONTROLS["config"]
        nist.update(m["nist"])
        iso.update(m["iso"])
    return sorted(nist), sorted(iso)


def compute():
    now = time.time()
    impacts = load_impacts()
    with db.conn() as c:
        findings = [dict(r) for r in c.execute("SELECT * FROM findings")]
        events = [dict(r) for r in c.execute("SELECT * FROM events WHERE ts >= ?",
                                             (now - EVENT_WINDOW,))]
    for f in findings:
        f["extra"] = json.loads(f["extra"] or "{}")

    cluster_f = [f for f in findings if f["workload"] == "cluster/cluster"]
    cluster_exposed = any(f["source"] in ("kubehunter", "nmap") and
                          f["severity"] in ("high", "medium") for f in cluster_f)
    bench_fails = sum(1 for f in cluster_f if f["source"] == "kubebench" and
                      f["extra"].get("status") == "FAIL")

    pods = set()
    for f in findings:
        if f["workload"] != "cluster/cluster" and (
                f["source"] == "gatekeeper" or f["extra"].get("kind") == "Pod"):
            pods.add(f["workload"])
    for e in events:
        if e["workload"] != "unknown/unknown":
            pods.add(e["workload"])
    pods = {p for p in pods if p.split("/")[0] in impacts}

    risks = []
    for w in sorted(pods):
        ns = w.split("/")[0]
        mine = [f for f in findings if f["workload"] == w]
        evs = [e for e in events if e["workload"] == w]
        static_high = [f for f in mine if f["source"] == "checkov" and f["severity"] == "high"]
        viol = [f for f in mine if f["source"] == "gatekeeper"]
        weakness = bool(static_high or viol)

        L, why = 1, ["base 1"]
        if static_high:
            L += 1; why.append("+1 high static finding")
        if viol:
            L += 1; why.append("+1 policy violation")
        if weakness and cluster_exposed:
            L += 1; why.append("+1 cluster exposure compounds weakness")
        if evs:
            L = 5; why = ["runtime event observed -> 5"]
        L = min(L, 5)
        I = impacts[ns]
        score = L * I
        enforced = bool(viol) and all(v["extra"].get("action") == "deny" for v in viol)
        b = band(score)
        if b in ("Critical", "High"):
            treatment = "Mitigate"
        elif viol or static_high:
            treatment = "Mitigate"
        else:
            treatment = "Accept (monitor)"
        cats = {f["category"] for f in mine if f["severity"] in ("high", "medium")}
        if evs:
            cats.add("runtime_event")
        nist, iso = _controls_for(cats)
        top = []
        for f in sorted(mine, key=lambda x: {"high": 0, "medium": 1}.get(x["severity"], 2)):
            if f["severity"] in ("high", "medium") and f["message"] not in top:
                top.append(f["message"])
        risks.append({
            "workload": w, "namespace": ns, "impact": I, "likelihood": L,
            "score": score, "band": b, "treatment": treatment, "enforced": enforced,
            "violated_constraints": sorted({v["rule_id"] for v in viol}),
            "static_high": len(static_high), "runtime_events": len(evs),
            "finding_count": len(mine), "likelihood_basis": why,
            "nist": nist, "iso": iso, "top_findings": top[:6],
        })

    # Cluster-level asset
    L, why = 1, ["base 1"]
    if cluster_exposed:
        L += 1; why.append("+1 exposed sensitive interfaces (kube-hunter/nmap)")
    if bench_fails:
        L += 1; why.append(f"+1 CIS benchmark failures ({bench_fails})")
    cats = {f["category"] for f in cluster_f if f["severity"] in ("high", "medium")}
    nist, iso = _controls_for(cats or {"config"})
    risks.append({
        "workload": "cluster/cluster", "namespace": "cluster", "impact": CLUSTER_IMPACT,
        "likelihood": L, "score": L * CLUSTER_IMPACT, "band": band(L * CLUSTER_IMPACT),
        "treatment": "Mitigate" if L > 1 else "Accept (monitor)", "enforced": False,
        "violated_constraints": [], "static_high": 0, "runtime_events": 0,
        "finding_count": len(cluster_f), "likelihood_basis": why,
        "nist": nist, "iso": iso,
        "top_findings": [f["message"] for f in cluster_f
                         if f["severity"] in ("high", "medium")][:6],
    })
    risks.sort(key=lambda r: -r["score"])
    return risks


_CACHE = {"t": 0.0, "v": None}


def load_impacts():
    if _CACHE["v"] is None or time.time() - _CACHE["t"] > 20:
        _CACHE["v"] = _load_impacts_uncached()
        _CACHE["t"] = time.time()
    return dict(_CACHE["v"])
