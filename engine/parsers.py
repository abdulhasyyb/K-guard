import json
import pathlib
import xml.etree.ElementTree as ET

# Checkov OSS has no severity field, so we assign our own (documented in the report).
HIGH_IDS = {"CKV_K8S_16", "CKV_K8S_20", "CKV_K8S_23"}
MEDIUM_IDS = {"CKV_K8S_22", "CKV_K8S_28", "CKV_K8S_29", "CKV_K8S_30",
              "CKV_K8S_31", "CKV_K8S_37", "CKV_K8S_38", "CKV_K8S_40"}
HIGH_WORDS = ["privileged", "host path", "hostpath", "host network", "hostnetwork",
              "host pid", "hostpid", "host ipc", "hostipc", "cluster-admin", "wildcard"]
HIGH_PORTS = {2379, 2380, 10250}  # etcd client/peer, kubelet API


def classify(text):
    t = text.lower()
    if any(w in t for w in ["hostpath", "host path", "host filesystem", "host network",
                            "hostnetwork", "host pid", "hostpid", "host ipc", "hostipc"]):
        return "host_access"
    if any(w in t for w in ["privileged", "privilege escalation", "privilegeescalation",
                            "capabilit", "net_raw"]):
        return "privilege"
    if any(w in t for w in ["root", "high uid", "runasnonroot"]):
        return "root_user"
    if "limit" in t:
        return "resource_limits"
    if any(w in t for w in ["service account", "serviceaccount", "rbac", "cluster-admin",
                            "clusterrole", "role binding", "rolebinding", "secrets"]):
        return "rbac"
    if any(w in t for w in ["image", "digest", "latest", "pull policy"]):
        return "image_hygiene"
    return "config"


def parse_checkov(path):
    data = json.loads(pathlib.Path(path).read_text())
    if isinstance(data, list):  # multiple frameworks -> list of reports
        data = data[0]
    rows = []
    for fc in data.get("results", {}).get("failed_checks", []):
        parts = fc["resource"].split(".", 2)
        kind = parts[0]
        ns = parts[1] if len(parts) > 1 else "default"
        name = parts[2] if len(parts) > 2 else parts[-1]
        if kind == "Pod":
            workload = f"{ns}/{name}"
        elif kind.startswith("Cluster"):
            workload = "cluster/cluster"
        else:
            workload = f"{ns}/{name}"
        cid, cname = fc["check_id"], fc["check_name"]
        low = cname.lower()
        if cid in HIGH_IDS or any(w in low for w in HIGH_WORDS):
            sev = "high"
        elif cid in MEDIUM_IDS:
            sev = "medium"
        else:
            sev = "low"
        rows.append({"rule_id": cid, "severity": sev, "workload": workload,
                     "category": classify(cname), "message": cname,
                     "extra": {"kind": kind, "resource": fc["resource"]}})
    return rows


def parse_gatekeeper(path):
    data = json.loads(pathlib.Path(path).read_text())
    rows = []
    for item in data.get("items", []):
        cname = item["metadata"]["name"]
        action = item.get("spec", {}).get("enforcementAction", "deny")
        for v in (item.get("status", {}) or {}).get("violations", []) or []:
            if v.get("kind") != "Pod":
                continue
            msg = v.get("message", "")
            cat = classify(cname + " " + msg)
            rows.append({"rule_id": cname,
                         "severity": "medium" if cat == "resource_limits" else "high",
                         "workload": f"{v['namespace']}/{v['name']}",
                         "category": cat, "message": msg,
                         "extra": {"kind": "Pod", "action": action, "constraint": cname}})
    return rows


def parse_kubebench(path):
    data = json.loads(pathlib.Path(path).read_text())
    controls = data.get("Controls", []) if isinstance(data, dict) else []
    rows = []
    for ctl in controls:
        for test in ctl.get("tests", []) or []:
            for r in test.get("results", []) or []:
                status = (r.get("status") or "").upper()
                if status not in ("FAIL", "WARN"):
                    continue
                rows.append({"rule_id": r.get("test_number", "?"),
                             "severity": "medium" if status == "FAIL" else "low",
                             "workload": "cluster/cluster", "category": "cis_config",
                             "message": f"[{status}] {r.get('test_desc', '')}",
                             "extra": {"kind": "Cluster", "status": status,
                                       "section": test.get("section"),
                                       "remediation": (r.get("remediation") or "")[:400]}})
    return rows


def parse_kubehunter(path):
    data = json.loads(pathlib.Path(path).read_text())
    rows = []
    for v in data.get("vulnerabilities", []) or []:
        rows.append({"rule_id": v.get("vid", "?"),
                     "severity": (v.get("severity") or "low").lower(),
                     "workload": "cluster/cluster", "category": "cluster_exposure",
                     "message": f"{v.get('vulnerability')} @ {v.get('location')}",
                     "extra": {"kind": "Cluster", "evidence": v.get("evidence"),
                               "category": v.get("category")}})
    return rows


def parse_nmap(path):
    root = ET.parse(path).getroot()
    rows = []
    for port in root.iter("port"):
        st = port.find("state")
        if st is None or st.get("state") != "open":
            continue
        num = int(port.get("portid"))
        svc = port.find("service")
        sname = svc.get("name", "unknown") if svc is not None else "unknown"
        rows.append({"rule_id": f"PORT-{num}",
                     "severity": "high" if num in HIGH_PORTS else "info",
                     "workload": "cluster/cluster", "category": "cluster_exposure",
                     "message": f"{num}/{port.get('protocol')} open ({sname})",
                     "extra": {"kind": "Cluster", "port": num}})
    return rows


PARSERS = {
    "checkov": ("out/checkov.json", parse_checkov),
    "gatekeeper": ("out/gatekeeper.json", parse_gatekeeper),
    "kubebench": ("out/kubebench.json", parse_kubebench),
    "kubehunter": ("out/kubehunter.json", parse_kubehunter),
    "nmap": ("out/nmap.xml", parse_nmap),
}
