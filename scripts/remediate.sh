#!/usr/bin/env bash
# Remediate: enforce policies, replace vulnerable pods with hardened ones, record residual risk (about 2 min).
cd "$(dirname "$0")/.." || exit 1
API=http://localhost:8000
echo "[*] policies -> deny (enforcing)"
for k in k8sdenyprivileged/deny-privileged k8sdenyhostpath/deny-hostpath k8srequirelimits/require-limits k8sdenyroot/deny-root; do
  kubectl patch "$k" --type merge -p '{"spec":{"enforcementAction":"deny"}}' >/dev/null
done
echo "[*] removing vulnerable pods + over-privileged RBAC"
kubectl delete -f manifests/bad/ --ignore-not-found --grace-period=1 >/dev/null
echo "[*] deploying hardened pods (must pass admission)"
kubectl apply -f manifests/fixed/
kubectl wait --for=condition=Ready pod --all -n payments --timeout=180s
kubectl wait --for=condition=Ready pod --all -n web --timeout=180s
echo "[*] waiting 75s for the Gatekeeper audit to refresh"
sleep 75
.venv/bin/checkov -d manifests/good -d manifests/fixed --framework kubernetes -o json > out/checkov.json 2>/dev/null
curl -s -X POST $API/reset/events >/dev/null      # incident closed
curl -s -X POST $API/ingest/all
echo
curl -s -X POST $API/snapshot/after
echo
echo "[*] residual risk recorded:"
curl -s "$API/api/compare" | jq -r '.[] | "  \(.workload)\t\(.before) (\(.before_band)) -> \(.after) (\(.after_band))"'
