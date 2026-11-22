#!/usr/bin/env bash
# Return the lab to the vulnerable BASELINE state (about 2 min). Run before every rehearsal/demo.
cd "$(dirname "$0")/.." || exit 1
API=http://localhost:8000
echo "[*] policies -> dryrun"
for k in k8sdenyprivileged/deny-privileged k8sdenyhostpath/deny-hostpath k8srequirelimits/require-limits k8sdenyroot/deny-root; do
  kubectl patch "$k" --type merge -p '{"spec":{"enforcementAction":"dryrun"}}' >/dev/null
done
echo "[*] removing old pods, then deploying vulnerable + clean workloads"
kubectl delete -f manifests/bad/ --ignore-not-found --grace-period=1 >/dev/null
kubectl delete pod test-priv -n payments --ignore-not-found --grace-period=1 >/dev/null
kubectl apply -f manifests/bad/ -f manifests/good/
kubectl wait --for=condition=Ready pod --all -n payments --timeout=180s
kubectl wait --for=condition=Ready pod --all -n web --timeout=180s
echo "[*] waiting 75s for the Gatekeeper audit"
sleep 75
echo "[*] re-scanning manifests (vulnerable + clean)"
rm -rf out/scan && mkdir -p out/scan
cp manifests/bad/*.yaml manifests/good/*.yaml out/scan/
.venv/bin/checkov -d out/scan --framework kubernetes -o json > out/checkov.json 2>/dev/null
curl -s -X POST $API/reset/events >/dev/null
curl -s -X POST $API/reset/snapshots >/dev/null
curl -s -X POST $API/ingest/all
echo
curl -s -X POST $API/snapshot/baseline
echo
echo "[*] baseline ready -> open the dashboard"
