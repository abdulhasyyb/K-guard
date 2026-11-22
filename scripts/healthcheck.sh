#!/usr/bin/env bash
# K-Guard post-reboot health check. Run from anywhere: bash ~/k-guard/scripts/healthcheck.sh
cd "$(dirname "$0")/.." || exit 1
API=http://localhost:8000
PASS=0; FAIL=0
ok()  { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
hdr() { echo; echo "== $1"; }

hdr "1. Host"
systemctl is-active --quiet docker && ok "docker running" || bad "docker not running -> sudo systemctl start docker"
if swapon --show | grep -q swapfile; then ok "swap active"; else bad "swap off -> sudo swapon /swapfile"; fi
free -h | awk '/^Mem:/{print "  memory: " $7 " available of " $2}'

hdr "2. Cluster"
if ! docker ps --format '{{.Names}}' | grep -q '^kguard-control-plane$'; then
  echo "  node container is stopped -> starting it (waits up to 2 min)"
  docker start kguard-control-plane >/dev/null 2>&1
  for i in $(seq 1 24); do
    kubectl get nodes --no-headers 2>/dev/null | grep -q ' Ready' && break
    sleep 5
  done
fi
docker ps --format '{{.Names}}' | grep -q '^kguard-control-plane$' && ok "kind node container running" || bad "kind node container missing -> run scripts/rebuild.sh"
kubectl config use-context kind-kguard >/dev/null 2>&1
kubectl get nodes --no-headers 2>/dev/null | grep -q ' Ready' && ok "node Ready" || bad "node not Ready (wait 1-2 min and re-run; if still bad run scripts/rebuild.sh)"

hdr "3. Gatekeeper"
n=$(kubectl get pods -n gatekeeper-system --no-headers 2>/dev/null | grep -c ' Running')
[ "$n" -ge 2 ] && ok "gatekeeper pods running ($n)" || bad "gatekeeper pods not ready ($n/2): kubectl get pods -n gatekeeper-system"
t=$(kubectl get constrainttemplates --no-headers 2>/dev/null | wc -l)
[ "$t" -ge 4 ] && ok "4 constraint templates present" || bad "constraint templates: $t/4 -> kubectl apply -f policies/templates/"
c=$(kubectl get constraints -o json 2>/dev/null | jq '.items | length' 2>/dev/null)
[ "${c:-0}" -ge 4 ] && ok "4 constraints present" || bad "constraints: ${c:-0}/4 -> kubectl apply -f policies/constraints/"
kubectl get constraints -o json 2>/dev/null | jq -r '.items[] | "    \(.metadata.name): \(.spec.enforcementAction)"'

hdr "4. Workloads"
r=0
for ns in payments web; do
  k=$(kubectl get pods -n "$ns" --no-headers 2>/dev/null | grep -c ' Running')
  r=$((r + k))
done
[ "$r" -ge 7 ] && ok "7 workload pods running" || bad "only $r/7 pods running -> kubectl get pods -A | grep -E 'payments|web'"

hdr "5. Falco"
kubectl get pods -n falco --no-headers 2>/dev/null | sed 's/^/    /'
tot=$(kubectl get pods -n falco --no-headers 2>/dev/null | wc -l)
notready=$(kubectl get pods -n falco --no-headers 2>/dev/null | awk '{split($2,a,"/"); if (a[1]!=a[2] || $3!="Running") c++} END{print c+0}')
[ "$tot" -ge 3 ] && [ "$notready" -eq 0 ] && ok "falco, sidekick, metacollector all ready" || bad "falco pods not all ready (wait 2 min and re-run; else kubectl describe pod -n falco)"
GW=$(docker network inspect kind 2>/dev/null | jq -r '.[0].IPAM.Config[] | select((.Gateway // "") | test("^[0-9.]+$")) | .Gateway')
CFG=$(helm get values falco -n falco 2>/dev/null | grep -o 'http://[0-9.]*:[0-9]*/falco' | head -1)
if [ -n "$GW" ] && [ "$CFG" = "http://$GW:8000/falco" ]; then
  ok "sidekick webhook -> $CFG matches gateway"
else
  bad "webhook is '$CFG' but gateway is '$GW' -> run the helm upgrade below"
  echo "    helm upgrade falco falcosecurity/falco -n falco --set driver.kind=modern_ebpf --set collectors.kubernetes.enabled=true --set tty=true --set falcosidekick.enabled=true --set falcosidekick.replicaCount=1 --set falcosidekick.config.webhook.address=http://$GW:8000/falco"
fi

hdr "6. K-Guard engine"
if ! curl -s -m 3 "$API/api/risks" >/dev/null; then
  echo "  engine not running -> starting it"
  nohup .venv/bin/uvicorn engine.main:app --host 0.0.0.0 --port 8000 > out/engine.log 2>&1 &
  sleep 5
fi
if curl -s -m 3 "$API/api/risks" >/dev/null; then ok "engine responding on :8000"; else bad "engine down -> tail -n 20 out/engine.log"; fi
nrisk=$(curl -s "$API/api/risks" | jq 'length' 2>/dev/null)
if [ "${nrisk:-0}" -lt 2 ]; then
  echo "  no findings in DB -> re-ingesting scanner output"
  curl -s -X POST "$API/ingest/all" | jq -c .
fi
code=$(docker exec kguard-control-plane curl -s -m 5 -o /dev/null -w '%{http_code}' "http://$GW:8000/api/events" 2>/dev/null)
[ "$code" = "200" ] && ok "cluster node can reach the engine" || bad "node cannot reach engine at $GW:8000 (got '$code')"

hdr "7. End-to-end (attack -> Falco -> engine)"
before=$(curl -s "$API/api/events?limit=1000" | jq 'length' 2>/dev/null)
./attacks/attack.sh bad-root payments >/dev/null 2>&1
sleep 12
after=$(curl -s "$API/api/events?limit=1000" | jq 'length' 2>/dev/null)
[ "${after:-0}" -gt "${before:-0}" ] && ok "runtime event reached the engine ($before -> $after)" || bad "no new event arrived -> kubectl logs -n falco -l app.kubernetes.io/name=falcosidekick --tail=20"
curl -s -X POST "$API/reset/events" >/dev/null   # keep the baseline clean

hdr "8. Current risk table"
curl -s "$API/api/risks" | jq -r '.[] | "  \(.workload)\tL\(.likelihood) x I\(.impact) = \(.score)\t\(.band)"'

echo; echo "RESULT: $PASS passed, $FAIL failed"
