#!/usr/bin/env bash
# Rebuild the whole lab from the repo (about 10 min). Use only if the cluster will not come back.
cd "$(dirname "$0")/.." || exit 1
set -x
kind delete cluster --name kguard
kind create cluster --name kguard
kubectl wait --for=condition=Ready node --all --timeout=240s
kubectl create ns payments; kubectl create ns web
kubectl label ns payments kguard.io/impact=5
kubectl label ns web kguard.io/impact=3
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update
helm install gatekeeper gatekeeper/gatekeeper -n gatekeeper-system --create-namespace --set replicas=1
kubectl wait --for=condition=Ready pod -l control-plane=controller-manager -n gatekeeper-system --timeout=240s
kubectl apply -f policies/templates/
sleep 25
kubectl apply -f policies/constraints/
GW=$(docker network inspect kind | jq -r '.[0].IPAM.Config[] | select((.Gateway // "") | test("^[0-9.]+$")) | .Gateway')
helm install falco falcosecurity/falco -n falco --create-namespace \
  --set driver.kind=modern_ebpf --set collectors.kubernetes.enabled=true --set tty=true \
  --set falcosidekick.enabled=true --set falcosidekick.replicaCount=1 \
  --set falcosidekick.config.webhook.address=http://$GW:8000/falco
kubectl apply -f manifests/bad/ -f manifests/good/
kubectl wait --for=condition=Ready pod --all -n payments --timeout=240s
kubectl wait --for=condition=Ready pod --all -n web --timeout=240s
echo "Rebuilt. Wait 2-3 min for Falco, then run scripts/healthcheck.sh"
