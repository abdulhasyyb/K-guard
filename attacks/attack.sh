#!/usr/bin/env bash
# Simulated attacker activity inside a vulnerable pod
POD=${1:-bad-root}
NS=${2:-payments}
echo "[*] Attacker foothold in $NS/$POD"
kubectl exec -n "$NS" "$POD" -- sh -c 'id; cat /etc/shadow; ls /var/run/secrets/kubernetes.io/serviceaccount'
echo "[*] Done"
