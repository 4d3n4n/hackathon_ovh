#!/usr/bin/env bash
# Vérification post-merge de la boucle IA -> PR -> Argo CD -> Trivy.
# Usage recette : bash demo/verify-after-merge.sh
# Usage prod/demo : APP_NAME=vulnerable-app NAMESPACE=demo bash demo/verify-after-merge.sh

set -euo pipefail

APP_NAME="${APP_NAME:-vulnerable-app-recette}"
NAMESPACE="${NAMESPACE:-demo-recette}"

if [[ -z "${KUBECONFIG:-}" ]]; then
  export KUBECONFIG="$(find "$PWD" -maxdepth 1 -name 'Kubeconfig*.yaml' -print -quit)"
fi

section() {
  echo
  echo "=================================================================="
  echo "  $1"
  echo "=================================================================="
}

section "1. Applications Argo CD"
kubectl -n argocd get applications

echo
echo "-- ${APP_NAME} revision/status --"
kubectl -n argocd get application "${APP_NAME}" \
  -o jsonpath='targetRevision={.spec.source.targetRevision}{"\n"}revision={.status.sync.revision}{"\n"}sync={.status.sync.status}{"\n"}health={.status.health.status}{"\n"}'

section "2. Rollout du workload"
kubectl -n "${NAMESPACE}" rollout status deploy/vulnerable-web --timeout=180s
kubectl -n "${NAMESPACE}" get deploy,pod,svc

section "3. Correctif réellement appliqué"
echo "-- image --"
kubectl -n "${NAMESPACE}" get deploy vulnerable-web \
  -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'

echo "-- containerPort --"
kubectl -n "${NAMESPACE}" get deploy vulnerable-web \
  -o jsonpath='{.spec.template.spec.containers[0].ports[0].containerPort}{"\n"}'

echo "-- pod securityContext --"
kubectl -n "${NAMESPACE}" get deploy vulnerable-web \
  -o jsonpath='{.spec.template.spec.securityContext}{"\n"}'

echo "-- container securityContext --"
kubectl -n "${NAMESPACE}" get deploy vulnerable-web \
  -o jsonpath='{.spec.template.spec.containers[0].securityContext}{"\n"}'

section "4. Rapports Trivy disponibles"
kubectl -n "${NAMESPACE}" get vulnerabilityreports || true
kubectl -n "${NAMESPACE}" get configauditreports || true

section "5. Résumé des vulnérabilités"
if command -v jq >/dev/null 2>&1; then
  kubectl -n "${NAMESPACE}" get vulnerabilityreports -o json \
    | jq -r '.items[]? | "\(.metadata.name) image=\(.report.artifact.repository):\(.report.artifact.tag) critical=\(.report.summary.criticalCount) high=\(.report.summary.highCount) medium=\(.report.summary.mediumCount) low=\(.report.summary.lowCount)"'
else
  kubectl -n "${NAMESPACE}" get vulnerabilityreports -o yaml
fi

section "6. Checks de configuration encore en échec"
if command -v jq >/dev/null 2>&1; then
  kubectl -n "${NAMESPACE}" get configauditreports -o json \
    | jq -r '.items[].report.checks[]? | select(.success != true) | [.severity, .checkID, .title] | @tsv'
else
  kubectl -n "${NAMESPACE}" get configauditreports -o yaml
fi

echo
echo "Si les nouveaux rapports ne sont pas encore visibles, attends 2 à 5 minutes puis relance ce script."
