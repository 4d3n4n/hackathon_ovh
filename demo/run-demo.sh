#!/usr/bin/env bash
# Script de demo — rejoue l'etat actuel du projet, etape par etape.
# Usage : bash demo/run-demo.sh
# Variable optionnelle : KUBECONFIG.

set -euo pipefail

if [[ -z "${KUBECONFIG:-}" ]]; then
  if [[ -f "$HOME/.kube-hackathon/kubeconfig-equipe-14.yaml" ]]; then
    export KUBECONFIG="$HOME/.kube-hackathon/kubeconfig-equipe-14.yaml"
  else
    export KUBECONFIG="$(find "$PWD" -maxdepth 1 -name 'Kubeconfig*.yaml' -print -quit)"
  fi
fi

pause() {
  echo
  read -rp ">>> Appuie sur Entree pour continuer... " _
  echo
}

step() {
  echo
  echo "=================================================================="
  echo "  $1"
  echo "=================================================================="
}

step "1. Connexion au cluster"
kubectl get nodes
pause

step "2. Applications Argo CD (GitOps : Git est la source de verite)"
kubectl -n argocd get applications 2>/dev/null || echo "(Applications Argo CD non lisibles — verifie KUBECONFIG et le namespace argocd)"
pause

step "3. Le workload vulnerable qui tourne"
kubectl -n demo get deploy,pod,svc
echo
echo "-- securityContext du conteneur --"
kubectl -n demo get deploy vulnerable-web -o jsonpath='{.spec.template.spec.containers[0].securityContext}'
echo
echo "-- image utilisee --"
kubectl -n demo get deploy vulnerable-web -o jsonpath='{.spec.template.spec.containers[0].image}'
echo
pause

step "4. Rapport Trivy — vulnerabilites (CVE)"
kubectl -n demo get vulnerabilityreports
echo
echo "-- resume --"
REPORT=$(kubectl -n demo get vulnerabilityreports -o jsonpath='{.items[0].metadata.name}')
kubectl -n demo get vulnerabilityreport "$REPORT" -o jsonpath='{.report.summary}'
echo
pause

step "5. Rapport Trivy — configuration (misconfig)"
kubectl -n demo get configauditreports
echo
echo "-- checks en echec --"
CONFIG_REPORT=$(kubectl -n demo get configauditreports -o jsonpath='{.items[0].metadata.name}')
kubectl -n demo get configauditreport "$CONFIG_REPORT" -o json \
  | python3 -c "import json,sys; d=json.load(sys.stdin); [print(c['severity'], c['checkID'], '-', c['title']) for c in d['report']['checks'] if not c.get('success', True)]"
pause

step "6. Remediateur IA OVH — analyse et PR recette en dry-run"
echo "Le dry-run lit les rapports Trivy de demo-recette, appelle OVH AI Endpoints, valide le correctif, mais ne cree aucune branche."
read -rp "Executer l'analyse IA maintenant ? (o/N) " REPLY
if [[ "$REPLY" =~ ^[oO]$ ]]; then
  python3 apps/remediator/ai_remediator.py --source live || echo "(analyse IA non executee — verifier cle AI, reseau ou rapports Trivy)"
else
  echo "(saute)"
fi
echo
echo "Pour creer la vraie PR ensuite :"
echo "python3 apps/remediator/ai_remediator.py --source live --create-pr"
pause

step "7. Preuve du self-heal GitOps (optionnel)"
echo "On va scaler manuellement a 3 replicas (drift hors Git)..."
read -rp "Executer ce test ? (o/N) " REPLY
if [[ "$REPLY" =~ ^[oO]$ ]]; then
  kubectl -n demo scale deploy vulnerable-web --replicas=3
  echo "Attente 30s pour laisser Argo CD reagir..."
  sleep 30
  echo "-- etat apres self-heal --"
  kubectl -n demo get deploy vulnerable-web
else
  echo "(saute)"
fi

step "Fin de la demo — etat actuel du projet"
echo "Composants pas encore installes : Kyverno, Falco, Prometheus."
