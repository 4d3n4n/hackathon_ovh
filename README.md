# Hackathon OVHcloud x Ynov — équipe 14

Boucle GitOps de sécurité : détection (Trivy/Kyverno/Falco) → proposition de correctif par IA (OVHcloud AI Endpoints) → Pull Request → revue humaine → merge → resynchronisation Argo CD → preuve de correction.

## Structure

- `apps/vulnerable-app/` — workload volontairement vulnérable (cible de démo)
- `apps/remediator/` — script qui lit les rapports, appelle l'IA, ouvre la PR
- `infra/argocd-apps/` — App of Apps Argo CD (root-app + une Application par composant)
- `infra/trivy/`, `infra/kyverno/`, `infra/prometheus/`, `infra/falco/` — Applications Argo CD pour chaque composant de sécurité (charts figés)
- `policies/` — policies Kyverno
- `docs/` — rapport d'architecture, tableau CNCF
- `demo/` — script de démo, commandes de restauration de l'état vulnérable

## Règle GitOps

Après le bootstrap initial d'Argo CD (fait une seule fois, hors Git) et le premier apply de `infra/argocd-apps/root-app.yaml`, **tout changement de ressource part de Git**. Aucun `kubectl apply` manuel sur le cluster ensuite, sauf secrets.

## Bootstrap (une seule fois, hors Git)

```bash
export KUBECONFIG=/chemin/vers/kubeconfig-equipe-14.yaml
kubectl create namespace argocd
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml --server-side --force-conflicts
kubectl apply -f infra/argocd-apps/root-app.yaml
```

## Secrets

Aucun secret n'est commité. Variables d'environnement requises pour le remédiateur : voir `apps/remediator/README.md`.

## Remédiateur IA

Le MVP de remédiation est dans `apps/remediator/`. Il lit les rapports Trivy, appelle OVHcloud AI Endpoints avec la clé locale ignorée par Git, génère une analyse, applique uniquement un correctif allow-listé sur le workload de démo, puis peut préparer une Pull Request.

Dry-run sans modification :

```bash
python3 apps/remediator/ai_remediator.py --source live
```

Création de PR :

```bash
python3 apps/remediator/ai_remediator.py --source live --create-pr
```

La PR reste toujours soumise à revue humaine avant merge.

Procédure détaillée de démo et vérification post-merge : `docs/PROCEDURE_REMEDIATION_IA.md`.

Pipeline propre IA → recette → main : `docs/PROCEDURE_RECETTE_GITOPS.md`.
