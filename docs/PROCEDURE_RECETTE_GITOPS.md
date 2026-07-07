# Procédure — pipeline propre IA → recette → main

Objectif : éviter qu’une correction générée par l’IA parte directement en production GitOps.

Le flux cible est :

```text
main
  └─ état de démo/prod suivi par Argo CD dans namespace demo

recette
  └─ état de test suivi par Argo CD dans namespace demo-recette

IA
  └─ ouvre une PR vers recette, jamais directement vers main par défaut
```

## Architecture Argo CD

Deux Applications Argo CD déploient le même workload, mais depuis deux branches et deux namespaces différents :

| Application Argo CD | Branche Git | Path | Namespace Kubernetes | Rôle |
|---|---|---|---|---|
| `vulnerable-app` | `main` | `apps/vulnerable-app/overlays/prod` | `demo` | environnement démo/prod |
| `vulnerable-app-recette` | `recette` | `apps/vulnerable-app/overlays/recette` | `demo-recette` | environnement de validation |

Les manifests sont organisés en Kustomize :

```text
apps/vulnerable-app/
  base/
    deployment.yaml
    service.yaml
  overlays/
    prod/
      kustomization.yaml      # namespace demo
    recette/
      kustomization.yaml      # namespace demo-recette
```

## Pourquoi `main` reste vulnérable ?

C’est volontaire pour la démo jury : `main/demo` garde une application vulnérable afin de rejouer les détections Trivy/Falco.

La correction IA est testée dans `recette/demo-recette`. Une fois validée, on peut promouvoir vers `main` au moment choisi.

## Première mise en place de la branche recette

Après avoir commité cette structure, pousser d’abord la branche `recette`, puis `main`.

```bash
git checkout main
git pull --ff-only

git add apps/vulnerable-app infra/argocd-apps README.md docs demo apps/remediator
git commit -m "feat(gitops): ajoute un environnement recette Argo CD"

git branch recette
git push -u origin recette
git push origin main
```

Pourquoi cet ordre ?

- `vulnerable-app-recette` référence `targetRevision: recette`.
- Si `main` est poussé avant que la branche `recette` existe, Argo CD crée l’Application mais ne trouve pas encore la branche.

## Vérifier que la recette est déployée

```bash
export KUBECONFIG="$(find "$PWD" -maxdepth 1 -name 'Kubeconfig*.yaml' -print -quit)"

kubectl -n argocd annotate application root-app \
  argocd.argoproj.io/refresh=hard \
  --overwrite

kubectl -n argocd get applications
kubectl -n demo-recette get deploy,pod,svc
```

Attendu :

```text
vulnerable-app-recette   Synced   Healthy
```

Et dans `demo-recette`, au départ, le workload doit être vulnérable comme `demo`.

## Générer une PR IA vers recette

Depuis un worktree propre :

```bash
source .env

python3 apps/remediator/ai_remediator.py \
  --source live \
  --create-pr
```

Par défaut, le script utilise :

```text
namespace rapport Trivy : demo-recette
base branch          : recette
feature branch       : ai/remediate-vulnerable-web-recette
```

Donc la PR générée par l’IA cible `recette`.

## Valider la PR IA en recette

Après merge de la PR dans `recette` :

```bash
bash demo/verify-after-merge.sh
```

Le script vérifie par défaut :

```text
Application Argo : vulnerable-app-recette
Namespace        : demo-recette
```

On veut voir :

- Argo `Synced/Healthy` ;
- pod `Running` ;
- image non-root ;
- `privileged: false` ;
- baisse des CVE Trivy ;
- baisse des checks ConfigAudit Trivy.

## Promouvoir vers main

Si la recette est validée, ouvrir une PR GitHub :

```text
recette → main
```

Après merge vers `main`, Argo CD appliquera dans `demo`.

Pour vérifier l’environnement `main/demo` :

```bash
APP_NAME=vulnerable-app NAMESPACE=demo bash demo/verify-after-merge.sh
```

## Résumé à dire au jury

> L’IA ne pousse pas en production. Elle ouvre une PR vers `recette`. Argo CD déploie automatiquement cette branche dans un namespace isolé. Après validation humaine et technique, on promeut vers `main`, qui est l’environnement suivi par l’Application principale.

