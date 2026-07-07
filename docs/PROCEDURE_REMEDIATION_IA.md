# Procédure — boucle IA de remédiation GitOps

Cette procédure sert à démontrer la boucle :

`Trivy → OVH AI Endpoints → Pull Request → revue humaine → merge → Argo CD → nouveaux rapports Trivy`.

## Ce qui est automatique

- Trivy Operator scanne le workload et crée les rapports Kubernetes.
- Le remédiateur lit les rapports Trivy et appelle OVH AI Endpoints.
- Le remédiateur prépare le correctif GitOps, crée une branche, commit, push et ouvre une PR.
- Après merge sur `main`, Argo CD détecte le changement Git et resynchronise le cluster.
- Après le nouveau déploiement, Trivy régénère des rapports pour le nouveau ReplicaSet.

## Ce qui reste volontairement humain

- La revue de la PR.
- Le merge de la PR.
- La vérification finale pendant la démo.

On ne veut pas que l’IA merge seule ou applique directement dans Kubernetes. C’est un point important à expliquer au jury : l’IA propose, l’humain valide, GitOps applique.

## Préparer le terminal

Depuis la racine du repo :

```bash
cd /Users/adenan/Downloads/hackaton_ovh
export KUBECONFIG="$(find "$PWD" -maxdepth 1 -name 'Kubeconfig*.yaml' -print -quit)"
source .env
```

Le fichier `.env` reste local et ne doit jamais être commité.

## Avant merge : vérifier la PR

La PR doit montrer un changement sur :

- `apps/vulnerable-app/deployment.yaml`
- `apps/vulnerable-app/service.yaml`

Les points attendus :

- image remplacée par `nginxinc/nginx-unprivileged:1.31.2-alpine-slim` ;
- port conteneur passé de `80` à `8080` ;
- Service conservé en port `80`, mais `targetPort: 8080` ;
- `privileged: false` ;
- `allowPrivilegeEscalation: false` ;
- `readOnlyRootFilesystem: true` ;
- capabilities `drop: ALL` ;
- `runAsNonRoot: true` ;
- seccomp `RuntimeDefault` ;
- requests/limits CPU et mémoire ;
- `automountServiceAccountToken: false`.

Si la PR est correcte, la merger sur GitHub.

## Après merge : vérifier automatiquement

Utiliser le script :

```bash
bash demo/verify-after-merge.sh
```

Ce script vérifie :

- l’état Argo CD ;
- le rollout du Deployment ;
- l’image et le securityContext appliqués ;
- les rapports Trivy disponibles ;
- les compteurs de vulnérabilités ;
- les checks de configuration encore en échec.

## Après merge : commandes manuelles équivalentes

Forcer un refresh Argo si nécessaire :

```bash
kubectl -n argocd annotate application vulnerable-app argocd.argoproj.io/refresh=hard --overwrite
```

Vérifier Argo :

```bash
kubectl -n argocd get applications
```

Attendu :

```text
vulnerable-app   Synced   Healthy
```

Vérifier le rollout :

```bash
kubectl -n demo rollout status deploy/vulnerable-web
kubectl -n demo get deploy,pod,svc
```

Vérifier le contenu appliqué :

```bash
kubectl -n demo get deploy vulnerable-web \
  -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}{.spec.template.spec.containers[0].ports[0].containerPort}{"\n"}{.spec.template.spec.containers[0].securityContext}{"\n"}'
```

Attendu :

```text
nginxinc/nginx-unprivileged:1.31.2-alpine-slim
8080
{"allowPrivilegeEscalation":false,...,"privileged":false,"readOnlyRootFilesystem":true}
```

Vérifier les rapports Trivy :

```bash
kubectl -n demo get vulnerabilityreports
kubectl -n demo get configauditreports
```

Résumé des CVE :

```bash
kubectl -n demo get vulnerabilityreports -o json \
  | jq -r '.items[] | "\(.metadata.name) image=\(.report.artifact.repository):\(.report.artifact.tag) critical=\(.report.summary.criticalCount) high=\(.report.summary.highCount) medium=\(.report.summary.mediumCount)"'
```

Checks de configuration encore en échec :

```bash
kubectl -n demo get configauditreports -o json \
  | jq -r '.items[].report.checks[]? | select(.success != true) | [.severity, .checkID, .title] | @tsv'
```

## Point d’attention Trivy

Juste après le merge, il peut y avoir plusieurs rapports Trivy en même temps :

- anciens rapports liés à l’ancien ReplicaSet ;
- nouveaux rapports liés au nouveau ReplicaSet.

C’est normal. Pour la démo, montrer surtout :

1. Argo CD `Synced/Healthy` ;
2. nouveau pod `Running` ;
3. image corrigée ;
4. securityContext durci ;
5. baisse des vulnérabilités critiques/hautes et des erreurs de configuration sur le nouveau rapport.

