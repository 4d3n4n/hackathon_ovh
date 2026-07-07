# Remédiateur IA OVH

Ce dossier contient le MVP de la boucle :

`Trivy reports → OVHcloud AI Endpoints → correctif GitOps borné → Pull Request vers recette → revue humaine → merge recette → Argo CD recette`.

Le script ne donne jamais les accès au cluster à l’IA et ne modifie jamais Kubernetes directement. L’IA sert à produire l’analyse, le titre/la description de PR et le plan de validation. Les PR IA ciblent par défaut la branche `recette`, déployée par Argo CD dans le namespace `demo-recette`. Les fichiers réellement modifiés sont limités à :

- `apps/vulnerable-app/base/deployment.yaml`
- `apps/vulnerable-app/base/service.yaml`

## Pré-requis

Depuis la racine du repo :

```bash
export KUBECONFIG="$(find "$PWD" -maxdepth 1 -name 'Kubeconfig*.yaml' -print -quit)"
```

La clé OVH AI Endpoints peut être fournie de deux façons :

```bash
export AI_ENDPOINT_API_KEY="..."
```

ou via le fichier local ignoré par Git :

```text
Clé des points de terminaison AI.txt
```

Pour créer une vraie PR automatiquement, il faut aussi l’une de ces options :

- `gh` installé et connecté ;
- ou `GITHUB_TOKEN` / `GH_TOKEN` avec droits `Contents: Read/Write` et `Pull requests: Read/Write`.

Sans token GitHub, le script pousse la branche si Git est authentifié puis affiche le lien GitHub “Compare & Pull Request”.

## Tester sans modifier

Mode cluster live :

```bash
python3 apps/remediator/ai_remediator.py --source live
```

Par défaut, le mode live lit les rapports dans `demo-recette`.

Mode hors ligne sur les fixtures Trivy déjà commitées :

```bash
python3 apps/remediator/ai_remediator.py --source fixtures
```

Mode secours sans appel IA, utile si l’endpoint est indisponible pendant la soutenance :

```bash
python3 apps/remediator/ai_remediator.py --source fixtures --skip-ai
```

## Créer la PR de remédiation

```bash
python3 apps/remediator/ai_remediator.py --source live --create-pr
```

Par défaut, cette commande crée une PR :

- depuis `ai/remediate-vulnerable-web-recette` ;
- vers `recette` ;
- testée ensuite par l'Application Argo CD `vulnerable-app-recette`.

Pour créer exceptionnellement une PR directe vers `main`, il faut l’expliciter :

```bash
python3 apps/remediator/ai_remediator.py \
  --source live \
  --namespace demo \
  --base-branch main \
  --branch ai/remediate-vulnerable-web-main \
  --create-pr
```

Le correctif proposé remplace le workload volontairement vulnérable par un NGINX non-root et durcit le manifeste :

- image `nginxinc/nginx-unprivileged:1.31.2-alpine-slim` ;
- port conteneur `8080`, Service conservé en port `80` ;
- `runAsNonRoot`, UID/GID non-root, seccomp `RuntimeDefault` ;
- `privileged: false`, `allowPrivilegeEscalation: false`, capabilities `drop: ALL` ;
- filesystem root en lecture seule avec `/tmp` en `emptyDir` ;
- requests/limits CPU et mémoire ;
- token ServiceAccount désactivé.

Après merge dans `recette`, Argo CD resynchronise automatiquement `demo-recette` et Trivy génère de nouveaux rapports. Si la recette est validée, on ouvre ensuite une PR `recette → main`.
