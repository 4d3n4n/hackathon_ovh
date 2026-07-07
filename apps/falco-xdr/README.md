# Mini-XDR : Falco → IA → Issue GitHub

Ce dossier contient la brique de corrélation runtime de la démo :

`Alerte Falco (comportement) → OVHcloud AI Endpoints (analyse SOC) → Issue GitHub → investigation humaine`.

Contrairement à `apps/remediator/` (qui corrige un manifest via une Pull Request), une alerte
runtime n'a pas de "correctif YAML" évident — le script ne modifie donc jamais rien sur le
cluster ni sur le repo. Il se contente de lire les logs Falco, de faire analyser l'alerte
par l'IA (sévérité, technique MITRE probable, actions recommandées), puis d'ouvrir une
Issue GitHub pour qu'un humain investigue.

## Pré-requis

Depuis la racine du repo :

```bash
export KUBECONFIG="$(find "$PWD" -maxdepth 1 -name 'Kubeconfig*.yaml' -print -quit)"
```

La clé OVH AI Endpoints peut être fournie de deux façons :

```bash
export AI_ENDPOINT_API_KEY="..."
```

ou via le fichier local ignoré par Git (`Clé des points de terminaison AI.txt`).

Pour créer une vraie Issue automatiquement, il faut aussi l'une de ces options :

- `gh` installé et connecté ;
- ou `GITHUB_TOKEN` / `GH_TOKEN` avec droits `Issues: Read/Write`.

Sans token GitHub, le script affiche un lien `github.com/.../issues/new?...` pré-rempli
(titre + corps + labels) à ouvrir soi-même dans le navigateur.

## Tester sans réseau (fixture)

```bash
python3 apps/falco-xdr/falco_xdr.py --source fixtures
```

Utilise `demo/fixtures/falco-alert-sensitive-file-read.json`, une vraie alerte capturée sur
le cluster (`cat /etc/shadow` en root dans le pod vulnérable, règle Falco
`Read sensitive file untrusted`).

## Tester en direct sur le cluster

```bash
python3 apps/falco-xdr/falco_xdr.py --source live --since 15m
```

Lit les logs des pods Falco (namespace `falco`), ne garde que les alertes de priorité
`warning` ou plus grave concernant le namespace `demo`, dé-duplique par (règle, pod,
fichier/commande), puis affiche l'analyse IA sans rien créer (dry-run par défaut).

## Créer réellement l'Issue

```bash
python3 apps/falco-xdr/falco_xdr.py --source live --create-issue
```

Avant de créer une Issue, le script vérifie (si un token GitHub est disponible) qu'une
Issue ouverte portant la même empreinte (`<!-- falco-fingerprint: ... -->`) n'existe pas
déjà, pour éviter le bruit en cas de répétition de la même alerte.

## Mode secours sans IA

```bash
python3 apps/falco-xdr/falco_xdr.py --source live --skip-ai --create-issue
```

Utile si l'endpoint IA est indisponible pendant la soutenance : reformate l'alerte brute
en Issue exploitable, sans appel réseau vers l'IA.

## Déclencher une alerte de démo

```bash
kubectl exec deploy/vulnerable-web -n demo -- sh -c "cat /etc/shadow"
```

Ne fonctionne que si le workload tourne en root (état volontairement vulnérable, cf.
`apps/vulnerable-app/`) — un conteneur non-root reçoit `Permission denied` et Falco n'a
alors rien à détecter, ce qui est la preuve que le durcissement fonctionne.
