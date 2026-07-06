# Analyse et plan d'execution - Hackathon OVHcloud x Ynov

Date de l'analyse : 6 juillet 2026  
Derniere mise a jour : 6 juillet 2026, apres validation du socle Argo CD et de Trivy  
Equipe : equipe-14  
Statut : projet demarre - phases 2 et socle de la phase 4 operationnels

## Etat actuel - point de reprise

Legende : `[x]` verifie, `[ ]` restant.

### Fait et verifie sur le depot et le cluster

- [x] Depot GitHub `4d3n4n/hackathon_ovh` cree et branche locale `main` synchronisee avec `origin/main`.
- [x] Secrets exclus de Git ; aucun chemin kubeconfig/token/cle trouve dans l'historique Git actuel.
- [x] Kubeconfig et cle AI proteges en permissions `0600`.
- [x] Cluster OVH equipe 14 accessible ; 3 nodes Kubernetes `v1.35.2` sont `Ready`.
- [x] Argo CD `v3.4.2` installe dans `argocd` ; tous ses pods sont `Running`.
- [x] UI Argo CD accessible par port-forward local.
- [x] Pattern App of Apps actif avec `root-app`.
- [x] Applications `root-app`, `vulnerable-app` et `trivy-operator` toutes `Synced/Healthy`.
- [x] Workload `vulnerable-web` deploye dans `demo`, pod `1/1 Running` et Service cree.
- [x] Trivy Operator chart `0.33.2` deploye et limite au namespace `demo`.
- [x] Un `VulnerabilityReport` pour `nginx:1.16.0` et deux `ConfigAuditReport` sont disponibles.

### Prochaine action recommandee

Completer la phase 4 en extrayant et sauvegardant une fixture Trivy anonymisee, puis passer a la **phase 6 : premier appel AI Endpoints**. C'est le chemin critique vers la PR automatique. Kyverno peut etre realise en parallele, mais ne doit pas retarder le premier appel IA.

## 1. Synthese executive

Le but n'est pas d'installer une collection d'outils de securite. Il faut demontrer une boucle coherente et reproductible :

1. un workload Kubernetes volontairement vulnerable est decrit dans Git ;
2. Argo CD synchronise Git vers le cluster OVHcloud ;
3. Trivy ou Kubescape detecte les vulnerabilites ;
4. Kyverno detecte les mauvaises configurations ;
5. Falco detecte un comportement suspect a l'execution ;
6. Prometheus expose l'evolution des signaux de securite ;
7. un remediateur developpe par l'equipe envoie le rapport et le manifest Git a un modele OVHcloud AI Endpoints ;
8. le remediateur valide la proposition et ouvre automatiquement une Pull Request ;
9. un humain relit et merge la PR ;
10. Argo CD applique la correction et les controles montrent une amelioration mesurable.

La priorite absolue est donc la boucle **detection -> proposition IA -> PR -> revue humaine -> merge -> synchronisation -> preuve de correction**. Le jury privilegie la coherence de cette architecture et la demarche plutot que la profondeur de chaque outil.

### Definition de "termine"

Le projet sera considere pret lorsque :

- tous les composants obligatoires sont deployes depuis Git par Argo CD, hormis l'amorcage d'Argo CD et des secrets ;
- une vulnerabilite reproductible declenche une PR automatique ;
- la PR contient une correction comprehensible, un lien avec les constats detectes et des preuves de validation ;
- aucune correction IA n'est mergee automatiquement ;
- apres merge, Argo CD resynchronise et le workload reste fonctionnel ;
- les CVE Critical/High et les violations de configuration diminuent ou disparaissent ;
- le depot, le rapport d'architecture de 1-2 pages, le tableau CNCF et la demo de 10 minutes sont prets ;
- un plan B hors ligne permet de presenter chaque etape si le cluster, GitHub ou le reseau est indisponible.

## 2. Sources analysees

### Documents locaux

- `Brief Hackathon OVH x Ynov.pdf` - sujet officiel, contraintes, composants et livrables ;
- `Guide Hackathon OVH Ynov.pdf` - guide technique de 34 pages ;
- `README.txt` - inventaire et mode d'emploi des acces de l'equipe ;
- `Cle des points de terminaison AI.txt` - cle AI Endpoints, contenu volontairement non reproduit ;
- `Kubeconfig Equipe 14.yaml` - acces administrateur au cluster, contenu volontairement non reproduit.

### Verification externe au 6 juillet 2026

Les statuts et API susceptibles d'avoir evolue ont ete controles sur les sources officielles :

- [Argo - CNCF](https://www.cncf.io/projects/argo/) : Graduated ;
- [Kubescape - CNCF](https://www.cncf.io/projects/kubescape/) : Incubating ;
- [Falco - CNCF](https://www.cncf.io/projects/falco/) : Graduated ;
- [Prometheus - CNCF](https://www.cncf.io/announcements/2018/08/09/prometheus-graduates/) : Graduated ;
- [Kyverno - CNCF](https://www.cncf.io/announcements/2026/03/24/cloud-native-computing-foundation-announces-kyvernos-graduation/) : Graduated depuis mars 2026 ;
- [External Secrets - CNCF](https://www.cncf.io/projects/external-secrets/) : Sandbox, et non Incubating comme indique dans le guide ;
- [types de policies Kyverno](https://kyverno.io/docs/policy-types/overview/) : `ClusterPolicy` est legacy/deprecie depuis la version 1.18 ;
- [image NGINX non privilegiee](https://github.com/nginx/docker-nginx-unprivileged) : elle ecoute par defaut sur le port 8080.

## 3. Exigences non negociables

### Composants obligatoires

| Composant | Fonction attendue | Statut CNCF au 06/07/2026 | Preuve a montrer |
|---|---|---:|---|
| Argo CD | GitOps, synchronisation Git vers cluster | Graduated | Applications Synced/Healthy et self-heal |
| Trivy ou Kubescape | Audit des images et configurations | Trivy : non identifie comme projet CNCF heberge ; Kubescape : Incubating | rapport de vulnerabilites exploitable |
| Kyverno | Policy-as-code | Graduated | PolicyReport avec echec avant, succes apres |
| Falco | Detection runtime | Graduated | alerte lors d'une action suspecte controlee |
| Prometheus | Metriques et observabilite | Graduated | compteur de vulnerabilites avant/apres |
| OVHcloud AI Endpoints | Analyse et proposition de correction | hors CNCF, explicitement impose par le brief | appel reel et contenu de PR |

### Livrables

- depot Git complet gere par Argo CD ;
- code de la couche d'enrichissement/remediation IA ;
- demonstration live de bout en bout sur un workload volontairement vulnerable ;
- rapport d'architecture de 1-2 pages ;
- tableau du statut CNCF des composants ;
- soutenance de 10 minutes suivie de 5 minutes de questions.

### Regle GitOps

Apres l'installation initiale d'Argo CD et de l'Application racine, les changements de ressources doivent partir de Git. Les seuls ecarts acceptables a documenter sont l'amorcage des secrets et, si necessaire, l'installation initiale d'Argo CD.

## 4. Decisions d'architecture recommandees

### 4.1 Scanner : Trivy pour le MVP, avec reserve documentee

Le brief autorise explicitement **Kubescape ou Trivy** et le guide, le script pedagogique et les commandes fournis sont tous centres sur les CRD de Trivy. Pour maximiser les chances d'obtenir une boucle complete dans le temps imparti, le choix recommande est donc Trivy Operator.

Il existe toutefois une ambiguite : le brief demande des projets heberges par la CNCF, alors que Kubescape est clairement un projet CNCF Incubating et que Trivy n'apparait pas comme projet CNCF heberge dans les sources controlees. Action : faire confirmer ce point par un encadrant et consigner dans le rapport que Trivy est utilise parce qu'il est explicitement autorise par le brief. Si le jury exige strictement un projet heberge, basculer sur Kubescape.

### 4.2 Depot et deploiement

- GitHub est recommande car le guide et le prototype utilisent PyGithub.
- Utiliser le pattern Argo CD **App of Apps**.
- Figer toutes les versions de charts et les digests d'images. Ne pas conserver `targetRevision: "*"` dans la version finale.
- Activer `prune` et `selfHeal`, puis prouver le self-heal par un test controle.
- Separer `apps/`, `infra/`, `policies/` et `docs/`.

### 4.3 Remediateur

MVP recommande : executable Python lance manuellement pendant la demo. Il lit le cluster et GitHub, appelle AI Endpoints et ouvre une PR.

Amelioration prioritaire apres fonctionnement du MVP : empaqueter le meme code dans un Job/CronJob Kubernetes, avec ServiceAccount et RBAC minimal, tout en gardant un declenchement manuel fiable pour la demo.

Le modele ne doit jamais avoir le droit de merger ou d'ecrire directement dans le cluster. Il propose ; le code valide ; un humain decide.

### 4.4 Secrets

- Aucun kubeconfig, token GitHub ou token AI ne doit entrer dans Git, dans une image ou dans les logs.
- Pour le MVP local : variables d'environnement chargees depuis un fichier ignore par Git.
- Pour le Job in-cluster : Secret Kubernetes cree hors Git et reference par `secretKeyRef`.
- ESO n'est utile que si un secret store compatible est deja disponible. L'ajouter sans fournisseur externe fiable augmente le risque sans ameliorer la demo.
- Rotation/revocation des tokens apres le hackathon.

## 5. Architecture logique cible

```text
GitHub (source de verite)
  |
  | surveillance/synchronisation
  v
Argo CD -------------------------------> Cluster OVHcloud
                                           |
                  +------------------------+---------------------+
                  |                        |                     |
                  v                        v                     v
             Trivy reports          Kyverno reports        Falco alerts
                  |                        |                     |
                  +------------+-----------+                     |
                               v                                 v
                         Remediateur IA <---------------- enrichissement optionnel
                               |
                               +--> OVHcloud AI Endpoints
                               |
                               +--> branche + commit + Pull Request GitHub
                                                        |
                                                  revue humaine
                                                        |
                                                      merge
                                                        |
                                                 Argo CD resync
                                                        |
                                      workload corrige + nouvelles metriques
```

Prometheus collecte les metriques des composants et alimente la preuve avant/apres. Il n'est pas la source de decision du MVP.

## 6. Ecarts et pieges identifies dans le guide

Ces points doivent etre corriges ou verifies pendant l'implementation ; copier-coller le guide tel quel est risque.

1. **Secrets lisibles par les autres utilisateurs locaux.** Le kubeconfig et la cle AI sont actuellement en permissions `0644`. Ils devront passer en `0600` avant utilisation.
2. **Noms de fichiers differents.** Le README cite `kubeconfig-equipe-14.yaml` et `ai-endpoints-key.txt`, alors que les fichiers livres portent des noms francais avec espaces/accents. Les scripts devront utiliser des chemins cites correctement ou des noms normalises.
3. **Information AI incomplete.** La cle est fournie, mais le bundle ne donne ni modele exact ni URL de base propre au modele. Ces deux valeurs doivent etre recuperees dans le catalogue AI Endpoints.
4. **Trivy n'est pas clairement un projet CNCF heberge.** Kubescape l'est. Faire valider le choix Trivy par l'encadrement.
5. **Valeur Helm Trivy obsolete.** Le guide utilise `trivy.ignoreUnfixed`; le chart Trivy Operator 0.33.2 expose actuellement `trivyOperator.ignoreUnfixed`. Une valeur inconnue peut etre silencieusement ignoree.
6. **Versions flottantes.** `targetRevision: "*"` rend la demo non reproductible et peut casser entre deux synchronisations. Figer les versions apres un premier deploiement valide.
7. **Policies Kyverno vieillissantes.** `ClusterPolicy` est legacy/deprecie dans Kyverno 1.18, et `spec.validationFailureAction` est egalement deprecie. Pour aller vite, les exemples peuvent servir au prototype si la version est figee ; pour une solution actuelle, preferer `policies.kyverno.io/v1` et les policies CEL.
8. **Policy non-root manquante.** Le workload comporte `runAsUser: 0`, mais les trois policies proposees ne couvrent pas explicitement `runAsNonRoot`, les capabilities, le filesystem en lecture seule ou le seccomp.
9. **Correction NGINX potentiellement non fonctionnelle.** Ajouter seulement `runAsNonRoot: true` a l'image NGINX classique peut empecher le demarrage. L'image `nginx-unprivileged` ecoute par defaut sur 8080 ; ports, probes et eventuel Service doivent etre ajustes.
10. **Validation IA insuffisante.** `yaml.safe_load()` verifie uniquement la syntaxe YAML. Il ne prouve ni le schema Kubernetes, ni le respect des labels/selectors, ni l'existence de l'image, ni la conformite Kyverno, ni le demarrage du pod.
11. **Script non idempotent.** Le prototype supprime une branche en attrapant toutes les exceptions et peut echouer si une PR equivalente existe deja. Il ne detecte ni doublon, ni absence de changement, ni rapport deja traite.
12. **Mapping rapport -> manifest hardcode.** Le prototype lit seulement `reports[0]` et modifie un chemin fixe. Il faut au minimum filtrer sur le workload de demo et verifier que le rapport correspond bien au manifest cible.
13. **Confiance excessive dans le contenu du prompt.** Les rapports et manifests sont des entrees non fiables. Le modele doit recevoir des instructions strictes, produire une sortie structuree et ne pouvoir modifier qu'une liste autorisee de champs.
14. **Metrique Grafana a verifier.** Le nom et les labels de la metrique peuvent varier selon la version du chart. Le ServiceMonitor doit etre effectivement selectionne par kube-prometheus-stack. Le dashboard doit etre teste avec la version figee.
15. **Falco depend du noyau et des privileges.** `modern_ebpf` est le bon premier choix, mais il faut tester la compatibilite reelle des nodes OVHcloud et la valeur du chart fige. Prevoir une preuve enregistree si le driver est bloque.
16. **Charge cluster importante.** kube-prometheus-stack, Trivy, Falco et Kyverno peuvent saturer un petit cluster. Verifier capacite et quotas avant de tout installer ; definir des requests/limits raisonnables.
17. **"Plus aucune CVE" est une promesse fragile.** Le succes doit etre mesure par la disparition ou la baisse des Critical/High corrigeables et la resolution des violations ciblees, pas par un rapport absolument vide.

## 7. Checklist detaillee d'execution

### Phase 0 - Cadrage et securisation des acces (P0, avant tout commit)

- [ ] Confirmer le nom des membres, leurs roles et le proprietaire du depot.
- [ ] Confirmer l'ordre de passage de la soutenance, absent du bundle.
- [ ] Demander a l'encadrant si Trivy satisfait bien la contrainte CNCF du brief.
- [x] Passer le kubeconfig et la cle AI en permissions `0600`.
- [x] Documenter le chemin du kubeconfig local et utiliser un motif `Kubeconfig*.yaml` robuste aux accents.
- [x] Exclure de Git : kubeconfig, cles, `.env*`, tokens, certificats et manifests de secrets.
- [x] Verifier qu'aucun fichier de secret n'apparait dans l'historique Git actuel.
- [ ] Verifier avant la soutenance qu'aucun secret n'apparait dans l'historique shell, les captures ou le partage d'ecran.
- [ ] Recuperer le nom exact du modele OVH et son `base_url`.
- [ ] Creer un token GitHub fine-grained limite au seul depot, avec Contents RW et Pull Requests RW.
- [ ] Definir qui peut approuver/merger la PR pendant la demo.
- [x] Recevoir le feu vert puis demarrer le projet sur le cluster equipe 14.

**Critere de sortie :** acces identifies, secrets proteges, choix Trivy/Kubescape confirme, aucune donnee sensible versionnee.

### Phase 1 - Preflight technique et depot (P0)

- [x] Tester localement `kubectl`, Helm et Git.
- [ ] Tester la version et l'environnement virtuel Python qui serviront au remediateur.
- [ ] Installer Argo CD CLI ; installer k9s seulement si l'equipe le souhaite.
- [x] Utiliser explicitement le kubeconfig OVH sans remplacer le contexte GKE personnel.
- [x] Verifier la version serveur et les nodes : Kubernetes `v1.35.2`, 3 nodes `Ready`.
- [ ] Verifier capacite CPU/RAM, quotas et droits avant d'ajouter les stacks lourdes.
- [x] Valider la compatibilite initiale d'Argo CD 3.4.2 et Trivy Operator chart 0.33.2 avec le cluster.
- [x] Creer et publier le depot GitHub public `4d3n4n/hackathon_ovh`.
- [ ] Ajouter tous les membres de l'equipe comme collaborateurs si necessaire.
- [ ] Activer protection de `main` : PR obligatoire, pas de push direct, au moins une approbation si possible.
- [ ] Creer la structure :
  - [x] `apps/vulnerable-app/`
  - [ ] `apps/remediator/`
  - [x] `infra/argocd-apps/`
  - [x] Trivy gere par `infra/argocd-apps/trivy-operator.yaml` ; dossier `infra/trivy/` inutile pour le chart actuel.
  - [ ] `infra/kyverno/`
  - [ ] `infra/prometheus/`
  - [ ] `infra/falco/`
  - [ ] `policies/`
  - [ ] `docs/`
  - [ ] `demo/`
- [x] Ajouter le README racine, la structure cible, la regle GitOps et les commandes de bootstrap.
- [ ] Ajouter l'architecture detaillee et les conventions de branches.
- [ ] Figer les versions initiales de chaque chart dans un fichier de decisions.

**Critere de sortie :** depot partage, branche principale protegee, cluster joignable en lecture, capacite connue, versions choisies.

### Phase 2 - Socle GitOps Argo CD (P0)

- [x] Installer Argo CD `v3.4.2` une seule fois dans `argocd`.
- [x] Attendre tous les pods Ready et verifier qu'ils sont `Running`.
- [x] Connecter le depot public en lecture a Argo CD.
- [x] Creer, publier et appliquer l'Application racine `root-app`.
- [x] Configurer `automated`, `prune`, `selfHeal` et `CreateNamespace=true`.
- [x] Deployer directement le workload de demo depuis Git et obtenir `Synced/Healthy`.
- [ ] Modifier le nombre de replicas dans Git et verifier la synchronisation.
- [ ] Tester le self-heal avec une modification manuelle controlee puis observer son annulation.
- [x] Verifier les trois Applications Argo CD `Synced/Healthy`.

**Critere de sortie :** un changement Git apparait automatiquement dans le cluster et un drift manuel est repare.

### Phase 3 - Workload vulnerable reproductible (P0)

- [x] Creer le Deployment vulnerable avec l'image ancienne `nginx:1.16.0`.
- [x] Ajouter volontairement `privileged: true`, execution root et absence de resources.
- [x] Ajouter un Service `vulnerable-web`.
- [ ] Ajouter une probe minimale afin de prouver que l'app fonctionne avant et apres correction.
- [x] Etiqueter clairement le workload avec `demo-target: "true"`.
- [x] Deployer uniquement via Argo CD.
- [x] Verifier le Deployment et le pod `1/1 Running`.
- [ ] Tester l'acces HTTP au Service par un port-forward ou depuis le cluster.
- [ ] Creer un tag Git ou un script de scenario permettant de reintroduire proprement la version vulnerable.
- [x] Ne conserver aucun secret dans le depot ou son historique actuel.

**Critere de sortie :** workload fonctionnel, quatre familles de problemes presentes, restauration de l'etat vulnerable testee.

### Phase 4 - Detection statique avec Trivy/Kubescape (P0)

- [x] Creer l'Application Argo CD de Trivy Operator avec chart fige `0.33.2`.
- [x] Utiliser la cle actuelle `trivyOperator.ignoreUnfixed`.
- [x] Limiter le scan au namespace `demo`, a deux jobs concurrents et avec des resources bornees.
- [x] Obtenir le premier `VulnerabilityReport` et les premiers `ConfigAuditReport`.
- [x] Verifier que le rapport de vulnerabilites cible `vulnerable-web` et `nginx:1.16.0`.
- [ ] Extraire Critical/High, image, versions installees et versions corrigees.
- [x] Verifier que Trivy genere aussi les rapports de configuration du ReplicaSet et du Service.
- [ ] Conserver un exemple JSON anonymise comme fixture de test du remediateur.
- [x] Observer un premier rapport environ 1 a 2 minutes apres le demarrage de Trivy ; refaire une mesure exacte pour la demo finale.

**Critere de sortie :** rapport machine-readable fiable et fixture de test sans secret.

### Phase 5 - Kyverno et policy-as-code (P0)

- [ ] Deployer Kyverno via Argo CD avec une version figee et ServerSideApply.
- [ ] Choisir soit les nouvelles `ValidatingPolicy` CEL, soit une version Kyverno figee compatible avec les exemples legacy.
- [ ] Commencer en mode Audit.
- [ ] Ajouter les controles :
  - [ ] conteneur non privilegie ;
  - [ ] execution non-root ;
  - [ ] tag/digest d'image explicite ;
  - [ ] requests et limits CPU/memoire ;
  - [ ] suppression des capabilities inutiles ;
  - [ ] seccomp `RuntimeDefault` ;
  - [ ] si compatible avec l'image, filesystem racine en lecture seule.
- [ ] Exclure proprement les namespaces systeme si necessaire.
- [ ] Tester les policies contre la fixture vulnerable.
- [ ] Verifier les PolicyReports avant/apres.
- [ ] Garder Audit pour la premiere demo ; presenter Enforce comme durcissement ulterieur.

**Critere de sortie :** violations lisibles avant correction, disparition des violations ciblees apres correction.

### Phase 6 - Premier appel AI Endpoints (P0, chemin critique)

- [ ] Charger token, base URL et modele depuis l'environnement.
- [ ] Faire un appel `curl` minimal sans afficher le token.
- [ ] Faire le meme appel via le SDK Python compatible OpenAI.
- [ ] Fixer timeout, nombre maximal de tokens et temperature faible.
- [ ] Tester les erreurs 401, 429, timeout et reponse vide.
- [ ] Enregistrer uniquement des metadonnees non sensibles : modele, duree, statut, identifiant de requete si disponible.
- [ ] Creer un mock local de la reponse pour developper sans consommer l'API.

**Critere de sortie :** appel reel reussi et test offline disponible.

### Phase 7 - Remediateur MVP local (P0, coeur du projet)

- [ ] Lire uniquement les rapports du namespace `demo` et du workload cible.
- [ ] Lire le manifest depuis `main` dans GitHub, jamais depuis l'etat live comme source de verite.
- [ ] Correlier explicitement rapport, image, Deployment et chemin Git.
- [ ] Resumer les constats pour limiter taille, cout et bruit du prompt.
- [ ] Donner au modele une liste fermee de champs modifiables.
- [ ] Exiger une sortie structuree : explication, correctifs, manifest ou patch.
- [ ] Traiter le contenu des rapports/manifests comme non fiable et encadrer les instructions du prompt.
- [ ] Valider la reponse :
  - [ ] YAML parseable ;
  - [ ] `apiVersion`, `kind`, nom, namespace, labels et selectors preserves ;
  - [ ] image explicitement figee et existante ;
  - [ ] `privileged` absent/false ;
  - [ ] `runAsNonRoot` et UID coherents avec l'image ;
  - [ ] ports/probes coherents, notamment 8080 pour NGINX unprivileged ;
  - [ ] requests/limits presentes ;
  - [ ] aucune ressource ou permission additionnelle inattendue ;
  - [ ] schema Kubernetes valide ;
  - [ ] policies Kyverno satisfaites ;
  - [ ] absence de secret dans le diff et le texte de PR.
- [ ] Refuser la PR si une validation critique echoue.
- [ ] Produire un diff minimal et lisible.
- [ ] Creer une branche unique incluant workload + hash du rapport.
- [ ] Detecter une PR ouverte equivalente et eviter les doublons.
- [ ] Ne rien faire si le manifest propose est identique.
- [ ] Creer commit et PR avec : resume, constats, changements, validations et mention "revue humaine obligatoire".
- [ ] Ne jamais merger automatiquement.
- [ ] Ajouter tests unitaires sur fixture Trivy et reponses IA valides/invalides.
- [ ] Ajouter README d'execution et variables requises, sans valeurs secretes.

**Critere de sortie :** une execution repetable ouvre exactement une PR valide, une seconde execution ne cree pas de doublon.

### Phase 8 - Validation et fermeture de boucle (P0)

- [ ] Faire relire la PR par un autre membre.
- [ ] Verifier que le diff ne modifie que le workload attendu.
- [ ] Merger manuellement.
- [ ] Observer Argo CD passer par OutOfSync puis Synced/Healthy.
- [ ] Verifier rollout, Ready, logs et HTTP de l'app corrigee.
- [ ] Attendre le nouveau scan.
- [ ] Comparer Critical/High avant/apres.
- [ ] Comparer PolicyReports avant/apres.
- [ ] Verifier qu'aucune nouvelle regression n'a ete introduite.
- [ ] Mesurer le temps total de la boucle pour la soutenance.

**Critere de sortie :** cluster corrige et fonctionnel, preuves avant/apres reproductibles.

### Phase 9 - Prometheus et preuve visuelle (P0 minimal, P1 dashboard)

- [ ] Deployer kube-prometheus-stack ou une installation Prometheus adaptee a la capacite.
- [ ] Figer la version et definir requests/limits.
- [ ] Activer le ServiceMonitor du scanner avec les labels attendus par Prometheus.
- [ ] Verifier dans Prometheus que la cible est `UP`.
- [ ] Identifier le nom exact des metriques et labels de la version figee.
- [ ] Construire un panneau avant/apres : Critical, High et total.
- [ ] Ajouter un panneau simple de sante des composants si le temps le permet.
- [ ] Exporter le dashboard dans Git.
- [ ] Capturer le dashboard comme plan B.

**Critere de sortie :** au moins une requete PromQL prouve l'evolution d'un signal de securite.

### Phase 10 - Falco runtime (P0)

- [ ] Deployer Falco via Argo CD avec chart fige et `modern_ebpf`.
- [ ] Verifier les contraintes noyau, BPF, capabilities et DaemonSet sur chaque node.
- [ ] Activer Falcosidekick/UI seulement si les ressources le permettent.
- [ ] Definir une action de demo sure et controlee.
- [ ] Declencher l'evenement dans le seul workload de demo.
- [ ] Verifier l'alerte, son horodatage, sa priorite et le workload associe.
- [ ] Eviter de lire ou afficher de vraies donnees sensibles ; privilegier un shell ou un fichier leurre.
- [ ] Capturer une preuve video/image en plan B.

**Critere de sortie :** une alerte runtime attribuable au workload apparait de facon reproductible.

### Phase 11 - Remediateur in-cluster (P1, apres MVP complet)

- [ ] Construire une image minimale, non-root et figee par digest.
- [ ] Deployer via Argo CD sous forme de Job/CronJob.
- [ ] Utiliser `load_incluster_config()`.
- [ ] Creer un ServiceAccount dedie.
- [ ] Donner uniquement `get/list/watch` sur les CRD de rapports necessaires.
- [ ] Monter les tokens par Secret, jamais par ConfigMap ou manifest Git.
- [ ] Ajouter NetworkPolicy si le CNI du cluster l'applique.
- [ ] Ajouter concurrence interdite, timeout, backoff et limites de ressources.
- [ ] Conserver un mode dry-run et un declenchement manuel.
- [ ] Prouver qu'une identite compromise ne peut ni merger une PR ni modifier directement le cluster.

**Critere de sortie :** automatisation in-cluster sure sans degrader la fiabilite de la demo.

### Phase 12 - Documentation et livrables (P0)

- [ ] Rediger le rapport d'architecture de 1-2 pages.
- [ ] Inclure le schema, le flux de donnees et le role de chaque composant.
- [ ] Expliquer le choix Trivy/Kubescape et l'ambiguite CNCF.
- [ ] Ajouter le tableau CNCF a jour.
- [ ] Documenter les limites : hallucination IA, latence de scan, dependance GitHub/reseau, faux positifs, cout et privileges.
- [ ] Documenter les garde-fous : validation, RBAC, secrets, revue humaine, versions figees.
- [ ] Completer le README racine : installation, bootstrap, rollback, demo, depannage.
- [ ] Completer le README du remediateur : variables, commandes, tests et erreurs.
- [ ] Ajouter les commandes de collecte de preuves sans secret.
- [ ] Verifier que tous les manifests et dashboards necessaires sont dans Git.
- [ ] Scanner l'historique Git pour detecter toute cle accidentelle.

**Critere de sortie :** un membre exterieur peut comprendre, deployer et expliquer la solution depuis le depot.

### Phase 13 - Preparation de la soutenance (P0)

- [ ] Affecter un narrateur et un operateur clavier distincts.
- [ ] Ecrire un script minute par minute.
- [ ] Preparer les onglets et port-forwards avant de commencer.
- [ ] Rejouer la boucle au moins deux fois depuis l'etat vulnerable.
- [ ] Chronometrer le temps de rescan et eviter d'attendre silencieusement.
- [ ] Preparer captures, logs anonymises et courte video de chaque etape.
- [ ] Preparer un commit/tag de restauration de l'etat vulnerable.
- [ ] Tester le plan B sans reseau.
- [ ] Repartir les reponses Q/A : architecture, securite, IA, Kubernetes, limites.
- [ ] Faire une verification finale d'absence de secrets a l'ecran.

**Critere de sortie :** demo inferieure ou egale a 10 minutes, reproductible et presentable hors ligne.

## 8. Ordre de priorite

### P0 - indispensable

1. secrets et acces ;
2. Argo CD et App of Apps ;
3. workload vulnerable ;
4. rapport Trivy/Kubescape ;
5. appel AI Endpoints ;
6. remediateur local et PR ;
7. merge humain, resync et preuve de correction ;
8. Kyverno, Falco et Prometheus suffisamment fonctionnels pour satisfaire le brief ;
9. rapport, tableau CNCF et demo.

### P1 - fort impact si P0 est stable

- Job/CronJob in-cluster et RBAC minimal ;
- deduplication multi-rapports ;
- validation schema/policies automatisee ;
- dashboard Grafana versionne ;
- issue GitHub enrichie depuis une alerte Falco ;
- NetworkPolicy et durcissement du conteneur remediateur.

### P2 - uniquement si tout le reste est repete

- Istio ;
- ESO sans fournisseur deja disponible ;
- remediation multi-workloads generique ;
- interface web dediee ;
- Enforce generalise des policies.

## 9. Repartition conseillee pour environ 7 personnes

| Pole | Personnes | Responsabilites | Dependances |
|---|---:|---|---|
| GitOps/plateforme | 2 | depot, Argo CD, App of Apps, workload, rollback | demarre immediatement |
| Detection/policies | 2 | Trivy/Kubescape, Kyverno, fixtures | depend du workload |
| Runtime/observabilite | 1 | Falco, Prometheus, dashboard | peut avancer en parallele |
| IA/remediation | 2 | AI Endpoints, code, validations, GitHub PR | chemin critique des le debut |

Une personne doit en plus tenir le journal de decisions et assembler le rapport au fil de l'eau ; ce role peut tourner.

## 10. Planning cible

### Jour 1 matin

- securiser les acces ;
- confirmer Trivy/Kubescape ;
- creer le depot ;
- installer Argo CD ;
- valider la premiere synchronisation GitOps.

### Jour 1 apres-midi

- deployer le workload vulnerable ;
- obtenir les premiers rapports ;
- faire le premier appel IA ;
- installer Kyverno ;
- commencer le remediateur sur fixture.

### Fin du jour 1

- Argo CD synchronise ;
- le workload est vulnerable et fonctionnel ;
- un rapport machine-readable existe ;
- un appel AI reel fonctionne ;
- le code sait produire localement une correction analysee.

### Jour 2 matin

- ouvrir la premiere PR automatiquement ;
- ajouter validations et deduplication ;
- fermer la boucle apres merge ;
- finaliser Falco et Prometheus ;
- commencer le rapport et les captures.

### Jour 2 apres-midi

- geler les fonctionnalites ;
- fiabiliser le rollback ;
- finaliser rapport/tableau CNCF ;
- repeter deux fois ;
- preparer le plan B et les Q/A.

## 11. Script de demo de 10 minutes

| Temps | Action | Message cle |
|---:|---|---|
| 0:00-1:00 | architecture + depot + Argo CD | Git est la source de verite |
| 1:00-2:00 | workload et rapport du scanner | la faille est detectee et structuree |
| 2:00-3:00 | PolicyReport Kyverno + alerte Falco | statique, configuration et runtime sont couverts |
| 3:00-5:00 | lancer le remediateur | l'IA analyse mais ne deploie rien directement |
| 5:00-6:30 | ouvrir et lire la PR | diff minimal, explication et validations |
| 6:30-7:30 | approbation et merge humains | le controle humain est volontaire |
| 7:30-9:00 | Argo CD resync + app Ready | GitOps applique le changement |
| 9:00-9:30 | rapports/metriques apres correction | amelioration mesurable |
| 9:30-10:00 | statuts CNCF, limites, suite | architecture coherente et garde-fous |

## 12. Registre des risques

| Risque | Probabilite | Impact | Mitigation |
|---|---:|---:|---|
| secret commite ou affiche | moyenne | critique | permissions 0600, gitignore, scan historique, captures anonymisees |
| cluster trop petit | moyenne | eleve | preflight capacite, limits, ordre d'installation, UI optionnelles |
| chart/API incompatible avec le guide | elevee | eleve | versions figees, lecture des values actuelles, tests par composant |
| correction IA invalide | elevee | eleve | validations fermes, image unprivileged, dry-run/schema, revue humaine |
| doublons de PR | elevee avec prototype | moyen | idempotency key, recherche de PR existante, branche unique |
| scan trop lent pour la demo | moyenne | eleve | mesurer, preparer etat pre-scane, dashboard/capture de secours |
| Falco bloque par le noyau | moyenne | moyen | modern eBPF, test tot, preuve enregistree |
| indisponibilite AI/GitHub/Wi-Fi | moyenne | eleve | fixtures et mock, captures/video, PR pre-creee de secours |
| ambiguite CNCF de Trivy | moyenne | moyen/eleve | confirmation encadrant, justification ecrite, plan Kubescape |
| app corrigee ne demarre pas | elevee si NGINX root | eleve | nginx-unprivileged, port 8080, probes et test HTTP |
| plus aucune CVE n'apparait apres correction | faible | moyen | mesurer baisse Critical/High et violations ciblees, ne pas promettre zero total |

## 13. Questions a trancher au lancement

- L'encadrement confirme-t-il que Trivy satisfait la contrainte CNCF malgre son statut distinct de Kubescape ?
- Quel depot GitHub et quelle organisation utiliser ?
- Quel modele AI Endpoints et quelle URL exacte sont attribues a l'equipe ?
- Quelle est la capacite reelle du cluster et combien d'equipes le partagent ?
- Le cluster a-t-il acces aux registries et bases de vulnerabilites necessaires ?
- Une solution de secret store compatible ESO est-elle deja fournie ?
- Quel est l'ordre exact de passage mardi ?

## 14. Etat de preparation local observe

- documents, kubeconfig et cle AI presents ;
- aucun projet applicatif ni depot Git n'a encore ete cree ;
- `kubectl` 1.36.1, Helm 4.2.0 et Git 2.54.0 sont installes ;
- Argo CD CLI et k9s ne sont pas installes ;
- la connectivite cluster et la validite des credentials n'ont volontairement pas ete testees pendant cette phase d'analyse ;
- les secrets n'ont pas ete affiches ni recopies dans ce document.

## 15. Prochaine etape, apres validation de cette analyse

Au deuxieme temps demande, commencer uniquement par la Phase 0 puis la Phase 1. Ne pas installer tous les composants d'un coup : valider chaque critere de sortie, conserver une preuve, puis passer a la phase suivante. Le premier objectif technique sera une synchronisation Argo CD fiable ; le premier objectif produit sera une PR automatique issue d'un vrai rapport.
