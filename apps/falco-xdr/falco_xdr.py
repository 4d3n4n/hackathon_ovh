#!/usr/bin/env python3
"""
Mini-XDR: correlateur Falco -> IA OVH -> Issue GitHub.

Boucle : alerte runtime Falco -> analyse par l'IA (severite, technique MITRE,
actions immediates) -> Issue GitHub ouverte automatiquement pour investigation
humaine. Contrairement au remediateur (apps/remediator), rien n'est jamais
corrige automatiquement ici : une alerte runtime n'a pas de "fix YAML" simple,
elle declenche une investigation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import textwrap
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

DEFAULT_BASE_URL = "https://oai.endpoints.kepler.ai.cloud.ovh.net/v1"
DEFAULT_MODEL = "gpt-oss-20b"
DEFAULT_FALCO_NAMESPACE = "falco"
DEFAULT_WORKLOAD_NAMESPACE = "demo"
DEFAULT_SINCE = "10m"
DEFAULT_MIN_PRIORITY = "warning"
DEFAULT_FIXTURE = "demo/fixtures/falco-alert-sensitive-file-read.json"
ISSUE_LABELS = ["security", "falco", "xdr"]

# Plus l'indice est bas, plus l'alerte est grave (ordre officiel des priorites Falco).
PRIORITY_ORDER = {
    "emergency": 0,
    "alert": 1,
    "critical": 2,
    "error": 3,
    "warning": 4,
    "notice": 5,
    "informational": 6,
    "debug": 7,
}


class XDRError(RuntimeError):
    pass


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def run(
    cmd: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        cmd,
        cwd=str(cwd),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and completed.returncode != 0:
        command = " ".join(cmd)
        stderr = completed.stderr.strip() or completed.stdout.strip()
        raise XDRError(f"Commande échouée: {command}\n{stderr}")
    return completed


def compact(value: Any, limit: int) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return text if len(text) <= limit else text[:limit] + "…"


# ---------- Clé API (mêmes conventions que apps/remediator) ----------


def load_first_secret_like_value(text: str) -> str:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("bearer "):
            return line.split(maxsplit=1)[1].strip()
        if "=" in line:
            _, value = line.split("=", 1)
            value = value.strip().strip('"').strip("'")
            if value:
                return value
        return line
    raise XDRError("Le fichier de clé AI ne contient pas de valeur exploitable.")


def read_api_key(root: Path, explicit_key_file: str | None) -> str:
    for env_name in (
        "AI_ENDPOINT_API_KEY",
        "OVH_AI_ENDPOINTS_ACCESS_TOKEN",
        "OVHCLOUD_API_KEY",
    ):
        value = os.environ.get(env_name)
        if value:
            return value.strip()

    candidates: list[Path] = []
    if explicit_key_file:
        candidates.append(Path(explicit_key_file).expanduser())
    candidates.extend(sorted(root.glob("*points de terminaison AI*.txt")))
    candidates.extend(sorted(root.glob("*AI*.txt")))

    seen: set[Path] = set()
    for candidate in candidates:
        candidate = candidate if candidate.is_absolute() else root / candidate
        if candidate in seen:
            continue
        seen.add(candidate)
        if candidate.exists() and candidate.is_file():
            token = load_first_secret_like_value(
                candidate.read_text(encoding="utf-8", errors="replace")
            )
            if len(token) < 20:
                raise XDRError(f"La clé AI lue depuis {candidate.name} semble trop courte.")
            return token

    raise XDRError(
        "Clé OVH AI Endpoints introuvable. Définis AI_ENDPOINT_API_KEY "
        "ou garde le fichier local 'Clé des points de terminaison AI.txt'."
    )


def detect_kubeconfig(root: Path) -> str | None:
    configured = os.environ.get("KUBECONFIG")
    if configured:
        return configured
    for pattern in ("Kubeconfig*.yaml", "*kubeconfig*.yaml", "*.kubeconfig"):
        matches = sorted(root.glob(pattern))
        if matches:
            return str(matches[0])
    return None


def kubectl_env(root: Path) -> dict[str, str]:
    env = os.environ.copy()
    kubeconfig = detect_kubeconfig(root)
    if kubeconfig:
        env["KUBECONFIG"] = kubeconfig
    return env


# ---------- Collecte des alertes Falco ----------


def parse_falco_json_lines(raw: str) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for line in raw.splitlines():
        start = line.find("{")
        if start == -1:
            continue
        candidate = line[start:]
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict) and "priority" in parsed and "rule" in parsed:
            alerts.append(parsed)
    return alerts


def collect_live_alerts(
    root: Path,
    *,
    falco_namespace: str,
    since: str,
    workload_namespace: str | None,
) -> list[dict[str, Any]]:
    completed = run(
        [
            "kubectl",
            "logs",
            "-n",
            falco_namespace,
            "-l",
            "app.kubernetes.io/name=falco",
            f"--since={since}",
            "--prefix=true",
            "--tail=-1",
        ],
        cwd=root,
        env=kubectl_env(root),
        check=False,
    )
    alerts = parse_falco_json_lines(completed.stdout)
    if workload_namespace:
        alerts = [
            alert
            for alert in alerts
            if alert.get("output_fields", {}).get("k8s.ns.name") == workload_namespace
        ]
    return alerts


def collect_fixture_alerts(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, list) else [data]


def filter_by_priority(alerts: list[dict[str, Any]], min_priority: str) -> list[dict[str, Any]]:
    threshold = PRIORITY_ORDER.get(min_priority.lower(), PRIORITY_ORDER["warning"])
    kept = []
    for alert in alerts:
        rank = PRIORITY_ORDER.get(str(alert.get("priority", "")).lower())
        if rank is not None and rank <= threshold:
            kept.append(alert)
    return kept


def incident_fingerprint(alert: dict[str, Any]) -> str:
    fields = alert.get("output_fields", {})
    key = "|".join(
        [
            str(alert.get("rule", "")),
            str(fields.get("k8s.pod.name", "")),
            str(fields.get("fd.name", fields.get("proc.cmdline", ""))),
        ]
    )
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]


def deduplicate_alerts(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Garde une occurrence par incident (même règle + même pod + même fichier/commande),
    en comptant les répétitions pour les remonter dans l'analyse."""
    grouped: dict[str, dict[str, Any]] = {}
    for alert in alerts:
        fp = incident_fingerprint(alert)
        if fp not in grouped:
            grouped[fp] = {"alert": alert, "occurrences": 0, "fingerprint": fp}
        grouped[fp]["occurrences"] += 1
    return list(grouped.values())


# ---------- Appel IA OVH (mêmes conventions que apps/remediator) ----------


def extract_response_text(response: dict[str, Any]) -> str:
    if isinstance(response.get("output_text"), str):
        return response["output_text"]

    chunks: list[str] = []
    for output in response.get("output", []) or []:
        for content in output.get("content", []) or []:
            if isinstance(content.get("text"), str):
                chunks.append(content["text"])
    if chunks:
        return "\n".join(chunks)

    for choice in response.get("choices", []) or []:
        message = choice.get("message", {})
        if isinstance(message.get("content"), str):
            return message["content"]

    raise XDRError("Réponse OVH AI Endpoints reçue, mais texte introuvable.")


def parse_ai_json(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        match = re.search(r"(?s)\{.*\}", cleaned)
        if not match:
            raise XDRError(
                "L'IA n'a pas renvoyé de JSON exploitable. Réponse: " + compact(cleaned, 900)
            )
        parsed = json.loads(match.group(0))

    required = {
        "severity_assessment",
        "mitre_technique",
        "likely_intent",
        "immediate_actions",
        "issue_title",
        "issue_body",
    }
    missing = sorted(required - set(parsed))
    if missing:
        raise XDRError(f"Réponse IA incomplète, clés manquantes: {missing}")
    return parsed


def incident_prompt(incident: dict[str, Any]) -> list[dict[str, str]]:
    system = textwrap.dedent(
        """
        Tu es analyste SOC (Security Operations Center) pour une démo GitOps Kubernetes.
        On te fournit une alerte runtime brute émise par Falco (comportement observé
        dans un conteneur, pas une simple analyse statique d'image).

        Réponds en français, uniquement avec un JSON valide (pas de bloc Markdown),
        avec ces clés :
        severity_assessment: string ("Faible", "Modérée", "Élevée" ou "Critique"),
        mitre_technique: string (ex: "T1555 - Credential Access from Password Stores"),
        likely_intent: string court (une phrase : que cherche probablement l'attaquant ?),
        immediate_actions: string[] (2 à 4 actions concrètes et réalistes, ex: isoler le
          pod, faire tourner les identifiants potentiellement exposés, vérifier les logs
          d'accès associés),
        issue_title: string commençant par "[Falco]",
        issue_body: string markdown en français, avec un résumé, le contexte
          (pod/namespace/image concernés) et les actions recommandées.

        Ne révèle jamais de secret et n'invente pas de token. Ne propose jamais de
        commande qui modifierait le cluster : cette alerte doit seulement déclencher
        une investigation humaine.
        """
    ).strip()

    user_payload = {
        "rule": incident["alert"].get("rule"),
        "priority": incident["alert"].get("priority"),
        "message": incident["alert"].get("output"),
        "fields": incident["alert"].get("output_fields"),
        "tags": incident["alert"].get("tags"),
        "occurrences_in_window": incident["occurrences"],
    }
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False, indent=2)},
    ]


def call_ovh_ai(
    *, api_key: str, base_url: str, model: str, incident: dict[str, Any]
) -> dict[str, Any]:
    endpoint = base_url.rstrip("/") + "/responses"
    payload = {
        "model": model,
        "store": False,
        "input": [
            {"type": "message", "role": message["role"], "content": message["content"]}
            for message in incident_prompt(incident)
        ],
        "temperature": 0.2,
    }
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise XDRError(
            f"Appel OVH AI Endpoints refusé ({error.code}). Détail: {compact(detail, 900)}"
        ) from error
    except urllib.error.URLError as error:
        raise XDRError(f"Appel OVH AI Endpoints impossible: {error}") from error

    text = extract_response_text(json.loads(body))
    return parse_ai_json(text)


def offline_analysis(incident: dict[str, Any]) -> dict[str, Any]:
    """Repli sans appel IA (réseau coupé pendant la démo) : reformate l'alerte brute."""
    alert = incident["alert"]
    fields = alert.get("output_fields", {})
    return {
        "severity_assessment": "Élevée" if alert.get("priority", "").lower() in
        ("emergency", "alert", "critical") else "Modérée",
        "mitre_technique": ", ".join(alert.get("tags", [])) or "non déterminé",
        "likely_intent": "Analyse hors-ligne : vérifier manuellement l'intention.",
        "immediate_actions": [
            "Isoler le pod concerné (network policy ou scale à 0).",
            "Vérifier les identifiants potentiellement exposés.",
            "Corréler avec les logs d'accès du namespace.",
        ],
        "issue_title": f"[Falco] {alert.get('rule', 'Alerte runtime')} — {fields.get('k8s.pod.name', '?')}",
        "issue_body": (
            f"## Alerte Falco (analyse hors-ligne, IA non appelée)\n\n"
            f"**Règle** : {alert.get('rule')}\n\n"
            f"**Message brut** : {alert.get('output')}\n"
        ),
    }


# ---------- GitHub (issues, pas de PR) ----------


def github_repo_from_remote(root: Path) -> tuple[str, str]:
    remote = run(["git", "config", "--get", "remote.origin.url"], cwd=root).stdout.strip()
    patterns = [
        r"github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/.]+)(?:\.git)?$",
        r"https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/.]+)(?:\.git)?$",
    ]
    for pattern in patterns:
        match = re.search(pattern, remote)
        if match:
            return match.group("owner"), match.group("repo")
    raise XDRError(f"Remote GitHub non reconnu: {remote}")


def github_api_request(
    method: str, path: str, token: str, payload: dict[str, Any] | None = None
) -> Any:
    request = urllib.request.Request(
        f"https://api.github.com{path}",
        data=json.dumps(payload).encode("utf-8") if payload is not None else None,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method=method,
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def find_existing_issue(root: Path, token: str, fingerprint: str) -> str | None:
    owner, repo = github_repo_from_remote(root)
    try:
        issues = github_api_request(
            "GET",
            f"/repos/{owner}/{repo}/issues?state=open&labels={','.join(ISSUE_LABELS)}&per_page=50",
            token,
        )
    except (urllib.error.HTTPError, urllib.error.URLError):
        return None
    marker = f"falco-fingerprint: {fingerprint}"
    for issue in issues:
        if marker in (issue.get("body") or ""):
            return issue.get("html_url")
    return None


def create_github_issue(
    root: Path, *, title: str, body: str, fingerprint: str
) -> str:
    full_body = f"{body}\n\n<!-- falco-fingerprint: {fingerprint} -->"
    owner, repo = github_repo_from_remote(root)

    if shutil_which("gh"):
        completed = run(
            [
                "gh", "issue", "create",
                "--title", title,
                "--body", full_body,
                "--label", ",".join(ISSUE_LABELS),
            ],
            cwd=root,
        )
        return completed.stdout.strip()

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        query = urllib.parse.urlencode(
            {"title": title, "body": full_body, "labels": ",".join(ISSUE_LABELS)}
        )
        return f"https://github.com/{owner}/{repo}/issues/new?{query}"

    try:
        created = github_api_request(
            "POST",
            f"/repos/{owner}/{repo}/issues",
            token,
            {"title": title, "body": full_body, "labels": ISSUE_LABELS},
        )
        return created.get("html_url", "")
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise XDRError(f"Création Issue GitHub refusée ({error.code}): {compact(detail, 900)}") from error


def shutil_which(name: str) -> str | None:
    import shutil

    return shutil.which(name)


# ---------- Orchestration ----------


def print_incident_summary(incident: dict[str, Any], analysis: dict[str, Any]) -> None:
    alert = incident["alert"]
    print(f"Règle Falco   : {alert.get('rule')} (priorité {alert.get('priority')})")
    print(f"Occurrences   : {incident['occurrences']} dans la fenêtre analysée")
    print(f"Pod           : {alert.get('output_fields', {}).get('k8s.pod.name')}")
    print(f"Sévérité IA   : {analysis['severity_assessment']}")
    print(f"Technique     : {analysis['mitre_technique']}")
    print(f"Intention     : {analysis['likely_intent']}")
    print("Actions immédiates:")
    for action in analysis["immediate_actions"]:
        print(f"  - {action}")
    print()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=["live", "fixtures"], default="live")
    parser.add_argument("--falco-namespace", default=DEFAULT_FALCO_NAMESPACE)
    parser.add_argument("--workload-namespace", default=DEFAULT_WORKLOAD_NAMESPACE)
    parser.add_argument("--since", default=DEFAULT_SINCE)
    parser.add_argument("--min-priority", default=DEFAULT_MIN_PRIORITY)
    parser.add_argument("--fixture-file", default=DEFAULT_FIXTURE)
    parser.add_argument("--api-key-file")
    parser.add_argument("--base-url", default=os.environ.get("AI_ENDPOINT_BASE_URL", DEFAULT_BASE_URL))
    parser.add_argument("--model", default=os.environ.get("AI_ENDPOINT_MODEL", DEFAULT_MODEL))
    parser.add_argument("--skip-ai", action="store_true", help="Analyse hors-ligne, sans appel IA.")
    parser.add_argument(
        "--create-issue", action="store_true", help="Ouvre réellement une Issue GitHub."
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = repo_root()

    if args.source == "fixtures":
        alerts = collect_fixture_alerts(root / args.fixture_file)
    else:
        alerts = collect_live_alerts(
            root,
            falco_namespace=args.falco_namespace,
            since=args.since,
            workload_namespace=args.workload_namespace,
        )

    alerts = filter_by_priority(alerts, args.min_priority)
    incidents = deduplicate_alerts(alerts)

    if not incidents:
        print(
            f"Aucune alerte Falco de priorité >= {args.min_priority} "
            f"trouvée (source={args.source})."
        )
        return 0

    api_key = None
    if not args.skip_ai:
        try:
            api_key = read_api_key(root, args.api_key_file)
        except XDRError as error:
            print(f"Avertissement: {error} -> repli en mode hors-ligne.")

    github_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

    for incident in incidents:
        if api_key:
            try:
                analysis = call_ovh_ai(
                    api_key=api_key, base_url=args.base_url, model=args.model, incident=incident
                )
            except XDRError as error:
                print(f"Avertissement IA: {error} -> repli en mode hors-ligne.")
                analysis = offline_analysis(incident)
        else:
            analysis = offline_analysis(incident)

        print_incident_summary(incident, analysis)

        if not args.create_issue:
            print("DRY-RUN: aucune Issue GitHub créée (relance avec --create-issue).\n")
            continue

        if github_token:
            existing = find_existing_issue(root, github_token, incident["fingerprint"])
            if existing:
                print(f"Issue déjà ouverte pour cet incident: {existing}\n")
                continue

        url = create_github_issue(
            root,
            title=analysis["issue_title"],
            body=analysis["issue_body"],
            fingerprint=incident["fingerprint"],
        )
        print(f"✅ Issue GitHub: {url}\n")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except XDRError as error:
        print(f"Erreur: {error}", file=sys.stderr)
        sys.exit(1)
