#!/usr/bin/env python3
"""
OVH AI Endpoints remediator for the hackathon demo.

The workflow is intentionally constrained:
1. read Trivy Operator reports from the live cluster, or from demo fixtures;
2. ask OVHcloud AI Endpoints for a human-readable remediation analysis;
3. apply only a small allow-listed GitOps patch for the demo workload;
4. optionally create a branch, commit, push, and open a GitHub Pull Request.

The AI never receives secrets and never writes directly to the cluster.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_BASE_URL = "https://oai.endpoints.kepler.ai.cloud.ovh.net/v1"
DEFAULT_MODEL = "gpt-oss-20b"
DEFAULT_TARGET_IMAGE = "nginxinc/nginx-unprivileged:1.31.2-alpine-slim"
DEFAULT_BRANCH = "ai/remediate-vulnerable-web"
DEFAULT_NAMESPACE = "demo"

SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "UNKNOWN": 4,
}


class RemediatorError(RuntimeError):
    """Expected operational failure with a user-friendly message."""


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
        raise RemediatorError(f"Commande échouée: {command}\n{stderr}")
    return completed


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
    raise RemediatorError("Le fichier de clé AI ne contient pas de valeur exploitable.")


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
                raise RemediatorError(
                    f"La clé AI lue depuis {candidate.name} semble trop courte."
                )
            return token

    raise RemediatorError(
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


def kubectl_get_json(root: Path, namespace: str, resource: str) -> dict[str, Any]:
    completed = run(
        ["kubectl", "-n", namespace, "get", resource, "-o", "json"],
        cwd=root,
        env=kubectl_env(root),
    )
    return json.loads(completed.stdout)


def normalize_summary(summary: dict[str, Any] | None) -> dict[str, int]:
    summary = summary or {}
    normalized: dict[str, int] = {}
    for source_key, target_key in (
        ("criticalCount", "critical"),
        ("highCount", "high"),
        ("mediumCount", "medium"),
        ("lowCount", "low"),
        ("unknownCount", "unknown"),
        ("noneCount", "none"),
    ):
        try:
            normalized[target_key] = int(summary.get(source_key, 0))
        except (TypeError, ValueError):
            normalized[target_key] = 0
    return normalized


def summarize_vulnerability_item(item: dict[str, Any]) -> dict[str, Any]:
    report = item.get("report", {})
    vulnerabilities = report.get("vulnerabilities", []) or []
    top = sorted(
        vulnerabilities,
        key=lambda vuln: (
            SEVERITY_ORDER.get(str(vuln.get("severity", "UNKNOWN")).upper(), 9),
            str(vuln.get("vulnerabilityID", "")),
        ),
    )[:12]
    return {
        "name": item.get("metadata", {}).get("name"),
        "namespace": item.get("metadata", {}).get("namespace"),
        "artifact": report.get("artifact", {}),
        "registry": report.get("registry", {}),
        "os": report.get("os", {}),
        "scanner": report.get("scanner", {}),
        "summary": normalize_summary(report.get("summary")),
        "top_vulnerabilities": [
            {
                "id": vuln.get("vulnerabilityID"),
                "severity": vuln.get("severity"),
                "resource": vuln.get("resource"),
                "installedVersion": vuln.get("installedVersion"),
                "fixedVersion": vuln.get("fixedVersion"),
                "title": compact(vuln.get("title", ""), 160),
            }
            for vuln in top
        ],
    }


def summarize_config_item(item: dict[str, Any]) -> dict[str, Any]:
    report = item.get("report", {})
    checks = report.get("checks", []) or []
    failed = [check for check in checks if not check.get("success", True)]
    failed = sorted(
        failed,
        key=lambda check: (
            SEVERITY_ORDER.get(str(check.get("severity", "UNKNOWN")).upper(), 9),
            str(check.get("checkID", "")),
        ),
    )
    return {
        "name": item.get("metadata", {}).get("name"),
        "namespace": item.get("metadata", {}).get("namespace"),
        "scanner": report.get("scanner", {}),
        "summary": normalize_summary(report.get("summary")),
        "failed_checks": [
            {
                "id": check.get("checkID"),
                "severity": check.get("severity"),
                "title": check.get("title"),
                "remediation": compact(check.get("remediation", ""), 220),
            }
            for check in failed[:25]
        ],
    }


def collect_live_reports(root: Path, namespace: str) -> dict[str, Any]:
    vulnerabilities = kubectl_get_json(root, namespace, "vulnerabilityreports")
    configs = kubectl_get_json(root, namespace, "configauditreports")
    return {
        "source": "live-cluster",
        "namespace": namespace,
        "collected_at": utc_now(),
        "vulnerability_reports": [
            summarize_vulnerability_item(item)
            for item in vulnerabilities.get("items", [])
        ],
        "config_audit_reports": [
            summarize_config_item(item) for item in configs.get("items", [])
        ],
    }


def parse_simple_yaml_scalar(text: str, key: str) -> str | None:
    match = re.search(rf"(?m)^\s*{re.escape(key)}:\s*(.+?)\s*$", text)
    if not match:
        return None
    return match.group(1).strip().strip('"').strip("'")


def parse_yaml_summary(text: str) -> dict[str, int]:
    summary_match = re.search(r"(?ms)^\s{2}summary:\n(?P<body>(?:^\s{4}\w+Count:.*\n?)+)", text)
    if not summary_match:
        return {}
    body = summary_match.group("body")
    raw: dict[str, int] = {}
    for key, value in re.findall(r"(?m)^\s{4}(\w+Count):\s*(\d+)\s*$", body):
        raw[key] = int(value)
    return normalize_summary(raw)


def parse_fixture_vulnerability(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    blocks = re.split(r"\n\s{2}- ", text)
    vulnerabilities: list[dict[str, Any]] = []
    for block in blocks[1:]:
        vuln_id = parse_simple_yaml_scalar(block, "vulnerabilityID")
        if not vuln_id:
            continue
        vulnerabilities.append(
            {
                "id": vuln_id,
                "severity": parse_simple_yaml_scalar(block, "severity"),
                "resource": parse_simple_yaml_scalar(block, "resource"),
                "installedVersion": parse_simple_yaml_scalar(block, "installedVersion"),
                "fixedVersion": parse_simple_yaml_scalar(block, "fixedVersion"),
                "title": compact(parse_simple_yaml_scalar(block, "title") or "", 160),
            }
        )
    vulnerabilities = sorted(
        vulnerabilities,
        key=lambda vuln: (
            SEVERITY_ORDER.get(str(vuln.get("severity", "UNKNOWN")).upper(), 9),
            str(vuln.get("id", "")),
        ),
    )[:12]
    return {
        "name": parse_simple_yaml_scalar(text, "name"),
        "namespace": parse_simple_yaml_scalar(text, "namespace"),
        "artifact": {
            "repository": parse_simple_yaml_scalar(text, "repository"),
            "tag": parse_simple_yaml_scalar(text, "tag"),
        },
        "os": {
            "family": parse_simple_yaml_scalar(text, "family"),
            "name": parse_simple_yaml_scalar(text, "name"),
            "eosl": parse_simple_yaml_scalar(text, "eosl"),
        },
        "summary": parse_yaml_summary(text),
        "top_vulnerabilities": vulnerabilities,
        "fixture": str(path),
    }


def parse_fixture_config(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    checks: list[dict[str, Any]] = []
    for block in re.split(r"\n\s{2}- ", text)[1:]:
        if parse_simple_yaml_scalar(block, "success") != "false":
            continue
        checks.append(
            {
                "id": parse_simple_yaml_scalar(block, "checkID"),
                "severity": parse_simple_yaml_scalar(block, "severity"),
                "title": parse_simple_yaml_scalar(block, "title"),
                "remediation": compact(
                    parse_simple_yaml_scalar(block, "remediation") or "", 220
                ),
            }
        )
    checks = sorted(
        checks,
        key=lambda check: (
            SEVERITY_ORDER.get(str(check.get("severity", "UNKNOWN")).upper(), 9),
            str(check.get("id", "")),
        ),
    )
    return {
        "name": parse_simple_yaml_scalar(text, "name"),
        "namespace": parse_simple_yaml_scalar(text, "namespace"),
        "summary": parse_yaml_summary(text),
        "failed_checks": checks[:25],
        "fixture": str(path),
    }


def collect_fixture_reports(root: Path, fixture_dir: str) -> dict[str, Any]:
    directory = root / fixture_dir
    if not directory.exists():
        raise RemediatorError(f"Dossier de fixtures introuvable: {directory}")
    vulnerability_reports: list[dict[str, Any]] = []
    config_reports: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.yaml")):
        text = path.read_text(encoding="utf-8", errors="replace")
        if "kind: VulnerabilityReport" in text:
            vulnerability_reports.append(parse_fixture_vulnerability(path))
        elif "kind: ConfigAuditReport" in text:
            config_reports.append(parse_fixture_config(path))
    if not vulnerability_reports and not config_reports:
        raise RemediatorError(f"Aucun rapport Trivy exploitable dans {directory}")
    return {
        "source": "fixtures",
        "namespace": DEFAULT_NAMESPACE,
        "collected_at": utc_now(),
        "vulnerability_reports": vulnerability_reports,
        "config_audit_reports": config_reports,
    }


def collect_reports(args: argparse.Namespace, root: Path) -> dict[str, Any]:
    if args.source == "live":
        return collect_live_reports(root, args.namespace)
    if args.source == "fixtures":
        return collect_fixture_reports(root, args.fixture_dir)

    try:
        return collect_live_reports(root, args.namespace)
    except Exception as live_error:
        reports = collect_fixture_reports(root, args.fixture_dir)
        reports["live_error"] = compact(str(live_error), 500)
        return reports


def compact(value: Any, limit: int) -> str:
    text = " ".join(str(value).split())
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()


def read_current_manifests(root: Path) -> dict[str, str]:
    paths = [
        "apps/vulnerable-app/deployment.yaml",
        "apps/vulnerable-app/service.yaml",
    ]
    manifests: dict[str, str] = {}
    for relative in paths:
        path = root / relative
        if not path.exists():
            raise RemediatorError(f"Manifest attendu introuvable: {relative}")
        manifests[relative] = path.read_text(encoding="utf-8")
    return manifests


def ai_prompt(
    reports: dict[str, Any],
    manifests: dict[str, str],
    target_image: str,
) -> list[dict[str, str]]:
    allowed_files = ", ".join(manifests.keys())
    system = textwrap.dedent(
        f"""
        Tu es un assistant de remédiation sécurité Kubernetes pour une démo GitOps.
        Analyse les rapports Trivy fournis et propose une correction compréhensible.
        Réponds en français. Toutes les valeurs textuelles du JSON doivent être
        en français, y compris le titre et le corps de PR.

        Contraintes fortes :
        - Ne révèle jamais de secret et n'invente pas de token.
        - Ne propose aucune commande kubectl apply directe : la correction passe par Git + PR.
        - Ne propose aucune fusion automatique : un humain relit puis merge.
        - Les seuls fichiers modifiables sont : {allowed_files}.
        - Le correctif attendu pour ce MVP doit rester minimal et sûr :
          image NGINX non-root, port conteneur 8080, securityContext durci,
          ressources requests/limits, service account token désactivé.

        Réponds uniquement avec un JSON valide, sans bloc Markdown, avec ces clés :
        risk_summary: string,
        root_causes: string[],
        recommended_changes: string[],
        validation_plan: string[],
        pr_title: string commençant par "fix(security):",
        pr_body: string.
        """
    ).strip()

    user = {
        "reports": reports,
        "current_manifests": manifests,
        "allow_listed_target_image": target_image,
    }
    return [
        {"role": "system", "content": system},
        {
            "role": "user",
            "content": json.dumps(user, ensure_ascii=False, indent=2),
        },
    ]


def call_ovh_ai(
    *,
    api_key: str,
    base_url: str,
    model: str,
    reports: dict[str, Any],
    manifests: dict[str, str],
    target_image: str,
) -> dict[str, Any]:
    endpoint = base_url.rstrip("/") + "/responses"
    payload = {
        "model": model,
        "store": False,
        "input": [
            {
                "type": "message",
                "role": message["role"],
                "content": message["content"],
            }
            for message in ai_prompt(reports, manifests, target_image)
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
        raise RemediatorError(
            f"Appel OVH AI Endpoints refusé ({error.code}). Détail: {compact(detail, 900)}"
        ) from error
    except urllib.error.URLError as error:
        raise RemediatorError(f"Appel OVH AI Endpoints impossible: {error}") from error

    text = extract_response_text(json.loads(body))
    return parse_ai_json(text)


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

    raise RemediatorError("Réponse OVH AI Endpoints reçue, mais texte introuvable.")


def parse_ai_json(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        match = re.search(r"(?s)\{.*\}", cleaned)
        if not match:
            raise RemediatorError(
                "L'IA n'a pas renvoyé de JSON exploitable. Réponse: "
                + compact(cleaned, 900)
            )
        parsed = json.loads(match.group(0))

    required = {
        "risk_summary",
        "root_causes",
        "recommended_changes",
        "validation_plan",
        "pr_title",
        "pr_body",
    }
    missing = sorted(required - set(parsed))
    if missing:
        raise RemediatorError(f"Réponse IA incomplète, clés manquantes: {missing}")
    return parsed


def offline_ai_analysis(target_image: str) -> dict[str, Any]:
    return {
        "risk_summary": (
            "Le workload de démo utilise nginx:1.16.0 basé sur Debian 9 EOL, "
            "exécuté en root et privilégié. Les rapports Trivy montrent des CVE "
            "critiques/hautes et des échecs de durcissement Kubernetes."
        ),
        "root_causes": [
            "Image applicative obsolète avec OS en fin de vie.",
            "Container privilégié et exécuté en root.",
            "Absence de limites ressources, seccomp et capabilities drop.",
            "Port conteneur privilégié 80 alors qu'un process non-root doit viser 8080.",
        ],
        "recommended_changes": [
            f"Remplacer l'image par {target_image}.",
            "Passer le container sur le port 8080 et garder le Service en port 80.",
            "Activer runAsNonRoot, seccomp RuntimeDefault, privileged=false.",
            "Désactiver l'escalade de privilèges, drop ALL capabilities, rootfs read-only.",
            "Ajouter requests/limits CPU et mémoire.",
        ],
        "validation_plan": [
            "kubectl apply --dry-run=client --validate=false -f apps/vulnerable-app",
            "Après merge, vérifier Argo CD Synced/Healthy.",
            "Attendre le nouveau rapport Trivy et comparer les compteurs Critical/High.",
        ],
        "pr_title": "fix(security): durcit le workload vulnerable-web",
        "pr_body": (
            "Cette PR remplace le workload volontairement vulnérable par une variante "
            "NGINX non-root et applique un securityContext Kubernetes plus strict. "
            "Elle illustre la boucle Trivy → IA OVH → PR → revue humaine → Argo CD."
        ),
    }


def render_fixed_deployment(target_image: str) -> str:
    return textwrap.dedent(
        f"""\
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: vulnerable-web
          namespace: demo
          labels:
            app: vulnerable-web
            demo-target: "true"
        spec:
          replicas: 1
          selector:
            matchLabels:
              app: vulnerable-web
          template:
            metadata:
              labels:
                app: vulnerable-web
                demo-target: "true"
            spec:
              automountServiceAccountToken: false
              securityContext:
                runAsNonRoot: true
                runAsUser: 65532
                runAsGroup: 65532
                fsGroup: 65532
                seccompProfile:
                  type: RuntimeDefault
              containers:
                - name: web
                  image: {target_image}
                  securityContext:
                    allowPrivilegeEscalation: false
                    capabilities:
                      drop:
                        - ALL
                    privileged: false
                    readOnlyRootFilesystem: true
                  resources:
                    requests:
                      cpu: 50m
                      memory: 64Mi
                    limits:
                      cpu: 250m
                      memory: 128Mi
                  ports:
                    - containerPort: 8080
                  volumeMounts:
                    - name: tmp
                      mountPath: /tmp
              volumes:
                - name: tmp
                  emptyDir: {{}}
        """
    )


def render_fixed_service() -> str:
    return textwrap.dedent(
        """\
        apiVersion: v1
        kind: Service
        metadata:
          name: vulnerable-web
          namespace: demo
          labels:
            app: vulnerable-web
        spec:
          selector:
            app: vulnerable-web
          ports:
            - name: http
              port: 80
              targetPort: 8080
        """
    )


def proposed_files(target_image: str) -> dict[str, str]:
    return {
        "apps/vulnerable-app/deployment.yaml": render_fixed_deployment(target_image),
        "apps/vulnerable-app/service.yaml": render_fixed_service(),
    }


def validate_rendered_files(root: Path, files: dict[str, str]) -> list[str]:
    checks: list[str] = []
    deployment = files["apps/vulnerable-app/deployment.yaml"]
    service = files["apps/vulnerable-app/service.yaml"]
    required_snippets = [
        "runAsNonRoot: true",
        "allowPrivilegeEscalation: false",
        "privileged: false",
        "readOnlyRootFilesystem: true",
        "seccompProfile:",
        "drop:",
        "- ALL",
        "automountServiceAccountToken: false",
        "containerPort: 8080",
    ]
    for snippet in required_snippets:
        if snippet not in deployment:
            raise RemediatorError(f"Validation interne échouée: '{snippet}' absent.")
    if "runAsUser: 0" in deployment or "privileged: true" in deployment:
        raise RemediatorError("Validation interne échouée: root/privileged encore présent.")
    if "targetPort: 8080" not in service:
        raise RemediatorError("Validation interne échouée: Service pas redirigé vers 8080.")
    checks.append("validation interne des garde-fous OK")

    if shutil.which("kubectl"):
        with tempfile.TemporaryDirectory(prefix="remediator-manifests-") as tmp:
            tmp_path = Path(tmp)
            for relative, content in files.items():
                destination = tmp_path / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(content, encoding="utf-8")
            completed = run(
                [
                    "kubectl",
                    "apply",
                    "--dry-run=client",
                    "--validate=false",
                    "-f",
                    str(tmp_path / "apps/vulnerable-app"),
                ],
                cwd=root,
                env=kubectl_env(root),
                check=False,
            )
            if completed.returncode == 0:
                checks.append("kubectl dry-run client OK")
            else:
                checks.append(
                    "kubectl dry-run client non bloquant: "
                    + compact(completed.stderr or completed.stdout, 260)
                )
    return checks


def print_summary(
    reports: dict[str, Any],
    ai_analysis: dict[str, Any],
    validation: list[str],
    *,
    dry_run: bool,
) -> None:
    print("Source rapports:", reports.get("source"))
    if reports.get("live_error"):
        print("Note:", reports["live_error"])
    for report in reports.get("vulnerability_reports", []):
        artifact = report.get("artifact", {})
        print(
            "VulnReport:",
            report.get("name"),
            f"{artifact.get('repository', '?')}:{artifact.get('tag', '?')}",
            report.get("summary"),
        )
    for report in reports.get("config_audit_reports", []):
        print(
            "ConfigAuditReport:",
            report.get("name"),
            report.get("summary"),
            f"checks_failed={len(report.get('failed_checks', []))}",
        )
    print()
    print("Analyse IA:")
    print("-", ai_analysis["risk_summary"])
    print()
    print("Titre PR proposé:")
    print("-", ai_analysis["pr_title"])
    print()
    print("Validations:")
    for item in validation:
        print("-", item)
    if dry_run:
        print()
        print("DRY-RUN: aucun fichier modifié, aucune branche créée, aucune PR ouverte.")


def ensure_clean_worktree(root: Path) -> None:
    status = run(["git", "status", "--porcelain"], cwd=root).stdout.strip()
    if status:
        raise RemediatorError(
            "Le worktree n'est pas propre. Commit/stash d'abord, puis relance "
            "la création de PR.\nChangements détectés:\n" + status
        )


def checkout_branch(root: Path, branch: str) -> None:
    current = run(["git", "branch", "--show-current"], cwd=root).stdout.strip()
    if current == branch:
        return
    existing = run(["git", "rev-parse", "--verify", branch], cwd=root, check=False)
    if existing.returncode == 0:
        run(["git", "checkout", branch], cwd=root)
    else:
        run(["git", "checkout", "-b", branch], cwd=root)


def write_files(root: Path, files: dict[str, str]) -> None:
    for relative, content in files.items():
        path = root / relative
        path.write_text(content, encoding="utf-8")


def commit_changes(root: Path, files: dict[str, str], title: str) -> bool:
    for relative in files:
        run(["git", "add", relative], cwd=root)
    diff = run(["git", "diff", "--cached", "--quiet"], cwd=root, check=False)
    if diff.returncode == 0:
        return False
    run(["git", "diff", "--cached", "--check"], cwd=root)
    message = title if title.startswith("fix(") else "fix(security): remediate vulnerable-web"
    run(["git", "commit", "-m", message], cwd=root)
    return True


def push_branch(root: Path, branch: str) -> None:
    run(["git", "push", "-u", "origin", branch], cwd=root)


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
    raise RemediatorError(f"Remote GitHub non reconnu: {remote}")


def create_github_pr(
    root: Path,
    *,
    branch: str,
    title: str,
    body: str,
    base: str,
) -> str:
    if shutil.which("gh"):
        completed = run(
            [
                "gh",
                "pr",
                "create",
                "--base",
                base,
                "--head",
                branch,
                "--title",
                title,
                "--body",
                body,
            ],
            cwd=root,
        )
        return completed.stdout.strip()

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    owner, repo = github_repo_from_remote(root)
    if not token:
        return f"https://github.com/{owner}/{repo}/compare/{base}...{urllib.parse.quote(branch)}?expand=1"

    payload = json.dumps(
        {"title": title, "head": branch, "base": base, "body": body}
    ).encode("utf-8")
    request = urllib.request.Request(
        f"https://api.github.com/repos/{owner}/{repo}/pulls",
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            created = json.loads(response.read().decode("utf-8"))
            return created.get("html_url", "")
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        if error.code == 422 and "A pull request already exists" in detail:
            return f"https://github.com/{owner}/{repo}/pulls"
        raise RemediatorError(
            f"Création PR GitHub refusée ({error.code}): {compact(detail, 900)}"
        ) from error


def build_pr_body(ai_analysis: dict[str, Any], validation: list[str]) -> str:
    recommended = "\n".join(
        f"- {item}" for item in ai_analysis.get("recommended_changes", [])
    )
    plan = "\n".join(f"- {item}" for item in ai_analysis.get("validation_plan", []))
    checks = "\n".join(f"- {item}" for item in validation)
    return textwrap.dedent(
        f"""
        ## Analyse IA OVH

        {ai_analysis["risk_summary"]}

        ## Changements proposés

        {recommended}

        ## Plan de validation

        {plan}

        ## Validations locales du remédiateur

        {checks}

        ---

        PR générée par `apps/remediator/ai_remediator.py`.
        Elle reste soumise à revue humaine avant merge.
        """
    ).strip()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyse les rapports Trivy avec OVH AI Endpoints et prépare une PR GitOps."
    )
    parser.add_argument(
        "--source",
        choices=("auto", "live", "fixtures"),
        default="auto",
        help="Source des rapports Trivy. auto tente le cluster puis les fixtures.",
    )
    parser.add_argument("--namespace", default=DEFAULT_NAMESPACE)
    parser.add_argument("--fixture-dir", default="demo/fixtures")
    parser.add_argument("--api-key-file")
    parser.add_argument(
        "--base-url",
        default=os.environ.get("AI_ENDPOINT_BASE_URL", DEFAULT_BASE_URL),
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("AI_ENDPOINT_MODEL", DEFAULT_MODEL),
    )
    parser.add_argument(
        "--target-image",
        default=os.environ.get("REMEDIATOR_TARGET_IMAGE", DEFAULT_TARGET_IMAGE),
    )
    parser.add_argument("--branch", default=DEFAULT_BRANCH)
    parser.add_argument("--base-branch", default="main")
    parser.add_argument(
        "--skip-ai",
        action="store_true",
        help="Mode secours pour tester le pipeline sans appeler OVH AI Endpoints.",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Écrit les manifests corrigés dans le worktree courant, sans commit ni PR.",
    )
    parser.add_argument(
        "--create-pr",
        action="store_true",
        help="Crée une branche, commit, push et ouvre une PR si un token/gh est disponible.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = repo_root()

    try:
        reports = collect_reports(args, root)
        manifests = read_current_manifests(root)
        if args.skip_ai:
            ai_analysis = offline_ai_analysis(args.target_image)
        else:
            api_key = read_api_key(root, args.api_key_file)
            ai_analysis = call_ovh_ai(
                api_key=api_key,
                base_url=args.base_url,
                model=args.model,
                reports=reports,
                manifests=manifests,
                target_image=args.target_image,
            )

        files = proposed_files(args.target_image)
        validation = validate_rendered_files(root, files)
        dry_run = not args.write and not args.create_pr
        print_summary(reports, ai_analysis, validation, dry_run=dry_run)

        if dry_run:
            return 0

        if args.create_pr:
            ensure_clean_worktree(root)
            checkout_branch(root, args.branch)

        write_files(root, files)

        if args.write and not args.create_pr:
            print("\nFichiers écrits localement. Aucune branche/PR créée.")
            return 0

        title = str(ai_analysis.get("pr_title") or "fix(security): remediate vulnerable-web")
        body = build_pr_body(ai_analysis, validation)
        committed = commit_changes(root, files, title)
        if not committed:
            print("\nAucun changement à committer: la remédiation semble déjà appliquée.")
            return 0
        push_branch(root, args.branch)
        pr_url = create_github_pr(
            root,
            branch=args.branch,
            title=title,
            body=body,
            base=args.base_branch,
        )
        print("\nPR prête:")
        print(pr_url)
        return 0
    except RemediatorError as error:
        print(f"Erreur: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
