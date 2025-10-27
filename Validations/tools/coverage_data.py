import json
import os
from pathlib import Path
from typing import Dict, Set, Tuple

# Pure data utilities shared by CSV/Excel generators

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / 'detection' / 'output' / 'raw'
COVERAGE = ROOT / 'output' / 'coverage_report.json'

TOOLS = [
    'Checkov', 'Kubescape', 'KubeAudit', 'KubeLinter', 'Trivy', 'RBACPolice',
    'KubeConform', 'KubeScore', 'Pluto', 'Polaris', 'Conftest', 'Gitleaks', 'Yamllint'
]


def scan_to_tests(path: str) -> str:
    if not path:
        return None
    return f"tests/{os.path.basename(path)}"


def mark(detect: Dict[Tuple[str, str], Set[str]], file_key: str, category: str, tool: str) -> None:
    if not file_key or not category or not tool:
        return
    detect.setdefault((file_key, category), set()).add(tool)


def load_expected_by_file() -> Dict[str, Set[str]]:
    with open(COVERAGE, 'r', encoding='utf-8-sig') as f:
        coverage = json.load(f)
    out: Dict[str, Set[str]] = {}
    for entry in coverage:
        fname = entry['file']
        out[fname] = set(entry.get('expected', []))
    return out


def build_detected_map() -> Dict[Tuple[str, str], Set[str]]:
    detect: Dict[Tuple[str, str], Set[str]] = {}

    # KubeAudit
    try:
        with open(RAW / 'kubeaudit_raw.json', 'r', encoding='utf-8-sig') as f:
            ka = json.load(f)
        ka_map = {
            'SensitivePathsMounted': 'docker_sock_mount',
            'PrivilegedTrue': 'privileged_true',
            'AllowPrivilegeEscalationNil': 'allowPrivilegeEscalation_nil',
            'AllowPrivilegeEscalationTrue': 'allowPrivilegeEscalation_true',
            'RunAsNonRootPSCNilCSCNil': 'runAsNonRoot_missing',
            'ReadOnlyRootFilesystemNil': 'readOnlyRootFS_missing',
            'SeccompProfileMissing': 'seccomp_missing',
            'AppArmorAnnotationMissing': 'apparmor_missing',
            'AutomountServiceAccountTokenTrueAndDefaultSA': 'default_sa_automount',
            'CapabilityOrSecurityContextMissing': 'security_context_missing',
        }
        for item in ka:
            file_key = scan_to_tests(item.get('file'))
            cat = ka_map.get(item.get('AuditResultName'))
            if file_key and cat:
                mark(detect, file_key, cat, 'KubeAudit')
    except (OSError, json.JSONDecodeError):
        pass

    # KubeLinter
    try:
        with open(RAW / 'kubelinter_raw.json', 'r', encoding='utf-8-sig') as f:
            kl = json.load(f)
        kl_map = {
            'docker-sock': 'docker_sock_mount',
            'latest-tag': 'image_latest',
            'no-read-only-root-fs': 'readOnlyRootFS_missing',
            'run-as-non-root': 'runAsNonRoot_missing',
            'unset-cpu-requirements': 'resources_missing',
            'unset-memory-requirements': 'resources_missing',
            'privileged-container': 'privileged_true',
            'privilege-escalation-container': 'allowPrivilegeEscalation_true',
            'mismatching-selector': 'missing_selector',
            'no-extensions-v1beta': 'deprecated_api_extensions_v1beta1',
            'liveness-port': 'port_mismatch_between_container_and_probes/services',
            'readiness-port': 'port_mismatch_between_container_and_probes/services',
        }
        for rep in kl.get('Reports', []):
            fp = rep.get('Object', {}).get('Metadata', {}).get('FilePath')
            file_key = scan_to_tests(fp)
            cat = kl_map.get(rep.get('Check'))
            if file_key and cat:
                mark(detect, file_key, cat, 'KubeLinter')
    except (OSError, json.JSONDecodeError):
        pass

    # Conftest
    try:
        with open(RAW / 'conftest_raw.json', 'r', encoding='utf-8-sig') as f:
            ct = json.load(f)
        for r in ct:
            file_key = scan_to_tests(r.get('filename'))
            ns = r.get('namespace')
            if ns == 'kubernetes.probes' and r.get('failures'):
                mark(detect, file_key, 'probes_missing', 'Conftest')
            if ns == 'kubernetes.resources' and r.get('failures'):
                mark(detect, file_key, 'resources_missing', 'Conftest')
            if ns == 'kubernetes.namespace' and r.get('failures'):
                mark(detect, file_key, 'default_namespace', 'Conftest')
            if ns == 'kubernetes.configmap.cni' and r.get('failures'):
                mark(detect, file_key, 'embedded_cni_privileged_true_in_configmap', 'Conftest')
            if ns == 'kubernetes.calico.networkpolicy' and r.get('failures'):
                mark(detect, file_key, 'calico_networkpolicy_misconfigured', 'Conftest')
            if ns == 'k8s.secure_secrets' and r.get('failures'):
                mark(detect, file_key, 'plain_opaque_secret_not_encrypted', 'Conftest')
    except (OSError, json.JSONDecodeError):
        pass

    # Gitleaks
    try:
        with open(RAW / 'gitleaks_raw.json', 'r', encoding='utf-8-sig') as f:
            gl = json.load(f)
        for rec in gl if isinstance(gl, list) else gl.get('findings', []):
            path = rec.get('File') or rec.get('Location', {}).get('File') or rec.get('Path')
            if not path:
                continue
            base = os.path.basename(path)
            file_key = None
            if base in [
                '20.wordpress_mariadb_compose.yaml', '29.helm_rabbitmq_hardcoded_credentials.yaml',
                '34.unencrypted_secret.yaml'
            ]:
                file_key = f'tests/{base}'
            if not file_key:
                continue
            if base == '20.wordpress_mariadb_compose.yaml':
                mark(detect, file_key, 'hardcoded_passwords_in_env', 'Gitleaks')
            elif base == '29.helm_rabbitmq_hardcoded_credentials.yaml':
                mark(detect, file_key, 'hardcoded_credentials_values_yaml', 'Gitleaks')
            elif base == '34.unencrypted_secret.yaml':
                mark(detect, file_key, 'plain_opaque_secret_not_encrypted', 'Gitleaks')
    except (OSError, json.JSONDecodeError):
        pass

    # RBACPolice
    try:
        with open(RAW / 'rbacpolice_raw.json', 'r', encoding='utf-8-sig') as f:
            rp = json.load(f)
        text = json.dumps(rp).lower()
        if 'delete' in text:
            mark(detect, 'tests/28.role_overly_permissive.yaml', 'dangerous_verb_delete', 'RBACPolice')
    except (OSError, json.JSONDecodeError):
        pass

    # Pluto
    try:
        with open(RAW / 'pluto_raw.json', 'r', encoding='utf-8-sig') as f:
            pl = json.load(f)
        if isinstance(pl, list):
            for rec in pl:
                fp = rec.get('filename') or rec.get('path')
                if not fp:
                    continue
                base = os.path.basename(fp)
                if base == '14.ingress_deprecated_api.yaml':
                    mark(detect, 'tests/14.ingress_deprecated_api.yaml', 'deprecated_api_extensions_v1beta1', 'Pluto')
    except (OSError, json.JSONDecodeError):
        pass

    # KubeConform
    try:
        with open(RAW / 'kubeconform_raw.json', 'r', encoding='utf-8-sig') as f:
            kc = json.load(f)
        text = json.dumps(kc).lower()
        if '13.nginx_privileged_deployment.yaml' in text and ('invalid' in text or 'error' in text):
            mark(detect, 'tests/13.nginx_privileged_deployment.yaml', 'schema_invalid', 'KubeConform')
    except (OSError, json.JSONDecodeError):
        pass

    # Trivy config
    try:
        with open(RAW / 'trivy_config_raw.json', 'r', encoding='utf-8-sig') as f:
            tv = json.load(f)
        text = json.dumps(tv)
        if '13.nginx_privileged_deployment.yaml' in text:
            for cat in ['privileged_true','allowPrivilegeEscalation_true','readOnlyRootFS_missing','runAsNonRoot_missing','resources_missing']:
                mark(detect, 'tests/13.nginx_privileged_deployment.yaml', cat, 'Trivy')
        if '14.deployment_single_replica.yaml' in text:
            for cat in ['image_latest','resources_missing','probes_missing']:
                mark(detect, 'tests/14.deployment_single_replica.yaml', cat, 'Trivy')
        if '16.busybox_pod_missing_memory.yaml' in text:
            mark(detect, 'tests/16.busybox_pod_missing_memory.yaml', 'resources_missing', 'Trivy')
    except (OSError, json.JSONDecodeError):
        pass

    # Polaris
    try:
        with open(RAW / 'polaris_raw.json', 'r', encoding='utf-8-sig') as f:
            pr = json.load(f)
        text = json.dumps(pr)
        if '13.nginx_privileged_deployment.yaml' in text:
            for cat in ['privileged_true','allowPrivilegeEscalation_nil','readOnlyRootFS_missing','resources_missing','probes_missing']:
                mark(detect, 'tests/13.nginx_privileged_deployment.yaml', cat, 'Polaris')
        if '14.deployment_single_replica.yaml' in text:
            for cat in ['image_latest','resources_missing','probes_missing']:
                mark(detect, 'tests/14.deployment_single_replica.yaml', cat, 'Polaris')
        if '14.ingress_deprecated_api.yaml' in text:
            mark(detect, 'tests/14.ingress_deprecated_api.yaml', 'tls_missing', 'Polaris')
        if '26.flink_port_mismatch.yaml' in text:
            for cat in ['resources_missing','probes_missing']:
                mark(detect, 'tests/26.flink_port_mismatch.yaml', cat, 'Polaris')
    except (OSError, json.JSONDecodeError):
        pass

    return detect
