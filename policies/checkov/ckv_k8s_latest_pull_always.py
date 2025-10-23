# ckv_k8s_latest_pull_always.py
from __future__ import annotations
import re
from typing import Any, Dict, Iterable

from checkov.common.models.enums import CheckCategories, CheckResult
from checkov.kubernetes.checks.base_k8_check import BaseK8Check


def _iter_containers(conf: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    # Pod
    spec = conf.get("spec") or {}
    if isinstance(spec.get("containers"), list):
        for c in spec["containers"]:
            if isinstance(c, dict):
                yield c
    # Workloads (Deployment/DaemonSet/StatefulSet/Job/CronJob)
    tmpl = spec.get("template") or {}
    tspec = (tmpl.get("spec") or {}) if isinstance(tmpl, dict) else {}
    if isinstance(tspec.get("containers"), list):
        for c in tspec["containers"]:
            if isinstance(c, dict):
                yield c


class LatestWithoutPullAlways(BaseK8Check):
    def __init__(self) -> None:
        name = "Using :latest without imagePullPolicy: Always"
        id = "CKV_K8S_LATEST_PULL_ALWAYS"
        super().__init__(name=name, id=id, categories=[CheckCategories.KUBERNETES], supported_entities=["*"])

    def scan_entity_conf(self, conf: Dict[str, Any]) -> CheckResult:
        # If any container violates the rule, the resource fails
        for c in _iter_containers(conf):
            image = (c.get("image") or "").strip()
            if re.search(r":[Ll]atest$", image):
                pull = (c.get("imagePullPolicy") or "").strip()
                if pull != "Always":
                    return CheckResult.FAILED
        return CheckResult.PASSED


check = LatestWithoutPullAlways()
