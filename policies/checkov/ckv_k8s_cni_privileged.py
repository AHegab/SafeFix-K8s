from checkov.kubernetes.checks.resource.base_spec_check import BaseK8Check
from checkov.common.models.enums import CheckCategories, CheckResult
import yaml, json

class CNIEmbeddedPrivileged(BaseK8Check):
    def __init__(self):
        name = "CNI embedded config should not set privileged=true"
        id = "CKV_K8S_CNI_001"
        super().__init__(name=name, id=id, categories=[CheckCategories.KUBERNETES], supported_entities=["ConfigMap"])

    def scan_spec_conf(self, conf):
        data = conf.get("data") or {}
        for key, val in data.items():
            if not isinstance(val, str):
                continue
            parsed = None
            for loader in (yaml.safe_load, json.loads):
                try:
                    parsed = loader(val)
                    break
                except Exception:
                    pass
            if isinstance(parsed, dict):
                # look for .cni.privileged or any privileged=True
                cni = parsed.get("cni") or {}
                if isinstance(cni, dict) and cni.get("privileged") is True:
                    return CheckResult.FAILED
                # generic search
                stack = [parsed]
                while stack:
                    cur = stack.pop()
                    if isinstance(cur, dict):
                        if cur.get("privileged") is True:
                            return CheckResult.FAILED
                        stack.extend(cur.values())
                    elif isinstance(cur, list):
                        stack.extend(cur)
        return CheckResult.PASSED

check = CNIEmbeddedPrivileged()
