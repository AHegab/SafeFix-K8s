# Conftest Kubernetes Security Policy Bundle

This comprehensive policy bundle detects **40+ critical Kubernetes misconfigurations** for workload manifests (Pod, Deployment, DaemonSet, StatefulSet, Job, CronJob), plus RBAC, Secrets, Networking, and Ingress resources.

## Prerequisites

- **Conftest**: Install from [https://www.conftest.dev/](https://www.conftest.dev/)
- **OPA** (optional, for unit testing): Install from [https://www.openpolicyagent.org/](https://www.openpolicyagent.org/)

```bash
# Install conftest (macOS)
brew install conftest

# Install conftest (Linux/Windows)
# Download from https://github.com/open-policy-agent/conftest/releases
```

## Policy Rules

### Core Security Checks (10 Rules)

| Rule ID | Description | Severity |
|---------|-------------|----------|
| `KSV_CAP_DROP_MISSING` | Container does not drop ALL default capabilities | HIGH |
| `KSV_PRIVILEGED` | Container runs in privileged mode | CRITICAL |
| `KSV_ALLOW_PRIVILEGE_ESCALATION` | Container allows privilege escalation | HIGH |
| `KSV_NO_SECCOMP` | No seccomp profile configured | HIGH |
| `KSV_NO_APPARMOR` | No AppArmor annotation/profile | MEDIUM |
| `KSV_READONLY_ROOTFS_FALSE` | Root filesystem not read-only | MEDIUM |
| `KSV_DEFAULT_SA_TOKEN` | Uses default service account with automount enabled | MEDIUM |
| `KSV_DEFAULT_NAMESPACE` | Resource deployed to default namespace | LOW |
| `KSV_IMAGE_NOT_PINNED` | Image not pinned by digest or uses floating tag | MEDIUM |
| `KSV_NO_LIMITS_NO_PROBES` | Missing resource limits AND probes | MEDIUM |

### Extended Security Checks (30+ Additional Rules)

| Category | Rules |
|----------|-------|
| **Resource Management** | CPU/Memory limits and requests (strict enforcement) |
| **Security Context** | runAsNonRoot enforcement, privileged containers |
| **Host Access** | hostNetwork, hostPID, hostIPC, hostPath volumes |
| **Images** | imagePullPolicy validation |
| **Health** | Liveness and readiness probes (both required) |
| **Secrets** | Unencrypted secrets, hardcoded credentials, cloud creds in env |
| **ConfigMaps** | Sensitive data detection |
| **Deployments** | Selector/label matching, high availability |
| **Ingress** | TLS requirement |
| **NetworkPolicy** | Coverage validation |
| **RBAC** | Wildcard prevention, dangerous permissions |
| **Dangerous Mounts** | Docker socket detection, CNI privileged configs |


## Usage

### Test Against Sample Manifests

Run conftest against the test directory:

```bash
conftest test -p policy.rego tests/
```

### Test Against Your Manifests

Test all YAML files in a directory:

```bash
conftest test -p policy.rego /path/to/your/manifests/
```

Test a single file:

```bash
conftest test -p policy.rego deployment.yaml
```

### Run Unit Tests

Run OPA unit tests to verify policy logic:

```bash
conftest verify -p policy.rego -p policy_tests.rego
```

Or using OPA directly:

```bash
opa test policy.rego policy_tests.rego -v
```

## Expected Output Examples

## Expected Output Examples

### Failing Test (privileged container)

When testing `tests/privileged_bad.yaml`:

```bash
$ conftest test -p policy.rego tests/privileged_bad.yaml

FAIL - tests/privileged_bad.yaml - main - KSV_PRIVILEGED: Container 'app' in Pod 'insecure-pod-privileged' runs in privileged mode. Set securityContext.privileged: false
FAIL - tests/privileged_bad.yaml - main - KSV_ALLOW_PRIVILEGE_ESCALATION: Container 'app' in Pod 'insecure-pod-privileged' does not explicitly set allowPrivilegeEscalation: false
FAIL - tests/privileged_bad.yaml - main - KSV_NO_SECCOMP: Container 'app' in Pod 'insecure-pod-privileged' has no seccomp profile. Set securityContext.seccompProfile.type: RuntimeDefault
FAIL - tests/privileged_bad.yaml - main - RESOURCE_LIMITS: Container 'app' in Pod 'insecure-pod-privileged' must set CPU limit
FAIL - tests/privileged_bad.yaml - main - RESOURCE_LIMITS: Container 'app' in Pod 'insecure-pod-privileged' must set memory limit
...

40 tests, 20 passed, 0 warnings, 20 failures, 0 exceptions
```

### Passing Test (secure pod)

When testing a compliant manifest:

```bash
$ conftest test -p policy.rego tests/caps_drop_ok.yaml

40 tests, 40 passed, 0 warnings, 0 failures, 0 exceptions
```

### Production Scan Example

```bash
$ conftest test -p policy.rego manifests/production/*.yaml

FAIL - manifests/production/backend-deployment.yaml - main - DOCKER_SOCKET: Deployment 'debug-pod' mounts Docker socket - grants full cluster control
FAIL - manifests/production/frontend-deployment.yaml - main - HIGH_AVAILABILITY: Deployment 'frontend' in production must have replicas >= 2 (current: 1)
FAIL - manifests/production/api-ingress.yaml - main - INGRESS_TLS: Ingress 'api' must define spec.tls for HTTPS
FAIL - manifests/production/admin-role.yaml - main - RBAC_WILDCARD: ClusterRole 'admin' grants wildcard resource '*' - use specific resources instead

4 tests, 0 passed, 0 warnings, 4 failures, 0 exceptions
```


## Rule Details

### Core Security Rules (1-10)

### 1. KSV_CAP_DROP_MISSING
Ensures containers drop all default Linux capabilities.

**Fix:**
```yaml
securityContext:
  capabilities:
    drop:
    - ALL
```

### 2. KSV_PRIVILEGED
Detects containers running with `privileged: true`.

**Fix:**
```yaml
securityContext:
  privileged: false
```

### 3. KSV_ALLOW_PRIVILEGE_ESCALATION
Ensures `allowPrivilegeEscalation` is explicitly set to `false`.

**Fix:**
```yaml
securityContext:
  allowPrivilegeEscalation: false
```

### 4. KSV_NO_SECCOMP
Checks for seccomp profile at container or pod level.

**Valid values:** `RuntimeDefault`, `runtime/default`, `docker/default`, `Localhost`

**Fix:**
```yaml
spec:
  securityContext:
    seccompProfile:
      type: RuntimeDefault
```

### 5. KSV_NO_APPARMOR
Checks for AppArmor annotations on Pod metadata.

**Fix:**
```yaml
metadata:
  annotations:
    container.apparmor.security.beta.kubernetes.io/<container-name>: runtime/default
```

### 6. KSV_READONLY_ROOTFS_FALSE
Ensures container root filesystem is read-only.

**Fix:**
```yaml
securityContext:
  readOnlyRootFilesystem: true
```

### 7. KSV_DEFAULT_SA_TOKEN
Detects use of default service account with token automounting.

**Fix:**
```yaml
spec:
  serviceAccountName: my-custom-sa
  automountServiceAccountToken: false
```

### 8. KSV_DEFAULT_NAMESPACE
Flags resources deployed to the `default` namespace.

**Fix:**
```yaml
metadata:
  namespace: production  # or any non-default namespace
```

### 9. KSV_IMAGE_NOT_PINNED
Detects images using `:latest` tag or no digest.

**Fix:**
```yaml
image: nginx@sha256:abcd1234567890...
```

### 10. KSV_NO_LIMITS_NO_PROBES
Flags containers missing BOTH resource limits AND probes.

**Fix:**
```yaml
resources:
  limits:
    cpu: "1"
    memory: "512Mi"
livenessProbe:
  httpGet:
    path: /healthz
    port: 8080
```

### Extended Security Rules (11-40+)

### 11-14. RESOURCE_LIMITS / RESOURCE_REQUESTS
**Strict enforcement:** Every container must have CPU and memory limits/requests.

**Fix:**
```yaml
resources:
  limits:
    cpu: "2"
    memory: "1Gi"
  requests:
    cpu: "500m"
    memory: "256Mi"
```

### 15. RUN_AS_NON_ROOT
**Fix:**
```yaml
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
```

### 16-18. HOST_NETWORK / HOST_PID / HOST_IPC
**Fix:** Remove these fields or set to `false`:
```yaml
spec:
  hostNetwork: false
  hostPID: false
  hostIPC: false
```

### 19. HOST_PATH
Avoid mounting host filesystem.

**Fix:** Use PersistentVolumes, ConfigMaps, or Secrets instead:
```yaml
volumes:
- name: data
  persistentVolumeClaim:
    claimName: my-pvc
```

### 20. IMAGE_PULL_POLICY
**Fix:**
```yaml
imagePullPolicy: Always  # or IfNotPresent for digests
```

### 21-22. HEALTH_PROBES
**Both required:**
```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 8080
readinessProbe:
  httpGet:
    path: /ready
    port: 8080
```

### 23. UNENCRYPTED_SECRET
**Fix:**
```yaml
metadata:
  annotations:
    encryption.kubernetes.io/encrypted: "true"
```

Or use external secret management (Vault, AWS Secrets Manager, etc.)

### 24. HARDCODED_CLOUD_CREDS
**Fix:** Use secretKeyRef:
```yaml
env:
- name: AWS_ACCESS_KEY_ID
  valueFrom:
    secretKeyRef:
      name: aws-creds
      key: access-key-id
```

Or use workload identity (IRSA, Workload Identity, etc.)

### 25-26. CONFIGMAP_SENSITIVE
Don't store secrets in ConfigMaps.

**Fix:** Use Secret resources:
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: db-password
stringData:
  password: mypassword
```

### 27. DEPLOYMENT_SELECTOR
**Fix:** Ensure selector matches template labels:
```yaml
spec:
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp  # Must match selector
```

### 28. HIGH_AVAILABILITY
For production namespaces, use replicas >= 2:
```yaml
spec:
  replicas: 3
```

### 29. INGRESS_TLS
**Fix:**
```yaml
spec:
  tls:
  - hosts:
    - example.com
    secretName: tls-cert
```

### 30. NETWORK_POLICY
**Fix:** Create matching NetworkPolicy:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend
spec:
  podSelector:
    matchLabels:
      app: frontend
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: backend
```

Or add annotation:
```yaml
metadata:
  annotations:
    network-policy-confirmed: "true"
```

### 31-33. RBAC_WILDCARD / RBAC_DANGEROUS
Avoid wildcards and dangerous permissions:
```yaml
# Bad
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]

# Good
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
```

### 34. DOCKER_SOCKET
**Never mount Docker socket** - it grants full cluster control.

**Fix:** Use Kubernetes APIs or dedicated build tools.

### 35. CNI_PRIVILEGED
Avoid privileged CNI configurations.

**Fix:** Remove `"privileged":true` from CNI annotations.


## Customization

### Stricter Variant: Require Limits on ALL Containers

Modify rule `KSV_NO_LIMITS_NO_PROBES` to fail if ANY container is missing limits:

```rego
# Change this line in the rule:
missing_limits := cpu_limit == "" or mem_limit == ""

# To fail even if only one of cpu/memory is missing
```

### Relaxed Variant: Allow Some Capabilities

Modify `KSV_CAP_DROP_MISSING` to allow specific capabilities:

```rego
# Allow NET_BIND_SERVICE in addition to dropping ALL
allowed_caps := ["NET_BIND_SERVICE"]
not has_only_allowed_caps(caps.add, allowed_caps)
```

## File Structure

```
.
├── policy.rego              # Main policy file with all 10 rules
├── policy_tests.rego        # OPA unit tests for each rule
├── tests/
│   ├── caps_drop_ok.yaml
│   ├── caps_drop_bad.yaml
│   ├── privileged_ok.yaml
│   ├── privileged_bad.yaml
│   ├── priv_escalation_ok.yaml
│   ├── priv_escalation_bad.yaml
│   ├── seccomp_ok.yaml
│   ├── seccomp_bad.yaml
│   ├── apparmor_ok.yaml
│   ├── apparmor_bad.yaml
│   ├── readonly_rootfs_ok.yaml
│   ├── readonly_rootfs_bad.yaml
│   ├── sa_token_ok.yaml
│   ├── sa_token_bad.yaml
│   ├── namespace_ok.yaml
│   ├── namespace_bad.yaml
│   ├── image_pinned_ok.yaml
│   ├── image_pinned_bad.yaml
│   ├── limits_probes_ok.yaml
│   └── limits_probes_bad.yaml
└── README.md                # This file
```

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Kubernetes Security Scan
on: [push, pull_request]
jobs:
  conftest:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - name: Install Conftest
      run: |
        wget https://github.com/open-policy-agent/conftest/releases/download/v0.45.0/conftest_0.45.0_Linux_x86_64.tar.gz
        tar xzf conftest_0.45.0_Linux_x86_64.tar.gz
        sudo mv conftest /usr/local/bin/
    - name: Run Conftest
      run: conftest test -p policy.rego manifests/
```

## Troubleshooting

### No violations found but expected failures

Ensure you're testing the correct file path and that the policy file is loaded:

```bash
conftest test -p policy.rego --trace tests/privileged_bad.yaml
```

### Policy syntax errors

Validate policy syntax with OPA:

```bash
opa check policy.rego
```

### Container field not detected

The policy handles both Pod and controller-based manifests (Deployment, StatefulSet, etc.). Ensure your manifest structure matches Kubernetes API conventions.

## References

- [Conftest Documentation](https://www.conftest.dev/)
- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)

## License

This policy bundle is provided as-is for production use. Adapt rules to your organization's security requirements.
