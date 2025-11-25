# Detailed Fix Guide for Top Failing Categories

## Overview

This guide provides detailed fixes for the three most common validation failures:
1. **Security/CapabilitiesNotDropped** - 23 failures (HIGH priority)
2. **Security/ReadOnlyRootFSFalse** - 17 failures (HIGH priority)
3. **Security/MissingSeccompProfile** - 6 failures (HIGH priority)

---

## 🔴 Issue #1: Security/CapabilitiesNotDropped (23 failures)

### What's Wrong?

Containers are not dropping ALL Linux capabilities. This leaves containers with unnecessary privileges that can be exploited.

### Why It Fails Validation

The validator checks:
```python
"ALL" in (securityContext.get("capabilities", {}).get("drop", []))
```

**Current state in most failing files:**
```yaml
securityContext:
  capabilities:
    drop:
      - NET_BIND_SERVICE  # ❌ Only drops one capability
```

**Required state:**
```yaml
securityContext:
  capabilities:
    drop:
      - ALL  # ✅ Drops all capabilities
```

### The Fix

**Option 1: Drop ALL capabilities (recommended)**
```yaml
spec:
  template:
    spec:
      containers:
      - name: app
        securityContext:
          capabilities:
            drop:
              - ALL  # This is what validation expects
```

**Option 2: Drop ALL then selectively re-add (if capabilities needed)**
```yaml
spec:
  template:
    spec:
      containers:
      - name: app
        securityContext:
          capabilities:
            drop:
              - ALL
            add:
              - NET_BIND_SERVICE  # Only if truly needed
```

### Files Affected (23 files)

All failing files have containers missing `capabilities.drop: ["ALL"]`:
- hidden-in-layers.deployment.yaml
- cache-store.deployment.yaml
- build-code.deployment.yaml
- poor-registry.deployment.yaml
- 34.secrets-holder.yaml
- 16.busybox_pod_missing_memory.yaml
- batch-checkjob.yaml
- 13.jenkins_agent_pod.yaml
- 14.deployment_single_replica.yaml
- internal-proxy.deployment.yaml
- hunger-check.deployment.yaml
- kubernetes-goat-home.deployment.yaml

### LLM Prompt Fix

**Current LLM behavior:** Adding individual capabilities to drop list

**Improved prompt instruction:**
```
CRITICAL: For Security/CapabilitiesNotDropped:
- ALWAYS set capabilities.drop to ["ALL"]
- If specific capabilities are needed, add them AFTER dropping ALL
- Example:
  securityContext:
    capabilities:
      drop: ["ALL"]
      add: ["NET_BIND_SERVICE"]  # Only if required

NEVER use:
  capabilities:
    drop: ["NET_BIND_SERVICE"]  # ❌ Wrong

ALWAYS use:
  capabilities:
    drop: ["ALL"]  # ✅ Correct
```

---

## 🔴 Issue #2: Security/ReadOnlyRootFSFalse (17 failures)

### What's Wrong?

Containers are running with writable root filesystems. This allows attackers to modify the container filesystem if they gain access.

### Why It Fails Validation

The validator checks:
```python
securityContext.get("readOnlyRootFilesystem", False) == True
```

**Current state:**
```yaml
securityContext:
  allowPrivilegeEscalation: false
  # readOnlyRootFilesystem is missing or false
```

**Required state:**
```yaml
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true  # ✅ Required
```

### The Fix

**Step 1: Add readOnlyRootFilesystem**
```yaml
spec:
  template:
    spec:
      containers:
      - name: app
        securityContext:
          readOnlyRootFilesystem: true
```

**Step 2: Mount temporary directories (if app needs write access)**
```yaml
spec:
  template:
    spec:
      containers:
      - name: app
        securityContext:
          readOnlyRootFilesystem: true
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /app/cache
      volumes:
      - name: tmp
        emptyDir: {}
      - name: cache
        emptyDir: {}
```

### Common Scenarios

#### Scenario 1: App writes to /tmp
```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
- name: tmp
  mountPath: /tmp
volumes:
- name: tmp
  emptyDir: {}
```

#### Scenario 2: App needs cache directory
```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
- name: cache
  mountPath: /var/cache/app
volumes:
- name: cache
  emptyDir: {}
```

#### Scenario 3: Nginx needs writable directories
```yaml
securityContext:
  readOnlyRootFilesystem: true
volumeMounts:
- name: nginx-cache
  mountPath: /var/cache/nginx
- name: nginx-run
  mountPath: /var/run
volumes:
- name: nginx-cache
  emptyDir: {}
- name: nginx-run
  emptyDir: {}
```

### Files Affected (17 files)

- cache-store.deployment.yaml
- internal-proxy.deployment.yaml
- hunger-check.deployment.yaml
- kubernetes-goat-home.deployment.yaml
- poor-registry.deployment.yaml
- build-code.deployment.yaml
- 34.secrets-holder.yaml
- 16.busybox_pod_missing_memory.yaml
- 13.jenkins_agent_pod.yaml

### LLM Prompt Fix

**Improved prompt instruction:**
```
For Security/ReadOnlyRootFSFalse:
- ALWAYS add readOnlyRootFilesystem: true to securityContext
- Identify directories the app needs to write to (e.g., /tmp, /var/cache)
- Add emptyDir volumes for writable directories
- Mount these volumes to the container

Example fix:
  securityContext:
    readOnlyRootFilesystem: true
    runAsNonRoot: true
  volumeMounts:
  - name: tmp
    mountPath: /tmp

  volumes:
  - name: tmp
    emptyDir: {}

Common writable directories:
- /tmp
- /var/cache/*
- /var/run
- /var/log (if app writes logs locally)
```

---

## 🔴 Issue #3: Security/MissingSeccompProfile (6 failures)

### What's Wrong?

Containers are missing seccomp (secure computing mode) profiles. Seccomp restricts the system calls a container can make, reducing attack surface.

### Why It Fails Validation

The validator checks:
```python
securityContext.get("seccompProfile") is not None
and securityContext["seccompProfile"].get("type") != "Unconfined"
```

**Current state:**
```yaml
securityContext:
  allowPrivilegeEscalation: false
  # seccompProfile is missing
```

**Required state:**
```yaml
securityContext:
  allowPrivilegeEscalation: false
  seccompProfile:
    type: RuntimeDefault  # ✅ Required
```

### The Fix

**Option 1: RuntimeDefault (recommended)**
```yaml
spec:
  template:
    spec:
      securityContext:
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: app
        securityContext:
          seccompProfile:
            type: RuntimeDefault
```

**Option 2: Localhost (custom profile)**
```yaml
spec:
  template:
    spec:
      containers:
      - name: app
        securityContext:
          seccompProfile:
            type: Localhost
            localhostProfile: my-profile.json
```

### Pod-level vs Container-level

You can set seccomp at **pod level** (applies to all containers):
```yaml
spec:
  template:
    spec:
      securityContext:
        seccompProfile:
          type: RuntimeDefault  # Applies to all containers
      containers:
      - name: app
        # inherits pod-level seccomp
```

Or at **container level** (per-container):
```yaml
spec:
  template:
    spec:
      containers:
      - name: app
        securityContext:
          seccompProfile:
            type: RuntimeDefault
      - name: sidecar
        securityContext:
          seccompProfile:
            type: RuntimeDefault
```

### Files Affected (6 files)

- cache-store.deployment.yaml
- 34.secrets-holder.yaml
- 16.busybox_pod_missing_memory.yaml
- 13.jenkins_agent_pod.yaml
- internal-proxy.deployment.yaml
- hunger-check.deployment.yaml

### LLM Prompt Fix

**Improved prompt instruction:**
```
For Security/MissingSeccompProfile:
- ALWAYS add seccompProfile to securityContext
- Use RuntimeDefault as the type (most compatible)
- Add at pod level OR container level (container level preferred)

Pod-level (simpler):
  spec:
    securityContext:
      seccompProfile:
        type: RuntimeDefault
    containers:
    - name: app
      # inherits from pod

Container-level (more control):
  spec:
    containers:
    - name: app
      securityContext:
        seccompProfile:
          type: RuntimeDefault

NEVER use:
  seccompProfile:
    type: Unconfined  # ❌ Disables seccomp

ALWAYS use:
  seccompProfile:
    type: RuntimeDefault  # ✅ Correct
```

---

## 🔧 Complete Example: Fixing All Three Issues

### Before (failing validation):
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx:1.21
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          capabilities:
            drop:
              - NET_BIND_SERVICE  # ❌ Should be ALL
          # ❌ Missing readOnlyRootFilesystem
          # ❌ Missing seccompProfile
```

### After (passing validation):
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
spec:
  template:
    spec:
      securityContext:
        seccompProfile:
          type: RuntimeDefault  # ✅ Added at pod level
      containers:
      - name: app
        image: nginx:1.21
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          runAsUser: 1000
          capabilities:
            drop:
              - ALL  # ✅ Fixed: drop ALL
          readOnlyRootFilesystem: true  # ✅ Added
          seccompProfile:
            type: RuntimeDefault  # ✅ Added at container level
        volumeMounts:
        - name: nginx-cache
          mountPath: /var/cache/nginx
        - name: nginx-run
          mountPath: /var/run
      volumes:
      - name: nginx-cache
        emptyDir: {}
      - name: nginx-run
        emptyDir: {}
```

---

## 📊 Validation Checklist

Use this checklist for each container:

```
Container Security Checklist:
☐ capabilities.drop includes "ALL"
☐ readOnlyRootFilesystem: true
☐ seccompProfile.type: RuntimeDefault
☐ allowPrivilegeEscalation: false
☐ runAsNonRoot: true
☐ runAsUser: <non-zero>
☐ emptyDir volumes for writable directories
```

---

## 🚀 Quick Fix Script

Run this to check which containers in a file need fixes:

```bash
# Check capabilities
grep -n "capabilities:" yourfile.yaml -A 3

# Check readOnlyRootFilesystem
grep -n "readOnlyRootFilesystem:" yourfile.yaml

# Check seccompProfile
grep -n "seccompProfile:" yourfile.yaml

# If any are missing or wrong, apply fixes above
```

---

## 💡 Testing Your Fixes

After applying fixes, validate locally:

```bash
# Run validation on single file
python Validations/validation_gates_improved.py \
  --tests-dir "path/to/original" \
  --fixed-dir "path/to/fixed" \
  --payload "path/to/llm_payload.json" \
  --out-dir "path/to/output" \
  --log-level DEBUG

# Check the report
cat path/to/output/REPORT_VALIDATE_*.json | python -m json.tool
```

---

## 📈 Expected Results After Fixes

**Before fixes:**
- ❌ 23 failures for CapabilitiesNotDropped
- ❌ 17 failures for ReadOnlyRootFSFalse
- ❌ 6 failures for MissingSeccompProfile
- **Total: 46 HIGH severity failures**

**After fixes:**
- ✅ 0 failures for CapabilitiesNotDropped
- ✅ 0 failures for ReadOnlyRootFSFalse
- ✅ 0 failures for MissingSeccompProfile
- **Total: 0 HIGH severity failures**

This should improve your pass rate from **13.3% → ~70%+**

---

## 🎯 Priority Order

Fix in this order for maximum impact:

1. **First:** Fix `CapabilitiesNotDropped` (23 files) - quickest win
2. **Second:** Fix `ReadOnlyRootFSFalse` (17 files) - may need volume mounts
3. **Third:** Fix `MissingSeccompProfile` (6 files) - simple addition

---

## 🔗 References

- [Kubernetes Security Contexts](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [Linux Capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Seccomp Profiles](https://kubernetes.io/docs/tutorials/security/seccomp/)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
