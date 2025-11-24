# Validation Gates - Quick Start Guide

## 🚀 Get Started in 3 Steps

### Step 1: Run Validation
```bash
python validation_gates_improved.py \
  --tests-dir tests/ \
  --fixed-dir output/fixed/ \
  --payload payload.json \
  --out-dir output/validation/
```

### Step 2: Check Results
```bash
# View summary
cat output/validation/SUMMARY_VALIDATION.csv

# View detailed report for a specific file
cat output/validation/REPORT_VALIDATE_test.yaml.json
```

### Step 3: Fix Issues
Look at the `findings` array in the JSON report to see exactly what failed and how to fix it.

---

## 📋 Common Commands

### Basic Validation
```bash
python validation_gates_improved.py \
  --tests-dir tests/ \
  --fixed-dir output/fixed/ \
  --payload payload.json \
  --out-dir output/validation/
```

### Debug Mode (see detailed logs)
```bash
python validation_gates_improved.py \
  --tests-dir tests/ \
  --fixed-dir output/fixed/ \
  --payload payload.json \
  --out-dir output/validation/ \
  --log-level DEBUG
```

### Strict Mode (fail on MEDIUM issues)
```bash
python validation_gates_improved.py \
  --tests-dir tests/ \
  --fixed-dir output/fixed/ \
  --payload payload.json \
  --out-dir output/validation/ \
  --strict-mode
```

### Custom Config
```bash
python validation_gates_improved.py \
  --tests-dir tests/ \
  --fixed-dir output/fixed/ \
  --payload payload.json \
  --out-dir output/validation/ \
  --config my_config.yaml
```

### Sequential Processing (no parallel)
```bash
python validation_gates_improved.py \
  --tests-dir tests/ \
  --fixed-dir output/fixed/ \
  --payload payload.json \
  --out-dir output/validation/ \
  --no-parallel
```

---

## 🔍 Understanding Output

### Status Levels
- **PASS** ✅ - All validations passed
- **NEEDS_REVIEW** ⚠️ - Schema warnings (kubeconform)
- **FAIL** ❌ - Security validation failures

### Severity Levels
- **CRITICAL** 🔴 - Immediate security risk (privileged, hostPath)
- **HIGH** 🟠 - Serious security issue (runAsRoot, capabilities)
- **MEDIUM** 🟡 - Important best practice (resources, probes)
- **LOW** 🟢 - Minor issue (default namespace)

### Example Output
```json
{
  "file": "test.yaml",
  "status": "FAIL",
  "findings": [
    {
      "category": "Security/CapabilitiesNotDropped",
      "severity": "HIGH",
      "passed": false,
      "message": "capabilities.drop missing 'ALL' (found: ['NET_BIND_SERVICE'])",
      "container": "app"
    }
  ]
}
```

**This means:**
- Container `app` is missing `capabilities.drop: ["ALL"]`
- Current value: `["NET_BIND_SERVICE"]`
- Fix: Change to `["ALL"]`

---

## ⚙️ Quick Configuration

Edit `validation_config.yaml`:

### Add Your Registry
```yaml
trusted_registries:
  - "docker.io"
  - "gcr.io"
  - "your-company.io"  # Add this
```

### Adjust Severity
```yaml
validation_rules:
  "Security/CapabilitiesNotDropped":
    severity: "CRITICAL"  # Change from HIGH
```

### Configure Workers
```yaml
validation_settings:
  max_workers: 8  # Default is 4
```

---

## 🧪 Run Tests

```bash
# Run all tests
python test_validation_gates.py

# Verbose output
python test_validation_gates.py -v

# Run specific test
python -m unittest test_validation_gates.TestCategoryValidators.test_validate_capabilities_drop_all
```

---

## 🐛 Troubleshooting

### "No files found in payload"
Check your payload.json structure:
```json
{
  "files": [
    {
      "file": "test.yaml",
      "findings": [{"category": "Security/PrivilegedContainer"}]
    }
  ]
}
```

### More failures than expected?
The new version validates 16+ categories (vs 7 in old version).
Check detailed findings to see what's actually wrong.

### Validation is slow?
Enable parallel processing:
```bash
python validation_gates_improved.py ... --config validation_config.yaml
```

Make sure `enable_parallel_validation: true` in config.

---

## 📊 Interpreting CSV Summary

| Column | Meaning |
|--------|---------|
| `status` | PASS / NEEDS_REVIEW / FAIL |
| `total_checks` | Total validations performed |
| `failed_checks` | How many failed |
| `critical_failures` | CRITICAL severity failures |
| `high_failures` | HIGH severity failures |
| `medium_failures` | MEDIUM severity failures |

**Rule of thumb:**
- If `critical_failures > 0` or `high_failures > 0` → FAIL
- If `medium_failures > 0` in strict mode → NEEDS_REVIEW
- Otherwise → PASS

---

## 🎯 Common Fixes

### CapabilitiesNotDropped
```yaml
securityContext:
  capabilities:
    drop:
      - ALL  # Must include this
```

### RunAsRoot
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
```

### MissingSeccompProfile
```yaml
securityContext:
  seccompProfile:
    type: RuntimeDefault
```

### ReadOnlyRootFSFalse
```yaml
securityContext:
  readOnlyRootFilesystem: true
```

### MissingResources
```yaml
resources:
  requests:
    cpu: "100m"
    memory: "128Mi"
  limits:
    cpu: "500m"
    memory: "512Mi"
```

### MissingProbes
```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 30
readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 5
```

---

## 📚 Documentation Links

- **README_VALIDATION_GATES.md** - Complete usage guide
- **MIGRATION_GUIDE.md** - Migrating from old version
- **IMPROVEMENTS.md** - What was improved and why
- **IMPLEMENTATION_SUMMARY.md** - Complete implementation details
- **validation_config.yaml** - Configuration file

---

## 💡 Tips

1. **Start with debug mode** to understand validation logic
   ```bash
   --log-level DEBUG
   ```

2. **Use strict mode in CI/CD** to catch all issues
   ```bash
   --strict-mode
   ```

3. **Check diff summary** to see what changed
   ```json
   "diff_summary": {
     "security_fields_added": [...],
     "resources_added": [...]
   }
   ```

4. **Look at container names** in findings to know where to fix
   ```json
   "container": "app"  # Fix this specific container
   ```

5. **Use severity levels** to prioritize fixes
   - Fix CRITICAL first
   - Then HIGH
   - Then MEDIUM/LOW

---

## 🔗 Integration

### CI/CD
```yaml
- name: Validate Security
  run: |
    python validation_gates_improved.py \
      --tests-dir tests/ \
      --fixed-dir output/fixed/ \
      --payload payload.json \
      --out-dir output/validation/ \
      --strict-mode
```

### Pre-commit Hook
```bash
#!/bin/bash
python validation_gates_improved.py ... || exit 1
```

---

## Exit Codes

- **0** - PASS or NEEDS_REVIEW
- **1** - FAIL

Use in scripts:
```bash
python validation_gates_improved.py ...
if [ $? -ne 0 ]; then
  echo "Validation failed!"
  exit 1
fi
```

---

## Need Help?

1. Check logs: `--log-level DEBUG`
2. Run tests: `python test_validation_gates.py`
3. Review documentation: `README_VALIDATION_GATES.md`
4. Check examples in `MIGRATION_GUIDE.md`

---

**That's it! You're ready to validate Kubernetes security configurations.** 🎉
