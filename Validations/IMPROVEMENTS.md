# Validation Gates Improvements

## Priority 1: Critical Fixes

### 1. Add Missing Validation Categories
**Problem**: Only 7 categories validated, but ~20 categories exist in reports
**Impact**: Many security issues pass validation incorrectly

**Missing Categories:**
- `Security/MissingSeccompProfile` - Check for `securityContext.seccompProfile`
- `Security/ReadOnlyRootFSFalse` - Check `securityContext.readOnlyRootFilesystem == True`
- `Security/MissingAppArmorProfile` - Check annotations for AppArmor
- `Auth/AutomountServiceAccountToken` - Check `automountServiceAccountToken == False`
- `Auth/DefaultServiceAccount` - Check `serviceAccountName != "default"`
- `Auth/DefaultNamespace` - Check `metadata.namespace != "default"`
- `Image/TagNotPinned` - Check image tags aren't `latest` or missing
- `Image/UntrustedRegistry` - Validate against trusted registry list

### 2. Fix Capabilities Validation Logic
**Problem**: Line 62 validation doesn't account for proper context merging
**Current Code:**
```python
"Security/CapabilitiesNotDropped": lambda sc: "ALL" in (sc.get("capabilities", {}).get("drop", []) or []),
```

**Issue**: When checking effective context, capabilities need special handling:
- Pod-level securityContext doesn't have `capabilities`
- Only container-level has `capabilities`
- Current merge logic might lose capabilities info

**Fix**: Add specific capabilities merge logic in `iter_effective_security_contexts()`

### 3. Add Detailed Validation Reporting
**Problem**: "Auto-fix categories not satisfied: X" doesn't explain what's wrong
**Fix**: Return specific findings for each failed validation

Example:
```
Before: "Auto-fix categories not satisfied: Security/CapabilitiesNotDropped"
After:  "Security/CapabilitiesNotDropped FAILED:
         - Container 'app': capabilities.drop missing 'ALL' (found: ['NET_BIND_SERVICE'])"
```

## Priority 2: Code Quality

### 4. Better Logging
Replace print statements with proper logging:
```python
import logging
logging.info(f"Validating {rel}...")
logging.debug(f"Categories: {cats}")
```

### 5. Configuration Externalization
Move constants to config file or CLI args:
- DANGEROUS_FIELDS
- FORBIDDEN_CAPS
- NON_AUTO_FIX_CATEGORIES
- AUTO_FIX_REQUIREMENTS
- Trusted registries list

### 6. Type Safety Improvements
Add complete type hints:
```python
from typing import Optional, Tuple, Iterator

def category_fixed(doc: dict, cat: str) -> Tuple[bool, Optional[str]]:
    """Returns (passed, failure_reason)"""
    ...
```

### 7. Eliminate Redundant YAML Operations
**Current Flow:**
1. Load YAML (line 279)
2. Auto-fix schema (line 286)
3. Save YAML (line 288)
4. Re-load YAML (line 293)

**Improved Flow:**
- Work with in-memory docs
- Only save once at the end
- Validate schema separately from fixing

### 8. Separate Concerns
Split `validate_one()` into smaller functions:
- `validate_yaml_parseable()`
- `validate_schema()`
- `validate_security()`
- `validate_categories()`
- `generate_report()`

## Priority 3: Advanced Features

### 9. Add Validation Severity Levels
Not all failures are equal:
- **CRITICAL**: Dangerous misconfigs (privileged, hostPath)
- **HIGH**: Missing security controls (runAsRoot, capabilities)
- **MEDIUM**: Missing resources, probes
- **LOW**: Schema warnings, style issues

### 10. Support for Custom Validation Rules
Allow users to add custom validators via config:
```yaml
custom_validators:
  - name: "Custom/EnforceLabels"
    check: "metadata.labels.team is not None"
    severity: "MEDIUM"
```

### 11. Diff Analysis
Show *what changed* between original and secured:
- What fields were added/removed/modified
- Highlight security-relevant changes

### 12. Parallel Validation
For multiple files, validate in parallel using multiprocessing

### 13. Integration with Policy Engines
Support OPA/Kyverno policies as validation rules

## Quick Wins (Can Implement Now)

1. **Add validation for missing categories** (30 min)
2. **Fix capabilities check** (15 min)
3. **Better error messages** (20 min)
4. **Add logging** (10 min)
5. **Remove redundant YAML load** (10 min)

## Testing Needs

Current validation shows failures but no unit tests visible.
Add tests for:
- Each validation category
- Schema auto-fix scenarios
- Edge cases (empty containers, missing fields)
- Effective security context merging
- Multi-doc YAML handling
