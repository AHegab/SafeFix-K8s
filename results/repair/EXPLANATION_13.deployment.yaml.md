# Fix Explanation for 13.deployment.yaml

## Summary
Applied 20 fixes across 13 categories:

**Auth/AutomountServiceAccountToken**: Disabled automatic mounting of ServiceAccount token to reduce attack surface.

**Auth/DefaultNamespace**: Added namespace 'default-app' to avoid using the default namespace, improving security isolation.

**Auth/DefaultServiceAccount**: Disabled automatic mounting of ServiceAccount token to reduce attack surface. Using default service account (no custom SA specified).

**Auth/RunAsRoot**: Applied comprehensive security hardening:
  - allowPrivilegeEscalation: false (prevents privilege escalation)
  - capabilities.drop: [ALL] (removes unnecessary privileges)
  - readOnlyRootFilesystem: true (prevents filesystem tampering)
  - runAsNonRoot: true + runAsUser: 1000 (ensures non-root execution)
  - pod-level seccompProfile RuntimeDefault
  - Added tmp/cache/run emptyDir volumes and mounts where needed

**Policy/PodSecurityViolation**: Removed the 'privileged' setting from the container's security context to comply with Pod Security Standards, which prohibit running containers in privileged mode for security reasons.

**Probes/MissingReadinessLiveness**: Added TCP-based liveness and readiness probes on port 80 for nginx to enable automatic recovery and traffic management.

**Resources/MissingLimits**: Added resource limits (cpu: 200m, memory: 256Mi) to prevent resource exhaustion.

**Resources/MissingRequests**: Added resource requests (cpu: 100m, memory: 128Mi) for proper scheduling.

**Security/AllowPrivilegeEscalation**: Applied comprehensive security hardening:
  - allowPrivilegeEscalation: false (prevents privilege escalation)
  - capabilities.drop: [ALL] (removes unnecessary privileges)
  - readOnlyRootFilesystem: true (prevents filesystem tampering)
  - runAsNonRoot: true + runAsUser: 1000 (ensures non-root execution)
  - pod-level seccompProfile RuntimeDefault
  - Added tmp/cache/run emptyDir volumes and mounts where needed

**Security/CapabilitiesNotDropped**: Applied comprehensive security hardening:
  - allowPrivilegeEscalation: false (prevents privilege escalation)
  - capabilities.drop: [ALL] (removes unnecessary privileges)
  - readOnlyRootFilesystem: true (prevents filesystem tampering)
  - runAsNonRoot: true + runAsUser: 1000 (ensures non-root execution)
  - pod-level seccompProfile RuntimeDefault
  - Added tmp/cache/run emptyDir volumes and mounts where needed

**Security/MissingAppArmorProfile**: Configured AppArmor via Pod annotations (runtime/default profile) for 1 container(s). AppArmor must be set via annotations, not securityContext.

**Security/MissingSeccompProfile**: Applied comprehensive security hardening:
  - allowPrivilegeEscalation: false (prevents privilege escalation)
  - capabilities.drop: [ALL] (removes unnecessary privileges)
  - readOnlyRootFilesystem: true (prevents filesystem tampering)
  - runAsNonRoot: true + runAsUser: 1000 (ensures non-root execution)
  - pod-level seccompProfile RuntimeDefault
  - Added tmp/cache/run emptyDir volumes and mounts where needed

**Security/ReadOnlyRootFSFalse**: Applied comprehensive security hardening:
  - allowPrivilegeEscalation: false (prevents privilege escalation)
  - capabilities.drop: [ALL] (removes unnecessary privileges)
  - readOnlyRootFilesystem: true (prevents filesystem tampering)
  - runAsNonRoot: true + runAsUser: 1000 (ensures non-root execution)
  - pod-level seccompProfile RuntimeDefault
  - Added tmp/cache/run emptyDir volumes and mounts where needed

**Skipped Categories** (by design):
- Image/TagNotPinned: Image tag pinning should be handled by CI/CD pipeline with proper vulnerability scanning. Avoid automatic version changes that could introduce vulnerable or incompatible versions. Recommendation: Use image digests (SHA256) in your deployment pipeline.
- Misc/Unmapped: Not suitable for inline fix
- Network/MissingNetworkPolicy: NetworkPolicy requires separate resource with application-specific traffic rules. Create as separate manifest based on your architecture.
- Schema/InvalidManifest: Not suitable for inline fix
- Style/YamlLint: Not suitable for inline fix


## Statistics
- Total patches: 20
- Categories processed: 19
- Categories skipped: 5
- Status: Success

## Skipped Categories
- Image/TagNotPinned
- Misc/Unmapped
- Network/MissingNetworkPolicy
- Schema/InvalidManifest
- Style/YamlLint
