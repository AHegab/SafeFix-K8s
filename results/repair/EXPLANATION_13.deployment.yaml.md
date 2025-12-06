# Fix Explanation for 13.deployment.yaml

## Summary
Applied 23 fixes across 12 categories:

**Auth/AutomountServiceAccountToken**: Disabled automatic mounting of ServiceAccount token to reduce attack surface.

**Auth/DefaultNamespace**: Added namespace 'default-app' to avoid using the default namespace, improving security isolation.

**Auth/DefaultServiceAccount**: Added dedicated ServiceAccount 'nginx-deployment-sa' following the principle of least privilege.

**Auth/RunAsRoot**: Applied comprehensive security hardening:
  - allowPrivilegeEscalation: false (prevents privilege escalation)
  - capabilities.drop: [ALL] (removes unnecessary privileges)
  - readOnlyRootFilesystem: true (prevents filesystem tampering)
  - runAsNonRoot: true + runAsUser: 1000 (ensures non-root execution)
  - pod-level seccompProfile RuntimeDefault
  - Added tmp/cache/run emptyDir volumes and mounts where needed

**Image/TagNotPinned**: The image tag was changed from 'latest' to a specific version '1.21.6' to ensure consistent deployments and avoid unexpected changes. Additionally, the container was set to not run in privileged mode to enhance security by reducing the potential attack surface.

**Policy/PodSecurityViolation**: The privileged mode was removed from the nginx container's security context to comply with Pod Security Standards, which restrict the use of privileged containers to enhance security.

**Probes/MissingReadinessLiveness**: Added TCP-based liveness and readiness probes for nginx to enable automatic recovery and traffic management.

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

**Security/ReadOnlyRootFSFalse**: Applied comprehensive security hardening:
  - allowPrivilegeEscalation: false (prevents privilege escalation)
  - capabilities.drop: [ALL] (removes unnecessary privileges)
  - readOnlyRootFilesystem: true (prevents filesystem tampering)
  - runAsNonRoot: true + runAsUser: 1000 (ensures non-root execution)
  - pod-level seccompProfile RuntimeDefault
  - Added tmp/cache/run emptyDir volumes and mounts where needed

**Skipped Categories** (by design):
- Misc/Unmapped: Not suitable for inline fix
- Network/MissingNetworkPolicy: NetworkPolicy requires separate resource with application-specific traffic rules. Create as separate manifest based on your architecture.
- Schema/InvalidManifest: Not suitable for inline fix
- Style/YamlLint: Not suitable for inline fix


## Statistics
- Total patches: 23
- Categories processed: 19
- Categories skipped: 4
- Status: Success

## Skipped Categories
- Misc/Unmapped
- Network/MissingNetworkPolicy
- Schema/InvalidManifest
- Style/YamlLint
