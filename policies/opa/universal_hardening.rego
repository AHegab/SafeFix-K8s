package safefix.k8s

import data.lib.k8s as k

# Helpers to iterate containers for both Pod and controllers
containers(obj) = cs {
  some c; cs := obj.spec.containers; cs[c]
} else = cs {
  some c; cs := obj.spec.template.spec.containers; cs[c]
}

# ----- Metadata sanity -----
deny[msg] {
  not input.metadata.name
  msg := {"id":"METADATA_NAME_MISSING","severity":"HIGH","msg":"metadata.name is required"}
}

# ----- Image hygiene -----
deny[msg] {
  some c; containers(input)[c]
  endswith(c.image, ":latest")
  not c.imagePullPolicy
  msg := {"id":"LATEST_WITHOUT_PULL_ALWAYS","severity":"MEDIUM",
          "msg": sprintf("Container %q uses :latest without imagePullPolicy: Always", [c.name])}
}
deny[msg] {
  some c; containers(input)[c]
  endswith(c.image, ":latest")
  c.imagePullPolicy != "Always"
  msg := {"id":"LATEST_WITHOUT_PULL_ALWAYS","severity":"MEDIUM",
          "msg": sprintf("Container %q uses :latest without imagePullPolicy: Always", [c.name])}
}

# ----- Probes -----
deny[msg] {
  some c; containers(input)[c]
  not c.livenessProbe
  not c.readinessProbe
  msg := {"id":"PROBES_MISSING","severity":"MEDIUM",
          "msg": sprintf("Container %q missing both liveness & readiness probes", [c.name])}
}

# ----- Privilege / hardening -----
deny[msg] {
  some c; containers(input)[c]
  not c.securityContext.runAsNonRoot
  msg := {"id":"RUN_AS_NON_ROOT_MISSING","severity":"HIGH",
          "msg": sprintf("Container %q missing runAsNonRoot: true", [c.name])}
}
deny[msg] {
  some c; containers(input)[c]
  not c.securityContext.allowPrivilegeEscalation
  msg := {"id":"ALLOW_PRIV_ESC_TRUE_OR_UNSET","severity":"HIGH",
          "msg": sprintf("Container %q allowPrivilegeEscalation not explicitly false", [c.name])}
} else {
  some c; containers(input)[c]
  c.securityContext.allowPrivilegeEscalation
  msg := {"id":"ALLOW_PRIV_ESC_TRUE_OR_UNSET","severity":"HIGH",
          "msg": sprintf("Container %q allowPrivilegeEscalation true", [c.name])}
}
deny[msg] {
  some c; containers(input)[c]
  not c.securityContext.capabilities.drop
  msg := {"id":"CAPS_NOT_DROPPED","severity":"MEDIUM",
          "msg": sprintf("Container %q capabilities not dropped", [c.name])}
}
deny[msg] {
  not input.spec.securityContext.seccompProfile.type
  not input.spec.template.spec.securityContext.seccompProfile.type
  msg := {"id":"SECCOMP_MISSING","severity":"HIGH","msg":"Pod seccompProfile missing (RuntimeDefault recommended)"}
}

# ----- Resources -----
deny[msg] {
  some c; containers(input)[c]
  not c.resources.requests.cpu
} 
deny[msg] {
  some c; containers(input)[c]
  not c.resources.requests.memory
}
deny[msg] {
  some c; containers(input)[c]
  not c.resources.limits.cpu
}
deny[msg] {
  some c; containers(input)[c]
  not c.resources.limits.memory
}
# Convert the four above into one canonical ID in post-normalization:
warn[msg] {
  some c; containers(input)[c]
  not c.resources.requests.cpu or
  not c.resources.requests.memory or
  not c.resources.limits.cpu or
  not c.resources.limits.memory
  msg := {"id":"RESOURCES_REQUESTS_LIMITS_MISSING","severity":"MEDIUM",
          "msg":"CPU/memory requests/limits missing on one or more containers"}
}

# ----- ServiceAccount token -----
deny[msg] {
  not input.spec.automountServiceAccountToken
  not input.spec.template.spec.automountServiceAccountToken
  msg := {"id":"SA_TOKEN_AUTOMOUNT_ENABLED","severity":"MEDIUM",
          "msg":"ServiceAccount token auto-mounting not disabled (set automountServiceAccountToken: false)"}
}

# ----- Docker socket & hostPath type -----
deny[msg] {
  some v
  v := input.spec.volumes[_]
  v.hostPath
  v.hostPath.path == "/var/run/docker.sock"
  msg := {"id":"DOCKER_SOCK_MOUNT","severity":"HIGH",
          "msg":"Host docker socket is mounted"}
} else {
  some v
  v := input.spec.template.spec.volumes[_]
  v.hostPath
  v.hostPath.path == "/var/run/docker.sock"
  msg := {"id":"DOCKER_SOCK_MOUNT","severity":"HIGH",
          "msg":"Host docker socket is mounted"}
}

deny[msg] {
  some v
  v := input.spec.volumes[_]
  v.hostPath
  v.hostPath.path == "/var/run/docker.sock"
  not v.hostPath.type
  msg := {"id":"HOSTPATH_TYPE_UNSET_FOR_SOCK","severity":"LOW",
          "msg":"hostPath.type not set for /var/run/docker.sock"}
} else {
  some v
  v := input.spec.template.spec.volumes[_]
  v.hostPath
  v.hostPath.path == "/var/run/docker.sock"
  not v.hostPath.type
  msg := {"id":"HOSTPATH_TYPE_UNSET_FOR_SOCK","severity":"LOW",
          "msg":"hostPath.type not set for /var/run/docker.sock"}
}
