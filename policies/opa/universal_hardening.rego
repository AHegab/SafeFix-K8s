package k8s.universal_hardening

# runAsNonRoot: true
deny contains msg if {
  has_podspec
  not run_as_non_root
  msg := sprintf("%s must set runAsNonRoot: true", [obj_name])
}

# allowPrivilegeEscalation: false  
deny contains msg if {
  input.kind == "Pod"
  some c
  container := input.spec.containers[c]
  not container.securityContext.allowPrivilegeEscalation
  msg := sprintf("%s container %q must set allowPrivilegeEscalation: false", [obj_name, container.name])
}

deny contains msg if {
  input.kind != "Pod"
  some c
  container := input.spec.template.spec.containers[c]
  not container.securityContext.allowPrivilegeEscalation
  msg := sprintf("%s container %q must set allowPrivilegeEscalation: false", [obj_name, container.name])
}

# privileged: false
deny contains msg if {
  input.kind == "Pod"
  some c
  container := input.spec.containers[c]
  container.securityContext.privileged == true
  msg := sprintf("%s container %q must not be privileged", [obj_name, container.name])
}

deny contains msg if {
  input.kind != "Pod"
  some c
  container := input.spec.template.spec.containers[c]
  container.securityContext.privileged == true
  msg := sprintf("%s container %q must not be privileged", [obj_name, container.name])
}

# CAP_SYS_ADMIN not added
deny contains msg if {
  input.kind == "Pod"
  some c
  container := input.spec.containers[c]
  container.securityContext.capabilities.add[_] == "SYS_ADMIN"
  msg := sprintf("%s container %q must not add CAP_SYS_ADMIN", [obj_name, container.name])
}

deny contains msg if {
  input.kind != "Pod"
  some c
  container := input.spec.template.spec.containers[c]
  container.securityContext.capabilities.add[_] == "SYS_ADMIN"
  msg := sprintf("%s container %q must not add CAP_SYS_ADMIN", [obj_name, container.name])
}

# seccompProfile: RuntimeDefault
deny contains msg if {
  has_podspec
  not pod_or_container_seccomp_default
  msg := sprintf("%s must set seccompProfile.type: RuntimeDefault", [obj_name])
}

# --- helpers ---
has_podspec if { input.spec.containers }
has_podspec if { input.spec.template.spec.containers }

run_as_non_root if {
  sc := input.spec.securityContext
  sc.runAsNonRoot == true
}

run_as_non_root if {
  sc := input.spec.template.spec.securityContext
  sc.runAsNonRoot == true
}

run_as_non_root if {
  some c
  input.spec.containers[c].securityContext.runAsNonRoot == true
}

run_as_non_root if {
  some c
  input.spec.template.spec.containers[c].securityContext.runAsNonRoot == true
}

pod_or_container_seccomp_default if {
  input.spec.securityContext.seccompProfile.type == "RuntimeDefault"
}

pod_or_container_seccomp_default if {
  input.spec.template.spec.securityContext.seccompProfile.type == "RuntimeDefault"
}

pod_or_container_seccomp_default if {
  some c
  input.spec.containers[c].securityContext.seccompProfile.type == "RuntimeDefault"
}

pod_or_container_seccomp_default if {
  some c
  input.spec.template.spec.containers[c].securityContext.seccompProfile.type == "RuntimeDefault"
}

obj_name := sprintf("%s/%s", [lower(input.kind), input.metadata.name]) if { input.kind == "Pod" }
obj_name := input.metadata.name if { input.kind != "Pod" }
