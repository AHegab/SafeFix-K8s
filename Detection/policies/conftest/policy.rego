

# Example: require imagePullPolicy: Always
imagepull_not_always contains c if {
  input.kind == "Pod"
  c := input.spec.containers[_]
  v := c.imagePullPolicy
  v != "Always"
}

# Example: require runAsNonRoot: true
run_as_non_root_missing contains c if {
  input.kind == "Pod"
  c := input.spec.containers[_]
  not c.securityContext.runAsNonRoot
}

# Example: require limits
limits_missing contains c if {
  input.kind == "Pod"
  c := input.spec.containers[_]
  not c.resources.limits
}

# Example: require readinessProbe
readiness_probe_missing contains c if {
  input.kind == "Pod"
  c := input.spec.containers[_]
  not c.readinessProbe
}

# Example: require livenessProbe
liveness_probe_missing contains c if {
  input.kind == "Pod"
  c := input.spec.containers[_]
  not c.livenessProbe
}

# Example: require securityContext.privileged == false
privileged_container contains c if {
  input.kind == "Pod"
  c := input.spec.containers[_]
  c.securityContext.privileged == true
}

# Example: require readOnlyRootFilesystem: true
readonly_rootfs_missing contains c if {
  input.kind == "Pod"
  c := input.spec.containers[_]
  not c.securityContext.readOnlyRootFilesystem
}

# Example: require seccompProfile
seccomp_profile_missing if {
  input.kind == "Pod"
  not input.metadata.annotations["seccomp.security.alpha.kubernetes.io/pod"]
}

# Example: require AppArmor profile
apparmor_profile_missing if {
  input.kind == "Pod"
  not input.metadata.annotations["container.apparmor.security.beta.kubernetes.io/prod"]
}
  msg := "pod: mounts /var/run/docker.sock"

