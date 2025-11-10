package main

__doc__ := {
  "summary": "Require runAsNonRoot=true (pod or container)",
  "category": "pod-security",
}

# Deny when neither pod nor any container enforces runAsNonRoot=true
deny contains msg if {
  not pod_run_as_non_root(input)
  msg := "workload must set runAsNonRoot=true at podSecurityContext or container securityContext"
}

pod_run_as_non_root(obj) = true if {
  obj.kind == "Pod"
  obj.spec.securityContext
  obj.spec.securityContext.runAsNonRoot == true
}

pod_run_as_non_root(obj) = true if {
  obj.kind != "Pod"
  ps := obj.spec.template.spec
  ps.securityContext
  ps.securityContext.runAsNonRoot == true
}

pod_run_as_non_root(obj) = true if {
  obj.kind == "Pod"
  some i
  c := obj.spec.containers[i]
  c.securityContext
  c.securityContext.runAsNonRoot == true
}

pod_run_as_non_root(obj) = true if {
  obj.kind == "Pod"
  obj.spec.initContainers
  some i
  c := obj.spec.initContainers[i]
  c.securityContext
  c.securityContext.runAsNonRoot == true
}

pod_run_as_non_root(obj) = true if {
  obj.kind != "Pod"
  ps := obj.spec.template.spec
  some i
  c := ps.containers[i]
  c.securityContext
  c.securityContext.runAsNonRoot == true
}

pod_run_as_non_root(obj) = true if {
  obj.kind != "Pod"
  ps := obj.spec.template.spec
  ps.initContainers
  some i
  c := ps.initContainers[i]
  c.securityContext
  c.securityContext.runAsNonRoot == true
}
