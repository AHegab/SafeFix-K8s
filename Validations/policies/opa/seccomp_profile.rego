package main

import future.keywords.contains
import future.keywords.if

# Seccomp profile validation
# Ensures seccompProfile is set to RuntimeDefault or Localhost

deny contains msg if {
	input.kind == "Pod"
	not input.spec.securityContext
	msg := "Pod must define spec.securityContext"
}

deny contains msg if {
	input.kind == "Pod"
	input.spec.securityContext
	not input.spec.securityContext.seccompProfile
	msg := "Pod securityContext must define seccompProfile"
}

deny contains msg if {
	input.kind == "Pod"
	input.spec.securityContext.seccompProfile
	not valid_seccomp_type(input.spec.securityContext.seccompProfile.type)
	msg := sprintf("Pod seccompProfile.type must be RuntimeDefault or Localhost, got: %s", [input.spec.securityContext.seccompProfile.type])
}

deny contains msg if {
	input.kind != "Pod"
	input.kind != "List"
	has_template(input)
	podspec := input.spec.template.spec
	not podspec.securityContext
	workload := default_name(input.metadata.name)
	msg := sprintf("%s must define securityContext", [workload])
}

deny contains msg if {
	input.kind != "Pod"
	input.kind != "List"
	has_template(input)
	podspec := input.spec.template.spec
	podspec.securityContext
	not podspec.securityContext.seccompProfile
	workload := default_name(input.metadata.name)
	msg := sprintf("%s securityContext must define seccompProfile", [workload])
}

deny contains msg if {
	input.kind != "Pod"
	input.kind != "List"
	has_template(input)
	podspec := input.spec.template.spec
	podspec.securityContext.seccompProfile
	not valid_seccomp_type(podspec.securityContext.seccompProfile.type)
	workload := default_name(input.metadata.name)
	msg := sprintf("%s seccompProfile.type must be RuntimeDefault or Localhost, got: %s", [workload, podspec.securityContext.seccompProfile.type])
}

# Container-level seccomp check
deny contains msg if {
	input.kind == "Pod"
	some i
	container := input.spec.containers[i]
	container.securityContext
	container.securityContext.seccompProfile
	not valid_seccomp_type(container.securityContext.seccompProfile.type)
	name := default_name(container.name)
	msg := sprintf("container \"%s\" seccompProfile.type must be RuntimeDefault or Localhost", [name])
}

# Helper functions
has_template(obj) if {
	obj.spec.template
}

valid_seccomp_type(t) if {
	t == "RuntimeDefault"
}

valid_seccomp_type(t) if {
	t == "Localhost"
}

default_name(n) = n if {
	n
}

default_name(n) = "(unnamed)" if {
	not n
}
