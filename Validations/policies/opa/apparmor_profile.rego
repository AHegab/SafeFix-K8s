package main

import future.keywords.contains
import future.keywords.if

# AppArmor profile validation
# Ensures AppArmor profile annotation is set

deny contains msg if {
	input.kind == "Pod"
	not has_apparmor_annotation(input)
	msg := "Pod must have AppArmor annotation (container.apparmor.security.beta.kubernetes.io/<container>)"
}

deny contains msg if {
	input.kind != "Pod"
	input.kind != "List"
	has_template(input)
	not has_apparmor_annotation(input.spec.template)
	workload := default_name(input.metadata.name)
	msg := sprintf("%s must have AppArmor annotation (container.apparmor.security.beta.kubernetes.io/<container>)", [workload])
}

deny contains msg if {
	input.kind == "Pod"
	has_apparmor_annotation(input)
	some key, value in input.metadata.annotations
	startswith(key, "container.apparmor.security.beta.kubernetes.io/")
	value == "unconfined"
	container_name := substring(key, 47, -1)
	msg := sprintf("container \"%s\" has AppArmor profile set to 'unconfined' (insecure)", [container_name])
}

deny contains msg if {
	input.kind != "Pod"
	input.kind != "List"
	has_template(input)
	has_apparmor_annotation(input.spec.template)
	some key, value in input.spec.template.metadata.annotations
	startswith(key, "container.apparmor.security.beta.kubernetes.io/")
	value == "unconfined"
	container_name := substring(key, 47, -1)
	workload := default_name(input.metadata.name)
	msg := sprintf("%s container \"%s\" has AppArmor profile set to 'unconfined' (insecure)", [workload, container_name])
}

# Helper functions
has_apparmor_annotation(obj) if {
	obj.metadata.annotations
	some key, _ in obj.metadata.annotations
	startswith(key, "container.apparmor.security.beta.kubernetes.io/")
}

has_template(obj) if {
	obj.spec.template
}

default_name(n) = n if {
	n
}

default_name(n) = "(unnamed)" if {
	not n
}
