package main

import future.keywords.contains
import future.keywords.if

# Health probes validation
# Ensures containers have liveness and readiness probes

deny contains msg if {
	input.kind == "Pod"
	some i
	container := input.spec.containers[i]
	not container.livenessProbe
	name := default_name(container.name)
	msg := sprintf("container \"%s\" must define livenessProbe", [name])
}

deny contains msg if {
	input.kind != "Pod"
	input.kind != "List"
	has_template(input)
	podspec := input.spec.template.spec
	some i
	container := podspec.containers[i]
	not container.livenessProbe
	name := default_name(container.name)
	msg := sprintf("container \"%s\" must define livenessProbe", [name])
}

deny contains msg if {
	input.kind == "Pod"
	some i
	container := input.spec.containers[i]
	not container.readinessProbe
	name := default_name(container.name)
	msg := sprintf("container \"%s\" must define readinessProbe", [name])
}

deny contains msg if {
	input.kind != "Pod"
	input.kind != "List"
	has_template(input)
	podspec := input.spec.template.spec
	some i
	container := podspec.containers[i]
	not container.readinessProbe
	name := default_name(container.name)
	msg := sprintf("container \"%s\" must define readinessProbe", [name])
}

# Helper functions
has_template(obj) if {
	obj.spec.template
}

default_name(n) = n if {
	n
}

default_name(n) = "(unnamed)" if {
	not n
}
