package main

import future.keywords.contains
import future.keywords.if

# Image pull policy validation
# Ensures imagePullPolicy is set to Always for security

deny contains msg if {
	input.kind == "Pod"
	some i
	container := input.spec.containers[i]
	not container.imagePullPolicy
	name := default_name(container.name)
	msg := sprintf("container \"%s\" must set imagePullPolicy", [name])
}

deny contains msg if {
	input.kind == "Pod"
	some i
	container := input.spec.containers[i]
	container.imagePullPolicy
	container.imagePullPolicy != "Always"
	name := default_name(container.name)
	msg := sprintf("container \"%s\" imagePullPolicy should be 'Always', got: '%s'", [name, container.imagePullPolicy])
}

deny contains msg if {
	input.kind != "Pod"
	input.kind != "List"
	has_template(input)
	podspec := input.spec.template.spec
	some i
	container := podspec.containers[i]
	not container.imagePullPolicy
	name := default_name(container.name)
	msg := sprintf("container \"%s\" must set imagePullPolicy", [name])
}

deny contains msg if {
	input.kind != "Pod"
	input.kind != "List"
	has_template(input)
	podspec := input.spec.template.spec
	some i
	container := podspec.containers[i]
	container.imagePullPolicy
	container.imagePullPolicy != "Always"
	name := default_name(container.name)
	msg := sprintf("container \"%s\" imagePullPolicy should be 'Always', got: '%s'", [name, container.imagePullPolicy])
}

# Init containers
deny contains msg if {
	input.kind == "Pod"
	input.spec.initContainers
	some i
	container := input.spec.initContainers[i]
	not container.imagePullPolicy
	name := default_name(container.name)
	msg := sprintf("initContainer \"%s\" must set imagePullPolicy", [name])
}

deny contains msg if {
	input.kind != "Pod"
	input.kind != "List"
	has_template(input)
	podspec := input.spec.template.spec
	podspec.initContainers
	some i
	container := podspec.initContainers[i]
	not container.imagePullPolicy
	name := default_name(container.name)
	msg := sprintf("initContainer \"%s\" must set imagePullPolicy", [name])
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
