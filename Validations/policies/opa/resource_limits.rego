package main

import future.keywords.contains
import future.keywords.if

# Resource limits and requests validation
# Ensures all containers have CPU and memory limits/requests set

deny contains msg if {
	input.kind == "Pod"
	some i
	container := input.spec.containers[i]
	not container.resources.limits.cpu
	name := default_name(container.name)
	msg := sprintf("container \"%s\" must set CPU limit", [name])
}

deny contains msg if {
	input.kind != "Pod"
	input.kind != "List"
	podspec := input.spec.template.spec
	some i
	container := podspec.containers[i]
	not container.resources.limits.cpu
	name := default_name(container.name)
	msg := sprintf("container \"%s\" must set CPU limit", [name])
}

deny contains msg if {
	input.kind == "Pod"
	some i
	container := input.spec.containers[i]
	not container.resources.limits.memory
	name := default_name(container.name)
	msg := sprintf("container \"%s\" must set memory limit", [name])
}

deny contains msg if {
	input.kind != "Pod"
	input.kind != "List"
	podspec := input.spec.template.spec
	some i
	container := podspec.containers[i]
	not container.resources.limits.memory
	name := default_name(container.name)
	msg := sprintf("container \"%s\" must set memory limit", [name])
}

deny contains msg if {
	input.kind == "Pod"
	some i
	container := input.spec.containers[i]
	not container.resources.requests.cpu
	name := default_name(container.name)
	msg := sprintf("container \"%s\" must set CPU request", [name])
}

deny contains msg if {
	input.kind != "Pod"
	input.kind != "List"
	podspec := input.spec.template.spec
	some i
	container := podspec.containers[i]
	not container.resources.requests.cpu
	name := default_name(container.name)
	msg := sprintf("container \"%s\" must set CPU request", [name])
}

deny contains msg if {
	input.kind == "Pod"
	some i
	container := input.spec.containers[i]
	not container.resources.requests.memory
	name := default_name(container.name)
	msg := sprintf("container \"%s\" must set memory request", [name])
}

deny contains msg if {
	input.kind != "Pod"
	input.kind != "List"
	podspec := input.spec.template.spec
	some i
	container := podspec.containers[i]
	not container.resources.requests.memory
	name := default_name(container.name)
	msg := sprintf("container \"%s\" must set memory request", [name])
}

# Helper function
default_name(n) = n if {
	n
}

default_name(n) = "(unnamed)" if {
	not n
}
