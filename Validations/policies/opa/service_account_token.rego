package main

import future.keywords.contains
import future.keywords.if

# Service account token auto-mounting validation
# Prevents automatic mounting of default service account tokens

deny contains msg if {
	input.kind == "Pod"
	not input.spec.automountServiceAccountToken == false
	msg := "Pod should set automountServiceAccountToken: false to prevent auto-mounting default SA token"
}

deny contains msg if {
	input.kind != "Pod"
	input.kind != "List"
	has_template(input)
	podspec := input.spec.template.spec
	not podspec.automountServiceAccountToken == false
	workload := default_name(input.metadata.name)
	msg := sprintf("%s should set automountServiceAccountToken: false to prevent auto-mounting default SA token", [workload])
}

deny contains msg if {
	input.kind == "Pod"
	input.spec.serviceAccountName == "default"
	not input.spec.automountServiceAccountToken == false
	msg := "Pod using 'default' service account should explicitly set automountServiceAccountToken: false"
}

deny contains msg if {
	input.kind != "Pod"
	input.kind != "List"
	has_template(input)
	podspec := input.spec.template.spec
	podspec.serviceAccountName == "default"
	not podspec.automountServiceAccountToken == false
	workload := default_name(input.metadata.name)
	msg := sprintf("%s using 'default' service account should explicitly set automountServiceAccountToken: false", [workload])
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
