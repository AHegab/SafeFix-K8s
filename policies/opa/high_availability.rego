package main

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# Deny if deployment has only 1 replica (not HA)
deny contains msg if {
    input.kind == "Deployment"
    input.spec.replicas == 1
    msg := sprintf("%s: deployment has only 1 replica (not highly available)", [input.metadata.name])
}

# Warn if replicas not specified (defaults to 1)
warn contains msg if {
    input.kind == "Deployment"
    not input.spec.replicas
    msg := sprintf("%s: replicas not specified (defaults to 1, not highly available)", [input.metadata.name])
}
