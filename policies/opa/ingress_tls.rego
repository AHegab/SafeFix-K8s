package main

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# Deny if ingress has no TLS configuration
deny contains msg if {
    input.kind == "Ingress"
    not input.spec.tls
    msg := sprintf("Ingress '%s': no TLS configuration", [input.metadata.name])
}

deny contains msg if {
    input.kind == "Ingress"
    count(input.spec.tls) == 0
    msg := sprintf("Ingress '%s': TLS array is empty", [input.metadata.name])
}
