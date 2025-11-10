package main

import future.keywords.in
import future.keywords.contains
import future.keywords.if

# Deny if deployment selector doesn't match pod template labels
deny contains msg if {
    input.kind == "Deployment"
    not selector_matches_labels
    msg := sprintf("%s: selector doesn't match pod template labels", [input.metadata.name])
}

deny contains msg if {
    input.kind == "Deployment"
    not input.spec.selector
    msg := sprintf("%s: no selector defined", [input.metadata.name])
}

deny contains msg if {
    input.kind == "Deployment"
    not input.spec.selector.matchLabels
    msg := sprintf("%s: no matchLabels in selector", [input.metadata.name])
}

selector_matches_labels if {
    input.spec.selector.matchLabels == input.spec.template.metadata.labels
}
