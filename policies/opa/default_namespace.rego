package kubernetes.namespace

deny contains msg if {
  not input.metadata.namespace
  msg := sprintf("%s: no namespace set (defaults to 'default')", [input.metadata.name])
}

deny contains msg if {
  input.metadata.namespace == "default"
  msg := sprintf("%s: resource in default namespace", [input.metadata.name])
}
