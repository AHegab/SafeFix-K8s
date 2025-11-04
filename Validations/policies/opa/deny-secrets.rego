package k8s.secure_secrets

deny contains msg if {
  input.kind == "Secret"
  not exempt_secret
  not governance_ok
  msg := sprintf("Plain Secret %q must be encrypted or managed by SealedSecrets/ExternalSecrets/KMS", [input.metadata.name])
}

exempt_secret if {
  input.apiVersion == "bitnami.com/v1alpha1"
  input.kind == "SealedSecret"
}

exempt_secret if {
  input.kind == "ExternalSecret"
}

governance_ok if {
  ann := input.metadata.annotations
  ann != null
  ann["safefixk8s.io/allow-plain-secret"] == "true"
}

governance_ok if {
  ann := input.metadata.annotations
  ann != null
  ann["secrets.example.com/managed"] == "true"
}
