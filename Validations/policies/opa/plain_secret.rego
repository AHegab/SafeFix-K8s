package kubernetes.plainsecret

is_unencrypted_secret if {
  input.kind == "Secret"
  # Opaque raw secret without sealed/external-secret mechanisms
  not input.metadata.annotations["bitnami.com/sealed-secrets"]
  not input.metadata.annotations["kubernetes.io/encryption-provider"]
  not input.metadata.annotations["external-secrets.io/remote-ref"]
}

deny contains msg if {
  is_unencrypted_secret
  msg := sprintf("%s: plain Secret (Opaque) without encryption/externalsecret annotations", [input.metadata.name])
}
