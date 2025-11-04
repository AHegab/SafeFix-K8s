package lib.helpers

# Simple name helper - return container name or fallback
default_name(n) = n if {
  n
}

default_name(n) = "(unnamed)" if {
  not n
}

# Pod spec helpers
podspec(obj) = obj.spec if {
  obj.kind == "Pod"
}

podspec(obj) = obj.spec.jobTemplate.spec.template.spec if {
  obj.kind == "CronJob"
}

podspec(obj) = obj.spec.template.spec if {
  obj.kind != "Pod"
  obj.kind != "CronJob"
}
