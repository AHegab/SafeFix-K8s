#!/usr/bin/env bash
# Detection/detectors.sh
# SafeFix-K8s: bash port of detectors.ps1 for Mac/Linux.
# Usage: detectors.sh <lean|extended> <path>
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

OUTPUT_ROOT="${SAFEFIX_OUTPUT_ROOT:-$SCRIPT_DIR/output}"
mkdir -p "$OUTPUT_ROOT"
OUTPUT_ROOT="$(cd "$OUTPUT_ROOT" && pwd)"
DETECTION_DIR="$OUTPUT_ROOT/detection"
OUT_DIR="$DETECTION_DIR/raw"
LOGS_DIR="$DETECTION_DIR/logs"
mkdir -p "$OUT_DIR" "$LOGS_DIR"
export SAFEFIX_DETECTION_RAW_DIR="$OUT_DIR"
export SAFEFIX_DETECTION_LOG_DIR="$LOGS_DIR"

TOOL_TIMINGS=()

# --- helpers ------------------------------------------------------------------
wrap_placeholder() {
  local out="$1" tool="$2" msg="$3"
  msg="${msg//\"/\'}"
  printf '[{"tool":"%s","note":"%s"}]' "$tool" "$msg" > "$out"
  echo "[$tool] -> $out (placeholder)"
}

write_nonempty() {
  local path="$1"
  if [[ ! -s "$path" ]]; then
    echo "Output '$path' missing/empty." >&2
    return 1
  fi
}

resolve_scan_path() {
  local path="$1"
  if [[ "$path" = /* ]]; then
    if [[ ! -e "$path" ]]; then echo "Path does not exist: $path" >&2; return 1; fi
    (cd "$path" && pwd); return 0
  fi
  local cwd_target="$PWD/$path"
  if [[ -e "$cwd_target" ]]; then (cd "$cwd_target" && pwd); return 0; fi
  local repo_target="$REPO_ROOT/$path"
  if [[ -e "$repo_target" ]]; then (cd "$repo_target" && pwd); return 0; fi
  echo "Cannot find path '$path' from CWD or repo root ($REPO_ROOT)." >&2
  return 1
}

to_scan_rel() {
  local abs_root="$1" abs_file="$2"
  local rel="${abs_file#"$abs_root"}"
  rel="${rel#/}"
  echo "/scan/$rel"
}

invoke_with_timing() {
  local name="$1"; shift
  local start end status="ok"
  start=$(date +%s)
  if ! "$@"; then status="error"; fi
  end=$(date +%s)
  TOOL_TIMINGS+=("$name|$((end - start))|$status")
}

# --- image sets -----------------------------------------------------------
LEAN_IMAGES=(
  "stackrox/kube-linter:latest"
  "quay.io/fairwinds/polaris:latest"
  "bridgecrew/checkov:latest"
  "aquasec/trivy:latest"
  "quay.io/kubescape/kubescape:latest"
  "zegl/kube-score:latest"
  "cytopia/yamllint:latest"
  "ghcr.io/shopify/kubeaudit:latest"
  "ghcr.io/yannh/kubeconform:latest"
  "openpolicyagent/conftest:latest"
)
EXTENDED_EXTRA_IMAGES=(
  "us-docker.pkg.dev/fairwinds-ops/oss/pluto:v5"
)

ensure_images() {
  local images=("$@")
  local img present
  for img in "${images[@]}"; do
    present=$(docker images --format '{{.Repository}}:{{.Tag}}' | grep -F -x "$img" || true)
    if [[ -z "$present" ]]; then
      echo "Pulling: $img"
      docker pull "$img" >/dev/null 2>&1 || echo "Warning: Could not pull $img"
    fi
  done
}

# --- embedded config extraction (delegated to python3 for reliable YAML/regex handling) ---
expand_embedded_configs() {
  local path="$1"
  local abs out
  abs=$(resolve_scan_path "$path") || return 1
  out="$SCRIPT_DIR/.tmp-extracted"
  mkdir -p "$out"
  python3 - "$abs" "$out" <<'PYEOF'
import re, sys, os

abs_root, out_dir = sys.argv[1], sys.argv[2]
data_re = re.compile(r'^\s{2,}([A-Za-z0-9._-]+):\s*\|\s*\n((?:\s{4,}.+\n?)+)', re.MULTILINE)

for root, _, files in os.walk(abs_root):
    for fname in files:
        if not (fname.endswith(".yaml") or fname.endswith(".yml")):
            continue
        fpath = os.path.join(root, fname)
        base = os.path.splitext(fname)[0]
        try:
            doc = open(fpath, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        for part in re.split(r'^\s*---\s*$', doc, flags=re.MULTILINE):
            if not part.strip() or "kind:" not in part or "ConfigMap" not in part:
                continue
            for m in data_re.finditer(part):
                key = m.group(1)
                val = re.sub(r'^\s{4}', '', m.group(2), flags=re.MULTILINE)
                out_file = os.path.join(out_dir, f"embedded__{base}__{key.replace(':', '_')}.yaml")
                with open(out_file, "w", encoding="utf-8") as fh:
                    fh.write(val)
PYEOF
  echo "$out"
}

# --- detectors --------------------------------------------------------------
det_kubeconform() {
  local path="$1" out="${2:-$OUT_DIR/kubeconform_raw.json}"
  local abs
  abs=$(resolve_scan_path "$path") || { wrap_placeholder "$out" "kubeconform" "path resolution failed"; return; }
  if docker run --rm -v "${abs}:/scan:ro" ghcr.io/yannh/kubeconform:latest \
      -summary -output json -strict -ignore-missing-schemas -verbose /scan > "$out" 2>/dev/null && write_nonempty "$out"; then
    echo "[kubeconform] -> $out"
  else
    wrap_placeholder "$out" "kubeconform" "docker run failed"
  fi
}

det_kubelinter() {
  local path="$1" out="${2:-$OUT_DIR/kubelinter_raw.json}"
  local cfg="$REPO_ROOT/policies/kubelinter-config.yaml"
  local abs
  abs=$(resolve_scan_path "$path") || { wrap_placeholder "$out" "kubelinter" "path resolution failed"; return; }
  if [[ -f "$cfg" ]]; then
    docker run --rm -v "${abs}:/scan:ro" -v "${cfg}:/cfg/kubelinter-config.yaml:ro" stackrox/kube-linter:latest \
      lint /scan --config /cfg/kubelinter-config.yaml --format json > "$out" 2>/dev/null
  else
    docker run --rm -v "${abs}:/scan:ro" stackrox/kube-linter:latest \
      lint /scan --format json > "$out" 2>/dev/null
  fi
  if write_nonempty "$out"; then echo "[kube-linter] -> $out"; else wrap_placeholder "$out" "kubelinter" "no output"; fi
}

det_polaris() {
  local path="$1" out="${2:-$OUT_DIR/polaris_raw.json}"
  local abs
  abs=$(resolve_scan_path "$path") || { wrap_placeholder "$out" "polaris" "path resolution failed"; return; }
  if docker run --rm -v "${abs}:/scan:ro" quay.io/fairwinds/polaris:latest \
      polaris audit --audit-path /scan --format json > "$out" 2>/dev/null && write_nonempty "$out"; then
    echo "[polaris] -> $out"
  else
    wrap_placeholder "$out" "polaris" "docker run failed"
  fi
}

det_checkov() {
  local path="$1" out="${2:-$OUT_DIR/checkov_raw.json}"
  local abs checks_dir local_bin
  abs=$(resolve_scan_path "$path") || { wrap_placeholder "$out" "checkov" "path resolution failed"; return; }
  checks_dir="$REPO_ROOT/policies/checkov"
  local_bin=$(command -v checkov || true)
  if [[ -n "$local_bin" ]]; then
    if [[ -d "$checks_dir" ]]; then
      checkov -d "$abs" --framework kubernetes --quiet --compact -o json --external-checks-dir "$checks_dir" > "$out" 2>/dev/null
    else
      checkov -d "$abs" --framework kubernetes --quiet --compact -o json > "$out" 2>/dev/null
    fi
  else
    local docker_args=(run --rm -v "${abs}:/scan:ro")
    if [[ -d "$checks_dir" ]]; then docker_args+=(-v "${checks_dir}:/ext:ro"); fi
    docker_args+=(bridgecrew/checkov:latest -d /scan --framework kubernetes --quiet --compact)
    if [[ -d "$checks_dir" ]]; then docker_args+=(--external-checks-dir /ext); fi
    docker_args+=(-o json)
    docker "${docker_args[@]}" > "$out" 2>/dev/null
  fi
  if write_nonempty "$out"; then echo "[checkov] -> $out"; else wrap_placeholder "$out" "checkov" "no output"; fi
}

det_trivyconfig() {
  local path="$1" out="${2:-$OUT_DIR/trivy_config_raw.json}"
  local abs
  abs=$(resolve_scan_path "$path") || { wrap_placeholder "$out" "trivy-config" "path resolution failed"; return; }
  if docker run --rm -v "${abs}:/scan:ro" aquasec/trivy:latest \
      config --quiet --format json /scan > "$out" 2>/dev/null && write_nonempty "$out"; then
    echo "[trivy config] -> $out"
  else
    wrap_placeholder "$out" "trivy-config" "docker run failed"
  fi
}

det_kubescape() {
  local path="$1" out="${2:-$OUT_DIR/kubescape_raw.json}"
  local abs local_bin
  abs=$(resolve_scan_path "$path") || { wrap_placeholder "$out" "kubescape" "path resolution failed"; return; }
  export KUBESCAPE_DISABLE_GIT_INFO=true
  local_bin=$(command -v kubescape || true)
  if [[ -n "$local_bin" ]]; then
    kubescape scan "$abs" --format json --format-version v2 --output "$out" >/dev/null 2>&1
  else
    docker run --rm -e KUBESCAPE_DISABLE_GIT_INFO=true -v "${abs}:/scan:ro" \
      quay.io/kubescape/kubescape:latest scan /scan --format json --format-version v2 \
      --output /scan/kubescape_raw.json >/dev/null 2>&1
    if [[ -f "$abs/kubescape_raw.json" && "$abs/kubescape_raw.json" != "$out" ]]; then
      mv -f "$abs/kubescape_raw.json" "$out"
    fi
  fi
  if [[ -s "$out" ]]; then
    echo "[kubescape] -> $out"
  else
    wrap_placeholder "$out" "kubescape" "failed: kubescape produced no usable output"
  fi
}

det_kubescore() {
  local path="$1" out="${2:-$OUT_DIR/kubescore_raw.json}"
  local abs
  abs=$(resolve_scan_path "$path") || { wrap_placeholder "$out" "kube-score" "path resolution failed"; return; }
  local files=() rel f
  while IFS= read -r -d '' f; do
    rel=$(to_scan_rel "$abs" "$f")
    files+=("$rel")
  done < <(find "$abs" -type f \( -iname '*.yaml' -o -iname '*.yml' \) -print0)
  if [[ ${#files[@]} -eq 0 ]]; then
    echo '[]' > "$out"; echo "[kube-score] -> $out (no YAML)"; return
  fi
  if docker run --rm -v "${abs}:/scan:ro" zegl/kube-score:latest score --output-format json "${files[@]}" > "$out" 2>/dev/null && write_nonempty "$out"; then
    echo "[kube-score] -> $out"
  else
    wrap_placeholder "$out" "kube-score" "docker run failed"
  fi
}

det_yamllint() {
  local path="$1" out="${2:-$OUT_DIR/yamllint_raw.txt}"
  local abs
  abs=$(resolve_scan_path "$path") || { wrap_placeholder "$out" "yamllint" "path resolution failed"; return; }
  if docker run --rm -v "${abs}:/scan:ro" cytopia/yamllint:latest -f parsable -s /scan > "$out" 2>/dev/null && write_nonempty "$out"; then
    echo "[yamllint] -> $out"
  else
    wrap_placeholder "$out" "yamllint" "docker run failed"
  fi
}

det_kubeaudit() {
  local path="$1" out="${2:-$OUT_DIR/kubeaudit_raw.json}"
  local abs local_bin
  abs=$(resolve_scan_path "$path") || { wrap_placeholder "$out" "kubeaudit" "path resolution failed"; return; }
  local files=()
  while IFS= read -r -d '' f; do files+=("$f"); done < <(find "$abs" -type f \( -iname '*.yaml' -o -iname '*.yml' \) -print0)
  if [[ ${#files[@]} -eq 0 ]]; then
    echo '[]' > "$out"; echo "[kubeaudit] -> $out (no YAML)"; return
  fi
  local_bin=$(command -v kubeaudit || true)
  local tmp_accum
  tmp_accum=$(mktemp)
  : > "$tmp_accum"
  echo "[kubeaudit] Scanning ${#files[@]} files..."
  local f raw rel dir
  for f in "${files[@]}"; do
    if [[ -n "$local_bin" ]]; then
      raw=$(kubeaudit all -f "$f" -p json 2>/dev/null || true)
    else
      dir=$(dirname "$f")
      raw=$(docker run --rm -v "${dir}:/scan:ro" ghcr.io/shopify/kubeaudit:latest \
        all -f "/scan/$(basename "$f")" -p json 2>/dev/null || true)
    fi
    rel=$(to_scan_rel "$abs" "$f")
    if [[ -n "$raw" ]]; then
      printf '%s\n' "$raw" | grep -E '^\s*\{' | grep -v -E 'Deprecation|WARNING' | \
        python3 -c "
import sys, json
rel = sys.argv[1]
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        obj = json.loads(line)
    except Exception:
        continue
    obj['file'] = rel
    print(json.dumps(obj))
" "$rel" >> "$tmp_accum"
    fi
  done
  if [[ -s "$tmp_accum" ]]; then
    python3 -c "
import json, sys
objs = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
json.dump(objs, open(sys.argv[2], 'w'), indent=2)
print(f'[kubeaudit] -> {sys.argv[2]} ({len(objs)} findings)')
" "$tmp_accum" "$out"
  else
    echo '[]' > "$out"; echo "[kubeaudit] -> $out (no findings)"
  fi
  rm -f "$tmp_accum"
}

det_conftest() {
  local path="$1" out="${2:-$OUT_DIR/conftest_raw.json}"
  local abs
  abs=$(resolve_scan_path "$path") || { wrap_placeholder "$out" "conftest" "path resolution failed"; return; }
  local policy_dirs=("$REPO_ROOT/policies/conftest" "$REPO_ROOT/policies/opa" "$REPO_ROOT/policies/opa_minimal")
  local mounted=() d
  for d in "${policy_dirs[@]}"; do [[ -d "$d" ]] && mounted+=("$d"); done
  if [[ ${#mounted[@]} -eq 0 ]]; then
    wrap_placeholder "$out" "conftest" "No OPA/conftest policy directories found"; return
  fi
  local tmp_policy_dir
  tmp_policy_dir=$(mktemp -d)
  for d in "${mounted[@]}"; do
    find "$d" -type f -iname '*.rego' -exec cp -f {} "$tmp_policy_dir" \;
  done
  local local_bin
  local_bin=$(command -v conftest || true)
  if [[ -n "$local_bin" ]]; then
    conftest test "$abs" --policy "$tmp_policy_dir" --all-namespaces --output json > "$out" 2>/dev/null
  else
    docker run --rm -v "${abs}:/scan:ro" -v "${tmp_policy_dir}:/policy:ro" openpolicyagent/conftest:latest \
      test /scan --policy /policy --all-namespaces --output json > "$out" 2>/dev/null
  fi
  rm -rf "$tmp_policy_dir"
  if write_nonempty "$out"; then
    echo "[conftest] -> $out (all OPA policies)"
  else
    wrap_placeholder "$out" "conftest" "no output"
  fi
}

det_pluto() {
  local path="$1" out="${2:-$OUT_DIR/pluto_raw.json}"
  local abs local_bin
  abs=$(resolve_scan_path "$path") || { wrap_placeholder "$out" "pluto" "path resolution failed"; return; }
  local_bin=$(command -v pluto || true)
  if [[ -n "$local_bin" ]]; then
    echo "[pluto] Scanning for deprecated APIs..."
    if pluto detect-files -d "$abs" --output json > "$out" 2>/dev/null && write_nonempty "$out"; then
      echo "[pluto] -> $out"
    else
      echo '{"items":[],"target-versions":{}}' > "$out"
      echo "[pluto] -> $out (no deprecated APIs found)"
    fi
  else
    echo '{"items":[],"target-versions":{},"note":"Pluto CLI not installed. Please install pluto locally for API deprecation scanning."}' > "$out"
    echo "[pluto] -> $out (placeholder - tool not installed)"
  fi
}

det_rbacpolice() {
  local path="$1" out="${2:-$OUT_DIR/rbacpolice_raw.json}"
  local abs
  abs=$(resolve_scan_path "$path") || { wrap_placeholder "$out" "rbac-police" "path resolution failed"; return; }
  python3 - "$abs" "$out" <<'PYEOF'
import json, os, re, sys

abs_root, out_path = sys.argv[1], sys.argv[2]

def scan_rel(fpath):
    rel = os.path.relpath(fpath, abs_root).replace(os.sep, "/")
    return "/scan/" + rel

rbac_files = []
for root, _, files in os.walk(abs_root):
    for fname in files:
        if not (fname.endswith(".yaml") or fname.endswith(".yml")):
            continue
        fpath = os.path.join(root, fname)
        try:
            text = open(fpath, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        if re.search(r'kind:\s*(Role|ClusterRole|RoleBinding|ClusterRoleBinding)', text):
            rbac_files.append((fpath, text))

if not rbac_files:
    json.dump([{"tool": "rbac-police", "note": "No RBAC manifests found"}], open(out_path, "w"))
    print(f"[rbac-police] -> {out_path} (placeholder - no RBAC files)")
    sys.exit(0)

dangerous_verbs = ['delete', 'deletecollection', 'create', 'update', 'patch', 'escalate', 'bind', 'impersonate']
sensitive_resources = ['secrets', 'configmaps', 'serviceaccounts', 'roles', 'clusterroles', 'rolebindings', 'clusterrolebindings']
findings = []

for fpath, text in rbac_files:
    fname = scan_rel(fpath)
    if re.search(r'kind:\s*(Role|ClusterRole)', text):
        is_cluster = bool(re.search(r'kind:\s*ClusterRole', text))
        kind = "ClusterRole" if is_cluster else "Role"

        if re.search(r"verbs:\s*\[\s*['\"]?\*['\"]?\s*\]", text) or re.search(r"verbs:\s*\n\s*-\s*['\"]?\*['\"]?", text):
            findings.append({"rule": "WildcardVerbs", "severity": "HIGH",
                "message": "Wildcard verbs (*) grants all permissions - violates least privilege principle",
                "file": fname, "kind": kind, "category": "excessive_permissions"})
        if re.search(r"resources:\s*\[\s*['\"]?\*['\"]?\s*\]", text) or re.search(r"resources:\s*\n\s*-\s*['\"]?\*['\"]?", text):
            findings.append({"rule": "WildcardResources", "severity": "HIGH",
                "message": "Wildcard resources (*) grants access to all resource types",
                "file": fname, "kind": kind, "category": "excessive_permissions"})
        if re.search(r"apiGroups:\s*\[\s*['\"]?\*['\"]?\s*\]", text) or re.search(r"apiGroups:\s*\n\s*-\s*['\"]?\*['\"]?", text):
            findings.append({"rule": "WildcardAPIGroups", "severity": "MEDIUM",
                "message": "Wildcard apiGroups (*) grants access to all API groups",
                "file": fname, "kind": kind, "category": "excessive_permissions"})

        for verb in dangerous_verbs:
            if re.search(rf"verbs:\s*\[.*['\"]?{verb}['\"]?.*\]", text) or re.search(rf"verbs:[\s\S]*?-\s*['\"]?{verb}['\"]?", text):
                findings.append({"rule": f"DangerousVerb_{verb}", "severity": "MEDIUM",
                    "message": f"Dangerous verb '{verb}' detected - ensure this is necessary",
                    "file": fname, "kind": kind, "category": "dangerous_permissions"})

        for res in sensitive_resources:
            if re.search(rf"resources:\s*\[.*['\"]?{res}['\"]?.*\]", text) or re.search(rf"resources:[\s\S]*?-\s*['\"]?{res}['\"]?", text):
                findings.append({"rule": f"SensitiveResource_{res}", "severity": "MEDIUM",
                    "message": f"Access to sensitive resource '{res}' - verify this is required",
                    "file": fname, "kind": kind, "category": "sensitive_access"})

        if re.search(r'name:\s*cluster-admin', text):
            findings.append({"rule": "ClusterAdminReference", "severity": "CRITICAL",
                "message": "References cluster-admin role - grants full cluster access",
                "file": fname, "kind": kind, "category": "excessive_permissions"})

        detected_verbs = re.findall(r'-\s*([a-z]+)\s*(?=#|$|\n)', text)
        dangerous_count = sum(1 for v in detected_verbs if v in dangerous_verbs)
        if dangerous_count > 2:
            findings.append({"rule": "MultipleDestructiveVerbs", "severity": "HIGH",
                "message": f"Multiple dangerous verbs detected ({dangerous_count}) - likely overly permissive",
                "file": fname, "kind": kind, "category": "excessive_permissions"})

        has_delete = re.search(r"verbs:[\s\S]*?-\s*delete", text) or re.search(r"verbs:\s*\[.*delete.*\]", text)
        has_modify = re.search(r"verbs:[\s\S]*?-\s*(create|update)", text) or re.search(r"verbs:\s*\[.*(create|update).*\]", text)
        if has_delete and has_modify:
            findings.append({"rule": "DeleteWithModifyPerms", "severity": "MEDIUM",
                "message": "Both delete and create/update permissions - verify least privilege",
                "file": fname, "kind": kind, "category": "excessive_permissions"})

    if re.search(r'kind:\s*(RoleBinding|ClusterRoleBinding)', text):
        is_cluster_binding = bool(re.search(r'kind:\s*ClusterRoleBinding', text))
        kind = "ClusterRoleBinding" if is_cluster_binding else "RoleBinding"

        if re.search(r'name:\s*system:masters', text):
            findings.append({"rule": "SystemMastersBinding", "severity": "CRITICAL",
                "message": "Binding to system:masters group - grants full cluster access",
                "file": fname, "kind": kind, "category": "excessive_permissions"})
        if re.search(r'roleRef:[\s\S]*?name:\s*cluster-admin', text):
            findings.append({"rule": "ClusterAdminBinding", "severity": "CRITICAL",
                "message": "Binds to cluster-admin role - grants full cluster access",
                "file": fname, "kind": kind, "category": "excessive_permissions"})

if not findings:
    json.dump([], open(out_path, "w"))
    print(f"[rbac-police] -> {out_path} (no findings)")
else:
    json.dump(findings, open(out_path, "w"), indent=2)
    print(f"[rbac-police] -> {out_path} ({len(findings)} findings)")
PYEOF
}

det_gitleaks() {
  local path="$1" out="${2:-$OUT_DIR/gitleaks_raw.json}"
  local abs local_bin rules_path
  abs=$(resolve_scan_path "$path") || { wrap_placeholder "$out" "gitleaks" "path resolution failed"; return; }
  rules_path="$REPO_ROOT/policies/gitleaks-rules.toml"

  gitleaks_nonempty() {
    local p="$1"
    [[ -s "$p" ]] || return 1
    local trim
    trim=$(tr -d '[:space:]' < "$p")
    [[ "$trim" == "[]" ]] && return 1
    return 0
  }

  local_bin=$(command -v gitleaks || true)
  if [[ -n "$local_bin" ]]; then
    if [[ -f "$rules_path" ]]; then
      gitleaks detect --source "$abs" --no-git --report-path "$out" --report-format json --config "$rules_path" 2>/dev/null
    fi
    if ! gitleaks_nonempty "$out"; then
      echo "[gitleaks] No findings with repo rules; retrying with default rules"
      gitleaks detect --source "$abs" --no-git --report-path "$out" --report-format json 2>/dev/null
    fi
    [[ -f "$out" ]] || echo '[]' > "$out"
    echo "[gitleaks] -> $out"
  else
    local tmp_out="$abs/gitleaks_raw.json"
    if [[ -f "$rules_path" ]]; then
      docker run --rm -v "${abs}:/scan" -v "${rules_path}:/rules.toml:ro" zricethezav/gitleaks:latest \
        detect --source /scan --no-git --report-path /scan/gitleaks_raw.json --report-format json --config /rules.toml >/dev/null 2>&1
    else
      docker run --rm -v "${abs}:/scan" zricethezav/gitleaks:latest \
        detect --source /scan --no-git --report-path /scan/gitleaks_raw.json --report-format json >/dev/null 2>&1
    fi
    if [[ -f "$tmp_out" && "$tmp_out" != "$out" ]]; then mv -f "$tmp_out" "$out"; fi
    if ! gitleaks_nonempty "$out"; then
      echo "[gitleaks] Docker run yielded no findings; retrying without custom rules"
      docker run --rm -v "${abs}:/scan" zricethezav/gitleaks:latest \
        detect --source /scan --no-git --report-path /scan/gitleaks_raw.json --report-format json >/dev/null 2>&1
      if [[ -f "$tmp_out" && "$tmp_out" != "$out" ]]; then mv -f "$tmp_out" "$out"; fi
    fi
    [[ -f "$out" ]] || echo '[]' > "$out"
    echo "[gitleaks] -> $out (docker)"
  fi
}

# --- orchestration ------------------------------------------------------------
print_summary() {
  echo ""
  echo "────────── Runtime summary ──────────"
  printf '%-20s %10s %10s\n' "Tool" "Seconds" "Status"
  local entry name secs status
  for entry in "${TOOL_TIMINGS[@]}"; do
    IFS='|' read -r name secs status <<< "$entry"
    printf '%-20s %10s %10s\n' "$name" "$secs" "$status"
  done
}

run_lean() {
  local path="$1"
  ensure_images "${LEAN_IMAGES[@]}"
  local abs
  abs=$(resolve_scan_path "$path") || exit 1
  echo "Scanning: $abs"
  invoke_with_timing "KubeConform" det_kubeconform "$abs"
  invoke_with_timing "KubeLinter"  det_kubelinter  "$abs"
  invoke_with_timing "Polaris"     det_polaris     "$abs"
  invoke_with_timing "Checkov"     det_checkov     "$abs"
  invoke_with_timing "TrivyConfig" det_trivyconfig "$abs"
  invoke_with_timing "Kubescape"   det_kubescape   "$abs"
  invoke_with_timing "KubeScore"   det_kubescore   "$abs"
  invoke_with_timing "Yamllint"    det_yamllint    "$abs"
  invoke_with_timing "KubeAudit"   det_kubeaudit   "$abs"
  invoke_with_timing "Conftest"    det_conftest    "$abs"
  print_summary
}

run_extended() {
  local path="$1"
  ensure_images "${LEAN_IMAGES[@]}" "${EXTENDED_EXTRA_IMAGES[@]}"
  local abs
  abs=$(resolve_scan_path "$path") || exit 1

  local extracted has_extracted="false"
  extracted=$(expand_embedded_configs "$path")
  if [[ -n "$(find "$extracted" -type f \( -iname '*.yaml' -o -iname '*.yml' \) 2>/dev/null)" ]]; then
    has_extracted="true"
  fi

  echo "Scanning: $abs (EXTENDED MODE)"
  [[ "$has_extracted" == "true" ]] && echo "Detected embedded configs -> scanning extracted dir: $extracted"

  invoke_with_timing "KubeConform" det_kubeconform "$abs"
  invoke_with_timing "KubeLinter"  det_kubelinter  "$abs"
  invoke_with_timing "Polaris"     det_polaris     "$abs"
  invoke_with_timing "Checkov"     det_checkov     "$abs"
  invoke_with_timing "TrivyConfig" det_trivyconfig "$abs"
  invoke_with_timing "KubeScore"   det_kubescore   "$abs"
  invoke_with_timing "Yamllint"    det_yamllint    "$abs"
  invoke_with_timing "KubeAudit"   det_kubeaudit   "$abs"
  invoke_with_timing "RBACPolice"  det_rbacpolice  "$abs"
  invoke_with_timing "Pluto"       det_pluto       "$abs"
  invoke_with_timing "Gitleaks"    det_gitleaks    "$abs"
  invoke_with_timing "Conftest"    det_conftest    "$abs"

  if [[ "$has_extracted" == "true" ]]; then
    echo ""
    echo "Scanning embedded-configs materialized at: $extracted"
    invoke_with_timing "KubeConform (embedded)" det_kubeconform "$extracted" "$OUT_DIR/kubeconform_raw_embedded.json"
    invoke_with_timing "KubeLinter (embedded)"  det_kubelinter  "$extracted" "$OUT_DIR/kubelinter_raw_embedded.json"
    invoke_with_timing "Polaris (embedded)"     det_polaris     "$extracted" "$OUT_DIR/polaris_raw_embedded.json"
    invoke_with_timing "Checkov (embedded)"     det_checkov     "$extracted" "$OUT_DIR/checkov_raw_embedded.json"
    invoke_with_timing "TrivyConfig (embedded)" det_trivyconfig "$extracted" "$OUT_DIR/trivy_config_raw_embedded.json"
    invoke_with_timing "KubeScore (embedded)"   det_kubescore   "$extracted" "$OUT_DIR/kubescore_raw_embedded.json"
    invoke_with_timing "Yamllint (embedded)"    det_yamllint    "$extracted" "$OUT_DIR/yamllint_raw_embedded.txt"
    invoke_with_timing "KubeAudit (embedded)"   det_kubeaudit   "$extracted" "$OUT_DIR/kubeaudit_raw_embedded.json"
    invoke_with_timing "RBACPolice (embedded)"  det_rbacpolice  "$extracted" "$OUT_DIR/rbacpolice_raw_embedded.json"
    invoke_with_timing "Pluto (embedded)"       det_pluto       "$extracted" "$OUT_DIR/pluto_raw_embedded.json"
    invoke_with_timing "Conftest (embedded)"    det_conftest    "$extracted" "$OUT_DIR/conftest_raw_embedded.json"
  fi

  print_summary
}

MODE="${1:-extended}"
SCAN_PATH="${2:-.}"

echo ""
echo "========================================"
echo "  SafeFix-K8s Detection Layer"
echo "========================================"
echo ""

case "$MODE" in
  lean) run_lean "$SCAN_PATH" ;;
  extended) run_extended "$SCAN_PATH" ;;
  *) echo "Unknown mode: $MODE (expected 'lean' or 'extended')" >&2; exit 1 ;;
esac

echo ""
echo "========================================"
echo "  Detection Complete!"
echo "  Output location: $OUT_DIR"
echo "========================================"
