#!/usr/bin/env python3
"""
multi_llm_orchestrator.py  — resilient raw-mode

- Accepts classic SafeFix payloads ({"files":[...]}) AND raw tool payloads ({"version": "...", "items":[...]}).
- Adds YAML context (snippet + derived hints) to prompts so LLMs can output valid RFC-6902 ops.
- Robustly extracts JSON arrays from messy LLM outputs.
- Provides a deterministic local fallback for common schema categories when providers return nothing.
- Writes SECURED_*, DIFF_*, REPORT_*.json, REPORT_ALL.csv (with provider errors).

Env / flags: same as before.
"""

import argparse, json, os, re, difflib, time, random
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import requests
import yaml

# ---------------------- Simple .env loader ----------------------
def load_dotenv_from_root() -> None:
    here = Path.cwd()
    candidates = [here / ".env", here.parent / ".env", Path(__file__).resolve().parent.parent / ".env"]
    for p in candidates:
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line: continue
                k, v = line.split("=", 1)
                k = k.strip(); v = v.strip().strip('"').strip("'")
                if k and (k not in os.environ):
                    os.environ[k] = v
            break

load_dotenv_from_root()

# ------------------------- Helpers ------------------------------
def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))

def read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="ignore")

def write_text(p: Path, s: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(s, encoding="utf-8")

def yaml_load_all(s: str) -> List[Any]:
    try:
        docs = list(yaml.safe_load_all(s))
        return [d for d in docs if d is not None]
    except yaml.YAMLError:
        return []

def yaml_dump_all(docs: List[Any]) -> str:
    return yaml.safe_dump_all(docs, sort_keys=False, default_flow_style=False)

def unified_diff_text(original: str, fixed: str, orig_path: str, fixed_path: str) -> str:
    a = original.splitlines(keepends=True)
    b = fixed.splitlines(keepends=True)
    return "".join(difflib.unified_diff(a, b, fromfile=orig_path, tofile=fixed_path, lineterm="", n=3))

def get_pod_spec(workload: Dict) -> Optional[Dict]:
    if not isinstance(workload, dict): return None
    spec = workload.get("spec")
    if not isinstance(spec, dict): return None
    if str(workload.get("kind") or "") == "Pod": return spec
    tmpl = spec.get("template")
    if isinstance(tmpl, dict) and isinstance(tmpl.get("spec"), dict): return tmpl["spec"]
    return None

# -------------------- JSON Pointer helpers ----------------------
def _pointer_walk(doc: Any, pointer: str, create_missing: bool=False):
    if pointer == "" or pointer == "/":
        return None, None
    parts = [p for p in pointer.split("/") if p != ""]
    cur = doc
    for part in parts[:-1]:
        key = part.replace("~1","/").replace("~0","~")
        if isinstance(cur, list):
            idx = int(key)
            if idx >= len(cur):
                if create_missing:
                    while len(cur) <= idx: cur.append({})
                else:
                    raise KeyError(pointer)
            cur = cur[idx]
        else:
            if key not in cur:
                if create_missing:
                    cur[key] = {}
                else:
                    raise KeyError(pointer)
            cur = cur[key]
    last = parts[-1].replace("~1","/").replace("~0","~")
    return cur, last

def apply_json_patch(doc: Any, patch_ops: List[Dict[str,Any]]) -> Any:
    for op in patch_ops:
        op_type = op.get("op")
        path = op.get("path")
        if not isinstance(op_type, str) or not isinstance(path, str):
            continue
        parent, key = _pointer_walk(doc, path, create_missing=(op_type=="add"))
        if parent is None:
            if op_type in ("add", "replace"): doc = op.get("value")
            elif op_type == "remove": doc = None
            continue
        if isinstance(parent, list):
            idx = int(key)
            if op_type == "add":
                val = op.get("value")
                if idx == len(parent): parent.append(val)
                elif 0 <= idx < len(parent): parent.insert(idx, val)
            elif op_type == "replace":
                parent[idx] = op.get("value")
            elif op_type == "remove":
                if 0 <= idx < len(parent): parent.pop(idx)
        else:
            if op_type in ("add","replace"):
                parent[key] = op.get("value")
            elif op_type == "remove":
                if key in parent: del parent[key]
    return doc

# ------------------ Providers & Prompting -----------------------
SYSTEM_PROMPT = (
    "You are SafeFix, a Kubernetes YAML repair assistant. "
    "Only output a STRICT JSON array of RFC-6902 patch objects. "
    "Each object must include: op, path, value (for add/replace). "
    "Never wrap in markdown fences; no prose."
)

USER_PROMPT_TEMPLATE = """\
Context:
{context}

Target file (relative): {file}
YAML snippet (truncated):
---
{yaml_snippet}
---

Derived hints:
{derived_hints}

Categories to fix in THIS file only:
{categories}

Rules:
- Keep behavior unchanged except for the fixes listed.
- Make minimal, surgical changes; do NOT touch unrelated fields.
- If image not pinned, only set imagePullPolicy: IfNotPresent (never invent digests).
- If hostPath mount, remove or replace with emptyDir if safe.
- For RBAC wildcards, narrow verbs to ['get','list'] and resources to the minimal safe baseline.
- JSON array only; no markdown; no comments.

Special guidance (based on categories):
{special_guidance}

Return ONLY a JSON array with RFC-6902 ops.
"""

def derive_special_guidance(categories: List[str]) -> str:
    cats = set([c for c in categories if c])
    g: List[str] = []
    if "MISSING_KIND" in cats or "SCHEMA_VALIDATION_ERROR" in cats:
        g += [
            "- Ensure required top-level keys exist: apiVersion, kind, metadata.name.",
            "- Choose apiVersion/kind consistent with the present fields; never change existing names.",
        ]
    if "MISSING_SELECTOR" in cats:
        g += [
            "- For Deployment: add spec.selector.matchLabels that EXACTLY equals spec.template.metadata.labels.",
            "- Do not modify replicas, image, or other fields.",
        ]
    return "\n".join(g) if g else "- None."

def derive_hints_from_yaml(docs: List[Dict[str,Any]]) -> str:
    if not docs: return "- Could not parse YAML."
    d = docs[0]
    hints = []
    kind = d.get("kind","")
    if kind: hints.append(f"- kind: {kind}")
    apiv = d.get("apiVersion","")
    if apiv: hints.append(f"- apiVersion: {apiv}")
    name = ((d.get("metadata") or {}).get("name")) or ""
    if name: hints.append(f"- metadata.name: {name}")
    if (d.get("spec") or {}).get("template"):
        hints.append("- Looks like a controller with spec.template (e.g., Deployment).")
        tmpl = (d.get("spec") or {}).get("template") or {}
        tlabels = ((tmpl.get("metadata") or {}).get("labels") or {})
        if tlabels:
            hints.append(f"- template.labels keys: {', '.join(sorted(tlabels.keys()))}")
    rules = (d.get("rules") or [])
    if rules: hints.append(f"- Has RBAC rules (Role/ClusterRole), rules count={len(rules)}.")
    return "\n".join(hints) if hints else "- No obvious structure."

def first_yaml_snippet(text: str, max_chars: int = 1500) -> str:
    if not text: return "(empty file or unreadable)"
    s = text.strip()
    return s[:max_chars]

# ---------- Robust HTTP (retry/backoff + tolerant JSON parsing) ----------
def _extract_retry_secs_from_text(text: str) -> Optional[float]:
    m = re.search(r"try again in\s+([0-9]+(?:\.[0-9]+)?)s", text or "", re.IGNORECASE)
    if m:
        try: return float(m.group(1))
        except: return None
    return None

def _post_json(url: str, headers: Dict[str,str], payload: Dict[str,Any], *, provider: Optional[str]=None, max_retries: int=6) -> Tuple[Optional[dict], Optional[str]]:
    session = requests.Session()
    attempt = 0
    lowered_tokens_once = False
    last_err = None

    while True:
        attempt += 1
        try:
            r = session.post(url, headers=headers, json=payload, timeout=90)
            status = r.status_code
            if 200 <= status < 300:
                return r.json(), None

            if status == 402 and provider == "openrouter":
                if not lowered_tokens_once:
                    lowered_tokens_once = True
                    if isinstance(payload, dict) and "max_tokens" in payload:
                        payload["max_tokens"] = max(256, int(payload.get("max_tokens", 512) // 2))
                    else:
                        payload["max_tokens"] = 256
                    continue
                last_err = f"{status} OpenRouter credit/limit"
                return None, last_err

            if status == 429:
                wait = _extract_retry_secs_from_text(r.text) or (min(2**attempt, 30) + random.uniform(0, 0.5))
                time.sleep(wait)
            elif 500 <= status < 600:
                wait = min(2**attempt, 30) + random.uniform(0, 0.5)
                time.sleep(wait)
            else:
                last_err = f"{status} {r.text[:200]}"
                return None, last_err

        except requests.RequestException as e:
            last_err = f"network {e}"
            wait = min(2**attempt, 30) + random.uniform(0, 0.5)
            time.sleep(wait)

        if attempt >= max_retries:
            return None, last_err or "retries exhausted"

def _extract_json_array(text: str) -> Optional[List[dict]]:
    """
    Be tolerant to models returning prose or code fences. Find the first [...] array and parse it.
    """
    if not text: return None
    # Strip markdown fences if present
    text = text.strip()
    text = re.sub(r"^```(?:json)?", "", text).strip()
    text = re.sub(r"```$", "", text).strip()
    # Try direct parse
    try:
        obj = json.loads(text)
        if isinstance(obj, list): return obj
    except Exception:
        pass
    # Fallback: find first array
    m = re.search(r"\[.*\]", text, flags=re.S)
    if not m: return None
    frag = m.group(0)
    try:
        arr = json.loads(frag)
        return arr if isinstance(arr, list) else None
    except Exception:
        return None

# ---------------- Provider calls ----------------
def call_openrouter(model: str, prompt: str) -> Tuple[Optional[List[dict]], Optional[str]]:
    key = os.environ.get("OPENROUTER_API_KEY")
    if not key or not model: return None, "missing key or model"
    url = "https://openrouter.ai/api/v1/chat/completions"
    body = {"model": model,
            "messages":[{"role":"system","content":SYSTEM_PROMPT},
                        {"role":"user","content":prompt}],
            "temperature": 0.1, "max_tokens": 640}
    headers = {"Authorization": f"Bearer {key}", "Content-Type":"application/json",
               "User-Agent": "SafeFix-K8s/1.0", "HTTP-Referer": "https://safefix.local"}
    js, err = _post_json(url, headers, body, provider="openrouter")
    if not js: return None, err or "no json"
    try:
        txt = js["choices"][0]["message"]["content"].strip()
        ops = _extract_json_array(txt)
        return ops, None if ops is not None else "parse-failed"
    except Exception as e:
        return None, f"extract-error {e}"

def call_groq(model: str, prompt: str) -> Tuple[Optional[List[dict]], Optional[str]]:
    key = os.environ.get("GROQ_API_KEY")
    if not key or not model: return None, "missing key or model"
    url = "https://api.groq.com/openai/v1/chat/completions"
    body = {"model": model,
            "messages":[{"role":"system","content":SYSTEM_PROMPT},
                        {"role":"user","content":prompt}],
            "temperature": 0.1, "max_tokens": 1024}
    js, err = _post_json(url, {"Authorization": f"Bearer {key}", "Content-Type":"application/json"}, body, provider="groq")
    if not js: return None, err or "no json"
    try:
        txt = js["choices"][0]["message"]["content"].strip()
        ops = _extract_json_array(txt)
        return ops, None if ops is not None else "parse-failed"
    except Exception as e:
        return None, f"extract-error {e}"

def call_gemini(model: str, prompt: str) -> Tuple[Optional[List[dict]], Optional[str]]:
    key = os.environ.get("GEMINI_API_KEY")
    if not key or not model: return None, "missing key or model"
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
    body = {"contents":[{"parts":[{"text": SYSTEM_PROMPT + "\n\n" + prompt}]}],
            "generationConfig":{"temperature":0.1}}
    js_err = None
    try:
        r = requests.post(url, json=body, timeout=90)
        if 200 <= r.status_code < 300:
            js = r.json()
            txt = js["candidates"][0]["content"]["parts"][0]["text"].strip()
            ops = _extract_json_array(txt)
            return ops, None if ops is not None else "parse-failed"
        js_err = f"{r.status_code} {r.text[:160]}"
    except Exception as e:
        js_err = f"network {e}"
    return None, js_err

def call_ollama(model: str, prompt: str) -> Tuple[Optional[List[dict]], Optional[str]]:
    base = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
    if not model or not base: return None, "missing base or model"
    url = f"{base.rstrip('/')}/api/chat"
    body = {"model": model, "messages":[{"role":"system","content":SYSTEM_PROMPT},
                                        {"role":"user","content":prompt}], "stream": False}
    try:
        r = requests.post(url, json=body, timeout=90)
        if 200 <= r.status_code < 300:
            js = r.json()
            txt = js.get("message",{}).get("content","").strip()
            ops = _extract_json_array(txt)
            if ops is not None: return ops, None
    except Exception as e:
        pass
    # fallback endpoint
    try:
        url2 = f"{base.rstrip('/')}/api/generate"
        r2 = requests.post(url2, json={"model":model,"prompt":SYSTEM_PROMPT+"\n\n"+prompt,"stream":False}, timeout=90)
        if 200 <= r2.status_code < 300:
            js2 = r2.json()
            txt2 = js2.get("response","").strip()
            ops = _extract_json_array(txt2)
            return ops, None if ops is not None else "parse-failed"
        return None, f"{r2.status_code} {r2.text[:160]}"
    except Exception as e:
        return None, f"network {e}"

# ------------------ Voting & Application ------------------------
def sanitize_ops(ops: Any) -> List[Dict[str,Any]]:
    out: List[Dict[str,Any]] = []
    if not isinstance(ops, list): return out
    for o in ops:
        if not isinstance(o, dict): continue
        op = o.get("op"); path = o.get("path")
        if not isinstance(op, str) or not isinstance(path, str): continue
        if op not in ("add","replace","remove"): continue
        if op in ("add","replace") and "value" not in o: continue
        out.append({"op":op,"path":path,"value":o.get("value")})
    return out

def vote_merge(provider_ops: List[Tuple[str, List[Dict[str,Any]]]]) -> List[Dict[str,Any]]:
    priority = ["openrouter","groq","gemini","ollama"]
    seen: Dict[str, Dict[str,Any]] = {}
    counts: Dict[str, int] = {}
    first_provider: Dict[str, str] = {}
    for provider, ops in provider_ops:
        for op in ops:
            key = json.dumps(op, sort_keys=True)
            counts[key] = counts.get(key, 0) + 1
            if key not in first_provider:
                first_provider[key] = provider
            if key not in seen:
                seen[key] = op
    if not counts: return []
    max_votes = max(counts.values())
    winners = [k for k,v in counts.items() if v == max_votes]
    winners.sort(key=lambda k: priority.index(first_provider.get(k,"ollama")) if first_provider.get(k,"ollama") in priority else 99)
    return [seen[k] for k in winners]

# --------- Local deterministic fallback for common raw categories ----------
def _fallback_ops_for_missing_selector(doc: Dict[str,Any]) -> List[Dict[str,Any]]:
    if not isinstance(doc, dict): return []
    if (doc.get("kind") != "Deployment") or not isinstance(doc.get("spec"), dict): return []
    tmpl = (doc["spec"].get("template") or {})
    tmeta = (tmpl.get("metadata") or {})
    tlabels = (tmeta.get("labels") or {})
    if not tlabels: return []
    return [
        {"op":"add","path":"/spec/selector","value":{"matchLabels": tlabels}}
    ]

def local_fallback_ops(categories: List[str], docs: List[Dict[str,Any]]) -> List[Dict[str,Any]]:
    ops: List[Dict[str,Any]] = []
    cats = set([c for c in categories if c])
    if not docs: return ops
    d0 = docs[0]
    if "MISSING_SELECTOR" in cats:
        ops += _fallback_ops_for_missing_selector(d0)
    # (We intentionally avoid guessing kind/apiVersion; too risky without provider agreement)
    return ops

# ---------------- Payload normalizer ----------------
def normalize_payload_to_files(payload: Dict[str,Any]) -> Tuple[Dict[str,Any], List[Dict[str,Any]]]:
    context = payload.get("context") or {}
    meta = payload.get("metadata") or {}
    if not context:
        context = {
            "source_tool": meta.get("source_tool") or payload.get("version") or "unknown",
            "generated_at": payload.get("generated_at") or "",
            "raw_findings_count": meta.get("raw_findings_count") or 0,
            "note": "Auto-derived context from raw payload."
        }
    files = payload.get("files")
    if isinstance(files, list) and files:
        return context, files
    items = payload.get("items") or []
    if not isinstance(items, list) or not items:
        return context, []
    by_file: Dict[str, List[Dict[str,Any]]] = {}
    for it in items:
        file_rel = it.get("file") or it.get("filename") or "UNKNOWN_FILE"
        finding = {
            "category": it.get("category") or it.get("rule") or "UNKNOWN",
            "severity": it.get("severity"),
            "message": it.get("message") or it.get("description"),
            "resourceRef": {"kind": it.get("kind",""), "name": it.get("name",""), "namespace": it.get("namespace","") or "default"},
            "raw": {"tools": it.get("tools"), "rule_ids": it.get("rule_ids"), "examples": it.get("examples"), "line": it.get("line")}
        }
        by_file.setdefault(file_rel, []).append(finding)
    files_list = [{"file": f, "findings": v} for f, v in sorted(by_file.items())]
    return context, files_list

# ---------------- Prompt builder (now includes YAML context) ----------------
def build_prompt(context: Dict[str,Any], file_entry: Dict[str,Any], original_text: str) -> str:
    file_rel = file_entry.get("file","")
    findings = file_entry.get("findings") or []
    if findings:
        rr = findings[0].get("resourceRef") or {}
        kind = rr.get("kind",""); name = rr.get("name",""); ns = rr.get("namespace","") or "default"
    else:
        kind = name = ""; ns = "default"
    cats = sorted(set(f["category"] for f in findings if f.get("category")))
    categories = "- " + "\n- ".join(cats) if cats else "- "
    docs = yaml_load_all(original_text)
    snippet = first_yaml_snippet(original_text)
    hints = derive_hints_from_yaml(docs)
    special = derive_special_guidance(cats)
    return USER_PROMPT_TEMPLATE.format(
        context=json.dumps(context, ensure_ascii=False, indent=2),
        file=file_rel,
        yaml_snippet=snippet,
        derived_hints=hints,
        categories=categories,
        special_guidance=special,
        kind=kind, name=name, namespace=ns
    )

# ------------------------------ Main -----------------------------
def main():
    ap = argparse.ArgumentParser(description="Vote across multiple LLMs to fix payload categories and write secured YAMLs.")
    ap.add_argument("--payload", required=True, help="Path to output_llm_payload.json OR raw tool payload (e.g., raw-kubeconform).")
    ap.add_argument("--tests-dir", required=True, help="Directory containing original YAML files (as referenced in payload)")
    ap.add_argument("--out-dir", default="output/llm_fixes", help="Output directory")
    ap.add_argument("--or-model", default=os.environ.get("OPENROUTER_MODEL","openai/gpt-4o-mini"))
    ap.add_argument("--groq-model", default=os.environ.get("GROQ_MODEL","llama-3.1-8b-instant"))
    ap.add_argument("--gemini-model", default=os.environ.get("GEMINI_MODEL","gemini-2.5-flash"))
    ap.add_argument("--ollama-model", default=os.environ.get("OLLAMA_MODEL","meta-llama/llama-3-8b"))
    args = ap.parse_args()

    payload = read_json(Path(args.payload))
    context, files = normalize_payload_to_files(payload)

    tests_dir = Path(args.tests_dir).resolve()
    out_dir   = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    rows: List[Tuple[str,str,str,int,int]] = []  # file, provider, status, applied, skipped

    for f in files:
        file_rel = f.get("file")
        findings = f.get("findings") or []
        if not file_rel or not findings:
            continue

        file_path = tests_dir / file_rel
        original = read_text(file_path) if file_path.exists() else ""
        prompt = build_prompt(context, f, original)

        provider_ops: List[Tuple[str,List[Dict[str,Any]]]] = []
        provider_errs: Dict[str,str] = {}

        # space calls slightly (helps with bursty 429s)
        if os.environ.get("OPENROUTER_API_KEY"):
            ops, err = call_openrouter(args.or_model, prompt); time.sleep(1.1)
            provider_ops.append(("openrouter", sanitize_ops(ops or [])))
            if err: provider_errs["openrouter"] = err
        if os.environ.get("GROQ_API_KEY"):
            ops, err = call_groq(args.groq_model, prompt); time.sleep(1.1)
            provider_ops.append(("groq", sanitize_ops(ops or [])))
            if err: provider_errs["groq"] = err
        if os.environ.get("GEMINI_API_KEY"):
            ops, err = call_gemini(args.gemini_model, prompt); time.sleep(1.1)
            provider_ops.append(("gemini", sanitize_ops(ops or [])))
            if err: provider_errs["gemini"] = err
        if os.environ.get("OLLAMA_BASE_URL"):
            ops, err = call_ollama(args.ollama_model, prompt); time.sleep(1.1)
            provider_ops.append(("ollama", sanitize_ops(ops or [])))
            if err: provider_errs["ollama"] = err

        have_any = any(len(ops)>0 for _,ops in provider_ops)
        merged: List[Dict[str,Any]] = []

        if have_any:
            merged = vote_merge(provider_ops)
        else:
            # local deterministic fallback for a few raw categories
            cats = sorted(set(ff.get("category") for ff in findings if ff.get("category")))
            merged = local_fallback_ops(cats, yaml_load_all(original))

        applied: List[Dict[str,Any]] = []
        skipped: List[Dict[str,Any]] = []
        fixed = ""

        if merged:
            # apply
            docs = yaml_load_all(original) if original else []
            if docs:
                # assign to likely target doc (first workload / podspec)
                def target_doc_index(path: str) -> int:
                    if re.search(r"/(spec|template)/", path):
                        for i, d in enumerate(docs):
                            if get_pod_spec(d): return i
                    return 0
                for op in merged:
                    try:
                        idx = target_doc_index(op.get("path",""))
                        docs[idx] = apply_json_patch(docs[idx], [op])
                        applied.append(op)
                    except Exception as e:
                        skipped.append({"op": op, "reason": f"apply error: {e}"})
                fixed = yaml_dump_all(docs)
            else:
                # could not parse original; skip applying but still report ops
                skipped = [{"op": op, "reason": "original YAML not parseable"} for op in merged]

        safe = file_rel.replace("\\","_").replace("/","_").replace("..","")
        secured_path = out_dir / f"SECURED_{safe}"
        diff_path    = out_dir / f"DIFF_{safe}.diff"
        report_path  = out_dir / f"REPORT_{safe}.json"

        if fixed:
            write_text(secured_path, fixed)
            write_text(diff_path, unified_diff_text(original, fixed, str(Path(args.tests_dir)/file_rel), str(secured_path)))

        rows.extend([(file_rel, prov, "ok" if ops else "empty", len(ops), 0) for prov, ops in provider_ops])

        reason = None
        if not have_any and not merged:
            reason = "No provider produced valid JSON Patch ops (and no local fallback applicable)."
        elif not have_any and merged:
            reason = "Providers empty; used local deterministic fallback."

        cats = sorted(set(ff.get("category") for ff in findings if ff.get("category")))
        summary = {
            "file": file_rel,
            "categories_fixed": cats,
            "providers": [{ "name": n, "ops": ops } for n,ops in provider_ops],
            "provider_errors": provider_errs,
            "applied_ops_count": len(applied),
            "skipped_ops_count": len(skipped),
            "reason": reason,
            "notes": [
                "Prompt included YAML snippet and derived hints to increase JSON compliance.",
                "Ties resolved by provider priority: openrouter > groq > gemini > ollama.",
                "Local fallback currently covers MISSING_SELECTOR (Deployment)."
            ]
        }
        write_text(report_path, json.dumps(summary, indent=2))

    csv_lines = ["file,provider,status,ops_applied,ops_skipped"]
    for file_rel, prov, status, a, s in rows:
        csv_lines.append(",".join([file_rel.replace(",",";"), prov, status, str(a), str(s)]))
    write_text(out_dir / "REPORT_ALL.csv", "\n".join(csv_lines))

    print(f"[OK] Wrote secured files, diffs and reports to: {out_dir}")

# ---------------- Raw single-file runner (still available) ----------------
def run_llm_on_raw_file(raw_path: Path, tests_dir: Path, out_dir: Path):
    raw = read_json(raw_path)
    context, files = normalize_payload_to_files(raw)
    out_dir = Path(out_dir).resolve(); out_dir.mkdir(parents=True, exist_ok=True)
    for idx, fe in enumerate(files):
        file_rel = fe.get("file") or f"RAW_{idx}.yaml"
        file_path = Path(tests_dir)/file_rel
        original = read_text(file_path) if file_path.exists() else ""
        prompt = build_prompt(context, {"file": file_rel, "findings": fe.get("findings") or []}, original)

        provider_ops: List[Tuple[str, List[Dict[str,Any]]]] = []
        if os.environ.get("OPENROUTER_API_KEY"):
            ops, _ = call_openrouter(os.environ.get("OPENROUTER_MODEL","openai/gpt-4o-mini"), prompt); time.sleep(1.1)
            provider_ops.append(("openrouter", sanitize_ops(ops or [])))
        if os.environ.get("GROQ_API_KEY"):
            ops, _ = call_groq(os.environ.get("GROQ_MODEL","llama-3.1-8b-instant"), prompt); time.sleep(1.1)
            provider_ops.append(("groq", sanitize_ops(ops or [])))
        if os.environ.get("GEMINI_API_KEY"):
            ops, _ = call_gemini(os.environ.get("GEMINI_MODEL","gemini-2.5-flash"), prompt); time.sleep(1.1)
            provider_ops.append(("gemini", sanitize_ops(ops or [])))
        if os.environ.get("OLLAMA_BASE_URL"):
            ops, _ = call_ollama(os.environ.get("OLLAMA_MODEL","meta-llama/llama-3-8b"), prompt); time.sleep(1.1)
            provider_ops.append(("ollama", sanitize_ops(ops or [])))

        merged = vote_merge(provider_ops) if any(len(ops)>0 for _,ops in provider_ops) else local_fallback_ops(
            sorted(set(ff.get("category") for ff in (fe.get("findings") or []) if ff.get("category"))),
            yaml_load_all(original)
        )

        applied, skipped = [], []
        docs = yaml_load_all(original) if original else []
        if docs and merged:
            def target_doc_index(path: str) -> int:
                if re.search(r"/(spec|template)/", path):
                    for i, d in enumerate(docs):
                        if get_pod_spec(d): return i
                return 0
            for op in merged:
                try:
                    idx = target_doc_index(op.get("path",""))
                    docs[idx] = apply_json_patch(docs[idx], [op])
                    applied.append(op)
                except Exception as e:
                    skipped.append({"op": op, "reason": f"apply error: {e}"})
        fixed = yaml_dump_all(docs) if docs else ""

        sanitized_file = file_rel.replace("\\", "_").replace("/", "_").replace("..", "")
        safe = f"RAW_{idx}_{sanitized_file}"
        secured_path = out_dir / f"SECURED_{safe}"
        diff_path    = out_dir / f"DIFF_{safe}.diff"
        report_path  = out_dir / f"REPORT_{safe}.json"
        if fixed:
            write_text(secured_path, fixed)
            write_text(diff_path, unified_diff_text(original, fixed, str(file_path), str(secured_path)))
        write_text(report_path, json.dumps({
            "file": file_rel,
            "categories_fixed": sorted(set(ff.get("category") for ff in (fe.get("findings") or []) if ff.get("category"))),
            "providers": [{ "name": n, "ops": ops } for n,ops in provider_ops],
            "applied_ops_count": len(applied),
            "skipped_ops_count": len(skipped),
            "notes": ["Processed via raw runner with YAML context and tolerant JSON extraction."]
        }, indent=2))

if __name__ == "__main__":
    main()
