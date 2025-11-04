# SafeFix-K8s — parallel multi-LLM fan-out with quorum merge
# Requires: pip install httpx jsonschema

from __future__ import annotations
import os, json, asyncio, hashlib, argparse, time
from pathlib import Path
from typing import Dict, Any, List, Optional
import re
import httpx
from jsonschema import validate, ValidationError

LLM_TIMEOUT_SECONDS = 25
RETRIES             = 2
SMALL_DELAY_SECONDS = 0.20
# Prefer OpenRouter first so we can control exact models, others are fallback
MODELS: List[str]   = ["openrouter", "groq", "gemini", "ollama"]
PROVIDER_PRIORITY: List[str] = ["openrouter", "groq", "gemini", "ollama"]

# Optional single-model override kept for backward compatibility
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "google/gemma-2-9b-it:free")
GROQ_MODEL_SINGLE = os.getenv("GROQ_MODEL", "").strip()
GROQ_MODELS_FALLBACK = (
    [GROQ_MODEL_SINGLE] if GROQ_MODEL_SINGLE else
    ["llama-3.3-70b-versatile", "llama-3.1-70b-versatile", "llama-3.1-8b-instant"]
)
OLLAMA_MODEL     = os.getenv("OLLAMA_MODEL", "llama3.1:8b-instruct")

# Default ordered list of OpenRouter models for this use-case (K8s YAML + JSON discipline)
DEFAULT_OPENROUTER_MODELS: List[str] = [
    "meta-llama/llama-3.3-70b-instruct:free",  # strong instruction following
    "mistralai/mistral-7b-instruct:free",      # light + fast fallback
    "deepseek/deepseek-r1-distill-llama-70b:free",  # reasoning-leaning fallback
    "qwen/qwen3-vl-32b-instruct",             # VLM fallback (not required but allowed)
]

RESPONSE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "classification": {"type": "string", "enum": ["fix", "ignore", "needs_review"]},
        "patch": {"type": "string"},
        "rationale": {"type": "string"},
        # Optional enrichments for better downstream hygiene
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "rule_ids": {"type": "array", "items": {"type": "string"}},
        "edits": {"type": "array", "items": {"type": "string"}},
        "line_hints": {"type": "array", "items": {"type": "integer", "minimum": 1}},
        "notes": {"type": "string"}
    },
    "required": ["classification", "rationale"],
    "additionalProperties": False,
    "allOf": [
        {
            "if": {"properties": {"classification": {"const": "fix"}}},
            "then": {"required": ["patch"]}
        }
    ]
}

def system_prompt() -> str:
    return (
        "You are a Kubernetes security fixer. "
        "Given one finding (file, category, tool hints), decide whether to FIX, IGNORE, "
        "or mark as NEEDS_REVIEW. If you recommend a fix, you MUST include a minimal unified diff patch. "
        "Rules:\n"
        "- Output ONLY a single JSON object matching the provided JSON Schema exactly (no code fences, no prose).\n"
        "- If classification is 'fix', 'patch' MUST be a valid git-style unified diff that modifies exactly ONE file: the provided 'file' path.\n"
        "- The diff must contain '---' and '+++' headers and at least one '@@' hunk. No extra files, no renames, no adds/deletes.\n"
        "- The patch MUST be minimal: only lines necessary for the fix. Preserve unrelated content and formatting.\n"
        "- Ensure the resulting YAML is syntactically valid. If you cannot produce a correct patch, return 'needs_review' and explain why in 'rationale'.\n"
        "- Include optional 'confidence' in [0,1], 'rule_ids' (e.g., CKV_*/KSV*/OPA), 'edits' summary, and 'line_hints' when known.\n"
        "JSON Schema:" + json.dumps(RESPONSE_SCHEMA, separators=(',', ':'))
    )

def load_dotenv_from_file(path: str = ".env") -> None:
    p = Path(path)
    if not p.exists():
        return
    try:
        for raw in p.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            # Don't clobber already-set env vars
            if k and (k not in os.environ or not os.environ.get(k)):
                os.environ[k] = v
    except (OSError, UnicodeDecodeError):
        # best-effort; keep silent to avoid breaking runtime
        return

def make_user_prompt(item: Dict[str, Any]) -> str:
    acceptance = {
        "file_constraint": "Patch must target exactly this path",
        "format": "git-style unified diff (---/+++/@@)",
        "valid_yaml": True,
        "minimal": True,
        "optional_fields": ["confidence (0..1)", "rule_ids", "edits", "line_hints"],
    }
    enriched = dict(item)
    enriched["acceptance"] = acceptance
    return (
        "Analyze and respond with ONLY JSON matching the schema.\n"
        "Apply changes only to the given file path and produce a unified diff if you choose 'fix'.\n"
        "Finding:\n" + json.dumps(enriched, ensure_ascii=False, indent=2)
    )

def _extract_first_json_object(text: str) -> Dict[str, Any]:
    start = -1
    depth = 0
    in_str = False
    esc = False
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif ch == '\\':
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            continue
        if ch == '{':
            if depth == 0:
                start = i
            depth += 1
        elif ch == '}':
            if depth > 0:
                depth -= 1
                if depth == 0 and start != -1:
                    frag = text[start:i+1]
                    return json.loads(frag)
    raise json.JSONDecodeError("No complete JSON object found", text, 0)

def validate_response(model: str, raw_text: str) -> Dict[str, Any]:
    try:
        data = _extract_first_json_object(raw_text)
        validate(instance=data, schema=RESPONSE_SCHEMA)
        return data
    except (json.JSONDecodeError, ValidationError) as e:
        return {"classification": "needs_review",
                "rationale": f"{model} invalid JSON/schema: {str(e)}",
                "patch": ""}

_DIFF_HEADER_RE = re.compile(r"^(--- |\+\+\+ )")
_HUNK_RE = re.compile(r"^@@ -(?P<start1>\d+)(?:,(?P<len1>\d+))? \+(?P<start2>\d+)(?:,(?P<len2>\d+))? @@")

def _is_unified_diff(text: str) -> bool:
    if not text or "@@" not in text: return False
    has_headers = any(line.startswith("--- ") for line in text.splitlines()) and \
                  any(line.startswith("+++ ") for line in text.splitlines())
    return has_headers

def _extract_diff_target(text: str) -> Optional[str]:
    for line in text.splitlines():
        if line.startswith("+++ "):
            path = line[4:].strip()
            if path.startswith("a/") or path.startswith("b/"):
                path = path[2:]
            path = path.split('\t')[0].split(' ')[0]
            return path
    return None

def _apply_unified_diff_to_text(orig_text: str, patch: str) -> Optional[str]:
    lines = orig_text.splitlines(keepends=True)
    new_lines: List[str] = []
    i = 0
    in_hunk = False
    for line in patch.splitlines(keepends=False):
        if line.startswith('@@ '):
            m = _HUNK_RE.match(line)
            if not m:
                return None
            start1 = int(m.group('start1'))
            target_index = start1 - 1
            if target_index < i:
                return None
            new_lines.extend(lines[i:target_index])
            i = target_index
            in_hunk = True
            continue
        if not in_hunk:
            continue
        if not line:
            if i >= len(lines):
                new_lines.append("\n")
            else:
                new_lines.append(lines[i])
                i += 1
            continue
        tag = line[0]
        content = line[1:]
        if tag == ' ':
            if i >= len(lines):
                return None
            if lines[i].rstrip('\n\r') != content:
                return None
            new_lines.append(lines[i])
            i += 1
        elif tag == '-':
            if i >= len(lines):
                return None
            if lines[i].rstrip('\n\r') != content:
                return None
            i += 1
        elif tag == '+':
            nl = '\n' if (len(lines) == 0 or lines[0].endswith('\n')) else ('\r\n' if any(l.endswith('\r\n') for l in lines[:50]) else '\n')
            new_lines.append(content + nl)
        else:
            return None
    new_lines.extend(lines[i:])
    return ''.join(new_lines)

def _yaml_is_valid(text: str) -> bool:
    try:
        import yaml  # type: ignore
    except ImportError:
        return True
    try:
        list(yaml.safe_load_all(text))
        return True
    except yaml.YAMLError:  # type: ignore[attr-defined]
        return False

def _apply_hygiene(text: str, _category: str = "") -> tuple[str, List[str]]:
    """Apply conservative hygiene hardening to K8s YAML while preserving intent.
    Returns (new_text, applied_rule_names). If PyYAML is not available or YAML invalid, returns input unchanged.
    Rules (applied only when fields are missing/unsafe):
      - Flip privileged: true -> false
      - For pod.spec and all (init)containers securityContext:
          * allowPrivilegeEscalation: false (if missing)
          * readOnlyRootFilesystem: true (if missing)
          * runAsNonRoot: true (if missing)
          * capabilities.drop includes ALL (if missing)
    """
    try:
        import yaml  # type: ignore
    except ImportError:
        return text, []

    applied: List[str] = []
    try:
        docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError:  # type: ignore[attr-defined]
        return text, []

    def ensure_sc(sc: dict) -> List[str]:
        local: List[str] = []
        if sc.get("allowPrivilegeEscalation") is None:
            sc["allowPrivilegeEscalation"] = False
            local.append("allowPrivilegeEscalation:false")
        if sc.get("readOnlyRootFilesystem") is None:
            sc["readOnlyRootFilesystem"] = True
            local.append("readOnlyRootFilesystem:true")
        if sc.get("runAsNonRoot") is None:
            sc["runAsNonRoot"] = True
            local.append("runAsNonRoot:true")
        caps = sc.get("capabilities")
        if caps is None:
            caps = {}
            sc["capabilities"] = caps
        drop = caps.get("drop")
        if not isinstance(drop, list):
            drop = [] if drop is None else ([drop] if isinstance(drop, str) else [])
            caps["drop"] = drop
        if "ALL" not in [str(x).upper() for x in drop]:
            drop.append("ALL")
            local.append("capabilities.drop+=ALL")
        return local

    changed = False

    def walk_flip_priv(d: Any) -> None:
        nonlocal changed
        if isinstance(d, dict):
            if d.get("privileged") is True:
                d["privileged"] = False
                applied.append("privileged:false")
                changed = True
            for v in d.values():
                walk_flip_priv(v)
        elif isinstance(d, list):
            for v in d:
                walk_flip_priv(v)

    for doc in docs:
        if not isinstance(doc, dict):
            continue
        # Walk spec
        spec = doc.get("spec")
        # Support workload controllers with template.spec
        if isinstance(spec, dict) and "template" in spec and isinstance(spec.get("template"), dict):
            podspec = spec["template"].get("spec")
        else:
            podspec = spec if isinstance(spec, dict) else None

        # Flip privileged: true at any level
        walk_flip_priv(doc)

        # Pod-level securityContext
        if isinstance(podspec, dict):
            psc = podspec.get("securityContext")
            if psc is None:
                psc = {}
                podspec["securityContext"] = psc
            local = ensure_sc(psc)
            if local:
                applied.extend([f"pod.securityContext:{x}" for x in local])
                changed = True

            for key in ("initContainers", "containers"):
                arr = podspec.get(key)
                if not isinstance(arr, list):
                    continue
                for idx2, c in enumerate(arr):
                    if not isinstance(c, dict):
                        continue
                    sc = c.get("securityContext")
                    if sc is None:
                        sc = {}
                        c["securityContext"] = sc
                    local2 = ensure_sc(sc)
                    if local2:
                        applied.extend([f"{key}[{idx2}].securityContext:{x}" for x in local2])
                        changed = True

    if not changed:
        return text, []

    try:
        new_text = yaml.safe_dump_all(docs, sort_keys=False)
        return new_text, applied
    except yaml.YAMLError:  # type: ignore[attr-defined]
        return text, []

def _semantic_check(category: str, text: str) -> tuple[bool, str | None]:
    """Lightweight category-aware guardrails to avoid obvious unsafe remnants.
    Returns (ok, reason_if_fail).
    """
    cat = (category or "").upper()
    # Generic privilege checks
    if "PRIVILEG" in cat:
        # Reject if any privileged: true remains
        if re.search(r"(?m)^\s*privileged:\s*true\b", text):
            return False, "semantic_violation: privileged:true present"
    if "ESCALATION" in cat or "PRIV_ESC" in cat:
        if re.search(r"(?m)^\s*allowPrivilegeEscalation:\s*true\b", text):
            return False, "semantic_violation: allowPrivilegeEscalation:true present"
    return True, None

def _validate_and_write_patch(file_path: str, patch: str, idx: int, apply_dir: str, validate_mode: str, category: str = "", autofix: bool = False, hygiene: bool = False) -> Dict[str, Any]:
    """Try to apply a unified diff patch to file_path and optionally YAML-validate.
    Returns a dict like {status: pass|fail|skipped, reason: <text>} and writes the patched file into apply_dir/idx/ on success.
    """
    if validate_mode == "none":
        # No validation requested
        return {"status": "skipped", "reason": "validation disabled"}

    if not patch:
        return {"status": "fail", "reason": "empty_patch"}
    if not _is_unified_diff(patch):
        return {"status": "fail", "reason": "not_unified_diff"}

    target = _extract_diff_target(patch) or ""
    norm_target = target.replace("\\", "/")
    norm_file = file_path.replace("\\", "/")
    if not target or not (norm_target.endswith(norm_file) or norm_file.endswith(norm_target)):
        return {"status": "fail", "reason": f"diff_target_mismatch: diff={target} item={file_path}"}

    src = Path(file_path)
    if not src.exists():
        return {"status": "fail", "reason": f"file_not_found: {file_path}"}

    try:
        orig = src.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        return {"status": "fail", "reason": f"read_error: {type(e).__name__}: {e}"}

    new_text = _apply_unified_diff_to_text(orig, patch)
    if new_text is None:
        return {"status": "fail", "reason": "patch_apply_failed"}

    if validate_mode == "yaml" and not _yaml_is_valid(new_text):
        return {"status": "fail", "reason": "yaml_invalid_after_patch"}

    # Category-aware semantic checks to avoid accepting unsafe patches
    ok, why = _semantic_check(category, new_text)
    autofix_status: Optional[str] = None
    if not ok:
        # Try a conservative auto-fix if enabled: flip true -> false for obvious risky flags
        if autofix:
            fixed_text = new_text
            fixed_text = re.sub(r"(?m)^(\s*privileged:\s*)true(\s*(#.*)?)$", r"\1false\2", fixed_text)
            fixed_text = re.sub(r"(?m)^(\s*allowPrivilegeEscalation:\s*)true(\s*(#.*)?)$", r"\1false\2", fixed_text)
            if fixed_text != new_text:
                # Re-validate YAML if requested
                if validate_mode == "yaml" and not _yaml_is_valid(fixed_text):
                    return {"status": "fail", "reason": "yaml_invalid_after_autofix"}
                ok2, why2 = _semantic_check(category, fixed_text)
                if ok2:
                    new_text = fixed_text
                    autofix_status = "applied"
                else:
                    return {"status": "fail", "reason": why2 or why or "semantic_violation"}
            else:
                return {"status": "fail", "reason": why or "semantic_violation"}
        else:
            return {"status": "fail", "reason": why or "semantic_violation"}

    # Optional hygiene pass (after basic semantic checks)
    applied_hygiene: List[str] = []
    if hygiene:
        new_text, applied_hygiene = _apply_hygiene(new_text, category)
        if validate_mode == "yaml" and not _yaml_is_valid(new_text):
            return {"status": "fail", "reason": "yaml_invalid_after_hygiene"}

    # Write to sandbox
    try:
        sandbox = Path(apply_dir) / str(idx)
        dst = sandbox / file_path
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(new_text, encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        return {"status": "fail", "reason": f"write_error: {type(e).__name__}: {e}"}

    res: Dict[str, Any] = {"status": "pass", "reason": "ok", "sandbox_path": str(dst)}
    if autofix_status:
        res["autofix"] = autofix_status
    if applied_hygiene:
        res["hygiene"] = {"applied": applied_hygiene}
    return res

def load_payload() -> List[Dict[str, Any]]:
    candidates = [
        Path("output/llm_payload.json"),
        Path("Detection/output/llm_payload.json"),
        Path("detection/output/llm_payload.json"),
        Path("llm_payload.json"),
    ]
    for p in candidates:
        if p.exists():
            obj = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(obj, list): return obj
            if isinstance(obj, dict) and isinstance(obj.get("items"), list): return obj["items"]
            raise ValueError(f"{p} has unexpected structure. Expected a list or {{'items':[...]}}, got {type(obj)}")
    raise FileNotFoundError("llm_payload.json not found in ., output/, or Detection/detection output/")

def provider_enabled(name: str) -> bool:
    if name == "groq":        return bool(os.getenv("GROQ_API_KEY", ""))
    if name == "openrouter":  return bool(os.getenv("OPENROUTER_API_KEY", ""))
    if name == "gemini":      return bool(os.getenv("GEMINI_API_KEY", ""))
    if name == "ollama":      return True
    return False

async def _post_json(client, url, timeout_seconds: int, **kw) -> httpx.Response:
    return await client.post(url, **kw, timeout=timeout_seconds)

def _err_with_body(prefix: str, e: Exception) -> str:
    if isinstance(e, httpx.HTTPStatusError) and e.response is not None:
        body = e.response.text
        body = body if len(body) < 500 else body[:500] + "…"
        return f"{prefix}: {e} :: {body}"
    return f"{prefix}: {e}"

class ProviderSkipVote(Exception):
    """Internal signal to skip counting a provider's vote (e.g., rate-limited).

    Raised by a provider adapter to indicate the vote should be ignored
    (for example due to rate limiting 429), without counting as failure.
    """

async def call_groq(client: httpx.AsyncClient, prompt: str, timeout_seconds: int) -> str:
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {os.getenv('GROQ_API_KEY','')}"}
    last_err = None
    for model in GROQ_MODELS_FALLBACK:
        body = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt()},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0,
            "response_format": {"type": "json_object"}
        }
        try:
            r = await _post_json(client, url, timeout_seconds, headers=headers, json=body)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
        except (httpx.HTTPError, KeyError, json.JSONDecodeError) as e:
            last_err = _err_with_body(f"groq ({model})", e)
    raise RuntimeError(last_err or "groq unknown error")

async def call_openrouter(client: httpx.AsyncClient, prompt: str, timeout_seconds: int) -> str:
    url = "https://openrouter.ai/api/v1/chat/completions"
    referer = os.getenv("OPENROUTER_SITE_URL", "https://safefixk8s.local")
    app_title = os.getenv("OPENROUTER_APP_TITLE", "SafeFixK8s")
    headers = {
        "Authorization": f"Bearer {os.getenv('OPENROUTER_API_KEY','')}",
        "HTTP-Referer": referer,
        "X-Title": app_title,
    }
    # Allow comma-separated override via env; else use curated defaults
    cfg = os.getenv("OPENROUTER_MODELS", "").strip()
    model_candidates = [m.strip() for m in cfg.split(',') if m.strip()] or DEFAULT_OPENROUTER_MODELS
    # Back-compat single-model override takes precedence if explicitly set
    single = os.getenv("OPENROUTER_MODEL", "").strip()
    if single:
        model_candidates = [single]

    last_err: Optional[str] = None
    last_code: Optional[int] = None
    for model in model_candidates:
        body = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt()},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0,
            "response_format": {"type": "json_object"}
        }
        try:
            r = await _post_json(client, url, timeout_seconds, headers=headers, json=body)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
        except httpx.HTTPStatusError as e:
            code = e.response.status_code if e.response is not None else None
            last_code = code
            # Some models don't support forced JSON; retry without it
            if code in (400, 415, 422):
                try:
                    body.pop("response_format", None)
                    r2 = await _post_json(client, url, timeout_seconds, headers=headers, json=body)
                    r2.raise_for_status()
                    return r2.json()["choices"][0]["message"]["content"]
                except httpx.HTTPError as e2:
                    last_err = _err_with_body(f"openrouter ({model})", e2)
                    continue
            # Rate limit or auth issues: move to next candidate
            if code in (401, 403, 429):
                last_err = _err_with_body(f"openrouter ({model})", e)
                continue
            last_err = _err_with_body(f"openrouter ({model})", e)
            continue
        except httpx.HTTPError as e:
            last_err = _err_with_body(f"openrouter ({model})", e)
            continue
    if last_code == 429:
        # Signal the caller to SKIP counting this vote entirely
        raise ProviderSkipVote(last_err or "openrouter rate limited (429)")
    raise RuntimeError(last_err or "openrouter unknown error")

async def call_gemini(client: httpx.AsyncClient, prompt: str, timeout_seconds: int) -> str:
    key = os.getenv("GEMINI_API_KEY", "").strip()
    prefer = os.getenv("GEMINI_MODEL", "").strip()
    model_candidates = [m for m in [prefer, "gemini-2.5-flash", "gemini-1.5-flash-8b", "gemini-1.5-flash"] if m]
    try:
        from google import genai  # type: ignore
        try:
            from google.genai import errors as genai_errors  # type: ignore
            EXC_GEMINI_SDK = (genai_errors.APIError, genai_errors.ServerError, RuntimeError)  # type: ignore[attr-defined]
        except ImportError:
            EXC_GEMINI_SDK = (RuntimeError,)
        sys_user = system_prompt() + "\n" + prompt
        gclient = genai.Client(api_key=key)
        last_err: Optional[str] = None
        for model in model_candidates:
            try:
                resp = gclient.models.generate_content(model=model, contents=sys_user)
                text = getattr(resp, "text", None)
                if not text:
                    cands = getattr(resp, "candidates", None) or []
                    if cands and hasattr(cands[0], "content"):
                        parts = getattr(cands[0].content, "parts", None) or []
                        if parts and hasattr(parts[0], "text"):
                            text = parts[0].text
                if text:
                    return text
                last_err = "Gemini SDK returned no text"
            except EXC_GEMINI_SDK as e:  # type: ignore[misc]
                last_err = f"{type(e).__name__}: {e}"
                continue
        raise RuntimeError(last_err or "Gemini SDK failed")
    except ImportError:
        pass
    last_err: Optional[str] = None
    for model in model_candidates:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"
        body = {
            "contents": [{"parts": [{"text": system_prompt() + "\n" + prompt}]}],
            "generationConfig": {"temperature": 0}
        }
        try:
            r = await _post_json(client, url, timeout_seconds, json=body)
            r.raise_for_status()
            j = r.json()
            cands = j.get("candidates") or []
            if not cands:
                last_err = f"Gemini empty response: {j}"
                continue
            parts = cands[0].get("content", {}).get("parts") or []
            if not parts or "text" not in parts[0]:
                last_err = f"Gemini no text in parts: {j}"
                continue
            return parts[0]["text"]
        except httpx.HTTPError as e:
            last_err = f"HTTPError: {e}"
            continue
    raise RuntimeError(last_err or "Gemini REST failed")

async def call_ollama(client: httpx.AsyncClient, prompt: str, timeout_seconds: int) -> str:
    url = "http://localhost:11434/api/chat"
    body = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt()},
            {"role": "user", "content": prompt},
        ],
        "stream": False
    }
    r = await _post_json(client, url, timeout_seconds, json=body)
    r.raise_for_status()
    return r.json()["message"]["content"]

ADAPTERS = {
    "groq": call_groq,
    "openrouter": call_openrouter,
    "gemini": call_gemini,
    "ollama": call_ollama,
}

async def ask_one(adapter_name: str, fn, client: httpx.AsyncClient, prompt: str, retries: int, timeout_seconds: int) -> Dict[str, Any]:
    last_err: str | None = None
    for _ in range(retries + 1):
        try:
            txt = await fn(client, prompt, timeout_seconds)
            return validate_response(adapter_name, txt)
        except ProviderSkipVote:
            # Special-case: instruct caller to ignore this provider
            return {"__skip": True}
        except (httpx.HTTPError, RuntimeError, json.JSONDecodeError, KeyError) as e:
            last_err = _err_with_body(adapter_name, e)
            await asyncio.sleep(0.8)
    return {"classification": "needs_review", "rationale": last_err or f"{adapter_name} failed", "patch": ""}

async def ask_all(models: List[str], prompt: str, retries: int, timeout_seconds: int) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    enabled = [m for m in models if (m in ADAPTERS and provider_enabled(m))]
    async with httpx.AsyncClient() as client:
        tasks = [ask_one(m, ADAPTERS[m], client, prompt, retries, timeout_seconds) for m in enabled]
        results = await asyncio.gather(*tasks)
    for m, res in zip(enabled, results):
        # Skip providers that explicitly signaled to be ignored (e.g., 429)
        if isinstance(res, dict) and res.get("__skip") is True:
            continue
        out[m] = res
    return out

def _provider_prio(name: str) -> int:
    return PROVIDER_PRIORITY.index(name) if name in PROVIDER_PRIORITY else 99

def merge_consensus(votes: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    counts: Dict[str, int] = {}
    for v in votes.values():
        k = v.get("classification", "needs_review")
        counts[k] = counts.get(k, 0) + 1

    fix_votes = counts.get("fix", 0)
    final_cls = "fix" if fix_votes >= 2 else (
        "ignore" if counts.get("ignore", 0) > max(fix_votes, counts.get("needs_review", 0)) else
        "needs_review"
    )

    chosen_patch = ""
    chosen_from: Optional[str] = None
    if final_cls == "fix":
        patches = [(m, v.get("patch", ""), float(v.get("confidence", 0.5))) for m, v in votes.items() if v.get("patch")]
        if patches:
            # Prefer higher confidence; tie-break by patch length
            best = max(patches, key=lambda t: (t[2], len(t[1])))
            chosen_from, chosen_patch, _ = best

    summary = "; ".join([f"{m}:{v.get('classification')}" for m, v in votes.items()])
    return {"final_classification": final_cls, "final_patch": chosen_patch, "from_model": chosen_from or "",
            "votes": votes, "vote_summary": summary}

def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0, help="Process only first N items (0=all)")
    ap.add_argument("--models", type=str, default="", help="Comma-separated providers: groq,openrouter,gemini,ollama")
    ap.add_argument("--timeout", type=int, default=0, help="Per-request timeout seconds (0=default)")
    ap.add_argument("--retries", type=int, default=0, help="Retries per model (0=default)")
    ap.add_argument("--selftest", type=str, default="", help="Run a 1-item provider test: groq|openrouter|gemini|ollama")
    ap.add_argument("--validate", type=str, default="none", choices=["none", "yaml"],
                    help="Post-patch validator: none|yaml (apply diff in-memory and YAML-parse)")
    ap.add_argument("--apply-dir", type=str, default="output/patch_sandbox",
                    help="Directory to write patched files for inspection (created if missing)")
    ap.add_argument("--autofix", action="store_true", help="Conservatively flip privileged:true and allowPrivilegeEscalation:true to false if still present after patch")
    ap.add_argument("--hygiene", action="store_true", help="After a patch is accepted, apply conservative hygiene (securityContext hardening) before writing")
    return ap.parse_args()

def _mask(s): 
    return (s[:4]+"…"+s[-4:]) if s and len(s)>=8 else "<missing>"

async def self_test(which: str):
    test_item = {"file":"(selftest)","category":"NO_RES_LIMITS","hints":["cpu/mem not set"],"policy":"least-privilege"}
    prompt = make_user_prompt(test_item)
    print(f"[SelfTest] Keys GROQ={_mask(os.getenv('GROQ_API_KEY',''))} "
          f"OPENROUTER={_mask(os.getenv('OPENROUTER_API_KEY',''))} GEMINI={_mask(os.getenv('GEMINI_API_KEY',''))}")
    async with httpx.AsyncClient() as client:
        txt = await ADAPTERS[which](client, prompt, LLM_TIMEOUT_SECONDS)
        print(f"[SelfTest:{which}] OK -> {txt[:180]}…")

async def main():
    args = parse_args()

    # Load API keys and model preferences from .env early
    load_dotenv_from_file(".env")

    if args.selftest:
        if args.selftest not in ADAPTERS:
            print("Use one of: groq, openrouter, gemini, ollama")
            return
        await self_test(args.selftest); return

    models = [m.strip() for m in args.models.split(",") if m.strip()] if args.models else MODELS
    timeout_seconds = args.timeout if args.timeout else LLM_TIMEOUT_SECONDS
    retries = args.retries if args.retries else RETRIES

    payload = load_payload()
    total = len(payload)
    if args.limit and args.limit > 0:
        payload = payload[:args.limit]

    enabled = [m for m in models if provider_enabled(m)]
    print(f"[SafeFix-LLM] Items: {len(payload)}/{total} | Models: {enabled} "
        f"| timeout={timeout_seconds}s retries={retries}")
    print(f"[Keys] GROQ={_mask(os.getenv('GROQ_API_KEY',''))} "
          f"| OPENROUTER={_mask(os.getenv('OPENROUTER_API_KEY',''))} "
          f"| GEMINI={_mask(os.getenv('GEMINI_API_KEY',''))}")

    t0 = time.time()
    results: List[Dict[str, Any]] = []

    for idx, item in enumerate(payload, start=1):
        if not isinstance(item, dict):
            continue

        prompt = make_user_prompt(item)
        votes = await ask_all(models, prompt, retries, timeout_seconds)
        merged = merge_consensus(votes)

        # Build candidate fix patches from votes and try them in provider priority order.
        file_path = str(item.get("file", "")).strip()
        fix_candidates: List[tuple[str, str, float]] = [
            (m, v.get("patch", ""), float(v.get("confidence", 0.5)))
            for m, v in votes.items() if v.get("classification") == "fix" and v.get("patch")
        ]

        validation = {"status": "skipped", "reason": "validation disabled"}
        chosen_model = None
        chosen_patch = None

        if fix_candidates:
            # Sort by provider priority, then by confidence desc, then patch length desc
            fix_candidates.sort(key=lambda t: (_provider_prio(t[0]), -t[2], -len(t[1])))

            if args.validate == "none":
                # No validation requested; just pick the top-priority patch
                chosen_model, chosen_patch, _ = fix_candidates[0]
                validation = {"status": "skipped", "reason": "validation disabled"}
            else:
                last_reason = None
                for model_name, patch_text, _conf in fix_candidates:
                    vres = _validate_and_write_patch(file_path, patch_text, idx, args.apply_dir, args.validate, str(item.get("category", "")), autofix=args.autofix, hygiene=args.hygiene)
                    if vres.get("status") == "pass":
                        chosen_model, chosen_patch = model_name, patch_text
                        validation = vres
                        break
                    else:
                        last_reason = vres.get("reason")
                if chosen_patch is None:
                    validation = {"status": "fail", "reason": last_reason or "patch_apply_failed_all"}

        # If no patch was accepted but hygiene is requested, try hygiene-only write for this file
        if (chosen_patch is None) and args.hygiene and args.validate != "none" and isinstance(file_path, str) and file_path:
            srcp = Path(file_path)
            if srcp.exists():
                try:
                    orig_text = srcp.read_text(encoding="utf-8")
                    new_text, applied_hyg = _apply_hygiene(orig_text, str(item.get("category", "")))
                    if applied_hyg and (not args.validate == "yaml" or _yaml_is_valid(new_text)):
                        sandbox = Path(args.apply_dir) / str(idx)
                        dst = sandbox / file_path
                        dst.parent.mkdir(parents=True, exist_ok=True)
                        dst.write_text(new_text, encoding="utf-8")
                        validation = {"status": "pass", "reason": "hygiene_only", "sandbox_path": str(dst), "hygiene": {"applied": applied_hyg}}
                except (OSError, UnicodeDecodeError):
                    # ignore hygiene-only attempt errors; keep original validation
                    pass

        # Update merged result based on validation outcome
        if chosen_patch is not None and validation.get("status") == "pass":
            merged["final_classification"] = "fix"
            merged["final_patch"] = chosen_patch
            merged["from_model"] = chosen_model or merged.get("from_model") or ""
            if chosen_model and chosen_model in votes:
                try:
                    merged["confidence"] = float(votes[chosen_model].get("confidence", 0.5))
                except (TypeError, ValueError):
                    merged["confidence"] = 0.5
        elif merged.get("final_classification") == "fix" and validation.get("status") == "fail":
            merged["final_classification"] = "needs_review"
            merged["final_patch"] = ""

        short_id = hashlib.sha1(json.dumps(item, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:12]
        results.append({
            "id": short_id,
            "file": item.get("file"),
            "category": item.get("category"),
            "consensus": merged,
            "validation": validation,
        })

        print(f"  • processed {idx}/{len(payload)} (elapsed {time.time()-t0:.1f}s)")
        await asyncio.sleep(SMALL_DELAY_SECONDS)

    Path("output").mkdir(exist_ok=True)
    out_path = Path("output/llm_decisions.json")
    out_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[SafeFix-LLM] Wrote {out_path} | total elapsed {time.time()-t0:.1f}s")

if __name__ == "__main__":
    asyncio.run(main())
