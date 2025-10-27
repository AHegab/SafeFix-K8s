# SafeFix-K8s — parallel multi-LLM fan-out with quorum merge
# Requires: pip install httpx jsonschema

from __future__ import annotations
import os, json, asyncio, hashlib, argparse, time
from pathlib import Path
from typing import Dict, Any, List, Optional
import re
import httpx
from jsonschema import validate, ValidationError

# =========================
# Config knobs (edit here)
# =========================
LLM_TIMEOUT_SECONDS = 25
RETRIES             = 2
SMALL_DELAY_SECONDS = 0.20
MODELS: List[str]   = ["groq", "openrouter", "gemini", "ollama"]

# Provider model choices (you can override via env)
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "google/gemma-2-9b-it:free")

# Try these Groq models in order until one works for your account
# You can override with GROQ_MODEL to force a single model.
GROQ_MODEL_SINGLE = os.getenv("GROQ_MODEL", "").strip()
GROQ_MODELS_FALLBACK = (
    [GROQ_MODEL_SINGLE] if GROQ_MODEL_SINGLE else
    ["llama-3.1-70b-versatile", "llama-3.1-8b-instant", "gemma2-9b-it"]
)

OLLAMA_MODEL     = os.getenv("OLLAMA_MODEL", "llama3.1:8b-instruct")

# =========================
# Response schema (strict)
# =========================
RESPONSE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "classification": {"type": "string", "enum": ["fix", "ignore", "needs_review"]},
        "patch": {"type": "string"},
        "rationale": {"type": "string"},
    },
    "required": ["classification", "rationale"],
    "additionalProperties": False,
    # Require a patch when the model votes to fix
    "allOf": [
        {
            "if": {"properties": {"classification": {"const": "fix"}}},
            "then": {"required": ["patch"]}
        }
    ]
}

# =========================
# Prompt helpers
# =========================
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
        "JSON Schema:" + json.dumps(RESPONSE_SCHEMA, separators=(',', ':'))
    )

def make_user_prompt(item: Dict[str, Any]) -> str:
    acceptance = {
        "file_constraint": "Patch must target exactly this path",
        "format": "git-style unified diff (---/+++/@@)",
        "valid_yaml": True,
        "minimal": True,
    }
    enriched = dict(item)
    enriched["acceptance"] = acceptance
    return (
        "Analyze and respond with ONLY JSON matching the schema.\n"
        "Apply changes only to the given file path and produce a unified diff if you choose 'fix'.\n"
        "Finding:\n" + json.dumps(enriched, ensure_ascii=False, indent=2)
    )

# =========================
# JSON cleaning/validation
# =========================
def _extract_first_json_object(text: str) -> Dict[str, Any]:
    """Extract the first complete top-level JSON object from a noisy string.
    Works with code fences, explanatory text, or multiple JSON objects."""
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
        # not in string
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

# =========================
# Unified diff helpers + YAML validation
# =========================

_DIFF_HEADER_RE = re.compile(r"^(--- |\+\+\+ )")
_HUNK_RE = re.compile(r"^@@ -(?P<start1>\d+)(?:,(?P<len1>\d+))? \+(?P<start2>\d+)(?:,(?P<len2>\d+))? @@")

def _is_unified_diff(text: str) -> bool:
    if not text or "@@" not in text: return False
    has_headers = any(line.startswith("--- ") for line in text.splitlines()) and \
                  any(line.startswith("+++ ") for line in text.splitlines())
    return has_headers

def _extract_diff_target(text: str) -> Optional[str]:
    # Extract from '+++ ' header. Accept optional a/ or b/ prefixes.
    for line in text.splitlines():
        if line.startswith("+++ "):
            path = line[4:].strip()
            # strip possible timestamps and prefixes
            if path.startswith("a/") or path.startswith("b/"):
                path = path[2:]
            # drop tabs or spaces following path (e.g., timestamps)
            path = path.split('\t')[0].split(' ')[0]
            return path
    return None

def _apply_unified_diff_to_text(orig_text: str, patch: str) -> Optional[str]:
    """Apply a single-file unified diff to the provided original text. Returns new text or None on failure."""
    lines = orig_text.splitlines(keepends=True)
    new_lines: List[str] = []
    i = 0  # index into original lines
    in_hunk = False
    for line in patch.splitlines(keepends=False):
        if line.startswith('@@ '):
            m = _HUNK_RE.match(line)
            if not m:
                return None
            # positions are 1-based; compute start (inclusive)
            start1 = int(m.group('start1'))
            # append unchanged lines before this hunk
            target_index = start1 - 1
            if target_index < i:  # overlapping or out of order
                return None
            new_lines.extend(lines[i:target_index])
            i = target_index
            in_hunk = True
            continue
        if not in_hunk:
            # skip headers and file lines
            continue
        if not line:
            # empty line as context
            if i >= len(lines):
                new_lines.append("\n")
            else:
                new_lines.append(lines[i])
                i += 1
            continue
        tag = line[0]
        content = line[1:]
        if tag == ' ':
            # context line: must match original
            if i >= len(lines):
                return None
            if lines[i].rstrip('\n\r') != content:
                return None
            new_lines.append(lines[i])
            i += 1
        elif tag == '-':
            # deletion: original must match, don't append
            if i >= len(lines):
                return None
            if lines[i].rstrip('\n\r') != content:
                return None
            i += 1
        elif tag == '+':
            # addition: append with newline
            # Preserve original newline style if possible
            nl = '\n' if (len(lines) == 0 or lines[0].endswith('\n')) else ('\r\n' if any(l.endswith('\r\n') for l in lines[:50]) else '\n')
            new_lines.append(content + nl)
        else:
            # end of hunk or unknown -> treat as failure
            return None
    # append remaining original lines
    new_lines.extend(lines[i:])
    return ''.join(new_lines)

def _yaml_is_valid(text: str) -> bool:
    try:
        import yaml  # type: ignore
    except ImportError:
        # If PyYAML is not available, skip strict validation and accept
        return True
    try:
        # support multi-doc YAML
        list(yaml.safe_load_all(text))
        return True
    except yaml.YAMLError:  # type: ignore[attr-defined]
        return False

# =========================
# Payload loader (auto-detect)
# =========================
def load_payload() -> List[Dict[str, Any]]:
    # Prefer the new builder output first, then fallback locations.
    candidates = [
        Path("output/llm_payload.json"),
        Path("detection/output/llm_payload.json"),
        Path("llm_payload.json"),
    ]
    for p in candidates:
        if p.exists():
            obj = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(obj, list): return obj
            if isinstance(obj, dict) and isinstance(obj.get("items"), list): return obj["items"]
            raise ValueError(f"{p} has unexpected structure. Expected a list or {{'items':[...]}}, got {type(obj)}")
    raise FileNotFoundError("llm_payload.json not found in ., output/, or detection/output/")

# =========================
# Provider adapters
# =========================
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
            # ask model to emit a JSON object, helps avoid non-JSON chatter
            "response_format": {"type": "json_object"}
        }
        try:
            r = await _post_json(client, url, timeout_seconds, headers=headers, json=body)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
        except (httpx.HTTPError, KeyError, json.JSONDecodeError) as e:
            last_err = _err_with_body(f"groq ({model})", e)
            # try next fallback model
    raise RuntimeError(last_err or "groq unknown error")

async def call_openrouter(client: httpx.AsyncClient, prompt: str, timeout_seconds: int) -> str:
    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {os.getenv('OPENROUTER_API_KEY','')}",
        "HTTP-Referer": "https://safefixk8s.local",
        "X-Title": "SafeFixK8s",
    }
    combined = system_prompt() + "\n" + prompt  # inline system into user
    model = os.getenv("OPENROUTER_MODEL", "google/gemma-2-9b-it:free")

    # 1st try: ask provider to emit a JSON object (some support it)
    body = {
        "model": model,
        "messages": [{"role": "user", "content": combined}],
        "temperature": 0,
        "response_format": {"type": "json_object"}
    }
    try:
        r = await _post_json(client, url, timeout_seconds, headers=headers, json=body)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]
    except httpx.HTTPStatusError as e:
        # If the backend rejects response_format, retry without it
        if e.response is not None and e.response.status_code in (400, 415, 422):
            body.pop("response_format", None)
            r2 = await _post_json(client, url, timeout_seconds, headers=headers, json=body)
            r2.raise_for_status()
            return r2.json()["choices"][0]["message"]["content"]
        raise


async def call_gemini(client: httpx.AsyncClient, prompt: str, timeout_seconds: int) -> str:
    """Call Gemini using the official SDK if available; otherwise fall back to REST.
    Defaults to the latest widely available 'gemini-2.5-flash' unless overridden via GEMINI_MODEL.
    """
    key = os.getenv("GEMINI_API_KEY", "").strip()
    prefer = os.getenv("GEMINI_MODEL", "").strip()
    model_candidates = [m for m in [prefer, "gemini-2.5-flash", "gemini-1.5-flash-8b", "gemini-1.5-flash"] if m]

    # 1) Try official SDK (google-genai)
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
        pass  # fall back to REST if SDK is unavailable

    # 2) REST fallback (v1beta remains most compatible across accounts)
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

# =========================
# Core fan-out + retries
# =========================
async def ask_one(adapter_name: str, fn, client: httpx.AsyncClient, prompt: str, retries: int, timeout_seconds: int) -> Dict[str, Any]:
    last_err: str | None = None
    for _ in range(retries + 1):
        try:
            txt = await fn(client, prompt, timeout_seconds)
            return validate_response(adapter_name, txt)
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
        out[m] = res
    return out

# =========================
# Quorum merge
# =========================
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
        patches = [(m, v.get("patch", "")) for m, v in votes.items() if v.get("patch")]
        if patches:
            # prefer longest (more complete) patch
            chosen_from, chosen_patch = max(patches, key=lambda t: len(t[1]))

    summary = "; ".join([f"{m}:{v.get('classification')}" for m, v in votes.items()])
    return {"final_classification": final_cls, "final_patch": chosen_patch, "from_model": chosen_from or "",
            "votes": votes, "vote_summary": summary}

# =========================
# CLI / Runner
# =========================
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

        # Optional post-fix validation
        validation = {"status": "skipped", "reason": "validation disabled"}
        if merged.get("final_classification") == "fix" and args.validate != "none":
            patch = merged.get("final_patch", "")
            file_path = str(item.get("file", "")).strip()
            if not patch:
                validation = {"status": "fail", "reason": "empty_patch"}
            elif not _is_unified_diff(patch):
                validation = {"status": "fail", "reason": "not_unified_diff"}
            else:
                target = _extract_diff_target(patch) or ""
                # normalize backslashes in Windows vs posix
                norm_target = target.replace("\\", "/")
                norm_file = file_path.replace("\\", "/")
                if not target or not (norm_target.endswith(norm_file) or norm_file.endswith(norm_target)):
                    validation = {"status": "fail", "reason": f"diff_target_mismatch: diff={target} item={file_path}"}
                else:
                    try:
                        src = Path(file_path)
                        if not src.exists():
                            validation = {"status": "fail", "reason": f"file_not_found: {file_path}"}
                        else:
                            orig = src.read_text(encoding="utf-8")
                            new_text = _apply_unified_diff_to_text(orig, patch)
                            if new_text is None:
                                validation = {"status": "fail", "reason": "patch_apply_failed"}
                            else:
                                if args.validate == "yaml" and not _yaml_is_valid(new_text):
                                    validation = {"status": "fail", "reason": "yaml_invalid_after_patch"}
                                else:
                                    # write to sandbox for inspection
                                    sandbox = Path(args.apply_dir) / str(idx)
                                    dst = sandbox / file_path
                                    dst.parent.mkdir(parents=True, exist_ok=True)
                                    dst.write_text(new_text, encoding="utf-8")
                                    validation = {"status": "pass", "reason": "ok"}
                    except (OSError, UnicodeDecodeError, ValueError) as e:
                        validation = {"status": "fail", "reason": f"exception: {type(e).__name__}: {e}"}

        # downgrade classification if validation fails
        if validation.get("status") == "fail":
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
