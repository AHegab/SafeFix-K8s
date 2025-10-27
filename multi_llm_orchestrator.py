# SafeFix-K8s — parallel multi-LLM fan-out with quorum merge
# Requires: pip install httpx jsonschema

from __future__ import annotations
import os, json, asyncio, hashlib, argparse, time
from pathlib import Path
from typing import Dict, Any, List, Tuple
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
}

# =========================
# Prompt helpers
# =========================
def system_prompt() -> str:
    return (
        "You are a Kubernetes security fixer. "
        "Given one finding (file, category, tool hints), decide whether to FIX, IGNORE, "
        "or mark as NEEDS_REVIEW. If you recommend a fix, include a minimal patch. "
        "Output ONLY a JSON object that matches this schema exactly: "
        + json.dumps(RESPONSE_SCHEMA, separators=(',', ':'))
    )

def make_user_prompt(item: Dict[str, Any]) -> str:
    return "Analyze and respond with ONLY JSON matching the schema.\nFinding:\n" + \
           json.dumps(item, ensure_ascii=False, indent=2)

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
# Payload loader (auto-detect)
# =========================
def load_payload() -> List[Dict[str, Any]]:
    candidates = [
        Path("llm_payload.json"),
        Path("output/llm_payload.json"),
        Path("detection/output/llm_payload.json"),
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

async def _post_json(client, url, **kw) -> httpx.Response:
    return await client.post(url, **kw, timeout=LLM_TIMEOUT_SECONDS)

def _err_with_body(prefix: str, e: Exception) -> str:
    if isinstance(e, httpx.HTTPStatusError) and e.response is not None:
        body = e.response.text
        body = body if len(body) < 500 else body[:500] + "…"
        return f"{prefix}: {e} :: {body}"
    return f"{prefix}: {e}"

async def call_groq(client: httpx.AsyncClient, prompt: str) -> str:
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
            r = await _post_json(client, url, headers=headers, json=body)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]
        except Exception as e:
            last_err = _err_with_body(f"groq ({model})", e)
            # try next fallback model
    raise RuntimeError(last_err or "groq unknown error")

async def call_openrouter(client: httpx.AsyncClient, prompt: str) -> str:
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
        r = await client.post(url, headers=headers, json=body, timeout=LLM_TIMEOUT_SECONDS)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]
    except httpx.HTTPStatusError as e:
        # If the backend rejects response_format, retry without it
        if e.response is not None and e.response.status_code in (400, 415, 422):
            body.pop("response_format", None)
            r2 = await client.post(url, headers=headers, json=body, timeout=LLM_TIMEOUT_SECONDS)
            r2.raise_for_status()
            return r2.json()["choices"][0]["message"]["content"]
        raise


async def call_gemini(client: httpx.AsyncClient, prompt: str) -> str:
    key = os.getenv("GEMINI_API_KEY","")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent?key={key}"
    body = {
        "contents": [{"parts": [{"text": system_prompt() + "\n" + prompt}]}],
        "generationConfig": {"temperature": 0}
    }
    r = await _post_json(client, url, json=body)
    r.raise_for_status()
    j = r.json()
    cands = j.get("candidates") or []
    if not cands: raise RuntimeError(f"Gemini empty response: {j}")
    parts = cands[0].get("content", {}).get("parts") or []
    if not parts or "text" not in parts[0]:
        raise RuntimeError(f"Gemini no text in parts: {j}")
    return parts[0]["text"]

async def call_ollama(client: httpx.AsyncClient, prompt: str) -> str:
    url = "http://localhost:11434/api/chat"
    body = {
        "model": OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": system_prompt()},
            {"role": "user", "content": prompt},
        ],
        "stream": False
    }
    r = await _post_json(client, url, json=body)
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
async def ask_one(adapter_name: str, fn, client: httpx.AsyncClient, prompt: str) -> Dict[str, Any]:
    last_err: str | None = None
    for _ in range(RETRIES + 1):
        try:
            txt = await fn(client, prompt)
            return validate_response(adapter_name, txt)
        except Exception as e:
            last_err = _err_with_body(adapter_name, e)
            await asyncio.sleep(0.8)
    return {"classification": "needs_review", "rationale": last_err or f"{adapter_name} failed", "patch": ""}

async def ask_all(models: List[str], prompt: str) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    enabled = [m for m in models if (m in ADAPTERS and provider_enabled(m))]
    async with httpx.AsyncClient() as client:
        tasks = [ask_one(m, ADAPTERS[m], client, prompt) for m in enabled]
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
    if final_cls == "fix":
        patches = [v.get("patch", "") for v in votes.values() if v.get("patch")]
        if patches: chosen_patch = max(patches, key=len)

    summary = "; ".join([f"{m}:{v.get('classification')}" for m, v in votes.items()])
    return {"final_classification": final_cls, "final_patch": chosen_patch, "votes": votes, "vote_summary": summary}

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
    return ap.parse_args()

def _mask(s): 
    return (s[:4]+"…"+s[-4:]) if s and len(s)>=8 else "<missing>"

async def self_test(which: str):
    test_item = {"file":"(selftest)","category":"NO_RES_LIMITS","hints":["cpu/mem not set"],"policy":"least-privilege"}
    prompt = make_user_prompt(test_item)
    print(f"[SelfTest] Keys GROQ={_mask(os.getenv('GROQ_API_KEY',''))} "
          f"OPENROUTER={_mask(os.getenv('OPENROUTER_API_KEY',''))} GEMINI={_mask(os.getenv('GEMINI_API_KEY',''))}")
    async with httpx.AsyncClient() as client:
        txt = await ADAPTERS[which](client, prompt)
        print(f"[SelfTest:{which}] OK -> {txt[:180]}…")

async def main():
    global MODELS, LLM_TIMEOUT_SECONDS, RETRIES
    args = parse_args()

    if args.selftest:
        if args.selftest not in ADAPTERS:
            print("Use one of: groq, openrouter, gemini, ollama")
            return
        await self_test(args.selftest); return

    if args.models:   MODELS = [m.strip() for m in args.models.split(",") if m.strip()]
    if args.timeout:  LLM_TIMEOUT_SECONDS = args.timeout
    if args.retries:  RETRIES = args.retries

    payload = load_payload()
    total = len(payload)
    if args.limit and args.limit > 0:
        payload = payload[:args.limit]

    enabled = [m for m in MODELS if provider_enabled(m)]
    print(f"[SafeFix-LLM] Items: {len(payload)}/{total} | Models: {enabled} "
          f"| timeout={LLM_TIMEOUT_SECONDS}s retries={RETRIES}")
    print(f"[Keys] GROQ={_mask(os.getenv('GROQ_API_KEY',''))} "
          f"| OPENROUTER={_mask(os.getenv('OPENROUTER_API_KEY',''))} "
          f"| GEMINI={_mask(os.getenv('GEMINI_API_KEY',''))}")

    t0 = time.time()
    results: List[Dict[str, Any]] = []

    for idx, item in enumerate(payload, start=1):
        if not isinstance(item, dict): continue

        prompt = make_user_prompt(item)
        votes  = await ask_all(MODELS, prompt)
        merged = merge_consensus(votes)

        short_id = hashlib.sha1(json.dumps(item, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:12]
        results.append({"id": short_id, "file": item.get("file"), "category": item.get("category"), "consensus": merged})

        print(f"  • processed {idx}/{len(payload)} (elapsed {time.time()-t0:.1f}s)")
        await asyncio.sleep(SMALL_DELAY_SECONDS)

    Path("output").mkdir(exist_ok=True)
    out_path = Path("output/llm_decisions.json")
    out_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[SafeFix-LLM] Wrote {out_path} | total elapsed {time.time()-t0:.1f}s")

if __name__ == "__main__":
    asyncio.run(main())
