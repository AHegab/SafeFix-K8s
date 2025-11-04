# LLMs

Purpose: Generate safe, minimal unified-diff patches for each finding using multiple LLM providers with quorum/consensus and strict validation.

Providers supported:
- Groq (OpenAI-compatible API), OpenRouter, Google Gemini (SDK with REST fallback), Ollama (local)

Environment variables:
- `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `GEMINI_API_KEY`
- Optional: `OPENROUTER_MODELS` (comma-separated ordered list), `OPENROUTER_MODEL` (single override), `OPENROUTER_SITE_URL`, `OPENROUTER_APP_TITLE`, `GROQ_MODEL`, `OLLAMA_MODEL`, `GEMINI_MODEL`

Inputs:
- `output/llm_payload.json` (from Normalizer)

Outputs:
- `output/llm_decisions.json` (per-item votes and consensus)
- `output/patch_sandbox/` (per-item patched files when validation passes)

Usage (Windows PowerShell):
- Self-test a single provider:
  - `python .\LLMs\multi_llm_orchestrator.py --selftest groq`
- Full run with YAML validation:
  - `python .\LLMs\multi_llm_orchestrator.py --models groq,openrouter,gemini --validate yaml --apply-dir output\patch_sandbox`

 Important behavior:
- Each model must return a single JSON object matching a strict schema; invalid responses become `needs_review`.
- If classification is `fix`, a minimal unified diff is required. The diff is applied in-memory and optionally YAML-validated.
- If application or YAML validation fails, the item is downgraded to `needs_review` and no patch is emitted to the sandbox.

OpenRouter model selection:
 - The orchestrator prefers OpenRouter first by default and tries models in this order unless overridden:
   - meta-llama/llama-3.3-70b-instruct:free → mistralai/mistral-7b-instruct:free → deepseek/deepseek-r1-distill-llama-70b:free → qwen/qwen3-vl-32b-instruct
 - You can change the order via `OPENROUTER_MODELS` in `.env`.
 - We send messages using the OpenAI Chat API format with separate `system` and `user` roles, and set `HTTP-Referer`/`X-Title` headers as recommended by OpenRouter.
