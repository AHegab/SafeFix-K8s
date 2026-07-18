# Integrating SafeFixK8s into Another Pipeline

SafeFixK8s is a pip-installable CLI (`safefixk8s`). It doesn't need to live inside
your repo — install it as a dependency and call it as a step in your own pipeline.

## Prerequisites

- Python 3.8+
- Docker (running — required by the detection stage's 13 scanners)
- Windows: PowerShell 5.1+ (`pipeline.py` runs `Detection/detectors.ps1`)
- Mac/Linux: Bash 4.0+ (`pipeline.py` runs `Detection/detectors.sh` — auto-selected via `platform.system()`, no flag needed)
- At least one LLM API key (Groq, OpenRouter, Gemini, or OpenAI)

## 1. Install

```bash
pip install "git+https://github.com/AHegab/SafeFix-K8s.git"
```

Or, for local development against a checked-out copy:

```bash
git clone https://github.com/AHegab/SafeFix-K8s.git
pip install -e ./SafeFixK8s
```

Either way this puts a `safefixk8s` command on `PATH`. It works from any working
directory — it locates its own internal scripts (`Detection/`, `Normalizer/`, `LLMs/`,
`Validations/`) relative to where it's installed, not relative to your cwd.

## 2. Configure API keys

Set these as environment variables or in a `.env` file in whatever environment runs
the command (your CI job, container, or local shell):

```bash
GROQ_API_KEY=...
OPENROUTER_API_KEY=...
GEMINI_API_KEY=...
OPENAI_API_KEY=...
```

Only one provider is required; more providers give automatic fallback.

## 3. Run it

```bash
safefixk8s --input ./k8s-manifests --output ./safefix-results
```

Runs all 4 stages (detect → normalize → repair → validate) against manifests in
`./k8s-manifests`, writing:

```
safefix-results/
├── detection/raw/           # raw scanner findings
├── normalization/           # unified findings + LLM payload
├── repair/                  # SECURED_*.yaml + EXPLANATION_*.md
└── validation/              # 7-gate validation reports, SUMMARY_VALIDATION.csv
```

To run a single stage instead of the full pipeline:

```bash
safefixk8s --stage detection --input ./k8s-manifests
safefixk8s --stage normalize --raw ./safefix-results/detection/raw --tests ./k8s-manifests
safefixk8s --stage repair --payload ./safefix-results/normalization/llm_payload.json
safefixk8s --stage validate --tests ./k8s-manifests --fixed ./safefix-results/repair
```

Exit code is `0` on success, `1` on failure — standard for chaining in scripts/CI.

## 4. Wire it into your pipeline

Because it's a plain CLI with a clean exit code, drop it in as any other step:

```bash
safefixk8s --input ./manifests --output ./safefix-out || exit 1

# consume results downstream
cat ./safefix-out/repair/SECURED_*.yaml
cat ./safefix-out/validation/SUMMARY_VALIDATION.csv
```

Example CI step (GitHub Actions):

```yaml
- name: Run SafeFixK8s
  run: |
    pip install "git+https://github.com/AHegab/SafeFix-K8s.git"
    safefixk8s --input ./k8s-manifests --output ./safefix-results
  env:
    GROQ_API_KEY: ${{ secrets.GROQ_API_KEY }}

- name: Publish secured manifests
  run: cp safefix-results/repair/SECURED_*.yaml ./deploy/
```

## Notes

- Docker and PowerShell/Bash must be available wherever the `detection` stage runs
  (e.g. a self-hosted runner, or a Docker-in-Docker CI setup).
- `--input`/`--output` are always resolved relative to your current working
  directory, so point them at manifests/output locations in your own repo.
- No submodule, no Dockerfile, no code changes required on the consuming side.
