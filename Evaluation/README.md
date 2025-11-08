# Detection Effectiveness Evaluation

This module evaluates how well the detection stage (and tools) identify the actual, known vulnerabilities in the `tests/` manifests.

Artifacts:
- `ground_truth_vulns.json` – curated list of expected issues per file using the Normalizer's canonical categories.
- `evaluate_detection.py` – script that compares normalized findings (`llm_payload.json`) to the ground truth and computes precision/recall.

Quick start:
1) Run the pipeline (all tools):
   - `python cli.py pipeline --path tests`  
     This creates `output/normalization/llm_payload.json`.
2) Evaluate against ground truth:
   - `python cli.py evaluate --normalized output/normalization/llm_payload.json`
3) Per-tool evaluation (single tool mode):
   - `python cli.py pipeline --path tests --tool Checkov --skip-scan --skip-llm --skip-normalize` (adapt flags as needed)
   - `python cli.py evaluate --scope output/Checkov`

The evaluation report is saved to `output/detection_effectiveness_report.json` and includes per-file and per-tool precision/recall.
