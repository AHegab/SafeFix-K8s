#!/usr/bin/env python3
"""
Evaluate detection effectiveness by comparing normalized findings (llm_payload.json)
against a curated ground truth of actual vulnerabilities per file.

Outputs a JSON report with precision/recall per file, per category, and per tool
(based on the tools list provided by the normalizer for each item).

Usage:
  python Evaluation/evaluate_detection.py --gt Evaluation/ground_truth_vulns.json \
         --normalized output/normalization/llm_payload.json \
         --out output/detection_effectiveness_report.json

You can also point --scope to a folder; the script will recursively evaluate all
llm_payload.json files under it (useful for per-tool outputs at output/<tool>/normalization/).
"""
import argparse, json
from pathlib import Path
from collections import defaultdict

CANON = {
    # passthrough canonical categories (must match Normalizer)
    "PRIVILEGED": "PRIVILEGED",
    "PRIV_ESCALATION": "PRIV_ESCALATION",
    "CAP_SYS_ADMIN": "CAP_SYS_ADMIN",
    "HOSTPATH": "HOSTPATH",
    "MISSING_CAP_DROP": "MISSING_CAP_DROP",
    "RUN_AS_NONROOT_FALSE": "RUN_AS_NONROOT_FALSE",
    "READONLY_ROOTFS_FALSE": "READONLY_ROOTFS_FALSE",
    "NO_SECCOMP": "NO_SECCOMP",
    "NO_APPARMOR": "NO_APPARMOR",
    "HARD_CODED_CREDS": "HARD_CODED_CREDS",
    "PLAIN_SECRET": "PLAIN_SECRET",
    "SERVICEACCOUNT_TOKEN_AUTO": "SERVICEACCOUNT_TOKEN_AUTO",
    "RBAC_OVER_PERMISSIVE": "RBAC_OVER_PERMISSIVE",
    "NETWORK_POLICY_MISSING": "NETWORK_POLICY_MISSING",
    "IMAGE_LATEST": "IMAGE_LATEST",
    "HOST_NAMESPACE": "HOST_NAMESPACE",
    "CNI_EMBEDDED_PRIVILEGED": "CNI_EMBEDDED_PRIVILEGED",
    "POD_DEFAULT_NAMESPACE": "POD_DEFAULT_NAMESPACE",
    "NO_PROBES": "NO_PROBES",
    "NO_RES_LIMITS": "NO_RES_LIMITS",
    "DEPRECATED_API": "DEPRECATED_API",
    "SCHEMA_INVALID": "SCHEMA_INVALID",
    "YAML_FORMATTING": "YAML_FORMATTING",
    "MISSING_SECURITY_CONTEXT": "MISSING_SECURITY_CONTEXT",
}

# Synonyms mapping (if ground truth uses a synonym, remap to canonical)
SYN = {
    "PRIVILEGED_CONTAINER": "PRIVILEGED",
    "ALLOW_PRIV_ESC": "PRIV_ESCALATION",
    "DOCKER_SOCK": "HOSTPATH",
    "NO_SECURITY_CONTEXT": "MISSING_SECURITY_CONTEXT",
    "UNPINNED_LATEST": "IMAGE_LATEST",
    "RBAC_WILDCARD": "RBAC_OVER_PERMISSIVE",
}

def canonize(cat: str) -> str:
    x = (cat or "").strip().upper()
    return CANON.get(x) or CANON.get(SYN.get(x, "")) or x


def load_ground_truth(p: Path):
    data = json.loads(p.read_text(encoding="utf-8"))
    files = data.get("files", {})
    gt = {Path(k).as_posix(): {canonize(c) for c in v} for k, v in files.items()}
    return gt


def iter_llm_payloads(normalized: Path, scope: Path | None):
    if normalized:
        yield normalized
        return
    if scope and scope.exists():
        for p in scope.rglob("llm_payload.json"):
            yield p


def evaluate_one(payload_path: Path, gt_map: dict):
    payload = json.loads(payload_path.read_text(encoding="utf-8"))
    items = payload.get("items", [])

    # Build detections: file -> {category: set(tools)}
    det: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for it in items:
        f = Path(it.get("file", "")).as_posix()
        cat = canonize(it.get("category", ""))
        if not f or cat not in CANON:
            continue
        for t in it.get("tools", []) or []:
            det[f][cat].add(t)
        # also track detection by any tool
        if not it.get("tools"):
            det[f][cat].add("(unknown)")

    # Evaluate
    per_file = {}
    tool_stats = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})

    all_files = set(gt_map.keys()) | set(det.keys())
    for f in sorted(all_files):
        gt_cats = set(gt_map.get(f, set()))
        found_cats = set(det.get(f, {}).keys())

        tp = len(gt_cats & found_cats)
        fn = len(gt_cats - found_cats)
        fp = len(found_cats - gt_cats)
        recall = (tp / len(gt_cats)) if gt_cats else 1.0
        precision = (tp / (tp + fp)) if (tp + fp) else 1.0

        # Missed-by metrics (categories that appear in ground truth but not detected)
        missed_categories = sorted(gt_cats - found_cats)
        engaged_tools = set()
        for cat in found_cats:
            engaged_tools.update(det.get(f, {}).get(cat, set()))
        tool_miss_counts = {t: len(missed_categories) for t in engaged_tools} if missed_categories else {}

        # per-tool accounting
        for cat in gt_cats:
            tools = det.get(f, {}).get(cat, set())
            if tools:
                for t in tools:
                    tool_stats[t]["tp"] += 1
            else:
                # count a miss for a synthetic "(any)" and for known tools later
                tool_stats["(any)"]["fn"] += 1
        for cat in (found_cats - gt_cats):
            for t in det.get(f, {}).get(cat, set()) or ["(any)"]:
                tool_stats[t]["fp"] += 1
        # remaining FN for tools that did not report a true category
        for cat in (gt_cats - found_cats):
            tool_stats["(any)"]["fn"] += 1

        per_file[f] = {
            "ground_truth": sorted(gt_cats),
            "detected": sorted(found_cats),
            "tp": tp, "fp": fp, "fn": fn,
            "recall": round(recall, 3),
            "precision": round(precision, 3),
            "missed_by": {
                "categories": missed_categories,
                "engaged_tools": sorted(engaged_tools),
                "tool_miss_counts": tool_miss_counts
            }
        }

    # Consolidate per-tool metrics
    per_tool = {}
    for t, s in tool_stats.items():
        tp, fp, fn = s["tp"], s["fp"], s["fn"]
        rec = (tp / (tp + fn)) if (tp + fn) else 1.0
        prec = (tp / (tp + fp)) if (tp + fp) else 1.0
        per_tool[t] = {"tp": tp, "fp": fp, "fn": fn, "recall": round(rec, 3), "precision": round(prec, 3)}

    totals = {
        "files": len(all_files),
        "tp": sum(v["tp"] for v in per_file.values()),
        "fp": sum(v["fp"] for v in per_file.values()),
        "fn": sum(v["fn"] for v in per_file.values()),
        "missed_categories_total": sum(len(v.get("missed_by", {}).get("categories", [])) for v in per_file.values())
    }
    totals["recall"] = round((totals["tp"] / (totals["tp"] + totals["fn"])) if (totals["tp"] + totals["fn"]) else 1.0, 3)
    totals["precision"] = round((totals["tp"] / (totals["tp"] + totals["fp"])) if (totals["tp"] + totals["fp"]) else 1.0, 3)

    # Roll up missed_by categories per engaged tool (tool-level attribution of misses)
    per_tool_missed_categories: dict[str, set[str]] = defaultdict(set)
    for fdata in per_file.values():
        missed = fdata.get("missed_by", {}).get("categories", [])
        engaged = fdata.get("missed_by", {}).get("engaged_tools", [])
        if missed:
            for t in engaged:
                for cat in missed:
                    per_tool_missed_categories[t].add(cat)

    per_tool_missed_categories_serializable = {k: sorted(v) for k, v in per_tool_missed_categories.items()}

    return {
        "payload": str(payload_path),
        "totals": totals,
        "per_file": per_file,
        "per_tool": per_tool,
        "per_tool_missed_categories": per_tool_missed_categories_serializable,
    }


def load_proof(proof_path: Path):
    """Load a safe_fix_proof.json file (if exists) and compute remediation metrics.

    Classification heuristics are based on filename segment prefixes inside the combination output
    directory:
      SECURED_*, INEFFECTIVE_*, VALIDATION_*, DECISIONS_*, MANUAL_REQUIRED_*, SCAFFOLD_*.
    Sandbox paths are aggregated under SANDBOX.
    """
    if not proof_path.exists():
        return None
    try:
        proof = json.loads(proof_path.read_text(encoding="utf-8"))
    except Exception as e:  # pragma: no cover - defensive
        return {"error": f"failed to parse proof: {e}"}

    files = proof.get("files", [])
    buckets: dict[str, list[dict]] = defaultdict(list)
    gate_pass = 0
    gate_fail = 0
    for entry in files:
        fname = entry.get("file", "")
        label = Path(fname).name  # e.g. SECURED_tests_13.deployment.yaml
        bucket = "OTHER"
        upper_label = label.upper()
        for prefix in ["SECURED_", "INEFFECTIVE_", "VALIDATION_", "DECISIONS_", "MANUAL_REQUIRED_", "SCAFFOLD_"]:
            if upper_label.startswith(prefix):
                bucket = prefix.rstrip("_")  # remove trailing underscore for cleaner key
                break
        if "/sandbox/" in fname.replace("\\", "/"):
            bucket = "SANDBOX"
        buckets[bucket].append(entry)
        for g in entry.get("gates", []):
            if g.get("status") == "PASS":
                gate_pass += 1
            else:
                gate_fail += 1

    def summarize(bucket_name: str):
        arr = buckets.get(bucket_name, [])
        total = len(arr)
        passes = sum(1 for e in arr if e.get("overall") == "PASS")
        fails = total - passes
        return {"total": total, "overall_pass": passes, "overall_fail": fails}

    remediation = {
        "buckets": {b: summarize(b) for b in sorted(buckets.keys())},
        "gate_totals": {"pass": gate_pass, "fail": gate_fail},
    }

    # Derived metric: remediation effectiveness for SECURED bucket
    secured_stats = remediation["buckets"].get("SECURED") or {"total": 0, "overall_pass": 0}
    if secured_stats["total"]:
        remediation["secured_effectiveness"] = round(
            secured_stats["overall_pass"] / secured_stats["total"], 3
        )
    else:
        remediation["secured_effectiveness"] = None
    return remediation


def derive_pipeline_deltas(payload_json: dict):
    """Return per-stage delta metrics using llm_payload metadata.

    Stages considered:
      raw -> aggregated -> llm_items (post-filter)
    """
    meta = payload_json.get("metadata", {})
    raw_ct = meta.get("raw_findings_count")
    agg_ct = meta.get("aggregated_count")
    llm_ct = meta.get("llm_items_count") or len(payload_json.get("items", []))
    deltas = {
        "raw_findings": raw_ct,
        "aggregated_findings": agg_ct,
        "llm_items": llm_ct,
    }
    if raw_ct:
        deltas["reduction_raw_to_agg_pct"] = round(100.0 * (1 - (agg_ct / raw_ct)), 2) if agg_ct is not None else None
        deltas["reduction_raw_to_llm_pct"] = round(100.0 * (1 - (llm_ct / raw_ct)), 2)
    if agg_ct:
        deltas["reduction_agg_to_llm_pct"] = round(100.0 * (1 - (llm_ct / agg_ct)), 2)
    deltas["severity_distribution"] = meta.get("severity_distribution", {})
    return deltas


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gt", default="Evaluation/ground_truth_vulns.json")
    ap.add_argument("--normalized", default="", help="Path to llm_payload.json (optional if --scope provided)")
    ap.add_argument("--scope", default="", help="Folder to search recursively for llm_payload.json")
    ap.add_argument("--out", default="output/detection_effectiveness_report.json")
    ap.add_argument("--proof", default="", help="Optional path to safe_fix_proof.json for remediation metrics integration")
    args = ap.parse_args()

    gt = load_ground_truth(Path(args.gt))

    reports = []
    if args.normalized:
        rep = evaluate_one(Path(args.normalized), gt)
        # Attach pipeline delta metrics for the primary payload
        try:
            payload_json = json.loads(Path(args.normalized).read_text(encoding="utf-8"))
            rep["pipeline_deltas"] = derive_pipeline_deltas(payload_json)
        except Exception:  # pragma: no cover
            pass
        reports.append(rep)
    else:
        scope = Path(args.scope) if args.scope else Path("output")
        for p in iter_llm_payloads(None, scope):
            rep = evaluate_one(p, gt)
            try:
                payload_json = json.loads(p.read_text(encoding="utf-8"))
                rep["pipeline_deltas"] = derive_pipeline_deltas(payload_json)
            except Exception:  # pragma: no cover
                pass
            reports.append(rep)

    # Combine into a single report
    combined = {
        "generated_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        "ground_truth": args.gt,
        "reports": reports
    }

    # Integrate remediation proof if provided
    if args.proof:
        remediation = load_proof(Path(args.proof))
        if remediation is not None:
            combined["remediation"] = remediation

    # Global per-tool missed categories rollup (union across reports)
    global_tool_missed: dict[str, set[str]] = defaultdict(set)
    for r in reports:
        for t, cats in (r.get("per_tool_missed_categories", {}) or {}).items():
            for c in cats:
                global_tool_missed[t].add(c)
    combined["per_tool_missed_categories"] = {k: sorted(v) for k, v in global_tool_missed.items()}

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(combined, indent=2), encoding="utf-8")
    print(f"[OK] Wrote {out_path} (evaluated {len(reports)} payloads)")

    # Also emit a compact stage_deltas.json for quick tracking
    try:
        primary = reports[0] if reports else {}
        deltas = primary.get("pipeline_deltas", {})
        secured_total = None
        secured_pass = None
        if "remediation" in combined:
            b = combined["remediation"].get("buckets", {}).get("SECURED", {})
            secured_total = b.get("total")
            secured_pass = b.get("overall_pass")
        stage_summary = {
            "raw_findings": deltas.get("raw_findings"),
            "aggregated_findings": deltas.get("aggregated_findings"),
            "llm_items": deltas.get("llm_items"),
            "reduction_raw_to_agg_pct": deltas.get("reduction_raw_to_agg_pct"),
            "reduction_raw_to_llm_pct": deltas.get("reduction_raw_to_llm_pct"),
            "reduction_agg_to_llm_pct": deltas.get("reduction_agg_to_llm_pct"),
            "severity_distribution": deltas.get("severity_distribution", {}),
            "secured_bucket_total": secured_total,
            "secured_bucket_overall_pass": secured_pass,
        }
        sd_path = out_path.parent / "stage_deltas.json"
        sd_path.write_text(json.dumps(stage_summary, indent=2), encoding="utf-8")
        print(f"[OK] Wrote {sd_path}")
    except Exception:  # pragma: no cover
        pass


if __name__ == "__main__":
    main()
