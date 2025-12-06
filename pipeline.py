#!/usr/bin/env python3
"""
SafeFixK8s Pipeline CLI
=======================

Complete pipeline orchestrator for Kubernetes security remediation.

Stages:
  1. Detection     - Run 13 security scanners (PowerShell)
  2. Normalization - Unify findings into single schema (Python)
  3. Repair        - Generate fixes using multi-LLM consensus (Python)
  4. Validation    - Validate fixes with 7-gate framework (Python)

Usage:
  # Run full pipeline
  python pipeline.py --input tests/ --output output/

  # Run specific stages
  python pipeline.py --input tests/ --stages 1,2,3,4

  # Run single stage
  python pipeline.py --stage detection --input tests/
  python pipeline.py --stage normalize --input Detection/output/detection/raw
  python pipeline.py --stage repair --input output/normalization/llm_payload.json
  python pipeline.py --stage validate --input tests/ --fixed output/repair/

Author: SafeFixK8s
"""

import argparse
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ============================================================================
# CONFIGURATION
# ============================================================================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Pipeline stage names
STAGES = {
    1: "detection",
    2: "normalization",
    3: "repair",
    4: "validation"
}

# Default paths
DEFAULT_OUTPUT_DIR = Path("output")
DEFAULT_TESTS_DIR = Path("tests")


# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def run_command(cmd: List[str], description: str, cwd: Optional[Path] = None) -> Tuple[bool, str, str]:
    """
    Run a shell command and return success status, stdout, stderr.
    """
    logger.info(f"Running: {description}")
    logger.debug(f"Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=cwd,
            timeout=3600  # 1 hour timeout
        )

        if result.returncode == 0:
            logger.info(f"✓ {description} completed successfully")
            return True, result.stdout, result.stderr
        else:
            logger.error(f"✗ {description} failed (exit code: {result.returncode})")
            logger.error(f"Error: {result.stderr}")
            return False, result.stdout, result.stderr

    except subprocess.TimeoutExpired:
        logger.error(f"✗ {description} timed out after 1 hour")
        return False, "", "Command timed out"
    except FileNotFoundError as e:
        logger.error(f"✗ Command not found: {cmd[0]}")
        return False, "", str(e)
    except Exception as e:
        logger.error(f"✗ {description} failed: {e}")
        return False, "", str(e)


def ensure_dir(path: Path) -> Path:
    """Create directory if it doesn't exist."""
    path.mkdir(parents=True, exist_ok=True)
    return path


# ============================================================================
# STAGE 1: DETECTION
# ============================================================================

def run_detection(input_dir: Path, output_dir: Path, mode: str = "extended") -> bool:
    """
    Run detection stage using PowerShell detectors.ps1.

    Args:
        input_dir: Directory containing test YAML manifests
        output_dir: Output directory for detection results
        mode: Detection mode ('lean' or 'extended')

    Returns:
        True if successful, False otherwise
    """
    logger.info("=" * 70)
    logger.info("STAGE 1: DETECTION")
    logger.info("=" * 70)

    # Prepare paths
    detectors_script = Path("Detection/detectors.ps1")
    if not detectors_script.exists():
        logger.error(f"Detectors script not found: {detectors_script}")
        return False

    if not input_dir.exists():
        logger.error(f"Input directory not found: {input_dir}")
        return False

    # Prepare output directory
    # Note: detectors.ps1 creates $SAFEFIX_OUTPUT_ROOT/detection/raw
    # So we set it to output_dir, and it will create output_dir/detection/raw
    ensure_dir(output_dir)

    # Prepare PowerShell command
    # The detectors.ps1 script uses functions, not parameters
    # We need to: 1) set SAFEFIX_OUTPUT_ROOT, 2) source script, 3) call function
    function_name = "Det-RunExtended" if mode == "extended" else "Det-RunLean"

    ps_cmd = [
        "powershell",
        "-ExecutionPolicy", "Bypass",
        "-Command",
        f"$env:SAFEFIX_OUTPUT_ROOT='{output_dir.absolute()}'; " +
        f". '{detectors_script.absolute()}'; " +
        f"{function_name} -Path '{input_dir.absolute()}'"
    ]

    # Run detection
    success, stdout, stderr = run_command(
        ps_cmd,
        f"Detection ({mode} mode) on {input_dir}",
        cwd=Path.cwd()
    )

    if success:
        # detectors.ps1 creates $SAFEFIX_OUTPUT_ROOT/detection/raw
        raw_dir = output_dir / "detection" / "raw"
        if raw_dir.exists():
            raw_files = list(raw_dir.glob("*.json"))
            logger.info(f"Detection completed: {len(raw_files)} tool outputs generated")
            logger.info(f"Raw findings: {raw_dir}")
            return True
        else:
            logger.error("Detection completed but no raw output found")
            return False

    return False


# ============================================================================
# STAGE 2: NORMALIZATION
# ============================================================================

def run_normalization(raw_dir: Path, tests_dir: Path, output_dir: Path) -> bool:
    """
    Run normalization stage to unify findings.

    Args:
        raw_dir: Directory with raw detector outputs
        tests_dir: Directory with original test manifests
        output_dir: Output directory for normalized results

    Returns:
        True if successful, False otherwise
    """
    logger.info("=" * 70)
    logger.info("STAGE 2: NORMALIZATION")
    logger.info("=" * 70)

    # Prepare paths
    normalizer_script = Path("Normalizer/normalizer.py")
    if not normalizer_script.exists():
        logger.error(f"Normalizer script not found: {normalizer_script}")
        return False

    if not raw_dir.exists():
        logger.error(f"Raw directory not found: {raw_dir}")
        return False

    # Create output directory
    norm_output = ensure_dir(output_dir / "normalization")

    # Prepare output file paths
    out_normalized = norm_output / "normalized_findings.json"
    out_payload = norm_output / "llm_payload.json"
    out_buckets = norm_output / "buckets.csv"

    # Prepare command
    cmd = [
        sys.executable,
        str(normalizer_script.absolute()),
        "--raw-dir", str(raw_dir.absolute()),
        "--tests-dir", str(tests_dir.absolute()),
        "--out-normalized", str(out_normalized.absolute()),
        "--out-llm-payload", str(out_payload.absolute()),
        "--out-buckets-csv", str(out_buckets.absolute())
    ]

    # Run normalization
    success, stdout, stderr = run_command(
        cmd,
        "Normalization",
        cwd=Path.cwd()
    )

    if success:
        # Check for the payload file we specified
        if out_payload.exists():
            with open(out_payload, 'r', encoding='utf-8') as f:
                payload = json.load(f)
                item_count = len(payload.get('items', []))
                logger.info(f"Normalization completed: {item_count} findings normalized")
                logger.info(f"LLM payload: {out_payload}")
                return True
        else:
            logger.error("Normalization completed but no payload found")
            return False

    return False


# ============================================================================
# STAGE 3: REPAIR (LLM)
# ============================================================================

def run_repair(
    payload_file: Path,
    tests_dir: Path,
    output_dir: Path,
    models: str = "groq,openrouter,gemini",
    concurrency: int = 5
) -> bool:
    """
    Run LLM repair stage to generate fixes.

    Args:
        payload_file: LLM payload JSON file
        tests_dir: Directory with original test manifests
        output_dir: Output directory for repairs
        models: Comma-separated list of LLM models
        concurrency: Number of concurrent requests

    Returns:
        True if successful, False otherwise
    """
    logger.info("=" * 70)
    logger.info("STAGE 3: REPAIR (LLM)")
    logger.info("=" * 70)

    # Prepare paths
    llm_script = Path("LLMs/multi_llm_orchestrator.py")
    if not llm_script.exists():
        logger.error(f"LLM orchestrator script not found: {llm_script}")
        return False

    if not payload_file.exists():
        logger.error(f"Payload file not found: {payload_file}")
        return False

    # Create output directory
    repair_output = ensure_dir(output_dir / "repair")

    # Prepare command
    cmd = [
        sys.executable,
        str(llm_script.absolute()),
        "--payload", str(payload_file.absolute()),
        "--tests-dir", str(tests_dir.absolute()),
        "--out-dir", str(repair_output.absolute()),
        "--models", models,
        "--concurrency", str(concurrency),
        "--autofix",
        "--hygiene"
    ]

    # Run repair
    success, stdout, stderr = run_command(
        cmd,
        f"LLM Repair (models: {models})",
        cwd=Path.cwd()
    )

    if success:
        secured_files = list(repair_output.glob("SECURED_*.yaml"))
        if secured_files:
            logger.info(f"Repair completed: {len(secured_files)} files secured")
            logger.info(f"Secured manifests: {repair_output}")
            return True
        else:
            logger.error("Repair completed but no secured files found")
            return False

    return False


# ============================================================================
# STAGE 4: VALIDATION
# ============================================================================

def run_validation(
    tests_dir: Path,
    fixed_dir: Path,
    payload_file: Path,
    output_dir: Path,
    strict: bool = False
) -> bool:
    """
    Run validation stage with 7-gate framework.

    Args:
        tests_dir: Directory with original test manifests
        fixed_dir: Directory with secured/fixed manifests
        payload_file: LLM payload JSON file
        output_dir: Output directory for validation results
        strict: Enable strict mode

    Returns:
        True if successful, False otherwise
    """
    logger.info("=" * 70)
    logger.info("STAGE 4: VALIDATION")
    logger.info("=" * 70)

    # Prepare paths
    validation_script = Path("Validations/validation_gates_improved.py")
    if not validation_script.exists():
        logger.error(f"Validation script not found: {validation_script}")
        return False

    if not tests_dir.exists():
        logger.error(f"Tests directory not found: {tests_dir}")
        return False

    if not fixed_dir.exists():
        logger.error(f"Fixed directory not found: {fixed_dir}")
        return False

    # Create output directory
    validation_output = ensure_dir(output_dir / "validation")

    # Prepare command
    cmd = [
        sys.executable,
        str(validation_script.absolute()),
        "--tests-dir", str(tests_dir.absolute()),
        "--fixed-dir", str(fixed_dir.absolute()),
        "--payload", str(payload_file.absolute()),
        "--out-dir", str(validation_output.absolute())
    ]

    if strict:
        cmd.append("--strict-mode")

    # Run validation
    success, stdout, stderr = run_command(
        cmd,
        "Validation (7-gate framework)",
        cwd=Path.cwd()
    )

    if success:
        summary_file = validation_output / "SUMMARY_VALIDATION.csv"
        if summary_file.exists():
            logger.info(f"Validation completed")
            logger.info(f"Validation summary: {summary_file}")
            return True
        else:
            logger.warning("Validation completed but no summary found")
            return True

    return False


# ============================================================================
# PIPELINE ORCHESTRATION
# ============================================================================

def run_full_pipeline(
    input_dir: Path,
    output_dir: Path,
    detection_mode: str = "extended",
    llm_models: str = "groq,openrouter,gemini",
    concurrency: int = 5,
    strict_validation: bool = False
) -> bool:
    """
    Run the complete SafeFixK8s pipeline.

    Args:
        input_dir: Directory with test YAML manifests
        output_dir: Output directory for all results
        detection_mode: Detection mode ('lean' or 'extended')
        llm_models: Comma-separated list of LLM models
        concurrency: Number of concurrent LLM requests
        strict_validation: Enable strict validation mode

    Returns:
        True if all stages successful, False otherwise
    """
    logger.info("*" * 70)
    logger.info("SAFEFIXK8S PIPELINE - FULL EXECUTION")
    logger.info("*" * 70)
    logger.info(f"Input: {input_dir}")
    logger.info(f"Output: {output_dir}")
    logger.info("")

    # Stage 1: Detection
    if not run_detection(input_dir, output_dir, detection_mode):
        logger.error("Pipeline failed at stage 1: Detection")
        return False

    # Stage 2: Normalization
    raw_dir = output_dir / "detection" / "raw"
    if not run_normalization(raw_dir, input_dir, output_dir):
        logger.error("Pipeline failed at stage 2: Normalization")
        return False

    # Stage 3: Repair
    payload_file = output_dir / "normalization" / "llm_payload.json"
    if not run_repair(payload_file, input_dir, output_dir, llm_models, concurrency):
        logger.error("Pipeline failed at stage 3: Repair")
        return False

    # Stage 4: Validation
    fixed_dir = output_dir / "repair"
    if not run_validation(input_dir, fixed_dir, payload_file, output_dir, strict_validation):
        logger.error("Pipeline failed at stage 4: Validation")
        return False

    # Success
    logger.info("")
    logger.info("*" * 70)
    logger.info("PIPELINE COMPLETED SUCCESSFULLY!")
    logger.info("*" * 70)
    logger.info(f"Results available in: {output_dir.absolute()}")
    logger.info("")
    logger.info("Output structure:")
    logger.info(f"  {output_dir}/detection/raw/           - Raw detector outputs")
    logger.info(f"  {output_dir}/normalization/           - Normalized findings + LLM payload")
    logger.info(f"  {output_dir}/repair/                  - Secured YAML manifests")
    logger.info(f"  {output_dir}/validation/              - Validation reports")

    return True


# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="SafeFixK8s Pipeline CLI - Kubernetes Security Remediation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run full pipeline
  python pipeline.py --input tests/ --output output/

  # Run with specific LLM models
  python pipeline.py --input tests/ --models groq,gemini --concurrency 10

  # Run in strict validation mode
  python pipeline.py --input tests/ --strict

  # Run individual stages
  python pipeline.py --stage detection --input tests/
  python pipeline.py --stage normalize --raw output/detection/raw --tests tests/
  python pipeline.py --stage repair --payload output/normalization/llm_payload.json
  python pipeline.py --stage validate --tests tests/ --fixed output/repair/
        """
    )

    # Main arguments
    parser.add_argument(
        "--input", "-i",
        type=Path,
        help="Input directory (test YAML manifests for full pipeline or detection)"
    )

    parser.add_argument(
        "--output", "-o",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory (default: {DEFAULT_OUTPUT_DIR})"
    )

    # Stage selection
    parser.add_argument(
        "--stage",
        choices=["detection", "normalize", "repair", "validate", "all"],
        default="all",
        help="Run specific stage (default: all)"
    )

    # Detection options
    parser.add_argument(
        "--detection-mode",
        choices=["lean", "extended"],
        default="extended",
        help="Detection mode: lean (10 tools) or extended (13 tools) (default: extended)"
    )

    # Normalization options
    parser.add_argument(
        "--raw",
        type=Path,
        help="Raw detector outputs directory (for normalize stage)"
    )

    parser.add_argument(
        "--tests",
        type=Path,
        help="Test manifests directory (for normalize/validate stages)"
    )

    # Repair options
    parser.add_argument(
        "--payload",
        type=Path,
        help="LLM payload JSON file (for repair/validate stages)"
    )

    parser.add_argument(
        "--models",
        type=str,
        default="groq,openrouter,gemini",
        help="Comma-separated LLM models (default: groq,openrouter,gemini)"
    )

    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Number of concurrent LLM requests (default: 5)"
    )

    # Validation options
    parser.add_argument(
        "--fixed",
        type=Path,
        help="Fixed/secured manifests directory (for validate stage)"
    )

    parser.add_argument(
        "--strict",
        action="store_true",
        help="Enable strict validation mode"
    )

    # Logging
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )

    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Quiet mode (errors only)"
    )

    args = parser.parse_args()

    # Configure logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    elif args.quiet:
        logging.getLogger().setLevel(logging.ERROR)

    # Validate arguments and run pipeline
    try:
        if args.stage == "all":
            # Full pipeline
            if not args.input:
                parser.error("--input is required for full pipeline")

            success = run_full_pipeline(
                input_dir=args.input,
                output_dir=args.output,
                detection_mode=args.detection_mode,
                llm_models=args.models,
                concurrency=args.concurrency,
                strict_validation=args.strict
            )

        elif args.stage == "detection":
            if not args.input:
                parser.error("--input is required for detection stage")
            success = run_detection(args.input, args.output, args.detection_mode)

        elif args.stage == "normalize":
            raw_dir = args.raw or (args.output / "detection" / "raw")
            tests_dir = args.tests or args.input or DEFAULT_TESTS_DIR
            success = run_normalization(raw_dir, tests_dir, args.output)

        elif args.stage == "repair":
            payload = args.payload or (args.output / "normalization" / "llm_payload.json")
            tests_dir = args.tests or args.input or DEFAULT_TESTS_DIR
            success = run_repair(payload, tests_dir, args.output, args.models, args.concurrency)

        elif args.stage == "validate":
            tests_dir = args.tests or args.input or DEFAULT_TESTS_DIR
            fixed_dir = args.fixed or (args.output / "repair")
            payload = args.payload or (args.output / "normalization" / "llm_payload.json")
            success = run_validation(tests_dir, fixed_dir, payload, args.output, args.strict)

        else:
            parser.error(f"Unknown stage: {args.stage}")
            success = False

        # Exit with appropriate code
        sys.exit(0 if success else 1)

    except KeyboardInterrupt:
        logger.error("\nPipeline interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
