import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_pipeline_help_exit_zero():
    result = subprocess.run([sys.executable, str(PROJECT_ROOT / "pipeline.py"), "--help"], capture_output=True)
    assert result.returncode == 0, f"pipeline --help failed, stderr: {result.stderr.decode('utf-8')}"
