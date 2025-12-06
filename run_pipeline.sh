#!/bin/bash
# SafeFixK8s Pipeline - Linux/Mac Shell Launcher
# Run the full SafeFixK8s pipeline

echo "===================================="
echo "SafeFixK8s Pipeline"
echo "===================================="
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 not found!"
    echo "Please install Python 3.8 or higher"
    exit 1
fi

# Run the pipeline
python3 pipeline.py --input tests/ --output results/

echo ""
echo "===================================="
echo "Pipeline completed!"
echo "Check results/ folder for outputs"
echo "===================================="
