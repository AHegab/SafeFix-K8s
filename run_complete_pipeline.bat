@echo off
REM Run all detection tools with validation and merge fixes

echo ============================================================
echo SafeFixK8s - Complete Pipeline with Auto-Merge
echo ============================================================
echo.
echo This will:
echo   1. Run all detection tools (Checkov, Trivy, KubeAudit, etc.)
echo   2. Apply LLM fixes with 3-way consensus voting
echo   3. Validate all fixes through 7 gates
echo   4. Merge all validated fixes into unified manifests
echo.
echo Models: Groq, OpenRouter, Gemini
echo Gates: 1,2,3,4,5,6,7 (schema, policy, dryrun, sandbox, health, network, e2e)
echo.

set MODELS=groq,openrouter,gemini
set GATES=1,2,3,4,5,6,7

echo Starting pipeline...
echo.

REM Run all tools sequentially
python run_all_tools_sequential.py

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Pipeline failed during tool execution
    exit /b 1
)

echo.
echo ============================================================
echo STEP: MERGE ALL FIXES
echo ============================================================
echo.

REM Merge all validated fixes
python orchestrator\merge_all_fixes.py

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Failed to merge fixes
    exit /b 1
)

echo.
echo ============================================================
echo PIPELINE COMPLETE
echo ============================================================
echo.

REM Show final results
python show_merged_fixes.py

echo.
echo [SUCCESS] Complete pipeline executed successfully!
echo.
pause
