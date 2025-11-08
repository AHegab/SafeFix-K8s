@echo off
REM Run each detection tool individually with full pipeline

echo ============================================================
echo SafeFixK8s - Run All Tools Individually
echo ============================================================
echo.
echo This will run each tool separately:
echo   1. Checkov
echo   2. Trivy  
echo   3. KubeAudit
echo   4. Conftest
echo   5. RBACPolice
echo.
echo Each tool will:
echo   - Detect security issues
echo   - Apply LLM fixes (3-way consensus: Groq, OpenRouter, Gemini)
echo   - Validate through gates 1,2,3 (schema, policy, dryrun)
echo.
echo After all tools complete, fixes will be merged automatically.
echo.
pause

set MODELS=groq,openrouter,gemini
set GATES=1,2,3,4,5,6,7

echo.
echo ============================================================
echo TOOL 1/5: CHECKOV
echo ============================================================
echo.
python orchestrator\safefix_single_tool.py --tool checkov --models %MODELS% --gates %GATES%

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Checkov failed
    pause
    exit /b 1
)

echo.
echo ============================================================
echo TOOL 2/5: TRIVY
echo ============================================================
echo.
python orchestrator\safefix_single_tool.py --tool trivy --models %MODELS% --gates %GATES%

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Trivy failed
    pause
    exit /b 1
)

echo.
echo ============================================================
echo TOOL 3/5: KUBEAUDIT
echo ============================================================
echo.
python orchestrator\safefix_single_tool.py --tool kubeaudit --models %MODELS% --gates %GATES%

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] KubeAudit failed
    pause
    exit /b 1
)

echo.
echo ============================================================
echo TOOL 4/5: CONFTEST
echo ============================================================
echo.
python orchestrator\safefix_single_tool.py --tool conftest --models %MODELS% --gates %GATES%

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Conftest failed
    pause
    exit /b 1
)

echo.
echo ============================================================
echo TOOL 5/5: RBAC-POLICE
echo ============================================================
echo.
python orchestrator\safefix_single_tool.py --tool rbac-police --models %MODELS% --gates %GATES%

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] RBAC-Police failed
    pause
    exit /b 1
)

echo.
echo ============================================================
echo ALL TOOLS COMPLETE - MERGING FIXES
echo ============================================================
echo.
python orchestrator\merge_all_fixes.py

if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Merge failed
    pause
    exit /b 1
)

echo.
echo ============================================================
echo SHOWING FINAL RESULTS
echo ============================================================
echo.
python show_merged_fixes.py

echo.
echo ============================================================
echo SUCCESS - PIPELINE COMPLETE
echo ============================================================
echo.
echo Final manifests ready in: output\FINAL_SECURED_MANIFESTS
echo.
pause
