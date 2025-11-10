@echo off
REM Run ALL 13 detection tools individually with full pipeline

echo ============================================================
echo SafeFixK8s - Run ALL 13 Tools Individually
echo ============================================================
echo.
echo This will run ALL 13 tools separately:
echo   1. Checkov          8. KubeScore
echo   2. Trivy            9. KubeConform
echo   3. KubeAudit       10. Pluto
echo   4. KubeLinter      11. RBACPolice
echo   5. Polaris         12. Gitleaks
echo   6. Kubescape       13. Conftest
echo   7. Yamllint
echo.
echo Each tool will:
echo   - Detect security issues
echo   - Apply LLM fixes (3-way consensus: Groq, OpenRouter, Gemini)
echo   - Validate through security gates
echo   - Merge all fixes for each file
echo.
pause

set MODELS=groq,openrouter,gemini
set GATES=1,2,3,4,5,6,7
set TOTAL=0
set SUCCESS=0
set FAILED=0

echo.
echo Starting pipeline at %TIME%
echo.

REM ============================================================
REM TOOL 1: CHECKOV
REM ============================================================
echo.
echo ============================================================
echo TOOL 1/13: CHECKOV
echo ============================================================
set /a TOTAL+=1
python orchestrator\safefix_single_tool.py --tool checkov --models %MODELS% --gates %GATES%
if %ERRORLEVEL% EQU 0 (
    set /a SUCCESS+=1
    python orchestrator\merge_single_tool_fixes.py --run-dir output\*__Checkov
) else (
    set /a FAILED+=1
    echo [WARNING] Checkov failed, continuing...
)

REM ============================================================
REM TOOL 2: TRIVY
REM ============================================================
echo.
echo ============================================================
echo TOOL 2/13: TRIVY
echo ============================================================
set /a TOTAL+=1
python orchestrator\safefix_single_tool.py --tool trivy --models %MODELS% --gates %GATES%
if %ERRORLEVEL% EQU 0 (
    set /a SUCCESS+=1
    python orchestrator\merge_single_tool_fixes.py --run-dir output\*__Trivy
) else (
    set /a FAILED+=1
    echo [WARNING] Trivy failed, continuing...
)

REM ============================================================
REM TOOL 3: KUBEAUDIT
REM ============================================================
echo.
echo ============================================================
echo TOOL 3/13: KUBEAUDIT
echo ============================================================
set /a TOTAL+=1
python orchestrator\safefix_single_tool.py --tool kubeaudit --models %MODELS% --gates %GATES%
if %ERRORLEVEL% EQU 0 (
    set /a SUCCESS+=1
    python orchestrator\merge_single_tool_fixes.py --run-dir output\*__KubeAudit
) else (
    set /a FAILED+=1
    echo [WARNING] KubeAudit failed, continuing...
)

REM ============================================================
REM TOOL 4: KUBELINTER
REM ============================================================
echo.
echo ============================================================
echo TOOL 4/13: KUBELINTER
echo ============================================================
set /a TOTAL+=1
python orchestrator\safefix_single_tool.py --tool kubelinter --models %MODELS% --gates %GATES%
if %ERRORLEVEL% EQU 0 (
    set /a SUCCESS+=1
    python orchestrator\merge_single_tool_fixes.py --run-dir output\*__KubeLinter
) else (
    set /a FAILED+=1
    echo [WARNING] KubeLinter failed, continuing...
)

REM ============================================================
REM TOOL 5: POLARIS
REM ============================================================
echo.
echo ============================================================
echo TOOL 5/13: POLARIS
echo ============================================================
set /a TOTAL+=1
python orchestrator\safefix_single_tool.py --tool polaris --models %MODELS% --gates %GATES%
if %ERRORLEVEL% EQU 0 (
    set /a SUCCESS+=1
    python orchestrator\merge_single_tool_fixes.py --run-dir output\*__Polaris
) else (
    set /a FAILED+=1
    echo [WARNING] Polaris failed, continuing...
)

REM ============================================================
REM TOOL 6: KUBESCAPE
REM ============================================================
echo.
echo ============================================================
echo TOOL 6/13: KUBESCAPE
echo ============================================================
set /a TOTAL+=1
python orchestrator\safefix_single_tool.py --tool kubescape --models %MODELS% --gates %GATES%
if %ERRORLEVEL% EQU 0 (
    set /a SUCCESS+=1
    python orchestrator\merge_single_tool_fixes.py --run-dir output\*__Kubescape
) else (
    set /a FAILED+=1
    echo [WARNING] Kubescape failed, continuing...
)

REM ============================================================
REM TOOL 7: YAMLLINT
REM ============================================================
echo.
echo ============================================================
echo TOOL 7/13: YAMLLINT
echo ============================================================
set /a TOTAL+=1
python orchestrator\safefix_single_tool.py --tool yamllint --models %MODELS% --gates %GATES%
if %ERRORLEVEL% EQU 0 (
    set /a SUCCESS+=1
    python orchestrator\merge_single_tool_fixes.py --run-dir output\*__Yamllint
) else (
    set /a FAILED+=1
    echo [WARNING] Yamllint failed, continuing...
)

REM ============================================================
REM TOOL 8: KUBESCORE
REM ============================================================
echo.
echo ============================================================
echo TOOL 8/13: KUBESCORE
echo ============================================================
set /a TOTAL+=1
python orchestrator\safefix_single_tool.py --tool kubescore --models %MODELS% --gates %GATES%
if %ERRORLEVEL% EQU 0 (
    set /a SUCCESS+=1
    python orchestrator\merge_single_tool_fixes.py --run-dir output\*__KubeScore
) else (
    set /a FAILED+=1
    echo [WARNING] KubeScore failed, continuing...
)

REM ============================================================
REM TOOL 9: KUBECONFORM
REM ============================================================
echo.
echo ============================================================
echo TOOL 9/13: KUBECONFORM
echo ============================================================
set /a TOTAL+=1
python orchestrator\safefix_single_tool.py --tool kubeconform --models %MODELS% --gates %GATES%
if %ERRORLEVEL% EQU 0 (
    set /a SUCCESS+=1
    python orchestrator\merge_single_tool_fixes.py --run-dir output\*__KubeConform
) else (
    set /a FAILED+=1
    echo [WARNING] KubeConform failed, continuing...
)

REM ============================================================
REM TOOL 10: PLUTO
REM ============================================================
echo.
echo ============================================================
echo TOOL 10/13: PLUTO
echo ============================================================
set /a TOTAL+=1
python orchestrator\safefix_single_tool.py --tool pluto --models %MODELS% --gates %GATES%
if %ERRORLEVEL% EQU 0 (
    set /a SUCCESS+=1
    python orchestrator\merge_single_tool_fixes.py --run-dir output\*__Pluto
) else (
    set /a FAILED+=1
    echo [WARNING] Pluto failed, continuing...
)

REM ============================================================
REM TOOL 11: RBACPOLICE
REM ============================================================
echo.
echo ============================================================
echo TOOL 11/13: RBACPOLICE  
echo ============================================================
set /a TOTAL+=1
python orchestrator\safefix_single_tool.py --tool rbacpolice --models %MODELS% --gates %GATES%
if %ERRORLEVEL% EQU 0 (
    set /a SUCCESS+=1
    python orchestrator\merge_single_tool_fixes.py --run-dir output\*__RBACPolice
) else (
    set /a FAILED+=1
    echo [WARNING] RBACPolice failed, continuing...
)

REM ============================================================
REM TOOL 12: GITLEAKS
REM ============================================================
echo.
echo ============================================================
echo TOOL 12/13: GITLEAKS
echo ============================================================
set /a TOTAL+=1
python orchestrator\safefix_single_tool.py --tool gitleaks --models %MODELS% --gates %GATES%
if %ERRORLEVEL% EQU 0 (
    set /a SUCCESS+=1
    python orchestrator\merge_single_tool_fixes.py --run-dir output\*__Gitleaks
) else (
    set /a FAILED+=1
    echo [WARNING] Gitleaks failed, continuing...
)

REM ============================================================
REM TOOL 13: CONFTEST
REM ============================================================
echo.
echo ============================================================
echo TOOL 13/13: CONFTEST
echo ============================================================
set /a TOTAL+=1
python orchestrator\safefix_single_tool.py --tool conftest --models %MODELS% --gates %GATES%
if %ERRORLEVEL% EQU 0 (
    set /a SUCCESS+=1
    python orchestrator\merge_single_tool_fixes.py --run-dir output\*__Conftest
) else (
    set /a FAILED+=1
    echo [WARNING] Conftest failed, continuing...
)

echo.
echo ============================================================
echo ALL TOOLS COMPLETE
echo ============================================================
echo.
echo Pipeline finished at %TIME%
echo.
echo Total tools: %TOTAL%
echo Success: %SUCCESS%
echo Failed: %FAILED%
echo.

if %SUCCESS% GTR 0 (
    echo.
    echo ============================================================
    echo MERGED MANIFESTS AVAILABLE
    echo ============================================================
    echo.
    echo Each tool's merged fixes are in:
    echo   output\YYYY-MM-DD__HH-MM-SS__ToolName\merged\merged_manifests\
    echo.
    echo To view all merged files:
    dir /s /b output\*\merged\merged_manifests\*.yaml
    echo.
)

pause
