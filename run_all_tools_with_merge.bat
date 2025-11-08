@echo off
REM Run all detection tools individually and merge each one's fixes

echo ============================================================
echo SafeFixK8s - Run All Tools with Individual Merging
echo ============================================================
echo.
echo This will:
echo   1. Run each tool (Checkov, Trivy, KubeAudit, Conftest, RBACPolice)
echo   2. Each tool: Detect → LLM Fix → Validate → Merge
echo   3. Create merged manifests for each tool
echo.
echo Models: Groq, OpenRouter, Gemini (3-way consensus)
echo Gates: 1-7 (schema, policy, dryrun, sandbox, health, network, e2e)
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
echo [*] Merging Checkov fixes...
for /f "delims=" %%i in ('dir /b /ad /o-d output\*__Checkov 2^>nul') do (
    set CHECKOV_DIR=%%i
    goto :merge_checkov
)
:merge_checkov
if defined CHECKOV_DIR (
    python orchestrator\merge_single_tool_fixes.py --run-dir output\%CHECKOV_DIR%
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
echo [*] Merging Trivy fixes...
for /f "delims=" %%i in ('dir /b /ad /o-d output\*__Trivy 2^>nul') do (
    set TRIVY_DIR=%%i
    goto :merge_trivy
)
:merge_trivy
if defined TRIVY_DIR (
    python orchestrator\merge_single_tool_fixes.py --run-dir output\%TRIVY_DIR%
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
echo [*] Merging KubeAudit fixes...
for /f "delims=" %%i in ('dir /b /ad /o-d output\*__Kubeaudit 2^>nul') do (
    set KUBEAUDIT_DIR=%%i
    goto :merge_kubeaudit
)
:merge_kubeaudit
if defined KUBEAUDIT_DIR (
    python orchestrator\merge_single_tool_fixes.py --run-dir output\%KUBEAUDIT_DIR%
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
echo [*] Merging Conftest fixes...
for /f "delims=" %%i in ('dir /b /ad /o-d output\*__Conftest 2^>nul') do (
    set CONFTEST_DIR=%%i
    goto :merge_conftest
)
:merge_conftest
if defined CONFTEST_DIR (
    python orchestrator\merge_single_tool_fixes.py --run-dir output\%CONFTEST_DIR%
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
echo [*] Merging RBAC-Police fixes...
for /f "delims=" %%i in ('dir /b /ad /o-d output\*__Rbac-police 2^>nul') do (
    set RBAC_DIR=%%i
    goto :merge_rbac
)
:merge_rbac
if defined RBAC_DIR (
    python orchestrator\merge_single_tool_fixes.py --run-dir output\%RBAC_DIR%
)

echo.
echo ============================================================
echo ALL TOOLS COMPLETE
echo ============================================================
echo.
echo Merged manifests created for each tool:
echo   output\*__Checkov\merged\merged_manifests\
echo   output\*__Trivy\merged\merged_manifests\
echo   output\*__Kubeaudit\merged\merged_manifests\
echo   output\*__Conftest\merged\merged_manifests\
echo   output\*__Rbac-police\merged\merged_manifests\
echo.
echo [SUCCESS] All tools completed successfully!
echo.
pause
