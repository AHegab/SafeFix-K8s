@echo off
setlocal enabledelayedexpansion

echo ================================================================================
echo SafeFix-K8s: Running Tools One-by-One
echo ================================================================================
echo.
echo Configuration:
echo  - LLMs: groq,openrouter,gemini
echo  - Gates: 1,2,3,4,5,6,7
echo  - Path: tests
echo.
echo This will run each tool and collect validated fix files in output/final_fixes/
echo.
pause

set MODELS=groq,openrouter,gemini
set GATES=1,2,3,4,5,6,7
set PATH_TO_SCAN=tests

set TOOLS=checkov trivy kubeaudit conftest kubelinter kubescape polaris kube-score rbac-police pluto gitleaks kubeconform yamllint

set COUNT=0
for %%t in (%TOOLS%) do set /a COUNT+=1

set CURRENT=0

for %%t in (%TOOLS%) do (
    set /a CURRENT+=1
    echo.
    echo ================================================================================
    echo [!CURRENT!/!COUNT!] Running: %%t
    echo ================================================================================
    
    python orchestrator\safefix_single_tool.py --tool %%t --path !PATH_TO_SCAN! --models !MODELS! --gates !GATES!
    
    if errorlevel 1 (
        echo [FAIL] %%t failed with error code !errorlevel!
    ) else (
        echo [OK] %%t completed successfully
    )
    
    echo.
    echo Press any key to continue to next tool, or Ctrl+C to stop...
    pause >nul
)

echo.
echo ================================================================================
echo All tools completed!
echo ================================================================================
echo Check output/final_fixes/ for validated fix files
echo.
pause
