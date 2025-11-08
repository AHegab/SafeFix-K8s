@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo ================================================================================
echo SafeFix-K8s: Run All Tools with 3 LLMs and Show Validation
echo ================================================================================
echo.
echo Configuration:
echo  - LLMs: groq, openrouter, gemini (3-way consensus voting)
echo  - Gates: 1,2,3,4,5,6,7 (all validation gates)
echo  - Path: tests
echo.

set MODELS=groq,openrouter,gemini
set GATES=1,2,3,4,5,6,7
set PATH_TO_SCAN=tests

REM List of tools - only those with normalizers
set TOOLS=checkov trivy kubeaudit conftest rbac-police

set TOTAL=0
for %%t in (%TOOLS%) do set /a TOTAL+=1

set CURRENT=0

for %%t in (%TOOLS%) do (
    set /a CURRENT+=1
    echo.
    echo ================================================================================
    echo [!CURRENT!/!TOTAL!] Running: %%t
    echo ================================================================================
    
    python orchestrator\safefix_single_tool.py --tool %%t --path !PATH_TO_SCAN! --models !MODELS! --gates !GATES!
    
    if errorlevel 1 (
        echo.
        echo [FAIL] %%t failed with error code !errorlevel!
    ) else (
        echo.
        echo [OK] %%t completed successfully
        echo.
        echo --- VALIDATION RESULTS FOR %%t ---
        python show_validation_results.py | findstr /C:"%%t" /C:"TOOL:" /C:"LLMs" /C:"Total Items" /C:"CONSENSUS" /C:"VALIDATION" /C:"VALIDATED FIXES" /C:"File:" /C:"Fixes:" /C:"Category:"
    )
    
    echo.
    echo --------------------------------------------------------------------------------
)

echo.
echo ================================================================================
echo ALL TOOLS COMPLETED - FULL VALIDATION SUMMARY
echo ================================================================================
python show_validation_results.py

echo.
echo ================================================================================
echo Validation complete! Check validation report above.
echo ================================================================================
pause
