@echo off
setlocal EnableExtensions
set "ERRORLEVEL="
chcp 65001 >nul
cd /d "%~dp0.." || goto failed
gh auth status >nul 2>&1 || gh auth login --hostname github.com --git-protocol https --web
gh auth status >nul 2>&1 || (echo [FAIL] GitHub 未登录，已停止。 & pause & exit /b 1)
git remote get-url origin >nul 2>&1
if "%errorlevel%"=="2" goto create
if not "%errorlevel%"=="0" (
    echo 无法读取当前仓库的 origin 配置。
    goto failed
)
git push -u origin main || goto failed
goto uploaded

:create
gh repo create cross-platform-privacy-environment-kit --public --source . --remote origin --push || goto failed

:uploaded
echo [OK] 已上传到 GitHub。每周自动更新需要另外配置定时任务，详见 AUTO-UPDATE.md。
pause
exit /b 0

:failed
echo [FAIL] 上传失败，请检查上面的报错。
pause
exit /b 1
