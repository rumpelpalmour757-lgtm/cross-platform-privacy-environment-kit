@echo off
chcp 65001 >nul
cd /d "%~dp0.."
gh auth status >nul 2>&1 || gh auth login --hostname github.com --git-protocol https --web
gh auth status >nul 2>&1 || (echo [FAIL] GitHub 未登录，已停止。 & pause & exit /b 1)
git remote get-url origin >nul 2>&1 && (git push -u origin main) || (gh repo create cross-platform-privacy-environment-kit --public --source . --remote origin --push)
if errorlevel 1 (echo [FAIL] 上传失败，请把上面的报错发给我。) else (echo [OK] 已上传到你的 GitHub 公开仓库，之后每周一 09:00 自动更新。)
pause
