# 仓库与自动更新说明

这个仓库是「跨平台网络隐私与本机环境工具包」的 **MIT 公开开源版本库**；项目主页见 [README.md](README.md)，许可与外部参考说明见 [LICENSE](LICENSE) 与 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。

> **公开仓库安全闸门**：`tools/auto_update.py` 已硬编码排除本机私有源目录下的 `research-reports/`、`sources/` 与旧 `THIRD-PARTY-NOTICE.md`，并会在提交前执行隐私与版权镜像双重检查，确保第三方原文与个人路径永远不会被同步到公开仓库。

## 自动更新做什么

[tools/auto_update.py](tools/auto_update.py) 每次运行依次：

1. 从本机工具包源目录 `LocalProxyNetwork\privacy-environment-kit` 同步受控脚本与模板改动（自动保护仓库自带的 `LICENSE`、`THIRD-PARTY-NOTICES.md`、`CHANGELOG.md`、`docs/`、`.github/`、`tools/`，并永久排除 `research-reports/` 与 `routing-global.json` 等本机私有文件）。
2. **隐私与版权闸门**：发现 Windows 用户名、账号邮箱、代理分享链接（`vless://` 等），或任何第三方镜像目录与微信转发原文标记，就整次中止，不提交、不上传。
3. 跑全部单元测试（含 UI 与 Python 算法一致性及 Markdown 链接自检），失败就中止并撤回本次同步。
4. 可选：生成一周一次的国内直连名单 **预览**（只生成，不会自动套用到 v2rayN）。
5. 有改动才提交，并在 `outputs` 目录生成新的干净开源发布压缩包；已关联 GitHub 时自动上传。

## 手动运行

```powershell
python tools/auto_update.py --refresh-allowlists
```

常用参数：`--no-push` 只在本机提交；`--force-package` 没有改动也重新打包。

## 第一次关联 GitHub

双击 [tools/Link-GitHub.cmd](tools/Link-GitHub.cmd)：浏览器里登录 GitHub 授权后，会自动推送或创建公开仓库 `cross-platform-privacy-environment-kit`；之后每周的自动更新会自动上传。
