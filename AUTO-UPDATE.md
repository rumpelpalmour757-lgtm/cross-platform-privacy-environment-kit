# 仓库与自动更新说明

这个仓库是「跨平台网络隐私与本机环境工具包」的 **MIT 公开开源版本库**；项目主页见 [README.md](README.md)，许可与外部参考说明见 [LICENSE](LICENSE) 与 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。

`tools/auto_update.py` 是作者本机用的同步脚本：把本机私有源目录里的工具包同步进这个仓库，过隐私与版权闸门和全部单元测试，在本机提交并打包。**默认不推送**，要推必须显式加 `--push`。发布包里不含 `tools/`，这份说明只对克隆下来的仓库有用。

> **隐私闸门只是辅助检查。** 它按固定规则扫描仓库里已跟踪和这次要加入的文件，拦得住常见的分享链接、用户目录路径和邮箱，拦不住的东西见下文“闸门查什么、不查什么”。推上公开仓库之前，请自己看一遍 `git show --stat`。

## 三条默认规则

1. **默认不推送。** 同步、过闸门、跑测试、提交、打包都照常做，提交只留在本机；加 `--push` 才推到 origin。
2. **新文件要点名。** 源目录里出现仓库还没跟踪过的文件时，整次运行停下并列出这些文件；要进仓库的，用 `--allow-new 路径` 逐个点名。
3. **仓库里人工改过的文件以仓库为准。** 源目录要覆盖或删除的文件，如果在上次自动同步以后被人在仓库里改过，整次运行停下并列出这些文件，不会被源目录的旧版本冲回去。

## 每次运行做什么

1. **开工前检查。** 工作区必须干净（`git status --porcelain` 为空），否则列出这些文件后退出，什么都不动。加了 `--push` 时，当前分支还必须是 `main`（或本机记录的 origin 默认分支），否则同样直接退出。
2. **同步**（`--no-sync` 跳过这一步）。先把要做的事全部算好，有需要人决定的就在动手之前停下：
   - 仓库已跟踪、源目录内容和仓库 HEAD 不同的文件：用源目录的版本覆盖。只差在换行符这类 git 会统一的地方的，不算不同。
   - 仓库已跟踪、源目录里已经没有的文件：从仓库删除。
   - 源目录里有、仓库没跟踪过的新文件：停下，见上面第 2 条。
   - 要覆盖或删除的文件被人工改过：停下，见下文“仓库里人工改过的文件”。
   - 一律不拷：被 `.gitignore` 忽略的文件（日志里列为 skipped）、工具包文档教人生成的本机输出（`env-health.html`、`evidence/`、`*.wfw`、`*.jsonl`）、私有资料（`research-reports/`、`sources/`、旧 `THIRD-PARTY-NOTICE.md`）、`__pycache__` 这类缓存、`routing-global.json`。
   - 仓库目录里没跟踪的和被忽略的本机文件（`.venv/`、日志、旧 ZIP、笔记）不删也不改。

   日志逐个列出这次新增、覆盖、删除的文件。
3. **隐私与版权闸门。** 扫描 git 已跟踪的和这次要加入的文件，被 `.gitignore` 忽略的不扫。命中就整次中止，并还原这次同步动过的文件。
4. **跑全部单元测试**（含 UI 与 Python 算法一致性及 Markdown 链接自检）。没过就整次中止并还原。被跳过的用例会在日志里逐条列出，例如没装 Node.js 时网页与 Python 对账那一项，这些用例在这台电脑上什么也没查。
5. 可选：生成一周一次的国内直连名单 **预览**（只生成，不会自动套用到 v2rayN；拉取失败只记警告，不算失败）。
6. **提交。** 只提交这次同步写入、覆盖、删除的文件，提交信息是 `auto-update: 日期`，日志里打印 `git diff --stat`。没有改动就不提交。提交的作者或提交者邮箱不是 noreply 地址时，日志里会提醒一句。
7. **打包。** 有新提交（或加了 `--force-package`）时，用 `git archive` 把已提交的内容打成 ZIP 放进输出目录，排除规则和发布工作流相同（看 `.gitattributes` 里的 `export-ignore`），工作区里没提交的文件不会进包。
8. **推送。** 只有加了 `--push` 才推。不推时日志最后一句会说：这次提交只在本机，用 `git show --stat HEAD` 查看，用 `git push origin main` 或重跑时加 `--push` 推送。

## 失败时怎样还原

脚本不再执行 `git reset --hard` 和 `git clean`，只还原它自己动过的文件。

| 什么时候失败 | 怎样处理 | 退出码 |
| --- | --- | --- |
| 开工前就被拒：工作区不干净、找不到源目录、参数不对、有新文件或人工改动要人决定、`--push` 时不在 main | 什么都没动 | 2 |
| 同步之后、提交之前：闸门命中、测试没过、按了 Ctrl+C | 覆盖和删除的文件用 `git checkout HEAD -- 路径` 取回，这次新写入的文件和新建的空目录删掉；别的文件一概不碰 | 1（Ctrl+C 是 130） |
| 加了 `--no-sync` 时失败 | 没有同步，就没有要还原的，什么都不回滚 | 1 |
| 提交那一步之后：打包或推送出错 | 本机的提交都留着，不撤 | 3 |

退出码 3 之后：修好问题，用 `git push origin main` 推送，或者重跑时加 `--push`；ZIP 没有生成的，重跑时加 `--force-package` 补打。

## 哪些文件在哪里改

| 在哪里维护 | 文件 | 同步怎样对待 |
| --- | --- | --- |
| 这个仓库 | `README.md`、`CHANGELOG.md`、`LICENSE`、`THIRD-PARTY-NOTICES.md`、`CLAUDE-PROXY-OPTIMIZATION-GUIDE.md`、`PRIVACY-CHECKLIST.md`、`AUTO-UPDATE.md`、`docs/`、`tools/`、`.github/`、`.gitignore`、`.gitattributes`、`test_public_release.py`、`test_auto_update.py` | 不读源目录里的同名文件，也不覆盖、不删除 |
| 本机源目录 | 其余所有文件：各 Python 工具和它们的测试、各 `.ps1` 脚本、`WINDOWS-KILL-SWITCH.md`、路由 JSON、`claude-doh-domains.txt`、`mobile/` | 以源目录为准，覆盖或删除仓库里的版本；仓库里人工改过的先停下 |
| 只在本机 | `research-reports/`、`sources/`、旧 `THIRD-PARTY-NOTICE.md`、体检单、证据目录、防火墙备份和日志 | 不同步，`.gitignore` 也忽略它们 |

### 仓库里人工改过的文件

同步要用源目录的版本覆盖或删除一个已跟踪的文件时，脚本看最后一次改这个文件的提交：提交信息不以 `auto-update: ` 开头，就说明它在上次自动同步以后被人在仓库里改过（合并 PR、在网页上改、手工提交）。这时整次运行停下，提示“仓库里这几个文件在上次自动同步以后被人工改过：把它们拷回源目录，或者加 `--source-wins` 明确让源目录覆盖”。

- 只有源目录的内容和仓库 HEAD 不一样的文件才算冲突。仓库刚公开时所有提交都是手工的，只要两边内容一致，同步照常进行。
- 把仓库里的版本拷回源目录以后，这个文件在仓库里的最后一次提交仍是手工的；以后源目录再改它，同步还会停一次。确认源目录的版本是新的，加一次 `--source-wins`，那次自动提交以后就恢复正常。
- `--source-wins` 对这一次运行里的所有冲突一起生效，用之前先看清停下时列出的清单。

## 参数

| 参数 | 作用 |
| --- | --- |
| `--source 目录` | 私有源目录。不给时取环境变量 `PRIVACY_KIT_SOURCE`，再没有就用脚本里写的默认路径。目录里没有 `README.md` 视为找不到，直接退出 |
| `--outputs 目录` | ZIP 输出目录。不给时取环境变量 `PRIVACY_KIT_OUTPUTS`，再没有就用脚本里写的默认路径 |
| `--no-sync` | 不同步，只对已提交的内容过闸门、跑测试，按需打包和推送。仓库内维护的文档请先手工提交，再用它推送 |
| `--allow-new 路径` | 放行一个源目录里的新文件，路径相对仓库根目录；可以重复给。点名的文件照样要过闸门 |
| `--source-wins` | 允许源目录覆盖或删除仓库里人工改过的文件 |
| `--push` | 全部成功后推送到 origin，只推 `main` 或 origin 默认分支。推送前不会先 `git fetch` |
| `--no-push` | 留给旧命令行用，现在默认就不推送；和 `--push` 同时给会报错退出 |
| `--force-package` | 没有新提交也重新打包 |
| `--refresh-allowlists`、`--allowlist-directory 目录` | 生成名单预览、指定预览的存放目录 |

## 手动运行

```powershell
python tools/auto_update.py --source "<源目录>"
git show --stat HEAD
git push origin main
```

第一条只在本机提交；看过第二条的输出确认无误，再用第三条推送。

## 定时任务怎样配

仓库里没有注册定时任务的脚本，需要自己在系统里建。命令行里带着 `--no-push` 的旧任务照旧能用。

**只同步，不推送（默认，推荐）。**

- Windows：在“任务计划程序”里新建任务，触发器选每周一次；操作选“启动程序”，程序填 `py`，参数填 `-3 tools\auto_update.py --source "<源目录>"`，“起始于”填仓库目录。
- macOS / Linux：在 `crontab -e` 里加一行，日志写在仓库外面：

  ```sh
  20 9 * * 1 cd "<仓库目录>" && python3 tools/auto_update.py --source "<源目录>" >> "$HOME/privacy-kit-auto-update.log" 2>&1
  ```

每次运行后看一眼日志或退出码：2 表示要人处理（工作区不干净、有新文件、有人工改动），1 表示已经还原，3 表示提交那一步之后（打包或推送）出错、提交留在本机。确认提交没问题，再手动 `git push origin main`。

**同步后自动推送。** 在上面的参数后面加 `--push`。这样等于没人看过就上公开仓库：闸门只是辅助检查，测试只说明代码能跑。建议先按默认方式跑几次，确认过闸门和新文件拦截都生效以后再改成这样。另外：

- 推送前不会先 `git fetch`。远端有本机没有的提交（比如刚合并了 PR）时，推送会被拒绝，提交留在本机，退出码 3；先在仓库里把远端的改动拉下来处理好，再推送。
- 要推送的提交里，作者或提交者的邮箱不是 noreply 地址时，脚本不推（退出码 3），免得把真实邮箱带上公开仓库。这个邮箱确实可以公开的，请手动推送。

## 闸门查什么、不查什么

**查：**

- 代理分享链接：vless、vmess、trojan、hysteria、hysteria2、hy2、tuic、ss、ssr，协议名不分大小写，链接里带 `@`、`:`、`%` 的也算。
- 带账号口令的 socks、http、https 代理地址；`user:password` 这类明显的占位写法放行。
- 用户目录路径：`X:\Users\<名字>`、`/home/<名字>`、`/Users/<名字>`、`/mnt/c/Users/<名字>`。名字是 `<USER>`、`%USERNAME%`、`$USER`、`user`、`runner`、`Public`、`Shared` 这类占位符或系统账户的放行；当前账户的名字（`USERNAME` 环境变量和家目录名两样都查）不设长度下限。
- 邮箱：git 配置的邮箱和它的前缀；git 配的是 GitHub noreply 地址时，查其中的登录名加 `@`；以及不在允许清单里的任何邮箱（`example.com`、`example.org`、`example.net`、`.example`、`.invalid`、`.test`、`.localhost`、`users.noreply.github.com` 和 `git@`、`noreply@` 放行）。
- Windows 上，当前用户名作为独立的词出现（4 个字符以上，不是常见词）。
- 第三方镜像：任何层级的 `research-reports/`、`sources/`、旧 `THIRD-PARTY-NOTICE.md`，以及两个固定的镜像标记。
- 编码：识别 UTF-8、UTF-16、UTF-32 的 BOM，解码后再扫（Windows PowerShell 5.1 用 `>` 重定向出来的就是带 BOM 的 UTF-16）。含 NUL 字节又没有 BOM 的未知二进制文件直接拦下；`.png`、`.jpg`、`.pdf`、`.zip` 等已知类型不扫，在日志里逐个列出，请自己看一眼。

**不查：**

- 订阅地址、JSON 形式的节点配置、API 密钥和令牌、私钥。
- 图片（包括二维码）、PDF、压缩包里的内容。
- 提交历史和提交说明：只扫文件现在的内容，以前的提交里有过、后来删掉的不查；提交的作者和提交者邮箱只在推送前看一次（见上一节）。
- 不经过这个脚本的提交和推送，比如手工 `git push`。
- 正文里用自然语言写出的姓名、地点。

GitHub 仓库设置里的 secret scanning 和 push protection 建议打开，作为另一层检查。

## 第一次关联 GitHub

`tools/Link-GitHub.cmd` 是作者本人第一次关联 GitHub 时用的：已经配了 origin 就推送 `main`；没有 origin，或者推送失败，就接着用 `gh repo create --public --push` 新建公开仓库。它不过闸门、不跑测试，也不会创建任何定时任务；末尾“之后每周一 09:00 自动更新”的提示，要另外建好定时任务（见上文）才成立，而且现在的自动更新默认不推送。复用这个仓库的人，建议手动执行 `git remote add origin <仓库地址>` 和 `git push -u origin main`。
