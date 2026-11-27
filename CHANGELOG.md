# 版本记录

## 未发布

v0.4.2 以后合并、还没有发版的改动。这一节没有改任何 `.ps1` 脚本。

### CI 和发布流程（`.github/workflows/`、`tools/ci/`）

- `tests.yml`：ubuntu 的两个任务（Python 3.10、3.13）跑完全套以后，在“Windows 模拟”下再跑一遍全套：临时目录是指向真实目录的符号链接（像 Windows runner 临时目录的 8.3 短名，拿到的路径和解析以后的不一样），路径里有空格和中文（其中几个字 cp950 里没有）；交给子进程的文本输入和文本模式写的文件用 CRLF 换行；`~名字` 按 ntpath 的规则展开成家目录旁边的同名目录；输出编码 cp950。模拟用的 `tools/ci/sitecustomize.py` 只在这一步经 `PYTHONPATH` 加载，在 Windows 上什么都不做，不进发布包；先跑一遍自检，确认几样模拟确实生效。它只是近似：不改 `os.sep`、`sys.platform`、盘符、文件名大小写和路径长度规则，只能在 Windows 上跑的用例照旧跳过，真正的 Windows 结果仍看 windows-latest。拿 PR #1 当时在 Windows CI 上红过的两个提交（`439f2c0`、`087e96d`）试过：在本机原样跑全绿；在模拟下，Windows CI 上红过的那 4 项都红了，另外还红了两项后来已经修掉的问题（`config_snapshot.py` 打印路径遇到 cp950 里没有的字就报错，`087e96d` 修了；Linux 挂载表用例遇到带空格的临时路径不对，`80dc14d` 修了）。
- `tests.yml`：Windows 任务在跑测试之前打印 Python、git、Node.js、PowerShell 7 和 Windows PowerShell 的版本，系统 ANSI/OEM 代码页和控制台代码页，Python 看到的编码，临时目录和它解析以后的路径。
- `tests.yml` 新增 `archive` 任务：用和 `release.yml` 相同的 `git archive` 命令打包，解到带空格和中文的目录，在 ubuntu-latest 和 windows-latest 上各用 Python 3.13 跑一遍全套；先确认包里没有 `tools/`、`.github/`、`.gitattributes`、`docs/releases/`，日志里打印包内文件数和内容摘要，两种系统可以对照是不是同一份内容。包里没有 `tools/`，自动同步的用例在这个任务里显示为跳过。
- `tests.yml` 可以手动运行（`workflow_dispatch`），给发布前补跑用。
- `release.yml` 打包前查要打包的那个提交上“测试”工作流的结果：只认 push 和手动运行（pull request 测的是合并结果，不是这个提交本身）；这个提交上还有没跑完的就拒绝；取最近开始的一次，结论必须是 success，`tests` 的三个任务和 `archive` 的两个任务都要在、都要是 success（这次运行里另有别的任务的，也要是 success）。没有记录、还在跑、少了任务、有任务没过都拒绝发布，什么都不建；加 `archive` 任务以前的提交（v0.4.2 和更早）上没有发布包两项，用这个工作流发不了；重跑办法写在 `release.yml` 开头（Re-run all jobs；没有记录时在“测试”里 Run workflow，选指向这个提交的分支或标签）。工作流的权限加了 `actions: read`，用来读运行记录。
- `test_public_release.py` 新增检查：`release.yml` 闸门里列的五个任务名（`tests` 三个、`archive` 两个）和 `tests.yml` 的矩阵对得上，查测试结果在打包之前，`tests.yml` 可以手动运行。
- `test_public_release.py` 新增发布闸门的行为测试：从 `release.yml` 里取出“查测试结果”那一步的脚本原样运行，`gh` 换成假的（按构造的运行记录回答，`--jq` 的过滤式交给 jq），试全绿、重跑转绿、没有记录、别的提交上的运行、只有 pull request 的运行、最近一次没过、还在跑或排队、结论不是 success、少了任务（包括整次运行里没有发布包两项）、有任务没过或被跳过、接口出错，核对退出码和拒绝的原因。闸门里的每一项检查（只认 push 和手动运行、按提交查、取最近开始的一次、没跑完就拒绝、结论必须是 success、逐个任务查）改松了，都有用例变红。只在 Linux 上跑（发布工作流跑在 ubuntu-latest），没有 bash 或 jq 时跳过，在 GitHub Actions 上缺了就报错、不跳过；发布包里没有 `.github/`，在包里显示为跳过。

### 自动同步（`tools/auto_update.py`、`AUTO-UPDATE.md`）

- 标准错误也设成 UTF-8（写不出的字符转义成 `\uXXXX` 这类写法）：参数解析出错的提示和脚本自己的记录编码一致，`>> 日志 2>&1` 写出来的日志不再混着两种编码。Python 打不开脚本（`can't open file`）的那一行在脚本运行之前写出，仍按系统代码页。`AUTO-UPDATE.md` 里日志编码的说明照改。
- 新增测试：输出编码是 cp950 时，参数解析出错的提示按 UTF-8 写出，简体字不再变成 `\uXXXX`；在本进程里调用 `main()` 的那项测试同时接管标准错误，不再改动测试运行器自己的输出流。

### 备份（`claude_local_data.py`）

- 明文密钥检查：写成一项、不带空格的 `--header=名字: 值`、`-H=名字: 值`（`.mcp.json` 的参数列表里，以及 hook 或 statusLine 命令里）也按请求头查；以前只认 `--header`、`名字: 值` 分成两项，或中间是空格、引号的写法。判定和分开写的形式一致：`--header=Accept: application/json`、引用环境变量的值照旧不算，冒号后面是几个词的值跟在请求头选项后面照样算。
- 新增测试：上面几种写法各一例（报错列出键路径、不打印值），以及几种不该报的写法。

### 升级要注意

- `claude_local_data.py`、`test_claude_local_data.py` 在本机源目录维护，这次直接在仓库里改了。用自动同步的，先把这两个文件拷回源目录，否则下一次同步会把它们列为人工改动并停下（见 [AUTO-UPDATE.md](AUTO-UPDATE.md) 的“仓库里人工改过的文件”）。其余改动的文件只在仓库里维护。

### 没有验证的

- 新加的 CI 步骤和任务（Windows 环境打印、Windows 模拟、`archive` 两项）和发布闸门，要推到 GitHub 上跑过才知道能不能跑通。本地只用 PyYAML 解析了两个工作流（这里没有 actionlint）；发布闸门那段脚本只用假的 `gh` 和构造的运行记录测过（上面那项测试），没有调用过真的 GitHub API，也没有真的发过版：真的 gh 用它内置的 jq 实现执行 `--jq`，测试里用的是系统的 jq；接口返回的任务名是不是正好等于 `tests.yml` 里 `name:` 展开后的样子，也要真的跑过才知道。
- 这里没有 Windows 和 PowerShell：Windows 那边新加的步骤，以及 `archive` 在 windows-latest 上把包解到中文目录里跑的那几项 PowerShell 测试，都没有跑过。
- 本地在 Linux 上用 Python 3.10、3.13 跑过全套，原样和 Windows 模拟下各一遍；也照 `archive` 的做法把包解到带空格和中文的目录里跑过。

## v0.4.2（2026-11-27）— 自动同步默认不推送、体检与备份检查收紧、文档与脚本行为对齐

> **升级前先看：自动同步的行为变了。** 默认不再推送，要推必须加 `--push`；工作区不干净时拒绝运行；源目录里的新文件要用 `--allow-new` 点名；仓库里人工改过的文件不会再被源目录悄悄覆盖。靠定时任务自动推送的，要自己改任务的命令行，详见 [AUTO-UPDATE.md](AUTO-UPDATE.md)。这一版没有改任何 `.ps1` 脚本。

### 补记：2026-11-25 的修复（提交 `db8187e`）

这次修复在 v0.4.1 标签之后提交，当时没有记进版本记录，也没有单独发布，所以从发布页下载 v0.4.1 的人没有拿到它。它改了 `config_snapshot.py`、`environment_report.py`、`inspect_unix_network.py` 和 `test_environment_report.py`：

- 体检报告按 Unix 采集器实际输出的 `candidate_interface_types` 字段读取默认路由的接口类型。
- 采集器不可用时，相关检查记为 `unknown`，不再拿缺省数据判定。
- 调用子进程时标准输入改为空设备，不再继承终端。

### 自动同步（`tools/auto_update.py`、`AUTO-UPDATE.md`、`.gitignore`）

- **默认不推送**，新增 `--push`：只推 `main` 或本机记录的 origin 默认分支；待推送的提交里作者或提交者邮箱不是 noreply 地址时不推。旧的 `--no-push` 照旧能用，和 `--push` 同时给会报错。推送前不会先 `git fetch`。
- 开工前工作区必须干净，否则列出文件、什么都不动（退出码 2）。未跟踪的文件不受 `status.showUntrackedFiles` 配置影响，照样算不干净；已跟踪的文件标记了 assume-unchanged 或 skip-worktree（`git status` 看不到它们的本地改动）也拒绝。
- 动手之前再查一遍：要写入或删除的文件是符号链接或 Windows 目录联接（junction），或在这样的目录里、要新增的文件在工作区里已有同名文件、要覆盖或删除的文件在工作区里和最后一次提交不一样，都停下列出（退出码 2）。源目录里的新文件和已跟踪的文件名只差大小写时也停下，提示先在仓库里 `git mv`：Windows 和 macOS 把两个名字当成同一个文件。
- git 拒绝在仓库里工作时（例如目录所有者是别的账户，git 报 `detected dubious ownership`），拒绝信息里带上 git 的原话和它给出的 `safe.directory` 处理办法，不再只说“不是 git 工作区”。
- 单元测试和名单预览子进程的输出按子进程实际写出的编码读取（中文 Windows 上是 cp950 或 cp936），测试失败时日志里的中文路径和断言信息不再是乱码。
- 失败时只还原这次同步动过的文件：覆盖和删除的用 `git checkout HEAD --` 取回，新写入的删掉；不再执行 `git reset --hard` 和 `git clean`。`--no-sync` 下失败不回滚；提交以后的失败（打包、推送）退出码 3，提交保留；提交刚做完、还没来得及记下就按了 Ctrl+C 的，也按提交以后处理，不再把已提交的新文件从工作区删掉。回滚日志只计实际取回和删掉的文件。
- 源目录里仓库没跟踪过的新文件要用 `--allow-new 路径` 逐个点名，点名的照样过闸门；文档教人生成的本机输出（`env-health.html`、`evidence/`、`*.wfw`、`*.jsonl`）和 `.gitignore` 忽略的文件不拷。
- 仓库里人工改过的文件（最后一次提交不是 `auto-update:` 开头）要被源目录覆盖或删除时停下列出；`--source-wins` 放行。
- 只删除已跟踪、源目录里已经没有的文件；仓库目录里没跟踪的和被忽略的本机文件不删不改。
- 本机打包改用 `git archive`，排除规则和发布工作流相同；日志列出新增、覆盖、删除的文件和 `git diff --stat`，被跳过的测试逐条写进日志，被 `.gitignore` 忽略而没拷的文件按顶层目录合并计数；打包失败时删掉 `.part`；版本号改从 `environment_report.KIT_VERSION` 取。
- 隐私闸门加固：识别 UTF-8/16/32 的 BOM 后再扫；协议名不分大小写，补了 `hy2`；带账号口令的 socks、http(s) 地址；不依赖本机用户名的用户目录路径规则（占位符和 `alice`、`john` 这类文档示例名放行，但当前账户名照查，只有 CI、容器和系统账户例外）；符号链接按它指向的路径文字扫描；不在允许清单里的邮箱和 noreply 背后的登录名；已跟踪或要加入的文件里任意层级的私有目录名（根目录下被 `.gitignore` 忽略的本机副本不再拦）；没有 BOM 的未知二进制文件直接拦下；扫描范围改为 git 已跟踪和这次要加入的文件，被忽略的不扫。闸门仍然只是辅助检查，不查的东西见 `AUTO-UPDATE.md`。
- `AUTO-UPDATE.md`：Windows 定时任务改成经 `cmd.exe` 把输出追加到日志文件，脚本写绝对路径，写明“起始于”不加引号、路径末尾不带 `\`、运行中别关弹出的窗口（关窗口、结束任务不会还原，以及之后怎样手工还原）、退出码 2 时怎样从日志分辨原因；手动运行改用 `py -3`。
- `.gitignore` 增加本机输出（根目录 `.html`、证据目录、防火墙备份和日志）、本机环境与编辑器杂项、私有资料目录。
- 新增 `test_auto_update.py`：在临时目录里建源目录、仓库和本机裸仓库来跑脚本；没有 `tools/` 或 `git` 时跳过。

### 统一体检（`environment_report.py`、`audit_client_boundary.py`、`inspect_unix_network.py`）

- 「默认路由与 IPv6 暴露面」：macOS 上带 `I` 标志的接口作用域默认路由不再算作可转发候选，单独计数；IPv6 同时有隧道和非隧道默认路由时，Linux 记 `unknown`，macOS 只有隧道分流路由覆盖 `2000::/3` 才算通过；IPv6 路由表读不到记 `unknown`，并和“内核没开 IPv6”分开；隧道网卡名补了 `ipsec`。
- Windows 的系统 DNS 检查要所有有解析器的网卡都满足才算通过，否则 `unknown`，说明里按“地址族 #接口编号”列出不满足的行（TUN 网卡、虚拟网卡和 IPv6 记录也算在内）；Windows 路由检查的说明写明没有采集接口类型。
- 本地 MCP 计数：计入 `~/.claude.json` 里 `projects.*.mcpServers`；给了 `--project-dir` 时计入项目的 `.mcp.json`（`audit_client_boundary.py` 也新增 `--project-dir`）；读取上限放到 32 MiB；读不了的配置单独计数，数到 0 而又有读不了的记 `unknown`；设了 `CLAUDE_CONFIG_DIR` 或 `--config-dir` 时也读该目录下的 `.claude.json`（客户端是否这样存放没有核对）。
- CLI 五个开关：`settings.json` 读不了（符号链接、过大、不是合法 JSON）、值认不出（例如 `on`）、进程环境和 `settings.json` 不一致时记 `unknown`，不再记缺口。
- 本地数据盘点有进不去的位置时记 `unknown`，提示可用 `--config-dir` 传真实路径。
- `--json-out`、`--html-out` 在 macOS 和 Linux 上写成只有自己能读写的文件（0600；Windows 上沿用所在文件夹的权限），两份输出都先生成再写盘，写不进去时报一行错；`--from-json` 遇到字段类型不对或超过 16 MiB 的文件报一行错（退出码 2），不再打出 traceback。
- HTML 体检单的范围说明写明包含宿主机时区、UTC 偏移与区域语言。
- JSON 新增字段：`clientBoundary.data` 里的 `localMcpBridges.claudeDesktopMcpUnreadableConfigCount`、`localMcpBridges.claudeCliMcpUnreadableConfigCount`、`localMcpBridges.projectMcpConfigInspected`、`cliSettingsReadState`、`cliAntiTelemetryUndetermined`；macOS 的 `network.data` 里的 `interface_scoped_route_count` 与 `tunnel_split_prefixes`。旧的报告 JSON 用 `--from-json` 照样能读。

### 备份（`claude_local_data.py`、`config_snapshot.py`）

- `claude_local_data.py` 的明文密钥检查覆盖面加宽：`.mcp.json` 参数列表里的每个字符串都查，认得 `--api-key 值`、`--token=值` 和请求头写法；`env`、`headers` 下按整词认 `TOKEN`、`KEY`、`SECRET`、`PASSWORD`、`PWD`、`PAT`、`COOKIE` 等，以及以 `Auth` 结尾的名字（如 `X-Auth`）；任何位置以 `token` 结尾的键名（`auth.token`、`apiToken`）；URL 里的 `用户:口令@`、`?token=` 和 `#access_token=`；常见密钥形状不再要求出现在开头；新增 PEM 私钥头；重复键两个值都查。`apiKeyHelper` 这类值是脚本路径的设置、权限规则里的命令名（如 `Bash(gh auth token:*)`）、`--key` 后面的文件路径、对环境变量的引用（`${变量}`、`$变量`、PowerShell 的 `$env:变量` 和 `${env:变量}`、cmd 的 `%变量%`）不再误报。藏在 URL 路径里的令牌、写成 JSON 数字的值、`-p` 这类短参数后面的值、hook 或 statusLine 命令里用空格隔开的 `--api-key 值`、命令里加了引号的赋值（`export API_TOKEN="…"`、`$env:API_TOKEN="…"`，常见密钥形状除外）仍然查不出来。
- 新的“名字=值”“名字: 值”扫描不把这些当成密钥：grep 或 rg 的匹配模式（值以 `|`、`\`、`(`、`[` 开头，如 `'token=|password='`、`'token=\w+'`）；冒号后面是几个词的提示文字（如 `echo 'Password: not stored here'`），但 `Authorization`、`Cookie`、`X-Api-Key` 等认证请求头和 `-H`/`--header` 后面的请求头照查；以 `limit`、`max`、`min`、`count`、`size`、`length`、`domain` 结尾的名字（`--token-limit=200000`、`TOKEN_LIMIT`、`COOKIE_DOMAIN`）。hook 或 statusLine 命令里的“名字=一个词”“名字: 一个词”仍可能误报，报错会列出键路径，确认后可加 `--allow-inline-secrets`。
- 不是严格 JSON 的 `settings.json`、`settings.local.json`、`.mcp.json`（带注释、尾逗号、非 UTF-8、嵌套过深）按“无法确认”拒绝，以前是静默放行；空文件照常通过，`audit_client_boundary.py` 和统一体检也把空文件当成“读到了、什么都没配”，不再记成读不了。
- `claude_local_data.py` 的快照先在一个和最终路径一样长的暂存目录里建好、校验，再改名发布：Windows 没开长路径时，以前可能在暂存目录里校验通过，改成更长的最终名字以后却打不开。路径超过 Windows 长度上限时，报错多一句说明（只说长度，不打印路径）。`config_snapshot.py` 的暂存方式没有改，发布名仍比暂存名长 1 个字符。
- 三个脚本（`config_snapshot.py`、`claude_local_data.py`、`refresh_allowlists.py`）打印路径时，遇到输出编码里没有的字（输出重定向或经管道时，繁体中文 Windows 用 cp950，没有简体字）改成 `\uXXXX` 输出，不再在备份、快照或预览已经做完以后报“stopped”。
- `--allow-inline-secrets` 照样检查、照样备份，并在 stderr 列出放过了哪些文件和键名；报错最多列 10 处“文件标签: 键路径”，不打印值。
- 备份成功后打印按文件名排除了几个条目（`.env*`、密钥和凭据文件、`.git`），`manifest.json` 新增 `excluded_secret_entries`；格式号仍是 2，新旧版本的快照互相读得回。
- 快照目录里多出的文件（例如 `.DS_Store`）在报错里点名；符号链接导致拒绝时说出处数和所在类别；两个工具的 `recover` 统一成“恢复目录不能在快照里面”，放快照的那个目录可以用。
- `claude_local_data.py audit` 在网络盘或同步目录上照常盘点，结果里注明 `network_or_synced_storage`；`backup` 仍然拒绝。
- Linux 挂载表：同一挂载点以后出现的记录为准，八进制转义全部解码，补了 ceph、glusterfs、virtiofs、vboxsf 等网络和共享文件系统。
- 超深嵌套、无法展开的 `~用户` 路径等引起的 `RuntimeError`、`RecursionError` 输出一行错误、返回 1。
- 导入时不再要求有家目录（默认备份目录用到时才计算）；`--backup-root` 的帮助写出默认位置；非 Windows 上 `restore --apply` 的报错提示改用 `recover`。

### 路由与移动端（`refresh_allowlists.py`、`mobile/`）

- Android 校验器：以前会打出 traceback 的输入（字段类型不对，比如 `domain` 写成数字、`outboundTag` 写成数组，或者嵌套过深）改为报一行错；以前能通过的文件照旧通过，检查没有加严（`domain`、`ip` 写成字符串而不是数组时照旧不一定报错）。通过时的文字改为实际检查的项目，并写明只做结构检查、不逐条比对。
- `refresh_allowlists.py`：拉到的网段和私网、CGNAT、链路本地、文档示例等保留段有重叠就拒绝（以前只拒绝完全落在保留段里的）；请求头不再带版本号。
- Shadowrocket 校验器的 `unsupported [General] setting` 报错补了一句检查范围。
- `mobile/README.md`：13 条规则逐条列出、没有兜底规则、导入前怎样备份和恢复、三端局域网直连写法的差别、域名策略没有实测、二维码容量、校验器实际查什么；iOS 模板改称“全代理模板”；出处改为公开链接。
- 测试：DoH 清单与代码里的清单一致；钉住 Android 紧凑版 JSON 和二维码的 SHA-256；去掉“文件存在才校验”。

### 文档与离线网页

- `WINDOWS-KILL-SWITCH.md`：断网开关一节先设执行策略（`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force`，不加 `-Force` 时 Windows PowerShell 5.1 会先问、默认答“否”），`Remove` 另给不依赖会话设置的写法；更新保护范围要先 `Remove` 再 `Install`，两步之间不受保护；虚拟网卡选不进保护范围；断网开关不导出 `.wfw`；LAN DNS Guard 的 `.wfw` 备份和日志在哪里、怎样导回、整份覆盖的后果；两个脚本的手工撤销与查看命令；参数表；断线演练各阶段和结果怎么读；5157 验收前先关 TUN；副作用集中列出；已知问题。
- README、代理指南、综合报告：代理指南里指向 LAN DNS Guard 副作用的链接改为指到那一节；README 补了 `refresh_allowlists.py` 的完整命令（输出目录放在仓库外）、Windows 上的 `py -3` 自检命令和备份的长路径说明；`.wfw` 备份只属于 LAN DNS Guard，“校验 SHA-256”改为“记录”；明文密钥检查只有 `claude_local_data.py` 有，备份一节补全各命令、默认位置和各平台实际查了什么；统一体检只报告是否装了桌面端，MSIX 放行规则看 `Inspect-WindowsFirewall.ps1`；三端规则的说法照实写；MSIX 防火墙冲突标为静态分析的推断；“39 个目标”的清单没有随仓库发布；手机端结论标明来自公开研究；测试项数不再写死；“全部公开链接”改为“主要背景来源”。`THIRD-PARTY-NOTICES.md` 里 `refresh_allowlists.py` 的上游改为它实际拉取的 `Loyalsoldier/clash-rules`。
- 离线网页：断网规划器的预览改用和脚本一样的规则名、端口区间与 `::/0`（`SchemaVersion` 2），规则数改为“共 N 条”；生成的命令改成和文档一样的 `Set-ExecutionPolicy -Scope Process … -Force` 加 `& .\Manage-WindowsKillSwitch.ps1 @settings`；卸载命令单独一块、单独复制；网卡名拒绝不可见字符和弯单引号；端口框清空时报错；本地存储被改坏时页面不再初始化到一半停下；勾选和切换后键盘焦点留在原处，选中的按钮加 `aria-pressed`；导出用本地日期；深色主题的主按钮改用深色字；按 Esc 收起小贴士；跟随系统的“减少动态效果”；清单页改称“参考 `PRIVACY-CHECKLIST.md` 整理”。
- 架构图：第 1 层补上 `environment_report.py`，去掉“加密盘”的说法和过时的版本号。
- `test_public_release.py` 新增检查：Markdown 里的 HTML 链接和页内锚点、离线网页的本地链接和脚本用到的元素、发布包里会断的链接（指向 `export-ignore` 的路径）、公开文件不得引用私有研究资料、网页断网预览与 `build_kill_switch.py` 整张规则表对账、网页命令里预览安装和卸载分开、各处版本号一致。
- CI：`tests.yml` 的注释照实写测试矩阵，加 20 分钟超时，`checkout` 不保留凭据。

### 已知问题（下一个版本修，要在 Windows 真机上验证）

这一版没有改任何 `.ps1`，下面几条照旧存在，手工处理办法见 [WINDOWS-KILL-SWITCH.md](WINDOWS-KILL-SWITCH.md) 的「已知问题」：

- 两个管理脚本的目录权限检查掩码算错，工具包放在 `C:\Program Files` 下时 `Install`、`Remove` 都被拒。
- 断网开关 `Remove` 只删名字、规则组、描述都对得上的规则，可能输出 `removed` 而同组规则还在，输出也不带 `ForeignOrUnexpectedRules`。
- LAN DNS Guard 的 `Install` 中途失败时不恢复原有规则；同组里有对不上的规则时整体拒绝卸载。
- `Test-ProxyState.ps1` 默认把 IPv4 和 IPv6 混在一起预检。
- 虚拟网卡选不进保护范围，建了外部虚拟交换机以后是否仍然覆盖没有实测，`Install`、`Status` 也不发警告。
- 其余较小的：DHCP 检测查不到接口时按没开处理、上游和 DHCP 同址时无法安装、两种“物理网卡”口径、OneDrive 目录和非 NTFS 卷的处理、PowerShell 与 Python 规划器的细节差异、`Install` 和 `Status` 的标准输出没有脱敏、两份管理脚本的同名函数和流程走样、防火墙体检的分类正则、隧道网卡正则各写一份、部分报错不够具体。

### 没有验证的

- PowerShell 脚本只在 CI 的 windows-latest（英文系统）上做过语法解析，并运行了两个管理脚本的 `Preview` 和验收脚本的一项参数检查；`Install`、`Remove`、`Status` 没有在 Windows 上运行过，离线网页生成的命令也没有在 PowerShell 里执行过。
- 没有 Mac 真机：macOS 的路由判定只用合成的 `netstat` 输出测过。
- 没有联网核对域名和网段清单（30 项生态条目、`160.79.104.0/21`、两个 IPv6 前缀）现在是否仍然准确，也没有核对上游名单会不会被新的网段检查误拒。
- 自动同步的新保护只在临时仓库里测过，没有在作者的机器和定时任务上跑过，也没有真推到 GitHub。
- 全套测试由 CI 在 ubuntu-latest 的 Python 3.10、3.13 和 windows-latest 的 Python 3.13 上跑（以合并前最后一次 CI 结果为准），本地另在 Linux 上用 Python 3.11、3.12、3.13 跑过。没有在中文（繁体或简体）Windows 上跑过：代码页、长路径、目录联接、文件名大小写这几类 Windows 情况是用模拟测的，`AUTO-UPDATE.md` 里把输出写进日志的 Windows 定时任务配法也没有在任务计划程序里实际建过。
- 离线网页没有在真实浏览器里打开过：焦点和深色主题对比度是按代码和公式核对的。
- 客户端的行为（Claude Code 的设置名和配置存放位置、v2rayNG 导入规则集是替换还是追加等）是凭了解写的，没有核对。

## 2026-11-24 文档修订（适用 v0.4.1）

- 公开综合报告核对 Cage 的 WebGL 错误与两次客机网关事件，区分租约计时、从网关未开放到恢复任务结束的日志间隔，以及用户实际断网时长。
- 检查清单、代理指南与离线工作台加入网页登录分步排查，记录提示原文、首次可见时间和对照结果。个案中的账号处置类型和原因仍为未知。

## v0.4.1（2026-11-23）— 统一三态体检单与工程边界补强

- **合并客户端边界审计与三态安全摘要**：`environment_report.py` 现自动合并 `audit_client_boundary.py`，新增 10 项三态核验摘要（`pass` 已通过 / `gap` 存在缺口 / `unknown` 未知盲区）与三层证据分级（`observed_local` / `static_config` / `external_blind_spot`），强制把外部出口 IP 信誉、运行态 GPU/TPM 健康度与平台地区政策显式标为 `unknown`。
- **一键导出离线可打印 HTML 体检单**：`environment_report.py` 新增 `--html-out`、`--json-out`、`--from-json` 与 `--quiet` 参数，输出零外部 CDN、全量 HTML 转义、支持直接打印存 PDF 的单文件离线体检单（拒绝通过符号链接写入）。
- **本地 MCP 桥接只读盘点**：`audit_client_boundary.py` 新增 `--config-dir` 参数与 `localMcpBridges` 字段，只读统计 Desktop/CLI 本地 MCP Server 配置数量（绝不输出名称、命令、参数或密钥）并在配置存在时提醒复核宿主机跨界元信息。
- **补强文档、清单与交互工作台**：在 `PRIVACY-CHECKLIST.md`、`docs/CLIENT-BOUNDARY-AND-LEAK-REPORT.md`、`CLAUDE-PROXY-OPTIMIZATION-GUIDE.md` 与 `docs/index.html` 中增补本地 MCP 桥接自查、出口 IP 历史信誉盲区提示、第 6 条误区（「网络层零泄露 ≠ 虚拟化/运行态无异常」的工程权衡）及对应交互检查项，并修正 UI 中 Unix 体检命令示例。

## v0.4.0（2026-11-23）— MIT 公开开源版

- **正式以 MIT 许可公开发布**：新增根目录 [LICENSE](LICENSE)（Copyright (c) 2026 Celeste）与清晰的 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。
- **清理第三方原文镜像并重写干净版综合报告**：彻底移除此前私有备份中包含第三方原文和微信文章的 `research-reports/` 镜像目录，并重建干净的提交历史；将全部跨端客户端边界、独立四层实测数据、五大常见误区纠偏与工具包落地映射整合为一份干净原创报告 [docs/CLIENT-BOUNDARY-AND-LEAK-REPORT.md](docs/CLIENT-BOUNDARY-AND-LEAK-REPORT.md)。
- **全新离线交互式展示与配置工作台 UI**：新增零外部依赖、可在线（GitHub Pages）亦可本地离线打开的 [docs/index.html](docs/index.html)（含路由生成器、Windows 断网开关与 LAN DNS 规划器、可持久化跨端隐私自检清单、原创实测报告阅读器，以及协作伙伴 **哈基米 (Gemini)** 署名与互动小助手）。
- **项目展示与工程基建对齐**：补齐统一风格的矢量图标（`docs/images/logo.svg`）、架构总览图（`docs/images/architecture-cover.svg`）、哈基米徽章（`docs/images/hajimi-mascot.svg`）、GitHub Actions 跨平台自动测试（`.github/workflows/tests.yml`）与版本发布工作流（`.github/workflows/release.yml`）。
- **公开仓库安全同步闸门**：升级 `tools/auto_update.py`，默认排除本机私有的 `research-reports/` 与镜像目录，并在隐私闸门中新增版权镜像拦截，防止后续每周自动同步误把私人资料推上公开仓库。

## v0.3.8（2026-11-23）— 外部审查修复版

- **修复 Linux 测试失败**：`test_claude_local_data.py` 的 `Path.open` 桩放行 `/proc/mounts` 挂载表读取，消除 Linux 下误报。
- **修复断网开关 DHCP 检测与 PowerShell 5.1 崩溃**：`Manage-WindowsKillSwitch.ps1` 新增 `Get-DhcpEnabledAliases`，所选网卡启用 DHCP 且未指定 `-DhcpServer` 时 `Preview` 发出告警、`Install` 拒绝安装；同时修复不带 `-DhcpServer` 时 `$dhcpAddressInts` 为 `$null` 在 PowerShell 5.1 严格模式触发崩溃的既有缺陷。
- **补全副作用与校验范围说明**：在 `WINDOWS-KILL-SWITCH.md`、`CLAUDE-PROXY-OPTIMIZATION-GUIDE.md`、`PRIVACY-CHECKLIST.md`、`README.md` 与 `mobile/README.md` 中补全路由器 DNS 旁路防护在关代理后的解析副作用，以及静态路由校验的范围边界。

## v0.3.7（2026-11-23）— 脱敏与移动端细节补全

- 清理旧报告中残留的本机路径标识；使 `build_routing.py` 帮助文案中的域名计数动态计算。
- 补充 Android 保活、开机自连、改设置后重启服务、网页认证 Wi-Fi 冲突与应用分身边界说明。

## v0.3.6（2026-11-23）— 全端实测补强

- 将 `CLAUDE_ECOSYSTEM_DOMAINS` 与 `claude-doh-domains.txt` 扩充至 30 项，补齐实测发现的外围与 Artifact 预览域名。
- `audit_client_boundary.py` 新增 5 项 CLI 防后台外联环境变量核查；`Inspect-WindowsFirewall.ps1` 新增 MSIX 显式出站放行规则检测。
- 更新 Android 13 条路由规则与配套离线二维码。

## v0.3.4 ~ v0.3.5（2026-11-22）— 跨平台安全加固基线

- 建立 `Manage-WindowsLanDnsGuard.ps1` 与 `build_lan_dns_guard.py` 物理网卡防路由器 53 端口旁路方案。
- 强化 `config_snapshot.py` 与 `claude_local_data.py` 的本地卷策略、符号链接拒绝、明文密钥拦截与 Windows 私有 NTFS ACL。
