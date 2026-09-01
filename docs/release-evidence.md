[简体中文](release-evidence.md) | [繁體中文](release-evidence.zh-TW.md) | [English](release-evidence.en.md)

# 结构化发布证据

AgentGuard 的严格发布门禁不再把“某个文件里出现了关键词”当作证据。需要凭据或真机的八类检查必须提供结构化 JSON，并绑定**当前完整提交号**以及现场重算的产物摘要：普通发布文件使用标准 SHA-256，macOS `.app` 使用整个 bundle 的确定性 tree-v2，验收报告使用包含报告与逐项材料的 acceptance-closure-v1。这能降低误绑定、误操作和部分机械伪造风险，例如误传脚本、空产物、未修改模板或与当前候选无关的旧报告。

> 这仍是未签名的本地自证，只能防误绑定、误操作和部分机械伪造。能控制工作区的人仍可伪造所有字段或替换产物；抵抗这种攻击需要由可信执行器签发并验证的证据签名，属于后续阶段。证据 JSON 通过不等于安装包已可发布。

## 八类证据

| `kind` | 判据 | 环境变量 |
|---|---|---|
| `macos_codesign` | `codesign --verify --deep --strict --verbose=4` 成功，并读取同一产物的签名身份 | `AGENTGUARD_EVIDENCE_MACOS_CODESIGN` |
| `macos_notarize` | `notarytool` 返回 Accepted，且 staple 验证成功 | `AGENTGUARD_EVIDENCE_MACOS_NOTARIZE` |
| `windows_sign` | `signtool verify /pa /v` 成功 | `AGENTGUARD_EVIDENCE_WINDOWS_SIGN` |
| `android_sign` | `apksigner verify --print-certs` 确认发布证书而非 debug 证书 | `AGENTGUARD_EVIDENCE_ANDROID_SIGN` |
| `acceptance_macos` | macOS 真机清单完成 | `AGENTGUARD_EVIDENCE_ACCEPTANCE_MACOS` |
| `acceptance_android` | 开启无障碍服务的 Android 真机产生签名信封，桌面端以注册公钥验签且判决符合预期 | `AGENTGUARD_EVIDENCE_ACCEPTANCE_ANDROID` |
| `acceptance_firefox` | Firefox 真机清单完成 | `AGENTGUARD_EVIDENCE_ACCEPTANCE_FIREFOX` |
| `acceptance_windows` | Windows 真机清单完成 | `AGENTGUARD_EVIDENCE_ACCEPTANCE_WINDOWS` |

## JSON 约束

每份证据都包含以下字段：

```json
{
  "schema": "agentguard-release-evidence-v1",
  "kind": "acceptance_firefox",
  "signer": null,
  "commit": "完整的 40 位 Git 提交号",
  "command": "target/release/guard-cli manual-acceptance firefox docs/acceptance-firefox.md evidence/firefox/report.md --repo-root .",
  "exit_code": 0,
  "timestamp": "RFC 3339 时间",
  "output": "AGENTGUARD_ACCEPTANCE_FIREFOX=PASS",
  "artifact": {
    "path": "evidence/firefox/report.md",
    "sha256": "普通文件、.app tree-v2 或验收 closure-v1 的 64 位 SHA-256"
  }
}
```

验证器要求：

- `--file` 指向的证据 JSON 必须是可读 UTF-8、大小不超过 1 MiB 的普通文件，文件本身不能是符号链接；schema 之外的未知字段也会被拒绝。
- `commit` 必须是门禁正在检查的完整提交号，不能是短哈希或其他候选。
- 四类签名证据的 `signer` 必须是非空字符串，并与门禁从证据 JSON 之外取得的预期发布者身份一致；四类验收证据的 `signer` 必须是 `null`，且直接调用验证器时禁止传 `--expected-signer`。
- `command`、`timestamp` 和 `output` 必须替换模板占位符，`exit_code` 必须为 `0`；时间采用有效 RFC 3339 格式，校验时必须处于过去 30 天至未来 10 分钟的窗口内，并且不能早于 HEAD 提交时间（允许 10 分钟时钟误差）。`command` 必须逐字包含同一 `artifact.path`，防止命令验证 A、证据却绑定 B。
- `artifact.path` 必须是仓库根目录下的相对路径，只用 `/` 分隔；每个组件必须匹配可移植 ASCII `[A-Za-z0-9._-]+`，且不能是 `.` 或 `..`。绝对路径、反斜线、空白、shell glob/展开字符和控制字符都会被拒；目标及其任一路径组件也不能是符号链接。普通文件必须非空；两个 macOS kind 还接受至少包含一个非空普通文件的 `.app` 目录，但 bundle 内任一符号链接、特殊文件或非 UTF-8 路径都会 fail-closed。
- 验证器会现场重算摘要并与 `artifact.sha256` 比较。普通**非验收**文件使用标准 SHA-256；`.app` 使用带 `agentguard-tree-sha256-v2` 域分隔符的确定性摘要。tree-v2 绑定 bundle 根目录及每个条目的 Unix `0111` 可执行位掩码，并按 UTF-8 相对路径字节排序绑定条目类型、路径长度/路径、文件长度与内容；它不绑定其他 mode 位、xattr 或 ACL。在不提供 POSIX mode 的系统上不能据此声称已观测到真实可执行位。tree-v2 也不证明 quarantine/Gatekeeper 或首次启动行为，正式候选仍必须在隔离机上以下载后的实际包完成首次启动验收。
- 四类签名证据的 `command` 必须无 `#`、PowerShell 或 batch 注释，并采用校验器接受的精确、fail-closed 成功链。macOS 代码签名必须是 `codesign --verify --deep --strict --verbose=4 ARTIFACT && codesign -dv --verbose=4 ARTIFACT`；Windows 必须先执行 `signtool verify /pa /v` 并检查 PowerShell `$?` 与 `$LASTEXITCODE`，再对同一文件执行 `Get-AuthenticodeSignature`、验证状态/证书并现场输出指纹；Android 只接受单段 `apksigner verify --print-certs ARTIFACT`。产物必须位于 `evidence/`、`dist/`、`target/release/`，或 `apps/**/dist/`、`apps/**/target/release/`、`apps/**/build/outputs/` 的发布产物路径；`macos_codesign` 只接受 `.app`/`.dmg`，`macos_notarize` 接受 `.app`/`.dmg`/`.pkg`，Windows 接受 `.exe`/`.msi`/`.msix`，Android 只接受 `.apk`。
- 公证前先在仓库外执行 `xcrun notarytool store-credentials AgentGuard-Notary --apple-id "$APPLE_ID" --team-id "$AGENTGUARD_EXPECTED_MACOS_TEAM_ID"`，按安全提示交互输入 app-specific password，把凭据写入登录钥匙串；不要把密码放进命令参数，密码或 API 私钥也不得写入仓库、JSON `command` 或证据日志。`.app` 公证必须按 `ditto -c -k --keepParent APP ZIP` → `xcrun notarytool submit ZIP --wait --team-id <Team ID> --keychain-profile AgentGuard-Notary` → `xcrun stapler staple APP` → `xcrun stapler validate APP` 的四段 `&&` 成功链执行；`.dmg`/`.pkg` 则省略 ditto，直接对同一 `artifact.path` 执行后三段。ZIP、artifact 与逐项证据路径都服从上述可移植 ASCII 组件规则；`--team-id` 和 `--keychain-profile` 都必须恰好出现一次。
- 签名类 `output` 除成功信号外还必须绑定证书身份：codesign 包含 `valid on disk`、`satisfies its designated requirement` 与精确行 `TeamIdentifier=<10 位 Team ID>`；notarytool 包含 Accepted 状态且 stapler 包含 `validate action worked`；Windows 包含 `Successfully verified` 与精确行 `CertificateSHA256=<64 位十六进制摘要>`；Android 包含 `Signer #1 certificate SHA-256 digest: <证书指纹>`。Android 输出若出现 `Android Debug` 会被拒绝。
- 四类验收证据分别只接受 `evidence/macos/`、`evidence/android/`、`evidence/firefox/`、`evidence/windows/` 前缀下、大小不超过 16 MiB 的 `.md` 报告。`command` 必须是实际成功执行的单段 `guard-cli manual-acceptance <平台> <清单> <artifact.path> --repo-root .`；清单依次为 `docs/acceptance-macos.md`、`docs/acceptance-runbook.md`、`docs/acceptance-firefox.md` 与 `docs/acceptance-windows.md`，其标准输出标记写入 JSON `output`。
- 校验器会解析 Markdown 表：Firefox 必须恰好包含 F1–F8，Windows 为 W1–W7，Android 为 A1–A4，macOS 为 1、2、3、4、5、5b、5c 与 6–14。每个 ID 必须恰好一行，第二列精确为 `PASS (native)`，第三列必须是对应平台目录下的仓库相对路径：`evidence/firefox/`、`evidence/windows/`、`evidence/android/` 或 `evidence/macos/`。逐项路径不得被其他用例复用；每个组件须匹配 `[A-Za-z0-9._-]+`，并继续拒绝空组件、`.`、`..`、绝对路径、反斜线、空白、shell glob/展开字符、冒号与控制字符。缺失、重复、`PASS (sim)`、FAIL、BLOCKED 或 N/A 都会被拒。报告正文和 JSON 的 `output` 还必须有一整行与 kind 对应的精确标记 `AGENTGUARD_ACCEPTANCE_<平台>=PASS`，且只能在上述条件全部满足后写入。

验收类 `artifact.sha256` 使用 `agentguard-acceptance-closure-sha256-v1`：它绑定报告原始 bytes，并按路径排序绑定每个唯一逐项引用的相对路径、长度与文件内容。任一报告或引用材料变化都会改变摘要。这个闭包仍是未签名本地自证，只证明校验时这些 bytes 被一起绑定，不能证明截图、日志或设备数据的真实来源；可信来源证明仍需后续签名执行器或外部见证。

验收标记逐项为 `AGENTGUARD_ACCEPTANCE_MACOS=PASS`、`AGENTGUARD_ACCEPTANCE_ANDROID=PASS`、`AGENTGUARD_ACCEPTANCE_FIREFOX=PASS` 与 `AGENTGUARD_ACCEPTANCE_WINDOWS=PASS`。

### 签名者身份来源

签名 JSON 不能自行决定谁是可信发布者；严格门禁从外部配置读取预期身份，并把它传给验证器的必填参数 `--expected-signer`：

| `kind` | `signer` 格式 | 外部预期值 |
|---|---|---|
| `macos_codesign`、`macos_notarize` | 同一个 10 位 Apple Team ID | `AGENTGUARD_EXPECTED_MACOS_TEAM_ID` |
| `windows_sign` | 发布证书的 64 位 SHA-256 指纹 | `AGENTGUARD_EXPECTED_WINDOWS_CERT_SHA256` |
| `android_sign` | 发布证书的 64 位 SHA-256 指纹 | `AGENTGUARD_EXPECTED_ANDROID_CERT_SHA256` |

Windows 与 Android 指纹输入可含大小写或冒号，验证前会规范化为 64 位十六进制值；JSON 的 `signer`、命令输出里的证书身份和外部预期值必须指向同一个发布者。四个验收 kind 不接受外部 signer。

Windows 可在已配置 `signtool` 的 Developer PowerShell 中执行下面这一整行；把路径在命令的两处和 JSON 的 `artifact.path` 中同步替换。命令先让 `signtool` 验证信任链，再从同一文件读取 Authenticode 证书并输出验证器要求的独立指纹行；不能把 `<指纹>` 文字直接写成成功输出。

```powershell
signtool verify /pa /v dist/AgentGuard.exe; if (-not $? -or $LASTEXITCODE -ne 0) { exit 1 }; $signature = Get-AuthenticodeSignature dist/AgentGuard.exe; if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) { exit 1 }; Write-Output ('CertificateSHA256=' + $signature.SignerCertificate.GetCertHashString('SHA256'))
```

## 生成、填写与复核

先冻结待发布提交，确认索引和所有非 ignored 工作树文件为 clean，再生成故意无效的模板：

```bash
mkdir -p evidence/firefox
commit="$(git rev-parse HEAD)"
commit_time="$(git show -s --format=%ct HEAD)"
cargo build --release -p guard-cli
cargo run -p guard-cli -- evidence-template --kind acceptance_firefox \
  --commit "$commit" > evidence/firefox/evidence.json
```

模板只是字段清单，未填写时必须验证失败。执行真机验收，把报告保存为例如 `evidence/firefox/report.md`。先实际运行人工验收校验并取得唯一 marker，再用同一入口计算报告闭包摘要；把精确命令、marker 与摘要填入 JSON 后显式复核：

```bash
target/release/guard-cli manual-acceptance firefox docs/acceptance-firefox.md \
  evidence/firefox/report.md --repo-root .
# 成功时唯一输出：AGENTGUARD_ACCEPTANCE_FIREFOX=PASS

cargo run -p guard-cli -- evidence-digest \
  --repo-root . --path evidence/firefox/report.md

cargo run -p guard-cli -- evidence-verify \
  --kind acceptance_firefox \
  --file evidence/firefox/evidence.json \
  --commit "$commit" --commit-time "$commit_time" --repo-root .

export AGENTGUARD_EVIDENCE_ACCEPTANCE_FIREFOX=evidence/firefox/evidence.json
bash scripts/release-gate.sh --strict
```

`.app` 必须用同一个 `evidence-digest` 入口计算 tree-v2 摘要，不能用内部 Mach-O 的 SHA-256 代替。先在仓库外设置 `AgentGuard-Notary` 钥匙串 profile（不要记录密码），再执行例如：

```bash
xcrun notarytool store-credentials AgentGuard-Notary \
  --apple-id "$APPLE_ID" \
  --team-id "$AGENTGUARD_EXPECTED_MACOS_TEAM_ID"
# 根据安全提示交互输入 app-specific password；不要把密码放进命令参数或日志。

app=apps/desktop-macos/src-tauri/target/release/bundle/macos/AgentGuard.app
zip=evidence/macos/AgentGuard.zip
ditto -c -k --keepParent "$app" "$zip" && \
  xcrun notarytool submit "$zip" --wait --team-id "$AGENTGUARD_EXPECTED_MACOS_TEAM_ID" \
    --keychain-profile AgentGuard-Notary && \
  xcrun stapler staple "$app" && \
  xcrun stapler validate "$app"
cargo run -p guard-cli -- evidence-digest --repo-root . --path "$app"
```

JSON 的 `command` 应记录上述变量展开后的仓库相对路径单行命令，不能记录 `$app`/`$zip` 占位形式。

其他七类按上表替换 `kind` 与环境变量。不要手工把校验器本身、空目录或旧提交报告填进变量。

直接复核签名证据时还必须显式提供外部预期身份，例如：

```bash
expected_signer="${AGENTGUARD_EXPECTED_MACOS_TEAM_ID:?set the production Team ID}"
cargo run -p guard-cli -- evidence-verify \
  --kind macos_codesign \
  --file evidence/macos/codesign.json \
  --commit "$commit" --commit-time "$commit_time" --repo-root . \
  --expected-signer "$expected_signer"
```

`evidence/` 是 ignored 的本地证据工作区，只能在候选提交冻结后生成，不能提交进该候选，否则 `HEAD` 改变后原有 commit 绑定立即失效。严格门禁会在开始和结束时分别核对 `HEAD`、索引与所有非 ignored 工作树文件；结束时仍存在的 `HEAD` 或非 ignored 漂移会失败，ignored 的 `evidence/` 不计入脏工作树。起止快照不能证明受控工作区没有被并发对手瞬时修改后恢复，这仍属于未签名本地自证的边界。门禁通过后应把证据只读归档到受控位置；敏感日志、截图、账号或设备标识不得默认推送到 GitHub。

## 发布边界

严格门禁还要求 production preflight 零 `FAIL`。即使八份 JSON 都通过，只要仓库夹具密钥仍用于生产语义、自动门禁失败，或签名/公证/真机/全新安装/升级与回滚证据不完整，结论仍是 **No-Go**。目前尚未配置正式 Apple Team ID、Windows 发布证书 SHA-256 与 Android 发布证书 SHA-256，四类签名检查保持 `UNVERIFIED`；仓库也尚未提供完整的公证、真机、升级与回滚证据。因此不能宣称阶段已闭环或可发布。
