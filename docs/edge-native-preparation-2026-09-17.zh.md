# Edge 正式版验收准备与首次启动确认

日期：2026-09-17。源码基线 `f4834812a7cf5842835b07cb02f9570015fac6b4`，该提交的 [CI 35126965648](https://github.com/gcsagroup/agentguard/actions/runs/35126965648) 已终态成功，13 项作业全部通过。本轮完成正式浏览器准备；**扩展尚未加载，Edge B1–B5 均未完整通过，发布仍为 No-Go。**

## 已准备的准确浏览器

从[微软官方发布接口](https://edgeupdates.microsoft.com/api/products?view=enterprise)选取 Stable／MacOS／universal 的 `153.0.4234.32`，保留完整接口响应及选中元数据。官方 PKG 为 429,856,524 字节，SHA-256 为 `8ccdfd126c8e80411108c8ec45cbc610779a08c54285d02d48681e8d8afed529`。

下载字节数与官方摘要逐项核对；安装包签名为 Microsoft Corporation，Team ID `UBF8T346G9`，Gatekeeper 安装评估为 `accepted / Notarized Developer ID`。展开包后，将原始签名 App 放入 `/Users/lazy/Applications/Microsoft Edge.app`，没有重签，没有执行需要 root 的安装脚本。放置前后的深层严格签名校验，以及最终 App 的 Gatekeeper 执行评估均通过。这是可启动浏览器的准备证据，不是完整 PKG 安装器／更新器验收。

已有 Edge 默认资料保留。启动参数明确使用独立路径 `/Users/lazy/Library/Application Support/AgentGuard Browser Acceptance/Edge`，该路径此前不存在；未登录或导入日常资料。未设置扩展加载或跳过首次启动的参数。

## 当前实际停点

Computer Use 已取得准确 Edge 原生首次启动窗口“欢迎使用 Microsoft Edge”。窗口显示使用条款链接和“启动 Microsoft Edge”按钮。已取消“设为默认浏览器”和“发送可选诊断数据”两项勾选，未点击启动按钮。

当前条款明确约定使用软件即表示同意。Computer Use 的确认规则要求接受 EULA 时取得用户明确同意，因此已提出具体确认，不能以此前笼统的测试授权或直接修改资料文件绕过该步骤。确认前不执行依赖启动完成的扩展安装和行为验收。

前轮[Chrome 控制限制](chrome-native-preparation-2026-09-17.zh.md)与本轮许可确认是两个独立问题；前轮失败仍保留。B4 还缺少已确认的上一公开版本，不能用本地旧 ZIP 冒充公开版本。

## 独立准备和验证

- 两端仍使用同一候选 ZIP，SHA-256 为 `67b34bbedbb77bed07c5cb6ae99b11a7ad12b3a53650496cce686bde6e2e49e2`。23 个包文件与当前源码、既有解压副本逐项一致；本轮没有重新打包。
- 已准备只监听 `127.0.0.1` 的原生验收夹具服务器。七份既有 HTML 保持原字节，另将 F5d 的两个普通请求变成可点击按钮；记录请求的原始路径、解码路径、正文长度与摘要。自测 14 项通过，覆盖原字节响应、模拟终点计数、编码、嵌套查询、非法路径和只读计数接口。自测结束已关闭服务器。它验证的是验收辅助脚本，**没有证明扩展阻断成功**。
- 固定 AgentGuard App 024 的 91 个文件和模式与冻结清单完全一致；实际原生界面显示两项权限已授权、未在守护，活动记录有秒及时区，安装正文仍显示“这条观察记录不证明实际发起了安装”。没有启动新桌面观察会话。
- 仓库不变量 23 项通过；官方摘要、包大小、App 版本、证据摘要及文档链接核对通过。没有生成正式 `PASS (native)` 报告或发布证据。

原始官方元数据、包、签名、公证、原生界面读回摘要、夹具和自测位于 `.artifacts/edge-native-2026-09-17/`；公开摘要与文件哈希见[证据索引](evidence/edge-native-preparation-2026-09-17.json)。后续继续使用上述固定 Edge 路径和独立资料。F13 暂缓、AGD-027 原性能预算、AGD-031 条件及 19 类正式发布材料要求保持；任务计数仍为 28／1／1／2。
