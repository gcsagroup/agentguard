# AgentGuard 隐私说明草案

[简体中文](privacy-policy.md) | [繁體中文](privacy-policy.zh-TW.md) | [English](privacy-policy.en.md)

新增默认关闭的实验性网页邮箱模块：开启后仅在候选 Gmail/Outlook 页面本地读取可识别的主题、正文、收件人字段及附件存在状态。邮件专项记录仅保留固定风险类别、阻断状态、时间、站点来源和 Gmail/Outlook 固定名称；不存正文、主题、地址、附件名或完整链接，不读取附件内容，不调用邮箱 API 或转发到桌面端。模块不能阻止邮箱自身草稿同步、直接 API 或其他未覆盖路径；关闭仅停止邮件专项，既有付款规则保持启用。

- **最后更新：** 2026-09-07
- **产品版本：** 1.0.0-rc.1
- **适用范围：** macOS、Windows、Android 伴生应用、iOS WebShield/Safari Extension、首个 GA 的 Chrome/Edge Chromium 扩展、CLI 与本地 API

> 这是随源码提供的技术披露草案，不是已经完成法务审阅的正式隐私政策。公开分发前必须补充有效的运营主体、联系地址、适用地区和数据保留条款。

Firefox manifest 与 Native Messaging host 只作为仓库源码原型保留，不在首个 GA 浏览器包、商店提交或本隐私声明的发布能力范围内。iOS WebShield 是首发产品范围内的独立 Xcode/Swift Safari Extension，不是 Chromium 扩展的 Safari 打包。

## 摘要

AgentGuard 默认在本机处理观测数据，不提供默认云端账户、遥测或厂商上传服务。用户或企业可以主动配置威胁情报、策略同步、Android 中继或本地 API；这些连接的目标、传输安全和数据保留由实际部署配置决定。

| 数据 | 默认是否离开设备 | 说明 |
|---|---|---|
| UI / AX / UIA / Accessibility 文本 | 否 | 仅在内存中用于本地规则判断；默认不把原文写入持久化审计记录 |
| ScreenCaptureKit / GDI 帧 | 否 | 在本机提取摘要或视觉特征；默认不上传原始像素 |
| 浏览器 DOM 信号 | 否 | 在扩展内扫描；有限的发现摘要与最小化 URL 可保存在扩展本地，不发送给 Native Host 或厂商服务 |
| iOS Safari 页面事件 | 否 | 内容规则和原生合同在本机执行；只保留规则/动作枚举、时间和缩减到 origin 的 HTTP(S) URL，默认无上传 |
| 审计数据库 | 否 | 桌面发布版强制 SQLCipher；CLI/开发构建可显式使用普通 SQLite |
| 威胁情报与企业策略 | 可选下载 | 仅在部署方配置端点后访问；发布路径要求签名验证 |
| Android 中继 | 可选 | 用户可配置 loopback、ADB reverse 或 LAN 地址 |
| 崩溃遥测与广告追踪 | 否 | 当前源码候选未集成默认遥测或广告 SDK |

## 本机处理的数据

1. 无障碍树、窗口与表单文本，用于识别支付、隐私过度披露、注入和可疑界面。
2. 浏览器 DOM 信号，用于本地检测隐藏文本、隐私陷阱，并在覆盖的付款/提交动作执行前进行 block-only 阻断。
3. 屏幕帧或帧摘要，用于透明浮层、低对比度内容、隐写与帧变化检测。
4. 网络流元数据，例如主机名和粗略大小；AgentGuard 不是完整抓包工具。
5. 审计记录，例如事件类型、规则编号、判决、固定安全摘要与人工确认结果。持久化事件采用 `persistable_event_v1`：布尔值、数值、枚举、受限标识符及经格式校验的摘要；URL 只保留 scheme 与规范化 host，非 HTTP(S) URI 只保留 scheme，环境清单只保留数量。原始 UI/OCR/剪贴板文本、路径、命令操作数、URL userinfo/path/query/fragment、自由文本理由及未知字段不落库。
6. Android 环境调查结果，例如其它可读输入的广播接收器或无障碍服务。
7. iOS Safari Extension 的合同版本、随机 request ID、规则 ID、固定 finding/action 枚举、时间和当前 URL。Swift 在落盘前再次校验并把 URL 缩减为 HTTP(S) origin；原始 DOM、输入值、页面标题和 URL path/query/fragment 不落盘。

## 典型存储位置

- macOS：`~/Library/Application Support/agentguard/`
- Windows：应用数据目录中的本地审计与配置文件
- Android：应用私有目录中的 JSONL 信封、偏好和 Android Keystore 密钥
- iOS：App Group `group.com.agentguard.webshield` 中的原子 JSONL 审计和同意/开关；最多保留 7 天或 500 条，用户可清除，读取时也会物理删除过期行
- Chrome/Edge Chromium 扩展：扩展本地存储；最近记录中的 URL 会移除 userinfo、query 与 fragment，并遮蔽形似令牌的路径段

Core/桌面审计中，没有经格式校验的应用来源会保存为稳定 SHA-256 伪名；外部会话 ID 也只保存稳定伪名，以支持同一数据库内关联而不保留原始 ID。此哈希不是匿名化承诺；低熵标识仍可能被猜测，因此导出审计文件仍应按敏感本地数据保护。

该最小化只适用于新写入。旧版本已经写入的历史行不会自动改写（否则会破坏原有哈希链和签名），在完成经批准的清空或迁移前仍须视为可能包含原始观察内容。

Android Keystore 中的适配器私钥按设计不可导出。macOS 发布版把审计加密口令与 Ed25519 种子分开存入当前用户 Keychain；Windows 发布版使用两个当前用户 DPAPI envelope。CLI/开发路径仍可显式使用 `0600` 文件型签名密钥，能读取该文件的账户或 root 可导出。Keychain/DPAPI 也是本机静态保护，不等同于 Secure Enclave/TPM 不可导出。仓库中的公开测试密钥仅供夹具与评测，不能用于生产。

## 网络行为

- 核心规则判断默认不需要互联网。
- 威胁情报和企业策略只在用户或组织配置端点后下载。
- 本地 API 默认绑定 loopback 并要求 Bearer token；只有显式使用 `--allow-lan` 才允许 LAN 绑定。LAN 例外可能是明文 HTTP，部署方必须自行提供受信网络或额外传输保护。
- Android 中继由用户主动配置；发送内容和目标取决于该配置。
- 首个 GA 的 Chrome/Edge 扩展不申请 Native Messaging 权限，也不连接 AgentGuard 云服务。静态 DNR 由浏览器本地按 URL、方法与资源类型匹配；它不会读取 HTTPS 请求体。
- iOS WebShield 没有上传端点、`connectNative` 长连接或远程 DNR 情报；App 与 Safari Extension 通过本机 App Group/原生消息交换最小化事件。

## 权限与控制

- macOS：辅助功能与屏幕录制；拒绝权限会降低覆盖，应用不得把这种状态描述为完整保护。
- Windows：UI Automation、窗口与屏幕观测能力取决于系统权限和目标应用。
- Android：无障碍服务与可见的普通常驻会话通知；风险通知通常发生在动作之后，不是阻塞确认。
- Chrome/Edge：需要在 HTTP(S) 页面运行内容脚本、使用本地存储/通知，并由静态 DNR 阻断声明范围内的请求；页面内提示只有“关闭”，不能授权或重放动作。
- iOS：用户必须在 Safari 启用扩展并授予相应网站访问权限；未授权 frame、closed Shadow DOM 与脚本直接网络调用不在已声明覆盖内。用户可在容器 App 关闭保护或清除本地审计，也可在 Safari 设置撤销网站权限。
- 用户可以结束会话、停用可选观测、关闭中继，并删除本地数据库与报告。

## 当前发布状态

本仓库是源码发布候选。正式签名安装包、商店数据安全表单、法务审阅、真实设备验收和公开支持渠道尚未完成。

## 联系方式

当前源码候选未提供可对外承诺的隐私联系地址。公开分发前必须在此填写真实、可用并由运营主体维护的联系方式。
