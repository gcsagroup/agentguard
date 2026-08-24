# AgentGuard macOS 商店文案草案

**SKU：** `com.agentguard.desktop.macos` · **版本：** 1.0.0-rc.1  
**用途：** Mac App Store 与 **Developer ID 直装下载** 页草稿；提交前需法务/合规审阅。

## 应用名称

**AgentGuard for Mac**

## 副标题（≤ 30 字符，MAS）

本地 AI 代理防护栏

## 简短描述

AgentGuard 在 macOS 菜单栏运行，对第三方 AI 代理的操作进行本地规则检测、隐私评分与关键操作确认。默认不上传屏幕内容；审计与决策数据保存在本机。

## 完整描述（直装 / MAS 可调长度）

AgentGuard 是面向 Claude、Cursor 等 AI 代理的 **本地优先** 安全壳：

- **Menu Bar 常驻**：快速查看会话状态、规则加载与隐私综合分
- **ScreenCaptureKit（可选）**：在用户授予「屏幕录制」权限后，以低帧率采集 **粗粒度统计**（非全屏上传）；无权限时自动降级为模拟/demo 路径
- **Critical Confirm**：对支付、敏感表单、可疑浮层等触发阻断或二次确认
- **本地审计**：SQLite 记录决策链；可选 SQLCipher 加密（见文档）
- **威胁情报**：可配置 CDN 拉取 Ed25519 验签 bundle；默认不售卖个人数据

本 RC 不含在线订阅结算；Pro  entitlement 为本地/企业 PoC 配置。

## 分类建议

- **Mac App Store：** 生产力 / 工具  
- **直装：** 安全 / 开发者工具

## 权限说明（审核与用户可见）

| 权限 | 用途 | 数据去向 |
|------|------|----------|
| 屏幕录制（TCC） | ScreenCaptureKit 低 FPS 粗统计、透明浮层检测 | **仅本机**；帧不落盘；见 `docs/sck-bridge.md` |
| 辅助功能（可选） | 未来 AX 增强（当前 RC 以 SCK/模拟为主） | 本机 |
| 网络（可选） | 威胁情报 bundle、企业策略同步、**若启用** Tauri updater | 用户/企业配置的 HTTPS 端点 |
| 文件/应用支持 | 本地 audit DB、报告导出至 `~/Library/Application Support/agentguard/` | 本机 |

## 隐私要点（商店 bullet）

- 默认 **local-first**：Guard 事件与审计存于设备 SQLite
- **不上传** 屏幕像素或完整 DOM（浏览器扩展单独说明）
- 威胁情报 bundle **签名验证** 后本地加载
- 无第三方广告追踪；无默认 analytics SDK
- 联系邮箱与 DPA：发布前替换 [`privacy-policy.md`](privacy-policy.md) 中的占位 Contact

## Mac App Store 与直装差异

| 渠道 | 更新 | 签名 | 备注 |
|------|------|------|------|
| Mac App Store | App Store 更新 | Apple Distribution | 需 App Sandbox 策略重评 |
| 直装 DMG | Tauri updater 或手动下载 | Developer ID + 公证 | 见 [`macos-release.md`](macos-release.md) |

**同一 Bundle ID 不可同时直装 updater 与 MAS 更新。**

## 截图 / 预览建议

1. Menu Bar 托盘与仪表盘（规则数、隐私分、TCC 状态）
2. Critical Confirm 对话框（模拟威胁注入）
3. 审计列表 / 会话报告导出路径
4. TCC 引导文案（屏幕录制说明）

## 支持 URL / 隐私政策 URL

- 支持：`https://example.com/agentguard/support`（占位）
- 隐私：`https://example.com/agentguard/privacy`（对齐 `docs/privacy-policy.md`）

## 发布检查

- [ ] 版本与 `tauri.conf.json` 一致
- [ ] 权限字符串与 entitlements 一致
- [ ] RC 免责声明（Windows 真机 UIA 等 deferred 项）是否需要在描述中注明
- [ ] 中文/英文商店字段是否分别准备
