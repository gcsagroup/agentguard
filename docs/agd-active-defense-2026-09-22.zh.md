# 主动防御第一波：真拦截落地，观察不停写成阻断

日期：2026-09-22。固定 App 仍为 AgentGuard Local Agent Test Ver 2.1（024），未改名、未重建。完整原 M1 与发布仍为 No-Go。

本轮按「能不能在动作发生前拦住」加强主动防护：把 Chrome 已有阻断做实，让桌面独立高风险停住同一会话的协作式网关，接通已有 AUTH / EGRESS / MEMORY 入口，并在界面上写清三条路径的真实处置。没有把 `OVL-009` / `OVL-010` 升回 Critical，没有为产量改情报包或堆关键词。

## 1. Chrome 执行前阻断

正式 Chrome 153.0.8010.52 加载候选 ZIP 后，B1、B2、B3、B5 通过；B4 因无上一公开版为 N/A。Edge 未安装，记 BLOCKED。详见[Chrome 手测](chrome-native-b15-2026-09-22.zh.md)。这是首个 GA 里对网页动作的执行前阻断，不能写成商店验收通过。

## 2. 桌面独立高风险 → 同一会话网关停住

明确注入（`OVL-004`，需确认且动作为 Block/Alert）仍弹窗。命中后：拒绝当前待确认工具、暂停托管本地任务、已连接且支持工作区的隔离网关进入暂停并使旧批准失效。视树差异（`OVL-010`）仍只记 LogOnly，不停网关。

接线在观察提交之后，工作区 HTTP 不占用轮询线程。组件测试：明确注入仍为独立风险；视树差异不停网关；未连接时 halt 返回 false；已连接时暂停工作区且旧预览失效。外部 App 里已经发生的点击仍不能撤销。

## 3. AUTH / EGRESS / MEMORY

按已有 AGD-017 / AGD-008 / PRIV-004 复跑组件入口，不写 IMPORT / PACKAGE / UNICODE 关键词规则，不改生效 `intel/bundle.json`。

| 队列 | 本轮核对 | 仍缺 |
|---|---|---|
| AUTH | 正常签发、受众、范围、匿名/过期、研究引用 sub 不扩权；控制 HTTP 拒绝非回环 Host/Origin | MCP HTTP/SSE 传输层认证未当作产品覆盖 |
| EGRESS | `egress_control` 含过期授权与已撤销会话不能派发 | 真实隔离会话的直接 socket / 宿主别名仍以既有 AGD-008 为准 |
| MEMORY | PRIV-004 记忆写入仍需批准；安装文档不当作待执行安装 | 指定客户端的真实记忆入口是否全部经过此路径未核 |

IMPORT / PACKAGE / UNICODE 保持失败队列。证据见[组件核对](evidence/intel-auth-egress-memory-2026-09-22.json)。

## 4. 主动防护页诚实文案

「主动防护」页增加三条路径说明：浏览器是执行前阻断；网关是协作式拦截；桌面是事后观察，明确注入会暂停同一会话网关与本地任务，视树差异只记观察。确认通道和本地任务在收到 `cooperative-halted` 后提示：外部动作并未被撤销。界面 136 项检查通过，含本条区分。

## 5. 第二波：form.submit 能同步拦则拦；DNR 不加未核别名

未改写原型的 `HTMLFormElement.prototype.submit` 由 MAIN world 包装后发出探测，isolated 门对陷阱/付款表单同步 `preventDefault` 并跳过原生提交。普通搜索表单的 `form.submit()` 不拦。页面从 iframe 取出原生方法后仍不在保证内，文档已按此改写，没有假保证。

已核情报包 `2026.07.30` 仍是域名、注入和浮层标记，没有可加入静态 DNR 的精确付款路径别名。未改 `payment-shape-block.json`，不检查 body，不拦 GET/HEAD，不加 Native Messaging，不恢复页内允许一次。

## 未做

- 未把视树差异重新升为桌面 Critical。
- 未用 OS 钩子拦截任意 App 点击。
- 未把 `guard-nm-host` 放进 GA manifest。
- 未把深伪、邮件模块、Android A5/A6 当成本轮主动防御。
- 未给 DNR 堆未核付款别名。
