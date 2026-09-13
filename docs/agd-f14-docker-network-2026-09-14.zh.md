# F13 暂缓与 F14 Docker 网络恢复记录

日期：2026-09-14。状态：**F14 Docker 虚拟链路场景通过；F13 用户暂缓、未验收。**

用户明确要求“先跳过 F13，然后继续推进”。F13 保留原系统休眠／唤醒定义，记为用户暂缓、未验收，不计通过，也不再作为本轮继续开发的等待条件。

## 范围与完成标准

复用现有镜像 `sha256:7de5789da80158e418d22bf911ea3829aa1abdeb2338dd556dc99b13c89d8490`，使用一个自有合成服务容器 `agentguard-f14-20260914` 和一个专属桥接网络，不新增镜像或 Volume。服务只发布 Mac 的回环端口；容器内控制端口不发布。测试不读取生产资料，不操作其他容器或 Mac 的 Wi-Fi。

路径是准确 010 App 的确认通道 → 同包网关／Chromium → Mac 发布端口 → Docker Desktop Linux VM → 非回环桥接网卡 → 自有合成服务。Mac 端目标仍为回环地址；故障发生在实际承载流量的 Linux VM 网卡。验收范围为 Docker 虚拟链路，不能外推为 Mac 物理网卡断网。

步骤 → 验证：

1. 读取合成页面 → 原生 App 核对并批准，真实浏览器获得页面。
2. 批准唯一合成 POST，服务收件后暂留响应 → 保留正文、请求编号及收件时间。
3. 保持服务 PID 与启动时间不变，实际移除虚拟网卡 → 网络和路由消失，已派发请求返回未知，旧会话失败。
4. 恢复原 IP 与网卡 → 观察至少 25 秒，无自动重发；旧批准与旧会话恢复均拒绝。
5. 建立新会话、重新核对批准新请求 → 新会话／动作编号不同，恰好新增一条收件，真实浏览器读回结果。
6. 结束本方会话 → 保存审计、复核 App 整包及签名；F13 例外独立保留。

## 过程与失败保留

- 初次内部网络配置未发布测试端口，未进入产品验收；记录保存在 `.artifacts/f14-docker-2026-09-14/network-probe.json`。改为专属桥接网络后，继续复用同一服务容器。
- 第二次环境探针通过：服务保持同一 PID／启动时间，网卡移除后请求超时、恢复后成功，见 `network-probe-02.json`。此项仅是环境检查，不独立计作 F14 产品通过。
- 原生首批次读取成功，但新验收脚本将契约值 `success` 误写成 `succeeded`，断链步骤尚未执行即失败；保留 `native-01/report.json` 与原脚本。修正验收断言后另开 `native-02`，产品代码不变。

运行器见 [agd-browser-network-recovery.mjs](../scripts/acceptance/agd-browser-network-recovery.mjs)。`--approvals native` 仅等待原生界面批准，`auto` 明确标记为脚本批准；两者不混记。每批使用新输出目录并保留脚本、网关摘要、容器身份、网络状态、请求与审计。`host-test-support.mjs` 新增可选 RPC 等待时长，默认仍为 45 秒，仅为原生核对预留时间。

- `native-02` 在真实断链后取得已派发未知回执，但脚本立即读取到过渡态 `paused` 而提前终止。原有集成测试本来就等待终态同步；本轮修正为最多等待 5 秒进入 `failed`，保留首次失败，不放宽最终状态要求。`native-03` 的记录最终为 `failed`，原生界面也实际显示“会话失败”，恢复按钮不可用。

## 正式结果

可随 GitHub 查看[脱敏验收摘要](evidence/f14-docker-2026-09-14.json)。下列 `.artifacts` 原始请求、日志和审计仅保存在本地，未提交到 GitHub。

[native-03 报告](../.artifacts/f14-docker-2026-09-14/native-03/report.json)通过。四次 GET／POST 均在准确 010 App 中核对请求编号、目标、正文并点击“仅批准当前请求”；测试器只执行重复旧批准的拒绝验证，没有替代原生批准。浏览器动作由确定性验收器发起，不是模型自主任务。

- 网关 SHA-256 `773c6732e9fd0fa2f1e92b1c54ae40e04aac2864ccb937984edd7fe476d3100a`；原生主程序 SHA-256 `e67d0d412f06aa5d028706e6b66195b3f6048e0456fc5df2331a1a4e280666e1`。验后 90 个包文件不变，严格签名核验通过。
- 同一容器、服务 PID 与启动时间不变；虚拟网卡 `eth0` 及其路由实际消失，再恢复 `172.18.0.2`。入口为 `http://127.0.0.1:55960`，地址仅用于本轮合成测试。
- 正式批次开始时收件数为 1（上一失败批次的合成 POST，未删除）；本批已派发未知后为 2，恢复观察 **25.10 秒**仍为 2。旧批准、失败会话恢复和新会话接受旧批准都返回 409。新批准后为 3，增量恰为本轮两个不同编号的 POST；真实浏览器已读回新的成功编号。
- [核验结果](../.artifacts/f14-docker-2026-09-14/verification.json)：两会话浏览器审计分别 15、18 条，合计 **33 条验链通过**；工作区审计为 0，符合本次没有文件或命令动作的范围，不拿空日志增加证据数量。

M1 原定义的 F13 未执行；本轮 AGD-013 在用户暂缓 F13 的条件下结束，并据此进入 M2。完整原 M1 和发布仍未通过。后续 M2 源码修改与本次 010 证据分开记录，本轮没有重新打包 App。

## 复验入口

合成服务源码为 [agd-network-test-site.mjs](../scripts/acceptance/agd-network-test-site.mjs)。容器须使用上述固定镜像，带 `org.gcsa.agentguard.task=F14` 标签、只读根文件系统，唯一连接到同标签专属网络；将容器 8080 仅发布到 Mac 回环地址，9090 控制端口不发布。运行器在断链前逐项核验身份、网络独占及端口绑定，拒绝不匹配的对象。继续复用同一个容器；初次失败和本轮收件不清空。

复验时先读取该容器的实际发布端口，再指定准确候选的网关和包内浏览器入口。示例（端口和输出目录需与本批实际配置对应）：

```sh
node scripts/acceptance/agd-browser-network-recovery.mjs \
  --container agentguard-f14-20260914 --network agentguard-f14-20260914 \
  --origin http://127.0.0.1:55960 \
  --gateway 'apps/desktop-macos/src-tauri/target/debug/bundle/macos/AgentGuard Local Agent Test.app/Contents/Resources/agentguard/setup/gateway/agentguard-mcp' \
  --runtime 'apps/desktop-macos/src-tauri/target/debug/bundle/macos/AgentGuard Local Agent Test.app/Contents/Resources/agentguard/protected-browser/cli.mjs' \
  --out .artifacts/f14-docker-retest --approvals native
```

运行器输出本次连接文件路径，在准确 App 中导入，再逐次核对并批准四个预声明请求。新输出目录不可复用，以免覆盖旧结果。测试结束会恢复本方链路并结束本方网关；合成服务容器的结束状态另记录。

收尾已核实：本方网关与确认通道结束，合成服务容器停止并保留；复用同一镜像，未创建 Volume，未操作其他容器。
