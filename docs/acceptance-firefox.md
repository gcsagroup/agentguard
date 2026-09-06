[简体中文](acceptance-firefox.md) | [繁體中文](acceptance-firefox.zh-TW.md) | [English](acceptance-firefox.en.md)

# Firefox 排除说明（首个 GA）

> **这不是首个 GA 的验收清单，也不能生成 Firefox PASS。**

首个 GA 只发布 Chrome / Edge 共用的 Chromium ZIP。Firefox 当前仅保留 `manifest.firefox.json` 和相关源码，作为未来研发起点：不打包、不临时加载做发布验收、不提交 Firefox 商店，也不进入 `scripts/release-gate.sh --strict`。

## 当前必须成立的范围保护

- `apps/extension-chromium/scripts/package-store.sh --firefox` 返回非零且不产生 Firefox ZIP；
- Chrome / Edge ZIP 不包含 `manifest.firefox.json`、Native host 或 Firefox 专属元数据；
- 首个 GA 的 README、商店文案、权限说明、验收报告和发布结论都不得声称 Firefox 支持；
- 历史 F1–F8 报告、Firefox 截图、`AGENTGUARD_ACCEPTANCE_FIREFOX=PASS` 或 `acceptance_firefox` JSON 都不能授权首个 GA 发布。

可执行的当前检查只有负向范围检查：

```bash
make check-extension-gate
apps/extension-chromium/scripts/package-store.sh --firefox
# 预期：退出 64，且不产生 Firefox 包。
```

第二条命令失败是预期的范围保护行为；它不产生任何 Firefox 产品 PASS。

## 遗留 CLI 能力

`guard-cli manual-acceptance firefox`、`evidence-template --kind acceptance_firefox` 与对应校验代码暂时保留，是旧版/未来格式兼容能力。严格门禁不读取 `AGENTGUARD_EVIDENCE_ACCEPTANCE_FIREFOX`，也不接受该 kind 作为首个 GA 证据。任何调用得到的成功标记都只说明遗留格式自身通过，不能改变产品范围。

## Firefox 未来重新进入发布范围的前置条件

只有在单独产品决策后，才可建立新的 Firefox 发布清单。至少需要：

1. 重新审查 Firefox manifest、权限和商店隐私声明；
2. 建立独立且可复现的 Firefox 打包脚本，禁止复用 Chromium ZIP 结论；
3. 在真实 Firefox 上验证 DOM、Shadow DOM、frame、DNR 方法/编码/资源类型和误报边界；
4. 单独完成全新安装、升级、卸载、回滚和商店候选身份绑定；
5. 若未来考虑 Native Messaging，必须另做权限、身份、隐私与升级迁移设计，不能继承首个 GA 的旧原型；
6. 新增明确的 Firefox evidence kind、严格门禁接线和三语发布文档后，才可改变支持矩阵。

在这些条件全部完成前，Firefox 状态固定为：**源码原型 / 非首个 GA / 无发布 PASS**。
