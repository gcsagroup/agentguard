# Pro / Enterprise billing

AgentGuard uses a **local entitlement store** (`policies/entitlement.json`) so Pro features can be gated offline.

> **门控现状(第七轮复核后修正)。** 在此之前授权是**装饰性**的:`unlimited_audit` /
> `custom_rules` / `enterprise_export` 三个 flag 只被打印和显示,全仓没有任何一处读它们来
> 放行/拒绝行为 —— Free 和 Enterprise 跑得一模一样。现在 **`audit-export` 由
> `enterprise_export` 真正门控**(`Entitlement::allows_enterprise_export`):Free / Pro / 过期
> 授权导出被拒。这是授权第一处真正影响行为的地方。另两个 flag 目前仍未门控 —— 要么后续按同样
> 方式接上,要么在这里如实标注其未生效,不要让读者以为它们已强制。

## Dev activate

```bash
# Issue a token (dev secret unless AGENTGUARD_LICENSE_SECRET is set)
TOKEN=$(cargo run -q -p guard-cli -- entitlement-issue --license-id demo-1 --plan pro)
echo "$TOKEN"

cargo run -p guard-cli -- entitlement-activate --token "$TOKEN" --store policies/entitlement.json
cargo run -p guard-cli -- entitlement-status
```

## Webhook apply (file / one-shot)

```bash
# 夹具文件展示字段形状;它的 created_ms 是固定值,超出 ±10 分钟窗口会被拒——
# 这是设计,不是 bug。现场演示请用 `make webhook-demo`(用当前时间拼 body)。
cargo run -p guard-cli -- billing-webhook \
  --file eval/fixtures/billing_webhook_purchase.json \
  --store /tmp/ag-ent.json
```

### 重放与乱序保护(P1-7)

每个 webhook 事件**必须**带三个字段,缺一即拒:

* `event_id` —— 签发方事件 ID。接收端在授权文件旁维护幂等表(`<store>.webhook-state.json`,
  保留最近 512 个);见过的 ID 直接返回当前授权、不改动(签发方重试是常态,不是攻击)。
* `created_ms` —— 事件时刻。与本机时钟相差超过 ±10 分钟拒收。
* `version` —— 授权状态版本,单调递增。不高于已应用版本的拒收。

这三条合起来挡的是报告 P1-7 指出的形态:一份**旧的、签名合法的** purchase 在 refund 之后被
重放,把授权变回 Pro。测试 `refund后重放旧purchase被版本与时间窗双重拒绝` 把这条路走了一遍。
HTTP 接收端另有 body 上限 64 KiB(签名校验在读完 body 之后,没有上限就是无认证的内存放大器)。

## Local HTTP webhook receiver

**接收端现在要求签名(第七轮复核后修正)。** 在此之前 `POST /webhook/billing` 对原始 body
**没有任何签名校验**,而 `apply_webhook_event` 会直接用本地密钥从 payload 里自铸并激活授权
令牌 —— 一个匿名 POST `{"type":"purchase","plan":"enterprise"}` 就自授 Enterprise。现在:

* 设 `AGENTGUARD_WEBHOOK_SECRET` 后,接收端对每个 POST 校验
  `X-AgentGuard-Signature: sha256=<HMAC-SHA256(secret, 原始 body) 的 hex>`(常数时间比较);
  缺头 / 对不上 → 401。
* **没设密钥 → 拒收所有 POST(503,fail-closed)**,并在启动时告警。绝不在未认证下改动授权。

```bash
# Terminal A —— 必须设签名密钥,否则拒收
export AGENTGUARD_WEBHOOK_SECRET='replace-with-provider-signing-secret'
cargo run -p guard-cli -- billing-webhook-serve --bind 127.0.0.1:8787 --store /tmp/ag-ent.json

# Terminal B —— 算出签名再发
BODY='{"type":"purchase","license_id":"curl-1","plan":"pro"}'
SIG=$(cargo run -q -p guard-cli -- billing-webhook-sign --secret "$AGENTGUARD_WEBHOOK_SECRET" --body "$BODY")
curl -sS -X POST http://127.0.0.1:8787/webhook/billing \
  -H 'Content-Type: application/json' -H "X-AgentGuard-Signature: $SIG" \
  -d "$BODY"
curl -sS http://127.0.0.1:8787/health
```

## Production note
Point Stripe/Paddle/App Store webhooks at `POST /webhook/billing` (or adapt the JSON shape). The
local store format stays the same. **Verify the provider's own signature** (Stripe-Signature 等)—
上面的 `AGENTGUARD_WEBHOOK_SECRET` + HMAC 方案是一个能立即用的自托管签名,接真实 provider 时
换成它们各自的签名头/算法即可,但**签名校验这一步不能省**。

## Feature flags
| Plan | unlimited_audit | custom_rules | enterprise_export |
|------|-----------------|--------------|-------------------|
| Free | ❌ | ❌ | ❌ |
| Pro | ✅ | ✅ | ❌ |
| Enterprise | ✅ | ✅ | ✅ |
