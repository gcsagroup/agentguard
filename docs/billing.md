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
cargo run -p guard-cli -- billing-webhook \
  --file eval/fixtures/billing_webhook_purchase.json \
  --store /tmp/ag-ent.json
```

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
