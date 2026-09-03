# Pro / Enterprise billing

AgentGuard uses a **local entitlement store** (`policies/entitlement.json`) so Pro features can be gated offline.

## 商业边界:厂商签名授权(真机报告 P2-7)

> **哪一档算钱。** 授权有两档来源,`entitlement-status` 的 `source:` 行会说清楚:
>
> | 来源 | 怎么来的 | 显示 | 解锁企业功能(`allows_enterprise_export`) |
> |---|---|---|---|
> | `signed` | 厂商 **Ed25519 私钥**签发,客户端用 `AGENTGUARD_LICENSE_PUBKEY` 验签 | Pro / Enterprise | **是**(有效期内或 7 天离线宽限内) |
> | `signed_by_fixture` | 用仓库自带的公开夹具私钥签的(RFC 8032 测试向量,人人都有) | Pro / Enterprise | 否 —— 演示档 |
> | `dev_hmac` | `entitlement-issue`(HMAC,共享秘密写在源码里) | Pro / Enterprise | 否 —— 演示档 |
> | `webhook` | 本地 webhook 接收器(共享秘密) | Pro / Enterprise | 否 —— 演示档 |
> | `revoked` / `expired` | 签名授权被撤销 / 过了宽限 | Free | 否 |
>
> 以前只有 HMAC 一条路,而 `audit-export` 把它当边界用 —— 本机任何人
> `entitlement-issue --plan enterprise` 一条命令就能给自己开企业功能。持有验签方(装在用户机器上的
> 二进制)必然持有 HMAC 秘密,所以共享秘密**在结构上**做不成边界。非对称签名才行:持公钥的一方签不出
> 任何东西。三条老路都保留,照常演示,只是不再被当成钱。

```bash
# 厂商(签发机):生成一对密钥。私钥只留在这台机器上,不进仓库(.gitignore 已排除 policies/license-signing.key)。
cargo run -q -p guard-cli -- license-keygen --out /secure/agentguard-license.key
#   public: 8441abc7…                        ← 放进客户端环境 AGENTGUARD_LICENSE_PUBKEY(或指向存着它的文件)

# 厂商:签发一份授权。必须有到期日;serial 在续期/改档时递增。
TOKEN=$(cargo run -q -p guard-cli -- license-issue --secret /secure/agentguard-license.key \
          --license-id acme-1 --plan enterprise --days 365 --serial 1)

# 客户端:激活。签名验不过、公钥不匹配都直接报错(错误信息带两边的 key id)。
AGENTGUARD_LICENSE_PUBKEY=8441abc7… cargo run -q -p guard-cli -- entitlement-activate --token "$TOKEN"
AGENTGUARD_LICENSE_PUBKEY=8441abc7… cargo run -q -p guard-cli -- entitlement-status
#   plan=Enterprise active=true commercial=true … (gated=true)
#   source: vendor-signed license (key 8441abc7289aced8)

# 厂商:撤销。签一份名单,放到客户端 store 旁边的 <store>.revocations.json(传输方式不在这里:随更新包、HTTP 都行)。
cargo run -q -p guard-cli -- license-revoke --secret /secure/agentguard-license.key --license-id acme-1 \
  --out policies/entitlement.json.revocations.json
#   --max-serial 1 只撤 serial<=1(续期后的 serial 2 继续有效);不给 = 该 id 全部撤。
#   名单自己也是签名的:一份验不过的名单让激活/加载**报错**,而不是被当成"没有名单"。
```

规则,写在 `crates/guard-billing/src/license.rs` 的文件头并有测试:**必须有到期日**(没有到期的授权只能
靠名单收回,而名单的送达不受我们控制);到期后 **7 天离线宽限**(`in_grace`,功能仍在,状态说明),
宽限过了落回 Free;签名授权在**每次加载时重新验**(store 旁的 `.license.token`),到期 / 宽限 / 撤销
都是时间函数,不能只信落库那一刻。签的是带域分隔的定长文本
(`agentguard-license-v1|id|plan|issued|expires|serial`),不是 JSON。

preflight:`license.pubkey.fixture`(WARN)= 客户端还停在夹具公钥上,所有授权都是演示档、企业功能对所有人
关闭(fail-closed,所以是 WARN 不是 FAIL);`license.pubkey.invalid`(FAIL)= 配了却解析不了;
`license.secret.unignored`(FAIL)= 签发私钥在树里且没被 .gitignore 排除。

**边界仍然是软件的边界。** 持有二进制的人可以打补丁绕过任何客户端检查;这一档解决的是"任何人都能
给自己**签发**看起来合法的授权"这一条,不是"没人能改客户端"。平台收据校验(App Store / Play)是另一条
路,没有实现。

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
