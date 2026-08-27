# Local loopback HTTP API

AgentGuard exposes a **127.0.0.1-only by default** HTTP API for companion agents and tooling
(非回环绑定要显式 `--allow-lan`,见下方 Endpoints 表末的说明).

```bash
# 令牌:命令行 > AGENTGUARD_API_TOKEN > 自动生成(启动时打印一次)
export AGENTGUARD_API_TOKEN="$(cargo run -q -p guard-cli -- api-token)"
cargo run -p guard-cli -- api-serve \
  --bind 127.0.0.1:8788 \
  --rules crates/guard-schema/rules/p0_rules.yaml \
  --audit-db /tmp/agentguard-api-audit.db \
  --intel intel/bundle.json \
  --token "$AGENTGUARD_API_TOKEN"
```

## 令牌强度

弱令牌会让 `api-serve` **拒绝启动**:短于 24 个字符,或命中一张公开示例值表
(`dev-secret`、`changeme`、`password`……)。

这条检查不是形式主义。这个 API 上 `POST /v1/pause` 能把守卫停掉、
`POST /v1/confirm` 能替人回答确认框 —— 猜到令牌等于绕过整个产品。服务器没有速率
限制,一个本机进程可以按网络速度试。

本文档此前写的是 `export AGENTGUARD_API_TOKEN='dev-secret'`,`make api-serve` 的默认
值也是它;也就是说,任何照文档跑起来的部署,令牌都是一个写在公开仓库里的字符串。
现在两处都改了,而且错误信息会把 `dev-secret` 点名说出来,而不是只报"太短" ——
问题不在长度。

本机临时调试确实需要一个好记的令牌时,加 `--insecure-token` 明确覆盖。留这条口子
是刻意的:一个没有覆盖路径的检查,最终会被整个删掉。

## Auth

| Path | Auth |
|------|------|
| `GET /health` | none |
| `/v1/*` | `Authorization: Bearer <token>` required |

Missing/invalid token → **401**.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness |
| GET | `/v1/status` | Rules / pause / privacy / intel snapshot |
| GET | `/v1/audit/recent?limit=50` | Recent audit rows |
| GET | `/v1/audit/report?limit=500` | Session summary JSON |
| POST | `/v1/pause` | Pause engine |
| POST | `/v1/resume` | Resume engine |
| POST | `/v1/confirm` | Body `{"approve":true\|false}` → resume/pause |
| POST | `/v1/events` | Android 伴生应用的信封入口 —— **能清除已锁存的 Critical 环境风险**。除 bearer 令牌外,还验证一层**适配器签名**(未签名的调查只能**加**风险、不能清;适配器注册表未配时没有任何断言能清风险)。 |

**默认只绑 127.0.0.1;非回环绑定被拒。** 例外:`--allow-lan` 显式允许绑到非回环地址
(Android↔桌面走 Wi-Fi),但这是**明文 HTTP**,bearer 令牌在每条路由上仍然强制 —— 只在
可信 LAN 上用。`/v1/events` 尤其要留意:它是唯一能**移除**风险的入站面。

## Example

```bash
TOKEN="$(cargo run -q -p guard-cli -- api-token)"
curl -sS http://127.0.0.1:8788/health
curl -sS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8788/v1/status | jq .
curl -sS -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8788/v1/pause
```
