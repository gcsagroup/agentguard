# Local loopback HTTP API

AgentGuard exposes a **127.0.0.1-only** HTTP API for companion agents and tooling.

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

Non-loopback binds are refused.

## Example

```bash
TOKEN="$(cargo run -q -p guard-cli -- api-token)"
curl -sS http://127.0.0.1:8788/health
curl -sS -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8788/v1/status | jq .
curl -sS -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8788/v1/pause
```
