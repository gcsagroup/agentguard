# Local loopback HTTP API

AgentGuard exposes a **127.0.0.1-only by default** HTTP API for companion agents and tooling
(非回环绑定要显式 `--allow-lan`,见下方 Endpoints 表末的说明).

```bash
# 令牌:命令行 > AGENTGUARD_API_TOKEN > 自动生成(只有自动生成的那次会完整打印;
#       你自己给的令牌启动时只打脱敏形式 ag_01…cdef,不进日志)
export AGENTGUARD_API_TOKEN="$(cargo run -q -p guard-cli -- api-token)"
cargo run -p guard-cli -- api-serve \
  --bind 127.0.0.1:8788 \
  --rules crates/guard-schema/rules/p0_rules.yaml \
  --intel intel/bundle.json \
  --token "$AGENTGUARD_API_TOKEN"
# --audit-db 默认在用户私有数据目录(Linux ~/.local/share/agentguard/api-audit.db,
# macOS ~/Library/Application Support/agentguard/,Windows %APPDATA%\agentguard\),不再是 /tmp。
```

## 审计库位置与请求上限(P1-7)

真机报告 P1-7 指出的四条边界,现在都关上了:

* **默认路径不可预测性**:`/tmp/agentguard-api-audit.db` 是任何本地用户都能预先创建、放符号链接的
  共享路径。默认改为用户私有数据目录(0700),并在打开前检查:是符号链接 → 拒;不是普通文件 → 拒;
  所在目录**其他人可写**(`/tmp` 这类 sticky 目录)→ 拒并告知默认私有位置。打开后文件权限设 0600。
  非 Unix 平台做符号链接/文件类型检查,不做权限位检查(没有那个概念)。
* **请求体上限** 256 KiB:`/v1/confirm`、`/v1/events` 超限回 **413**。多读一个字节判"超了",不是全读再量。
* **`limit` 上限** 1000:`/v1/audit/recent?limit=…` 与 `/v1/audit/report?limit=…` 被夹到上限,
  不再可能把整张审计表拉进内存。
* **令牌不进 stderr**:显式或环境变量给的令牌启动时只打脱敏形式;只有本次随机生成的令牌才完整打印一次
  (那是用户唯一能知道它的机会)。

没做的(如实):没有速率限制,也没有每客户端并发上限——令牌强度门槛(见下)是在线猜测的唯一防线。

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
