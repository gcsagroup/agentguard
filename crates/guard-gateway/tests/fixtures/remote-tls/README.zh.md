# 公开测试证书

这些 DER 文件只用于自有回环 TLS 夹具。`server-key.der` 是公开的测试私钥，不能用于真实服务。生产客户端必须由宿主提供自己的信任根，本模块没有内置或默认信任这些证书。

- `ca.der`：测试 CA。
- `server.der`：该 CA 签发、SAN 为 `localhost` 和 `mcp.localhost` 的服务器证书。
- `wrong-name.der`：同一 CA 签发、SAN 为 `wrong.example` 的负例证书。
- `server-key.der`：两个服务器证书共用的 PKCS#8 测试私钥。

生成日期 2026-09-15，有效期 3650 天。验收脚本使用 Node `X509Certificate` 和 `createPrivateKey` 读取，Rust 集成测试使用 rustls 读取。更新证书时需重新验证正常握手与错误名称时零 HTTP 请求；不能关闭客户端证书或名称验证来处理过期。
