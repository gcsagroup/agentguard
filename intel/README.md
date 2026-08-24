# Threat Intel

`bundle.json` 为可签名威胁特征包；`cdn-manifest.json` 描述 CDN 热更新入口。

```bash
# 生成密钥（secret.hex 已在 .gitignore）
cargo run -p guard-cli -- intel-keygen --out-dir intel/keys

# 签名并写回 bundle
cargo run -p guard-cli -- intel-sign --bundle intel/bundle.json --secret intel/keys/secret.hex

# 验签
cargo run -p guard-cli -- intel-verify --pubkey intel/keys/public.hex

# 从 CDN manifest 拉取（本地 file:// 或 https://）
cargo run -p guard-cli -- intel-fetch \
  --manifest intel/cdn-manifest.json \
  --pubkey intel/keys/public.hex \
  --out /tmp/bundle.fetched.json \
  --dry-run
```

签名格式：`ed25519:<base64>`（对 canonical JSON 的 SHA-256 digest 签名）。
legacy：`sha256:<hex>`。

热更新流程：`manifest` → 下载 `bundle_url` → Ed25519 验签 → 版本比较 → 写本地缓存 → `Engine::reload_intel`。
