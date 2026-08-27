# AgentGuard 威胁情报包

简体中文 · [繁體中文](README.zh-TW.md) · [English](README.en.md)

`bundle.json` 是威胁特征包，`cdn-manifest.json` 描述更新入口，`keys/public.hex` 是用于验证当前示例包的 Ed25519 公钥。私钥 `keys/secret.hex` 被 `.gitignore` 排除，绝不能提交或分发。

## 生成、签名和验证

从仓库根目录运行：

```bash
# 首次生成 Ed25519 密钥；命令不会覆盖已存在的密钥
cargo run -p guard-cli -- intel-keygen --out-dir intel/keys

# 使用私钥签名并写回 bundle.json
cargo run -p guard-cli -- intel-sign \
  --bundle intel/bundle.json \
  --secret intel/keys/secret.hex

# 使用固定公钥验证发布签名
cargo run -p guard-cli -- intel-verify \
  --bundle intel/bundle.json \
  --pubkey intel/keys/public.hex
```

在 Unix 系统上，密钥生成器使用受限目录/文件权限；如果现有私钥权限过宽，签名命令会拒绝使用它。若私钥可能已经泄露，仅修正权限不够，应轮换信任根并重新签发。

## 更新检查

本地清单 dry-run 示例：

```bash
cargo run -p guard-cli -- intel-fetch \
  --manifest intel/cdn-manifest.json \
  --pubkey intel/keys/public.hex \
  --out /tmp/agentguard-intel.json \
  --dry-run
```

流程为：读取 manifest → 获取 bundle → 使用给定公钥验证 bundle → 比较版本 → 在非 dry-run 时写入输出。manifest 中的版本提示不是信任根，实际 bundle 内容和签名才是验证对象。

## 签名算法边界

### 发布与生产：只接受 Ed25519

发布路径 `load_release` 要求：

- `signature` 必须是 `ed25519:<base64>`；
- 必须提供可读取的固定公钥；
- Ed25519 签名必须覆盖该 bundle 的 canonical JSON SHA-256 摘要；
- 未签名、未知算法或 `sha256:<hex>` 一律拒绝。

`intel-verify` 和带 `--pubkey` 的更新流程同样要求真实性验证。`sha256:<hex>` 不能替代发布签名，因为任何能修改 bundle 的人都可以重新计算摘要。

### 开发兼容：SHA-256 只检查完整性

`sha256:<hex>` 仅保留给不提供公钥的开发/离线软加载路径，用来发现意外损坏。它不证明发布者身份，不可用于生产认证，也不能被描述为数字签名。

不提供公钥的 `load_or_default` 对 Ed25519 包也无法完成真实性验证，只会以未经验证的方式加载并发出警告；生产消费者必须使用 `load_release` 和固定公钥。

## 操作要求

- 不提交 `intel/keys/secret.hex`，不把私钥放进构建产物、日志或 CI 普通变量。
- 发布前固定公钥指纹，并将密钥轮换作为显式迁移处理。
- 远程更新优先使用 HTTPS，但即使传输层受保护，也必须验证 Ed25519 bundle 签名。
- `--dry-run` 只验证和打印，不写 `--out`。

当前 `intel/bundle.json` 使用 Ed25519 格式；这证明示例包可验证，不等于已经建立生产发布、密钥托管或 CDN 运营流程。
