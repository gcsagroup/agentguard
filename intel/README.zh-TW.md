# AgentGuard 威脅情報套件

[简体中文](README.md) · 繁體中文 · [English](README.en.md)

`bundle.json` 是威脅特徵套件，`cdn-manifest.json` 描述更新入口，`keys/public.hex` 是用於驗證目前範例套件的 Ed25519 公開金鑰。私鑰 `keys/secret.hex` 已由 `.gitignore` 排除，絕不能提交或散布。

## 產生、簽章與驗證

從儲存庫根目錄執行：

```bash
# 首次產生 Ed25519 金鑰；命令不會覆寫已存在的金鑰
cargo run -p guard-cli -- intel-keygen --out-dir intel/keys

# 使用私鑰簽章並寫回 bundle.json
cargo run -p guard-cli -- intel-sign \
  --bundle intel/bundle.json \
  --secret intel/keys/secret.hex

# 使用固定公開金鑰驗證發布簽章
cargo run -p guard-cli -- intel-verify \
  --bundle intel/bundle.json \
  --pubkey intel/keys/public.hex
```

在 Unix 系統上，金鑰產生器使用受限目錄/檔案權限；若現有私鑰權限過寬，簽章命令會拒絕使用。若私鑰可能已經外洩，只修正權限仍不足，應輪換信任根並重新簽發。

## 更新檢查

本機清單 dry-run 範例：

```bash
cargo run -p guard-cli -- intel-fetch \
  --manifest intel/cdn-manifest.json \
  --pubkey intel/keys/public.hex \
  --out /tmp/agentguard-intel.json \
  --dry-run
```

流程為：讀取 manifest → 取得 bundle → 使用指定公開金鑰驗證 bundle → 比較版本 → 在非 dry-run 時寫入輸出。manifest 中的版本提示不是信任根，實際 bundle 內容與簽章才是驗證對象。

## 簽章演算法邊界

### 發布與生產：只接受 Ed25519

發布路徑 `load_release` 要求：

- `signature` 必須是 `ed25519:<base64>`；
- 必須提供可讀取的固定公開金鑰；
- Ed25519 簽章必須覆蓋該 bundle 的 canonical JSON SHA-256 摘要；
- 未簽章、未知演算法或 `sha256:<hex>` 一律拒絕。

`intel-verify` 與帶有 `--pubkey` 的更新流程同樣要求真實性驗證。`sha256:<hex>` 不能取代發布簽章，因為任何能修改 bundle 的人都可以重新計算摘要。

### 開發相容：SHA-256 只檢查完整性

`sha256:<hex>` 僅保留給不提供公開金鑰的開發/離線軟載入路徑，用於發現意外損壞。它不證明發布者身分，不可用於生產認證，也不能描述為數位簽章。

不提供公開金鑰的 `load_or_default` 對 Ed25519 套件也無法完成真實性驗證，只會以未驗證方式載入並發出警告；生產消費者必須使用 `load_release` 與固定公開金鑰。

## 操作要求

- 不提交 `intel/keys/secret.hex`，不把私鑰放入建置產物、日誌或 CI 一般變數。
- 發布前固定公開金鑰指紋，並將金鑰輪換視為明確遷移處理。
- 遠端更新優先使用 HTTPS，但即使傳輸層受保護，也必須驗證 Ed25519 bundle 簽章。
- `--dry-run` 只驗證與列印，不寫入 `--out`。

目前 `intel/bundle.json` 使用 Ed25519 格式；這證明範例套件可驗證，不等於已建立生產發布、金鑰託管或 CDN 營運流程。
