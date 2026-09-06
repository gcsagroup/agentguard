[简体中文](release-evidence.md) | [繁體中文](release-evidence.zh-TW.md) | [English](release-evidence.en.md)

# 結構化發佈證據

AgentGuard 的 `--strict` **RC 技術閘門**不再把「某個檔案裡出現了關鍵字」視為證據。需要憑據或真實裝置的十二類檢查必須提供結構化 JSON，並綁定**目前完整提交號**及現場重算的產物摘要：普通發佈檔案使用標準 SHA-256，Apple `.app` 使用整個 bundle 的確定性 tree-v2，驗收報告使用 acceptance-closure-v1。

> `--strict` 通過只代表候選可進入 GA 收口，不是 GA 核准或已上線。`--ga` 再要求 7 類閉環證據，共 19 類；見 [GA 發佈閉環閘門](ga-release-gate.zh-TW.md)。

> 這仍是未簽署的本機自證，只能防止誤綁定、誤操作與部分機械偽造。能控制工作區的人仍可偽造所有欄位或替換產物；抵抗這種攻擊需要由可信執行器簽發並驗證的證據簽章，屬於後續階段。證據 JSON 通過不等於安裝套件已可發佈。

## 十二類證據

| `kind` | 判據 | 環境變數 |
|---|---|---|
| `macos_codesign` | `codesign --verify --deep --strict --verbose=4` 成功，並讀取同一產物的簽署身分 | `AGENTGUARD_EVIDENCE_MACOS_CODESIGN` |
| `macos_notarize` | `notarytool` 回傳 Accepted，且 staple 驗證成功 | `AGENTGUARD_EVIDENCE_MACOS_NOTARIZE` |
| `windows_sign` | `signtool verify /pa /v` 成功 | `AGENTGUARD_EVIDENCE_WINDOWS_SIGN` |
| `android_sign` | `apksigner verify --print-certs` 確認發佈憑證而非 debug 憑證 | `AGENTGUARD_EVIDENCE_ANDROID_SIGN` |
| `ios_codesign` | 最終裝置 `.app` 通過 codesign 嚴格驗證，且輸出含 Apple Distribution authority 與預期 Team ID | `AGENTGUARD_EVIDENCE_IOS_CODESIGN` |
| `acceptance_macos` | macOS 真實裝置清單完成 | `AGENTGUARD_EVIDENCE_ACCEPTANCE_MACOS` |
| `acceptance_android` | 開啟無障礙服務的 Android 真實裝置產生簽署信封，桌面端以登錄公鑰驗章且判決符合預期 | `AGENTGUARD_EVIDENCE_ACCEPTANCE_ANDROID` |
| `acceptance_ios` | iPhone/iPad 上 I1–I6 Safari Web Extension 真機清單完成 | `AGENTGUARD_EVIDENCE_ACCEPTANCE_IOS` |
| `acceptance_ios_testflight` | TF1–TF3 上傳、真機安裝與升級完成 | `AGENTGUARD_EVIDENCE_ACCEPTANCE_IOS_TESTFLIGHT` |
| `acceptance_chrome` | Chrome stable 上候選 ZIP 的 B1–B5 完成 | `AGENTGUARD_EVIDENCE_ACCEPTANCE_CHROME` |
| `acceptance_edge` | Edge stable 上同一候選 ZIP 的 B1–B5 獨立完成 | `AGENTGUARD_EVIDENCE_ACCEPTANCE_EDGE` |
| `acceptance_windows` | Windows 真實裝置清單完成 | `AGENTGUARD_EVIDENCE_ACCEPTANCE_WINDOWS` |

## JSON 約束

每份證據都包含以下欄位：

```json
{
  "schema": "agentguard-release-evidence-v1",
  "kind": "acceptance_macos",
  "signer": null,
  "commit": "完整的 40 位 Git 提交號",
  "command": "target/release/guard-cli manual-acceptance macos docs/acceptance-macos.md evidence/macos/report.md --repo-root .",
  "exit_code": 0,
  "timestamp": "RFC 3339 時間",
  "output": "AGENTGUARD_ACCEPTANCE_MACOS=PASS",
  "artifact": {
    "path": "evidence/macos/report.md",
    "sha256": "普通檔案、.app tree-v2 或驗收 closure-v1 的 64 位 SHA-256"
  }
}
```

驗證器要求：

- `--file` 指向的證據 JSON 必須是可讀 UTF-8、大小不超過 1 MiB 的普通檔案，檔案本身不能是符號連結；schema 以外的未知欄位也會被拒絕。
- `commit` 必須是閘門正在檢查的完整提交號，不能是短雜湊或其他候選。
- 五類簽署證據的 `signer` 必須是非空字串，並與閘門從證據 JSON 之外取得的預期發佈者身分一致；嚴格閘門使用的七類驗收證據之 `signer` 必須是 `null`，且直接呼叫驗證器時禁止傳入 `--expected-signer`。
- `command`、`timestamp` 與 `output` 必須替換範本預留字串，`exit_code` 必須為 `0`；時間採用有效 RFC 3339 格式，校驗時必須位於過去 30 天至未來 10 分鐘的視窗內，且不能早於 HEAD 提交時間（允許 10 分鐘時鐘誤差）。`command` 必須逐字包含同一個 `artifact.path`，防止命令驗證 A、證據卻綁定 B。
- `artifact.path` 必須是儲存庫根目錄下的相對路徑，只使用 `/` 分隔；每個元件必須符合可攜式 ASCII `[A-Za-z0-9._-]+`。普通檔案必須非空；macOS/iOS 簽署 kind 還接受至少包含一個非空普通檔案的 `.app` 目錄，bundle 內任一符號連結、特殊檔案或非 UTF-8 路徑都會 fail-closed。
- 驗證器會現場重算摘要並與 `artifact.sha256` 比較。普通**非驗收**檔案使用標準 SHA-256；`.app` 使用帶有 `agentguard-tree-sha256-v2` domain separator 的確定性摘要。tree-v2 綁定 bundle 根目錄及每個項目的 Unix `0111` 可執行位元遮罩，並按 UTF-8 相對路徑位元組排序綁定項目類型、路徑長度／路徑、檔案長度與內容；它不綁定其他 mode 位元、xattr 或 ACL。在不提供 POSIX mode 的系統上不能據此宣稱已觀測到真實可執行位元。tree-v2 也不證明 quarantine／Gatekeeper 或首次啟動行為，正式候選仍必須在隔離機上以下載後的實際套件完成首次啟動驗收。
- 五類簽署證據的 `command` 必須不含註解，並採用校驗器接受的精確 fail-closed 成功鏈。macOS/iOS 程式碼簽署使用 `codesign --verify --deep --strict --verbose=4 ARTIFACT && codesign -dv --verbose=4 ARTIFACT`；iOS 輸出還須證明 Apple Distribution authority。Windows 與 Android 維持各自既有的固定驗證流程；`ios_codesign` 只接受發佈輸出路徑下的 `.app`。
- 公證前先在儲存庫外執行 `xcrun notarytool store-credentials AgentGuard-Notary --apple-id "$APPLE_ID" --team-id "$AGENTGUARD_EXPECTED_MACOS_TEAM_ID"`，依安全提示互動輸入 app-specific password，將憑據寫入登入鑰匙圈；不要把密碼放進命令參數，密碼或 API 私鑰也不得寫入儲存庫、JSON `command` 或證據記錄。`.app` 公證必須依 `ditto -c -k --keepParent APP ZIP` → `xcrun notarytool submit ZIP --wait --team-id <Team ID> --keychain-profile AgentGuard-Notary` → `xcrun stapler staple APP` → `xcrun stapler validate APP` 的四段 `&&` 成功鏈執行；`.dmg`／`.pkg` 則省略 ditto，直接對同一 `artifact.path` 執行後三段。ZIP、artifact 與逐項證據路徑都須符合上述可攜式 ASCII 元件規則；`--team-id` 與 `--keychain-profile` 都必須恰好出現一次。
- 簽署類 `output` 除成功訊號外還必須綁定憑證身分；iOS 除一般 codesign 成功與 Team ID 外，還必須包含 `Authority=Apple Distribution:`。其餘平台維持既有嚴格輸出判據。
- 嚴格閘門使用的七類驗收證據只接受對應 `evidence/<平台>/` 下、大小不超過 16 MiB 的 `.md` 報告：macOS、Android、Windows、iOS、iOS TestFlight、Chrome、Edge。命令必須是單段 `guard-cli manual-acceptance <平台> <清單> <artifact.path> --repo-root .`。
- 校驗器解析 Windows W1–W6/W8–W11、Android A1–A4、macOS 1–18（含 5b/5c）、iOS I1–I6、TestFlight TF1–TF3，以及 Chrome/Edge 各 B1–B5。每項須恰好一列 `PASS (native)` 並引用該 kind 目錄下不同的非空證據檔案；缺失、重複、仿真、FAIL、BLOCKED 或 N/A 都會被拒。

驗收類 `artifact.sha256` 使用 `agentguard-acceptance-closure-sha256-v1`：它綁定報告原始 bytes，並依路徑排序綁定每個唯一逐項引用的相對路徑、長度與檔案內容。任一報告或引用材料變更都會改變摘要。這個閉包仍是未簽署本機自證，只證明校驗時這些 bytes 被一併綁定，不能證明螢幕截圖、記錄或裝置資料的真實來源；可信來源證明仍需後續簽署執行器或外部見證。

嚴格閘門使用七個各自獨立的成功標記：`AGENTGUARD_ACCEPTANCE_MACOS=PASS`、`AGENTGUARD_ACCEPTANCE_ANDROID=PASS`、`AGENTGUARD_ACCEPTANCE_WINDOWS=PASS`、`AGENTGUARD_ACCEPTANCE_IOS=PASS`、`AGENTGUARD_ACCEPTANCE_IOS_TESTFLIGHT=PASS`、`AGENTGUARD_ACCEPTANCE_CHROME=PASS` 與 `AGENTGUARD_ACCEPTANCE_EDGE=PASS`。

### Firefox 遺留格式不是首個 GA 證據

`guard-cli` 暫時仍可解析 `acceptance_firefox`，僅供舊版／未來格式相容。`scripts/release-gate.sh --strict` 不讀取 `AGENTGUARD_EVIDENCE_ACCEPTANCE_FIREFOX`，本文件也不提供產生 Firefox PASS 的發佈流程。直接呼叫遺留命令得到的標記不能改變「Firefox 僅為原始碼原型、不封裝、不提交、不作首個 GA 閘門」的範圍。

### 簽署者身分來源

簽署 JSON 不能自行決定誰是可信發佈者；嚴格閘門從外部設定讀取預期身分，並把它傳給驗證器的必填參數 `--expected-signer`：

| `kind` | `signer` 格式 | 外部預期值 |
|---|---|---|
| `macos_codesign`、`macos_notarize` | macOS 發佈者的 10 位 Apple Team ID | `AGENTGUARD_EXPECTED_MACOS_TEAM_ID` |
| `ios_codesign` | iOS 發佈者的 10 位 Apple Team ID | `AGENTGUARD_EXPECTED_IOS_TEAM_ID` |
| `windows_sign` | 發佈憑證的 64 位 SHA-256 指紋 | `AGENTGUARD_EXPECTED_WINDOWS_CERT_SHA256` |
| `android_sign` | 發佈憑證的 64 位 SHA-256 指紋 | `AGENTGUARD_EXPECTED_ANDROID_CERT_SHA256` |

Windows 與 Android 指紋輸入可含大小寫或冒號，驗證前會正規化為 64 位十六進位值；JSON 的 `signer`、命令輸出裡的憑證身分與外部預期值必須指向同一個發佈者。七個嚴格閘門驗收 kind 不接受外部 signer。

Windows 可在已設定 `signtool` 的 Developer PowerShell 中執行下面這一整列；將路徑在命令的兩處與 JSON 的 `artifact.path` 中同步替換。命令先讓 `signtool` 驗證信任鏈，再從同一檔案讀取 Authenticode 憑證並輸出驗證器要求的獨立指紋列；不能把 `<指紋>` 文字直接寫成成功輸出。

```powershell
signtool verify /pa /v dist/AgentGuard.exe; if (-not $? -or $LASTEXITCODE -ne 0) { exit 1 }; $signature = Get-AuthenticodeSignature dist/AgentGuard.exe; if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) { exit 1 }; Write-Output ('CertificateSHA256=' + $signature.SignerCertificate.GetCertHashString('SHA256'))
```

## 產生、填寫與複核

先凍結待發佈提交，確認索引與所有非 ignored 工作樹檔案為 clean，再產生刻意無效的範本：

```bash
mkdir -p evidence/macos
commit="$(git rev-parse HEAD)"
commit_time="$(git show -s --format=%ct HEAD)"
cargo build --release -p guard-cli
cargo run -p guard-cli -- evidence-template --kind acceptance_macos \
  --commit "$commit" > evidence/macos/evidence.json
```

範本只是欄位清單，未填寫時必須驗證失敗。執行真實裝置驗收，把報告儲存為例如 `evidence/macos/report.md`。先實際執行人工驗收校驗並取得唯一 marker，再用同一入口計算報告閉包摘要；將精確命令、marker 與摘要填入 JSON 後明確複核：

```bash
target/release/guard-cli manual-acceptance macos docs/acceptance-macos.md \
  evidence/macos/report.md --repo-root .
# 成功時唯一輸出：AGENTGUARD_ACCEPTANCE_MACOS=PASS

cargo run -p guard-cli -- evidence-digest \
  --repo-root . --path evidence/macos/report.md

cargo run -p guard-cli -- evidence-verify \
  --kind acceptance_macos \
  --file evidence/macos/evidence.json \
  --commit "$commit" --commit-time "$commit_time" --repo-root .

export AGENTGUARD_EVIDENCE_ACCEPTANCE_MACOS=evidence/macos/evidence.json
bash scripts/release-gate.sh --strict
```

`.app` 必須使用同一個 `evidence-digest` 入口計算 tree-v2 摘要，不能以內部 Mach-O 的 SHA-256 代替。先在儲存庫外設定 `AgentGuard-Notary` 鑰匙圈 profile（不要記錄密碼），再執行例如：

```bash
xcrun notarytool store-credentials AgentGuard-Notary \
  --apple-id "$APPLE_ID" \
  --team-id "$AGENTGUARD_EXPECTED_MACOS_TEAM_ID"
# 依安全提示互動輸入 app-specific password；不要把密碼放進命令參數或記錄。

app=apps/desktop-macos/src-tauri/target/release/bundle/macos/AgentGuard.app
zip=evidence/macos/AgentGuard.zip
ditto -c -k --keepParent "$app" "$zip" && \
  xcrun notarytool submit "$zip" --wait --team-id "$AGENTGUARD_EXPECTED_MACOS_TEAM_ID" \
    --keychain-profile AgentGuard-Notary && \
  xcrun stapler staple "$app" && \
  xcrun stapler validate "$app"
cargo run -p guard-cli -- evidence-digest --repo-root . --path "$app"
```

JSON 的 `command` 應記錄上述變數展開後的儲存庫相對路徑單列命令，不能保留 `$app`／`$zip` 預留形式。

其他十一類按上表替換 `kind` 與環境變數。不要手動把校驗器本身、空目錄或舊提交報告填進變數。

直接複核簽署證據時還必須明確提供外部預期身分，例如：

```bash
expected_signer="${AGENTGUARD_EXPECTED_MACOS_TEAM_ID:?set the production Team ID}"
cargo run -p guard-cli -- evidence-verify \
  --kind macos_codesign \
  --file evidence/macos/codesign.json \
  --commit "$commit" --commit-time "$commit_time" --repo-root . \
  --expected-signer "$expected_signer"
```

`evidence/` 是 ignored 的本機證據工作區，只能在候選提交凍結後產生，不能提交進該候選，否則 `HEAD` 改變後原有 commit 綁定立即失效。嚴格閘門會在開始與結束時分別核對 `HEAD`、索引及所有非 ignored 工作樹檔案；結束時仍存在的 `HEAD` 或非 ignored 漂移會失敗，ignored 的 `evidence/` 不計入髒工作樹。起訖快照不能證明受控工作區未遭並行對手瞬時修改後還原，這仍屬於未簽署本機自證的邊界。閘門通過後應把證據唯讀封存到受控位置；敏感記錄、截圖、帳號或裝置識別資訊不得預設推送到 GitHub。

## 發佈邊界

RC 嚴格閘門還要求 production preflight 零 `FAIL`。即使十二份 JSON 都通過，只要測試金鑰仍有正式環境語意、自動閘門失敗，或簽署/公證/真實裝置/安裝/升級/回復材料不完整，結論仍是 **No-Go**。目前這些真實證據及 GA 所需 SBOM/授權、隱私/商店聲明、14 天 Beta、雙 RC、五方簽字、六渠道 smoke 與 5→25→100 擴量材料均未齊，因此仍是 **GA No-Go**。
