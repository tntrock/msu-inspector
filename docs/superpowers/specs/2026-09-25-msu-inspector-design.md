# msu-inspector 設計文件

- 日期：2026-09-25
- 狀態：已核准（2026-09-25）；2026-09-25 依格式研究結果修訂（見第 11 節）
- Repo：`tntrock/msu-inspector`（公開，MIT）
- 本機路徑：`D:\Claude\msu-inspector`

## 1. 目標與範圍

部署前審查用的 Windows 工具：把 Windows 更新套件（`.msu` / `.cab`）拖進來，**不安裝**，靜態解析出這包 KB 安裝後會對系統做哪些動作，標示風險，並可匯出 JSON 交給雲端 AI 進一步分析。單一 exe，同時提供 GUI 與 CLI，介面繁體中文為主、可即時切換 English。

### 第一版功能

| 功能 | 說明 |
|------|------|
| 載入 | 拖放或選擇 `.msu` / `.cab`，自動辨識格式 |
| 靜態分析 | 解析所有元件 manifest，列出 KB 會做的動作 |
| 本機比對 | 僅管理員模式：與本機現況比對，標示 新增 / 取代（版本 A→B）/ 相同 / 降版 / 不適用 |
| 風險標記 | 內建規則表標出高風險動作，並附命中規則與理由 |
| 瀏覽 | 分類樹 + 虛擬捲動表格 + 搜尋篩選 + 詳細資料窗格 |
| 匯出 JSON | 可勾選類別與細節程度，即時預估大小；可複製摘要到剪貼簿 |
| 雙語 | 繁中 / English，GUI 即時切換；CLI 以參數或環境變數指定 |
| CLI | 批次與自動化流程用 |

### 支援的更新格式

盡可能廣：

- 傳統 `.msu`：CAB 內含 CAB（Windows 10 22H2、Windows 11 23H2 以前、Server 2016/2019/2022）
- 新式 `.msu`：**`.msu` 本身就是 WIM 檔**（檔頭 `MSWIM`），內含 `.wim` + `.psf` 差異封裝與數個 CAB（Windows 11 24H2 / 25H2、Server 2025）
- 獨立 `.cab` 更新包
- .NET Framework 累積更新、SSU 等特殊包
- manifest 的 DCM（PA30 差異）壓縮

無法辨識的格式明確回報「不支援」，不輸出不完整的結果。

### 不在第一版範圍

- 兩個 KB 之間的差異比較
- 實際安裝或模擬安裝
- 自動上傳到 AI 服務
- 非 Windows 平台

## 2. 技術選型

| 項目 | 選擇 | 理由 |
|------|------|------|
| 語言 | Rust（edition 2021） | 與既有工具（`code-signer` 等）一致 |
| GUI | `eframe` / `egui` | 原生拖放、單一小 exe |
| 檔案對話框 | `rfd` | 同上 |
| CLI | `clap`（derive） | 標準做法 |
| Win32 API | `windows` crate | 呼叫系統內建 DLL |
| XML | `roxmltree` | 唯讀 DOM，API 穩定；單一 manifest 很小，逐檔解析即可 |
| 其他 | `serde` / `serde_json`、`thiserror`、`sha2`、`egui_extras`（虛擬捲動表格） | |
| 測試 | `tempfile`、`assert_cmd` | |

**容器與壓縮一律呼叫 Windows 內建 DLL，不依賴第三方 exe：**

| 需求 | 使用 |
|------|------|
| CAB | `cabinet.dll`（FDI API）：單次循序解壓，於 `fdintCOPY_FILE` 只挑需要的檔案（manifest、`.mum`、巢狀容器等）。純 Rust 的 `cab` crate 讀取 LZX 固實資料夾中的每個檔案都要從頭解壓，數萬個 manifest 時為平方時間，故不採用 |
| WIM | `wimgapi.dll`（以不套用 ACL 的方式展開到暫存資料夾） |
| PSF | 自行解析索引（獨立的 `*.psf.cix.xml`，或 PSF 檔頭內嵌、以 PA30 壓縮的索引），依來源型別還原：RAW 直接讀、PA30 用差異引擎、PA19 用 `mspatcha.dll` |
| 差異引擎（PA30） | 優先使用系統的 `UpdateCompression.dll`（24H2 起內建），其次為 `.msu` 內 `DesktopDeployment.cab` 附帶的 `UpdateCompression.dll`（**載入前驗證 Microsoft 簽章**），最後才用 `msdelta.dll` |
| DCM manifest | 差異引擎 + 本機 servicing stack `wcp.dll` 內嵌基底字典（資源型別 `0x266`、ID `1`；已在本機驗證可解開 WinSxS 內 19,173 個 manifest） |
| 簽章驗證 | `WinVerifyTrust` |

建置設定沿用既有專案：release profile `opt-level = "z"`、`lto`、`codegen-units = 1`、`strip`、`panic = "abort"`；`build.rs` 以 `winresource` 嵌入圖示與版本資訊；CJK 字型於執行時從 `C:\Windows\Fonts\msjh.ttc` 載入。

## 3. 架構

### 3.1 執行模式

同一個 `msu-inspector.exe`：

- 無參數（或只帶檔案路徑）→ 開啟 GUI
- 帶子指令 → CLI 模式

主控台子系統處理方式沿用 `code-signer`：若主控台是專為本程序建立的（檔案總管雙擊啟動），以 `FreeConsole` 釋放。

### 3.2 權限模式

| 狀況 | 行為 |
|------|------|
| 一般權限啟動（GUI） | 顯示選擇框：「靜態分析」或「以系統管理員重新啟動（啟用本機比對）」 |
| 已是管理員 | 直接進入「靜態分析 + 本機比對」模式 |
| 執行中 | 工具列顯示目前模式，並提供「提升權限」按鈕；以 `ShellExecuteW` 的 `runas` 重新啟動並帶入目前檔案路徑 |
| CLI | `--compare-local` 需要管理員權限，否則直接報錯 |

報告的 `mode` 欄位記錄產生時的模式。

### 3.3 模組

```
src/
  main.rs            進入點：分派 GUI / CLI
  lib.rs
  cli.rs
  i18n.rs            繁中 / English 字串表
  elevation.rs       檢查是否為管理員、runas 重新啟動
  core/
    container/       拆容器，輸出統一為「manifest 位元組串流」
      detect.rs        格式偵測
      cab.rs           cabinet.dll FDI（可處理巢狀 CAB）
      wim.rs           wimgapi.dll
      psf.rs           PSF 索引解析與還原
    delta.rs         差異引擎（UpdateCompression / msdelta / mspatcha）
    manifest/
      dcm.rs           DCM 解壓
      parse.rs         .mum / .manifest XML 解析為結構化資料
    model.rs         Package、Component、Action 等資料模型
    classify.rs      動作分類
    risk.rs          風險規則表
    local.rs         本機比對（唯讀）
    signature.rs     .msu Authenticode 驗證
    export.rs        JSON 匯出（篩選 + 預估大小）
  gui/               eframe/egui 介面
```

core 不依賴 GUI，可獨立測試。

### 3.4 資料流

```
.msu / .cab
  → 簽章驗證
  → 偵測格式
  → 拆容器（遞迴）
  → 取得 update.mum、pkgProperties.txt 與各元件 manifest
  → DCM 解壓
  → XML 解析
  → AnalysisReport
  →（管理員模式）本機比對
  → 分類與風險標記
  → GUI 顯示 / JSON 匯出
```

- 只在記憶體與暫存資料夾中處理，**不修改系統**；暫存資料夾在分析結束或程式結束時刪除。
- 分析在背景執行緒進行，透過 channel 回報進度；GUI 顯示進度（例如「解壓中 312/12034」），可取消。

## 4. 資料模型

### 4.1 封裝層級（Package）

來源：`update.mum`、`pkgProperties.txt`、`.msu` 內的 `.xml`。

- KB 編號
- 套件識別：name / version / processorArchitecture / language / publicKeyToken
- 適用的產品與版本
- 是否需要重新開機
- 支援資訊連結
- 父子套件關係
- 元件數量

### 4.2 動作類別

每個元件 manifest 為一個 Component，包含多個 Action。

| `kind` | 來源 | 重點欄位 |
|--------|------|----------|
| `file` | `<file>` | 目的路徑、檔名、版本、雜湊、大小、是否為 PE、`importPath`、SDDL |
| `registry` | `<registryKeys>` | 機碼、值名稱、型別、資料、動作（新增 / 修改 / 刪除）、`owner`、SDDL |
| `service` | `<memberships><categoryMembership><categoryInstance><serviceData>` | 服務名稱、映像路徑、啟動類型、服務型別、帳戶、權限、群組 |
| `driver` | `serviceData` 的 `type` 為 `kernelDriver` / `fileSystemDriver` / `recognizerDriver`，或 `.sys` 檔；`BootCritical` 類別 | 驅動名稱、映像路徑、載入階段（boot / system / auto / demand）、是否為 BootCritical |
| `scheduled_task` | `<taskScheduler><Task>` | 工作路徑（URI）、觸發條件、執行程式與參數、執行身分 |
| `generic_command` | `<genericCommands><genericCommand>` | `executableName`、`arguments`、是否於安裝時執行 |
| `firewall_rule` | `<firewallRule>` 元素，以及 `...\FirewallPolicy\FirewallRules` / `RestrictedServices` 下的登錄值 | 方向、程式、連接埠、協定、動作 |
| `wmi_mof` | `<mof>` | MOF 檔、反安裝 MOF |
| `etw_eventlog` | `<instrumentation>` | 提供者名稱、GUID |
| `advanced_installer` | 安裝時會執行自訂程式碼的元素：名稱以 `AI` 結尾者（`fveUpdateAI`、`HTTPAI`…）、`bfsvc`、`SecureBoot`、`appxRegistration`、`networkComponents`、`unattendActions`、`sppInstaller`、`installerRegistrations`、`Transforms`、`firewallGroupActivation`、`cleanupCache` 等 | 元素名稱、全部屬性 |
| `directory` | `<directories>` | 路徑、SDDL 名稱 |
| `setting` | SMI `<configuration>` | 設定名稱 |
| `unknown` | 未辨識的元素 | 保留原始 XML 片段，不丟棄 |

不視為動作的結構性元素：`assemblyIdentity`、`dependency`、`trustInfo`、`localization`、`deployment`、`migration`、`rescache`、`languagePack`、`imaging`、`feature`、`categoryDefinitions`、`satelliteCategory`、`languageCategory`、`containsSettings`、`compatibility`、`noInheritable`、`mvid`、`application`、`runtime`（.NET）、`description`、`deconstructionTool`。`memberships` 只擷取服務與類別（`typeName`），不另列為動作。

位於元件資料夾（WinSxS keyform 名稱）內的檔案，例如 `bootos.wim`、`f/application.manifest`，是要安裝的 payload，不當成容器或元件 manifest 處理。

檔案沒有個別版本欄位；檔案的「新版本」一律以所屬元件的 `assemblyIdentity` 版本表示。

### 4.3 風險規則

規則以表格定義於 `risk.rs`，每條規則有 ID、等級、比對條件與理由（雙語）。每筆標記都記錄命中的規則 ID 與理由。

- **高**：開機載入驅動（boot / system start）；LSA、Credential Provider、Security Package 相關登錄；`generic_command`；新增服務或變更服務啟動類型、執行帳戶；防火牆規則變更；開機相關設定（BCD、`Winlogon`、`Image File Execution Options`）
- **中**：新增排程工作；WMI MOF；COM 註冊；`System32` 內 PE 檔案的新版本
- **低 / 資訊**：一般資料檔、語系資源、ETW

## 5. JSON 輸出

```json
{
  "schema_version": "1.0",
  "tool": { "name": "msu-inspector", "version": "0.1.0" },
  "generated_at": "2026-09-25T10:00:00+08:00",
  "mode": "static | static+local",
  "local_context": { "os_build": "26100.4202", "arch": "amd64" },
  "source": {
    "file": "windows11.0-kb50xxxxx-x64.msu",
    "sha256": "...",
    "format": "msu-psf",
    "signature": { "valid": true, "signer": "Microsoft Corporation" }
  },
  "package": { "kb": "KB50xxxxx", "identity": {}, "applicability": [], "restart_required": true },
  "summary": { "components": 12034, "by_kind": { "file": 35120 }, "by_risk": { "high": 42 } },
  "high_risk": [
    { "kind": "service", "component": "...", "rule": "SVC_START_TYPE_CHANGE", "reason": "...", "detail": {} }
  ],
  "components": [
    {
      "identity": {},
      "actions": [
        {
          "kind": "file",
          "risk": "low",
          "local": { "status": "replace", "from": "10.0.26100.4061", "to": "10.0.26100.4202" }
        }
      ]
    }
  ],
  "warnings": [ "3 manifests failed DCM decompression: ..." ],
  "export_filter": { "kinds": ["service", "driver"], "detail": "risk" }
}
```

- `local_context` 與每個 action 的 `local` 只在 `static+local` 模式出現。
- 細節程度：
  - `summary`：輸出到 `summary` 為止
  - `risk`：再加 `high_risk`
  - `full`：再加完整 `components`
- detail ≥ `risk` 時另輸出 `rules`：本次出現的規則 ID → 等級與理由；`high_risk` 與各動作只以規則 ID 參照，避免同一段理由重複數千次。
- `export_filter` 記錄本次匯出篩掉了什麼，讓 AI 知道資料並不完整。
- `warnings` 一律輸出。
- JSON 鍵名一律英文，不隨介面語言變動；`reason` 等說明文字依匯出時的語言輸出。

## 6. GUI

```
┌ 工具列：[開啟檔案] [匯出 JSON] | 模式：靜態分析 [提升權限] | 語言：繁中▾ ┐
├ 概要列：KB · build · 架構 · 需重新開機 · 元件數 · ⚠ 高風險數 · 簽章狀態 ┤
├──────────────┬──────────────────────────────┬─────────────────┤
│ 分類樹        │ 動作表格（虛擬捲動）           │ 詳細資料窗格     │
│ 高風險 / 各類別│ 風險│類別│目標│動作│本機狀態    │ 全部欄位、命中規則│
│              │ 搜尋框 + 篩選（風險/類別/狀態） │ unknown 原始 XML │
├──────────────┴──────────────────────────────┴─────────────────┤
│ 狀態列：進度條 [取消] · 警告數（點擊查看）                          │
└──────────────────────────────────────────────────────────────┘
```

- 未載入檔案時，中央顯示大型拖放區。
- 匯出對話框：類別勾選、細節程度、即時預估大小；「複製摘要到剪貼簿」。
- 簽章無效時，概要列顯示紅色警告。

## 7. CLI

```
msu-inspector analyze <FILE> [--json <OUT>] [--detail summary|risk|full]
                             [--kinds file,service,...] [--compare-local] [--lang zh-TW|en]
```

- 未指定 `--json` 時，將摘要以文字輸出到 stdout。
- exit code：0 成功；1 分析完成但有 warnings；2 失敗。

## 8. 本機比對（管理員模式，唯讀）

| 項目 | 作法 | 狀態值 |
|------|------|--------|
| 檔案 | 讀本機對應路徑檔案版本（`GetFileVersionInfoW`） | `new` / `replace` / `same` / `downgrade` |
| 元件 | 列出 `C:\Windows\WinSxS\Manifests` 的檔名（keyform：`arch_短名稱_token_版本_語系_雜湊`），短名稱含 `..` 時以前綴 + 後綴比對 | `in_store_same` / `in_store_older` / `in_store_newer` / `not_in_store` |
| 適用性 | 比對 OS build 與架構 | 不符時報告頂端標示「此 KB 不適用本機，比對結果僅供參考」 |
| 服務 / 登錄 | 讀本機現值 | 顯示現值 → 新值 |

元件存放區（WinSxS）同時包含「已安裝」與「僅暫存」的元件，因此狀態值以 `in_store_*` 命名，不宣稱「已安裝」。程式不寫入系統任何位置。

## 9. 錯誤處理

- 單一 manifest 失敗（解壓或解析）不會中斷分析：記入 `warnings`，並在 GUI 狀態列提示。
- 整包層級失敗（格式不支援、檔案毀損、容器無法開啟）：明確報錯並中止。
- `.msu` Authenticode 簽章無效：照常分析，但報告與 GUI 顯示明顯警告。
- DCM 基底字典與本機 `wcp.dll` 版本不符而無法解壓：標記該 manifest 為「無法解壓」，不輸出猜測內容。
- 使用者取消：清除暫存資料夾，回到初始狀態。

## 10. 測試策略

- **單元測試（TDD）**：以手寫的小型 manifest / `.mum` 樣本，測試解析、分類、風險規則、JSON 匯出與篩選、大小預估。
- **容器測試**：測試時以系統 `makecab.exe` 產生小型巢狀 CAB，驗證拆包。
- **真實樣本整合測試**：真實 `.msu` 太大，不放進 repo。設定環境變數 `MSU_INSPECTOR_SAMPLES=<資料夾>` 才執行，涵蓋傳統 LCU、24H2 PSF 格式、.NET 累積更新、SSU 各一包；README 附上從 Microsoft Update Catalog 取得樣本的清單。
- **CLI 端對端**：`assert_cmd`。

## 11. 格式研究結果（2026-09-25）

實作前在本機（Windows 11 26100）驗證，並參考 PSFExtractor、PatchExtract.ps1 的公開原始碼：

- WinSxS manifest 以 `DCM\x01` 開頭，後接 PA30 差異資料；以 `wcp.dll` 資源（型別 `0x266`、ID `1`，9,066 位元組的 XML）為基底呼叫 `ApplyDeltaB` 即可還原。本機 19,173 個 manifest 全數成功。
- 本機 manifest 的頂層元素統計決定了第 4.2 節的分類；服務定義位於 `memberships` 內，而非頂層。
- 累積更新的 `.mum` 為 PSFX 格式（`customInformation PackageFormat="PSFX"`），頂層套件以 `<update><package>` 參照數千個子套件，元件清單在子套件 `.mum` 的 `<update><component>` 中。
- 24H2 起 `.msu` 本身為 WIM（檔頭 `MSWIM`）；內含的 `.psf` 在偏移 4 有 u32 索引長度，偏移 `0x80` 起為 PA30（空來源）壓縮的索引 XML（`<Container type="PSF"><Files><File name><Delta><Source type offset length>`）。
- 詳細資料窗格的「原始 XML」只保留給 `unknown` 動作；其餘動作以結構化欄位呈現，避免大型 LCU 在記憶體中保留數百 MB 的 manifest 原文。
