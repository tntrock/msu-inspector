# msu-inspector

Windows 更新套件（`.msu` / `.cab`）部署前審查工具：**不安裝**，靜態解析 KB 安裝後會對系統做的動作（檔案、登錄、服務、驅動、排程工作、執行指令、防火牆規則、WMI、進階安裝程式…），依規則標示風險，並可匯出 JSON 交給雲端 AI 進一步分析。

## 功能

- 拖放 `.msu` / `.cab`，自動辨識傳統 CAB 格式與 24H2 起的 WIM + PSF 格式
- 解開 WinSxS 的 DCM 壓縮 manifest（使用 Windows 內建的 msdelta 與 servicing stack 基底）
- 風險規則（開機驅動、genericCommand、LSA / 自動啟動登錄、允許輸入的防火牆規則…），每筆標記都附理由
- 系統管理員模式下與本機比對：檔案版本、元件存放區、登錄值、服務設定、排程工作
- JSON 匯出：可選類別與細節程度（統計 / 高風險 / 全部），即時預估大小
- 繁體中文 / English 介面；GUI 與 CLI 同一個 exe

## 使用

GUI：直接執行 `msu-inspector.exe`，或把更新檔拖到 exe 上。一般權限啟動時會詢問要「靜態分析」或「以系統管理員重新啟動」。

CLI：

    msu-inspector analyze <檔案> [--json <輸出.json>|-] [--detail summary|risk|full]
                          [--kinds file,service,...] [--compare-local] [--lang zh-TW|en]

Exit code：0 成功、1 完成但有警告、2 失敗。

## 建置

需要 Rust（stable）與 Windows 10 以上：

    cargo build --release

## 已知限制

- 本機比對以 `WinSxS\Manifests` 判斷元件是否在存放區，存放區同時包含已安裝與暫存的元件
- 檔案沒有個別版本欄位，「新版本」以所屬元件版本表示
- 尚未以真實 `.msu` 樣本完整測試（見 `docs/samples.md`）；WIM 格式（Windows 11 24H2 起）的套件可能需要以系統管理員身分執行——WIM 解壓縮只在以系統管理員權限執行測試時才會被涵蓋，非系統管理員權限下執行測試會略過該部分

## 授權

MIT

---

# msu-inspector (English)

A pre-deployment review tool for Windows update packages (`.msu` / `.cab`). Without installing anything, it statically parses what a KB would do to the system (files, registry, services, drivers, scheduled tasks, commands, firewall rules, WMI, advanced installers…), flags risky actions with explained rules, and exports JSON for further analysis by an AI.

## Features

- Drag and drop `.msu` / `.cab`; handles classic CAB packages and the WIM + PSF format used since Windows 11 24H2
- Decodes DCM-compressed WinSxS manifests with the built-in msdelta and the servicing-stack base manifest
- Rule-based risk flags (boot drivers, genericCommand, LSA / autostart registry, inbound-allow firewall rules…), each with a reason
- Local comparison when running as administrator: file versions, component store, registry values, service configuration, scheduled tasks
- JSON export with kind filter and detail level (summary / high-risk / full) plus live size estimate
- Traditional Chinese / English UI; GUI and CLI in one executable

## Usage

GUI: run `msu-inspector.exe` or drop an update onto it. When started without elevation it asks whether to run static analysis or restart as administrator.

CLI:

    msu-inspector analyze <file> [--json <out.json>|-] [--detail summary|risk|full]
                          [--kinds file,service,...] [--compare-local] [--lang zh-TW|en]

Exit codes: 0 success, 1 completed with warnings, 2 failure.

## Build

Requires Rust (stable) on Windows 10 or later:

    cargo build --release

## Known limitations

- Local comparison uses `WinSxS\Manifests` to decide whether a component is in the store; the store holds both installed and staged components
- Files have no individual version field; a file's new version is its component's version
- Real `.msu` samples have not been fully tested yet (see `docs/samples.md`); WIM-format packages (Windows 11 24H2 and later) may require running as administrator — WIM extraction is only exercised when tests are run with elevated privileges, and a non-elevated test run skips that part

## License

MIT
