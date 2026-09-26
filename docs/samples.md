# 真實樣本測試

真實 `.msu` 動輒數百 MB 到數 GB，不放進 repo。從 [Microsoft Update Catalog](https://www.catalog.update.microsoft.com/) 搜尋並下載下列各一包到同一個資料夾：

| 類型 | Catalog 搜尋字串 | 驗證重點 |
|------|------------------|----------|
| 24H2 LCU（`.msu` 為 WIM） | `Cumulative Update for Windows 11 Version 24H2 for x64` | WIM 外層、PSF、UpdateCompression |
| 23H2 LCU | `Cumulative Update for Windows 11 Version 23H2 for x64` | CAB 內含 CAB、PSFX |
| Windows 10 22H2 LCU | `Cumulative Update for Windows 10 Version 22H2 for x64` | 傳統格式 |
| Server 2022 LCU | `Cumulative Update for Microsoft server operating system version 21H2 for x64` | Server 版本 |
| .NET Framework CU | `Cumulative Update for .NET Framework 3.5 and 4.8.1 for Windows 11, version 24H2 for x64` | 非 Windows 元件版本 |
| SSU（若有獨立發行） | `Servicing Stack Update for Windows Server 2019 for x64` | 小型套件 |

執行：

    $env:MSU_INSPECTOR_SAMPLES = "D:\msu-samples"
    cargo test --release --test samples -- --nocapture

每個檔案會輸出：格式、元件數、動作數、高風險數、警告數，並在同一資料夾寫出 `<檔名>.full.json`。

24H2 樣本（WIM 格式）若在一般權限終端機下出現 `needs elevation`，請以系統管理員身分重新開啟終端機再跑一次。
