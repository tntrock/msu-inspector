# msu-inspector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 建立 `msu-inspector`：拖入 Windows 更新套件（`.msu` / `.cab`），不安裝、靜態解析出 KB 安裝後會對系統做的動作，標示風險，可選擇與本機比對，並匯出給 AI 分析用的 JSON（GUI + CLI，繁中 / English）。

**Architecture:** 單一 Rust crate，`core/` 不依賴 GUI。資料流：簽章驗證 → 容器偵測 → 遞迴拆容器（CAB 用 cabinet.dll FDI、WIM 用 wimgapi、PSF 自行解析索引）→ DCM 解壓（msdelta + wcp.dll 基底）→ roxmltree 解析 manifest / `.mum` → `AnalysisReport` →（管理員）本機比對 → 風險規則 → GUI（eframe/egui）或 JSON 匯出。Windows DLL 一律動態載入或 raw-dylib 連結，不需要 Windows SDK 的 import library。

**Tech Stack:** Rust 2021（本機 rustc 1.96）、eframe/egui 0.36、egui_extras 0.36、rfd 0.17、clap 4.6、roxmltree 0.21、serde/serde_json、thiserror 2、sha2 0.10、tempfile 3、windows 0.62；測試：assert_cmd 2、系統內建 `makecab.exe`。

**Spec:** `docs/superpowers/specs/2026-09-25-msu-inspector-design.md`（含第 11 節格式研究結果）

## Global Constraints

- 只支援 Windows（x64 / ARM64）；`cargo test` 在 Windows 上執行，測試可使用系統的 `makecab.exe`、`msdelta.dll`、`C:\Windows\WinSxS`。
- Rust edition 2021；相依套件僅限 Tech Stack 所列，新增任何 crate 前先詢問使用者。
- 程式註解、文件用繁體中文，與 `D:\VSCode\code-signer` 一致；識別字用英文。
- GUI 文字與 CLI 輸出訊息都放在 `src/i18n.rs`（`Strings` 的 `ZH_TW` / `EN`，以及同檔的在地化函式），其他檔案不寫死介面文字；例外：clap 的 `--help` 說明用英文 doc comment、風險規則理由放在 `risk.rs` 規則表（中英各一）、警告訊息放在 `export::warning_message`（中英各一）。
- JSON 鍵名一律英文、`schema_version` 為 `"1.0"`，不隨介面語言改變；只有 `reason`、`message` 等說明文字依匯出語言輸出。
- 程式**不修改系統**：只讀檔案與登錄；暫存資料夾在分析結束時刪除（`tempfile::TempDir`）。
- 只載入 System32 內的系統 DLL；`.msu` 附帶的 `UpdateCompression.dll` 必須先通過 `WinVerifyTrust` 且簽章者含 `Microsoft` 才可載入。
- 本機比對只在程序以系統管理員身分執行時啟用；CLI `--compare-local` 在非管理員時回報錯誤。
- CLI exit code：`0` 成功；`1` 分析完成但有 warnings；`2` 失敗。
- release profile：`opt-level = "z"`、`lto = true`、`codegen-units = 1`、`strip = true`、`panic = "abort"`。
- 每個 commit 訊息結尾加上 `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`。

## Review Focus

1. **24H2 WIM 格式的 `.msu` 在非管理員下展開失敗**：wimgapi 若回報權限不足（`ERROR_PRIVILEGE_NOT_HELD` / `ERROR_ACCESS_DENIED`），必須轉成 `CoreError::NeedsElevation`，GUI 顯示「請以系統管理員重新啟動」，而不是籠統的失敗。→ Task 7 測試 `maps_privilege_errors_to_needs_elevation`。
2. **大型 LCU 的取消與暫存清理**：分析中途按「取消」要在數秒內停止，且暫存資料夾被刪除。→ Task 6 `cancel_aborts_extraction`、Task 13 `cancel_removes_temp_dir`。
3. **路徑含中文**（例如 `D:\下載\KB.msu`）：FDI 的 ANSI 路徑參數不得造成開檔失敗。→ Task 6 `extracts_from_non_ascii_path`。
4. **非更新檔被拖進來**（任意 exe、zip、空檔、截斷的 CAB）：回報「不支援的格式」或容器錯誤，不 panic。→ Task 9 `rejects_non_update_files`、Task 6 `rejects_non_cab`。
5. **編碼**：`.mum` 以 UTF-8 BOM 開頭、`pkgProperties.txt` 為 UTF-16LE BOM；都要正確解析。→ Task 4 `parses_mum_with_bom`、`parses_utf16_pkg_properties`。

## File Structure

```
Cargo.toml / build.rs / assets/gen_icon.py / assets/icon.ico
.github/workflows/ci.yml
src/
  main.rs              進入點：無參數或只帶檔案 → GUI；子指令 → CLI
  lib.rs
  i18n.rs              Lang + Strings（繁中 / English）
  elevation.rs         是否為管理員、以 runas 重新啟動
  cli.rs               clap CLI
  core/
    mod.rs
    error.rs           CoreError
    model.rs           AnalysisReport 與所有資料型別、parse_version
    progress.rs        Progress、Ctx（進度回報 + 取消旗標）
    sys.rs             Windows 目錄、原生架構
    delta.rs           DeltaEngine（UpdateCompression / msdelta）、PA19、DCM
    signature.rs       WinVerifyTrust
    container/
      mod.rs           Role、Item、sniff、collect（遞迴拆包）、resolve_psfs
      cab.rs           cabinet.dll FDI
      wim.rs           wimgapi
      psf.rs           PSF 索引與還原
    manifest/
      mod.rs           decode_text、XML 小工具
      parse.rs         元件 manifest → Component
      package.rs       .mum / pkgProperties → PackageInfo
    analyze.rs         串起整個流程
    local.rs           本機比對
    risk.rs            風險規則表
    export.rs          JSON 匯出、大小預估、文字摘要
  gui/
    mod.rs             eframe 啟動、字型
    app.rs             主視窗、工具列、背景工作、拖放
    startup.rs         啟動時的模式選擇框
    results.rs         分類樹、表格、詳細資料、警告視窗
    export_dialog.rs   匯出對話框
tests/
  common/mod.rs        makecab 輔助、fixture 載入
  fixtures/*.manifest, *.mum
  delta.rs cab.rs wim.rs psf.rs collect.rs parse.rs package.rs analyze.rs local.rs risk.rs export.rs cli.rs winsxs.rs samples.rs
```

---

### Task 1: 專案骨架、資料模型、錯誤型別、進度

**Files:**
- Create: `Cargo.toml`, `build.rs`, `assets/gen_icon.py`, `assets/icon.ico`（由腳本產生）, `src/main.rs`, `src/lib.rs`, `src/i18n.rs`, `src/core/mod.rs`, `src/core/error.rs`, `src/core/model.rs`, `src/core/progress.rs`

**Interfaces:**
- Consumes: 無
- Produces:
  - `msu_inspector::i18n::Lang`（`ZhTw` / `En`；`ALL`、`code()`、`native_name()`、`parse(&str) -> Option<Lang>`、`detect()`）
  - `msu_inspector::core::CoreError`（`Io{path,source}`、`UnsupportedFormat(String)`、`Container{path,detail}`、`NeedsElevation(String)`、`Delta(String)`、`Xml(String)`、`NoPackageFound`、`Cancelled`、`Win32(String)`；`CoreError::io(&Path, io::Error)`）
  - `core::model::*`：`AssemblyIdentity`、`Risk`、`ActionKind`、各 `*Action` 結構、`ActionDetail`、`Action`、`LocalState`、`LocalStatus`、`Component`、`PackageInfo`、`SignatureStatus`、`SignatureInfo`、`ContainerFormat`、`ContainerInfo`、`SourceInfo`、`Mode`、`LocalContext`、`WarningCode`、`Warning`、`AnalysisReport`、`parse_version(&str) -> Option<[u32;4]>`
  - `core::progress::{Progress, Ctx}`（`Ctx::new(f)`、`Ctx::silent()`、`report(Progress)`、`is_cancelled()`、`check() -> Result<(), CoreError>`、`cancel_flag() -> Arc<AtomicBool>`）

- [ ] **Step 1: 建立 `Cargo.toml`**

```toml
[package]
name = "msu-inspector"
version = "0.1.0"
edition = "2021"
description = "Windows 更新套件（.msu）部署前審查工具（GUI + CLI）"
license = "MIT"
repository = "https://github.com/tntrock/msu-inspector"
build = "build.rs"
publish = false

[lib]
name = "msu_inspector"
path = "src/lib.rs"

[[bin]]
name = "msu-inspector"
path = "src/main.rs"

[dependencies]
# ---- GUI ----
eframe = "0.36"
egui_extras = "0.36"
rfd = "0.17"

# ---- CLI ----
clap = { version = "4.6", features = ["derive"] }

# ---- 解析 ----
roxmltree = "0.21"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
tempfile = "3"
thiserror = "2"

# ---- Win32 ----
[dependencies.windows]
version = "0.62"
features = [
    "Win32_Foundation",
    "Win32_Globalization",
    "Win32_Security",
    "Win32_Security_Cryptography",
    "Win32_Security_WinTrust",
    "Win32_Storage_Cabinets",
    "Win32_Storage_FileSystem",
    "Win32_System_Console",
    "Win32_System_LibraryLoader",
    "Win32_System_Memory",
    "Win32_System_Registry",
    "Win32_System_SystemInformation",
    "Win32_System_Threading",
    "Win32_UI_Shell",
    "Win32_UI_WindowsAndMessaging",
]

[dev-dependencies]
assert_cmd = "2"

[target.'cfg(windows)'.build-dependencies]
winresource = "0.1"

[profile.release]
opt-level = "z"
lto = true
codegen-units = 1
strip = true
panic = "abort"
```

- [ ] **Step 2: 建立 `build.rs` 與圖示**

`build.rs`：

```rust
//! 建置腳本：在 Windows 目標上把 assets/icon.ico 與版本資訊嵌入 exe。
//!
//! build.rs 在「主機」上執行，所以用 CARGO_CFG_TARGET_OS 判斷目標平台，而不是 cfg!(target_os)。

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/icon.ico");
        res.set("ProductName", "msu-inspector");
        res.set(
            "FileDescription",
            "msu-inspector - Windows 更新套件部署前審查工具",
        );
        // 缺 rc.exe 等工具時只警告，不中斷建置
        if let Err(e) = res.compile() {
            println!("cargo:warning=嵌入 Windows 資源失敗: {e}");
        }
    }
    println!("cargo:rerun-if-changed=assets/icon.ico");
    println!("cargo:rerun-if-changed=build.rs");
}
```

`assets/gen_icon.py`（只用 Python 標準函式庫；圖案：藍底白色放大鏡）：

```python
"""產生 assets/icon.ico（只用 Python 標準函式庫）。

圖案：藍色圓角方塊上的白色放大鏡，代表「檢視更新內容」。
執行：python assets/gen_icon.py
"""
import math
import struct
import zlib
from pathlib import Path

SIZES = [16, 32, 48, 256]
BG = (0x1F, 0x6F, 0xEB)
FG = (0xFF, 0xFF, 0xFF)


def pixel(u, v):
    """u, v ∈ [0,1)；回傳 RGBA。"""
    r = 0.2  # 圓角半徑
    cx = min(max(u, r), 1 - r)
    cy = min(max(v, r), 1 - r)
    if math.hypot(u - cx, v - cy) > r:
        return (0, 0, 0, 0)
    # 鏡片：圓環
    d = math.hypot(u - 0.43, v - 0.43)
    if 0.17 <= d <= 0.25:
        return FG + (255,)
    # 握把：從右下沿 45 度延伸的線段
    t = ((u - 0.58) + (v - 0.58)) / 2
    if 0.0 <= t <= 0.2 and abs((u - 0.58) - (v - 0.58)) < 0.09:
        return FG + (255,)
    return BG + (255,)


def png(size):
    rows = b""
    for y in range(size):
        rows += b"\x00" + b"".join(
            bytes(pixel((x + 0.5) / size, (y + 0.5) / size)) for x in range(size)
        )

    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(rows, 9))
        + chunk(b"IEND", b"")
    )


def main():
    images = [png(s) for s in SIZES]
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries = b""
    for s, img in zip(SIZES, images):
        dim = 0 if s == 256 else s
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(img), offset)
        offset += len(img)
    out = Path(__file__).with_name("icon.ico")
    out.write_bytes(header + entries + b"".join(images))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
```

Run: `python assets/gen_icon.py`
Expected: `wrote ...\assets\icon.ico`

- [ ] **Step 3: 建立 `src/lib.rs`、`src/main.rs`（暫時版本）、`src/core/mod.rs`**

`src/lib.rs`：

```rust
//! msu-inspector：Windows 更新套件部署前審查工具。

pub mod core;
pub mod i18n;
```

`src/main.rs`（Task 14 會換成正式版本）：

```rust
//! msu-inspector 進入點（Task 14 接上 GUI / CLI）。

fn main() {}
```

`src/core/mod.rs`：

```rust
//! 核心邏輯：不依賴 GUI，可單獨測試。

pub mod error;
pub mod model;
pub mod progress;

pub use error::CoreError;
```

- [ ] **Step 4: 建立 `src/i18n.rs`（只有 `Lang`；`Strings` 在 Task 14 加入）**

```rust
//! 介面語言：繁體中文 / English。

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    ZhTw,
    En,
}

impl Lang {
    pub const ALL: [Lang; 2] = [Lang::ZhTw, Lang::En];

    /// `--lang` 與 JSON `export_filter.language` 使用的代碼。
    pub fn code(self) -> &'static str {
        match self {
            Lang::ZhTw => "zh-TW",
            Lang::En => "en",
        }
    }

    /// 語言選單顯示的名稱（永遠用該語言本身書寫）。
    pub fn native_name(self) -> &'static str {
        match self {
            Lang::ZhTw => "繁體中文",
            Lang::En => "English",
        }
    }

    /// 解析語言代碼（不分大小寫；`zh`、`zh-tw`、`zh_TW` 皆視為繁中）。
    pub fn parse(s: &str) -> Option<Lang> {
        let s = s.trim().to_ascii_lowercase().replace('_', "-");
        match s.as_str() {
            "zh" | "zh-tw" | "zh-hant" | "zh-hk" | "zh-mo" => Some(Lang::ZhTw),
            "en" | "en-us" | "en-gb" => Some(Lang::En),
            _ => None,
        }
    }

    /// 由 Windows LANGID 判斷：zh-TW(0x0404)、zh-HK(0x0C04)、zh-MO(0x1404) → 繁中，其餘英文。
    pub fn from_langid(langid: u16) -> Lang {
        match langid {
            0x0404 | 0x0C04 | 0x1404 => Lang::ZhTw,
            _ => Lang::En,
        }
    }

    /// 依環境變數 `MSU_INSPECTOR_LANG`，其次 Windows 顯示語言決定預設語言。
    pub fn detect() -> Lang {
        if let Some(l) = std::env::var("MSU_INSPECTOR_LANG").ok().and_then(|v| Lang::parse(&v)) {
            return l;
        }
        // SAFETY: 無參數、無副作用的查詢。
        let id = unsafe { windows::Win32::Globalization::GetUserDefaultUILanguage() };
        Lang::from_langid(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_language_codes() {
        assert_eq!(Lang::parse("zh_TW"), Some(Lang::ZhTw));
        assert_eq!(Lang::parse(" EN "), Some(Lang::En));
        assert_eq!(Lang::parse("fr"), None);
        assert_eq!(Lang::from_langid(0x0404), Lang::ZhTw);
        assert_eq!(Lang::from_langid(0x0409), Lang::En);
    }
}
```

- [ ] **Step 5: 寫 `src/core/model.rs` 的失敗測試**

先建立檔案，只放測試模組（型別尚未存在，編譯會失敗）：

```rust
//! 分析結果的資料模型；JSON 匯出直接序列化這些型別（鍵名一律英文）。

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn action_serializes_flat_with_kind() {
        let a = Action::new(ActionDetail::File(FileAction {
            name: "a.dll".into(),
            destination: "$(runtime.system32)\\".into(),
            is_pe: true,
            ..Default::default()
        }));
        let v = serde_json::to_value(&a).unwrap();
        assert_eq!(v["kind"], "file");
        assert_eq!(v["name"], "a.dll");
        assert_eq!(v["risk"], "info");
        assert!(v.get("rules").is_none());
        assert!(v.get("local").is_none());
        assert!(v.get("source_name").is_none());
    }

    #[test]
    fn local_status_uses_spec_keys() {
        let s = LocalStatus {
            state: LocalState::Replace,
            current: Some("10.0.1".into()),
            incoming: Some("10.0.2".into()),
        };
        assert_eq!(
            serde_json::to_value(&s).unwrap(),
            json!({"status": "replace", "from": "10.0.1", "to": "10.0.2"})
        );
    }

    #[test]
    fn kind_codes_round_trip() {
        for k in ActionKind::ALL {
            assert_eq!(ActionKind::parse(k.code()), Some(k));
            assert_eq!(serde_json::to_value(k).unwrap(), json!(k.code()));
        }
        assert_eq!(ActionKind::parse("nope"), None);
    }

    #[test]
    fn risk_orders_by_severity() {
        assert!(Risk::High > Risk::Medium && Risk::Medium > Risk::Low && Risk::Low > Risk::Info);
        assert_eq!(Risk::ALL[0], Risk::High);
    }

    #[test]
    fn mode_serializes_like_spec() {
        assert_eq!(serde_json::to_value(Mode::StaticLocal).unwrap(), json!("static+local"));
        assert_eq!(Mode::Static.code(), "static");
    }

    #[test]
    fn parses_versions() {
        assert_eq!(parse_version("10.0.26100.1742"), Some([10, 0, 26100, 1742]));
        assert_eq!(parse_version("6.1"), Some([6, 1, 0, 0]));
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("1.2.3.4.5"), None);
        assert_eq!(parse_version("a.b"), None);
    }

    #[test]
    fn targets_are_readable() {
        let reg = ActionDetail::Registry(RegistryAction {
            key: "HKEY_LOCAL_MACHINE\\SOFTWARE\\X".into(),
            value_name: Some(String::new()),
            ..Default::default()
        });
        assert_eq!(reg.target(), "HKEY_LOCAL_MACHINE\\SOFTWARE\\X [(default)]");
        let file = ActionDetail::File(FileAction {
            name: "a.dll".into(),
            destination: "$(runtime.system32)".into(),
            ..Default::default()
        });
        assert_eq!(file.target(), "$(runtime.system32)\\a.dll");
    }
}
```

- [ ] **Step 6: 執行測試確認失敗**

Run: `cargo test --lib model`
Expected: 編譯失敗（`Action`、`ActionDetail` 等未定義）

- [ ] **Step 7: 實作 `src/core/model.rs`（放在測試模組上方）**

```rust
use std::collections::BTreeMap;

use serde::Serialize;

/// manifest / .mum 的 `assemblyIdentity`。
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct AssemblyIdentity {
    pub name: String,
    pub version: String,
    pub arch: String,
    pub language: String,
    pub public_key_token: String,
}

impl AssemblyIdentity {
    /// 顯示與搜尋用：`名稱 版本 (架構, 語系)`。
    pub fn display(&self) -> String {
        format!(
            "{} {} ({}, {})",
            self.name, self.version, self.arch, self.language
        )
    }
}

/// 風險等級；`Ord` 依嚴重程度排序（High 最大）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    #[default]
    Info,
    Low,
    Medium,
    High,
}

impl Risk {
    /// 由高到低，GUI 與摘要依此順序列出。
    pub const ALL: [Risk; 4] = [Risk::High, Risk::Medium, Risk::Low, Risk::Info];

    pub fn code(self) -> &'static str {
        match self {
            Risk::Info => "info",
            Risk::Low => "low",
            Risk::Medium => "medium",
            Risk::High => "high",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    File,
    Registry,
    Directory,
    Service,
    Driver,
    ScheduledTask,
    GenericCommand,
    FirewallRule,
    WmiMof,
    EtwEventlog,
    AdvancedInstaller,
    Setting,
    Unknown,
}

impl ActionKind {
    pub const ALL: [ActionKind; 13] = [
        ActionKind::File,
        ActionKind::Registry,
        ActionKind::Directory,
        ActionKind::Service,
        ActionKind::Driver,
        ActionKind::ScheduledTask,
        ActionKind::GenericCommand,
        ActionKind::FirewallRule,
        ActionKind::WmiMof,
        ActionKind::EtwEventlog,
        ActionKind::AdvancedInstaller,
        ActionKind::Setting,
        ActionKind::Unknown,
    ];

    /// JSON 與 `--kinds` 使用的代碼。
    pub fn code(self) -> &'static str {
        match self {
            ActionKind::File => "file",
            ActionKind::Registry => "registry",
            ActionKind::Directory => "directory",
            ActionKind::Service => "service",
            ActionKind::Driver => "driver",
            ActionKind::ScheduledTask => "scheduled_task",
            ActionKind::GenericCommand => "generic_command",
            ActionKind::FirewallRule => "firewall_rule",
            ActionKind::WmiMof => "wmi_mof",
            ActionKind::EtwEventlog => "etw_eventlog",
            ActionKind::AdvancedInstaller => "advanced_installer",
            ActionKind::Setting => "setting",
            ActionKind::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Option<ActionKind> {
        let s = s.trim();
        ActionKind::ALL
            .into_iter()
            .find(|k| k.code().eq_ignore_ascii_case(s))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FileAction {
    pub name: String,
    pub destination: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sddl_name: Option<String>,
    pub is_pe: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RegistryAction {
    pub key: String,
    /// `None` 表示只建立機碼；`Some("")` 為預設值。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// `replace` / `append` / `prepend` / `create_key`
    pub operation: String,
    pub owner: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sddl_name: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DirectoryAction {
    pub path: String,
    pub owner: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sddl_name: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ServiceAction {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub required_privileges: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub depend_on: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DriverAction {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_type: Option<String>,
    pub boot_critical: bool,
    /// `service`（來自 serviceData）或 `file`（只有 .sys 檔）
    pub origin: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TaskAction {
    pub uri: String,
    pub exec: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_as: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_level: Option<String>,
    pub triggers: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CommandAction {
    pub executable: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<String>,
    /// `install="false"` 的指令只在移除時執行
    pub runs_on_install: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FirewallAction {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_ports: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_ports: Option<String>,
    /// `element`（`<firewallRule>`）或 `registry`（FirewallRules 登錄值）
    pub origin: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MofAction {
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uninstall_file: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct EtwAction {
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guid: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AdvancedInstallerAction {
    pub element: String,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SettingAction {
    pub element: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct UnknownAction {
    pub element: String,
    pub raw_xml: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActionDetail {
    File(FileAction),
    Registry(RegistryAction),
    Directory(DirectoryAction),
    Service(ServiceAction),
    Driver(DriverAction),
    ScheduledTask(TaskAction),
    GenericCommand(CommandAction),
    FirewallRule(FirewallAction),
    WmiMof(MofAction),
    EtwEventlog(EtwAction),
    AdvancedInstaller(AdvancedInstallerAction),
    Setting(SettingAction),
    Unknown(UnknownAction),
}

/// 把目錄與名稱接成路徑；目錄已以 `\` 結尾時不重複加。
fn join_path(dir: &str, name: &str) -> String {
    if dir.is_empty() || dir.ends_with('\\') {
        format!("{dir}{name}")
    } else {
        format!("{dir}\\{name}")
    }
}

impl ActionDetail {
    pub fn kind(&self) -> ActionKind {
        match self {
            ActionDetail::File(_) => ActionKind::File,
            ActionDetail::Registry(_) => ActionKind::Registry,
            ActionDetail::Directory(_) => ActionKind::Directory,
            ActionDetail::Service(_) => ActionKind::Service,
            ActionDetail::Driver(_) => ActionKind::Driver,
            ActionDetail::ScheduledTask(_) => ActionKind::ScheduledTask,
            ActionDetail::GenericCommand(_) => ActionKind::GenericCommand,
            ActionDetail::FirewallRule(_) => ActionKind::FirewallRule,
            ActionDetail::WmiMof(_) => ActionKind::WmiMof,
            ActionDetail::EtwEventlog(_) => ActionKind::EtwEventlog,
            ActionDetail::AdvancedInstaller(_) => ActionKind::AdvancedInstaller,
            ActionDetail::Setting(_) => ActionKind::Setting,
            ActionDetail::Unknown(_) => ActionKind::Unknown,
        }
    }

    /// 表格「目標」欄：最能代表此動作的路徑、機碼或名稱。
    pub fn target(&self) -> String {
        match self {
            ActionDetail::File(f) => join_path(&f.destination, &f.name),
            ActionDetail::Registry(r) => match &r.value_name {
                None => r.key.clone(),
                Some(v) if v.is_empty() => format!("{} [(default)]", r.key),
                Some(v) => format!("{} [{v}]", r.key),
            },
            ActionDetail::Directory(d) => d.path.clone(),
            ActionDetail::Service(s) => s.name.clone(),
            ActionDetail::Driver(d) => d.name.clone(),
            ActionDetail::ScheduledTask(t) => t.uri.clone(),
            ActionDetail::GenericCommand(c) => match &c.arguments {
                Some(a) if !a.is_empty() => format!("{} {a}", c.executable),
                _ => c.executable.clone(),
            },
            ActionDetail::FirewallRule(f) => f.name.clone(),
            ActionDetail::WmiMof(m) => m.file.clone(),
            ActionDetail::EtwEventlog(e) => e.provider.clone(),
            ActionDetail::AdvancedInstaller(a) => a.element.clone(),
            ActionDetail::Setting(s) => s.element.clone(),
            ActionDetail::Unknown(u) => u.element.clone(),
        }
    }
}

/// 本機比對狀態。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalState {
    /// 本機不存在，會新增
    New,
    /// 本機存在但內容 / 版本不同，會被取代
    Replace,
    /// 與本機相同
    Same,
    /// 本機版本較新（套件會降版）
    Downgrade,
    /// 本機已存在，但無法比較內容
    Present,
    /// 目標路徑無法對應到本機位置
    UnknownPath,
    InStoreSame,
    InStoreOlder,
    InStoreNewer,
    NotInStore,
}

impl LocalState {
    pub const ALL: [LocalState; 10] = [
        LocalState::New,
        LocalState::Replace,
        LocalState::Same,
        LocalState::Downgrade,
        LocalState::Present,
        LocalState::UnknownPath,
        LocalState::InStoreSame,
        LocalState::InStoreOlder,
        LocalState::InStoreNewer,
        LocalState::NotInStore,
    ];

    pub fn code(self) -> &'static str {
        match self {
            LocalState::New => "new",
            LocalState::Replace => "replace",
            LocalState::Same => "same",
            LocalState::Downgrade => "downgrade",
            LocalState::Present => "present",
            LocalState::UnknownPath => "unknown_path",
            LocalState::InStoreSame => "in_store_same",
            LocalState::InStoreOlder => "in_store_older",
            LocalState::InStoreNewer => "in_store_newer",
            LocalState::NotInStore => "not_in_store",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalStatus {
    #[serde(rename = "status")]
    pub state: LocalState,
    #[serde(rename = "from", skip_serializing_if = "Option::is_none")]
    pub current: Option<String>,
    #[serde(rename = "to", skip_serializing_if = "Option::is_none")]
    pub incoming: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Action {
    #[serde(flatten)]
    pub detail: ActionDetail,
    pub risk: Risk,
    /// 命中的風險規則 ID（見 `risk.rs`）
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local: Option<LocalStatus>,
}

impl Action {
    pub fn new(detail: ActionDetail) -> Self {
        Action {
            detail,
            risk: Risk::Info,
            rules: Vec::new(),
            local: None,
        }
    }

    pub fn kind(&self) -> ActionKind {
        self.detail.kind()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Component {
    pub identity: AssemblyIdentity,
    /// manifest 檔名
    pub manifest: String,
    /// `Microsoft.Windows.Categories` 的 typeName（BootCritical、Service…）
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
    pub actions: Vec<Action>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local: Option<LocalStatus>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PackageInfo {
    pub kb: Option<String>,
    pub identity: AssemblyIdentity,
    pub release_type: Option<String>,
    /// `required` / `possible` / `never`
    pub restart: Option<String>,
    pub description: Option<String>,
    pub support_url: Option<String>,
    pub psfx: bool,
    pub applicability: Vec<String>,
    pub properties: BTreeMap<String, String>,
    pub sub_packages: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    Valid,
    Unsigned,
    Invalid,
    #[default]
    Unknown,
}

impl SignatureStatus {
    pub fn code(self) -> &'static str {
        match self {
            SignatureStatus::Valid => "valid",
            SignatureStatus::Unsigned => "unsigned",
            SignatureStatus::Invalid => "invalid",
            SignatureStatus::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SignatureInfo {
    pub status: SignatureStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerFormat {
    Cab,
    Wim,
    Psf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContainerInfo {
    pub path: String,
    pub format: ContainerFormat,
    /// 略過或失敗的原因；正常展開為 None
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SourceInfo {
    pub file: String,
    pub size: u64,
    pub sha256: String,
    /// `msu-cab` / `msu-wim` / `cab`，含 PSF 時加上 `+psf`
    pub format: String,
    pub signature: SignatureInfo,
    pub containers: Vec<ContainerInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta_engine: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub enum Mode {
    #[default]
    #[serde(rename = "static")]
    Static,
    #[serde(rename = "static+local")]
    StaticLocal,
}

impl Mode {
    pub fn code(self) -> &'static str {
        match self {
            Mode::Static => "static",
            Mode::StaticLocal => "static+local",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct LocalContext {
    /// 例如 `26100.4202`
    pub os_build: String,
    pub arch: String,
    pub applicable: bool,
    /// `arch_mismatch` / `build_mismatch`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_applicable_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WarningCode {
    ManifestDecodeFailed,
    ManifestParseFailed,
    MumParseFailed,
    ContainerFailed,
    PsfFailed,
    SignatureNotValid,
    LocalCompareFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Warning {
    pub code: WarningCode,
    pub subject: String,
    pub detail: String,
}

impl Warning {
    pub fn new(code: WarningCode, subject: impl Into<String>, detail: impl Into<String>) -> Self {
        Warning {
            code,
            subject: subject.into(),
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AnalysisReport {
    pub mode: Mode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_context: Option<LocalContext>,
    pub source: SourceInfo,
    pub package: PackageInfo,
    pub components: Vec<Component>,
    pub warnings: Vec<Warning>,
}

impl AnalysisReport {
    pub fn action_count(&self) -> usize {
        self.components.iter().map(|c| c.actions.len()).sum()
    }
}

/// 解析 `a.b.c.d` 版本字串；缺少的欄位補 0，非數字或超過四段回傳 None。
pub fn parse_version(s: &str) -> Option<[u32; 4]> {
    let mut out = [0u32; 4];
    for (i, part) in s.trim().split('.').enumerate() {
        if i >= 4 {
            return None;
        }
        out[i] = part.parse().ok()?;
    }
    Some(out)
}
```

- [ ] **Step 8: 建立 `src/core/error.rs` 與 `src/core/progress.rs`**

`src/core/error.rs`：

```rust
//! core 的錯誤型別；Display 為英文（CLI / 記錄用），GUI 經 i18n 轉成在地化訊息。

use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("I/O error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("unsupported file format: {0}")]
    UnsupportedFormat(String),
    #[error("cannot unpack {path}: {detail}")]
    Container { path: String, detail: String },
    #[error("administrator rights required: {0}")]
    NeedsElevation(String),
    #[error("delta decompression failed: {0}")]
    Delta(String),
    #[error("XML error: {0}")]
    Xml(String),
    #[error("no update package (.mum / .manifest) found")]
    NoPackageFound,
    #[error("cancelled")]
    Cancelled,
    #[error("Windows API error: {0}")]
    Win32(String),
}

impl CoreError {
    pub fn io(path: &Path, source: std::io::Error) -> Self {
        CoreError::Io {
            path: path.display().to_string(),
            source,
        }
    }
}
```

`src/core/progress.rs`：

```rust
//! 背景分析的進度回報與取消旗標。

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use super::CoreError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Progress {
    Hashing,
    Verifying,
    Unpacking { container: String },
    Decoding { done: usize, total: usize },
    Comparing { done: usize, total: usize },
}

type ProgressFn = dyn Fn(Progress) + Send + Sync;

/// 分析流程共用的環境：進度回呼 + 取消旗標。可 clone 給工作執行緒。
#[derive(Clone)]
pub struct Ctx {
    cancel: Arc<AtomicBool>,
    progress: Arc<ProgressFn>,
}

impl Ctx {
    pub fn new(progress: impl Fn(Progress) + Send + Sync + 'static) -> Self {
        Ctx {
            cancel: Arc::new(AtomicBool::new(false)),
            progress: Arc::new(progress),
        }
    }

    /// 不回報進度（CLI、測試）。
    pub fn silent() -> Self {
        Ctx::new(|_| {})
    }

    pub fn report(&self, p: Progress) {
        (self.progress)(p);
    }

    pub fn cancel_flag(&self) -> Arc<AtomicBool> {
        self.cancel.clone()
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    /// 已取消時回傳 `Err(CoreError::Cancelled)`，供各階段之間檢查。
    pub fn check(&self) -> Result<(), CoreError> {
        if self.is_cancelled() {
            Err(CoreError::Cancelled)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn reports_and_cancels() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let ctx = Ctx::new(move |p| s.lock().unwrap().push(p));
        ctx.report(Progress::Hashing);
        assert!(ctx.check().is_ok());
        ctx.cancel_flag().store(true, Ordering::Relaxed);
        assert!(matches!(ctx.check(), Err(CoreError::Cancelled)));
        assert_eq!(*seen.lock().unwrap(), vec![Progress::Hashing]);
    }
}
```

- [ ] **Step 9: 執行測試確認通過**

Run: `cargo test --lib`
Expected: `model`、`progress`、`i18n` 的測試全部 PASS

- [ ] **Step 10: 格式與 lint，然後 commit**

Run: `cargo fmt; cargo clippy --all-targets -- -D warnings`
Expected: 無警告

```bash
git add -A
git commit -m "feat: scaffold crate with data model, errors and progress context

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 2: 元件 manifest 解析（檔案、登錄、目錄、未知元素）

**Files:**
- Create: `src/core/manifest/mod.rs`, `src/core/manifest/parse.rs`, `tests/fixtures/basic.manifest`, `tests/parse.rs`
- Modify: `src/core/mod.rs`（加入 `pub mod manifest;`）

**Interfaces:**
- Consumes: Task 1 的 `model::*`、`CoreError`
- Produces:
  - `core::manifest::decode_text(&[u8]) -> Result<String, CoreError>`（處理 UTF-8 BOM、UTF-16LE/BE BOM，其餘 UTF-8 失敗時 lossy）
  - `core::manifest::parse::parse_component(manifest_name: &str, xml: &str) -> Result<Component, CoreError>`
  - `core::manifest::parse::is_pe_name(&str) -> bool`
  - crate 內部小工具：`manifest::{parse_doc, attr, child, elements, is_el, identity_of}`

- [ ] **Step 1: 建立 fixture `tests/fixtures/basic.manifest`**

```xml
<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v3" manifestVersion="1.0" copyright="Copyright (c) Microsoft Corporation. All Rights Reserved.">
  <assemblyIdentity name="Microsoft-Windows-AppReadiness-Service" version="10.0.26100.1591" processorArchitecture="amd64" language="neutral" buildType="release" publicKeyToken="31bf3856ad364e35" versionScope="nonSxS" />
  <dependency discoverable="no">
    <dependentAssembly dependencyType="install">
      <assemblyIdentity name="Other" version="10.0.26100.1" processorArchitecture="amd64" language="neutral" buildType="release" publicKeyToken="31bf3856ad364e35" />
    </dependentAssembly>
  </dependency>
  <file name="AppReadiness.dll" destinationPath="$(runtime.system32)\" sourceName="AppReadiness.dll" importPath="$(build.nttree)\" sourcePath=".\">
    <securityDescriptor name="WRP_FILE_DEFAULT_SDDL" />
    <asmv2:hash xmlns:asmv2="urn:schemas-microsoft-com:asm.v2" xmlns:dsig="http://www.w3.org/2000/09/xmldsig#">
      <dsig:Transforms>
        <dsig:Transform Algorithm="urn:schemas-microsoft-com:HashTransforms.Identity" />
      </dsig:Transforms>
      <dsig:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha256" />
      <dsig:DigestValue>q83vEjRWeJA=</dsig:DigestValue>
    </asmv2:hash>
  </file>
  <file name="readme.txt" destinationPath="$(runtime.windows)\AppReadiness\" sourceName="readme.txt" />
  <directories>
    <directory destinationPath="$(runtime.windows)\AppReadiness\" owner="true">
      <securityDescriptor name="AppReadiness_File_SDDL" />
    </directory>
  </directories>
  <registryKeys>
    <registryKey keyName="HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\AppReadiness">
      <registryValue name="NotifyObject" valueType="REG_SZ" value="{c980e4c2-c178-4572-935d-a8a429884806}" />
      <registryValue name="" valueType="REG_SZ" value="AppReadiness &amp; more" operationHint="append" />
      <securityDescriptor name="AppReadiness_Registry_SDDL" />
    </registryKey>
    <registryKey keyName="HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\AppReadiness\Empty" owner="true" />
  </registryKeys>
  <localization>
    <resources culture="en-US"><stringTable><string id="displayName" value="x" /></stringTable></resources>
  </localization>
  <fooBar mode="strange"><inner /></fooBar>
  <trustInfo>
    <security><accessControl><securityDescriptorDefinitions><securityDescriptorDefinition name="WRP_FILE_DEFAULT_SDDL" sddl="O:BA" /></securityDescriptorDefinitions></accessControl></security>
  </trustInfo>
</assembly>
```

- [ ] **Step 2: 寫失敗測試 `tests/parse.rs`**

```rust
use msu_inspector::core::manifest::parse::{is_pe_name, parse_component};
use msu_inspector::core::model::*;

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn of_kind(c: &Component, k: ActionKind) -> Vec<&ActionDetail> {
    c.actions.iter().filter(|a| a.kind() == k).map(|a| &a.detail).collect()
}

#[test]
fn parses_identity() {
    let c = parse_component("basic.manifest", &fixture("basic.manifest")).unwrap();
    assert_eq!(c.manifest, "basic.manifest");
    assert_eq!(c.identity.name, "Microsoft-Windows-AppReadiness-Service");
    assert_eq!(c.identity.version, "10.0.26100.1591");
    assert_eq!(c.identity.arch, "amd64");
    assert_eq!(c.identity.language, "neutral");
    assert_eq!(c.identity.public_key_token, "31bf3856ad364e35");
}

#[test]
fn parses_files_with_hash() {
    let c = parse_component("basic.manifest", &fixture("basic.manifest")).unwrap();
    let files = of_kind(&c, ActionKind::File);
    assert_eq!(files.len(), 2);
    let ActionDetail::File(f) = files[0] else { panic!() };
    assert_eq!(f.name, "AppReadiness.dll");
    assert_eq!(f.destination, "$(runtime.system32)\\");
    assert_eq!(f.source_name.as_deref(), Some("AppReadiness.dll"));
    assert_eq!(f.hash_alg.as_deref(), Some("sha256"));
    assert_eq!(f.hash.as_deref(), Some("q83vEjRWeJA="));
    assert_eq!(f.sddl_name.as_deref(), Some("WRP_FILE_DEFAULT_SDDL"));
    assert!(f.is_pe);
    let ActionDetail::File(txt) = files[1] else { panic!() };
    assert!(!txt.is_pe);
    assert_eq!(txt.hash, None);
}

#[test]
fn parses_registry_values_and_empty_keys() {
    let c = parse_component("basic.manifest", &fixture("basic.manifest")).unwrap();
    let regs: Vec<&RegistryAction> = of_kind(&c, ActionKind::Registry)
        .into_iter()
        .map(|d| match d {
            ActionDetail::Registry(r) => r,
            _ => unreachable!(),
        })
        .collect();
    assert_eq!(regs.len(), 3);
    assert_eq!(regs[0].value_name.as_deref(), Some("NotifyObject"));
    assert_eq!(regs[0].value_type.as_deref(), Some("REG_SZ"));
    assert_eq!(regs[0].operation, "replace");
    assert_eq!(regs[0].sddl_name.as_deref(), Some("AppReadiness_Registry_SDDL"));
    assert_eq!(regs[1].value_name.as_deref(), Some(""));
    assert_eq!(regs[1].data.as_deref(), Some("AppReadiness & more"));
    assert_eq!(regs[1].operation, "append");
    assert_eq!(regs[2].value_name, None);
    assert_eq!(regs[2].operation, "create_key");
    assert!(regs[2].owner);
}

#[test]
fn parses_directories() {
    let c = parse_component("basic.manifest", &fixture("basic.manifest")).unwrap();
    let dirs = of_kind(&c, ActionKind::Directory);
    let ActionDetail::Directory(d) = dirs[0] else { panic!() };
    assert_eq!(d.path, "$(runtime.windows)\\AppReadiness\\");
    assert!(d.owner);
    assert_eq!(d.sddl_name.as_deref(), Some("AppReadiness_File_SDDL"));
}

#[test]
fn keeps_unknown_elements_and_skips_structural_ones() {
    let c = parse_component("basic.manifest", &fixture("basic.manifest")).unwrap();
    let unknown = of_kind(&c, ActionKind::Unknown);
    assert_eq!(unknown.len(), 1, "only <fooBar> is unknown");
    let ActionDetail::Unknown(u) = unknown[0] else { panic!() };
    assert_eq!(u.element, "fooBar");
    assert!(u.raw_xml.starts_with("<fooBar mode=\"strange\">"));
    assert!(u.raw_xml.ends_with("</fooBar>"));
}

#[test]
fn accepts_bom_and_rejects_non_assembly() {
    let xml = format!("\u{feff}{}", fixture("basic.manifest"));
    assert!(parse_component("x", &xml).is_ok());
    assert!(parse_component("x", "<notAssembly/>").is_err());
    assert!(parse_component("x", "<assembly").is_err());
}

#[test]
fn detects_pe_names() {
    for n in ["a.dll", "b.EXE", "c.sys", "bootmgfw.efi", "d.ocx", "e.cpl"] {
        assert!(is_pe_name(n), "{n}");
    }
    for n in ["a.txt", "b.mui.bak", "noext", "x.xml"] {
        assert!(!is_pe_name(n), "{n}");
    }
}
```

- [ ] **Step 3: 執行測試確認失敗**

Run: `cargo test --test parse`
Expected: 編譯失敗（`manifest` 模組不存在）

- [ ] **Step 4: 實作 `src/core/manifest/mod.rs`**

```rust
//! manifest / .mum 的共用工具：文字解碼、XML 取值。

pub mod parse;

use roxmltree::{Document, Node, ParsingOptions};

use super::model::AssemblyIdentity;
use super::CoreError;

/// 依 BOM 解碼；沒有 BOM 視為 UTF-8，不合法時以替代字元保留內容。
pub fn decode_text(bytes: &[u8]) -> Result<String, CoreError> {
    fn utf16(body: &[u8], le: bool) -> Result<String, CoreError> {
        let units: Vec<u16> = body
            .chunks_exact(2)
            .map(|c| {
                if le {
                    u16::from_le_bytes([c[0], c[1]])
                } else {
                    u16::from_be_bytes([c[0], c[1]])
                }
            })
            .collect();
        String::from_utf16(&units).map_err(|e| CoreError::Xml(e.to_string()))
    }
    let text = if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        String::from_utf8_lossy(rest).into_owned()
    } else if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        utf16(rest, true)?
    } else if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        utf16(rest, false)?
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    };
    Ok(text)
}

/// 解析 XML；允許 DTD，並略過開頭殘留的 BOM 字元。
pub(crate) fn parse_doc(text: &str) -> Result<Document<'_>, CoreError> {
    let text = text.trim_start_matches('\u{feff}');
    let opts = ParsingOptions {
        allow_dtd: true,
        ..ParsingOptions::default()
    };
    Document::parse_with_options(text, opts).map_err(|e| CoreError::Xml(e.to_string()))
}

/// 元素的本地名稱（忽略命名空間前綴）是否為 `name`。
pub(crate) fn is_el(n: Node, name: &str) -> bool {
    n.is_element() && n.tag_name().name() == name
}

pub(crate) fn child<'a, 'i>(n: Node<'a, 'i>, name: &str) -> Option<Node<'a, 'i>> {
    n.children().find(|c| is_el(*c, name))
}

pub(crate) fn elements<'a, 'i: 'a>(
    n: Node<'a, 'i>,
    name: &'a str,
) -> impl Iterator<Item = Node<'a, 'i>> + 'a {
    n.children().filter(move |c| is_el(*c, name))
}

pub(crate) fn attr(n: Node, name: &str) -> Option<String> {
    n.attribute(name).map(str::to_string)
}

/// 讀取 `assemblyIdentity` 元素。
pub(crate) fn identity_of(n: Node) -> AssemblyIdentity {
    AssemblyIdentity {
        name: attr(n, "name").unwrap_or_default(),
        version: attr(n, "version").unwrap_or_default(),
        arch: attr(n, "processorArchitecture").unwrap_or_default(),
        language: attr(n, "language").unwrap_or_default(),
        public_key_token: attr(n, "publicKeyToken").unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_boms() {
        assert_eq!(decode_text(b"\xEF\xBB\xBFabc").unwrap(), "abc");
        assert_eq!(decode_text(b"\xFF\xFEa\x00b\x00").unwrap(), "ab");
        assert_eq!(decode_text(b"\xFE\xFF\x00a\x00b").unwrap(), "ab");
        assert_eq!(decode_text(b"plain").unwrap(), "plain");
    }
}
```

注意：`parse_doc` 會先去掉開頭 BOM，因此回傳的 `Document` 內 `node.range()` 是相對於去掉 BOM 後的字串；`parse.rs` 取原始片段時必須用同一個去掉 BOM 的字串（見下一步）。

- [ ] **Step 5: 實作 `src/core/manifest/parse.rs`（本 Task 只處理 file / registryKeys / directories / unknown）**

```rust
//! 元件 manifest → `Component`。
//!
//! 頂層元素的分類依據本機 WinSxS 19,173 個 manifest 的統計（見 spec 第 11 節）。

use roxmltree::Node;

use super::{attr, child, elements, identity_of, is_el, parse_doc};
use crate::core::model::*;
use crate::core::CoreError;

/// 不視為「動作」的結構性元素。
const STRUCTURAL: &[&str] = &[
    "assemblyIdentity",
    "dependency",
    "trustInfo",
    "localization",
    "deployment",
    "migration",
    "rescache",
    "languagePack",
    "imaging",
    "feature",
    "categoryDefinitions",
    "satelliteCategory",
    "languageCategory",
    "containsSettings",
    "compatibility",
    "noInheritable",
    "mvid",
    "application",
];

const PE_EXTENSIONS: &[&str] = &["exe", "dll", "sys", "efi", "ocx", "cpl", "scr", "drv", "com"];

/// `unknown` 動作保留的原始 XML 上限（字元邊界內截斷）。
const RAW_XML_LIMIT: usize = 4096;

pub fn is_pe_name(name: &str) -> bool {
    name.rsplit_once('.')
        .is_some_and(|(_, ext)| PE_EXTENSIONS.iter().any(|e| e.eq_ignore_ascii_case(ext)))
}

pub fn parse_component(manifest_name: &str, xml: &str) -> Result<Component, CoreError> {
    let xml = xml.trim_start_matches('\u{feff}');
    let doc = parse_doc(xml)?;
    let root = doc.root_element();
    if !is_el(root, "assembly") {
        return Err(CoreError::Xml(format!(
            "{manifest_name}: root element is <{}>, expected <assembly>",
            root.tag_name().name()
        )));
    }
    let mut comp = Component {
        identity: child(root, "assemblyIdentity")
            .map(identity_of)
            .unwrap_or_default(),
        manifest: manifest_name.to_string(),
        ..Default::default()
    };
    for node in root.children().filter(Node::is_element) {
        let name = node.tag_name().name();
        match name {
            n if STRUCTURAL.contains(&n) => {}
            "file" => comp
                .actions
                .push(Action::new(ActionDetail::File(parse_file(node)))),
            "registryKeys" => parse_registry_keys(node, &mut comp.actions),
            "directories" => parse_directories(node, &mut comp.actions),
            _ => comp.actions.push(unknown(xml, node)),
        }
    }
    Ok(comp)
}

fn sddl_name(n: Node) -> Option<String> {
    child(n, "securityDescriptor").and_then(|s| attr(s, "name"))
}

fn is_true(v: Option<String>) -> bool {
    v.is_some_and(|v| v.eq_ignore_ascii_case("true"))
}

fn parse_file(node: Node) -> FileAction {
    let name = attr(node, "name").unwrap_or_default();
    let hash = node.descendants().find(|n| is_el(*n, "hash"));
    let hash_alg = hash
        .and_then(|h| h.descendants().find(|n| is_el(*n, "DigestMethod")))
        .and_then(|m| attr(m, "Algorithm"))
        .map(|a| a.rsplit('#').next().unwrap_or("").to_string());
    let hash_value = hash
        .and_then(|h| h.descendants().find(|n| is_el(*n, "DigestValue")))
        .and_then(|v| v.text())
        .map(|t| t.trim().to_string());
    FileAction {
        is_pe: is_pe_name(&name),
        destination: attr(node, "destinationPath").unwrap_or_default(),
        source_name: attr(node, "sourceName"),
        hash_alg,
        hash: hash_value,
        sddl_name: sddl_name(node),
        name,
    }
}

fn parse_registry_keys(node: Node, out: &mut Vec<Action>) {
    for key in elements(node, "registryKey") {
        let key_name = attr(key, "keyName").unwrap_or_default();
        let owner = is_true(attr(key, "owner"));
        let sddl = sddl_name(key);
        let values: Vec<Node> = elements(key, "registryValue").collect();
        if values.is_empty() {
            out.push(Action::new(ActionDetail::Registry(RegistryAction {
                key: key_name.clone(),
                operation: "create_key".into(),
                owner,
                sddl_name: sddl.clone(),
                ..Default::default()
            })));
        }
        for v in values {
            let reg = RegistryAction {
                key: key_name.clone(),
                value_name: Some(attr(v, "name").unwrap_or_default()),
                value_type: attr(v, "valueType"),
                data: attr(v, "value"),
                operation: attr(v, "operationHint").unwrap_or_else(|| "replace".into()),
                owner,
                sddl_name: sddl.clone(),
            };
            out.push(Action::new(ActionDetail::Registry(reg)));
        }
    }
}

fn parse_directories(node: Node, out: &mut Vec<Action>) {
    for d in elements(node, "directory") {
        out.push(Action::new(ActionDetail::Directory(DirectoryAction {
            path: attr(d, "destinationPath").unwrap_or_default(),
            owner: is_true(attr(d, "owner")),
            sddl_name: sddl_name(d),
        })));
    }
}

/// 未辨識的元素：保留原始 XML 片段（最多 RAW_XML_LIMIT 位元組）。
fn unknown(xml: &str, node: Node) -> Action {
    let raw = &xml[node.range()];
    let raw_xml = if raw.len() > RAW_XML_LIMIT {
        let mut end = RAW_XML_LIMIT;
        while !raw.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &raw[..end])
    } else {
        raw.to_string()
    };
    Action::new(ActionDetail::Unknown(UnknownAction {
        element: node.tag_name().name().to_string(),
        raw_xml,
    }))
}
```

`src/core/mod.rs` 加入 `pub mod manifest;`。

- [ ] **Step 6: 執行測試確認通過**

Run: `cargo test --test parse; cargo test --lib manifest`
Expected: 全部 PASS

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: parse component manifests (files, registry, directories, unknown)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: manifest 解析（服務、驅動、排程、指令、防火牆、MOF、ETW、進階安裝程式、設定）

**Files:**
- Create: `tests/fixtures/actions.manifest`
- Modify: `src/core/manifest/parse.rs`, `tests/parse.rs`

**Interfaces:**
- Consumes: Task 2 的 `parse_component` 與 XML 小工具
- Produces: `parse_component` 產生全部 13 種 `ActionKind`；`Component.categories` 填入 `typeName`

- [ ] **Step 1: 建立 fixture `tests/fixtures/actions.manifest`**

```xml
<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v3" manifestVersion="1.0">
  <assemblyIdentity name="Test-Actions" version="10.0.26100.1742" processorArchitecture="amd64" language="neutral" buildType="release" publicKeyToken="31bf3856ad364e35" />
  <file name="acpiex.sys" destinationPath="$(runtime.drivers)\" sourceName="acpiex.sys" />
  <file name="dmcertinst.exe" destinationPath="$(runtime.system32)\" sourceName="dmcertinst.exe" />
  <file name="helper.sys" destinationPath="$(runtime.drivers)\" sourceName="helper.sys" />
  <memberships>
    <categoryMembership>
      <id name="Microsoft.Windows.Categories" version="1.0.0.0" publicKeyToken="365143bb27e7ac8b" typeName="BootCritical" />
    </categoryMembership>
    <categoryMembership>
      <id name="Microsoft.Windows.Categories.Services" version="10.0.26100.1742" publicKeyToken="31bf3856ad364e35" typeName="Service" />
      <categoryInstance subcategory="acpiex">
        <serviceData name="acpiex" displayName="Microsoft ACPIEx Driver" errorControl="critical" start="boot" type="kernelDriver" group="Boot Bus Extender" imagePath="System32\Drivers\acpiex.sys" tag="7" />
      </categoryInstance>
      <categoryInstance subcategory="AppReadiness">
        <serviceData name="AppReadiness" displayName="App Readiness" start="demand" type="win32ShareProcess" imagePath="%SystemRoot%\System32\svchost.exe -k AppReadiness -p" objectName="LocalSystem" requiredPrivileges="SeImpersonatePrivilege,SeTcbPrivilege" dependOnService="RpcSs" />
      </categoryInstance>
    </categoryMembership>
  </memberships>
  <taskScheduler>
    <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <RegistrationInfo>
        <URI>\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser</URI>
      </RegistrationInfo>
      <Triggers>
        <TimeTrigger id="NightlyTrigger"><StartBoundary>2008-09-01T03:00:00</StartBoundary></TimeTrigger>
        <BootTrigger />
      </Triggers>
      <Principals>
        <Principal id="LocalSystem"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal>
      </Principals>
      <Actions Context="LocalSystem">
        <Exec><Command>%windir%\system32\compattelrunner.exe</Command><Arguments>-m:appraiser.dll</Arguments></Exec>
        <ComHandler><ClassId>{01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}</ClassId></ComHandler>
      </Actions>
    </Task>
  </taskScheduler>
  <genericCommands>
    <genericCommand arguments="/install ASPNET" executableName="$(runtime.system32)\inetsrv\iissetup.exe" />
    <genericCommand arguments="/uninstall ASPNET" executableName="$(runtime.system32)\inetsrv\iissetup.exe" install="false" />
  </genericCommands>
  <firewallRule Action="Allow" Active="TRUE" Binary="%SystemRoot%\system32\dmcertinst.exe" Dir="Out" LPort="49152-65535" Name="@FirewallAPI.dll,-37507" Protocol="TCP" internalName="Microsoft-Windows-DeviceManagement-CertificateInstall-TCP-Out" />
  <registryKeys>
    <registryKey keyName="HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\RestrictedServices\Static\System">
      <registryValue name="DeviceManagement-4" valueType="REG_SZ" value="V2.0|Action=Block|Dir=in|App=%SystemRoot%\System32\dmcertinst.exe|Name=Block inbound traffic to dmcertinst.exe|" />
    </registryKey>
  </registryKeys>
  <mof name="$(runtime.wbem)\Microsoft.AppV.AppVClientWmi.mof" uninstallmof="$(runtime.wbem)\Remove.Microsoft.AppV.AppvClientWmi.mof" />
  <instrumentation xmlns:win="http://manifests.microsoft.com/win/2004/08/windows/events">
    <events xmlns="http://schemas.microsoft.com/win/2004/08/events">
      <provider guid="{1E2462BE-B025-48DA-8C1F-7B60B8CCAE53}" name="Microsoft-Windows-AppModel-MessagingDataModel" />
    </events>
  </instrumentation>
  <fveUpdateAI fveCommand="bootmgr" />
  <bfsvc Flags="17" Source="$(runtime.windows)\boot" />
  <networkComponents>
    <filterDriver identifier="ms_l1vhlwf" />
  </networkComponents>
  <asmv3:configuration xmlns:asmv3="urn:schemas-microsoft-com:asm.v3">
    <configurationSchema />
  </asmv3:configuration>
</assembly>
```

- [ ] **Step 2: 在 `tests/parse.rs` 加入失敗測試**

```rust
fn actions() -> Component {
    parse_component("actions.manifest", &fixture("actions.manifest")).unwrap()
}

#[test]
fn counts_every_kind() {
    let c = actions();
    let count = |k| c.actions.iter().filter(|a| a.kind() == k).count();
    assert_eq!(count(ActionKind::File), 3);
    assert_eq!(count(ActionKind::Driver), 2, "acpiex (service) + helper.sys (file)");
    assert_eq!(count(ActionKind::Service), 1);
    assert_eq!(count(ActionKind::ScheduledTask), 1);
    assert_eq!(count(ActionKind::GenericCommand), 2);
    assert_eq!(count(ActionKind::FirewallRule), 2, "element + registry value");
    assert_eq!(count(ActionKind::Registry), 1);
    assert_eq!(count(ActionKind::WmiMof), 1);
    assert_eq!(count(ActionKind::EtwEventlog), 1);
    assert_eq!(count(ActionKind::AdvancedInstaller), 3);
    assert_eq!(count(ActionKind::Setting), 1);
    assert_eq!(count(ActionKind::Unknown), 0);
    assert_eq!(c.categories, vec!["BootCritical".to_string(), "Service".to_string()]);
}

#[test]
fn parses_services_and_drivers() {
    let c = actions();
    let svc = c.actions.iter().find_map(|a| match &a.detail {
        ActionDetail::Service(s) => Some(s),
        _ => None,
    });
    let svc = svc.unwrap();
    assert_eq!(svc.name, "AppReadiness");
    assert_eq!(svc.start.as_deref(), Some("demand"));
    assert_eq!(svc.account.as_deref(), Some("LocalSystem"));
    assert_eq!(svc.required_privileges, vec!["SeImpersonatePrivilege", "SeTcbPrivilege"]);
    assert_eq!(svc.depend_on, vec!["RpcSs"]);

    let drivers: Vec<&DriverAction> = c
        .actions
        .iter()
        .filter_map(|a| match &a.detail {
            ActionDetail::Driver(d) => Some(d),
            _ => None,
        })
        .collect();
    let acpi = drivers.iter().find(|d| d.name == "acpiex").unwrap();
    assert_eq!(acpi.origin, "service");
    assert_eq!(acpi.start.as_deref(), Some("boot"));
    assert!(acpi.boot_critical);
    let helper = drivers.iter().find(|d| d.name == "helper").unwrap();
    assert_eq!(helper.origin, "file");
    assert_eq!(helper.image_path.as_deref(), Some("$(runtime.drivers)\\helper.sys"));
    assert!(helper.boot_critical);
}

#[test]
fn parses_tasks_and_commands() {
    let c = actions();
    let task = c.actions.iter().find_map(|a| match &a.detail {
        ActionDetail::ScheduledTask(t) => Some(t),
        _ => None,
    });
    let task = task.unwrap();
    assert_eq!(
        task.uri,
        "\\Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser"
    );
    assert_eq!(task.run_as.as_deref(), Some("S-1-5-18"));
    assert_eq!(task.run_level.as_deref(), Some("HighestAvailable"));
    assert_eq!(task.triggers, vec!["TimeTrigger", "BootTrigger"]);
    assert_eq!(
        task.exec,
        vec![
            "%windir%\\system32\\compattelrunner.exe -m:appraiser.dll".to_string(),
            "COM {01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}".to_string()
        ]
    );

    let cmds: Vec<&CommandAction> = c
        .actions
        .iter()
        .filter_map(|a| match &a.detail {
            ActionDetail::GenericCommand(g) => Some(g),
            _ => None,
        })
        .collect();
    assert_eq!(cmds[0].executable, "$(runtime.system32)\\inetsrv\\iissetup.exe");
    assert_eq!(cmds[0].arguments.as_deref(), Some("/install ASPNET"));
    assert!(cmds[0].runs_on_install);
    assert!(!cmds[1].runs_on_install);
}

#[test]
fn parses_firewall_rules_from_both_sources() {
    let c = actions();
    let fws: Vec<&FirewallAction> = c
        .actions
        .iter()
        .filter_map(|a| match &a.detail {
            ActionDetail::FirewallRule(f) => Some(f),
            _ => None,
        })
        .collect();
    let el = fws.iter().find(|f| f.origin == "element").unwrap();
    assert_eq!(el.name, "Microsoft-Windows-DeviceManagement-CertificateInstall-TCP-Out");
    assert_eq!(el.direction.as_deref(), Some("Out"));
    assert_eq!(el.action.as_deref(), Some("Allow"));
    assert_eq!(el.local_ports.as_deref(), Some("49152-65535"));
    let reg = fws.iter().find(|f| f.origin == "registry").unwrap();
    assert_eq!(reg.name, "Block inbound traffic to dmcertinst.exe");
    assert_eq!(reg.direction.as_deref(), Some("in"));
    assert_eq!(reg.action.as_deref(), Some("Block"));
    assert_eq!(reg.program.as_deref(), Some("%SystemRoot%\\System32\\dmcertinst.exe"));
}

#[test]
fn parses_mof_etw_advanced_installers() {
    let c = actions();
    let mof = c.actions.iter().find_map(|a| match &a.detail {
        ActionDetail::WmiMof(m) => Some(m),
        _ => None,
    });
    assert_eq!(
        mof.unwrap().uninstall_file.as_deref(),
        Some("$(runtime.wbem)\\Remove.Microsoft.AppV.AppvClientWmi.mof")
    );
    let etw = c.actions.iter().find_map(|a| match &a.detail {
        ActionDetail::EtwEventlog(e) => Some(e),
        _ => None,
    });
    assert_eq!(etw.unwrap().provider, "Microsoft-Windows-AppModel-MessagingDataModel");
    let ais: Vec<&AdvancedInstallerAction> = c
        .actions
        .iter()
        .filter_map(|a| match &a.detail {
            ActionDetail::AdvancedInstaller(x) => Some(x),
            _ => None,
        })
        .collect();
    let names: Vec<&str> = ais.iter().map(|a| a.element.as_str()).collect();
    assert_eq!(names, vec!["fveUpdateAI", "bfsvc", "networkComponents"]);
    assert_eq!(ais[0].attributes.get("fveCommand").map(String::as_str), Some("bootmgr"));
    assert_eq!(ais[2].attributes.get("children").map(String::as_str), Some("filterDriver"));
}
```

- [ ] **Step 3: 執行測試確認失敗**

Run: `cargo test --test parse`
Expected: `counts_every_kind` 等新測試 FAIL（服務等元素目前被歸為 unknown）

- [ ] **Step 4: 擴充 `src/core/manifest/parse.rs`**

在常數區加入：

```rust
/// 安裝時會執行自訂程式碼、但名稱不以 `AI` 結尾的進階安裝程式元素。
const ADVANCED_INSTALLERS: &[&str] = &[
    "bfsvc",
    "SecureBoot",
    "appxRegistration",
    "networkComponents",
    "unattendActions",
    "sppInstaller",
    "WinsockNameSpaceOnlineInstall",
    "WinsockAppPermittedLspCategories",
    "WinsockTransportOnlineInstall",
    "MsmqWorkgroupOnlineInstall",
    "MsmqHttpOnlineInstall",
    "MsmqAdIntegrationOnlineInstall",
    "pbr",
    "msdtc",
];

const DRIVER_SERVICE_TYPES: &[&str] = &["kernelDriver", "fileSystemDriver", "recognizerDriver"];
```

把 `parse_component` 的 `match` 換成完整版本，並在迴圈後呼叫 `finalize_drivers`：

```rust
        match name {
            n if STRUCTURAL.contains(&n) => {}
            "file" => comp
                .actions
                .push(Action::new(ActionDetail::File(parse_file(node)))),
            "registryKeys" => parse_registry_keys(node, &mut comp.actions),
            "directories" => parse_directories(node, &mut comp.actions),
            "memberships" => parse_memberships(node, &mut comp),
            "taskScheduler" => parse_tasks(node, &mut comp.actions),
            "genericCommands" => parse_generic_commands(node, &mut comp.actions),
            "firewallRule" => comp
                .actions
                .push(Action::new(ActionDetail::FirewallRule(firewall_element(node)))),
            "mof" => comp.actions.push(Action::new(ActionDetail::WmiMof(MofAction {
                file: attr(node, "name").unwrap_or_default(),
                uninstall_file: attr(node, "uninstallmof"),
            }))),
            "instrumentation" => {
                for p in node.descendants().filter(|n| is_el(*n, "provider")) {
                    comp.actions
                        .push(Action::new(ActionDetail::EtwEventlog(EtwAction {
                            provider: attr(p, "name").unwrap_or_default(),
                            guid: attr(p, "guid"),
                        })));
                }
            }
            "configuration" => comp
                .actions
                .push(Action::new(ActionDetail::Setting(SettingAction {
                    element: name.to_string(),
                }))),
            n if n.ends_with("AI") || ADVANCED_INSTALLERS.contains(&n) => comp
                .actions
                .push(Action::new(ActionDetail::AdvancedInstaller(advanced_installer(node)))),
            _ => comp.actions.push(unknown(xml, node)),
        }
    }
    finalize_drivers(&mut comp);
    Ok(comp)
```

在 `parse_registry_keys` 的 `for v in values` 迴圈內，`out.push(... Registry(reg))` 之前加入：

```rust
            if let Some(fw) = firewall_from_registry(&reg) {
                out.push(Action::new(ActionDetail::FirewallRule(fw)));
            }
```

新增函式：

```rust
fn split_list(v: Option<String>) -> Vec<String> {
    v.map(|s| {
        s.split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect()
    })
    .unwrap_or_default()
}

fn text_of(n: Option<Node>) -> Option<String> {
    n.and_then(|n| n.text()).map(|t| t.trim().to_string())
}

fn parse_memberships(node: Node, comp: &mut Component) {
    for cm in elements(node, "categoryMembership") {
        if let Some(t) = child(cm, "id").and_then(|id| attr(id, "typeName")) {
            if !comp.categories.contains(&t) {
                comp.categories.push(t);
            }
        }
        for inst in elements(cm, "categoryInstance") {
            for sd in elements(inst, "serviceData") {
                comp.actions.push(service_or_driver(sd));
            }
        }
    }
}

fn service_or_driver(sd: Node) -> Action {
    let service_type = attr(sd, "type");
    let name = attr(sd, "name").unwrap_or_default();
    let is_driver = service_type
        .as_deref()
        .is_some_and(|t| DRIVER_SERVICE_TYPES.iter().any(|d| d.eq_ignore_ascii_case(t)));
    if is_driver {
        Action::new(ActionDetail::Driver(DriverAction {
            name,
            image_path: attr(sd, "imagePath"),
            start: attr(sd, "start"),
            service_type,
            boot_critical: false,
            origin: "service".into(),
        }))
    } else {
        Action::new(ActionDetail::Service(ServiceAction {
            name,
            display_name: attr(sd, "displayName"),
            image_path: attr(sd, "imagePath"),
            start: attr(sd, "start"),
            service_type,
            account: attr(sd, "objectName"),
            required_privileges: split_list(attr(sd, "requiredPrivileges")),
            group: attr(sd, "group"),
            depend_on: split_list(attr(sd, "dependOnService")),
        }))
    }
}

/// 設定 BootCritical 旗標；沒有對應 serviceData 的 .sys 檔補一筆 `origin = file` 的驅動。
fn finalize_drivers(comp: &mut Component) {
    let boot_critical = comp.categories.iter().any(|c| c == "BootCritical");
    let mut service_images: Vec<String> = Vec::new();
    for a in &mut comp.actions {
        if let ActionDetail::Driver(d) = &mut a.detail {
            d.boot_critical = boot_critical;
            if let Some(p) = &d.image_path {
                service_images.push(p.to_ascii_lowercase());
            }
        }
    }
    let mut extra = Vec::new();
    for a in &comp.actions {
        let ActionDetail::File(f) = &a.detail else {
            continue;
        };
        let lower = f.name.to_ascii_lowercase();
        if !lower.ends_with(".sys") || service_images.iter().any(|p| p.ends_with(&lower)) {
            continue;
        }
        extra.push(Action::new(ActionDetail::Driver(DriverAction {
            name: f.name[..f.name.len() - 4].to_string(),
            image_path: Some(ActionDetail::File(f.clone()).target()),
            start: None,
            service_type: None,
            boot_critical,
            origin: "file".into(),
        })));
    }
    comp.actions.extend(extra);
}

fn parse_tasks(node: Node, out: &mut Vec<Action>) {
    for task in elements(node, "Task") {
        let uri = text_of(child(task, "RegistrationInfo").and_then(|r| child(r, "URI")))
            .unwrap_or_default();
        let principal = child(task, "Principals").and_then(|p| child(p, "Principal"));
        let run_as = text_of(principal.and_then(|p| child(p, "UserId").or_else(|| child(p, "GroupId"))));
        let run_level = text_of(principal.and_then(|p| child(p, "RunLevel")));
        let mut exec = Vec::new();
        if let Some(actions) = child(task, "Actions") {
            for a in actions.children().filter(Node::is_element) {
                match a.tag_name().name() {
                    "Exec" => {
                        let cmd = text_of(child(a, "Command")).unwrap_or_default();
                        match text_of(child(a, "Arguments")) {
                            Some(args) if !args.is_empty() => exec.push(format!("{cmd} {args}")),
                            _ => exec.push(cmd),
                        }
                    }
                    "ComHandler" => exec.push(format!(
                        "COM {}",
                        text_of(child(a, "ClassId")).unwrap_or_default()
                    )),
                    other => exec.push(other.to_string()),
                }
            }
        }
        let triggers = child(task, "Triggers")
            .map(|t| {
                t.children()
                    .filter(Node::is_element)
                    .map(|n| n.tag_name().name().to_string())
                    .collect()
            })
            .unwrap_or_default();
        out.push(Action::new(ActionDetail::ScheduledTask(TaskAction {
            uri,
            exec,
            run_as,
            run_level,
            triggers,
        })));
    }
}

fn parse_generic_commands(node: Node, out: &mut Vec<Action>) {
    for g in elements(node, "genericCommand") {
        out.push(Action::new(ActionDetail::GenericCommand(CommandAction {
            executable: attr(g, "executableName")
                .or_else(|| attr(g, "executable"))
                .unwrap_or_default(),
            arguments: attr(g, "arguments"),
            runs_on_install: !attr(g, "install").is_some_and(|v| v.eq_ignore_ascii_case("false")),
        })));
    }
}

fn firewall_element(n: Node) -> FirewallAction {
    FirewallAction {
        name: attr(n, "internalName")
            .or_else(|| attr(n, "Name"))
            .unwrap_or_default(),
        direction: attr(n, "Dir"),
        action: attr(n, "Action"),
        program: attr(n, "Binary"),
        protocol: attr(n, "Protocol"),
        local_ports: attr(n, "LPort"),
        remote_ports: attr(n, "RPort"),
        origin: "element".into(),
    }
}

/// `...\FirewallPolicy\FirewallRules` 或 `RestrictedServices` 下、以 `v2.` 開頭的值即為防火牆規則。
fn firewall_from_registry(r: &RegistryAction) -> Option<FirewallAction> {
    let key = r.key.to_ascii_lowercase();
    if !(key.contains("\\firewallpolicy\\firewallrules")
        || key.contains("\\firewallpolicy\\restrictedservices"))
    {
        return None;
    }
    let data = r.data.as_deref()?;
    if !data.get(..3)?.eq_ignore_ascii_case("v2.") {
        return None;
    }
    let mut fields = std::collections::BTreeMap::new();
    for part in data.split('|').skip(1) {
        if let Some((k, v)) = part.split_once('=') {
            fields
                .entry(k.to_ascii_lowercase())
                .or_insert_with(|| v.to_string());
        }
    }
    Some(FirewallAction {
        name: fields
            .get("name")
            .cloned()
            .or_else(|| r.value_name.clone())
            .unwrap_or_default(),
        direction: fields.get("dir").cloned(),
        action: fields.get("action").cloned(),
        program: fields.get("app").cloned(),
        protocol: fields.get("protocol").cloned(),
        local_ports: fields.get("lport").cloned(),
        remote_ports: fields.get("rport").cloned(),
        origin: "registry".into(),
    })
}

fn advanced_installer(n: Node) -> AdvancedInstallerAction {
    let mut attributes: std::collections::BTreeMap<String, String> = n
        .attributes()
        .map(|a| (a.name().to_string(), a.value().to_string()))
        .collect();
    let children: Vec<&str> = n
        .children()
        .filter(Node::is_element)
        .map(|c| c.tag_name().name())
        .collect();
    if !children.is_empty() {
        attributes.insert("children".into(), children.join(","));
    }
    AdvancedInstallerAction {
        element: n.tag_name().name().to_string(),
        attributes,
    }
}
```

- [ ] **Step 5: 執行測試確認通過**

Run: `cargo test --test parse`
Expected: 全部 PASS

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: parse services, drivers, tasks, commands, firewall, mof, etw and advanced installers

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: `.mum` 與 pkgProperties 解析、選出頂層套件

**Files:**
- Create: `src/core/manifest/package.rs`, `tests/fixtures/rollup.mum`, `tests/fixtures/sub.mum`, `tests/package.rs`
- Modify: `src/core/manifest/mod.rs`（加入 `pub mod package;`）

**Interfaces:**
- Consumes: Task 2 的 XML 小工具、`decode_text`
- Produces:
  - `package::MumInfo { file_name, identity, identifier, release_type, restart, description, support_url, psfx, parents: Vec<AssemblyIdentity>, sub_packages: Vec<AssemblyIdentity>, components: Vec<AssemblyIdentity> }`
  - `package::parse_mum(file_name: &str, xml: &str) -> Result<MumInfo, CoreError>`
  - `package::parse_pkg_properties(bytes: &[u8]) -> BTreeMap<String, String>`
  - `package::kb_from_file_name(&str) -> Option<String>`
  - `package::select_package(mums: &[MumInfo], kb_hint: Option<&str>, properties: BTreeMap<String,String>) -> PackageInfo`

- [ ] **Step 1: 建立 fixtures**

`tests/fixtures/rollup.mum`（依本機 `Package_for_RollupFix` 格式精簡）：

```xml
<?xml version="1.0" encoding="utf-8"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v3" manifestVersion="1.0" description="Fix for KB5129195" displayName="default" company="Microsoft Corporation" copyright="Microsoft Corporation" supportInformation="https://support.microsoft.com/help/5129195" creationTimeStamp="2026-09-12T21:27:54Z" lastUpdateTimeStamp="2026-09-12T21:27:54Z">
  <assemblyIdentity name="Package_for_RollupFix" version="26100.9457.1.0" processorArchitecture="amd64" language="neutral" publicKeyToken="31bf3856ad364e35" />
  <package identifier="KB5129195" releaseType="Security Update" restart="possible">
    <mum2:customInformation Version="10.0.26100.9457" xmlns:mum2="urn:schemas-microsoft-com:asm.v3" PackageFormat="PSFX" PSFXVersion="2" PSFXDeltaFormat="ForwardOnly" />
    <parent revisionCompare="GE" integrate="standalone" disposition="detect">
      <assemblyIdentity name="Microsoft-Windows-CoreEdition" version="10.0.26100.1742" processorArchitecture="amd64" language="neutral" buildType="release" publicKeyToken="31bf3856ad364e35" />
      <assemblyIdentity name="Microsoft-Windows-ProfessionalEdition" version="10.0.26100.1742" processorArchitecture="amd64" language="neutral" buildType="release" publicKeyToken="31bf3856ad364e35" />
    </parent>
    <update name="5129195-1_neutral_PACKAGE">
      <package integrate="hidden">
        <assemblyIdentity name="Package_1_for_KB5129195" version="26100.9457.1.0" processorArchitecture="amd64" language="neutral" publicKeyToken="31bf3856ad364e35" />
      </package>
    </update>
    <update name="5129195-2_neutral_PACKAGE">
      <package integrate="hidden">
        <assemblyIdentity name="Package_2_for_KB5129195" version="26100.9457.1.0" processorArchitecture="amd64" language="neutral" publicKeyToken="31bf3856ad364e35" />
      </package>
    </update>
  </package>
</assembly>
```

`tests/fixtures/sub.mum`：

```xml
<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v3" manifestVersion="1.0" copyright="Copyright (c) Microsoft Corporation. All Rights Reserved.">
  <assemblyIdentity name="Package_1_for_KB5129195" version="26100.9457.1.0" processorArchitecture="amd64" language="neutral" buildType="release" publicKeyToken="31bf3856ad364e35" />
  <package identifier="KB5129195" releaseType="Update">
    <update name="7f45e5eea8edbdadfec2cbe9f9a2e974">
      <component>
        <assemblyIdentity name="WindowsSearchEngineSKU-Group-Deployment" version="10.0.26100.9457" processorArchitecture="amd64" language="neutral" buildType="release" publicKeyToken="31bf3856ad364e35" versionScope="nonSxS" />
      </component>
    </update>
  </package>
</assembly>
```

- [ ] **Step 2: 寫失敗測試 `tests/package.rs`**

```rust
use std::collections::BTreeMap;

use msu_inspector::core::manifest::package::*;

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

#[test]
fn parses_mum_with_bom() {
    let xml = format!("\u{feff}{}", fixture("rollup.mum"));
    let m = parse_mum("Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.9457.1.0.mum", &xml).unwrap();
    assert_eq!(m.identity.name, "Package_for_RollupFix");
    assert_eq!(m.identifier.as_deref(), Some("KB5129195"));
    assert_eq!(m.release_type.as_deref(), Some("Security Update"));
    assert_eq!(m.restart.as_deref(), Some("possible"));
    assert_eq!(m.description.as_deref(), Some("Fix for KB5129195"));
    assert_eq!(m.support_url.as_deref(), Some("https://support.microsoft.com/help/5129195"));
    assert!(m.psfx);
    assert_eq!(m.parents.len(), 2);
    assert_eq!(m.sub_packages.len(), 2);
    assert!(m.components.is_empty());
}

#[test]
fn parses_component_lists() {
    let m = parse_mum("Package_1_for_KB5129195.mum", &fixture("sub.mum")).unwrap();
    assert_eq!(m.components.len(), 1);
    assert_eq!(m.components[0].name, "WindowsSearchEngineSKU-Group-Deployment");
    assert!(!m.psfx);
}

#[test]
fn parses_utf16_pkg_properties() {
    let text = "ApplicabilityInfo=\"Windows 11.0 Client SKUs\"\r\nKB Article Number=\"5129195\"\r\nProcessor Architecture=\"amd64\"\r\n";
    let mut bytes = vec![0xFF, 0xFE];
    for u in text.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    let p = parse_pkg_properties(&bytes);
    assert_eq!(p.get("ApplicabilityInfo").map(String::as_str), Some("Windows 11.0 Client SKUs"));
    assert_eq!(p.get("KB Article Number").map(String::as_str), Some("5129195"));
    assert_eq!(p.len(), 3);
}

#[test]
fn extracts_kb_from_file_names() {
    assert_eq!(kb_from_file_name("windows11.0-kb5043080-x64_abc.msu").as_deref(), Some("KB5043080"));
    assert_eq!(kb_from_file_name("Windows10.0-KB890830-x64.cab").as_deref(), Some("KB890830"));
    assert_eq!(kb_from_file_name("update.msu"), None);
    assert_eq!(kb_from_file_name("kbd.msu"), None);
}

#[test]
fn selects_top_level_package() {
    let rollup = parse_mum("Package_for_RollupFix.mum", &fixture("rollup.mum")).unwrap();
    let sub = parse_mum("Package_1_for_KB5129195.mum", &fixture("sub.mum")).unwrap();
    let mut props = BTreeMap::new();
    props.insert("ApplicabilityInfo".to_string(), "Windows 11.0 Client SKUs".to_string());
    let p = select_package(&[sub.clone(), rollup.clone()], Some("KB5129195"), props);
    assert_eq!(p.identity.name, "Package_for_RollupFix");
    assert_eq!(p.kb.as_deref(), Some("KB5129195"));
    assert_eq!(p.sub_packages, 2);
    assert!(p.psfx);
    assert_eq!(
        p.applicability,
        vec![
            "Windows 11.0 Client SKUs".to_string(),
            "Microsoft-Windows-CoreEdition".to_string(),
            "Microsoft-Windows-ProfessionalEdition".to_string()
        ]
    );

    // update.mum 優先
    let mut update = sub.clone();
    update.file_name = "update.mum".into();
    let p = select_package(&[rollup, update], None, BTreeMap::new());
    assert_eq!(p.identity.name, "Package_1_for_KB5129195");

    // 沒有任何 .mum：只帶 KB 提示
    let p = select_package(&[], Some("KB1"), BTreeMap::new());
    assert_eq!(p.kb.as_deref(), Some("KB1"));
}
```

- [ ] **Step 3: 執行測試確認失敗**

Run: `cargo test --test package`
Expected: 編譯失敗（`package` 模組不存在）

- [ ] **Step 4: 實作 `src/core/manifest/package.rs`**

```rust
//! `.mum`（套件 manifest）與 `*-pkgProperties.txt` 解析。

use std::collections::BTreeMap;

use super::{attr, child, decode_text, elements, identity_of, is_el, parse_doc};
use crate::core::model::{AssemblyIdentity, PackageInfo};
use crate::core::CoreError;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MumInfo {
    pub file_name: String,
    pub identity: AssemblyIdentity,
    pub identifier: Option<String>,
    pub release_type: Option<String>,
    pub restart: Option<String>,
    pub description: Option<String>,
    pub support_url: Option<String>,
    /// `customInformation PackageFormat="PSFX"`
    pub psfx: bool,
    pub parents: Vec<AssemblyIdentity>,
    pub sub_packages: Vec<AssemblyIdentity>,
    pub components: Vec<AssemblyIdentity>,
}

pub fn parse_mum(file_name: &str, xml: &str) -> Result<MumInfo, CoreError> {
    let doc = parse_doc(xml)?;
    let root = doc.root_element();
    if !is_el(root, "assembly") {
        return Err(CoreError::Xml(format!("{file_name}: not an <assembly>")));
    }
    let mut m = MumInfo {
        file_name: file_name.to_string(),
        identity: child(root, "assemblyIdentity")
            .map(identity_of)
            .unwrap_or_default(),
        description: attr(root, "description"),
        support_url: attr(root, "supportInformation"),
        ..Default::default()
    };
    let Some(pkg) = child(root, "package") else {
        return Ok(m);
    };
    m.identifier = attr(pkg, "identifier");
    m.release_type = attr(pkg, "releaseType");
    m.restart = attr(pkg, "restart");
    m.psfx = pkg.children().any(|n| {
        is_el(n, "customInformation")
            && n.attribute("PackageFormat")
                .is_some_and(|f| f.eq_ignore_ascii_case("PSFX"))
    });
    if let Some(parent) = child(pkg, "parent") {
        m.parents = elements(parent, "assemblyIdentity").map(identity_of).collect();
    }
    for update in elements(pkg, "update") {
        for c in elements(update, "component") {
            if let Some(id) = child(c, "assemblyIdentity") {
                m.components.push(identity_of(id));
            }
        }
        for p in elements(update, "package") {
            if let Some(id) = child(p, "assemblyIdentity") {
                m.sub_packages.push(identity_of(id));
            }
        }
    }
    Ok(m)
}

/// 每行 `Key="Value"`；檔案通常為 UTF-16LE。
pub fn parse_pkg_properties(bytes: &[u8]) -> BTreeMap<String, String> {
    let text = decode_text(bytes).unwrap_or_default();
    text.lines()
        .filter_map(|line| {
            let (k, v) = line.trim().split_once('=')?;
            Some((k.trim().to_string(), v.trim().trim_matches('"').to_string()))
        })
        .filter(|(k, _)| !k.is_empty())
        .collect()
}

/// 從檔名取出 `KBnnnnnn`（`kb` 後至少 5 位數字）。
pub fn kb_from_file_name(name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut i = 0;
    while let Some(pos) = lower[i..].find("kb") {
        let start = i + pos + 2;
        let digits: String = bytes[start..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .map(|b| *b as char)
            .collect();
        if digits.len() >= 5 {
            return Some(format!("KB{digits}"));
        }
        i = start;
    }
    None
}

fn eq_kb(a: Option<&str>, b: Option<&str>) -> bool {
    matches!((a, b), (Some(a), Some(b)) if a.eq_ignore_ascii_case(b))
}

/// 選出頂層套件：`update.mum` → `Package_for_*` 且 identifier 與 KB 相符 →
/// identifier 相符 → 參照最多子套件 / 元件者。
pub fn select_package(
    mums: &[MumInfo],
    kb_hint: Option<&str>,
    properties: BTreeMap<String, String>,
) -> PackageInfo {
    let top = mums
        .iter()
        .find(|m| m.file_name.eq_ignore_ascii_case("update.mum"))
        .or_else(|| {
            mums.iter().find(|m| {
                m.identity.name.to_ascii_lowercase().starts_with("package_for_")
                    && eq_kb(m.identifier.as_deref(), kb_hint)
            })
        })
        .or_else(|| mums.iter().find(|m| eq_kb(m.identifier.as_deref(), kb_hint)))
        .or_else(|| {
            mums.iter()
                .max_by_key(|m| m.sub_packages.len() + m.components.len())
        });

    let kb_from_props = properties
        .get("KB Article Number")
        .map(|n| format!("KB{}", n.trim()));
    let mut applicability: Vec<String> = properties
        .get("ApplicabilityInfo")
        .cloned()
        .into_iter()
        .collect();

    let Some(top) = top else {
        return PackageInfo {
            kb: kb_hint.map(str::to_string).or(kb_from_props),
            applicability,
            properties,
            ..Default::default()
        };
    };
    for p in &top.parents {
        if !applicability.contains(&p.name) {
            applicability.push(p.name.clone());
        }
    }
    let kb = top
        .identifier
        .clone()
        .filter(|i| i.to_ascii_uppercase().starts_with("KB"))
        .or_else(|| kb_hint.map(str::to_string))
        .or(kb_from_props);
    PackageInfo {
        kb,
        identity: top.identity.clone(),
        release_type: top.release_type.clone(),
        restart: top.restart.clone(),
        description: top.description.clone(),
        support_url: top.support_url.clone(),
        psfx: top.psfx,
        applicability,
        properties,
        sub_packages: top.sub_packages.len(),
    }
}
```

`src/core/manifest/mod.rs` 加入 `pub mod package;`。

- [ ] **Step 5: 執行測試確認通過**

Run: `cargo test --test package`
Expected: 全部 PASS

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: parse package .mum files and pkgProperties, select top-level package

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 5: 系統資訊與差異引擎（PA30 / PA19 / DCM）

**Files:**
- Create: `src/core/sys.rs`, `src/core/delta.rs`, `tests/delta.rs`
- Modify: `src/core/mod.rs`（加入 `pub mod delta; pub mod sys;`）

**Interfaces:**
- Consumes: `CoreError`、`model::parse_version`
- Produces:
  - `sys::windows_dir() -> PathBuf`、`sys::native_arch() -> &'static str`（`amd64` / `arm64` / `x86` / `unknown`）
  - `delta::DeltaEngine`：`system(dll: &str) -> Result<Self>`、`from_path(&Path) -> Result<Self>`、`select(package_dll: Option<&Path>) -> Result<Self>`、`label() -> &str`、`apply(source: &[u8], delta: &[u8]) -> Result<Vec<u8>>`、`create(source, target) -> Result<Vec<u8>>`（僅 msdelta 提供，測試用）；`Send + Sync`
  - `delta::apply_pa19(patch: &[u8]) -> Result<Vec<u8>>`
  - `delta::is_dcm(&[u8]) -> bool`、`delta::DcmDecoder`：`from_system() -> Result<Self>`、`with_base(Vec<u8>)`、`base() -> &[u8]`、`decode(&self, engine: &DeltaEngine, bytes: &[u8]) -> Result<Vec<u8>>`（非 DCM 原樣回傳）

背景（已在本機驗證，見 spec 第 11 節）：WinSxS manifest 以 `DCM\x01` 開頭、後接 PA30；以 servicing stack `wcp.dll` 的資源（型別 `0x266`、ID `1`）為來源呼叫 `ApplyDeltaB` 即可還原。**DCM 一律用 `msdelta.dll`**（已驗證）；PSF 用 `DeltaEngine::select` 挑出的引擎。

- [ ] **Step 1: 寫失敗測試 `tests/delta.rs`**

```rust
use msu_inspector::core::delta::{is_dcm, DcmDecoder, DeltaEngine};
use msu_inspector::core::sys;

fn msdelta() -> DeltaEngine {
    DeltaEngine::system("msdelta.dll").expect("msdelta.dll")
}

#[test]
fn applies_null_source_delta_round_trip() {
    let e = msdelta();
    let target = b"<assembly>hello</assembly>".repeat(20);
    let d = e.create(b"", &target).unwrap();
    assert!(d.starts_with(b"PA30"));
    assert_eq!(e.apply(b"", &d).unwrap(), target);
}

#[test]
fn applies_delta_against_source() {
    let e = msdelta();
    let src = b"version=1 ".repeat(100);
    let tgt = b"version=2 ".repeat(100);
    let d = e.create(&src, &tgt).unwrap();
    assert_eq!(e.apply(&src, &d).unwrap(), tgt);
}

#[test]
fn rejects_garbage_delta() {
    assert!(msdelta().apply(b"", b"not a delta").is_err());
}

#[test]
fn selected_engine_applies_msdelta_output() {
    let sel = DeltaEngine::select(None).unwrap();
    assert!(sel.label().starts_with("system:"), "{}", sel.label());
    let d = msdelta().create(b"", b"abc").unwrap();
    assert_eq!(sel.apply(b"", &d).unwrap(), b"abc");
}

#[test]
fn dcm_round_trip_with_system_base() {
    let e = msdelta();
    let dcm = DcmDecoder::from_system().expect("wcp.dll base");
    assert!(dcm.base().starts_with(b"<?xml"));
    let xml = b"<?xml version=\"1.0\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v3\"/>";
    let mut bytes = b"DCM\x01".to_vec();
    bytes.extend(e.create(dcm.base(), xml).unwrap());
    assert!(is_dcm(&bytes));
    assert_eq!(dcm.decode(&e, &bytes).unwrap(), xml);
}

#[test]
fn non_dcm_passes_through() {
    let dcm = DcmDecoder::with_base(Vec::new());
    assert_eq!(dcm.decode(&msdelta(), b"<assembly/>").unwrap(), b"<assembly/>");
}

#[test]
fn decodes_real_winsxs_manifest() {
    let dir = sys::windows_dir().join("WinSxS").join("Manifests");
    let entry = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .find(|e| {
            std::fs::read(e.path())
                .map(|b| is_dcm(&b))
                .unwrap_or(false)
        })
        .expect("a DCM manifest in WinSxS");
    let bytes = std::fs::read(entry.path()).unwrap();
    let out = DcmDecoder::from_system().unwrap().decode(&msdelta(), &bytes).unwrap();
    let text = String::from_utf8_lossy(&out);
    assert!(text.contains("<assembly"), "{}", &text[..text.len().min(200)]);
}

#[test]
fn reports_native_arch() {
    assert!(["amd64", "arm64", "x86"].contains(&sys::native_arch()));
    assert!(sys::windows_dir().join("System32").is_dir());
}
```

- [ ] **Step 2: 執行測試確認失敗**

Run: `cargo test --test delta`
Expected: 編譯失敗（`delta`、`sys` 模組不存在）

- [ ] **Step 3: 實作 `src/core/sys.rs`**

```rust
//! 系統資訊：Windows 目錄、原生處理器架構。

use std::path::PathBuf;

use windows::Win32::System::SystemInformation::{
    GetNativeSystemInfo, PROCESSOR_ARCHITECTURE_AMD64, PROCESSOR_ARCHITECTURE_ARM64,
    PROCESSOR_ARCHITECTURE_INTEL, SYSTEM_INFO,
};

pub fn windows_dir() -> PathBuf {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
}

/// 以元件 manifest 的 `processorArchitecture` 用語回傳原生架構。
pub fn native_arch() -> &'static str {
    let mut info = SYSTEM_INFO::default();
    // SAFETY: 只寫入呼叫端提供的結構。
    let arch = unsafe {
        GetNativeSystemInfo(&mut info);
        info.Anonymous.Anonymous.wProcessorArchitecture
    };
    match arch {
        PROCESSOR_ARCHITECTURE_AMD64 => "amd64",
        PROCESSOR_ARCHITECTURE_ARM64 => "arm64",
        PROCESSOR_ARCHITECTURE_INTEL => "x86",
        _ => "unknown",
    }
}
```

- [ ] **Step 4: 實作 `src/core/delta.rs`**

```rust
//! 差異引擎：PA30（UpdateCompression.dll / msdelta.dll）、PA19（mspatcha.dll）與 DCM manifest。
//!
//! DLL 一律以 LoadLibraryExW + GetProcAddress 動態載入，不需要 import library。

use std::ffi::c_void;
use std::path::{Path, PathBuf};

use windows::core::{s, HSTRING, PCWSTR};
use windows::Win32::Foundation::{FreeLibrary, FILETIME, HMODULE};
use windows::Win32::System::LibraryLoader::{
    FindResourceW, GetProcAddress, LoadLibraryExW, LoadResource, LockResource, SizeofResource,
    LOAD_LIBRARY_AS_DATAFILE, LOAD_LIBRARY_AS_IMAGE_RESOURCE, LOAD_LIBRARY_SEARCH_SYSTEM32,
    LOAD_WITH_ALTERED_SEARCH_PATH,
};
use windows::Win32::System::Memory::{VirtualFree, MEM_RELEASE};

use super::model::parse_version;
use super::{sys, CoreError};

#[repr(C)]
#[derive(Clone, Copy)]
struct DeltaInput {
    start: *const c_void,
    size: usize,
    editable: i32,
}

impl DeltaInput {
    fn of(buf: &[u8]) -> Self {
        DeltaInput {
            start: if buf.is_empty() {
                std::ptr::null()
            } else {
                buf.as_ptr().cast()
            },
            size: buf.len(),
            editable: 0,
        }
    }
}

#[repr(C)]
struct DeltaOutput {
    start: *mut c_void,
    size: usize,
}

type ApplyDeltaBFn = unsafe extern "system" fn(i64, DeltaInput, DeltaInput, *mut DeltaOutput) -> i32;
type DeltaFreeFn = unsafe extern "system" fn(*mut c_void) -> i32;
#[allow(clippy::type_complexity)]
type CreateDeltaBFn = unsafe extern "system" fn(
    i64,
    i64,
    i64,
    DeltaInput,
    DeltaInput,
    DeltaInput,
    DeltaInput,
    DeltaInput,
    *const FILETIME,
    u32,
    *mut DeltaOutput,
) -> i32;

const DELTA_FILE_TYPE_RAW: i64 = 1;
const CALG_MD5: u32 = 0x8003;

pub struct DeltaEngine {
    module: HMODULE,
    apply: ApplyDeltaBFn,
    free: DeltaFreeFn,
    create: Option<CreateDeltaBFn>,
    label: String,
}

// SAFETY: 只保存函式指標與模組代號；ApplyDeltaB 不依賴呼叫執行緒的狀態。
unsafe impl Send for DeltaEngine {}
unsafe impl Sync for DeltaEngine {}

impl Drop for DeltaEngine {
    fn drop(&mut self) {
        // SAFETY: module 由本結構載入並獨占。
        unsafe {
            let _ = FreeLibrary(self.module);
        }
    }
}

impl DeltaEngine {
    /// 載入 System32 內的 `UpdateCompression.dll` 或 `msdelta.dll`。
    pub fn system(dll: &str) -> Result<Self, CoreError> {
        // SAFETY: 只從 System32 載入。
        let module = unsafe { LoadLibraryExW(&HSTRING::from(dll), None, LOAD_LIBRARY_SEARCH_SYSTEM32) }
            .map_err(|e| CoreError::Delta(format!("{dll}: {e}")))?;
        Self::from_module(module, format!("system:{dll}"))
    }

    /// 載入指定路徑的 DLL（`.msu` 附帶的 UpdateCompression.dll）。呼叫端必須先驗證簽章。
    pub fn from_path(path: &Path) -> Result<Self, CoreError> {
        // SAFETY: 呼叫端已確認檔案為 Microsoft 簽章。
        let module = unsafe {
            LoadLibraryExW(
                &HSTRING::from(path.as_os_str()),
                None,
                LOAD_WITH_ALTERED_SEARCH_PATH,
            )
        }
        .map_err(|e| CoreError::Delta(format!("{}: {e}", path.display())))?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Self::from_module(module, format!("package:{name}"))
    }

    fn from_module(module: HMODULE, label: String) -> Result<Self, CoreError> {
        // SAFETY: 取得的函式指標依 msdelta.h 的原型轉型。
        unsafe {
            let apply = GetProcAddress(module, s!("ApplyDeltaB"));
            let free = GetProcAddress(module, s!("DeltaFree"));
            let create = GetProcAddress(module, s!("CreateDeltaB"));
            match (apply, free) {
                (Some(a), Some(f)) => Ok(DeltaEngine {
                    module,
                    apply: std::mem::transmute::<_, ApplyDeltaBFn>(a),
                    free: std::mem::transmute::<_, DeltaFreeFn>(f),
                    create: create.map(|c| std::mem::transmute::<_, CreateDeltaBFn>(c)),
                    label,
                }),
                _ => {
                    let _ = FreeLibrary(module);
                    Err(CoreError::Delta(format!(
                        "{label}: ApplyDeltaB / DeltaFree not exported"
                    )))
                }
            }
        }
    }

    /// 依 spec 的順序：系統 UpdateCompression → 套件附帶（呼叫端已驗證）→ 系統 msdelta。
    pub fn select(package_dll: Option<&Path>) -> Result<Self, CoreError> {
        if let Ok(e) = Self::system("UpdateCompression.dll") {
            return Ok(e);
        }
        if let Some(p) = package_dll {
            if let Ok(e) = Self::from_path(p) {
                return Ok(e);
            }
        }
        Self::system("msdelta.dll")
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    /// 套用 PA30 差異；`source` 為空代表 null-source（完整壓縮）差異。
    pub fn apply(&self, source: &[u8], delta: &[u8]) -> Result<Vec<u8>, CoreError> {
        let mut out = DeltaOutput {
            start: std::ptr::null_mut(),
            size: 0,
        };
        // SAFETY: 輸入緩衝區在呼叫期間有效；輸出由 DeltaFree 釋放。
        unsafe {
            if (self.apply)(0, DeltaInput::of(source), DeltaInput::of(delta), &mut out) == 0 {
                return Err(CoreError::Delta(format!(
                    "{}: ApplyDeltaB failed ({})",
                    self.label,
                    windows::core::Error::from_win32()
                )));
            }
            let v = std::slice::from_raw_parts(out.start as *const u8, out.size).to_vec();
            (self.free)(out.start);
            Ok(v)
        }
    }

    /// 產生 PA30 差異（測試用；只有 msdelta.dll 匯出 CreateDeltaB）。
    pub fn create(&self, source: &[u8], target: &[u8]) -> Result<Vec<u8>, CoreError> {
        let create = self
            .create
            .ok_or_else(|| CoreError::Delta(format!("{}: CreateDeltaB not exported", self.label)))?;
        let empty = DeltaInput::of(&[]);
        let ft = FILETIME::default();
        let mut out = DeltaOutput {
            start: std::ptr::null_mut(),
            size: 0,
        };
        // SAFETY: 同 apply。
        unsafe {
            let ok = create(
                DELTA_FILE_TYPE_RAW,
                0,
                0,
                DeltaInput::of(source),
                DeltaInput::of(target),
                empty,
                empty,
                empty,
                &ft,
                CALG_MD5,
                &mut out,
            );
            if ok == 0 {
                return Err(CoreError::Delta(format!(
                    "CreateDeltaB failed ({})",
                    windows::core::Error::from_win32()
                )));
            }
            let v = std::slice::from_raw_parts(out.start as *const u8, out.size).to_vec();
            (self.free)(out.start);
            Ok(v)
        }
    }
}

type ApplyPatchFn = unsafe extern "system" fn(
    *const u8,
    u32,
    *const u8,
    u32,
    *mut *mut u8,
    u32,
    *mut u32,
    *mut FILETIME,
    u32,
    *const c_void,
    *const c_void,
) -> i32;

/// 還原 PA19（舊版 PSF）null-source 修補：mspatcha.dll 的 ApplyPatchToFileByBuffers。
pub fn apply_pa19(patch: &[u8]) -> Result<Vec<u8>, CoreError> {
    // SAFETY: 從 System32 載入；輸出緩衝區由 mspatcha 以 VirtualAlloc 配置，用 VirtualFree 釋放。
    unsafe {
        let module = LoadLibraryExW(&HSTRING::from("mspatcha.dll"), None, LOAD_LIBRARY_SEARCH_SYSTEM32)
            .map_err(|e| CoreError::Delta(format!("mspatcha.dll: {e}")))?;
        let result = (|| {
            let f = GetProcAddress(module, s!("ApplyPatchToFileByBuffers"))
                .ok_or_else(|| CoreError::Delta("ApplyPatchToFileByBuffers not exported".into()))?;
            let f = std::mem::transmute::<_, ApplyPatchFn>(f);
            let mut out: *mut u8 = std::ptr::null_mut();
            let mut size = 0u32;
            let mut ft = FILETIME::default();
            let ok = f(
                patch.as_ptr(),
                patch.len() as u32,
                std::ptr::null(),
                0,
                &mut out,
                0,
                &mut size,
                &mut ft,
                0,
                std::ptr::null(),
                std::ptr::null(),
            );
            if ok == 0 || out.is_null() {
                return Err(CoreError::Delta(format!(
                    "PA19 patch failed ({})",
                    windows::core::Error::from_win32()
                )));
            }
            let v = std::slice::from_raw_parts(out, size as usize).to_vec();
            let _ = VirtualFree(out.cast(), 0, MEM_RELEASE);
            Ok(v)
        })();
        let _ = FreeLibrary(module);
        result
    }
}

pub const DCM_MAGIC: &[u8; 4] = b"DCM\x01";

pub fn is_dcm(bytes: &[u8]) -> bool {
    bytes.starts_with(DCM_MAGIC)
}

/// DCM manifest 解碼器：持有 wcp.dll 內嵌的基底 manifest。
pub struct DcmDecoder {
    base: Vec<u8>,
}

impl DcmDecoder {
    pub fn with_base(base: Vec<u8>) -> Self {
        DcmDecoder { base }
    }

    /// 從本機最新版 servicing stack 的 wcp.dll 讀取基底。
    pub fn from_system() -> Result<Self, CoreError> {
        let wcp = find_wcp_dll()?;
        Ok(DcmDecoder {
            base: load_base_resource(&wcp)?,
        })
    }

    pub fn base(&self) -> &[u8] {
        &self.base
    }

    pub fn decode(&self, engine: &DeltaEngine, bytes: &[u8]) -> Result<Vec<u8>, CoreError> {
        if !is_dcm(bytes) {
            return Ok(bytes.to_vec());
        }
        if self.base.is_empty() {
            return Err(CoreError::Delta("DCM base manifest unavailable".into()));
        }
        engine.apply(&self.base, &bytes[DCM_MAGIC.len()..])
    }
}

/// `WinSxS\<arch>_microsoft-windows-servicingstack_<token>_<version>_...\wcp.dll` 中版本最新者。
fn find_wcp_dll() -> Result<PathBuf, CoreError> {
    let winsxs = sys::windows_dir().join("WinSxS");
    let prefix = format!("{}_microsoft-windows-servicingstack_", sys::native_arch());
    let entries = std::fs::read_dir(&winsxs).map_err(|e| CoreError::io(&winsxs, e))?;
    let mut best: Option<([u32; 4], PathBuf)> = None;
    for e in entries.filter_map(Result::ok) {
        let name = e.file_name().to_string_lossy().to_ascii_lowercase();
        if !name.starts_with(&prefix) {
            continue;
        }
        let Some(ver) = name.split('_').nth(3).and_then(parse_version) else {
            continue;
        };
        let dll = e.path().join("wcp.dll");
        if dll.is_file() && best.as_ref().is_none_or(|(v, _)| ver > *v) {
            best = Some((ver, dll));
        }
    }
    best.map(|(_, p)| p)
        .ok_or_else(|| CoreError::Delta("servicing stack wcp.dll not found".into()))
}

/// 讀取 wcp.dll 的資源（型別 0x266、ID 1）。
fn load_base_resource(path: &Path) -> Result<Vec<u8>, CoreError> {
    // SAFETY: 以資料檔方式載入，不執行任何程式碼；資源指標在 FreeLibrary 前有效。
    unsafe {
        let module = LoadLibraryExW(
            &HSTRING::from(path.as_os_str()),
            None,
            LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE,
        )
        .map_err(|e| CoreError::Delta(format!("{}: {e}", path.display())))?;
        let result = (|| {
            let res = FindResourceW(Some(module), PCWSTR(1 as _), PCWSTR(0x266 as _));
            if res.is_invalid() {
                return Err(CoreError::Delta("DCM base resource not found in wcp.dll".into()));
            }
            let size = SizeofResource(Some(module), res) as usize;
            let handle = LoadResource(Some(module), res)
                .map_err(|e| CoreError::Delta(format!("LoadResource: {e}")))?;
            let ptr = LockResource(handle) as *const u8;
            if ptr.is_null() || size == 0 {
                return Err(CoreError::Delta("DCM base resource is empty".into()));
            }
            Ok(std::slice::from_raw_parts(ptr, size).to_vec())
        })();
        let _ = FreeLibrary(module);
        result
    }
}
```

`src/core/mod.rs` 加入 `pub mod delta;` 與 `pub mod sys;`。

註：windows 0.62 部分函式的參數包裝（例如 `FindResourceW` 的 `Option<HMODULE>`、`LoadLibraryExW` 的 `hfile`）若與上列不同，依 docs.rs（`windows` 0.62.2）調整呼叫處即可，邏輯不變。

- [ ] **Step 5: 執行測試確認通過**

Run: `cargo test --test delta`
Expected: 全部 PASS。若 `selected_engine_applies_msdelta_output` 失敗，代表 UpdateCompression.dll 不相容 msdelta 產生的 PA30：停下來回報，不要自行改動 `select` 的順序。

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: add delta engine (UpdateCompression/msdelta/mspatcha) and DCM decoder

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: 容器基礎與 CAB 解壓（cabinet.dll FDI）

**Files:**
- Create: `src/core/container/mod.rs`, `src/core/container/cab.rs`, `tests/common/mod.rs`, `tests/cab.rs`
- Modify: `src/core/mod.rs`（加入 `pub mod container;`）

**Interfaces:**
- Consumes: `CoreError`、`model::ContainerFormat`
- Produces:
  - `container::Role`（`Manifest`、`Mum`、`PkgProperties`、`PsfIndex`、`NestedCab`、`NestedWim`、`Psf`、`PackageDll`、`Ignore`；`to_disk() -> bool`）
  - `container::role_of(base_name: &str) -> Role`
  - `container::Item { vpath: String, name: String, data: ItemData }`、`ItemData::{Bytes(Vec<u8>), File(PathBuf)}`；`Item::new(vpath, data)`、`Item::bytes() -> Result<Cow<[u8]>, CoreError>`、`Item::path() -> Option<&Path>`
  - `container::Extracted { items: Vec<Item>, skipped: Vec<(String, Role)> }`
  - `container::sniff(path) -> Result<Option<ContainerFormat>, CoreError>`
  - `container::cab::extract(cab: &Path, vprefix: &str, out_dir: &Path, cancel: &AtomicBool, want: &dyn Fn(Role) -> bool) -> Result<Extracted, CoreError>`
  - 測試輔助 `tests/common/mod.rs`：`make_cab(dir, cab_name, files: &[(&str, &[u8])], lzx: bool) -> PathBuf`、`fixture(name) -> String`

- [ ] **Step 1: 建立測試輔助 `tests/common/mod.rs`**

```rust
//! 整合測試共用：以系統 makecab.exe 產生 CAB、讀取 fixture。
#![allow(dead_code)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR")))
        .unwrap()
}

/// 用 makecab 的 DDF 產生 CAB。`files` 的名稱可含 `\` 子目錄（以 DestinationDir 表示）。
/// `dir` 必須是純 ASCII 路徑（makecab 以 ANSI 讀 DDF）。
pub fn make_cab(dir: &Path, cab_name: &str, files: &[(&str, &[u8])], lzx: bool) -> PathBuf {
    let src = dir.join(format!("{cab_name}.src"));
    std::fs::create_dir_all(&src).unwrap();
    let mut ddf = String::from(
        ".OPTION EXPLICIT\n.Set Cabinet=on\n.Set Compress=on\n.Set MaxDiskSize=0\n\
         .Set MaxCabinetSize=0\n.Set FolderSizeThreshold=0\n.Set UniqueFiles=off\n\
         .Set RptFileName=nul\n.Set InfFileName=nul\n",
    );
    writeln!(ddf, ".Set CompressionType={}", if lzx { "LZX" } else { "MSZIP" }).unwrap();
    writeln!(ddf, ".Set DiskDirectoryTemplate=\"{}\"", dir.display()).unwrap();
    writeln!(ddf, ".Set CabinetNameTemplate=\"{cab_name}\"").unwrap();
    let mut current_dir = String::new();
    for (i, (name, data)) in files.iter().enumerate() {
        let (sub, base) = name.rsplit_once('\\').unwrap_or(("", name));
        if sub != current_dir {
            writeln!(ddf, ".Set DestinationDir=\"{sub}\"").unwrap();
            current_dir = sub.to_string();
        }
        let p = src.join(format!("f{i}"));
        std::fs::write(&p, data).unwrap();
        writeln!(ddf, "\"{}\" \"{base}\"", p.display()).unwrap();
    }
    let ddf_path = dir.join(format!("{cab_name}.ddf"));
    std::fs::write(&ddf_path, ddf).unwrap();
    let out = Command::new("makecab")
        .arg("/F")
        .arg(&ddf_path)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "makecab failed: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    dir.join(cab_name)
}
```

- [ ] **Step 2: 寫失敗測試 `tests/cab.rs`**

```rust
mod common;

use std::sync::atomic::AtomicBool;

use msu_inspector::core::container::{cab, role_of, ItemData, Role};
use msu_inspector::core::CoreError;

fn all(_: Role) -> bool {
    true
}

#[test]
fn classifies_entry_names() {
    assert_eq!(role_of("amd64_x_10.0.1_none_abc.manifest"), Role::Manifest);
    assert_eq!(role_of("update.MUM"), Role::Mum);
    assert_eq!(role_of("Windows10.0-KB5005565-x64-pkgProperties.txt"), Role::PkgProperties);
    assert_eq!(role_of("express.psf.cix.xml"), Role::PsfIndex);
    assert_eq!(role_of("inner.cab"), Role::NestedCab);
    assert_eq!(role_of("Windows11.0-KB1-x64.wim"), Role::NestedWim);
    assert_eq!(role_of("Windows11.0-KB1-x64.psf"), Role::Psf);
    assert_eq!(role_of("UpdateCompression.dll"), Role::PackageDll);
    assert_eq!(role_of("ntoskrnl.exe"), Role::Ignore);
    assert!(Role::NestedCab.to_disk() && !Role::Manifest.to_disk());
}

#[test]
fn extracts_wanted_files_only() {
    let t = tempfile::tempdir().unwrap();
    let cab_path = common::make_cab(
        t.path(),
        "a.cab",
        &[
            ("update.mum", b"<mum/>"),
            ("a.manifest", b"<assembly/>"),
            ("payload.dll", b"MZ...."),
            ("inner.cab", b"MSCF-fake"),
        ],
        false,
    );
    let out = t.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    let ex = cab::extract(&cab_path, "a.cab", &out, &AtomicBool::new(false), &all).unwrap();
    let mut names: Vec<&str> = ex.items.iter().map(|i| i.name.as_str()).collect();
    names.sort();
    assert_eq!(names, vec!["a.manifest", "inner.cab", "update.mum"]);
    let m = ex.items.iter().find(|i| i.name == "a.manifest").unwrap();
    assert_eq!(m.vpath, "a.cab/a.manifest");
    assert_eq!(&*m.bytes().unwrap(), b"<assembly/>");
    let inner = ex.items.iter().find(|i| i.name == "inner.cab").unwrap();
    let ItemData::File(p) = &inner.data else { panic!("nested cab must go to disk") };
    assert_eq!(std::fs::read(p).unwrap(), b"MSCF-fake");
}

#[test]
fn extracts_lzx_folder_with_many_files() {
    let t = tempfile::tempdir().unwrap();
    let bodies: Vec<(String, Vec<u8>)> = (0..400)
        .map(|i| (format!("c{i}.manifest"), format!("<assembly id=\"{i}\"/>").repeat(50).into_bytes()))
        .collect();
    let files: Vec<(&str, &[u8])> = bodies.iter().map(|(n, b)| (n.as_str(), b.as_slice())).collect();
    let cab_path = common::make_cab(t.path(), "big.cab", &files, true);
    let started = std::time::Instant::now();
    let ex = cab::extract(&cab_path, "big.cab", t.path(), &AtomicBool::new(false), &all).unwrap();
    assert_eq!(ex.items.len(), 400);
    assert!(started.elapsed().as_secs() < 10, "single pass extraction should be fast");
    let c7 = ex.items.iter().find(|i| i.name == "c7.manifest").unwrap();
    assert_eq!(&*c7.bytes().unwrap(), bodies[7].1.as_slice());
}

#[test]
fn keeps_subdirectory_in_vpath() {
    let t = tempfile::tempdir().unwrap();
    let cab_path = common::make_cab(t.path(), "s.cab", &[("amd64_x\\b.manifest", b"<assembly/>")], false);
    let ex = cab::extract(&cab_path, "s.cab", t.path(), &AtomicBool::new(false), &all).unwrap();
    assert_eq!(ex.items[0].name, "b.manifest");
    assert_eq!(ex.items[0].vpath, "s.cab/amd64_x/b.manifest");
}

#[test]
fn extracts_from_non_ascii_path() {
    let t = tempfile::tempdir().unwrap();
    let cab_path = common::make_cab(t.path(), "u.cab", &[("x.manifest", b"<assembly/>")], false);
    let dir = t.path().join("下載 測試");
    std::fs::create_dir_all(&dir).unwrap();
    let moved = dir.join("更新.cab");
    std::fs::copy(&cab_path, &moved).unwrap();
    let ex = cab::extract(&moved, "更新.cab", &dir, &AtomicBool::new(false), &all).unwrap();
    assert_eq!(ex.items.len(), 1);
}

#[test]
fn honors_want_filter_and_reports_skipped() {
    let t = tempfile::tempdir().unwrap();
    let cab_path = common::make_cab(
        t.path(),
        "p.cab",
        &[("a.manifest", b"<assembly/>"), ("big.psf", b"PSF")],
        false,
    );
    let want = |r: Role| r != Role::Psf;
    let ex = cab::extract(&cab_path, "p.cab", t.path(), &AtomicBool::new(false), &want).unwrap();
    assert_eq!(ex.items.len(), 1);
    assert_eq!(ex.skipped, vec![("p.cab/big.psf".to_string(), Role::Psf)]);
}

#[test]
fn cancel_aborts_extraction() {
    let t = tempfile::tempdir().unwrap();
    let cab_path = common::make_cab(t.path(), "c.cab", &[("a.manifest", b"<assembly/>")], false);
    let r = cab::extract(&cab_path, "c.cab", t.path(), &AtomicBool::new(true), &all);
    assert!(matches!(r, Err(CoreError::Cancelled)));
}

#[test]
fn rejects_non_cab() {
    let t = tempfile::tempdir().unwrap();
    let p = t.path().join("fake.cab");
    std::fs::write(&p, b"MSCF but truncated").unwrap();
    let r = cab::extract(&p, "fake.cab", t.path(), &AtomicBool::new(false), &all);
    assert!(matches!(r, Err(CoreError::Container { .. })), "{r:?}");
}
```

- [ ] **Step 3: 執行測試確認失敗**

Run: `cargo test --test cab`
Expected: 編譯失敗（`container` 模組不存在）

- [ ] **Step 4: 實作 `src/core/container/mod.rs`（本 Task 的部分）**

```rust
//! 容器拆解：CAB / WIM / PSF，輸出 manifest、.mum 等需要的項目。

pub mod cab;

use std::borrow::Cow;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::model::ContainerFormat;
use super::CoreError;

/// 容器中檔案的用途，依檔名判斷。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Manifest,
    Mum,
    PkgProperties,
    PsfIndex,
    NestedCab,
    NestedWim,
    Psf,
    PackageDll,
    Ignore,
}

impl Role {
    /// 可能很大、之後要以檔案開啟的項目寫到暫存資料夾；其餘留在記憶體。
    pub fn to_disk(self) -> bool {
        matches!(
            self,
            Role::NestedCab | Role::NestedWim | Role::Psf | Role::PackageDll
        )
    }
}

pub fn role_of(base_name: &str) -> Role {
    let n = base_name.to_ascii_lowercase();
    if n.ends_with(".manifest") {
        Role::Manifest
    } else if n.ends_with(".mum") {
        Role::Mum
    } else if n.ends_with(".psf.cix.xml") {
        Role::PsfIndex
    } else if n == "pkgproperties.txt" || n.ends_with("-pkgproperties.txt") || n.ends_with("_pkgproperties.txt") {
        Role::PkgProperties
    } else if n.ends_with(".cab") {
        Role::NestedCab
    } else if n.ends_with(".wim") {
        Role::NestedWim
    } else if n.ends_with(".psf") {
        Role::Psf
    } else if n == "updatecompression.dll" {
        Role::PackageDll
    } else {
        Role::Ignore
    }
}

#[derive(Debug)]
pub enum ItemData {
    Bytes(Vec<u8>),
    File(PathBuf),
}

/// 從容器取出的一個檔案。`vpath` 為虛擬路徑（`外層/內層/檔名`，以 `/` 分隔）。
#[derive(Debug)]
pub struct Item {
    pub vpath: String,
    pub name: String,
    pub data: ItemData,
}

impl Item {
    pub fn new(vpath: String, data: ItemData) -> Self {
        let name = vpath.rsplit(['/', '\\']).next().unwrap_or("").to_string();
        Item { vpath, name, data }
    }

    pub fn bytes(&self) -> Result<Cow<'_, [u8]>, CoreError> {
        match &self.data {
            ItemData::Bytes(b) => Ok(Cow::Borrowed(b)),
            ItemData::File(p) => std::fs::read(p)
                .map(Cow::Owned)
                .map_err(|e| CoreError::io(p, e)),
        }
    }

    pub fn path(&self) -> Option<&Path> {
        match &self.data {
            ItemData::File(p) => Some(p),
            ItemData::Bytes(_) => None,
        }
    }
}

/// 單一容器的解壓結果；`skipped` 記錄因 `want` 過濾而略過的非 Ignore 項目。
#[derive(Debug, Default)]
pub struct Extracted {
    pub items: Vec<Item>,
    pub skipped: Vec<(String, Role)>,
}

/// 依檔頭判斷容器格式；`.psf` 沒有可靠的檔頭，以副檔名判斷。
pub fn sniff(path: &Path) -> Result<Option<ContainerFormat>, CoreError> {
    let mut head = [0u8; 8];
    let mut f = std::fs::File::open(path).map_err(|e| CoreError::io(path, e))?;
    let n = f.read(&mut head).map_err(|e| CoreError::io(path, e))?;
    let head = &head[..n];
    if head.starts_with(b"MSCF") {
        return Ok(Some(ContainerFormat::Cab));
    }
    if head.starts_with(b"MSWIM\0\0\0") {
        return Ok(Some(ContainerFormat::Wim));
    }
    let is_psf = path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("psf"));
    Ok(is_psf.then_some(ContainerFormat::Psf))
}
```

- [ ] **Step 5: 實作 `src/core/container/cab.rs`**

```rust
//! CAB 解壓：cabinet.dll 的 FDI。單次循序解壓，於 fdintCOPY_FILE 只挑需要的檔案。
//!
//! FDI 以 ANSI 字串傳遞路徑，但實際開檔由我們的 `fdi_open` 回呼負責；
//! 我們傳入 UTF-8 位元組、在回呼中以 UTF-8 解碼，因此路徑含中文也能開啟。

use std::ffi::{c_void, CStr, CString};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use windows::core::PCSTR;
use windows::Win32::Storage::Cabinets::{
    fdintCLOSE_FILE_INFO, fdintCOPY_FILE, fdintNEXT_CABINET, FDICopy, FDICreate, FDIDestroy,
    ERF, FDICREATE_CPU_TYPE, FDINOTIFICATION, FDINOTIFICATIONTYPE,
};
use windows::Win32::System::Memory::{GetProcessHeap, HeapAlloc, HeapFree, HEAP_FLAGS};

use super::{role_of, Extracted, Item, ItemData, Role};
use crate::core::CoreError;

/// FDI 回呼中的「檔案代號」：指向此列舉的 Box 指標。
enum Handle {
    Read(File),
    Memory { vpath: String, buf: Vec<u8> },
    Disk { vpath: String, path: PathBuf, file: File },
}

struct Ctx<'a> {
    vprefix: &'a str,
    out_dir: &'a Path,
    cancel: &'a AtomicBool,
    want: &'a dyn Fn(Role) -> bool,
    out: Extracted,
    counter: usize,
    /// 目前開啟、尚未收到 CLOSE_FILE_INFO 的輸出代號（中止時由我們釋放）
    open_output: Option<isize>,
    error: Option<String>,
}

pub fn extract(
    cab: &Path,
    vprefix: &str,
    out_dir: &Path,
    cancel: &AtomicBool,
    want: &dyn Fn(Role) -> bool,
) -> Result<Extracted, CoreError> {
    let container_err = |detail: String| CoreError::Container {
        path: vprefix.to_string(),
        detail,
    };
    let dir = cab.parent().unwrap_or(Path::new("."));
    let mut dir = dir
        .to_str()
        .ok_or_else(|| container_err("path is not valid Unicode".into()))?
        .to_string();
    if !dir.ends_with('\\') {
        dir.push('\\');
    }
    let name = cab
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| container_err("path is not valid Unicode".into()))?;
    let dir = CString::new(dir).map_err(|e| container_err(e.to_string()))?;
    let name = CString::new(name).map_err(|e| container_err(e.to_string()))?;

    let mut ctx = Ctx {
        vprefix,
        out_dir,
        cancel,
        want,
        out: Extracted::default(),
        counter: 0,
        open_output: None,
        error: None,
    };
    let mut erf = ERF::default();
    // SAFETY: 回呼只操作本模組建立的 Handle；ctx 在 FDICopy 期間有效。
    unsafe {
        let hfdi = FDICreate(
            Some(fdi_alloc),
            Some(fdi_free),
            Some(fdi_open),
            Some(fdi_read),
            Some(fdi_write),
            Some(fdi_close),
            Some(fdi_seek),
            FDICREATE_CPU_TYPE(1), // cpu80386：保護模式
            &mut erf,
        );
        if hfdi.is_null() {
            return Err(container_err("FDICreate failed".into()));
        }
        let ok = FDICopy(
            hfdi,
            PCSTR(name.as_ptr().cast()),
            PCSTR(dir.as_ptr().cast()),
            0,
            Some(fdi_notify),
            None,
            Some(&mut ctx as *mut Ctx as *const c_void),
        );
        let _ = FDIDestroy(hfdi);
        if let Some(h) = ctx.open_output.take() {
            drop(Box::from_raw(h as *mut Handle));
        }
        if !ok.as_bool() {
            if cancel.load(Ordering::Relaxed) {
                return Err(CoreError::Cancelled);
            }
            let detail = ctx
                .error
                .take()
                .unwrap_or_else(|| format!("FDICopy failed (erfOper={})", erf.erfOper));
            return Err(container_err(detail));
        }
    }
    Ok(ctx.out)
}

unsafe extern "system" fn fdi_alloc(cb: u32) -> *mut c_void {
    unsafe {
        match GetProcessHeap() {
            Ok(heap) => HeapAlloc(heap, HEAP_FLAGS(0), cb as usize),
            Err(_) => std::ptr::null_mut(),
        }
    }
}

unsafe extern "system" fn fdi_free(pv: *const c_void) {
    unsafe {
        if let Ok(heap) = GetProcessHeap() {
            let _ = HeapFree(heap, HEAP_FLAGS(0), Some(pv));
        }
    }
}

unsafe extern "system" fn fdi_open(path: PCSTR, _oflag: i32, _pmode: i32) -> isize {
    let path = unsafe { CStr::from_ptr(path.0.cast()) };
    let Ok(path) = path.to_str() else {
        return -1;
    };
    match File::open(path) {
        Ok(f) => Box::into_raw(Box::new(Handle::Read(f))) as isize,
        Err(_) => -1,
    }
}

unsafe extern "system" fn fdi_read(hf: isize, pv: *mut c_void, cb: u32) -> u32 {
    let h = unsafe { &mut *(hf as *mut Handle) };
    let buf = unsafe { std::slice::from_raw_parts_mut(pv as *mut u8, cb as usize) };
    let Handle::Read(f) = h else {
        return u32::MAX;
    };
    let mut n = 0;
    while n < buf.len() {
        match f.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(_) => return u32::MAX,
        }
    }
    n as u32
}

unsafe extern "system" fn fdi_write(hf: isize, pv: *const c_void, cb: u32) -> u32 {
    let h = unsafe { &mut *(hf as *mut Handle) };
    let data = unsafe { std::slice::from_raw_parts(pv as *const u8, cb as usize) };
    match h {
        Handle::Memory { buf, .. } => {
            buf.extend_from_slice(data);
            cb
        }
        Handle::Disk { file, .. } => {
            if file.write_all(data).is_ok() {
                cb
            } else {
                u32::MAX
            }
        }
        Handle::Read(_) => u32::MAX,
    }
}

/// FDI 只對自己以 pfnopen 開啟的 cabinet 呼叫 close；輸出檔在 CLOSE_FILE_INFO 由我們關閉。
unsafe extern "system" fn fdi_close(hf: isize) -> i32 {
    drop(unsafe { Box::from_raw(hf as *mut Handle) });
    0
}

unsafe extern "system" fn fdi_seek(hf: isize, dist: i32, seektype: i32) -> i32 {
    let h = unsafe { &mut *(hf as *mut Handle) };
    let pos = match seektype {
        0 => SeekFrom::Start(dist as u64),
        1 => SeekFrom::Current(dist as i64),
        2 => SeekFrom::End(dist as i64),
        _ => return -1,
    };
    match h {
        Handle::Read(f) => f.seek(pos).map(|p| p as i32).unwrap_or(-1),
        _ => -1,
    }
}

/// 檔名只保留安全字元，避免 CAB 內的奇怪名稱影響暫存路徑。
fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() || ".-_".contains(c) { c } else { '_' })
        .collect()
}

unsafe extern "system" fn fdi_notify(kind: FDINOTIFICATIONTYPE, pfdin: *mut FDINOTIFICATION) -> isize {
    let n = unsafe { &mut *pfdin };
    let ctx = unsafe { &mut *(n.pv as *mut Ctx) };
    match kind {
        fdintCOPY_FILE => {
            if ctx.cancel.load(Ordering::Relaxed) {
                return -1;
            }
            let raw = unsafe { CStr::from_ptr(n.psz1.0.cast()) }.to_bytes();
            let inner = String::from_utf8_lossy(raw).replace('\\', "/");
            let base = inner.rsplit('/').next().unwrap_or(&inner).to_string();
            let vpath = format!("{}/{inner}", ctx.vprefix);
            let role = role_of(&base);
            if role == Role::Ignore {
                return 0;
            }
            if !(ctx.want)(role) {
                ctx.out.skipped.push((vpath, role));
                return 0;
            }
            let handle = if role.to_disk() {
                ctx.counter += 1;
                let path = ctx
                    .out_dir
                    .join(format!("{:05}_{}", ctx.counter, sanitize(&base)));
                match File::create(&path) {
                    Ok(file) => Handle::Disk { vpath, path, file },
                    Err(e) => {
                        ctx.error = Some(format!("{}: {e}", path.display()));
                        return -1;
                    }
                }
            } else {
                Handle::Memory {
                    vpath,
                    buf: Vec::with_capacity(n.cb.max(0) as usize),
                }
            };
            let h = Box::into_raw(Box::new(handle)) as isize;
            ctx.open_output = Some(h);
            h
        }
        fdintCLOSE_FILE_INFO => {
            ctx.open_output = None;
            let h = unsafe { Box::from_raw(n.hf as *mut Handle) };
            match *h {
                Handle::Memory { vpath, buf } => {
                    ctx.out.items.push(Item::new(vpath, ItemData::Bytes(buf)))
                }
                Handle::Disk { vpath, path, file } => {
                    drop(file);
                    ctx.out.items.push(Item::new(vpath, ItemData::File(path)));
                }
                Handle::Read(_) => {}
            }
            1
        }
        // 不支援分割成多個檔案的 CAB
        fdintNEXT_CABINET => -1,
        _ => 0,
    }
}
```

`src/core/mod.rs` 加入 `pub mod container;`。

註：若 windows 0.62 的 FDI 回呼型別為 `extern "C"` 而非 `extern "system"`，把本檔所有回呼的 ABI 改成與 `PFNALLOC` 等型別一致即可（x64 / ARM64 上兩者相同）。

- [ ] **Step 6: 執行測試確認通過**

Run: `cargo test --test cab`
Expected: 全部 PASS

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: add container roles and single-pass CAB extraction via FDI

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: WIM 展開（wimgapi）

**Files:**
- Create: `src/core/container/wim.rs`, `tests/wim.rs`
- Modify: `src/core/container/mod.rs`（加入 `pub mod wim;`）

**Interfaces:**
- Consumes: Task 6 的 `Role`、`role_of`、`Item`、`ItemData`、`Extracted`
- Produces:
  - `wim::extract(wim: &Path, vprefix: &str, out_dir: &Path, cancel: &AtomicBool, want: &dyn Fn(Role) -> bool) -> Result<Extracted, CoreError>`（展開所有 image；以 `WIM_MSG_PROCESS` 略過不需要的檔案）
  - `wim::map_error(code: u32, context: &str) -> CoreError`（1314 / 5 → `NeedsElevation`）
  - `wim::capture_for_tests(src_dir: &Path, wim: &Path) -> Result<(), CoreError>`（`#[doc(hidden)]`）

常數已對照公開的 wimgapi.h：`WIM_MSG = WM_APP + 0x1476 = 0x9476`、`WIM_MSG_PROCESS = 0x9479`（wParam = 目的路徑 PCWSTR、lParam = `*mut BOOL`，設為 FALSE 即略過該檔）、`WIM_MSG_ABORT_IMAGE = 0xFFFFFFFF`。

- [ ] **Step 1: 寫失敗測試 `tests/wim.rs`**

```rust
use std::sync::atomic::AtomicBool;

use msu_inspector::core::container::{wim, Role};
use msu_inspector::core::CoreError;

/// 建立 WIM；若本機 wimgapi 不允許非管理員擷取，回傳 None 並略過測試。
fn make_wim(dir: &std::path::Path) -> Option<std::path::PathBuf> {
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("amd64_comp_10.0.1.1_none_abc")).unwrap();
    std::fs::write(src.join("update.mum"), b"<mum/>").unwrap();
    std::fs::write(src.join("amd64_comp_10.0.1.1_none_abc").join("a.manifest"), b"<assembly/>").unwrap();
    std::fs::write(src.join("payload.dll"), vec![0u8; 4096]).unwrap();
    std::fs::write(src.join("big.psf"), b"PSF").unwrap();
    let wim_path = dir.join("t.wim");
    match wim::capture_for_tests(&src, &wim_path) {
        Ok(()) => Some(wim_path),
        Err(e) => {
            eprintln!("skipping: cannot capture WIM without elevation: {e}");
            None
        }
    }
}

#[test]
fn extracts_wanted_files_only() {
    let t = tempfile::tempdir().unwrap();
    let Some(w) = make_wim(t.path()) else { return };
    let out = t.path().join("out");
    std::fs::create_dir_all(&out).unwrap();
    let want = |r: Role| r != Role::Psf;
    let ex = wim::extract(&w, "t.wim", &out, &AtomicBool::new(false), &want).unwrap();
    let mut names: Vec<&str> = ex.items.iter().map(|i| i.name.as_str()).collect();
    names.sort();
    assert_eq!(names, vec!["a.manifest", "update.mum"]);
    assert!(!out.join("1").join("payload.dll").exists(), "payload must be skipped");
    let m = ex.items.iter().find(|i| i.name == "a.manifest").unwrap();
    assert_eq!(m.vpath, "t.wim/amd64_comp_10.0.1.1_none_abc/a.manifest");
    assert_eq!(&*m.bytes().unwrap(), b"<assembly/>");
    assert!(ex.skipped.iter().any(|(p, r)| p.ends_with("big.psf") && *r == Role::Psf));
}

#[test]
fn cancel_aborts_apply() {
    let t = tempfile::tempdir().unwrap();
    let Some(w) = make_wim(t.path()) else { return };
    let r = wim::extract(&w, "t.wim", t.path(), &AtomicBool::new(true), &|_| true);
    assert!(matches!(r, Err(CoreError::Cancelled)), "{r:?}");
}

#[test]
fn rejects_non_wim() {
    let t = tempfile::tempdir().unwrap();
    let p = t.path().join("x.wim");
    std::fs::write(&p, b"MSWIM\0\0\0garbage").unwrap();
    let r = wim::extract(&p, "x.wim", t.path(), &AtomicBool::new(false), &|_| true);
    assert!(r.is_err());
}

#[test]
fn maps_privilege_errors_to_needs_elevation() {
    assert!(matches!(wim::map_error(1314, "apply"), CoreError::NeedsElevation(_)));
    assert!(matches!(wim::map_error(5, "apply"), CoreError::NeedsElevation(_)));
    assert!(matches!(wim::map_error(2, "apply"), CoreError::Container { .. }));
}
```

- [ ] **Step 2: 執行測試確認失敗**

Run: `cargo test --test wim`
Expected: 編譯失敗（`wim` 模組不存在）

- [ ] **Step 3: 實作 `src/core/container/wim.rs`**

```rust
//! WIM 展開：wimgapi.dll（raw-dylib 連結，不需要 Windows SDK）。
//!
//! 以 WIM_MSG_PROCESS 回呼略過不需要的檔案，避免把 24H2 `.msu` 內數 GB 的 PSF 複製到暫存資料夾。

use std::ffi::c_void;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use windows::core::{HSTRING, PCWSTR};

use super::{role_of, Extracted, Item, ItemData, Role};
use crate::core::CoreError;

type Handle = *mut c_void;
type MessageCallback = unsafe extern "system" fn(u32, usize, isize, *mut c_void) -> u32;

#[link(name = "wimgapi", kind = "raw-dylib")]
extern "system" {
    fn WIMCreateFile(path: PCWSTR, access: u32, disposition: u32, flags: u32, compression: u32, result: *mut u32) -> Handle;
    fn WIMSetTemporaryPath(wim: Handle, path: PCWSTR) -> i32;
    fn WIMGetImageCount(wim: Handle) -> u32;
    fn WIMLoadImage(wim: Handle, index: u32) -> Handle;
    fn WIMApplyImage(image: Handle, path: PCWSTR, flags: u32) -> i32;
    fn WIMCaptureImage(wim: Handle, path: PCWSTR, flags: u32) -> Handle;
    fn WIMCloseHandle(h: Handle) -> i32;
    fn WIMRegisterMessageCallback(wim: Handle, cb: MessageCallback, user: *mut c_void) -> u32;
    fn WIMUnregisterMessageCallback(wim: Handle, cb: MessageCallback) -> u32;
}

const WIM_GENERIC_READ: u32 = 0x8000_0000;
const WIM_GENERIC_WRITE: u32 = 0x4000_0000;
const WIM_CREATE_NEW: u32 = 1;
const WIM_OPEN_EXISTING: u32 = 3;
const WIM_COMPRESS_XPRESS: u32 = 1;
const WIM_FLAG_NO_DIRACL: u32 = 0x10;
const WIM_FLAG_NO_FILEACL: u32 = 0x20;
const WIM_FLAG_NO_RP_FIX: u32 = 0x100;
const WIM_MSG: u32 = 0x8000 + 0x1476;
const WIM_MSG_PROCESS: u32 = WIM_MSG + 3;
const WIM_MSG_SUCCESS: u32 = 0;
const WIM_MSG_ABORT_IMAGE: u32 = 0xFFFF_FFFF;

const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_PRIVILEGE_NOT_HELD: u32 = 1314;

struct CallbackCtx<'a> {
    cancel: &'a AtomicBool,
    want: &'a dyn Fn(Role) -> bool,
    skipped: Vec<(String, Role)>,
    out_dir: &'a Path,
    vprefix: &'a str,
}

/// 看起來像「檔名」：有 1–8 字元的英數副檔名，且不全是數字（目錄名稱常帶版本號）。
fn looks_like_file(name: &str) -> bool {
    name.rsplit_once('.').is_some_and(|(_, ext)| {
        (1..=8).contains(&ext.len())
            && ext.chars().all(|c| c.is_ascii_alphanumeric())
            && !ext.chars().all(|c| c.is_ascii_digit())
    })
}

fn vpath_of(ctx: &CallbackCtx, full: &Path) -> String {
    let rel = full.strip_prefix(ctx.out_dir).unwrap_or(full);
    // 去掉第一層（image 編號資料夾）
    let rel: Vec<String> = rel
        .components()
        .skip(1)
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    format!("{}/{}", ctx.vprefix, rel.join("/"))
}

unsafe extern "system" fn on_message(msg: u32, wparam: usize, lparam: isize, user: *mut c_void) -> u32 {
    if msg != WIM_MSG_PROCESS {
        return WIM_MSG_SUCCESS;
    }
    let ctx = unsafe { &mut *(user as *mut CallbackCtx) };
    if ctx.cancel.load(Ordering::Relaxed) {
        return WIM_MSG_ABORT_IMAGE;
    }
    let path = unsafe { PCWSTR(wparam as *const u16).to_string() }.unwrap_or_default();
    let full = Path::new(&path);
    let name = full
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if !looks_like_file(&name) {
        return WIM_MSG_SUCCESS; // 目錄或無副檔名的檔案：保留
    }
    let role = role_of(&name);
    if role == Role::Ignore || !(ctx.want)(role) {
        if role != Role::Ignore {
            let vpath = vpath_of(ctx, full);
            ctx.skipped.push((vpath, role));
        }
        // SAFETY: lParam 指向 wimgapi 提供的 BOOL
        unsafe { *(lparam as *mut i32) = 0 };
    }
    WIM_MSG_SUCCESS
}

pub fn map_error(code: u32, context: &str) -> CoreError {
    match code {
        ERROR_ACCESS_DENIED | ERROR_PRIVILEGE_NOT_HELD => {
            CoreError::NeedsElevation(format!("{context}: WIM (error {code})"))
        }
        _ => CoreError::Container {
            path: context.to_string(),
            detail: format!("wimgapi error {code}: {}", windows::core::Error::from_hresult(windows::core::HRESULT::from_win32(code))),
        },
    }
}

fn last_error() -> u32 {
    // SAFETY: 無參數查詢。
    unsafe { windows::Win32::Foundation::GetLastError().0 }
}

pub fn extract(
    wim: &Path,
    vprefix: &str,
    out_dir: &Path,
    cancel: &AtomicBool,
    want: &dyn Fn(Role) -> bool,
) -> Result<Extracted, CoreError> {
    let tmp = out_dir.join("_wimtmp");
    std::fs::create_dir_all(&tmp).map_err(|e| CoreError::io(&tmp, e))?;
    let mut ctx = CallbackCtx {
        cancel,
        want,
        skipped: Vec::new(),
        out_dir,
        vprefix,
    };
    // SAFETY: 所有控制代碼在函式結束前關閉；ctx 在回呼註冊期間有效。
    unsafe {
        let mut created = 0u32;
        let h = WIMCreateFile(
            PCWSTR(HSTRING::from(wim.as_os_str()).as_ptr()),
            WIM_GENERIC_READ,
            WIM_OPEN_EXISTING,
            0,
            0,
            &mut created,
        );
        if h.is_null() {
            return Err(map_error(last_error(), vprefix));
        }
        let result = (|| {
            if WIMSetTemporaryPath(h, PCWSTR(HSTRING::from(tmp.as_os_str()).as_ptr())) == 0 {
                return Err(map_error(last_error(), vprefix));
            }
            WIMRegisterMessageCallback(h, on_message, &mut ctx as *mut CallbackCtx as *mut c_void);
            let count = WIMGetImageCount(h);
            for index in 1..=count {
                let img = WIMLoadImage(h, index);
                if img.is_null() {
                    return Err(map_error(last_error(), vprefix));
                }
                let dest = out_dir.join(index.to_string());
                std::fs::create_dir_all(&dest).map_err(|e| CoreError::io(&dest, e))?;
                let ok = WIMApplyImage(
                    img,
                    PCWSTR(HSTRING::from(dest.as_os_str()).as_ptr()),
                    WIM_FLAG_NO_DIRACL | WIM_FLAG_NO_FILEACL | WIM_FLAG_NO_RP_FIX,
                );
                let err = last_error();
                WIMCloseHandle(img);
                if ok == 0 {
                    if cancel.load(Ordering::Relaxed) {
                        return Err(CoreError::Cancelled);
                    }
                    return Err(map_error(err, vprefix));
                }
            }
            Ok(())
        })();
        WIMUnregisterMessageCallback(h, on_message);
        WIMCloseHandle(h);
        result?;
    }
    let _ = std::fs::remove_dir_all(&tmp);

    let mut out = Extracted {
        items: Vec::new(),
        skipped: ctx.skipped,
    };
    collect_files(out_dir, out_dir, vprefix, &mut out.items)?;
    Ok(out)
}

/// 走訪展開結果，把需要的檔案轉成 Item；小檔讀進記憶體後刪除。
fn collect_files(root: &Path, dir: &Path, vprefix: &str, items: &mut Vec<Item>) -> Result<(), CoreError> {
    for e in std::fs::read_dir(dir).map_err(|e| CoreError::io(dir, e))? {
        let e = e.map_err(|e| CoreError::io(dir, e))?;
        let path = e.path();
        if path.is_dir() {
            collect_files(root, &path, vprefix, items)?;
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        let role = role_of(&name);
        if role == Role::Ignore {
            continue;
        }
        let rel: Vec<String> = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .components()
            .skip(1)
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        let vpath = format!("{vprefix}/{}", rel.join("/"));
        let data = if role.to_disk() {
            ItemData::File(path)
        } else {
            let bytes = std::fs::read(&path).map_err(|e| CoreError::io(&path, e))?;
            let _ = std::fs::remove_file(&path);
            ItemData::Bytes(bytes)
        };
        items.push(Item::new(vpath, data));
    }
    Ok(())
}

/// 測試用：把資料夾擷取成 WIM（非管理員可能被拒絕）。
#[doc(hidden)]
pub fn capture_for_tests(src_dir: &Path, wim: &Path) -> Result<(), CoreError> {
    let tmp = wim.with_extension("tmpdir");
    std::fs::create_dir_all(&tmp).map_err(|e| CoreError::io(&tmp, e))?;
    // SAFETY: 同 extract。
    unsafe {
        let mut created = 0u32;
        let h = WIMCreateFile(
            PCWSTR(HSTRING::from(wim.as_os_str()).as_ptr()),
            WIM_GENERIC_WRITE,
            WIM_CREATE_NEW,
            0,
            WIM_COMPRESS_XPRESS,
            &mut created,
        );
        if h.is_null() {
            return Err(map_error(last_error(), "capture"));
        }
        WIMSetTemporaryPath(h, PCWSTR(HSTRING::from(tmp.as_os_str()).as_ptr()));
        let img = WIMCaptureImage(h, PCWSTR(HSTRING::from(src_dir.as_os_str()).as_ptr()), 0);
        let err = last_error();
        if !img.is_null() {
            WIMCloseHandle(img);
        }
        WIMCloseHandle(h);
        if img.is_null() {
            return Err(map_error(err, "capture"));
        }
    }
    Ok(())
}
```

`src/core/container/mod.rs` 加入 `pub mod wim;`。

- [ ] **Step 4: 執行測試確認通過**

Run: `cargo test --test wim`
Expected: 全部 PASS（若輸出 `skipping: cannot capture WIM without elevation`，再以系統管理員終端機執行一次 `cargo test --test wim`，確認擷取與展開測試實際通過，並在回報中註明非管理員時能否展開）

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: extract WIM containers via wimgapi with per-file filtering

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: PSF 索引解析與還原

**Files:**
- Create: `src/core/container/psf.rs`, `tests/psf.rs`
- Modify: `src/core/container/mod.rs`（加入 `pub mod psf;`）

**Interfaces:**
- Consumes: Task 5 的 `DeltaEngine`、`apply_pa19`；Task 2 的 `decode_text`、XML 小工具
- Produces:
  - `psf::SourceType::{Raw, Pa30, Pa19}`、`psf::PsfEntry { name: String, source: SourceType, offset: u64, length: u64 }`
  - `psf::parse_index(xml: &str) -> Result<Vec<PsfEntry>, CoreError>`
  - `psf::read_embedded_index(psf: &Path, engine: &DeltaEngine) -> Result<String, CoreError>`（偏移 4 的 u32 長度、偏移 0x80 起的 PA30 null-source）
  - `psf::load_index(psf: &Path, sidecar: Option<&[u8]>, engine: &DeltaEngine) -> Result<Vec<PsfEntry>, CoreError>`
  - `psf::read_entry(file: &mut File, entry: &PsfEntry, engine: &DeltaEngine) -> Result<Vec<u8>, CoreError>`

- [ ] **Step 1: 寫失敗測試 `tests/psf.rs`**

```rust
use std::fs::File;
use std::io::Write;

use msu_inspector::core::container::psf::{self, SourceType};
use msu_inspector::core::delta::DeltaEngine;

const PAYLOAD_BASE: u64 = 0x10000;

struct Built {
    path: std::path::PathBuf,
    index_xml: String,
    manifest: Vec<u8>,
    mum: Vec<u8>,
}

/// 產生 PSF：payload 從 0x10000 開始（一筆 RAW、一筆 PA30）；`embed` 為 true 時把索引放在檔頭。
fn build(dir: &std::path::Path, embed: bool) -> Built {
    let e = DeltaEngine::system("msdelta.dll").unwrap();
    let manifest = b"<assembly id=\"raw\"/>".to_vec();
    let mum = b"<assembly id=\"pa30\"/>".repeat(10);
    let mum_delta = e.create(b"", &mum).unwrap();
    let raw_off = PAYLOAD_BASE;
    let pa_off = raw_off + manifest.len() as u64;
    let index_xml = format!(
        "<?xml version=\"1.0\"?><Container type=\"PSF\" version=\"2.0\"><Files>\
         <File id=\"1\" name=\"amd64_x_10.0.1.1_none_abc\\a.manifest\" length=\"{}\" time=\"0\" attr=\"128\">\
         <Delta><Source type=\"RAW\" offset=\"{raw_off}\" length=\"{}\"/></Delta></File>\
         <File id=\"2\" name=\"update.mum\" length=\"{}\" time=\"0\" attr=\"128\">\
         <Delta><Source type=\"PA30\" offset=\"{pa_off}\" length=\"{}\"/></Delta></File>\
         </Files></Container>",
        manifest.len(),
        manifest.len(),
        mum.len(),
        mum_delta.len()
    );
    let mut buf = vec![0u8; PAYLOAD_BASE as usize];
    buf[..4].copy_from_slice(b"PSTR");
    if embed {
        let idx = e.create(b"", index_xml.as_bytes()).unwrap();
        buf[4..8].copy_from_slice(&(idx.len() as u32).to_le_bytes());
        buf[0x80..0x80 + idx.len()].copy_from_slice(&idx);
    }
    buf.extend_from_slice(&manifest);
    buf.extend_from_slice(&mum_delta);
    let path = dir.join(if embed { "embedded.psf" } else { "sidecar.psf" });
    File::create(&path).unwrap().write_all(&buf).unwrap();
    Built { path, index_xml, manifest, mum }
}

#[test]
fn parses_index_xml() {
    let t = tempfile::tempdir().unwrap();
    let b = build(t.path(), false);
    let entries = psf::parse_index(&b.index_xml).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, "amd64_x_10.0.1.1_none_abc\\a.manifest");
    assert_eq!(entries[0].source, SourceType::Raw);
    assert_eq!(entries[0].offset, PAYLOAD_BASE);
    assert_eq!(entries[1].source, SourceType::Pa30);
}

#[test]
fn reads_embedded_index_and_entries() {
    let t = tempfile::tempdir().unwrap();
    let b = build(t.path(), true);
    let e = DeltaEngine::select(None).unwrap();
    let entries = psf::load_index(&b.path, None, &e).unwrap();
    let mut f = File::open(&b.path).unwrap();
    assert_eq!(psf::read_entry(&mut f, &entries[0], &e).unwrap(), b.manifest);
    assert_eq!(psf::read_entry(&mut f, &entries[1], &e).unwrap(), b.mum);
}

#[test]
fn uses_sidecar_index() {
    let t = tempfile::tempdir().unwrap();
    let b = build(t.path(), false);
    let e = DeltaEngine::select(None).unwrap();
    let entries = psf::load_index(&b.path, Some(b.index_xml.as_bytes()), &e).unwrap();
    assert_eq!(entries.len(), 2);
    assert!(psf::load_index(&b.path, None, &e).is_err(), "no embedded index in sidecar PSF");
}

#[test]
fn rejects_out_of_range_entries() {
    let t = tempfile::tempdir().unwrap();
    let b = build(t.path(), false);
    let e = DeltaEngine::select(None).unwrap();
    let bad = psf::PsfEntry {
        name: "x.manifest".into(),
        source: SourceType::Raw,
        offset: 1 << 40,
        length: 10,
    };
    let mut f = File::open(&b.path).unwrap();
    assert!(psf::read_entry(&mut f, &bad, &e).is_err());
}
```

- [ ] **Step 2: 執行測試確認失敗**

Run: `cargo test --test psf`
Expected: 編譯失敗（`psf` 模組不存在）

- [ ] **Step 3: 實作 `src/core/container/psf.rs`**

```rust
//! PSF（Patch Storage File）：依索引（`*.psf.cix.xml` 或檔頭內嵌）取出指定檔案。
//!
//! 索引格式（見 spec 第 11 節）：
//! `<Container type="PSF"><Files><File name=".."><Delta><Source type="RAW|PA30|PA19" offset length/>`

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::core::delta::{apply_pa19, DeltaEngine};
use crate::core::manifest::{attr, child, decode_text, elements, is_el, parse_doc};
use crate::core::CoreError;

/// 單一項目大小上限：manifest / .mum 不會超過這個大小，超過視為索引錯誤。
const MAX_ENTRY: u64 = 256 * 1024 * 1024;
const EMBEDDED_INDEX_OFFSET: u64 = 0x80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceType {
    Raw,
    Pa30,
    Pa19,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsfEntry {
    pub name: String,
    pub source: SourceType,
    pub offset: u64,
    pub length: u64,
}

pub fn parse_index(xml: &str) -> Result<Vec<PsfEntry>, CoreError> {
    let doc = parse_doc(xml)?;
    let root = doc.root_element();
    if !is_el(root, "Container") {
        return Err(CoreError::Xml("PSF index root is not <Container>".into()));
    }
    let files = child(root, "Files").ok_or_else(|| CoreError::Xml("PSF index has no <Files>".into()))?;
    let mut out = Vec::new();
    for f in elements(files, "File") {
        let Some(src) = child(f, "Delta").and_then(|d| child(d, "Source")) else {
            continue;
        };
        let source = match attr(src, "type").unwrap_or_default().to_ascii_uppercase().as_str() {
            "RAW" => SourceType::Raw,
            "PA30" => SourceType::Pa30,
            "PA19" => SourceType::Pa19,
            other => return Err(CoreError::Xml(format!("unknown PSF source type {other}"))),
        };
        let num = |name: &str| -> Result<u64, CoreError> {
            attr(src, name)
                .and_then(|v| v.trim().parse().ok())
                .ok_or_else(|| CoreError::Xml(format!("PSF entry missing {name}")))
        };
        out.push(PsfEntry {
            name: attr(f, "name").unwrap_or_default(),
            source,
            offset: num("offset")?,
            length: num("length")?,
        });
    }
    Ok(out)
}

fn read_at(file: &mut File, offset: u64, length: u64) -> Result<Vec<u8>, CoreError> {
    let size = file
        .metadata()
        .map_err(|e| CoreError::Container { path: "psf".into(), detail: e.to_string() })?
        .len();
    if length > MAX_ENTRY || offset.checked_add(length).is_none_or(|end| end > size) {
        return Err(CoreError::Container {
            path: "psf".into(),
            detail: format!("entry out of range (offset {offset}, length {length}, file {size})"),
        });
    }
    let mut buf = vec![0u8; length as usize];
    file.seek(SeekFrom::Start(offset))
        .and_then(|_| file.read_exact(&mut buf))
        .map_err(|e| CoreError::Container { path: "psf".into(), detail: e.to_string() })?;
    Ok(buf)
}

/// 24H2 起的 PSF：偏移 4 為 u32 索引長度，偏移 0x80 起為 PA30（null-source）壓縮的索引 XML。
pub fn read_embedded_index(psf: &Path, engine: &DeltaEngine) -> Result<String, CoreError> {
    let mut f = File::open(psf).map_err(|e| CoreError::io(psf, e))?;
    let head = read_at(&mut f, 0, 8)?;
    let len = u32::from_le_bytes([head[4], head[5], head[6], head[7]]) as u64;
    if len == 0 {
        return Err(CoreError::Container {
            path: psf.display().to_string(),
            detail: "no embedded PSF index".into(),
        });
    }
    let delta = read_at(&mut f, EMBEDDED_INDEX_OFFSET, len)?;
    decode_text(&engine.apply(&[], &delta)?)
}

/// 有獨立索引檔時使用之，否則讀檔頭內嵌索引。
pub fn load_index(psf: &Path, sidecar: Option<&[u8]>, engine: &DeltaEngine) -> Result<Vec<PsfEntry>, CoreError> {
    let xml = match sidecar {
        Some(bytes) => decode_text(bytes)?,
        None => read_embedded_index(psf, engine)?,
    };
    parse_index(&xml)
}

pub fn read_entry(file: &mut File, entry: &PsfEntry, engine: &DeltaEngine) -> Result<Vec<u8>, CoreError> {
    let raw = read_at(file, entry.offset, entry.length)?;
    match entry.source {
        SourceType::Raw => Ok(raw),
        SourceType::Pa30 => engine.apply(&[], &raw),
        SourceType::Pa19 => apply_pa19(&raw),
    }
}
```

Task 2 的 `manifest/mod.rs` 中 `attr`、`child`、`elements`、`is_el`、`parse_doc` 為 `pub(crate)`，本檔在 crate 內使用即可。`src/core/container/mod.rs` 加入 `pub mod psf;`。

- [ ] **Step 4: 執行測試確認通過**

Run: `cargo test --test psf`
Expected: 全部 PASS

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: read PSF indexes (sidecar or embedded) and extract entries

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 9: 遞迴拆包（collect）與 PSF 還原（resolve_psfs）

**Files:**
- Modify: `src/core/container/mod.rs`, `tests/common/mod.rs`
- Create: `tests/collect.rs`

**Interfaces:**
- Consumes: Task 6–8 的 `cab::extract`、`wim::extract`、`psf::*`、`sniff`、`role_of`；Task 5 的 `DeltaEngine`；Task 1 的 `Ctx`、`Progress`、`Warning`、`ContainerInfo`
- Produces:
  - `container::Collected { outer: Option<ContainerFormat>, manifests: Vec<Item>, mums: Vec<Item>, pkg_properties: Option<Vec<u8>>, psf_indexes: Vec<Item>, psfs: Vec<Item>, package_dll: Option<PathBuf>, containers: Vec<ContainerInfo>, warnings: Vec<Warning>, saw_psf: bool }`
  - `container::collect(path: &Path, work: &Path, ctx: &Ctx) -> Result<Collected, CoreError>`：第一輪不展開 PSF；若沒有任何 manifest 且看到 PSF，第二輪連 PSF 一起展開
  - `container::resolve_psfs(c: &mut Collected, engine: &DeltaEngine, ctx: &Ctx) -> Result<(), CoreError>`：從 PSF 取出 manifest / `.mum` 併入（依檔名去重）
  - 測試輔助 `common::utf16(text) -> Vec<u8>`、`common::build_psf(dir, file_name, entries: &[(&str, &[u8], bool /*pa30*/)], embed: bool) -> (PathBuf, String)`

- [ ] **Step 1: 在 `tests/common/mod.rs` 加入輔助函式**

```rust
use std::io::Write as _;

use msu_inspector::core::delta::DeltaEngine;

/// UTF-16LE（含 BOM），模擬 pkgProperties.txt。
pub fn utf16(text: &str) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFE];
    for u in text.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

/// 產生 PSF：payload 從 0x10000 開始；`pa30` 為 true 的項目以 PA30 null-source 儲存。
/// `embed` 為 true 時索引放在檔頭（24H2 格式），否則回傳的 XML 需另存為 `*.psf.cix.xml`。
pub fn build_psf(
    dir: &Path,
    file_name: &str,
    entries: &[(&str, &[u8], bool)],
    embed: bool,
) -> (PathBuf, String) {
    let e = DeltaEngine::system("msdelta.dll").unwrap();
    let mut payload = Vec::new();
    let mut files = String::new();
    for (i, (name, data, pa30)) in entries.iter().enumerate() {
        let stored = if *pa30 { e.create(b"", data).unwrap() } else { data.to_vec() };
        let offset = 0x10000 + payload.len();
        writeln!(
            files,
            "<File id=\"{i}\" name=\"{name}\" length=\"{}\" time=\"0\" attr=\"128\"><Delta><Source type=\"{}\" offset=\"{offset}\" length=\"{}\"/></Delta></File>",
            data.len(),
            if *pa30 { "PA30" } else { "RAW" },
            stored.len()
        )
        .unwrap();
        payload.extend(stored);
    }
    let xml = format!("<?xml version=\"1.0\"?><Container type=\"PSF\" version=\"2.0\"><Files>{files}</Files></Container>");
    let mut buf = vec![0u8; 0x10000];
    buf[..4].copy_from_slice(b"PSTR");
    if embed {
        let idx = e.create(b"", xml.as_bytes()).unwrap();
        buf[4..8].copy_from_slice(&(idx.len() as u32).to_le_bytes());
        buf[0x80..0x80 + idx.len()].copy_from_slice(&idx);
    }
    buf.extend(payload);
    let path = dir.join(file_name);
    std::fs::File::create(&path).unwrap().write_all(&buf).unwrap();
    (path, xml)
}
```

（`use std::fmt::Write as _;` 已在檔案開頭；兩個 `Write` trait 以 `as _` 匯入不會衝突。）

- [ ] **Step 2: 寫失敗測試 `tests/collect.rs`**

```rust
mod common;

use msu_inspector::core::container::{collect, resolve_psfs};
use msu_inspector::core::delta::DeltaEngine;
use msu_inspector::core::model::{ContainerFormat, WarningCode};
use msu_inspector::core::progress::Ctx;
use msu_inspector::core::CoreError;

const PKG_PROPS: &str = "ApplicabilityInfo=\"Windows 10.0 Client SKUs\"\r\nKB Article Number=\"5099999\"\r\n";

fn names(items: &[msu_inspector::core::container::Item]) -> Vec<String> {
    let mut v: Vec<String> = items.iter().map(|i| i.name.clone()).collect();
    v.sort();
    v
}

#[test]
fn collects_nested_msu_layout() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    let inner = common::make_cab(
        d,
        "inner.cab",
        &[
            ("update.mum", b"<assembly/>"),
            ("a.manifest", b"<assembly/>"),
            ("b.manifest", b"<assembly/>"),
            ("amd64_c\\c.manifest", b"<assembly/>"),
            ("payload.dll", b"MZ"),
        ],
        true,
    );
    let wsus = common::make_cab(d, "WSUSSCAN.cab", &[("scan.manifest", b"<assembly/>")], false);
    let props = common::utf16(PKG_PROPS);
    let msu = common::make_cab(
        d,
        "Windows10.0-KB5099999-x64.msu",
        &[
            ("Windows10.0-KB5099999-x64.cab", &std::fs::read(&inner).unwrap()),
            ("WSUSSCAN.cab", &std::fs::read(&wsus).unwrap()),
            ("Windows10.0-KB5099999-x64-pkgProperties.txt", &props),
        ],
        false,
    );
    let work = d.join("work");
    let c = collect(&msu, &work, &Ctx::silent()).unwrap();
    assert_eq!(c.outer, Some(ContainerFormat::Cab));
    assert_eq!(names(&c.manifests), vec!["a.manifest", "b.manifest", "c.manifest"]);
    assert_eq!(names(&c.mums), vec!["update.mum"]);
    assert_eq!(c.pkg_properties.as_deref(), Some(props.as_slice()));
    let wsus_info = c.containers.iter().find(|i| i.path.ends_with("WSUSSCAN.cab")).unwrap();
    assert!(wsus_info.skipped.is_some());
    assert_eq!(c.containers.iter().filter(|i| i.skipped.is_none()).count(), 2);
    assert!(c.warnings.is_empty());
}

#[test]
fn desktop_deployment_only_provides_update_compression() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    let dd = common::make_cab(
        d,
        "DesktopDeployment.cab",
        &[("UpdateCompression.dll", b"MZ-fake"), ("tool.manifest", b"<assembly/>")],
        false,
    );
    let inner = common::make_cab(d, "kb.cab", &[("a.manifest", b"<assembly/>")], false);
    let msu = common::make_cab(
        d,
        "x.msu",
        &[
            ("DesktopDeployment.cab", &std::fs::read(&dd).unwrap()),
            ("kb.cab", &std::fs::read(&inner).unwrap()),
        ],
        false,
    );
    let c = collect(&msu, &d.join("work"), &Ctx::silent()).unwrap();
    assert_eq!(names(&c.manifests), vec!["a.manifest"]);
    let dll = c.package_dll.expect("UpdateCompression.dll path");
    assert_eq!(std::fs::read(dll).unwrap(), b"MZ-fake");
}

#[test]
fn dedupes_manifests_across_containers() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    let a = common::make_cab(d, "a.cab", &[("same.manifest", b"<assembly/>")], false);
    let b = common::make_cab(d, "b.cab", &[("SAME.manifest", b"<assembly/>")], false);
    let msu = common::make_cab(
        d,
        "x.msu",
        &[("a.cab", &std::fs::read(&a).unwrap()), ("b.cab", &std::fs::read(&b).unwrap())],
        false,
    );
    let c = collect(&msu, &d.join("work"), &Ctx::silent()).unwrap();
    assert_eq!(c.manifests.len(), 1);
}

#[test]
fn corrupt_nested_container_becomes_warning() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    let good = common::make_cab(d, "good.cab", &[("a.manifest", b"<assembly/>")], false);
    let msu = common::make_cab(
        d,
        "x.msu",
        &[("good.cab", &std::fs::read(&good).unwrap()), ("bad.cab", b"MSCF truncated")],
        false,
    );
    let c = collect(&msu, &d.join("work"), &Ctx::silent()).unwrap();
    assert_eq!(c.manifests.len(), 1);
    assert_eq!(c.warnings.len(), 1);
    assert_eq!(c.warnings[0].code, WarningCode::ContainerFailed);
}

#[test]
fn rejects_non_update_files() {
    let t = tempfile::tempdir().unwrap();
    for (name, bytes) in [
        ("x.exe", b"MZ\x90\x00 not an update".as_slice()),
        ("empty.msu", b"".as_slice()),
        ("x.zip", b"PK\x03\x04".as_slice()),
        ("lonely.psf", b"PSTR".as_slice()),
    ] {
        let p = t.path().join(name);
        std::fs::write(&p, bytes).unwrap();
        let r = collect(&p, &t.path().join("work"), &Ctx::silent());
        assert!(matches!(r, Err(CoreError::UnsupportedFormat(_))), "{name}: {r:?}");
    }
}

#[test]
fn cancel_stops_collection() {
    let t = tempfile::tempdir().unwrap();
    let msu = common::make_cab(t.path(), "x.msu", &[("a.manifest", b"<assembly/>")], false);
    let ctx = Ctx::silent();
    ctx.cancel_flag().store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(matches!(collect(&msu, &t.path().join("work"), &ctx), Err(CoreError::Cancelled)));
}

#[test]
fn resolves_manifests_from_psf_with_sidecar_index() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    let (psf, xml) = common::build_psf(
        d,
        "Windows10.0-KB5099999-x64.psf",
        &[
            ("amd64_x_10.0.1.1_none_abc\\a.manifest", b"<assembly id=\"a\"/>", true),
            ("amd64_x_10.0.1.1_none_abc\\f\\x.dll", b"MZ", false),
        ],
        false,
    );
    let inner = common::make_cab(
        d,
        "Windows10.0-KB5099999-x64.cab",
        &[("update.mum", b"<assembly/>"), ("express.psf.cix.xml", xml.as_bytes())],
        false,
    );
    let msu = common::make_cab(
        d,
        "x.msu",
        &[
            ("Windows10.0-KB5099999-x64.cab", &std::fs::read(&inner).unwrap()),
            ("Windows10.0-KB5099999-x64.psf", &std::fs::read(&psf).unwrap()),
        ],
        false,
    );
    let mut c = collect(&msu, &d.join("work"), &Ctx::silent()).unwrap();
    assert!(c.saw_psf);
    assert_eq!(c.psfs.len(), 1, "second pass extracts the PSF because no manifest was found");
    resolve_psfs(&mut c, &DeltaEngine::select(None).unwrap(), &Ctx::silent()).unwrap();
    assert_eq!(names(&c.manifests), vec!["a.manifest"]);
    assert_eq!(&*c.manifests[0].bytes().unwrap(), b"<assembly id=\"a\"/>");
    assert!(c.containers.iter().any(|i| i.format == ContainerFormat::Psf));
}

#[test]
fn skips_psf_when_manifests_already_found() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    let (psf, _) = common::build_psf(d, "kb.psf", &[("a.manifest", b"<assembly/>", false)], true);
    let inner = common::make_cab(d, "kb.cab", &[("b.manifest", b"<assembly/>")], false);
    let msu = common::make_cab(
        d,
        "x.msu",
        &[("kb.cab", &std::fs::read(&inner).unwrap()), ("kb.psf", &std::fs::read(&psf).unwrap())],
        false,
    );
    let c = collect(&msu, &d.join("work"), &Ctx::silent()).unwrap();
    assert!(c.saw_psf);
    assert!(c.psfs.is_empty());
    assert_eq!(names(&c.manifests), vec!["b.manifest"]);
}
```

- [ ] **Step 3: 執行測試確認失敗**

Run: `cargo test --test collect`
Expected: 編譯失敗（`collect`、`resolve_psfs` 未定義）

- [ ] **Step 4: 在 `src/core/container/mod.rs` 實作 `collect` 與 `resolve_psfs`**

在檔案開頭補上 import：

```rust
use std::collections::{HashSet, VecDeque};
use std::fs::File;

use super::delta::DeltaEngine;
use super::model::{ContainerInfo, Warning, WarningCode};
use super::progress::{Ctx, Progress};
```

新增：

```rust
/// 更新掃描用的中繼資料，與安裝動作無關。
const SCAN_METADATA: &str = "wsusscan.cab";
/// 安裝工具（DesktopDeployment*.cab）：只取 UpdateCompression.dll，不收 manifest。
const TOOLING_PREFIX: &str = "desktopdeployment";

#[derive(Debug, Default)]
pub struct Collected {
    pub outer: Option<ContainerFormat>,
    pub manifests: Vec<Item>,
    pub mums: Vec<Item>,
    pub pkg_properties: Option<Vec<u8>>,
    pub psf_indexes: Vec<Item>,
    pub psfs: Vec<Item>,
    pub package_dll: Option<PathBuf>,
    pub containers: Vec<ContainerInfo>,
    pub warnings: Vec<Warning>,
    /// 有 PSF 因過濾而未展開
    pub saw_psf: bool,
    seen: HashSet<String>,
}

impl Collected {
    /// manifest / .mum 依檔名（不分大小寫）去重。
    fn add_unique(&mut self, item: Item, role: Role) {
        if !self.seen.insert(item.name.to_ascii_lowercase()) {
            return;
        }
        match role {
            Role::Manifest => self.manifests.push(item),
            Role::Mum => self.mums.push(item),
            _ => {}
        }
    }
}

pub fn collect(path: &Path, work: &Path, ctx: &Ctx) -> Result<Collected, CoreError> {
    let first = collect_pass(path, &work.join("pass1"), ctx, false)?;
    if first.manifests.is_empty() && first.saw_psf {
        let mut second = collect_pass(path, &work.join("pass2"), ctx, true)?;
        second.saw_psf = true;
        return Ok(second);
    }
    Ok(first)
}

fn collect_pass(path: &Path, work: &Path, ctx: &Ctx, want_psf: bool) -> Result<Collected, CoreError> {
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let outer = match sniff(path)? {
        Some(f @ (ContainerFormat::Cab | ContainerFormat::Wim)) => f,
        _ => return Err(CoreError::UnsupportedFormat(file_name)),
    };
    let mut c = Collected {
        outer: Some(outer),
        ..Default::default()
    };
    let cancel = ctx.cancel_flag();
    let mut queue = VecDeque::from([(path.to_path_buf(), file_name, outer, false)]);
    let mut n = 0usize;
    while let Some((p, vpath, fmt, tooling)) = queue.pop_front() {
        ctx.check()?;
        ctx.report(Progress::Unpacking {
            container: vpath.clone(),
        });
        n += 1;
        let out = work.join(format!("c{n:04}"));
        std::fs::create_dir_all(&out).map_err(|e| CoreError::io(&out, e))?;
        let want = |r: Role| {
            if tooling {
                r == Role::PackageDll
            } else {
                r != Role::Psf || want_psf
            }
        };
        let result = match fmt {
            ContainerFormat::Cab => cab::extract(&p, &vpath, &out, &cancel, &want),
            ContainerFormat::Wim => wim::extract(&p, &vpath, &out, &cancel, &want),
            ContainerFormat::Psf => unreachable!("PSF is resolved separately"),
        };
        let ex = match result {
            Ok(ex) => ex,
            Err(e @ (CoreError::Cancelled | CoreError::NeedsElevation(_))) => return Err(e),
            Err(e) if n == 1 => return Err(e),
            Err(e) => {
                c.warnings
                    .push(Warning::new(WarningCode::ContainerFailed, &vpath, e.to_string()));
                c.containers.push(ContainerInfo {
                    path: vpath,
                    format: fmt,
                    skipped: Some(e.to_string()),
                });
                continue;
            }
        };
        c.containers.push(ContainerInfo {
            path: vpath.clone(),
            format: fmt,
            skipped: None,
        });
        if ex.skipped.iter().any(|(_, r)| *r == Role::Psf) {
            c.saw_psf = true;
        }
        for item in ex.items {
            let role = role_of(&item.name);
            match role {
                Role::Manifest | Role::Mum => c.add_unique(item, role),
                Role::PkgProperties => {
                    if c.pkg_properties.is_none() {
                        c.pkg_properties = Some(item.bytes()?.into_owned());
                    }
                }
                Role::PsfIndex => c.psf_indexes.push(item),
                Role::Psf => c.psfs.push(item),
                Role::PackageDll => {
                    if c.package_dll.is_none() {
                        c.package_dll = item.path().map(Path::to_path_buf);
                    }
                }
                Role::NestedCab | Role::NestedWim => {
                    let Some(fp) = item.path().map(Path::to_path_buf) else {
                        continue;
                    };
                    let lname = item.name.to_ascii_lowercase();
                    let nested = match sniff(&fp)? {
                        Some(f @ (ContainerFormat::Cab | ContainerFormat::Wim)) => f,
                        _ if role == Role::NestedCab => ContainerFormat::Cab,
                        _ => ContainerFormat::Wim,
                    };
                    if lname == SCAN_METADATA {
                        let _ = std::fs::remove_file(&fp);
                        c.containers.push(ContainerInfo {
                            path: item.vpath,
                            format: nested,
                            skipped: Some("scan metadata".into()),
                        });
                        continue;
                    }
                    queue.push_back((fp, item.vpath, nested, lname.starts_with(TOOLING_PREFIX)));
                }
                Role::Ignore => {}
            }
        }
        // 巢狀容器展開後即刪除，節省暫存空間（使用者的原始檔不動）
        if n > 1 {
            let _ = std::fs::remove_file(&p);
        }
    }
    Ok(c)
}

/// 從已展開的 PSF 取出 manifest / .mum。索引優先用同名 `*.psf.cix.xml`，
/// 其次 `express.psf.cix.xml`，都沒有時讀檔頭內嵌索引。
pub fn resolve_psfs(c: &mut Collected, engine: &DeltaEngine, ctx: &Ctx) -> Result<(), CoreError> {
    for psf_item in std::mem::take(&mut c.psfs) {
        ctx.check()?;
        let Some(path) = psf_item.path().map(Path::to_path_buf) else {
            continue;
        };
        ctx.report(Progress::Unpacking {
            container: psf_item.vpath.clone(),
        });
        let own_index = format!("{}.cix.xml", psf_item.name.to_ascii_lowercase());
        let sidecar = c
            .psf_indexes
            .iter()
            .find(|i| i.name.to_ascii_lowercase() == own_index)
            .or_else(|| {
                c.psf_indexes
                    .iter()
                    .find(|i| i.name.eq_ignore_ascii_case("express.psf.cix.xml"))
            })
            .map(|i| i.bytes().map(Cow::into_owned))
            .transpose()?;
        let entries = match psf::load_index(&path, sidecar.as_deref(), engine) {
            Ok(e) => e,
            Err(e) => {
                c.warnings
                    .push(Warning::new(WarningCode::PsfFailed, &psf_item.vpath, e.to_string()));
                c.containers.push(ContainerInfo {
                    path: psf_item.vpath.clone(),
                    format: ContainerFormat::Psf,
                    skipped: Some(e.to_string()),
                });
                continue;
            }
        };
        c.containers.push(ContainerInfo {
            path: psf_item.vpath.clone(),
            format: ContainerFormat::Psf,
            skipped: None,
        });
        let mut file = File::open(&path).map_err(|e| CoreError::io(&path, e))?;
        for entry in entries {
            let base = entry.name.rsplit(['\\', '/']).next().unwrap_or("").to_string();
            let role = role_of(&base);
            if !matches!(role, Role::Manifest | Role::Mum) {
                continue;
            }
            let vpath = format!("{}/{}", psf_item.vpath, entry.name.replace('\\', "/"));
            match psf::read_entry(&mut file, &entry, engine) {
                Ok(bytes) => c.add_unique(Item::new(vpath, ItemData::Bytes(bytes)), role),
                Err(e) => c
                    .warnings
                    .push(Warning::new(WarningCode::PsfFailed, vpath, e.to_string())),
            }
        }
    }
    Ok(())
}
```

- [ ] **Step 5: 執行測試確認通過**

Run: `cargo test --test collect`
Expected: 全部 PASS

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: recursively collect manifests from nested CAB/WIM/PSF containers

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 10: `.msu` 數位簽章驗證

**Files:**
- Create: `src/core/signature.rs`, `tests/signature.rs`
- Modify: `src/core/mod.rs`（加入 `pub mod signature;`）

**Interfaces:**
- Consumes: `model::{SignatureInfo, SignatureStatus}`
- Produces:
  - `signature::status_from_code(u32) -> SignatureStatus`
  - `signature::verify(path: &Path) -> SignatureInfo`（離線、不做撤銷檢查；只驗證內嵌 Authenticode）
  - `signature::is_microsoft_signed(path: &Path) -> bool`（`Valid` 且簽章者含 `Microsoft`）

- [ ] **Step 1: 寫失敗測試 `tests/signature.rs`**

```rust
use msu_inspector::core::model::SignatureStatus;
use msu_inspector::core::signature::{is_microsoft_signed, status_from_code, verify};
use msu_inspector::core::sys;

#[test]
fn maps_trust_codes() {
    assert_eq!(status_from_code(0), SignatureStatus::Valid);
    assert_eq!(status_from_code(0x800B_0100), SignatureStatus::Unsigned);
    assert_eq!(status_from_code(0x800B_0003), SignatureStatus::Unsigned);
    assert_eq!(status_from_code(0x8009_6010), SignatureStatus::Invalid);
}

#[test]
fn unsigned_file_is_unsigned() {
    let t = tempfile::tempdir().unwrap();
    let p = t.path().join("x.msu");
    std::fs::write(&p, b"MSCF not signed").unwrap();
    let info = verify(&p);
    assert_eq!(info.status, SignatureStatus::Unsigned);
    assert_eq!(info.signer, None);
    assert!(!is_microsoft_signed(&p));
}

#[test]
fn embedded_microsoft_signature_is_valid() {
    // MpSigStub.exe 使用內嵌 Authenticode（多數系統檔只有目錄簽章）
    let p = sys::windows_dir().join("System32").join("MpSigStub.exe");
    if !p.exists() {
        eprintln!("skipping: {} not present", p.display());
        return;
    }
    let info = verify(&p);
    assert_eq!(info.status, SignatureStatus::Valid);
    assert!(info.signer.as_deref().unwrap_or("").contains("Microsoft"), "{info:?}");
    assert!(is_microsoft_signed(&p));
}

#[test]
fn missing_file_is_not_valid() {
    assert_ne!(verify(std::path::Path::new("Z:\\no\\such.msu")).status, SignatureStatus::Valid);
}
```

- [ ] **Step 2: 執行測試確認失敗**

Run: `cargo test --test signature`
Expected: 編譯失敗

- [ ] **Step 3: 實作 `src/core/signature.rs`**

```rust
//! Authenticode 驗證（WinVerifyTrust），沿用 code-signer 的作法；離線、不查撤銷。

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Foundation::HWND;
use windows::Win32::Security::Cryptography::{CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE};
use windows::Win32::Security::WinTrust::*;

use super::model::{SignatureInfo, SignatureStatus};

pub fn status_from_code(code: u32) -> SignatureStatus {
    match code {
        0 => SignatureStatus::Valid,
        // TRUST_E_NOSIGNATURE、TRUST_E_SUBJECT_FORM_UNKNOWN、TRUST_E_PROVIDER_UNKNOWN
        0x800B_0100 | 0x800B_0003 | 0x800B_0001 => SignatureStatus::Unsigned,
        _ => SignatureStatus::Invalid,
    }
}

pub fn verify(path: &Path) -> SignatureInfo {
    let wpath: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wpath.as_ptr()),
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_REVOCATION_CHECK_NONE,
        ..Default::default()
    };
    data.Anonymous.pFile = &mut file_info;
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let no_ui = HWND(-1isize as *mut c_void);
    // SAFETY: data / file_info / wpath 在兩次呼叫期間有效；狀態資料在 CLOSE 時釋放。
    unsafe {
        let code = WinVerifyTrust(no_ui, &mut action, &mut data as *mut _ as *mut c_void) as u32;
        let status = status_from_code(code);
        let signer = if status == SignatureStatus::Valid {
            signer_name(data.hWVTStateData)
        } else {
            None
        };
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(no_ui, &mut action, &mut data as *mut _ as *mut c_void);
        SignatureInfo { status, signer }
    }
}

/// SAFETY: `state` 必須是 VERIFY 之後、CLOSE 之前的狀態控制代碼。
unsafe fn signer_name(state: windows::Win32::Foundation::HANDLE) -> Option<String> {
    unsafe {
        let prov = WTHelperProvDataFromStateData(state);
        if prov.is_null() {
            return None;
        }
        let sgnr = WTHelperGetProvSignerFromChain(prov, 0, false, 0);
        if sgnr.is_null() {
            return None;
        }
        let pc = WTHelperGetProvCertFromChain(sgnr, 0);
        if pc.is_null() || (*pc).pCert.is_null() {
            return None;
        }
        let mut buf = [0u16; 256];
        let n = CertGetNameStringW((*pc).pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, Some(&mut buf));
        (n > 1).then(|| String::from_utf16_lossy(&buf[..n as usize - 1]))
    }
}

pub fn is_microsoft_signed(path: &Path) -> bool {
    let info = verify(path);
    info.status == SignatureStatus::Valid
        && info.signer.as_deref().is_some_and(|s| s.contains("Microsoft"))
}
```

`src/core/mod.rs` 加入 `pub mod signature;`。

- [ ] **Step 4: 執行測試確認通過**

Run: `cargo test --test signature`
Expected: 全部 PASS

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: verify Authenticode signatures of update packages

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 11: 風險規則

**Files:**
- Create: `src/core/risk.rs`, `tests/risk.rs`
- Modify: `src/core/mod.rs`（加入 `pub mod risk;`）

**Interfaces:**
- Consumes: `model::*`、`i18n::Lang`
- Produces:
  - `risk::Rule { id: &'static str, level: Risk, zh: &'static str, en: &'static str }`、`risk::RULES: &[Rule]`
  - `risk::rule(id: &str) -> Option<&'static Rule>`、`Rule::reason(&self, lang: Lang) -> &'static str`
  - `risk::base_level(ActionKind) -> Risk`
  - `risk::evaluate(comp: &Component, action: &Action) -> Vec<&'static str>`
  - `risk::apply(report: &mut AnalysisReport)`：填入每個 `Action.risk` 與 `Action.rules`

規則（每條都附理由，命中的 ID 記在 `Action.rules`）：

| ID | 等級 | 條件 |
|---|---|---|
| `DRV_BOOT_START` | High | 驅動 `start` 為 `boot` / `system` |
| `DRV_BOOT_CRITICAL` | High | 驅動 `boot_critical` |
| `CMD_GENERIC` | High | `generic_command` 且 `runs_on_install` |
| `AI_BOOT` | High | 進階安裝程式 `bfsvc` / `SecureBoot` / `fveUpdateAI` |
| `REG_AUTOSTART` | High | 自動啟動 / 登入相關登錄位置 |
| `REG_SECURITY` | High | LSA、驗證、認證提供者等 |
| `FW_INBOUND_ALLOW` | High | 防火牆 `direction` = in 且 `action` = allow |
| `SVC_NEW` | High | 服務且本機比對為 `new` |
| `SVC_CHANGED` | High | 服務且本機比對為 `replace` |
| `TASK_NEW` | High | 排程工作且本機比對為 `new` |
| `AI_CUSTOM` | Medium | 其餘進階安裝程式 |
| `FW_RULE` | Medium | 其餘防火牆規則 |
| `TASK_DEFINED` | Medium | 排程工作（非 new） |
| `WMI_MOF` | Medium | MOF |
| `COM_REGISTRATION` | Medium | `...\CLSID\{...}\InprocServer32|LocalServer32` |
| `PE_SYSTEM` | Medium | PE 檔寫入 System32 / drivers |
| `DRV_FILE` | Medium | 只有 `.sys` 檔的驅動 |
| `UNKNOWN_ELEMENT` | Medium | 未辨識元素 |
| `SVC_DEFINED` | Low | 服務（非 new / replace） |
| `UNCHANGED_COMPONENT` | Info | 元件在本機存放區已是同版本：整個元件的動作都降為 Info |

- [ ] **Step 1: 寫失敗測試 `tests/risk.rs`**

```rust
use msu_inspector::core::model::*;
use msu_inspector::core::risk::{self, apply, evaluate, RULES};
use msu_inspector::i18n::Lang;

fn comp(actions: Vec<ActionDetail>) -> Component {
    Component {
        identity: AssemblyIdentity {
            name: "c".into(),
            version: "10.0.26100.1".into(),
            ..Default::default()
        },
        actions: actions.into_iter().map(Action::new).collect(),
        ..Default::default()
    }
}

fn reg(key: &str, value: &str) -> ActionDetail {
    ActionDetail::Registry(RegistryAction {
        key: key.into(),
        value_name: Some(value.into()),
        operation: "replace".into(),
        ..Default::default()
    })
}

fn rules_of(detail: ActionDetail) -> Vec<&'static str> {
    let c = comp(vec![detail]);
    evaluate(&c, &c.actions[0])
}

#[test]
fn every_rule_has_both_reasons_and_unique_id() {
    let mut ids: Vec<&str> = RULES.iter().map(|r| r.id).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), RULES.len());
    for r in RULES {
        assert!(!r.zh.is_empty() && !r.en.is_empty(), "{}", r.id);
        assert_eq!(risk::rule(r.id).unwrap().reason(Lang::En), r.en);
    }
}

#[test]
fn flags_boot_drivers() {
    let d = ActionDetail::Driver(DriverAction {
        name: "acpiex".into(),
        start: Some("boot".into()),
        boot_critical: true,
        origin: "service".into(),
        ..Default::default()
    });
    assert_eq!(rules_of(d), vec!["DRV_BOOT_START", "DRV_BOOT_CRITICAL"]);
    let f = ActionDetail::Driver(DriverAction {
        name: "x".into(),
        origin: "file".into(),
        ..Default::default()
    });
    assert_eq!(rules_of(f), vec!["DRV_FILE"]);
}

#[test]
fn flags_registry_locations() {
    assert_eq!(
        rules_of(reg("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "x")),
        vec!["REG_AUTOSTART"]
    );
    assert_eq!(
        rules_of(reg("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager", "BootExecute")),
        vec!["REG_AUTOSTART"]
    );
    assert!(rules_of(reg("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager", "Other")).is_empty());
    assert_eq!(
        rules_of(reg("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa", "Security Packages")),
        vec!["REG_SECURITY"]
    );
    assert_eq!(
        rules_of(reg("HKEY_CLASSES_ROOT\\CLSID\\{11111111-2222-3333-4444-555555555555}\\InprocServer32", "")),
        vec!["COM_REGISTRATION"]
    );
    assert!(rules_of(reg("HKEY_LOCAL_MACHINE\\SOFTWARE\\Contoso", "x")).is_empty());
}

#[test]
fn flags_commands_firewall_and_installers() {
    let cmd = |install| ActionDetail::GenericCommand(CommandAction {
        executable: "x.exe".into(),
        arguments: None,
        runs_on_install: install,
    });
    assert_eq!(rules_of(cmd(true)), vec!["CMD_GENERIC"]);
    assert!(rules_of(cmd(false)).is_empty());
    let fw = |dir: &str, act: &str| ActionDetail::FirewallRule(FirewallAction {
        name: "r".into(),
        direction: Some(dir.into()),
        action: Some(act.into()),
        origin: "element".into(),
        ..Default::default()
    });
    assert_eq!(rules_of(fw("In", "Allow")), vec!["FW_INBOUND_ALLOW"]);
    assert_eq!(rules_of(fw("Out", "Allow")), vec!["FW_RULE"]);
    let ai = |e: &str| ActionDetail::AdvancedInstaller(AdvancedInstallerAction {
        element: e.into(),
        attributes: Default::default(),
    });
    assert_eq!(rules_of(ai("bfsvc")), vec!["AI_BOOT"]);
    assert_eq!(rules_of(ai("HTTPAI")), vec!["AI_CUSTOM"]);
}

#[test]
fn service_and_task_rules_depend_on_local_state() {
    let mut c = comp(vec![ActionDetail::Service(ServiceAction {
        name: "s".into(),
        ..Default::default()
    })]);
    assert_eq!(evaluate(&c, &c.actions[0]), vec!["SVC_DEFINED"]);
    c.actions[0].local = Some(LocalStatus { state: LocalState::New, current: None, incoming: None });
    assert_eq!(evaluate(&c, &c.actions[0]), vec!["SVC_NEW"]);
    c.actions[0].local = Some(LocalStatus { state: LocalState::Replace, current: None, incoming: None });
    assert_eq!(evaluate(&c, &c.actions[0]), vec!["SVC_CHANGED"]);

    let mut t = comp(vec![ActionDetail::ScheduledTask(TaskAction::default())]);
    assert_eq!(evaluate(&t, &t.actions[0]), vec!["TASK_DEFINED"]);
    t.actions[0].local = Some(LocalStatus { state: LocalState::New, current: None, incoming: None });
    assert_eq!(evaluate(&t, &t.actions[0]), vec!["TASK_NEW"]);
}

#[test]
fn apply_sets_levels_and_unchanged_components_become_info() {
    let pe = ActionDetail::File(FileAction {
        name: "k.dll".into(),
        destination: "$(runtime.system32)\\".into(),
        is_pe: true,
        ..Default::default()
    });
    let txt = ActionDetail::File(FileAction {
        name: "a.txt".into(),
        destination: "$(runtime.windows)\\".into(),
        ..Default::default()
    });
    let etw = ActionDetail::EtwEventlog(EtwAction { provider: "p".into(), guid: None });
    let mut report = AnalysisReport {
        components: vec![comp(vec![pe.clone(), txt, etw]), comp(vec![pe])],
        ..Default::default()
    };
    report.components[1].local = Some(LocalStatus {
        state: LocalState::InStoreSame,
        current: Some("10.0.26100.1".into()),
        incoming: Some("10.0.26100.1".into()),
    });
    apply(&mut report);
    let a = &report.components[0].actions;
    assert_eq!((a[0].risk, a[0].rules.clone()), (Risk::Medium, vec!["PE_SYSTEM"]));
    assert_eq!((a[1].risk, a[1].rules.is_empty()), (Risk::Low, true));
    assert_eq!(a[2].risk, Risk::Info);
    let b = &report.components[1].actions[0];
    assert_eq!((b.risk, b.rules.clone()), (Risk::Info, vec!["UNCHANGED_COMPONENT"]));
}
```

- [ ] **Step 2: 執行測試確認失敗**

Run: `cargo test --test risk`
Expected: 編譯失敗

- [ ] **Step 3: 實作 `src/core/risk.rs`**

```rust
//! 風險規則：每條規則有 ID、等級與中英文理由；命中的 ID 記在 `Action.rules`。

use super::model::*;
use crate::i18n::Lang;

pub struct Rule {
    pub id: &'static str,
    pub level: Risk,
    pub zh: &'static str,
    pub en: &'static str,
}

impl Rule {
    pub fn reason(&self, lang: Lang) -> &'static str {
        match lang {
            Lang::ZhTw => self.zh,
            Lang::En => self.en,
        }
    }
}

macro_rules! rule {
    ($id:literal, $level:ident, $zh:literal, $en:literal) => {
        Rule { id: $id, level: Risk::$level, zh: $zh, en: $en }
    };
}

pub const RULES: &[Rule] = &[
    rule!("DRV_BOOT_START", High, "在開機或系統啟動階段載入的驅動程式", "Driver loaded at boot or system start"),
    rule!("DRV_BOOT_CRITICAL", High, "列為 BootCritical 的驅動程式，失敗可能導致無法開機", "BootCritical driver; a failure can prevent booting"),
    rule!("CMD_GENERIC", High, "安裝時執行外部程式（genericCommand）", "Runs an external program during installation (genericCommand)"),
    rule!("AI_BOOT", High, "更新開機管理程式、開機檔案或 Secure Boot 設定", "Updates the boot manager, boot files or Secure Boot configuration"),
    rule!("REG_AUTOSTART", High, "寫入自動啟動或登入流程相關的登錄位置", "Writes an autostart or logon-related registry location"),
    rule!("REG_SECURITY", High, "修改 LSA、驗證或認證提供者等安全性設定", "Changes LSA, authentication or credential provider settings"),
    rule!("FW_INBOUND_ALLOW", High, "允許輸入連線的防火牆規則", "Firewall rule that allows inbound traffic"),
    rule!("SVC_NEW", High, "本機尚未存在的新服務", "New service that does not exist on this machine"),
    rule!("SVC_CHANGED", High, "變更現有服務的啟動類型、帳戶或映像路徑", "Changes an existing service's start type, account or image path"),
    rule!("TASK_NEW", High, "本機尚未存在的新排程工作", "New scheduled task that does not exist on this machine"),
    rule!("AI_CUSTOM", Medium, "安裝時由進階安裝程式執行自訂動作", "An advanced installer runs custom actions during installation"),
    rule!("FW_RULE", Medium, "防火牆規則", "Firewall rule"),
    rule!("TASK_DEFINED", Medium, "定義排程工作", "Defines a scheduled task"),
    rule!("WMI_MOF", Medium, "編譯並註冊 WMI MOF", "Compiles and registers a WMI MOF"),
    rule!("COM_REGISTRATION", Medium, "註冊 COM 伺服器", "Registers a COM server"),
    rule!("PE_SYSTEM", Medium, "替換 System32 或驅動程式資料夾中的可執行檔", "Replaces an executable in System32 or the drivers folder"),
    rule!("DRV_FILE", Medium, "安裝驅動程式檔案（.sys）", "Installs a driver file (.sys)"),
    rule!("UNKNOWN_ELEMENT", Medium, "未辨識的 manifest 元素，需要人工檢視", "Unrecognized manifest element; review manually"),
    rule!("SVC_DEFINED", Low, "定義服務設定", "Defines service configuration"),
    rule!("UNCHANGED_COMPONENT", Info, "本機元件存放區已有相同版本，此動作不會改變系統", "The same component version is already in the local store; no change"),
];

pub fn rule(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.id == id)
}

/// 沒有命中任何規則時的預設等級。
pub fn base_level(kind: ActionKind) -> Risk {
    match kind {
        ActionKind::EtwEventlog | ActionKind::Setting => Risk::Info,
        _ => Risk::Low,
    }
}

const AUTOSTART_KEYS: &[&str] = &[
    "\\currentversion\\run",
    "\\currentversion\\runonce",
    "\\currentversion\\winlogon",
    "\\image file execution options",
    "\\session manager\\knowndlls",
    "\\explorer\\shellserviceobjectdelayload",
    "\\active setup\\installed components",
    "\\appcertdlls",
];
const SESSION_MANAGER_VALUES: &[&str] = &["bootexecute", "setupexecute", "pendingfilerenameoperations"];
const APPINIT_VALUES: &[&str] = &["appinit_dlls", "loadappinit_dlls"];
const SECURITY_KEYS: &[&str] = &[
    "\\control\\lsa",
    "\\authentication\\credential providers",
    "\\authentication\\credential provider filters",
    "\\control\\securityproviders",
    "\\credentialsdelegation",
    "\\control\\cryptography\\configuration",
];
const BOOT_INSTALLERS: &[&str] = &["bfsvc", "secureboot", "fveupdateai"];

fn registry_rules(r: &RegistryAction, out: &mut Vec<&'static str>) {
    let key = r.key.to_ascii_lowercase();
    let value = r.value_name.as_deref().unwrap_or("").to_ascii_lowercase();
    let autostart = AUTOSTART_KEYS.iter().any(|k| key.contains(k))
        || (key.ends_with("\\control\\session manager") && SESSION_MANAGER_VALUES.contains(&value.as_str()))
        || (key.ends_with("\\windows nt\\currentversion\\windows") && APPINIT_VALUES.contains(&value.as_str()));
    if autostart {
        out.push("REG_AUTOSTART");
    }
    if SECURITY_KEYS.iter().any(|k| key.contains(k)) {
        out.push("REG_SECURITY");
    }
    if key.contains("\\clsid\\{") && (key.ends_with("\\inprocserver32") || key.ends_with("\\localserver32")) {
        out.push("COM_REGISTRATION");
    }
}

fn local_state(action: &Action) -> Option<LocalState> {
    action.local.as_ref().map(|l| l.state)
}

pub fn evaluate(comp: &Component, action: &Action) -> Vec<&'static str> {
    if comp.local.as_ref().is_some_and(|l| l.state == LocalState::InStoreSame) {
        return vec!["UNCHANGED_COMPONENT"];
    }
    let mut out = Vec::new();
    match &action.detail {
        ActionDetail::Driver(d) => {
            if d.start.as_deref().is_some_and(|s| s.eq_ignore_ascii_case("boot") || s.eq_ignore_ascii_case("system")) {
                out.push("DRV_BOOT_START");
            }
            if d.boot_critical {
                out.push("DRV_BOOT_CRITICAL");
            }
            if d.origin == "file" {
                out.push("DRV_FILE");
            }
        }
        ActionDetail::GenericCommand(c) if c.runs_on_install => out.push("CMD_GENERIC"),
        ActionDetail::AdvancedInstaller(a) => {
            if BOOT_INSTALLERS.contains(&a.element.to_ascii_lowercase().as_str()) {
                out.push("AI_BOOT");
            } else {
                out.push("AI_CUSTOM");
            }
        }
        ActionDetail::Registry(r) => registry_rules(r, &mut out),
        ActionDetail::FirewallRule(f) => {
            let inbound = f.direction.as_deref().is_some_and(|d| d.eq_ignore_ascii_case("in"));
            let allow = f.action.as_deref().is_some_and(|a| a.eq_ignore_ascii_case("allow"));
            out.push(if inbound && allow { "FW_INBOUND_ALLOW" } else { "FW_RULE" });
        }
        ActionDetail::Service(_) => out.push(match local_state(action) {
            Some(LocalState::New) => "SVC_NEW",
            Some(LocalState::Replace) => "SVC_CHANGED",
            _ => "SVC_DEFINED",
        }),
        ActionDetail::ScheduledTask(_) => out.push(match local_state(action) {
            Some(LocalState::New) => "TASK_NEW",
            _ => "TASK_DEFINED",
        }),
        ActionDetail::WmiMof(_) => out.push("WMI_MOF"),
        ActionDetail::File(f) => {
            let dest = f.destination.to_ascii_lowercase();
            if f.is_pe
                && (dest.contains("$(runtime.system32)") || dest.contains("$(runtime.drivers)") || dest.contains("\\system32\\"))
            {
                out.push("PE_SYSTEM");
            }
        }
        ActionDetail::Unknown(_) => out.push("UNKNOWN_ELEMENT"),
        _ => {}
    }
    out
}

pub fn apply(report: &mut AnalysisReport) {
    for comp in &mut report.components {
        let hits: Vec<Vec<&'static str>> = comp.actions.iter().map(|a| evaluate(comp, a)).collect();
        for (action, rules) in comp.actions.iter_mut().zip(hits) {
            let unchanged = rules == ["UNCHANGED_COMPONENT"];
            let from_rules = rules.iter().filter_map(|id| rule(id)).map(|r| r.level).max();
            action.risk = if unchanged {
                Risk::Info
            } else {
                from_rules.unwrap_or(Risk::Info).max(base_level(action.kind()))
            };
            action.rules = rules;
        }
    }
}
```

`src/core/mod.rs` 加入 `pub mod risk;`。

- [ ] **Step 4: 執行測試確認通過**

Run: `cargo test --test risk`
Expected: 全部 PASS

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: add rule-based risk evaluation with bilingual reasons

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 12: 本機比對（唯讀）

**Files:**
- Create: `src/core/local.rs`, `tests/local.rs`
- Modify: `src/core/mod.rs`（加入 `pub mod local;`）, `src/core/sys.rs`（加入 `is_elevated`）

**Interfaces:**
- Consumes: `model::*`、`parse_version`、`Ctx`、`Progress`、`sys::windows_dir`、`sys::native_arch`
- Produces:
  - `sys::is_elevated() -> bool`
  - `local::LocalEnv { windows: PathBuf, arch: String, build: u32, ubr: u32, store: Store }`、`LocalEnv::detect() -> Result<Self, CoreError>`、`os_build() -> String`
  - `local::Store::{from_names, load, versions(&AssemblyIdentity) -> Vec<[u32;4]>, len}`、`local::keyform_matches(short, full) -> bool`
  - `local::resolve_path(dest: &str, windows: &Path, wow32: bool) -> Option<PathBuf>`
  - `local::file_version(&Path) -> Option<String>`、`local::compare_versions(current: Option<&str>, incoming: &str) -> LocalState`
  - `local::RegValue`（`render()`、`as_u64()`）、`local::read_reg_value(key_name: &str, value: &str, wow32: bool) -> Option<RegValue>`、`local::same_value(value_type: &str, incoming: &str, current: &RegValue) -> bool`
  - `local::ServiceSnapshot { start, account, image }`、`local::read_service(name) -> Option<ServiceSnapshot>`、`local::service_matches(incoming, current, windows: &Path) -> bool`
  - `local::compare_file`、`compare_registry`、`compare_service`、`compare_task`、`compare_component`（皆回傳 `LocalStatus`）
  - `local::servicing_base(u32) -> u32`、`local::target_build(&[Component]) -> Option<u32>`、`local::applicability(report, arch, build) -> (bool, Option<&'static str>)`
  - `local::compare(report: &mut AnalysisReport, env: &LocalEnv, ctx: &Ctx) -> Result<(), CoreError>`：設定 `mode = StaticLocal`、`local_context`、各元件與動作的 `local`

- [ ] **Step 1: 寫失敗測試 `tests/local.rs`**

```rust
use std::path::PathBuf;

use msu_inspector::core::local::*;
use msu_inspector::core::model::*;
use msu_inspector::core::sys;

fn win() -> PathBuf {
    PathBuf::from(r"C:\Windows")
}

#[test]
fn resolves_runtime_variables() {
    assert_eq!(resolve_path("$(runtime.system32)\\", &win(), false), Some(PathBuf::from(r"C:\Windows\System32")));
    assert_eq!(resolve_path("$(runtime.system32)\\", &win(), true), Some(PathBuf::from(r"C:\Windows\SysWOW64")));
    assert_eq!(resolve_path("$(runtime.drivers)\\x", &win(), false), Some(PathBuf::from(r"C:\Windows\System32\drivers\x")));
    assert_eq!(resolve_path("$(runtime.programFiles)\\A", &win(), true), Some(PathBuf::from(r"C:\Program Files (x86)\A")));
    assert_eq!(resolve_path("$(runtime.nope)\\x", &win(), false), None);
    assert_eq!(resolve_path("relative\\x", &win(), false), None);
}

#[test]
fn compares_versions() {
    assert_eq!(compare_versions(None, "10.0.1.2"), LocalState::New);
    assert_eq!(compare_versions(Some("10.0.1.1"), "10.0.1.2"), LocalState::Replace);
    assert_eq!(compare_versions(Some("10.0.1.2"), "10.0.1.2"), LocalState::Same);
    assert_eq!(compare_versions(Some("10.0.1.3"), "10.0.1.2"), LocalState::Downgrade);
    assert_eq!(compare_versions(Some("?"), "10.0.1.2"), LocalState::Present);
}

#[test]
fn matches_truncated_keyform_names() {
    let full = "microsoft-windows-3daudio-hrtfdata-deployment";
    assert!(keyform_matches("microsoft-windows-3..hrtfdata-deployment", full));
    assert!(keyform_matches(full, full));
    assert!(!keyform_matches("microsoft-windows-4..hrtfdata-deployment", full));
    assert!(!keyform_matches("microsoft-windows-3daudio", full));
}

#[test]
fn store_lookup_by_identity() {
    let store = Store::from_names([
        "amd64_microsoft-windows-3..hrtfdata-deployment_31bf3856ad364e35_10.0.26100.1_none_22f425f17c681669.manifest",
        "amd64_microsoft-windows-3..hrtfdata-deployment_31bf3856ad364e35_10.0.26100.9_none_aaaaaaaaaaaaaaaa.manifest",
        "wow64_microsoft-windows-3..hrtfdata-deployment_31bf3856ad364e35_10.0.26100.9_none_bbbbbbbbbbbbbbbb.manifest",
        "garbage.manifest",
    ]);
    assert_eq!(store.len(), 3);
    let id = AssemblyIdentity {
        name: "Microsoft-Windows-3DAudio-HrtfData-Deployment".into(),
        version: "10.0.26100.9".into(),
        arch: "amd64".into(),
        language: "neutral".into(),
        public_key_token: "31bf3856ad364e35".into(),
    };
    let mut v = store.versions(&id);
    v.sort();
    assert_eq!(v, vec![[10, 0, 26100, 1], [10, 0, 26100, 9]]);
    assert_eq!(compare_component(&store, &id).state, LocalState::InStoreSame);
    let newer = AssemblyIdentity { version: "10.0.26100.20".into(), ..id.clone() };
    let s = compare_component(&store, &newer);
    assert_eq!((s.state, s.current.as_deref()), (LocalState::InStoreOlder, Some("10.0.26100.9")));
    let older = AssemblyIdentity { version: "10.0.26100.5".into(), ..id.clone() };
    assert_eq!(compare_component(&store, &older).state, LocalState::InStoreNewer);
    let other = AssemblyIdentity { name: "other".into(), ..id };
    assert_eq!(compare_component(&store, &other).state, LocalState::NotInStore);
}

#[test]
fn applicability_rules() {
    assert_eq!(servicing_base(26200), 26100);
    assert_eq!(servicing_base(22631), 22621);
    assert_eq!(servicing_base(19045), 19041);
    let comp = |v: &str| Component {
        identity: AssemblyIdentity { version: v.into(), ..Default::default() },
        ..Default::default()
    };
    let comps = vec![comp("10.0.26100.100"), comp("10.0.26100.101"), comp("10.0.22621.5"), comp("4.0.15920.1")];
    assert_eq!(target_build(&comps), Some(26100));
    let mut report = AnalysisReport { components: comps, ..Default::default() };
    report.package.identity.arch = "amd64".into();
    assert_eq!(applicability(&report, "amd64", 26200), (true, None));
    assert_eq!(applicability(&report, "arm64", 26100), (false, Some("arch_mismatch")));
    assert_eq!(applicability(&report, "amd64", 22631), (false, Some("build_mismatch")));
}

#[test]
fn compares_registry_values_by_type() {
    assert!(same_value("REG_DWORD", "0x00000001", &RegValue::Dword(1)));
    assert!(same_value("REG_DWORD", "1", &RegValue::Dword(1)));
    assert!(!same_value("REG_DWORD", "0x2", &RegValue::Dword(1)));
    assert!(same_value("REG_BINARY", "01 0A ff", &RegValue::Binary(vec![1, 10, 255])));
    assert!(same_value("REG_MULTI_SZ", "\"a\",\"b\"", &RegValue::MultiStr(vec!["a".into(), "b".into()])));
    assert!(same_value("REG_SZ", "x", &RegValue::Str("x".into())));
    assert!(!same_value("REG_SZ", "x", &RegValue::Str("X".into())));
    assert_eq!(RegValue::Dword(10).render(), "0x0000000a");
    assert_eq!(RegValue::MultiStr(vec!["a".into(), "b".into()]).render(), "\"a\",\"b\"");
}

#[test]
fn compares_services() {
    let w = win();
    let cur = ServiceSnapshot {
        start: Some("auto".into()),
        account: Some("LocalSystem".into()),
        image: Some(r"%SystemRoot%\System32\svchost.exe -k netsvcs -p".into()),
    };
    let same = ServiceSnapshot {
        start: Some("Auto".into()),
        account: Some("localsystem".into()),
        image: Some(r"C:\Windows\System32\svchost.exe -k netsvcs -p".into()),
    };
    assert!(service_matches(&same, &cur, &w));
    let partial = ServiceSnapshot { start: Some("auto".into()), account: None, image: None };
    assert!(service_matches(&partial, &cur, &w), "fields missing in the manifest are not compared");
    let changed = ServiceSnapshot { start: Some("demand".into()), ..same };
    assert!(!service_matches(&changed, &cur, &w));
}

// ---- 以下讀取本機實際狀態（唯讀）----

#[test]
fn detects_local_environment() {
    let env = LocalEnv::detect().unwrap();
    assert!(env.build >= 10240);
    assert_eq!(env.arch, sys::native_arch());
    assert!(env.store.len() > 1000);
    assert!(env.os_build().starts_with(&env.build.to_string()));
}

#[test]
fn reads_local_file_and_registry() {
    let kernel32 = sys::windows_dir().join("System32").join("kernel32.dll");
    let v = file_version(&kernel32).expect("kernel32 version");
    let f = FileAction {
        name: "kernel32.dll".into(),
        destination: "$(runtime.system32)\\".into(),
        is_pe: true,
        ..Default::default()
    };
    assert_eq!(compare_file(&f, &v, false, &sys::windows_dir()).state, LocalState::Same);
    let missing = FileAction { name: "no-such-file.dll".into(), ..f };
    assert_eq!(compare_file(&missing, &v, false, &sys::windows_dir()).state, LocalState::New);

    let key = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    assert!(read_reg_value(key, "CurrentBuildNumber", false).is_some());
    let r = RegistryAction {
        key: key.into(),
        value_name: Some("MsuInspectorNoSuchValue".into()),
        value_type: Some("REG_SZ".into()),
        data: Some("x".into()),
        operation: "replace".into(),
        ..Default::default()
    };
    assert_eq!(compare_registry(&r, false).state, LocalState::New);
    let key_only = RegistryAction { value_name: None, ..r.clone() };
    assert_eq!(compare_registry(&key_only, false).state, LocalState::Same);
    let hkcu = RegistryAction { key: r"HKEY_CURRENT_USER\Software".into(), ..r };
    assert_eq!(compare_registry(&hkcu, false).state, LocalState::UnknownPath);
}

#[test]
fn reads_services_and_tasks() {
    assert!(read_service("EventLog").is_some());
    let s = compare_service("msu-inspector-no-such-service", &ServiceSnapshot::default(), &sys::windows_dir());
    assert_eq!(s.state, LocalState::New);
    assert_eq!(compare_task(r"\Microsoft\Windows\NoSuchTask-msu", &sys::windows_dir()).state, LocalState::New);
}

#[test]
fn first_store_entry_is_same() {
    let env = LocalEnv::detect().unwrap();
    let name = std::fs::read_dir(env.windows.join("WinSxS").join("Manifests"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .find(|n| n.starts_with(&format!("{}_microsoft-windows-", env.arch)) && !n.contains(".."))
        .unwrap();
    let parts: Vec<&str> = name.trim_end_matches(".manifest").split('_').collect();
    let n = parts.len();
    let id = AssemblyIdentity {
        name: parts[1..n - 4].join("_"),
        version: parts[n - 3].into(),
        arch: parts[0].into(),
        language: if parts[n - 2] == "none" { "neutral".into() } else { parts[n - 2].into() },
        public_key_token: parts[n - 4].into(),
    };
    assert_eq!(compare_component(&env.store, &id).state, LocalState::InStoreSame);
}
```

- [ ] **Step 2: 執行測試確認失敗**

Run: `cargo test --test local`
Expected: 編譯失敗

- [ ] **Step 3: 在 `src/core/sys.rs` 加入 `is_elevated`**

```rust
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// 目前程序是否以系統管理員（已提升權限）執行。
pub fn is_elevated() -> bool {
    // SAFETY: 權杖在函式結束前關閉。
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut std::ffi::c_void),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}
```

- [ ] **Step 4: 實作 `src/core/local.rs`**

```rust
//! 本機比對（唯讀）：檔案版本、元件存放區、登錄、服務、排程工作與適用性。

use std::collections::HashMap;
use std::ffi::c_void;
use std::path::{Path, PathBuf};

use windows::core::{w, HSTRING};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, VS_FIXEDFILEINFO,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
    KEY_WOW64_32KEY, KEY_WOW64_64KEY, REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ,
    REG_QWORD, REG_SZ, REG_VALUE_TYPE,
};

use super::model::*;
use super::progress::{Ctx, Progress};
use super::{sys, CoreError};

/// 比對結果中保留的字串長度上限（避免 REG_BINARY 塞爆 JSON）。
const MAX_SHOWN: usize = 512;

fn clip(s: &str) -> String {
    if s.len() <= MAX_SHOWN {
        return s.to_string();
    }
    let mut end = MAX_SHOWN;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

fn fmt_version(v: [u32; 4]) -> String {
    format!("{}.{}.{}.{}", v[0], v[1], v[2], v[3])
}

fn status(state: LocalState, current: Option<String>, incoming: Option<String>) -> LocalStatus {
    LocalStatus { state, current, incoming }
}

// ---------------- 環境 ----------------

pub struct LocalEnv {
    pub windows: PathBuf,
    pub arch: String,
    pub build: u32,
    pub ubr: u32,
    pub store: Store,
}

impl LocalEnv {
    pub fn detect() -> Result<Self, CoreError> {
        let windows = sys::windows_dir();
        let cv = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
        let build = read_reg_value(cv, "CurrentBuildNumber", false)
            .and_then(|v| v.render().trim().parse().ok())
            .ok_or_else(|| CoreError::Win32("cannot read CurrentBuildNumber".into()))?;
        let ubr = read_reg_value(cv, "UBR", false)
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let store = Store::load(&windows)?;
        Ok(LocalEnv {
            windows,
            arch: sys::native_arch().to_string(),
            build,
            ubr,
            store,
        })
    }

    pub fn os_build(&self) -> String {
        format!("{}.{}", self.build, self.ubr)
    }
}

// ---------------- 元件存放區 ----------------

/// `WinSxS\Manifests` 的檔名索引：(架構, token, 語系) → [(短名稱, 版本)]。
pub struct Store {
    entries: HashMap<(String, String, String), Vec<(String, [u32; 4])>>,
    count: usize,
}

impl Store {
    /// keyform：`arch_短名稱_token_版本_語系_雜湊`；短名稱本身可能含 `_`，所以從兩端切。
    pub fn from_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Self {
        let mut entries: HashMap<(String, String, String), Vec<(String, [u32; 4])>> = HashMap::new();
        let mut count = 0;
        for n in names {
            let n = n.to_ascii_lowercase();
            let n = n.strip_suffix(".manifest").unwrap_or(&n);
            let parts: Vec<&str> = n.split('_').collect();
            let len = parts.len();
            if len < 6 {
                continue;
            }
            let Some(ver) = parse_version(parts[len - 3]) else {
                continue;
            };
            let key = (parts[0].to_string(), parts[len - 4].to_string(), parts[len - 2].to_string());
            entries.entry(key).or_default().push((parts[1..len - 4].join("_"), ver));
            count += 1;
        }
        Store { entries, count }
    }

    pub fn load(windows: &Path) -> Result<Self, CoreError> {
        let dir = windows.join("WinSxS").join("Manifests");
        let names: Vec<String> = std::fs::read_dir(&dir)
            .map_err(|e| CoreError::io(&dir, e))?
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        Ok(Store::from_names(names.iter().map(String::as_str)))
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn versions(&self, id: &AssemblyIdentity) -> Vec<[u32; 4]> {
        let lang = if id.language.is_empty() || id.language.eq_ignore_ascii_case("neutral") {
            "none".to_string()
        } else {
            id.language.to_ascii_lowercase()
        };
        let key = (id.arch.to_ascii_lowercase(), id.public_key_token.to_ascii_lowercase(), lang);
        let name = id.name.to_ascii_lowercase();
        self.entries
            .get(&key)
            .map(|list| {
                list.iter()
                    .filter(|(short, _)| keyform_matches(short, &name))
                    .map(|(_, v)| *v)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// 長名稱在 keyform 中會截成 `前綴..後綴`。
pub fn keyform_matches(short: &str, full: &str) -> bool {
    match short.split_once("..") {
        None => short == full,
        Some((pre, suf)) => {
            full.len() >= pre.len() + suf.len() && full.starts_with(pre) && full.ends_with(suf)
        }
    }
}

pub fn compare_component(store: &Store, id: &AssemblyIdentity) -> LocalStatus {
    let versions = store.versions(id);
    let max = versions.iter().max().copied();
    let state = match (parse_version(&id.version), max) {
        (Some(inc), Some(_)) if versions.contains(&inc) => LocalState::InStoreSame,
        (Some(inc), Some(m)) if m < inc => LocalState::InStoreOlder,
        (Some(_), Some(_)) => LocalState::InStoreNewer,
        _ => LocalState::NotInStore,
    };
    status(state, max.map(fmt_version), Some(id.version.clone()))
}

// ---------------- 檔案 ----------------

/// 把 manifest 的 `$(runtime.xxx)` 目的路徑轉成本機路徑；無法對應時回傳 None。
pub fn resolve_path(dest: &str, windows: &Path, wow32: bool) -> Option<PathBuf> {
    let rest = dest.strip_prefix("$(")?;
    let end = rest.find(')')?;
    let var = rest[..end].to_ascii_lowercase();
    let tail = rest[end + 1..].trim_start_matches('\\');
    let win = windows.to_string_lossy();
    let drive = PathBuf::from(format!("{}\\", win.get(..2)?));
    let program_files = if wow32 { "Program Files (x86)" } else { "Program Files" };
    let sys32 = windows.join(if wow32 { "SysWOW64" } else { "System32" });
    let base = match var.as_str() {
        "runtime.system32" | "runtime.system" => sys32,
        "runtime.windows" | "runtime.systemroot" => windows.to_path_buf(),
        "runtime.drivers" => windows.join("System32").join("drivers"),
        "runtime.wbem" => sys32.join("wbem"),
        "runtime.fonts" => windows.join("Fonts"),
        "runtime.inf" => windows.join("INF"),
        "runtime.help" => windows.join("Help"),
        "runtime.bootdrive" | "runtime.systemdrive" => drive,
        "runtime.programfiles" => drive.join(program_files),
        "runtime.programfilesx86" => drive.join("Program Files (x86)"),
        "runtime.commonfiles" => drive.join(program_files).join("Common Files"),
        "runtime.programdata" => drive.join("ProgramData"),
        _ => return None,
    };
    Some(if tail.is_empty() { base } else { base.join(tail) })
}

pub fn file_version(path: &Path) -> Option<String> {
    let name = HSTRING::from(path.as_os_str());
    // SAFETY: 緩衝區大小由 GetFileVersionInfoSizeW 決定；VerQueryValueW 回傳的指標指向該緩衝區。
    unsafe {
        let size = GetFileVersionInfoSizeW(&name, None);
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        GetFileVersionInfoW(&name, None, size, buf.as_mut_ptr().cast()).ok()?;
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let mut len = 0u32;
        if !VerQueryValueW(buf.as_ptr().cast(), w!("\\"), &mut ptr, &mut len).as_bool() || ptr.is_null() {
            return None;
        }
        let info = &*(ptr as *const VS_FIXEDFILEINFO);
        Some(format!(
            "{}.{}.{}.{}",
            info.dwFileVersionMS >> 16,
            info.dwFileVersionMS & 0xFFFF,
            info.dwFileVersionLS >> 16,
            info.dwFileVersionLS & 0xFFFF
        ))
    }
}

pub fn compare_versions(current: Option<&str>, incoming: &str) -> LocalState {
    let Some(cur) = current else {
        return LocalState::New;
    };
    match (parse_version(cur), parse_version(incoming)) {
        (Some(c), Some(i)) if c < i => LocalState::Replace,
        (Some(c), Some(i)) if c == i => LocalState::Same,
        (Some(_), Some(_)) => LocalState::Downgrade,
        _ => LocalState::Present,
    }
}

/// 檔案沒有個別版本欄位，`incoming` 用所屬元件版本。
pub fn compare_file(f: &FileAction, component_version: &str, wow32: bool, windows: &Path) -> LocalStatus {
    let Some(dir) = resolve_path(&f.destination, windows, wow32) else {
        return status(LocalState::UnknownPath, None, None);
    };
    let path = dir.join(&f.name);
    if !path.exists() {
        return status(LocalState::New, None, Some(component_version.to_string()));
    }
    if !f.is_pe {
        return status(LocalState::Present, None, None);
    }
    let current = file_version(&path);
    let state = compare_versions(current.as_deref(), component_version);
    let state = if current.is_none() { LocalState::Present } else { state };
    status(state, current, Some(component_version.to_string()))
}

// ---------------- 登錄 ----------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegValue {
    Str(String),
    MultiStr(Vec<String>),
    Dword(u32),
    Qword(u64),
    Binary(Vec<u8>),
    Other(u32, Vec<u8>),
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

impl RegValue {
    /// 與 manifest 相同的表示法：DWORD 為 `0x%08x`、MULTI_SZ 為 `"a","b"`、二進位為大寫十六進位。
    pub fn render(&self) -> String {
        match self {
            RegValue::Str(s) => s.clone(),
            RegValue::MultiStr(v) => v.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(","),
            RegValue::Dword(d) => format!("0x{d:08x}"),
            RegValue::Qword(q) => format!("0x{q:016x}"),
            RegValue::Binary(b) | RegValue::Other(_, b) => hex(b),
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            RegValue::Dword(d) => Some(*d as u64),
            RegValue::Qword(q) => Some(*q),
            _ => None,
        }
    }
}

fn utf16_units(buf: &[u8]) -> Vec<u16> {
    buf.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect()
}

fn decode_reg(ty: REG_VALUE_TYPE, buf: &[u8]) -> RegValue {
    match ty {
        REG_SZ | REG_EXPAND_SZ => {
            let u = utf16_units(buf);
            let end = u.iter().position(|&c| c == 0).unwrap_or(u.len());
            RegValue::Str(String::from_utf16_lossy(&u[..end]))
        }
        REG_MULTI_SZ => RegValue::MultiStr(
            String::from_utf16_lossy(&utf16_units(buf))
                .split('\0')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
        ),
        REG_DWORD if buf.len() >= 4 => RegValue::Dword(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])),
        REG_QWORD if buf.len() >= 8 => {
            RegValue::Qword(u64::from_le_bytes(buf[..8].try_into().unwrap_or_default()))
        }
        REG_BINARY => RegValue::Binary(buf.to_vec()),
        other => RegValue::Other(other.0, buf.to_vec()),
    }
}

/// `HKEY_LOCAL_MACHINE\...` / `HKEY_CLASSES_ROOT\...` → (根機碼, 子機碼)；其他根（例如 HKCU）無法對應。
fn split_root(key: &str) -> Option<(HKEY, String)> {
    let lower = key.to_ascii_lowercase();
    if lower.starts_with("hkey_local_machine\\") {
        Some((HKEY_LOCAL_MACHINE, key["hkey_local_machine\\".len()..].to_string()))
    } else if lower.starts_with("hkey_classes_root\\") {
        Some((HKEY_LOCAL_MACHINE, format!("SOFTWARE\\Classes\\{}", &key["hkey_classes_root\\".len()..])))
    } else {
        None
    }
}

fn open_key(key_name: &str, wow32: bool) -> Option<HKEY> {
    let (root, sub) = split_root(key_name)?;
    let access = KEY_READ | if wow32 { KEY_WOW64_32KEY } else { KEY_WOW64_64KEY };
    let mut hkey = HKEY::default();
    // SAFETY: 成功時由呼叫端以 RegCloseKey 關閉。
    let r = unsafe { RegOpenKeyExW(root, &HSTRING::from(sub), Some(0), access, &mut hkey) };
    (r == ERROR_SUCCESS).then_some(hkey)
}

pub fn read_reg_value(key_name: &str, value: &str, wow32: bool) -> Option<RegValue> {
    let hkey = open_key(key_name, wow32)?;
    let name = HSTRING::from(value);
    // SAFETY: 兩段式查詢：先取大小再讀取。
    unsafe {
        let mut ty = REG_VALUE_TYPE::default();
        let mut len = 0u32;
        let mut result = RegQueryValueExW(hkey, &name, None, Some(&mut ty), None, Some(&mut len));
        let mut buf = vec![0u8; len as usize];
        if result == ERROR_SUCCESS {
            result = RegQueryValueExW(hkey, &name, None, Some(&mut ty), Some(buf.as_mut_ptr()), Some(&mut len));
        }
        let _ = RegCloseKey(hkey);
        if result != ERROR_SUCCESS {
            return None;
        }
        buf.truncate(len as usize);
        Some(decode_reg(ty, &buf))
    }
}

fn key_exists(key_name: &str, wow32: bool) -> Option<bool> {
    split_root(key_name)?;
    Some(match open_key(key_name, wow32) {
        Some(h) => {
            // SAFETY: h 由 open_key 開啟。
            unsafe {
                let _ = RegCloseKey(h);
            }
            true
        }
        None => false,
    })
}

fn parse_number(s: &str) -> Option<u64> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

fn parse_multi(s: &str) -> Vec<String> {
    s.split("\",\"")
        .map(|p| p.trim().trim_matches('"').to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

pub fn same_value(value_type: &str, incoming: &str, current: &RegValue) -> bool {
    match value_type.to_ascii_uppercase().as_str() {
        "REG_DWORD" | "REG_QWORD" => parse_number(incoming).is_some_and(|n| current.as_u64() == Some(n)),
        "REG_BINARY" => {
            let want: String = incoming.chars().filter(char::is_ascii_hexdigit).collect::<String>().to_ascii_uppercase();
            want == current.render()
        }
        "REG_MULTI_SZ" => match current {
            RegValue::MultiStr(v) => parse_multi(incoming) == *v,
            _ => false,
        },
        _ => matches!(current, RegValue::Str(s) if s == incoming),
    }
}

pub fn compare_registry(r: &RegistryAction, wow32: bool) -> LocalStatus {
    let Some(value) = &r.value_name else {
        return match key_exists(&r.key, wow32) {
            None => status(LocalState::UnknownPath, None, None),
            Some(true) => status(LocalState::Same, None, None),
            Some(false) => status(LocalState::New, None, None),
        };
    };
    if split_root(&r.key).is_none() {
        return status(LocalState::UnknownPath, None, None);
    }
    let incoming = r.data.as_deref().map(clip);
    match read_reg_value(&r.key, value, wow32) {
        None => status(LocalState::New, None, incoming),
        Some(cur) => {
            let same = r
                .data
                .as_deref()
                .is_none_or(|d| same_value(r.value_type.as_deref().unwrap_or("REG_SZ"), d, &cur));
            let state = if same { LocalState::Same } else { LocalState::Replace };
            status(state, Some(clip(&cur.render())), incoming)
        }
    }
}

// ---------------- 服務與排程工作 ----------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceSnapshot {
    pub start: Option<String>,
    pub account: Option<String>,
    pub image: Option<String>,
}

impl ServiceSnapshot {
    fn describe(&self) -> String {
        format!(
            "start={}; account={}; image={}",
            self.start.as_deref().unwrap_or("-"),
            self.account.as_deref().unwrap_or("-"),
            self.image.as_deref().unwrap_or("-")
        )
    }
}

pub fn read_service(name: &str) -> Option<ServiceSnapshot> {
    let key = format!(r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{name}");
    let start = read_reg_value(&key, "Start", false)?.as_u64()?;
    let delayed = read_reg_value(&key, "DelayedAutostart", false).and_then(|v| v.as_u64()) == Some(1);
    let start = match (start, delayed) {
        (0, _) => "boot",
        (1, _) => "system",
        (2, true) => "delayedAuto",
        (2, false) => "auto",
        (3, _) => "demand",
        (4, _) => "disabled",
        _ => "unknown",
    };
    Some(ServiceSnapshot {
        start: Some(start.to_string()),
        account: read_reg_value(&key, "ObjectName", false).map(|v| v.render()),
        image: read_reg_value(&key, "ImagePath", false).map(|v| v.render()),
    })
}

fn normalize_image(image: &str, windows: &Path) -> String {
    let mut s = image.trim().trim_matches('"').to_ascii_lowercase();
    let win = format!("{}\\", windows.to_string_lossy().to_ascii_lowercase());
    for prefix in ["\\??\\", "%systemroot%\\", "%windir%\\", "\\systemroot\\", win.as_str()] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest.to_string();
        }
    }
    s
}

/// manifest 沒寫的欄位不比對。
pub fn service_matches(incoming: &ServiceSnapshot, current: &ServiceSnapshot, windows: &Path) -> bool {
    let eq = |a: &Option<String>, b: &Option<String>| match (a, b) {
        (None, _) => true,
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        (Some(_), None) => false,
    };
    let image_eq = match (&incoming.image, &current.image) {
        (None, _) => true,
        (Some(a), Some(b)) => normalize_image(a, windows) == normalize_image(b, windows),
        (Some(_), None) => false,
    };
    eq(&incoming.start, &current.start) && eq(&incoming.account, &current.account) && image_eq
}

pub fn compare_service(name: &str, incoming: &ServiceSnapshot, windows: &Path) -> LocalStatus {
    match read_service(name) {
        None => status(LocalState::New, None, Some(incoming.describe())),
        Some(cur) => {
            let state = if service_matches(incoming, &cur, windows) {
                LocalState::Same
            } else {
                LocalState::Replace
            };
            status(state, Some(cur.describe()), Some(incoming.describe()))
        }
    }
}

pub fn compare_task(uri: &str, windows: &Path) -> LocalStatus {
    let path = windows.join("System32").join("Tasks").join(uri.trim_start_matches('\\'));
    let state = if path.exists() { LocalState::Present } else { LocalState::New };
    status(state, None, None)
}

// ---------------- 適用性與整體流程 ----------------

/// 共用同一套服務元件的版本（例如 25H2 的 26200 使用 26100 的累積更新）。
pub fn servicing_base(build: u32) -> u32 {
    match build {
        19041..=19045 => 19041,
        22621 | 22631 => 22621,
        26100 | 26200 => 26100,
        b => b,
    }
}

/// 元件版本 `10.0.<build>.x` 中最常見的 build（忽略 .NET 等非 Windows 版本號）。
pub fn target_build(components: &[Component]) -> Option<u32> {
    let mut counts: HashMap<u32, usize> = HashMap::new();
    for c in components {
        if let Some(v) = parse_version(&c.identity.version) {
            if v[0] == 10 && v[1] == 0 && v[2] >= 10240 {
                *counts.entry(v[2]).or_default() += 1;
            }
        }
    }
    counts.into_iter().max_by_key(|&(b, n)| (n, b)).map(|(b, _)| b)
}

pub fn applicability(report: &AnalysisReport, arch: &str, build: u32) -> (bool, Option<&'static str>) {
    let pkg_arch = report.package.identity.arch.to_ascii_lowercase();
    if !pkg_arch.is_empty() && pkg_arch != "neutral" && pkg_arch != arch {
        return (false, Some("arch_mismatch"));
    }
    if let Some(t) = target_build(&report.components) {
        if servicing_base(t) != servicing_base(build) {
            return (false, Some("build_mismatch"));
        }
    }
    (true, None)
}

fn is_wow(component_arch: &str, native: &str) -> bool {
    let a = component_arch.to_ascii_lowercase();
    (a == "wow64" || a == "x86") && native != "x86"
}

fn compare_action(detail: &ActionDetail, version: &str, wow32: bool, env: &LocalEnv) -> Option<LocalStatus> {
    match detail {
        ActionDetail::File(f) => Some(compare_file(f, version, wow32, &env.windows)),
        ActionDetail::Registry(r) => Some(compare_registry(r, wow32)),
        ActionDetail::Service(s) => Some(compare_service(
            &s.name,
            &ServiceSnapshot {
                start: s.start.clone(),
                account: s.account.clone(),
                image: s.image_path.clone(),
            },
            &env.windows,
        )),
        ActionDetail::Driver(d) if d.origin == "service" => Some(compare_service(
            &d.name,
            &ServiceSnapshot {
                start: d.start.clone(),
                account: None,
                image: d.image_path.clone(),
            },
            &env.windows,
        )),
        ActionDetail::ScheduledTask(t) => Some(compare_task(&t.uri, &env.windows)),
        _ => None,
    }
}

pub fn compare(report: &mut AnalysisReport, env: &LocalEnv, ctx: &Ctx) -> Result<(), CoreError> {
    let (applicable, reason) = applicability(report, &env.arch, env.build);
    report.mode = Mode::StaticLocal;
    report.local_context = Some(LocalContext {
        os_build: env.os_build(),
        arch: env.arch.clone(),
        applicable,
        not_applicable_reason: reason.map(str::to_string),
    });
    let total = report.components.len();
    for (i, comp) in report.components.iter_mut().enumerate() {
        if i % 100 == 0 {
            ctx.check()?;
            ctx.report(Progress::Comparing { done: i, total });
        }
        comp.local = Some(compare_component(&env.store, &comp.identity));
        let wow32 = is_wow(&comp.identity.arch, &env.arch);
        let version = comp.identity.version.clone();
        for a in &mut comp.actions {
            a.local = compare_action(&a.detail, &version, wow32, env);
        }
    }
    ctx.report(Progress::Comparing { done: total, total });
    Ok(())
}
```

`src/core/mod.rs` 加入 `pub mod local;`。

- [ ] **Step 5: 執行測試確認通過**

Run: `cargo test --test local`
Expected: 全部 PASS

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: compare package actions against the local machine (read-only)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 13: 分析流程（analyze）

**Files:**
- Create: `src/core/analyze.rs`, `tests/analyze.rs`
- Modify: `src/core/mod.rs`（加入 `pub mod analyze;`）

**Interfaces:**
- Consumes: Task 2–12 全部公開函式
- Produces:
  - `analyze::AnalyzeOptions { compare_local: bool, temp_root: Option<PathBuf> }`（`Default`）
  - `analyze::analyze(path: &Path, opts: &AnalyzeOptions, ctx: &Ctx) -> Result<AnalysisReport, CoreError>`
  - `analyze::format_label(outer: Option<ContainerFormat>, file_name: &str, has_psf: bool) -> String`

- [ ] **Step 1: 寫失敗測試 `tests/analyze.rs`**

```rust
mod common;

use msu_inspector::core::analyze::{analyze, format_label, AnalyzeOptions};
use msu_inspector::core::delta::{DcmDecoder, DeltaEngine};
use msu_inspector::core::model::*;
use msu_inspector::core::progress::Ctx;
use msu_inspector::core::CoreError;

/// 建立一個模擬 LCU 的 .msu：外層 CAB → 內層 LZX CAB（rollup.mum + 純文字 manifest + DCM manifest + 壞掉的 manifest）。
fn build_msu(dir: &std::path::Path) -> std::path::PathBuf {
    let dcm = DcmDecoder::from_system().unwrap();
    let mut basic_dcm = b"DCM\x01".to_vec();
    basic_dcm.extend(
        DeltaEngine::system("msdelta.dll")
            .unwrap()
            .create(dcm.base(), common::fixture("basic.manifest").as_bytes())
            .unwrap(),
    );
    let inner = common::make_cab(
        dir,
        "Windows11.0-KB5129195-x64.cab",
        &[
            ("Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.9457.1.0.mum", common::fixture("rollup.mum").as_bytes()),
            ("amd64_test-actions_31bf3856ad364e35_10.0.26100.1742_none_0.manifest", common::fixture("actions.manifest").as_bytes()),
            ("amd64_appreadiness_31bf3856ad364e35_10.0.26100.1591_none_0.manifest", &basic_dcm),
            ("broken.manifest", b"<assembly"),
        ],
        true,
    );
    let props = common::utf16("KB Article Number=\"5129195\"\r\n");
    common::make_cab(
        dir,
        "Windows11.0-KB5129195-x64.msu",
        &[
            ("Windows11.0-KB5129195-x64.cab", &std::fs::read(inner).unwrap()),
            ("Windows11.0-KB5129195-x64-pkgProperties.txt", &props),
        ],
        false,
    )
}

#[test]
fn analyzes_synthetic_msu() {
    let t = tempfile::tempdir().unwrap();
    let msu = build_msu(t.path());
    let temp_root = t.path().join("temp");
    std::fs::create_dir_all(&temp_root).unwrap();
    let opts = AnalyzeOptions { compare_local: false, temp_root: Some(temp_root.clone()) };
    let r = analyze(&msu, &opts, &Ctx::silent()).unwrap();

    assert_eq!(r.mode, Mode::Static);
    assert!(r.local_context.is_none());
    assert_eq!(r.package.kb.as_deref(), Some("KB5129195"));
    assert_eq!(r.package.identity.name, "Package_for_RollupFix");
    assert_eq!(r.source.file, "Windows11.0-KB5129195-x64.msu");
    assert_eq!(r.source.format, "msu-cab");
    assert_eq!(r.source.sha256.len(), 64);
    assert_eq!(r.source.signature.status, SignatureStatus::Unsigned);

    let names: Vec<&str> = r.components.iter().map(|c| c.identity.name.as_str()).collect();
    assert_eq!(names, vec!["Microsoft-Windows-AppReadiness-Service", "Test-Actions"]);
    let codes: Vec<WarningCode> = r.warnings.iter().map(|w| w.code).collect();
    assert!(codes.contains(&WarningCode::SignatureNotValid));
    assert!(codes.contains(&WarningCode::ManifestParseFailed));

    let high: Vec<&Action> = r.components.iter().flat_map(|c| &c.actions).filter(|a| a.risk == Risk::High).collect();
    assert!(high.iter().any(|a| a.rules.contains(&"DRV_BOOT_START")));
    assert!(high.iter().any(|a| a.rules.contains(&"CMD_GENERIC")));

    assert_eq!(std::fs::read_dir(&temp_root).unwrap().count(), 0, "temp dir must be removed");
}

#[test]
fn cancel_removes_temp_dir() {
    let t = tempfile::tempdir().unwrap();
    let msu = build_msu(t.path());
    let temp_root = t.path().join("temp");
    std::fs::create_dir_all(&temp_root).unwrap();
    let ctx = Ctx::silent();
    ctx.cancel_flag().store(true, std::sync::atomic::Ordering::Relaxed);
    let opts = AnalyzeOptions { compare_local: false, temp_root: Some(temp_root.clone()) };
    assert!(matches!(analyze(&msu, &opts, &ctx), Err(CoreError::Cancelled)));
    assert_eq!(std::fs::read_dir(&temp_root).unwrap().count(), 0);
}

#[test]
fn compares_with_local_machine_when_requested() {
    let t = tempfile::tempdir().unwrap();
    let msu = build_msu(t.path());
    let opts = AnalyzeOptions { compare_local: true, temp_root: None };
    let r = analyze(&msu, &opts, &Ctx::silent()).unwrap();
    if r.warnings.iter().any(|w| w.code == WarningCode::LocalCompareFailed) {
        eprintln!("local compare unavailable on this machine: {:?}", r.warnings);
        return;
    }
    assert_eq!(r.mode, Mode::StaticLocal);
    let ctx = r.local_context.as_ref().unwrap();
    assert!(!ctx.os_build.is_empty());
    assert!(r.components.iter().all(|c| c.local.is_some()));
}

#[test]
fn rejects_missing_and_non_update_files() {
    let t = tempfile::tempdir().unwrap();
    let p = t.path().join("notes.txt");
    std::fs::write(&p, b"hello").unwrap();
    assert!(matches!(analyze(&p, &AnalyzeOptions::default(), &Ctx::silent()), Err(CoreError::UnsupportedFormat(_))));
    let missing = t.path().join("missing.msu");
    assert!(matches!(analyze(&missing, &AnalyzeOptions::default(), &Ctx::silent()), Err(CoreError::Io { .. })));
}

#[test]
fn labels_formats() {
    assert_eq!(format_label(Some(ContainerFormat::Cab), "a.msu", false), "msu-cab");
    assert_eq!(format_label(Some(ContainerFormat::Wim), "a.MSU", true), "msu-wim+psf");
    assert_eq!(format_label(Some(ContainerFormat::Cab), "a.cab", false), "cab");
}
```

- [ ] **Step 2: 執行測試確認失敗**

Run: `cargo test --test analyze`
Expected: 編譯失敗

- [ ] **Step 3: 實作 `src/core/analyze.rs`**

```rust
//! 完整流程：雜湊 → 簽章 → 拆包 →（PSF）→ DCM 解壓與解析 → 套件資訊 →（本機比對）→ 風險。

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use sha2::{Digest, Sha256};

use super::container::{self, Item};
use super::delta::{is_dcm, DcmDecoder, DeltaEngine};
use super::local::{self, LocalEnv};
use super::manifest::decode_text;
use super::manifest::package::{kb_from_file_name, parse_mum, parse_pkg_properties, select_package};
use super::manifest::parse::parse_component;
use super::model::*;
use super::progress::{Ctx, Progress};
use super::{risk, signature, CoreError};

#[derive(Debug, Clone, Default)]
pub struct AnalyzeOptions {
    pub compare_local: bool,
    /// 暫存資料夾的上層位置；None 時用系統暫存資料夾
    pub temp_root: Option<PathBuf>,
}

pub fn format_label(outer: Option<ContainerFormat>, file_name: &str, has_psf: bool) -> String {
    let msu = file_name.to_ascii_lowercase().ends_with(".msu");
    let base = match (outer, msu) {
        (Some(ContainerFormat::Wim), true) => "msu-wim",
        (Some(ContainerFormat::Wim), false) => "wim",
        (_, true) => "msu-cab",
        _ => "cab",
    };
    if has_psf {
        format!("{base}+psf")
    } else {
        base.to_string()
    }
}

fn sha256_file(path: &Path, ctx: &Ctx) -> Result<String, CoreError> {
    let mut f = std::fs::File::open(path).map_err(|e| CoreError::io(path, e))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        ctx.check()?;
        let n = f.read(&mut buf).map_err(|e| CoreError::io(path, e))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn analyze(path: &Path, opts: &AnalyzeOptions, ctx: &Ctx) -> Result<AnalysisReport, CoreError> {
    let meta = std::fs::metadata(path).map_err(|e| CoreError::io(path, e))?;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    ctx.report(Progress::Hashing);
    let sha256 = sha256_file(path, ctx)?;
    ctx.report(Progress::Verifying);
    let signature = signature::verify(path);

    let builder = {
        let mut b = tempfile::Builder::new();
        b.prefix("msu-inspector-");
        b
    };
    let temp = match &opts.temp_root {
        Some(root) => builder.tempdir_in(root),
        None => builder.tempdir(),
    }
    .map_err(|e| CoreError::io(path, e))?;

    let mut collected = container::collect(path, temp.path(), ctx)?;
    let psf_engine = if collected.psfs.is_empty() {
        None
    } else {
        let package_dll = collected
            .package_dll
            .clone()
            .filter(|p| signature::is_microsoft_signed(p));
        let engine = DeltaEngine::select(package_dll.as_deref())?;
        container::resolve_psfs(&mut collected, &engine, ctx)?;
        Some(engine.label().to_string())
    };
    if collected.manifests.is_empty() && collected.mums.is_empty() {
        return Err(CoreError::NoPackageFound);
    }

    let mut warnings = std::mem::take(&mut collected.warnings);
    if signature.status != SignatureStatus::Valid {
        warnings.push(Warning::new(
            WarningCode::SignatureNotValid,
            &file_name,
            signature.status.code(),
        ));
    }
    let (components, parse_warnings) = decode_and_parse(&collected.manifests, ctx)?;
    warnings.extend(parse_warnings);

    let mut mums = Vec::new();
    for item in &collected.mums {
        let parsed = item
            .bytes()
            .and_then(|b| decode_text(&b))
            .and_then(|t| parse_mum(&item.name, &t));
        match parsed {
            Ok(m) => mums.push(m),
            Err(e) => warnings.push(Warning::new(WarningCode::MumParseFailed, &item.vpath, e.to_string())),
        }
    }
    let properties = collected
        .pkg_properties
        .as_deref()
        .map(parse_pkg_properties)
        .unwrap_or_default();
    let kb_hint = kb_from_file_name(&file_name);
    let package = select_package(&mums, kb_hint.as_deref(), properties);
    let has_psf = collected
        .containers
        .iter()
        .any(|c| c.format == ContainerFormat::Psf && c.skipped.is_none());

    let mut report = AnalysisReport {
        mode: Mode::Static,
        local_context: None,
        source: SourceInfo {
            format: format_label(collected.outer, &file_name, has_psf),
            file: file_name,
            size: meta.len(),
            sha256,
            signature,
            containers: std::mem::take(&mut collected.containers),
            delta_engine: psf_engine,
        },
        package,
        components,
        warnings,
    };
    drop(collected);

    if opts.compare_local {
        match LocalEnv::detect() {
            Ok(env) => local::compare(&mut report, &env, ctx)?,
            Err(e) => report
                .warnings
                .push(Warning::new(WarningCode::LocalCompareFailed, "local", e.to_string())),
        }
    }
    risk::apply(&mut report);
    temp.close().map_err(|e| CoreError::io(path, e))?;
    Ok(report)
}

type DcmTools = (DeltaEngine, Result<DcmDecoder, CoreError>);

fn decode_one(item: &Item, dcm: Option<&DcmTools>) -> Result<String, CoreError> {
    let bytes = item.bytes()?;
    if !is_dcm(&bytes) {
        return decode_text(&bytes);
    }
    let (engine, decoder) = dcm.ok_or_else(|| CoreError::Delta("DCM decoder unavailable".into()))?;
    let decoder = decoder
        .as_ref()
        .map_err(|e| CoreError::Delta(e.to_string()))?;
    decode_text(&decoder.decode(engine, &bytes)?)
}

/// 以多執行緒解壓並解析所有 manifest；單一檔案失敗只記警告。
fn decode_and_parse(items: &[Item], ctx: &Ctx) -> Result<(Vec<Component>, Vec<Warning>), CoreError> {
    let needs_dcm = items
        .iter()
        .any(|i| matches!(&i.data, container::ItemData::Bytes(b) if is_dcm(b)));
    let dcm: Option<DcmTools> = if needs_dcm {
        Some((DeltaEngine::system("msdelta.dll")?, DcmDecoder::from_system()))
    } else {
        None
    };
    let total = items.len();
    let done = AtomicUsize::new(0);
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .clamp(1, 16);
    let chunk = total.div_ceil(threads).max(1);
    let results: Vec<(Vec<Component>, Vec<Warning>)> = std::thread::scope(|s| {
        let handles: Vec<_> = items
            .chunks(chunk)
            .map(|part| {
                let dcm = dcm.as_ref();
                let done = &done;
                s.spawn(move || {
                    let mut comps = Vec::new();
                    let mut warns = Vec::new();
                    for item in part {
                        if ctx.is_cancelled() {
                            break;
                        }
                        match decode_one(item, dcm) {
                            Ok(text) => match parse_component(&item.name, &text) {
                                Ok(c) => comps.push(c),
                                Err(e) => warns.push(Warning::new(
                                    WarningCode::ManifestParseFailed,
                                    &item.vpath,
                                    e.to_string(),
                                )),
                            },
                            Err(e) => warns.push(Warning::new(
                                WarningCode::ManifestDecodeFailed,
                                &item.vpath,
                                e.to_string(),
                            )),
                        }
                        let d = done.fetch_add(1, Ordering::Relaxed) + 1;
                        if d % 250 == 0 || d == total {
                            ctx.report(Progress::Decoding { done: d, total });
                        }
                    }
                    (comps, warns)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().expect("manifest worker panicked"))
            .collect()
    });
    ctx.check()?;
    let mut comps = Vec::with_capacity(total);
    let mut warns = Vec::new();
    for (c, w) in results {
        comps.extend(c);
        warns.extend(w);
    }
    comps.sort_by(|a, b| {
        a.identity
            .name
            .to_ascii_lowercase()
            .cmp(&b.identity.name.to_ascii_lowercase())
            .then_with(|| a.identity.cmp(&b.identity))
    });
    Ok((comps, warns))
}
```

`src/core/mod.rs` 加入 `pub mod analyze;`。

- [ ] **Step 4: 執行測試確認通過**

Run: `cargo test --test analyze`
Expected: 全部 PASS

- [ ] **Step 5: 全部測試與 lint**

Run: `cargo test; cargo clippy --all-targets -- -D warnings`
Expected: 全部 PASS、無警告

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: wire the full analysis pipeline with parallel manifest parsing

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 14: JSON 匯出與大小預估

**Files:**
- Create: `src/core/export.rs`, `tests/export.rs`
- Modify: `src/core/mod.rs`（加入 `pub mod export;`）

**Interfaces:**
- Consumes: `model::*`、`risk::rule`、`i18n::Lang`
- Produces:
  - `export::Detail::{Summary, Risk, Full}`（`ALL`、`code()`、`parse(&str)`；`Ord`）
  - `export::ExportOptions { kinds: BTreeSet<ActionKind>, detail: Detail, lang: Lang }`、`ExportOptions::all(detail, lang)`
  - `export::SCHEMA_VERSION`、`export::warning_message(WarningCode, Lang) -> &'static str`
  - `export::build(report, opts, generated_at: &str) -> serde_json::Value`、`export::to_json_string(&Value) -> String`
  - `export::now_rfc3339() -> String`、`export::rfc3339_utc(secs: u64) -> String`
  - `export::SizeModel::build(report) -> SizeModel`、`SizeModel::estimate(&ExportOptions) -> usize`

JSON 結構（spec 第 5 節）：`schema_version`、`tool`、`generated_at`、`mode`、`local_context`（僅本機比對）、`source`、`package`（另加 `restart_required`）、`summary`、`rules`（detail ≥ risk：本次出現的規則 ID → 等級與理由）、`high_risk`（detail ≥ risk）、`components`（detail = full，只列含所選類別動作的元件）、`warnings`（含在地化 `message`）、`export_filter`。

- [ ] **Step 1: 寫失敗測試 `tests/export.rs`**

```rust
use std::collections::BTreeSet;

use msu_inspector::core::export::*;
use msu_inspector::core::model::*;
use msu_inspector::core::risk;
use msu_inspector::i18n::Lang;

fn sample_report(components: usize) -> AnalysisReport {
    let mut comps = Vec::new();
    for i in 0..components {
        let actions = vec![
            ActionDetail::File(FileAction {
                name: format!("f{i}.dll"),
                destination: "$(runtime.system32)\\".into(),
                hash_alg: Some("sha256".into()),
                hash: Some("q83vEjRWeJA=".into()),
                is_pe: true,
                ..Default::default()
            }),
            ActionDetail::Registry(RegistryAction {
                key: format!("HKEY_LOCAL_MACHINE\\SOFTWARE\\Contoso\\K{i}"),
                value_name: Some("V".into()),
                value_type: Some("REG_SZ".into()),
                data: Some("some value data".into()),
                operation: "replace".into(),
                ..Default::default()
            }),
            ActionDetail::Driver(DriverAction {
                name: format!("drv{i}"),
                start: Some(if i % 3 == 0 { "boot" } else { "demand" }.into()),
                image_path: Some(format!("System32\\drivers\\drv{i}.sys")),
                origin: "service".into(),
                ..Default::default()
            }),
        ];
        comps.push(Component {
            identity: AssemblyIdentity {
                name: format!("Microsoft-Windows-Component-{i}"),
                version: "10.0.26100.1742".into(),
                arch: "amd64".into(),
                language: "neutral".into(),
                public_key_token: "31bf3856ad364e35".into(),
            },
            manifest: format!("amd64_microsoft-windows-component-{i}_31bf3856ad364e35_10.0.26100.1742_none_0.manifest"),
            actions: actions.into_iter().map(Action::new).collect(),
            ..Default::default()
        });
    }
    let mut r = AnalysisReport {
        source: SourceInfo { file: "x.msu".into(), sha256: "00".repeat(32), format: "msu-cab".into(), ..Default::default() },
        package: PackageInfo { kb: Some("KB1".into()), restart: Some("required".into()), ..Default::default() },
        components: comps,
        warnings: vec![Warning::new(WarningCode::SignatureNotValid, "x.msu", "unsigned")],
        ..Default::default()
    };
    risk::apply(&mut r);
    r
}

#[test]
fn builds_summary_json() {
    let r = sample_report(3);
    let v = build(&r, &ExportOptions::all(Detail::Summary, Lang::En), "2026-09-25T00:00:00Z");
    assert_eq!(v["schema_version"], SCHEMA_VERSION);
    assert_eq!(v["tool"]["name"], "msu-inspector");
    assert_eq!(v["mode"], "static");
    assert!(v.get("local_context").is_none());
    assert_eq!(v["package"]["kb"], "KB1");
    assert_eq!(v["package"]["restart_required"], true);
    assert_eq!(v["summary"]["components"], 3);
    assert_eq!(v["summary"]["actions"], 9);
    assert_eq!(v["summary"]["by_kind"]["driver"], 3);
    assert_eq!(v["summary"]["by_risk"]["high"], 1);
    assert!(v.get("high_risk").is_none() && v.get("components").is_none());
    assert_eq!(v["warnings"][0]["code"], "signature_not_valid");
    assert!(!v["warnings"][0]["message"].as_str().unwrap().is_empty());
    assert_eq!(v["export_filter"]["detail"], "summary");
    assert_eq!(v["export_filter"]["language"], "en");
}

#[test]
fn risk_detail_lists_high_risk_with_rule_reasons() {
    let r = sample_report(6);
    let v = build(&r, &ExportOptions::all(Detail::Risk, Lang::ZhTw), "t");
    let high = v["high_risk"].as_array().unwrap();
    assert_eq!(high.len(), 2, "drv0 and drv3 start at boot");
    assert_eq!(high[0]["action"]["kind"], "driver");
    assert_eq!(high[0]["target"], "drv0");
    assert_eq!(high[0]["component"], "Microsoft-Windows-Component-0 10.0.26100.1742 (amd64, neutral)");
    assert_eq!(v["rules"]["DRV_BOOT_START"]["level"], "high");
    assert_eq!(
        v["rules"]["DRV_BOOT_START"]["reason"],
        risk::rule("DRV_BOOT_START").unwrap().reason(Lang::ZhTw)
    );
    assert!(v.get("components").is_none());
}

#[test]
fn full_detail_respects_kind_filter() {
    let r = sample_report(4);
    let opts = ExportOptions {
        kinds: BTreeSet::from([ActionKind::Registry]),
        detail: Detail::Full,
        lang: Lang::En,
    };
    let v = build(&r, &opts, "t");
    let comps = v["components"].as_array().unwrap();
    assert_eq!(comps.len(), 4);
    for c in comps {
        let actions = c["actions"].as_array().unwrap();
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0]["kind"], "registry");
    }
    assert_eq!(v["summary"]["actions"], 4);
    assert_eq!(v["high_risk"].as_array().unwrap().len(), 0);
    assert_eq!(v["export_filter"]["kinds"], serde_json::json!(["registry"]));
}

#[test]
fn estimates_size_within_fifteen_percent() {
    let r = sample_report(80);
    let model = SizeModel::build(&r);
    let cases = [
        ExportOptions::all(Detail::Summary, Lang::En),
        ExportOptions::all(Detail::Risk, Lang::En),
        ExportOptions::all(Detail::Full, Lang::En),
        ExportOptions { kinds: BTreeSet::from([ActionKind::File, ActionKind::Driver]), detail: Detail::Full, lang: Lang::En },
    ];
    for opts in cases {
        let actual = to_json_string(&build(&r, &opts, &now_rfc3339())).len() as f64;
        let est = model.estimate(&opts) as f64;
        let err = (est - actual).abs() / actual;
        assert!(err < 0.15, "{:?}/{:?}: estimate {est} vs actual {actual}", opts.detail, opts.kinds);
    }
}

#[test]
fn formats_rfc3339() {
    assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
    assert_eq!(rfc3339_utc(951_782_400), "2000-02-29T00:00:00Z");
    assert_eq!(rfc3339_utc(1_790_000_000), "2026-09-21T14:13:20Z");
    assert!(now_rfc3339().ends_with('Z'));
}

#[test]
fn parses_detail_codes() {
    for d in Detail::ALL {
        assert_eq!(Detail::parse(d.code()), Some(d));
    }
    assert!(Detail::Summary < Detail::Risk && Detail::Risk < Detail::Full);
}
```

- [ ] **Step 2: 執行測試確認失敗**

Run: `cargo test --test export`
Expected: 編譯失敗

- [ ] **Step 3: 實作 `src/core/export.rs`**

```rust
//! JSON 匯出（給 AI 分析）與大小預估。鍵名一律英文；說明文字依匯出語言。

use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use super::model::*;
use super::risk;
use crate::i18n::Lang;

pub const SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Detail {
    Summary,
    Risk,
    Full,
}

impl Detail {
    pub const ALL: [Detail; 3] = [Detail::Summary, Detail::Risk, Detail::Full];

    pub fn code(self) -> &'static str {
        match self {
            Detail::Summary => "summary",
            Detail::Risk => "risk",
            Detail::Full => "full",
        }
    }

    pub fn parse(s: &str) -> Option<Detail> {
        Detail::ALL.into_iter().find(|d| d.code().eq_ignore_ascii_case(s.trim()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportOptions {
    pub kinds: BTreeSet<ActionKind>,
    pub detail: Detail,
    pub lang: Lang,
}

impl ExportOptions {
    pub fn all(detail: Detail, lang: Lang) -> Self {
        ExportOptions {
            kinds: ActionKind::ALL.into_iter().collect(),
            detail,
            lang,
        }
    }
}

pub fn warning_message(code: WarningCode, lang: Lang) -> &'static str {
    let (zh, en) = match code {
        WarningCode::ManifestDecodeFailed => ("manifest 解壓失敗，未納入分析", "Manifest could not be decompressed and was not analyzed"),
        WarningCode::ManifestParseFailed => ("manifest 格式錯誤，未納入分析", "Manifest is malformed and was not analyzed"),
        WarningCode::MumParseFailed => ("套件描述檔（.mum）格式錯誤", "Package manifest (.mum) is malformed"),
        WarningCode::ContainerFailed => ("內層容器無法展開，其內容未納入分析", "A nested container could not be unpacked; its contents were not analyzed"),
        WarningCode::PsfFailed => ("PSF 差異封裝無法讀取", "PSF patch storage could not be read"),
        WarningCode::SignatureNotValid => ("更新檔的數位簽章無效或不存在", "The update package signature is missing or invalid"),
        WarningCode::LocalCompareFailed => ("無法讀取本機狀態，未做本機比對", "Local state could not be read; no local comparison was made"),
    };
    match lang {
        Lang::ZhTw => zh,
        Lang::En => en,
    }
}

fn high_risk_entry(c: &Component, a: &Action) -> Value {
    json!({
        "component": c.identity.display(),
        "manifest": c.manifest,
        "target": a.detail.target(),
        "action": a,
    })
}

pub fn build(report: &AnalysisReport, opts: &ExportOptions, generated_at: &str) -> Value {
    let included = |a: &Action| opts.kinds.contains(&a.kind());

    let mut by_kind: BTreeMap<&str, usize> = BTreeMap::new();
    let mut by_risk: BTreeMap<&str, usize> = BTreeMap::new();
    let mut by_local: BTreeMap<&str, usize> = BTreeMap::new();
    let mut by_store: BTreeMap<&str, usize> = BTreeMap::new();
    let mut rule_ids: BTreeSet<&'static str> = BTreeSet::new();
    let mut high = Vec::new();
    let mut total = 0usize;
    for c in &report.components {
        if let Some(l) = &c.local {
            *by_store.entry(l.state.code()).or_default() += 1;
        }
        for a in c.actions.iter().filter(|a| included(a)) {
            total += 1;
            *by_kind.entry(a.kind().code()).or_default() += 1;
            *by_risk.entry(a.risk.code()).or_default() += 1;
            if let Some(l) = &a.local {
                *by_local.entry(l.state.code()).or_default() += 1;
            }
            if a.risk == Risk::High {
                high.push(high_risk_entry(c, a));
                rule_ids.extend(a.rules.iter().copied());
            }
        }
    }

    let mut summary = json!({
        "components": report.components.len(),
        "actions": total,
        "by_kind": by_kind,
        "by_risk": by_risk,
    });
    if report.mode == Mode::StaticLocal {
        summary["by_local_status"] = json!(by_local);
        summary["components_by_store_status"] = json!(by_store);
    }

    let mut package = serde_json::to_value(&report.package).unwrap_or(Value::Null);
    package["restart_required"] = json!(report
        .package
        .restart
        .as_deref()
        .is_some_and(|r| r.eq_ignore_ascii_case("required")));

    let warnings: Vec<Value> = report
        .warnings
        .iter()
        .map(|w| {
            json!({
                "code": w.code,
                "subject": w.subject,
                "detail": w.detail,
                "message": warning_message(w.code, opts.lang),
            })
        })
        .collect();

    let mut root = Map::new();
    root.insert("schema_version".into(), json!(SCHEMA_VERSION));
    root.insert("tool".into(), json!({"name": "msu-inspector", "version": env!("CARGO_PKG_VERSION")}));
    root.insert("generated_at".into(), json!(generated_at));
    root.insert("mode".into(), json!(report.mode.code()));
    if let Some(ctx) = &report.local_context {
        root.insert("local_context".into(), json!(ctx));
    }
    root.insert("source".into(), json!(report.source));
    root.insert("package".into(), package);
    root.insert("summary".into(), summary);
    if opts.detail >= Detail::Risk {
        if opts.detail == Detail::Full {
            for c in &report.components {
                for a in c.actions.iter().filter(|a| included(a)) {
                    rule_ids.extend(a.rules.iter().copied());
                }
            }
        }
        let rules: Map<String, Value> = rule_ids
            .iter()
            .filter_map(|id| risk::rule(id))
            .map(|r| (r.id.to_string(), json!({"level": r.level, "reason": r.reason(opts.lang)})))
            .collect();
        root.insert("rules".into(), Value::Object(rules));
        root.insert("high_risk".into(), Value::Array(high));
    }
    if opts.detail == Detail::Full {
        let comps: Vec<Value> = report
            .components
            .iter()
            .filter_map(|c| {
                let actions: Vec<&Action> = c.actions.iter().filter(|a| included(a)).collect();
                (!actions.is_empty()).then(|| {
                    json!({
                        "identity": c.identity,
                        "manifest": c.manifest,
                        "categories": c.categories,
                        "local": c.local,
                        "actions": actions,
                    })
                })
            })
            .collect();
        root.insert("components".into(), Value::Array(comps));
    }
    root.insert("warnings".into(), Value::Array(warnings));
    root.insert(
        "export_filter".into(),
        json!({
            "kinds": opts.kinds.iter().map(|k| k.code()).collect::<Vec<_>>(),
            "detail": opts.detail.code(),
            "language": opts.lang.code(),
        }),
    );
    Value::Object(root)
}

pub fn to_json_string(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_default()
}

pub fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    rfc3339_utc(secs)
}

/// Unix 秒 → `YYYY-MM-DDTHH:MM:SSZ`（Howard Hinnant 的 civil_from_days）。
pub fn rfc3339_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// 匯出大小預估：先量測每個動作的 JSON 大小，勾選變動時只做加總。
pub struct SizeModel {
    base: usize,
    per_kind_full: BTreeMap<ActionKind, usize>,
    per_kind_high: BTreeMap<ActionKind, usize>,
    comps_per_kind: BTreeMap<ActionKind, usize>,
    comp_overhead: usize,
}

/// 以 to_string_pretty 量測，再補上在輸出中巢狀位置多出的縮排。
fn pretty_len<T: serde::Serialize>(v: &T, extra_indent: usize) -> usize {
    let s = serde_json::to_string_pretty(v).unwrap_or_default();
    s.len() + (s.matches('\n').count() + 1) * extra_indent + 2
}

impl SizeModel {
    pub fn build(report: &AnalysisReport) -> Self {
        let base = to_json_string(&build(report, &ExportOptions::all(Detail::Summary, Lang::En), &now_rfc3339())).len();
        let mut per_kind_full = BTreeMap::new();
        let mut per_kind_high = BTreeMap::new();
        let mut comps_per_kind: BTreeMap<ActionKind, usize> = BTreeMap::new();
        let mut overhead_total = 0usize;
        for c in &report.components {
            let mut kinds = BTreeSet::new();
            for a in &c.actions {
                let k = a.kind();
                *per_kind_full.entry(k).or_default() += pretty_len(a, 8);
                if a.risk == Risk::High {
                    *per_kind_high.entry(k).or_default() += pretty_len(&high_risk_entry(c, a), 4);
                }
                kinds.insert(k);
            }
            for k in kinds {
                *comps_per_kind.entry(k).or_default() += 1;
            }
            overhead_total += pretty_len(&c.identity, 6) + c.manifest.len() + 120;
        }
        let comp_overhead = overhead_total / report.components.len().max(1);
        SizeModel { base, per_kind_full, per_kind_high, comps_per_kind, comp_overhead }
    }

    pub fn estimate(&self, opts: &ExportOptions) -> usize {
        let sum = |m: &BTreeMap<ActionKind, usize>| -> usize {
            opts.kinds.iter().filter_map(|k| m.get(k)).sum()
        };
        let mut size = self.base;
        if opts.detail >= Detail::Risk {
            size += sum(&self.per_kind_high) + 600;
        }
        if opts.detail == Detail::Full {
            size += sum(&self.per_kind_full);
            let comps = opts.kinds.iter().filter_map(|k| self.comps_per_kind.get(k)).max().copied().unwrap_or(0);
            size += comps * self.comp_overhead;
        }
        size
    }
}
```

`src/core/mod.rs` 加入 `pub mod export;`。

- [ ] **Step 4: 執行測試確認通過**

Run: `cargo test --test export`
Expected: 全部 PASS。若 `estimates_size_within_fifteen_percent` 失敗，調整 `pretty_len` 的縮排常數或 `comp_overhead` 的固定值，使四種情況都在 15% 內；不要放寬測試門檻。

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: export analysis as JSON with detail levels, kind filter and size estimate

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---
### Task 15: 介面字串、CLI、權限提升

**Files:**
- Modify: `src/i18n.rs`（加入 `Strings`、`ZH_TW`、`EN` 與在地化輔助函式）, `src/lib.rs`, `src/main.rs`
- Create: `src/cli.rs`, `src/elevation.rs`, `tests/cli.rs`

**Interfaces:**
- Consumes: `analyze`、`export::*`、`risk::rule`、`sys::is_elevated`、`model::*`、`CoreError`、`Progress`
- Produces:
  - `i18n::Strings`（欄位見下）、`Lang::strings() -> &'static Strings`
  - `i18n::kind_name(ActionKind, Lang)`、`risk_name(Risk, Lang)`、`local_name(LocalState, Lang)`、`detail_name(Detail, Lang)`、`signature_name(SignatureStatus, Lang)`、`not_applicable_text(reason: &str, Lang)`（皆回傳 `&'static str`）
  - `i18n::error_text(&CoreError, Lang) -> String`、`i18n::progress_text(&Progress, Lang) -> String`
  - `cli::{EXIT_OK, EXIT_WARNINGS, EXIT_FAILED}`、`cli::run(Vec<OsString>) -> i32`、`cli::summary_text(&AnalysisReport, Lang) -> String`
  - `elevation::is_elevated()`（re-export）、`elevation::relaunch_elevated(file: Option<&Path>) -> Result<(), String>`、`elevation::params_for(file: Option<&Path>) -> String`

- [ ] **Step 1: 在 `src/i18n.rs` 加入字串表**

在 `impl Lang` 中加入：

```rust
    pub fn strings(self) -> &'static Strings {
        match self {
            Lang::ZhTw => &ZH_TW,
            Lang::En => &EN,
        }
    }
```

在檔案中（`impl Lang` 之後、測試模組之前）加入：

```rust
use crate::core::export::Detail;
use crate::core::model::{ActionKind, LocalState, Risk, SignatureStatus};
use crate::core::progress::Progress;
use crate::core::CoreError;

/// 每個介面字串都是欄位；ZH_TW 與 EN 少寫任何一個都會編譯失敗。
pub struct Strings {
    // ---- 視窗 / 工具列 ----
    pub app_title: &'static str,
    pub open_file: &'static str,
    pub export_json: &'static str,
    pub mode_static: &'static str,
    pub mode_local: &'static str,
    pub elevate: &'static str,
    pub drop_hint: &'static str,
    pub file_filter_name: &'static str,
    // ---- 啟動選擇框 ----
    pub startup_title: &'static str,
    pub startup_body: &'static str,
    pub startup_static: &'static str,
    pub startup_elevate: &'static str,
    pub elevate_failed: &'static str,
    // ---- 進度 ----
    pub cancel: &'static str,
    // ---- 概要列 ----
    pub restart: &'static str,
    pub components: &'static str,
    pub actions: &'static str,
    pub high_risk: &'static str,
    pub signature: &'static str,
    // ---- 結果 ----
    pub tree_all: &'static str,
    pub search_hint: &'static str,
    pub col_risk: &'static str,
    pub col_kind: &'static str,
    pub col_target: &'static str,
    pub col_component: &'static str,
    pub col_local: &'static str,
    pub details_none: &'static str,
    pub details_rules: &'static str,
    pub details_component: &'static str,
    pub details_fields: &'static str,
    pub warnings: &'static str,
    pub no_warnings: &'static str,
    pub close: &'static str,
    // ---- 匯出 ----
    pub export_title: &'static str,
    pub export_kinds: &'static str,
    pub export_detail: &'static str,
    pub estimated_size: &'static str,
    pub export_save: &'static str,
    pub export_copy: &'static str,
    pub copied: &'static str,
    pub saved_to: &'static str,
    pub select_all: &'static str,
    pub select_none: &'static str,
    // ---- CLI ----
    pub cli_needs_admin: &'static str,
    pub cli_written: &'static str,
    pub cli_bad_detail: &'static str,
    pub cli_bad_kind: &'static str,
    pub cli_mode: &'static str,
    pub cli_source: &'static str,
    pub cli_by_kind: &'static str,
    pub cli_top_high_risk: &'static str,
}

pub static ZH_TW: Strings = Strings {
    app_title: "msu-inspector - Windows 更新套件審查",
    open_file: "開啟檔案…",
    export_json: "匯出 JSON…",
    mode_static: "模式：靜態分析",
    mode_local: "模式：靜態分析 + 本機比對",
    elevate: "以系統管理員重新啟動",
    drop_hint: "把 .msu 或 .cab 更新檔拖到這裡，或按「開啟檔案…」",
    file_filter_name: "Windows 更新套件",
    startup_title: "選擇分析模式",
    startup_body: "靜態分析只讀取更新檔本身，不需要系統管理員權限。\n若要與這台電腦比對（哪些檔案、服務、登錄會被新增或取代），需要以系統管理員身分重新啟動。",
    startup_static: "靜態分析",
    startup_elevate: "以系統管理員重新啟動（啟用本機比對）",
    elevate_failed: "無法以系統管理員身分重新啟動",
    cancel: "取消",
    restart: "重新開機",
    components: "元件",
    actions: "動作",
    high_risk: "高風險",
    signature: "簽章",
    tree_all: "全部",
    search_hint: "搜尋目標或元件名稱…",
    col_risk: "風險",
    col_kind: "類別",
    col_target: "目標",
    col_component: "元件",
    col_local: "本機狀態",
    details_none: "在表格中選擇一列以查看詳細資料",
    details_rules: "命中的風險規則",
    details_component: "所屬元件",
    details_fields: "完整欄位",
    warnings: "警告",
    no_warnings: "沒有警告",
    close: "關閉",
    export_title: "匯出 JSON",
    export_kinds: "要匯出的類別",
    export_detail: "細節程度",
    estimated_size: "預估大小：",
    export_save: "另存新檔…",
    export_copy: "複製摘要（含高風險項目）到剪貼簿",
    copied: "已複製到剪貼簿",
    saved_to: "已儲存：",
    select_all: "全選",
    select_none: "全不選",
    cli_needs_admin: "--compare-local 需要以系統管理員身分執行",
    cli_written: "已寫入",
    cli_bad_detail: "--detail 只能是 summary、risk 或 full",
    cli_bad_kind: "不認得的類別",
    cli_mode: "模式",
    cli_source: "來源",
    cli_by_kind: "依類別",
    cli_top_high_risk: "高風險項目（最多 50 筆）",
};

pub static EN: Strings = Strings {
    app_title: "msu-inspector - Windows update package review",
    open_file: "Open file…",
    export_json: "Export JSON…",
    mode_static: "Mode: static analysis",
    mode_local: "Mode: static analysis + local comparison",
    elevate: "Restart as administrator",
    drop_hint: "Drop a .msu or .cab update here, or click \"Open file…\"",
    file_filter_name: "Windows update packages",
    startup_title: "Choose analysis mode",
    startup_body: "Static analysis only reads the update package and needs no administrator rights.\nTo compare against this computer (which files, services and registry values would be added or replaced), restart as administrator.",
    startup_static: "Static analysis",
    startup_elevate: "Restart as administrator (enable local comparison)",
    elevate_failed: "Could not restart as administrator",
    cancel: "Cancel",
    restart: "Restart",
    components: "Components",
    actions: "Actions",
    high_risk: "High risk",
    signature: "Signature",
    tree_all: "All",
    search_hint: "Search target or component…",
    col_risk: "Risk",
    col_kind: "Kind",
    col_target: "Target",
    col_component: "Component",
    col_local: "Local state",
    details_none: "Select a row to see its details",
    details_rules: "Matched risk rules",
    details_component: "Component",
    details_fields: "All fields",
    warnings: "Warnings",
    no_warnings: "No warnings",
    close: "Close",
    export_title: "Export JSON",
    export_kinds: "Kinds to export",
    export_detail: "Detail level",
    estimated_size: "Estimated size:",
    export_save: "Save as…",
    export_copy: "Copy summary (with high-risk items) to clipboard",
    copied: "Copied to clipboard",
    saved_to: "Saved:",
    select_all: "All",
    select_none: "None",
    cli_needs_admin: "--compare-local requires running as administrator",
    cli_written: "Written",
    cli_bad_detail: "--detail must be summary, risk or full",
    cli_bad_kind: "Unknown kind",
    cli_mode: "Mode",
    cli_source: "Source",
    cli_by_kind: "By kind",
    cli_top_high_risk: "High-risk items (up to 50)",
};

fn pick(lang: Lang, zh: &'static str, en: &'static str) -> &'static str {
    match lang {
        Lang::ZhTw => zh,
        Lang::En => en,
    }
}

pub fn kind_name(k: ActionKind, lang: Lang) -> &'static str {
    match k {
        ActionKind::File => pick(lang, "檔案", "File"),
        ActionKind::Registry => pick(lang, "登錄", "Registry"),
        ActionKind::Directory => pick(lang, "資料夾", "Directory"),
        ActionKind::Service => pick(lang, "服務", "Service"),
        ActionKind::Driver => pick(lang, "驅動程式", "Driver"),
        ActionKind::ScheduledTask => pick(lang, "排程工作", "Scheduled task"),
        ActionKind::GenericCommand => pick(lang, "執行指令", "Command"),
        ActionKind::FirewallRule => pick(lang, "防火牆規則", "Firewall rule"),
        ActionKind::WmiMof => pick(lang, "WMI MOF", "WMI MOF"),
        ActionKind::EtwEventlog => pick(lang, "ETW / 事件記錄", "ETW / Event log"),
        ActionKind::AdvancedInstaller => pick(lang, "進階安裝程式", "Advanced installer"),
        ActionKind::Setting => pick(lang, "設定", "Setting"),
        ActionKind::Unknown => pick(lang, "未辨識", "Unknown"),
    }
}

pub fn risk_name(r: Risk, lang: Lang) -> &'static str {
    match r {
        Risk::High => pick(lang, "高", "High"),
        Risk::Medium => pick(lang, "中", "Medium"),
        Risk::Low => pick(lang, "低", "Low"),
        Risk::Info => pick(lang, "資訊", "Info"),
    }
}

pub fn local_name(s: LocalState, lang: Lang) -> &'static str {
    match s {
        LocalState::New => pick(lang, "新增", "New"),
        LocalState::Replace => pick(lang, "取代", "Replace"),
        LocalState::Same => pick(lang, "相同", "Same"),
        LocalState::Downgrade => pick(lang, "降版", "Downgrade"),
        LocalState::Present => pick(lang, "已存在", "Present"),
        LocalState::UnknownPath => pick(lang, "無法對應路徑", "Unknown path"),
        LocalState::InStoreSame => pick(lang, "存放區已有相同版本", "Same version in store"),
        LocalState::InStoreOlder => pick(lang, "存放區為舊版", "Older version in store"),
        LocalState::InStoreNewer => pick(lang, "存放區已有較新版", "Newer version in store"),
        LocalState::NotInStore => pick(lang, "存放區沒有此元件", "Not in store"),
    }
}

pub fn detail_name(d: Detail, lang: Lang) -> &'static str {
    match d {
        Detail::Summary => pick(lang, "只要統計", "Summary only"),
        Detail::Risk => pick(lang, "統計 + 高風險項目", "Summary + high-risk items"),
        Detail::Full => pick(lang, "全部明細", "Full detail"),
    }
}

pub fn signature_name(s: SignatureStatus, lang: Lang) -> &'static str {
    match s {
        SignatureStatus::Valid => pick(lang, "有效", "Valid"),
        SignatureStatus::Unsigned => pick(lang, "未簽章", "Unsigned"),
        SignatureStatus::Invalid => pick(lang, "無效", "Invalid"),
        SignatureStatus::Unknown => pick(lang, "未知", "Unknown"),
    }
}

pub fn not_applicable_text(reason: &str, lang: Lang) -> &'static str {
    match reason {
        "arch_mismatch" => pick(lang, "此 KB 的處理器架構與本機不同，本機比對結果僅供參考", "This KB targets a different processor architecture; local comparison is for reference only"),
        _ => pick(lang, "此 KB 的 Windows 版本與本機不同，本機比對結果僅供參考", "This KB targets a different Windows build; local comparison is for reference only"),
    }
}

pub fn error_text(e: &CoreError, lang: Lang) -> String {
    let prefix = match e {
        CoreError::UnsupportedFormat(_) => pick(lang, "不支援的檔案格式（需要 .msu 或 .cab 更新檔）", "Unsupported file format (expects a .msu or .cab update)"),
        CoreError::NeedsElevation(_) => pick(lang, "這個更新檔需要以系統管理員身分才能展開，請按「以系統管理員重新啟動」", "This package can only be unpacked as administrator; use \"Restart as administrator\""),
        CoreError::NoPackageFound => pick(lang, "檔案中找不到更新套件內容（.mum / .manifest）", "No update package content (.mum / .manifest) was found"),
        CoreError::Cancelled => pick(lang, "已取消", "Cancelled"),
        CoreError::Container { .. } => pick(lang, "無法展開更新檔", "Cannot unpack the package"),
        _ => pick(lang, "分析失敗", "Analysis failed"),
    };
    format!("{prefix}\n{e}")
}

pub fn progress_text(p: &Progress, lang: Lang) -> String {
    match p {
        Progress::Hashing => pick(lang, "計算 SHA-256…", "Computing SHA-256…").to_string(),
        Progress::Verifying => pick(lang, "驗證數位簽章…", "Verifying signature…").to_string(),
        Progress::Unpacking { container } => format!("{} {container}", pick(lang, "展開", "Unpacking")),
        Progress::Decoding { done, total } => format!("{} {done}/{total}", pick(lang, "解析 manifest", "Parsing manifests")),
        Progress::Comparing { done, total } => format!("{} {done}/{total}", pick(lang, "與本機比對", "Comparing with this machine")),
    }
}
```

在 `i18n.rs` 的測試模組加入：

```rust
    #[test]
    fn every_kind_and_state_has_names_in_both_languages() {
        for k in ActionKind::ALL {
            assert!(!kind_name(k, Lang::ZhTw).is_empty() && !kind_name(k, Lang::En).is_empty());
        }
        for s in LocalState::ALL {
            assert_ne!(local_name(s, Lang::ZhTw), local_name(s, Lang::En));
        }
        assert!(error_text(&CoreError::NoPackageFound, Lang::ZhTw).starts_with("檔案中找不到"));
    }
```

- [ ] **Step 2: 建立 `src/elevation.rs`**

```rust
//! 權限：是否為系統管理員、以 UAC（runas）重新啟動自己。

use std::path::Path;

use windows::core::{w, HSTRING, PCWSTR};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

pub use crate::core::sys::is_elevated;

/// 重新啟動時帶入目前的檔案路徑（加上引號，路徑可含空白）。
pub fn params_for(file: Option<&Path>) -> String {
    file.map(|f| format!("\"{}\"", f.display())).unwrap_or_default()
}

/// 以系統管理員身分啟動新的自己；成功後呼叫端應關閉目前視窗。使用者在 UAC 按「否」時回傳錯誤。
pub fn relaunch_elevated(file: Option<&Path>) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    // SAFETY: 所有字串在呼叫期間有效。
    let r = unsafe {
        ShellExecuteW(
            None,
            w!("runas"),
            &HSTRING::from(exe.as_os_str()),
            &HSTRING::from(params_for(file)),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    // ShellExecute 的回傳值大於 32 代表成功
    if r.0 as isize > 32 {
        Ok(())
    } else {
        Err(format!("ShellExecuteW runas failed ({})", r.0 as isize))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_file_parameter() {
        assert_eq!(params_for(None), "");
        assert_eq!(params_for(Some(Path::new(r"D:\下載\KB 1.msu"))), "\"D:\\下載\\KB 1.msu\"");
    }
}
```

- [ ] **Step 3: 寫 CLI 失敗測試 `tests/cli.rs`**

```rust
mod common;

use assert_cmd::Command;

fn build_msu(dir: &std::path::Path) -> std::path::PathBuf {
    let inner = common::make_cab(
        dir,
        "kb.cab",
        &[
            ("Package_for_RollupFix.mum", common::fixture("rollup.mum").as_bytes()),
            ("amd64_test-actions.manifest", common::fixture("actions.manifest").as_bytes()),
        ],
        false,
    );
    common::make_cab(
        dir,
        "Windows11.0-KB5129195-x64.msu",
        &[("kb.cab", &std::fs::read(inner).unwrap())],
        false,
    )
}

fn cmd() -> Command {
    Command::cargo_bin("msu-inspector").unwrap()
}

#[test]
fn writes_full_json_and_returns_warning_code() {
    let t = tempfile::tempdir().unwrap();
    let msu = build_msu(t.path());
    let out = t.path().join("out.json");
    cmd()
        .args(["analyze"])
        .arg(&msu)
        .args(["--json"])
        .arg(&out)
        .args(["--detail", "full", "--lang", "en"])
        .assert()
        .code(1); // 測試檔未簽章 → 有警告
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(v["schema_version"], "1.0");
    assert_eq!(v["package"]["kb"], "KB5129195");
    assert!(!v["components"].as_array().unwrap().is_empty());
}

#[test]
fn prints_json_to_stdout_with_kind_filter() {
    let t = tempfile::tempdir().unwrap();
    let msu = build_msu(t.path());
    let output = cmd()
        .arg("analyze")
        .arg(&msu)
        .args(["--json", "-", "--kinds", "driver,service", "--detail", "full"])
        .output()
        .unwrap();
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(v["export_filter"]["kinds"], serde_json::json!(["service", "driver"]));
}

#[test]
fn prints_text_summary_by_default() {
    let t = tempfile::tempdir().unwrap();
    let msu = build_msu(t.path());
    let output = cmd().arg("analyze").arg(&msu).args(["--lang", "zh-TW"]).output().unwrap();
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("KB5129195"), "{text}");
    assert!(text.contains("DRV_BOOT_START"), "{text}");
}

#[test]
fn rejects_bad_arguments() {
    let t = tempfile::tempdir().unwrap();
    let msu = build_msu(t.path());
    cmd().arg("analyze").arg(&msu).args(["--detail", "huge"]).assert().code(2);
    cmd().arg("analyze").arg(&msu).args(["--kinds", "nope"]).assert().code(2);
    cmd().arg("analyze").arg(t.path().join("missing.msu")).assert().code(2);
    cmd().args(["--version"]).assert().code(0);
}

#[test]
fn compare_local_requires_admin() {
    if msu_inspector::elevation::is_elevated() {
        return;
    }
    let t = tempfile::tempdir().unwrap();
    let msu = build_msu(t.path());
    cmd().arg("analyze").arg(&msu).arg("--compare-local").assert().code(2);
}
```

- [ ] **Step 4: 執行測試確認失敗**

Run: `cargo test --test cli`
Expected: 編譯失敗（`cli`、`elevation` 未定義）

- [ ] **Step 5: 實作 `src/cli.rs`**

```rust
//! CLI：`msu-inspector analyze <FILE> [--json OUT|-] [--detail ...] [--kinds ...] [--compare-local] [--lang ...]`

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::core::analyze::{analyze, AnalyzeOptions};
use crate::core::export::{build, now_rfc3339, to_json_string, Detail, ExportOptions};
use crate::core::model::{ActionKind, AnalysisReport, Risk};
use crate::core::progress::Ctx;
use crate::core::risk;
use crate::core::sys::is_elevated;
use crate::i18n::{error_text, kind_name, risk_name, signature_name, Lang};

pub const EXIT_OK: i32 = 0;
pub const EXIT_WARNINGS: i32 = 1;
pub const EXIT_FAILED: i32 = 2;

#[derive(Parser)]
#[command(name = "msu-inspector", version, about = "Pre-deployment review of Windows update packages (.msu / .cab)")]
struct Cli {
    /// Interface language: zh-TW or en
    #[arg(long, global = true)]
    lang: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Analyze an update package without installing it
    Analyze(AnalyzeArgs),
}

#[derive(Args)]
struct AnalyzeArgs {
    /// .msu or .cab file
    file: PathBuf,
    /// Write JSON to this file ("-" for stdout); without it a text summary is printed
    #[arg(long)]
    json: Option<PathBuf>,
    /// summary, risk or full
    #[arg(long, default_value = "risk")]
    detail: String,
    /// Comma-separated action kinds to export (default: all)
    #[arg(long, value_delimiter = ',')]
    kinds: Vec<String>,
    /// Compare against this machine (requires administrator)
    #[arg(long)]
    compare_local: bool,
}

pub fn run(args: Vec<OsString>) -> i32 {
    let cli = match Cli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() { EXIT_FAILED } else { EXIT_OK };
        }
    };
    let lang = cli.lang.as_deref().and_then(Lang::parse).unwrap_or_else(Lang::detect);
    match cli.command {
        Command::Analyze(a) => run_analyze(a, lang),
    }
}

fn run_analyze(a: AnalyzeArgs, lang: Lang) -> i32 {
    let t = lang.strings();
    let Some(detail) = Detail::parse(&a.detail) else {
        eprintln!("{}", t.cli_bad_detail);
        return EXIT_FAILED;
    };
    let mut kinds = BTreeSet::new();
    for k in &a.kinds {
        match ActionKind::parse(k) {
            Some(kind) => {
                kinds.insert(kind);
            }
            None => {
                eprintln!("{}: {k}", t.cli_bad_kind);
                return EXIT_FAILED;
            }
        }
    }
    if kinds.is_empty() {
        kinds = ActionKind::ALL.into_iter().collect();
    }
    if a.compare_local && !is_elevated() {
        eprintln!("{}", t.cli_needs_admin);
        return EXIT_FAILED;
    }
    let opts = AnalyzeOptions {
        compare_local: a.compare_local,
        temp_root: None,
    };
    let report = match analyze(&a.file, &opts, &Ctx::silent()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{}", error_text(&e, lang));
            return EXIT_FAILED;
        }
    };
    let export = ExportOptions { kinds, detail, lang };
    match &a.json {
        Some(p) if p.as_os_str() == "-" => {
            println!("{}", to_json_string(&build(&report, &export, &now_rfc3339())));
        }
        Some(p) => {
            let json = to_json_string(&build(&report, &export, &now_rfc3339()));
            if let Err(e) = std::fs::write(p, json) {
                eprintln!("{}: {e}", p.display());
                return EXIT_FAILED;
            }
            eprintln!("{} {}", t.cli_written, p.display());
        }
        None => print!("{}", summary_text(&report, lang)),
    }
    if report.warnings.is_empty() {
        EXIT_OK
    } else {
        EXIT_WARNINGS
    }
}

/// 終端機用的文字摘要。
pub fn summary_text(report: &AnalysisReport, lang: Lang) -> String {
    let t = lang.strings();
    let mut s = String::new();
    let p = &report.package;
    let _ = writeln!(
        s,
        "{} · {} · {} · {}: {}",
        p.kb.as_deref().unwrap_or("-"),
        p.release_type.as_deref().unwrap_or("-"),
        p.identity.arch,
        t.restart,
        p.restart.as_deref().unwrap_or("-")
    );
    let _ = writeln!(
        s,
        "{}: {} ({}, SHA-256 {}) · {}: {}{}",
        t.cli_source,
        report.source.file,
        report.source.format,
        report.source.sha256,
        t.signature,
        signature_name(report.source.signature.status, lang),
        report.source.signature.signer.as_deref().map(|n| format!(" ({n})")).unwrap_or_default()
    );
    let _ = writeln!(s, "{}: {}", t.cli_mode, report.mode.code());
    let _ = writeln!(s, "{}: {} · {}: {}", t.components, report.components.len(), t.actions, report.action_count());
    let all = || report.components.iter().flat_map(|c| c.actions.iter().map(move |a| (c, a)));
    let risks: Vec<String> = Risk::ALL
        .iter()
        .map(|r| format!("{} {}", risk_name(*r, lang), all().filter(|(_, a)| a.risk == *r).count()))
        .collect();
    let _ = writeln!(s, "{}: {}", t.col_risk, risks.join(" · "));
    let kinds: Vec<String> = ActionKind::ALL
        .iter()
        .filter_map(|k| {
            let n = all().filter(|(_, a)| a.kind() == *k).count();
            (n > 0).then(|| format!("{} {n}", kind_name(*k, lang)))
        })
        .collect();
    let _ = writeln!(s, "{}: {}", t.cli_by_kind, kinds.join(", "));
    let _ = writeln!(s, "{}:", t.cli_top_high_risk);
    for (c, a) in all().filter(|(_, a)| a.risk == Risk::High).take(50) {
        let reasons: Vec<String> = a
            .rules
            .iter()
            .filter_map(|id| risk::rule(id))
            .map(|r| format!("{} {}", r.id, r.reason(lang)))
            .collect();
        let _ = writeln!(
            s,
            "  [{}] {} — {} ({})",
            kind_name(a.kind(), lang),
            a.detail.target(),
            reasons.join("; "),
            c.identity.name
        );
    }
    let _ = writeln!(s, "{}: {}", t.warnings, report.warnings.len());
    for w in &report.warnings {
        let _ = writeln!(s, "  {} {}", w.subject, w.detail);
    }
    s
}
```

- [ ] **Step 6: 更新 `src/lib.rs` 與 `src/main.rs`**

`src/lib.rs`：

```rust
//! msu-inspector：Windows 更新套件部署前審查工具。

pub mod cli;
pub mod core;
pub mod elevation;
pub mod i18n;
```

`src/main.rs`（Task 16 會加入 GUI）：

```rust
//! msu-inspector 進入點（Task 16 接上 GUI）。

fn main() {
    std::process::exit(msu_inspector::cli::run(std::env::args_os().collect()));
}
```

- [ ] **Step 7: 執行測試確認通過**

Run: `cargo test --test cli; cargo test --lib`
Expected: 全部 PASS

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat: add bilingual strings, CLI and elevation helper

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 16: GUI 骨架：主視窗、啟動模式選擇、背景分析與進度

**Files:**
- Create: `src/gui/mod.rs`, `src/gui/app.rs`, `src/gui/startup.rs`, `src/gui/results.rs`（本 Task 先放最小版本）, `src/gui/export_dialog.rs`（本 Task 先放最小版本）
- Modify: `src/lib.rs`（加入 `pub mod gui;`）, `src/main.rs`

**Interfaces:**
- Consumes: `analyze`、`SizeModel`、`Ctx`、`elevation::*`、`i18n::*`
- Produces:
  - `gui::run(file: Option<PathBuf>) -> eframe::Result`
  - `gui::results::Results::new(report, size_model, path) -> Results`，公開欄位 `path`、`report`、`size_model`；方法 `summary_bar(&self, ui, lang)`、`status_bar(&mut self, ui, lang)`、`ui(&mut self, ui, lang)`（Task 17 完成）
  - `gui::export_dialog::ExportDialog::new() -> Self`、`show(&mut self, ctx, lang, results) `、`is_open() -> bool`（Task 18 完成）

eframe 0.36 的 API 請比照 `D:\VSCode\code-signer\src\gui`：`impl eframe::App` 實作 `fn ui(&mut self, ui: &mut egui::Ui, frame)`，面板用 `egui::Panel::top/left/right/bottom(id).show(ui, ...)`、`egui::CentralPanel::default_margins().show(ui, ...)`。若某個方法名稱不同，以 context7 查 egui 0.36 文件後調整呼叫處即可，行為不變。

- [ ] **Step 1: 建立 `src/gui/mod.rs`**

```rust
//! 圖形介面（egui / eframe）。

mod app;
pub mod export_dialog;
pub mod results;
mod startup;

use std::path::PathBuf;
use std::sync::Arc;

use eframe::egui;

/// 開啟 GUI 直到視窗關閉；`file` 為啟動時要分析的檔案（例如從提升權限重新啟動）。
pub fn run(file: Option<PathBuf>) -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 760.0])
            .with_min_inner_size([860.0, 520.0])
            .with_drag_and_drop(true),
        ..Default::default()
    };
    eframe::run_native(
        "msu-inspector",
        options,
        Box::new(move |cc| {
            setup_fonts(&cc.egui_ctx);
            Ok(Box::new(app::App::new(file)))
        }),
    )
}

/// 載入系統中文字型作為備援字型，不把字型檔塞進 exe。
fn setup_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    let candidates = [
        r"C:\Windows\Fonts\msjh.ttc",
        r"C:\Windows\Fonts\msjhl.ttc",
        r"C:\Windows\Fonts\mingliu.ttc",
        r"C:\Windows\Fonts\msyh.ttc",
        r"C:\Windows\Fonts\simsun.ttc",
    ];
    if let Some(bytes) = candidates.iter().find_map(|p| std::fs::read(p).ok()) {
        fonts
            .font_data
            .insert("cjk".to_owned(), Arc::new(egui::FontData::from_owned(bytes)));
        for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
            fonts.families.entry(family).or_default().push("cjk".to_owned());
        }
    }
    ctx.set_fonts(fonts);
}
```

- [ ] **Step 2: 建立 `src/gui/startup.rs`**

```rust
//! 非管理員啟動時的模式選擇框。

use eframe::egui;

use crate::i18n::Strings;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    Static,
    Elevate,
}

/// 每個影格呼叫；使用者做出選擇時回傳 Some。按 Esc 或點外面視為選擇靜態分析。
pub fn show(ctx: &egui::Context, t: &Strings) -> Option<Choice> {
    let mut choice = None;
    let resp = egui::Modal::new(egui::Id::new("startup-mode")).show(ctx, |ui| {
        ui.set_max_width(460.0);
        ui.heading(t.startup_title);
        ui.add_space(6.0);
        ui.label(t.startup_body);
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui.button(t.startup_static).clicked() {
                choice = Some(Choice::Static);
            }
            if ui.button(t.startup_elevate).clicked() {
                choice = Some(Choice::Elevate);
            }
        });
    });
    if choice.is_none() && resp.should_close() {
        choice = Some(Choice::Static);
    }
    choice
}
```

- [ ] **Step 3: 建立最小版 `src/gui/results.rs` 與 `src/gui/export_dialog.rs`**

`src/gui/results.rs`（Task 17 擴充）：

```rust
//! 分析結果檢視。

use std::path::PathBuf;

use eframe::egui;

use crate::core::export::SizeModel;
use crate::core::model::AnalysisReport;
use crate::i18n::Lang;

pub struct Results {
    pub path: PathBuf,
    pub report: AnalysisReport,
    pub size_model: SizeModel,
}

impl Results {
    pub fn new(report: AnalysisReport, size_model: SizeModel, path: PathBuf) -> Self {
        Results { path, report, size_model }
    }

    pub fn summary_bar(&self, ui: &mut egui::Ui, _lang: Lang) {
        ui.label(self.report.package.kb.as_deref().unwrap_or("-"));
    }

    pub fn status_bar(&mut self, _ui: &mut egui::Ui, _lang: Lang) {}

    pub fn ui(&mut self, ui: &mut egui::Ui, lang: Lang) {
        let t = lang.strings();
        ui.label(format!("{}: {}", t.components, self.report.components.len()));
    }
}
```

`src/gui/export_dialog.rs`（Task 18 擴充）：

```rust
//! 匯出 JSON 對話框。

use eframe::egui;

use super::results::Results;
use crate::i18n::Lang;

pub struct ExportDialog {
    open: bool,
}

impl ExportDialog {
    pub fn new() -> Self {
        ExportDialog { open: true }
    }

    pub fn is_open(&self) -> bool {
        self.open
    }

    pub fn show(&mut self, ctx: &egui::Context, lang: Lang, _results: &Results) {
        let mut open = self.open;
        egui::Window::new(lang.strings().export_title)
            .open(&mut open)
            .show(ctx, |_ui| {});
        self.open = open;
    }
}
```

- [ ] **Step 4: 建立 `src/gui/app.rs`**

```rust
//! 主視窗：工具列、模式、拖放、背景分析與進度。

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;

use eframe::egui;

use super::export_dialog::ExportDialog;
use super::results::Results;
use super::startup::{self, Choice};
use crate::core::analyze::{analyze, AnalyzeOptions};
use crate::core::export::SizeModel;
use crate::core::model::AnalysisReport;
use crate::core::progress::{Ctx, Progress};
use crate::core::CoreError;
use crate::elevation;
use crate::i18n::{error_text, progress_text, Lang};

enum JobMsg {
    Progress(Progress),
    Done(Box<Result<(AnalysisReport, SizeModel), CoreError>>),
}

struct Job {
    file: PathBuf,
    rx: Receiver<JobMsg>,
    cancel: Arc<AtomicBool>,
    progress: Option<Progress>,
}

pub struct App {
    lang: Lang,
    elevated: bool,
    /// 非管理員啟動時，使用者是否已在選擇框做出決定
    mode_chosen: bool,
    pending: Option<PathBuf>,
    job: Option<Job>,
    results: Option<Results>,
    export: Option<ExportDialog>,
    error: Option<String>,
}

impl App {
    pub fn new(file: Option<PathBuf>) -> Self {
        let elevated = elevation::is_elevated();
        App {
            lang: Lang::detect(),
            elevated,
            mode_chosen: elevated,
            pending: file,
            job: None,
            results: None,
            export: None,
            error: None,
        }
    }

    /// 開始分析；已有工作時先取消舊的。
    fn start(&mut self, file: PathBuf, ctx: &egui::Context) {
        if let Some(j) = &self.job {
            j.cancel.store(true, Ordering::Relaxed);
        }
        let (tx, rx) = mpsc::channel();
        let progress_tx = tx.clone();
        let repaint = ctx.clone();
        let core_ctx = Ctx::new(move |p| {
            let _ = progress_tx.send(JobMsg::Progress(p));
            repaint.request_repaint();
        });
        let cancel = core_ctx.cancel_flag();
        let opts = AnalyzeOptions {
            compare_local: self.elevated,
            temp_root: None,
        };
        let path = file.clone();
        let done_repaint = ctx.clone();
        std::thread::spawn(move || {
            let result = analyze(&path, &opts, &core_ctx).map(|r| {
                let model = SizeModel::build(&r);
                (r, model)
            });
            let _ = tx.send(JobMsg::Done(Box::new(result)));
            done_repaint.request_repaint();
        });
        self.results = None;
        self.export = None;
        self.error = None;
        self.job = Some(Job {
            file,
            rx,
            cancel,
            progress: None,
        });
    }

    fn poll_job(&mut self) {
        let Some(job) = &mut self.job else {
            return;
        };
        let mut finished = None;
        while let Ok(msg) = job.rx.try_recv() {
            match msg {
                JobMsg::Progress(p) => job.progress = Some(p),
                JobMsg::Done(r) => finished = Some(*r),
            }
        }
        let Some(result) = finished else {
            return;
        };
        let file = job.file.clone();
        self.job = None;
        match result {
            Ok((report, model)) => self.results = Some(Results::new(report, model, file)),
            Err(CoreError::Cancelled) => {}
            Err(e) => self.error = Some(error_text(&e, self.lang)),
        }
    }

    fn current_file(&self) -> Option<PathBuf> {
        self.job
            .as_ref()
            .map(|j| j.file.clone())
            .or_else(|| self.results.as_ref().map(|r| r.path.clone()))
            .or_else(|| self.pending.clone())
    }

    fn relaunch(&mut self, ctx: &egui::Context, file: Option<PathBuf>) {
        match elevation::relaunch_elevated(file.as_deref()) {
            Ok(()) => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
            Err(e) => self.error = Some(format!("{}: {e}", self.lang.strings().elevate_failed)),
        }
    }

    fn open(&mut self, file: PathBuf, ctx: &egui::Context) {
        if self.mode_chosen {
            self.start(file, ctx);
        } else {
            self.pending = Some(file);
        }
    }

    fn toolbar(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let t = self.lang.strings();
        egui::Panel::top("toolbar").show(ui, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if ui.button(t.open_file).clicked() {
                    if let Some(p) = rfd::FileDialog::new()
                        .add_filter(t.file_filter_name, &["msu", "cab"])
                        .pick_file()
                    {
                        self.open(p, ctx);
                    }
                }
                if ui
                    .add_enabled(self.results.is_some(), egui::Button::new(t.export_json))
                    .clicked()
                {
                    self.export = Some(ExportDialog::new());
                }
                ui.separator();
                ui.label(if self.elevated { t.mode_local } else { t.mode_static });
                if !self.elevated && ui.button(t.elevate).clicked() {
                    let f = self.current_file();
                    self.relaunch(ctx, f);
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    egui::ComboBox::from_id_salt("lang")
                        .selected_text(self.lang.native_name())
                        .show_ui(ui, |ui| {
                            for l in Lang::ALL {
                                ui.selectable_value(&mut self.lang, l, l.native_name());
                            }
                        });
                });
            });
            ui.add_space(4.0);
        });
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let t = self.lang.strings();
        ctx.send_viewport_cmd(egui::ViewportCommand::Title(t.app_title.into()));
        self.poll_job();

        if !self.mode_chosen {
            match startup::show(&ctx, t) {
                Some(Choice::Static) => self.mode_chosen = true,
                Some(Choice::Elevate) => {
                    self.mode_chosen = true;
                    let f = self.pending.clone();
                    self.relaunch(&ctx, f);
                }
                None => {}
            }
        }
        if self.mode_chosen && self.job.is_none() {
            if let Some(f) = self.pending.take() {
                self.start(f, &ctx);
            }
        }
        if let Some(p) = ctx.input(|i| i.raw.dropped_files.iter().find_map(|f| f.path.clone())) {
            self.open(p, &ctx);
        }

        self.toolbar(ui, &ctx);
        let lang = self.lang;

        egui::Panel::bottom("status").show(ui, |ui| {
            ui.horizontal(|ui| {
                if let Some(job) = &self.job {
                    ui.spinner();
                    ui.label(job.progress.as_ref().map(|p| progress_text(p, lang)).unwrap_or_default());
                    if ui.button(t.cancel).clicked() {
                        job.cancel.store(true, Ordering::Relaxed);
                    }
                } else if let Some(r) = &mut self.results {
                    r.status_bar(ui, lang);
                }
            });
        });

        if let Some(r) = &self.results {
            egui::Panel::top("summary").show(ui, |ui| r.summary_bar(ui, lang));
        }

        egui::CentralPanel::default_margins().show(ui, |ui| {
            if let Some(err) = &self.error {
                ui.colored_label(ui.visuals().error_fg_color, err);
                ui.separator();
            }
            if self.job.is_some() {
                ui.centered_and_justified(|ui| ui.spinner());
            } else if let Some(r) = &mut self.results {
                r.ui(ui, lang);
            } else {
                ui.centered_and_justified(|ui| ui.heading(t.drop_hint));
            }
        });

        let mut close_export = false;
        if let (Some(dialog), Some(results)) = (&mut self.export, &self.results) {
            dialog.show(&ctx, lang, results);
            close_export = !dialog.is_open();
        }
        if close_export {
            self.export = None;
        }
    }
}
```

- [ ] **Step 5: 更新 `src/lib.rs` 與 `src/main.rs`**

`src/lib.rs` 加入 `pub mod gui;`。

`src/main.rs`：

```rust
//! msu-inspector 進入點：無參數或只帶一個既有檔案 → GUI；其餘 → CLI。

use std::ffi::OsString;
use std::path::PathBuf;

fn main() {
    let args: Vec<OsString> = std::env::args_os().collect();
    match gui_target(&args) {
        Some(file) => {
            detach_console_if_owned();
            if let Err(e) = msu_inspector::gui::run(file) {
                eprintln!("{e}");
                std::process::exit(msu_inspector::cli::EXIT_FAILED);
            }
        }
        None => std::process::exit(msu_inspector::cli::run(args)),
    }
}

/// `None` → CLI；`Some(None)` → 空白 GUI；`Some(Some(path))` → GUI 並分析該檔
/// （提升權限重新啟動、或把檔案拖到 exe 上時）。
fn gui_target(args: &[OsString]) -> Option<Option<PathBuf>> {
    match args.len() {
        1 => Some(None),
        2 => {
            let p = PathBuf::from(&args[1]);
            p.is_file().then_some(Some(p))
        }
        _ => None,
    }
}

/// 從檔案總管雙擊啟動時，Windows 會為這個主控台程式建立專屬的主控台視窗；
/// 若主控台上只有本程序（代表不是從終端機執行），就釋放它，只留下 GUI。
fn detach_console_if_owned() {
    use windows::Win32::System::Console::{FreeConsole, GetConsoleProcessList};
    let mut pids = [0u32; 2];
    // SAFETY: 緩衝區長度正確；兩個 API 都沒有其他前置條件。
    unsafe {
        if GetConsoleProcessList(&mut pids) == 1 {
            let _ = FreeConsole();
        }
    }
}
```

- [ ] **Step 6: 建置並手動驗證**

Run: `cargo build; cargo test`
Expected: 建置成功、所有測試 PASS

手動驗證（以一般權限開 PowerShell 執行 `cargo run`）：
1. 出現「選擇分析模式」對話框；按「靜態分析」後對話框關閉，工具列顯示「模式：靜態分析」。
2. 把 Task 13 測試產生的合成 `.msu`（或 `tests/samples` 中的真實 `.msu`）拖進視窗：狀態列出現進度與「取消」，完成後中央顯示元件數。
3. 語言選單切換為 English，所有文字立即改變。
4. 按「以系統管理員重新啟動」：出現 UAC；按「是」後新視窗以管理員啟動、直接分析同一個檔案，不再出現模式選擇框，工具列顯示「靜態分析 + 本機比對」。在 UAC 按「否」時，舊視窗顯示「無法以系統管理員身分重新啟動」。
5. 執行 `cargo run -- analyze <檔案>` 仍走 CLI。

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat: add GUI shell with startup mode chooser and background analysis

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 17: GUI 結果檢視（分類樹、表格、詳細資料、警告）

**Files:**
- Modify: `src/gui/results.rs`

**Interfaces:**
- Consumes: Task 16 的 `Results` 骨架；`risk::rule`；`i18n::*`
- Produces: `Results::{summary_bar, status_bar, ui}` 完整實作；`Results::kind_count(ActionKind) -> usize`（Task 18 使用）；`pub(crate) fn row_matches(...)`（可測試的篩選邏輯）

- [ ] **Step 1: 在 `src/gui/results.rs` 寫篩選邏輯的失敗測試**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::*;

    fn comp() -> Component {
        Component {
            identity: AssemblyIdentity { name: "Microsoft-Windows-Kernel".into(), ..Default::default() },
            ..Default::default()
        }
    }

    fn action(kind_file: bool, risk: Risk) -> Action {
        let detail = if kind_file {
            ActionDetail::File(FileAction { name: "ntoskrnl.exe".into(), destination: "$(runtime.system32)".into(), ..Default::default() })
        } else {
            ActionDetail::Service(ServiceAction { name: "EventLog".into(), ..Default::default() })
        };
        Action { risk, ..Action::new(detail) }
    }

    #[test]
    fn filters_by_tree_risk_and_search() {
        let c = comp();
        let all_risks = [true; 4];
        let file_high = action(true, Risk::High);
        let svc_low = action(false, Risk::Low);
        assert!(row_matches(&c, &file_high, TreeSel::All, &all_risks, ""));
        assert!(row_matches(&c, &file_high, TreeSel::HighRisk, &all_risks, ""));
        assert!(!row_matches(&c, &svc_low, TreeSel::HighRisk, &all_risks, ""));
        assert!(row_matches(&c, &svc_low, TreeSel::Kind(ActionKind::Service), &all_risks, ""));
        assert!(!row_matches(&c, &svc_low, TreeSel::Kind(ActionKind::File), &all_risks, ""));
        // Risk::ALL 順序為 High、Medium、Low、Info
        assert!(!row_matches(&c, &svc_low, TreeSel::All, &[true, true, false, true], ""));
        assert!(row_matches(&c, &file_high, TreeSel::All, &all_risks, "ntoskrnl"));
        assert!(row_matches(&c, &svc_low, TreeSel::All, &all_risks, "kernel"), "matches component name");
        assert!(!row_matches(&c, &svc_low, TreeSel::All, &all_risks, "zzz"));
    }
}
```

- [ ] **Step 2: 執行測試確認失敗**

Run: `cargo test --lib results`
Expected: 編譯失敗（`row_matches`、`TreeSel` 未定義）

- [ ] **Step 3: 以完整版本取代 `src/gui/results.rs`（保留 Step 1 的測試模組）**

```rust
//! 分析結果檢視：概要列、分類樹、虛擬捲動表格、詳細資料、警告視窗。

use std::collections::BTreeMap;
use std::path::PathBuf;

use eframe::egui;
use egui_extras::{Column, TableBuilder};

use crate::core::export::{warning_message, SizeModel};
use crate::core::model::*;
use crate::core::risk;
use crate::i18n::{
    kind_name, local_name, not_applicable_text, risk_name, signature_name, Lang,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TreeSel {
    All,
    HighRisk,
    Kind(ActionKind),
}

/// 篩選條件：分類樹選擇、風險勾選（依 `Risk::ALL` 順序）、搜尋字串（已轉小寫）。
pub(crate) fn row_matches(c: &Component, a: &Action, tree: TreeSel, risks: &[bool; 4], needle: &str) -> bool {
    let tree_ok = match tree {
        TreeSel::All => true,
        TreeSel::HighRisk => a.risk == Risk::High,
        TreeSel::Kind(k) => a.kind() == k,
    };
    let risk_idx = Risk::ALL.iter().position(|r| *r == a.risk).unwrap_or(0);
    tree_ok
        && risks[risk_idx]
        && (needle.is_empty()
            || a.detail.target().to_lowercase().contains(needle)
            || c.identity.name.to_lowercase().contains(needle))
}

fn risk_color(r: Risk, ui: &egui::Ui) -> egui::Color32 {
    match r {
        Risk::High => ui.visuals().error_fg_color,
        Risk::Medium => ui.visuals().warn_fg_color,
        Risk::Low => ui.visuals().text_color(),
        Risk::Info => ui.visuals().weak_text_color(),
    }
}

pub struct Results {
    pub path: PathBuf,
    pub report: AnalysisReport,
    pub size_model: SizeModel,
    rows: Vec<(u32, u32)>,
    filtered: Vec<usize>,
    tree: TreeSel,
    search: String,
    risks: [bool; 4],
    selected: Option<usize>,
    dirty: bool,
    show_warnings: bool,
    kind_counts: BTreeMap<ActionKind, usize>,
    high_count: usize,
}

impl Results {
    pub fn new(report: AnalysisReport, size_model: SizeModel, path: PathBuf) -> Self {
        let mut rows = Vec::with_capacity(report.action_count());
        let mut kind_counts = BTreeMap::new();
        let mut high_count = 0;
        for (ci, c) in report.components.iter().enumerate() {
            for (ai, a) in c.actions.iter().enumerate() {
                rows.push((ci as u32, ai as u32));
                *kind_counts.entry(a.kind()).or_default() += 1;
                if a.risk == Risk::High {
                    high_count += 1;
                }
            }
        }
        let filtered = (0..rows.len()).collect();
        Results {
            path,
            report,
            size_model,
            rows,
            filtered,
            tree: TreeSel::All,
            search: String::new(),
            risks: [true; 4],
            selected: None,
            dirty: false,
            show_warnings: false,
            kind_counts,
            high_count,
        }
    }

    pub fn kind_count(&self, k: ActionKind) -> usize {
        self.kind_counts.get(&k).copied().unwrap_or(0)
    }

    fn row(&self, i: usize) -> (&Component, &Action) {
        let (ci, ai) = self.rows[i];
        let c = &self.report.components[ci as usize];
        (c, &c.actions[ai as usize])
    }

    fn refilter(&mut self) {
        let needle = self.search.trim().to_lowercase();
        self.filtered = (0..self.rows.len())
            .filter(|&i| {
                let (c, a) = self.row(i);
                row_matches(c, a, self.tree, &self.risks, &needle)
            })
            .collect();
        if self.selected.is_some_and(|s| !self.filtered.contains(&s)) {
            self.selected = None;
        }
        self.dirty = false;
    }

    pub fn summary_bar(&self, ui: &mut egui::Ui, lang: Lang) {
        let t = lang.strings();
        let r = &self.report;
        let p = &r.package;
        ui.horizontal_wrapped(|ui| {
            ui.strong(p.kb.as_deref().unwrap_or("-"));
            ui.label(format!("· {}", p.release_type.as_deref().unwrap_or("-")));
            ui.label(format!("· {}", p.identity.arch));
            ui.label(format!("· {}: {}", t.restart, p.restart.as_deref().unwrap_or("-")));
            ui.label(format!("· {} {}", t.components, r.components.len()));
            ui.label(format!("· {} {}", t.actions, self.rows.len()));
            ui.colored_label(ui.visuals().error_fg_color, format!("· ⚠ {} {}", t.high_risk, self.high_count));
            let sig = &r.source.signature;
            let sig_text = format!(
                "· {}: {}{}",
                t.signature,
                signature_name(sig.status, lang),
                sig.signer.as_deref().map(|s| format!(" ({s})")).unwrap_or_default()
            );
            if sig.status == SignatureStatus::Valid {
                ui.label(sig_text);
            } else {
                ui.colored_label(ui.visuals().error_fg_color, sig_text);
            }
        });
        if let Some(ctx) = &r.local_context {
            if !ctx.applicable {
                let reason = ctx.not_applicable_reason.as_deref().unwrap_or("");
                ui.colored_label(ui.visuals().warn_fg_color, not_applicable_text(reason, lang));
            }
        }
    }

    pub fn status_bar(&mut self, ui: &mut egui::Ui, lang: Lang) {
        let t = lang.strings();
        ui.label(format!("{} · {} · {}", self.report.source.file, self.report.source.format, self.report.mode.code()));
        ui.separator();
        let n = self.report.warnings.len();
        let label = format!("{} {n}", t.warnings);
        if n == 0 {
            ui.label(label);
        } else if ui.link(label).clicked() {
            self.show_warnings = true;
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui, lang: Lang) {
        if self.dirty {
            self.refilter();
        }
        self.tree_panel(ui, lang);
        egui::Panel::right("details")
            .resizable(true)
            .default_size(360.0)
            .show(ui, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| self.details(ui, lang));
            });
        egui::CentralPanel::default_margins().show(ui, |ui| {
            self.filter_bar(ui, lang);
            self.table(ui, lang);
        });
        self.warnings_window(ui.ctx(), lang);
    }

    fn tree_panel(&mut self, ui: &mut egui::Ui, lang: Lang) {
        let t = lang.strings();
        egui::Panel::left("tree")
            .resizable(true)
            .default_size(200.0)
            .show(ui, |ui| {
                let mut sel = self.tree;
                ui.selectable_value(&mut sel, TreeSel::All, format!("{} ({})", t.tree_all, self.rows.len()));
                ui.selectable_value(&mut sel, TreeSel::HighRisk, format!("⚠ {} ({})", t.high_risk, self.high_count));
                ui.separator();
                for k in ActionKind::ALL {
                    let n = self.kind_count(k);
                    if n > 0 {
                        ui.selectable_value(&mut sel, TreeSel::Kind(k), format!("{} ({n})", kind_name(k, lang)));
                    }
                }
                if sel != self.tree {
                    self.tree = sel;
                    self.dirty = true;
                }
            });
    }

    fn filter_bar(&mut self, ui: &mut egui::Ui, lang: Lang) {
        let t = lang.strings();
        ui.horizontal(|ui| {
            let resp = ui.add(egui::TextEdit::singleline(&mut self.search).hint_text(t.search_hint).desired_width(260.0));
            if resp.changed() {
                self.dirty = true;
            }
            ui.separator();
            ui.label(t.col_risk);
            for (i, r) in Risk::ALL.iter().enumerate() {
                if ui.checkbox(&mut self.risks[i], risk_name(*r, lang)).changed() {
                    self.dirty = true;
                }
            }
            ui.label(format!("{} / {}", self.filtered.len(), self.rows.len()));
        });
        ui.add_space(4.0);
    }

    fn table(&mut self, ui: &mut egui::Ui, lang: Lang) {
        let t = lang.strings();
        let mut clicked = None;
        let local_mode = self.report.mode == Mode::StaticLocal;
        let mut builder = TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .sense(egui::Sense::click())
            .column(Column::initial(60.0).at_least(40.0))
            .column(Column::initial(110.0).at_least(60.0))
            .column(Column::remainder().at_least(200.0).clip(true))
            .column(Column::initial(240.0).at_least(80.0).clip(true));
        if local_mode {
            builder = builder.column(Column::initial(110.0).at_least(60.0));
        }
        builder
            .header(20.0, |mut h| {
                h.col(|ui| {
                    ui.strong(t.col_risk);
                });
                h.col(|ui| {
                    ui.strong(t.col_kind);
                });
                h.col(|ui| {
                    ui.strong(t.col_target);
                });
                h.col(|ui| {
                    ui.strong(t.col_component);
                });
                if local_mode {
                    h.col(|ui| {
                        ui.strong(t.col_local);
                    });
                }
            })
            .body(|body| {
                body.rows(18.0, self.filtered.len(), |mut row| {
                    let i = self.filtered[row.index()];
                    let (c, a) = self.row(i);
                    row.set_selected(self.selected == Some(i));
                    row.col(|ui| {
                        ui.colored_label(risk_color(a.risk, ui), risk_name(a.risk, lang));
                    });
                    row.col(|ui| {
                        ui.label(kind_name(a.kind(), lang));
                    });
                    row.col(|ui| {
                        ui.label(egui::RichText::new(a.detail.target()).monospace());
                    });
                    row.col(|ui| {
                        ui.label(&c.identity.name);
                    });
                    if local_mode {
                        row.col(|ui| {
                            if let Some(l) = &a.local {
                                ui.label(local_name(l.state, lang));
                            }
                        });
                    }
                    if row.response().clicked() {
                        clicked = Some(i);
                    }
                });
            });
        if clicked.is_some() {
            self.selected = clicked;
        }
    }

    fn details(&self, ui: &mut egui::Ui, lang: Lang) {
        let t = lang.strings();
        let Some(i) = self.selected else {
            ui.label(t.details_none);
            return;
        };
        let (c, a) = self.row(i);
        ui.heading(kind_name(a.kind(), lang));
        ui.label(egui::RichText::new(a.detail.target()).monospace());
        ui.colored_label(risk_color(a.risk, ui), format!("{}: {}", t.col_risk, risk_name(a.risk, lang)));
        if !a.rules.is_empty() {
            ui.add_space(6.0);
            ui.strong(t.details_rules);
            for id in &a.rules {
                if let Some(r) = risk::rule(id) {
                    ui.label(format!("• {} — {}", r.id, r.reason(lang)));
                }
            }
        }
        if let Some(l) = &a.local {
            ui.add_space(6.0);
            ui.label(format!(
                "{}: {}  {} → {}",
                t.col_local,
                local_name(l.state, lang),
                l.current.as_deref().unwrap_or("-"),
                l.incoming.as_deref().unwrap_or("-")
            ));
        }
        ui.add_space(6.0);
        ui.strong(t.details_component);
        ui.label(c.identity.display());
        ui.label(egui::RichText::new(&c.manifest).small());
        if !c.categories.is_empty() {
            ui.label(c.categories.join(", "));
        }
        if let Some(l) = &c.local {
            ui.label(local_name(l.state, lang));
        }
        ui.add_space(6.0);
        ui.strong(t.details_fields);
        let json = serde_json::to_string_pretty(&a.detail).unwrap_or_default();
        ui.add(
            egui::TextEdit::multiline(&mut json.as_str())
                .code_editor()
                .desired_width(f32::INFINITY),
        );
    }

    fn warnings_window(&mut self, ctx: &egui::Context, lang: Lang) {
        let t = lang.strings();
        let mut open = self.show_warnings;
        egui::Window::new(t.warnings)
            .open(&mut open)
            .default_size([640.0, 360.0])
            .show(ctx, |ui| {
                if self.report.warnings.is_empty() {
                    ui.label(t.no_warnings);
                }
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for w in &self.report.warnings {
                        ui.strong(warning_message(w.code, lang));
                        ui.label(egui::RichText::new(format!("{}\n{}", w.subject, w.detail)).small().monospace());
                        ui.separator();
                    }
                });
            });
        self.show_warnings = open;
    }
}
```

- [ ] **Step 4: 執行測試確認通過**

Run: `cargo test --lib results; cargo clippy --all-targets -- -D warnings`
Expected: PASS、無警告

- [ ] **Step 5: 手動驗證**

`cargo run`，載入合成 `.msu` 或真實樣本：
1. 概要列顯示 KB、版本類型、架構、重新開機、元件數、動作數、高風險數；未簽章檔的簽章欄為紅色。
2. 左側分類樹點「高風險」只剩高風險列；點「驅動程式」只剩驅動。
3. 搜尋框輸入 `acpiex` 立即篩選；取消勾選「低」後低風險列消失。
4. 點一列，右側顯示命中的規則與理由、所屬元件、完整欄位 JSON。
5. 狀態列「警告 N」可點開警告視窗。
6. 真實 LCU（數十萬列）捲動順暢。

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: GUI results view with category tree, virtual table and details

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 18: GUI 匯出對話框

**Files:**
- Modify: `src/gui/export_dialog.rs`

**Interfaces:**
- Consumes: `export::{build, to_json_string, now_rfc3339, Detail, ExportOptions}`、`Results::{report, size_model, kind_count}`、`i18n::{kind_name, detail_name}`
- Produces: 完整的 `ExportDialog`；`pub(crate) fn human_size(usize) -> String`；`pub(crate) fn default_file_name(&AnalysisReport, Detail) -> String`

- [ ] **Step 1: 寫失敗測試（`src/gui/export_dialog.rs` 測試模組）**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::{AnalysisReport, Mode};

    #[test]
    fn formats_sizes() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(2048), "2.0 KB");
        assert_eq!(human_size(5 * 1024 * 1024 + 300 * 1024), "5.3 MB");
    }

    #[test]
    fn builds_default_file_names() {
        let mut r = AnalysisReport::default();
        r.package.kb = Some("KB5129195".into());
        r.mode = Mode::StaticLocal;
        assert_eq!(default_file_name(&r, Detail::Risk), "KB5129195-static-local-risk.json");
        r.package.kb = None;
        r.source.file = "windows11.0-x64.msu".into();
        r.mode = Mode::Static;
        assert_eq!(default_file_name(&r, Detail::Full), "windows11.0-x64-static-full.json");
    }
}
```

- [ ] **Step 2: 執行測試確認失敗**

Run: `cargo test --lib export_dialog`
Expected: 編譯失敗

- [ ] **Step 3: 以完整版本取代 `src/gui/export_dialog.rs`（保留測試模組）**

```rust
//! 匯出 JSON 對話框：類別勾選、細節程度、即時預估大小、存檔、複製到剪貼簿。

use std::collections::BTreeSet;

use eframe::egui;

use super::results::Results;
use crate::core::export::{build, now_rfc3339, to_json_string, Detail, ExportOptions};
use crate::core::model::{ActionKind, AnalysisReport};
use crate::i18n::{detail_name, kind_name, Lang};

pub(crate) fn human_size(bytes: usize) -> String {
    const KB: f64 = 1024.0;
    let b = bytes as f64;
    if b < KB {
        format!("{bytes} B")
    } else if b < KB * KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{:.1} MB", b / KB / KB)
    }
}

pub(crate) fn default_file_name(report: &AnalysisReport, detail: Detail) -> String {
    let stem = report.package.kb.clone().unwrap_or_else(|| {
        std::path::Path::new(&report.source.file)
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "report".into())
    });
    format!("{stem}-{}-{}.json", report.mode.code().replace('+', "-"), detail.code())
}

pub struct ExportDialog {
    open: bool,
    kinds: BTreeSet<ActionKind>,
    detail: Detail,
    message: Option<String>,
}

impl ExportDialog {
    pub fn new() -> Self {
        ExportDialog {
            open: true,
            kinds: ActionKind::ALL.into_iter().collect(),
            detail: Detail::Risk,
            message: None,
        }
    }

    pub fn is_open(&self) -> bool {
        self.open
    }

    pub fn show(&mut self, ctx: &egui::Context, lang: Lang, results: &Results) {
        let t = lang.strings();
        let mut open = self.open;
        egui::Window::new(t.export_title)
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.strong(t.export_kinds);
                ui.horizontal(|ui| {
                    if ui.small_button(t.select_all).clicked() {
                        self.kinds = ActionKind::ALL.into_iter().collect();
                    }
                    if ui.small_button(t.select_none).clicked() {
                        self.kinds.clear();
                    }
                });
                egui::Grid::new("export-kinds").num_columns(3).show(ui, |ui| {
                    for (i, k) in ActionKind::ALL.into_iter().enumerate() {
                        let mut on = self.kinds.contains(&k);
                        let label = format!("{} ({})", kind_name(k, lang), results.kind_count(k));
                        if ui.checkbox(&mut on, label).changed() {
                            if on {
                                self.kinds.insert(k);
                            } else {
                                self.kinds.remove(&k);
                            }
                        }
                        if i % 3 == 2 {
                            ui.end_row();
                        }
                    }
                });
                ui.separator();
                ui.strong(t.export_detail);
                for d in Detail::ALL {
                    ui.radio_value(&mut self.detail, d, detail_name(d, lang));
                }
                let opts = ExportOptions {
                    kinds: self.kinds.clone(),
                    detail: self.detail,
                    lang,
                };
                ui.label(format!("{} {}", t.estimated_size, human_size(results.size_model.estimate(&opts))));
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button(t.export_save).clicked() {
                        self.save(results, &opts);
                    }
                    if ui.button(t.export_copy).clicked() {
                        let summary = ExportOptions::all(Detail::Risk, lang);
                        ctx.copy_text(to_json_string(&build(&results.report, &summary, &now_rfc3339())));
                        self.message = Some(t.copied.to_string());
                    }
                });
                if let Some(m) = &self.message {
                    ui.label(m);
                }
            });
        self.open = open;
    }

    fn save(&mut self, results: &Results, opts: &ExportOptions) {
        let t = opts.lang.strings();
        let Some(path) = rfd::FileDialog::new()
            .add_filter("JSON", &["json"])
            .set_file_name(default_file_name(&results.report, opts.detail))
            .save_file()
        else {
            return;
        };
        let json = to_json_string(&build(&results.report, opts, &now_rfc3339()));
        self.message = Some(match std::fs::write(&path, json) {
            Ok(()) => format!("{} {}", t.saved_to, path.display()),
            Err(e) => format!("{}: {e}", path.display()),
        });
    }
}
```

- [ ] **Step 4: 執行測試確認通過**

Run: `cargo test --lib export_dialog; cargo clippy --all-targets -- -D warnings`
Expected: PASS、無警告

- [ ] **Step 5: 手動驗證**

`cargo run` 載入檔案後按「匯出 JSON…」：
1. 勾選 / 取消類別與切換細節程度時，「預估大小」立即變動。
2. 「另存新檔…」預設檔名為 `KBxxxx-static-risk.json`；存檔後訊息顯示路徑；用文字編輯器開啟，`export_filter` 與勾選一致。
3. 「複製摘要到剪貼簿」後貼到記事本，是 detail = risk 的 JSON。

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat: GUI export dialog with kind filter, detail level and size estimate

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 19: 真實資料驗證、README、CI、發佈

**Files:**
- Create: `tests/winsxs.rs`, `tests/samples.rs`, `docs/samples.md`, `README.md`, `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: 全部
- Produces: 以本機 WinSxS 與真實 `.msu` 驗證解析器；專案文件；CI

- [ ] **Step 1: 建立 `tests/winsxs.rs`（以本機 WinSxS 的真實 manifest 驗證解析器）**

```rust
//! 以本機 WinSxS 的真實 manifest 驗證解析器：前 3000 個一般測試執行，全部則用 --ignored。

use msu_inspector::core::delta::{is_dcm, DcmDecoder, DeltaEngine};
use msu_inspector::core::manifest::{decode_text, parse::parse_component};
use msu_inspector::core::model::ActionKind;
use msu_inspector::core::sys;

fn run(limit: usize) {
    let engine = DeltaEngine::system("msdelta.dll").unwrap();
    let dcm = DcmDecoder::from_system().unwrap();
    let dir = sys::windows_dir().join("WinSxS").join("Manifests");
    let (mut parsed, mut failed, mut actions, mut unknown) = (0usize, Vec::new(), 0usize, 0usize);
    for e in std::fs::read_dir(dir).unwrap().filter_map(Result::ok).take(limit) {
        let bytes = std::fs::read(e.path()).unwrap();
        if !is_dcm(&bytes) {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        let text = decode_text(&dcm.decode(&engine, &bytes).unwrap()).unwrap();
        match parse_component(&name, &text) {
            Ok(c) => {
                parsed += 1;
                actions += c.actions.len();
                unknown += c.actions.iter().filter(|a| a.kind() == ActionKind::Unknown).count();
            }
            Err(err) => failed.push(format!("{name}: {err}")),
        }
    }
    eprintln!("parsed {parsed}, failed {}, actions {actions}, unknown {unknown}", failed.len());
    assert!(failed.is_empty(), "{:#?}", &failed[..failed.len().min(20)]);
    assert!(unknown * 100 <= actions.max(1), "unknown actions exceed 1%: {unknown}/{actions}");
}

#[test]
fn parses_local_winsxs_manifests() {
    run(3000);
}

#[test]
#[ignore = "解析整個 WinSxS，約需一分鐘"]
fn parses_all_local_winsxs_manifests() {
    run(usize::MAX);
}
```

- [ ] **Step 2: 執行並處理結果**

Run: `cargo test --test winsxs; cargo test --test winsxs -- --ignored --nocapture`
Expected: 兩者 PASS。若 `unknown` 超過 1%，把輸出中最常見的未知元素名稱記下來，逐一判斷應歸入 `STRUCTURAL`（不是安裝動作）或 `ADVANCED_INSTALLERS`（會執行自訂程式碼），在 `parse.rs` 常數中補上後重跑；同時在 spec 第 4.2 節補上該元素。

- [ ] **Step 3: 建立 `docs/samples.md` 與 `tests/samples.rs`**

`docs/samples.md`：

```markdown
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
```

`tests/samples.rs`：

```rust
//! 真實樣本測試：設定 MSU_INSPECTOR_SAMPLES 才執行（見 docs/samples.md）。

use msu_inspector::core::analyze::{analyze, AnalyzeOptions};
use msu_inspector::core::export::{build, now_rfc3339, to_json_string, Detail, ExportOptions};
use msu_inspector::core::model::{Risk, WarningCode};
use msu_inspector::core::progress::Ctx;
use msu_inspector::core::CoreError;
use msu_inspector::i18n::Lang;

#[test]
fn analyzes_real_samples() {
    let Ok(dir) = std::env::var("MSU_INSPECTOR_SAMPLES") else {
        eprintln!("skipping: MSU_INSPECTOR_SAMPLES not set");
        return;
    };
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("msu") || e.eq_ignore_ascii_case("cab")))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no .msu / .cab in {dir}");
    for f in files {
        let started = std::time::Instant::now();
        let report = match analyze(&f, &AnalyzeOptions::default(), &Ctx::silent()) {
            Ok(r) => r,
            Err(CoreError::NeedsElevation(e)) => {
                eprintln!("{}: needs elevation ({e}); rerun as administrator", f.display());
                continue;
            }
            Err(e) => panic!("{}: {e}", f.display()),
        };
        let decode_fail = report
            .warnings
            .iter()
            .filter(|w| matches!(w.code, WarningCode::ManifestDecodeFailed | WarningCode::ManifestParseFailed))
            .count();
        let high = report.components.iter().flat_map(|c| &c.actions).filter(|a| a.risk == Risk::High).count();
        eprintln!(
            "{}: {} · {} components · {} actions · {high} high · {} warnings · {:?}",
            f.display(),
            report.source.format,
            report.components.len(),
            report.action_count(),
            report.warnings.len(),
            started.elapsed()
        );
        assert!(!report.components.is_empty(), "{}: no components", f.display());
        assert!(decode_fail * 100 <= report.components.len(), "{}: >1% manifests failed", f.display());
        let json = to_json_string(&build(&report, &ExportOptions::all(Detail::Full, Lang::En), &now_rfc3339()));
        std::fs::write(f.with_extension("full.json"), json).unwrap();
    }
}
```

- [ ] **Step 4: 下載樣本並執行（需要使用者協助或網路）**

依 `docs/samples.md` 下載樣本到 `D:\msu-samples`（此資料夾不在 repo 內），然後：

Run: `$env:MSU_INSPECTOR_SAMPLES = "D:\msu-samples"; cargo test --release --test samples -- --nocapture`
Expected: 每個檔案都列出元件數 > 0，解析失敗 ≤ 1%。24H2 樣本若在一般權限下出現 `needs elevation`，以系統管理員終端機再跑一次並確認通過，然後把結果（哪些格式需要管理員）補進 README 的「已知限制」。

若某種格式失敗，**停下來回報**失敗的檔案與錯誤訊息，不要自行改寫容器格式邏輯。

- [ ] **Step 5: 建立 `README.md`（中文在前、英文在後）**

```markdown
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
- （依 Task 19 樣本測試結果補充：哪些格式需要系統管理員權限才能展開）

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
- (Fill in from the Task 19 sample run: which formats require administrator rights to unpack)

## License

MIT
```

把「已知限制」中括號內的說明換成 Step 4 的實際結果（中英兩段都要改）。

- [ ] **Step 6: 建立 `.github/workflows/ci.yml`**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --check
      - run: cargo clippy --all-targets -- -D warnings
      - run: cargo test
```

- [ ] **Step 7: 完整驗證**

Run: `cargo fmt --check; cargo clippy --all-targets -- -D warnings; cargo test; cargo build --release`
Expected: 全部成功；`target\release\msu-inspector.exe` 存在

以 release exe 重做 Task 16–18 的手動驗證各一次（一般權限與系統管理員各一次）。

- [ ] **Step 8: Commit 並推送**

```bash
git add -A
git commit -m "docs: add README, sample test guide, real-data tests and CI

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git push origin main
```

推送後確認 GitHub Actions 的 CI 通過（`gh run watch`）。
