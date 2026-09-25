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
        if let Some(l) = std::env::var("MSU_INSPECTOR_LANG")
            .ok()
            .and_then(|v| Lang::parse(&v))
        {
            return l;
        }
        // SAFETY: 無參數、無副作用的查詢。
        let id = unsafe { windows::Win32::Globalization::GetUserDefaultUILanguage() };
        Lang::from_langid(id)
    }

    pub fn strings(self) -> &'static Strings {
        match self {
            Lang::ZhTw => &ZH_TW,
            Lang::En => &EN,
        }
    }
}

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
        CoreError::UnsupportedFormat(_) => pick(
            lang,
            "不支援的檔案格式（需要 .msu 或 .cab 更新檔）",
            "Unsupported file format (expects a .msu or .cab update)",
        ),
        CoreError::NeedsElevation(_) => pick(
            lang,
            "這個更新檔需要以系統管理員身分才能展開，請按「以系統管理員重新啟動」",
            "This package can only be unpacked as administrator; use \"Restart as administrator\"",
        ),
        CoreError::NoPackageFound => pick(
            lang,
            "檔案中找不到更新套件內容（.mum / .manifest）",
            "No update package content (.mum / .manifest) was found",
        ),
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
        Progress::Unpacking { container } => {
            format!("{} {container}", pick(lang, "展開", "Unpacking"))
        }
        Progress::Decoding { done, total } => format!(
            "{} {done}/{total}",
            pick(lang, "解析 manifest", "Parsing manifests")
        ),
        Progress::Comparing { done, total } => format!(
            "{} {done}/{total}",
            pick(lang, "與本機比對", "Comparing with this machine")
        ),
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
}
