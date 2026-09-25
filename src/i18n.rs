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
