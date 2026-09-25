//! 權限：是否為系統管理員、以 UAC（runas）重新啟動自己。

use std::path::Path;

use windows::core::{w, HSTRING, PCWSTR};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

pub use crate::core::sys::is_elevated;

/// 重新啟動時帶入目前的檔案路徑（加上引號，路徑可含空白）。
pub fn params_for(file: Option<&Path>) -> String {
    file.map(|f| format!("\"{}\"", f.display()))
        .unwrap_or_default()
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
        assert_eq!(
            params_for(Some(Path::new(r"D:\下載\KB 1.msu"))),
            "\"D:\\下載\\KB 1.msu\""
        );
    }
}
