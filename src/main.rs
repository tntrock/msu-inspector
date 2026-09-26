//! msu-inspector 進入點：無參數或只帶一個既有檔案 → GUI；其餘 → CLI。

use std::ffi::OsString;
use std::path::PathBuf;

fn main() {
    // 最先執行：之後以名稱動態載入的 DLL 只從 System32 搜尋
    restrict_dll_search();
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
/// （提升權限重新啟動、或把檔案拖到 exe 上時）。路徑轉成絕對路徑：
/// 以系統管理員重新啟動時工作目錄會變成 System32，相對路徑會失效。
fn gui_target(args: &[OsString]) -> Option<Option<PathBuf>> {
    match args.len() {
        1 => Some(None),
        2 => {
            let p = PathBuf::from(&args[1]);
            let p = std::path::absolute(&p).unwrap_or(p);
            p.is_file().then_some(Some(p))
        }
        _ => None,
    }
}

fn restrict_dll_search() {
    use windows::Win32::System::LibraryLoader::{
        SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };
    // SAFETY: 只設定本程序的 DLL 搜尋路徑，沒有其他前置條件。
    let _ = unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) };
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gui_file_argument_becomes_absolute() {
        // cargo test 的工作目錄是套件根目錄
        let args = [
            OsString::from("msu-inspector.exe"),
            OsString::from("Cargo.toml"),
        ];
        let Some(Some(p)) = gui_target(&args) else {
            panic!("existing file should open the GUI");
        };
        assert!(p.is_absolute(), "{}", p.display());
        assert!(p.is_file());
    }
}
