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
