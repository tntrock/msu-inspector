//! 系統管理員模式下的拖放。
//!
//! winit 以 OLE（RegisterDragDrop）接收拖放；UIPI 會擋掉一般權限的檔案總管拖到提升權限的視窗，
//! 游標只會顯示「禁止」。此時改用舊式的 WM_DROPFILES，並以 ChangeWindowMessageFilterEx
//! 放行相關訊息；子類別化視窗程序接收檔案路徑，下一個影格由 `take()` 取出。

use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use eframe::egui;
use windows::core::BOOL;
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::Shell::{
    DefSubclassProc, DragAcceptFiles, DragFinish, DragQueryFileW, SetWindowSubclass, HDROP,
};
use windows::Win32::UI::WindowsAndMessaging::{
    ChangeWindowMessageFilterEx, EnumThreadWindows, IsWindowVisible, MSGFLT_ALLOW, WM_COPYDATA,
    WM_DROPFILES,
};

/// 未公開於 windows crate 的 WM_COPYGLOBALDATA；UIPI 下拖放必須一併放行。
const WM_COPYGLOBALDATA: u32 = 0x0049;
const SUBCLASS_ID: usize = 0x4D53_5549; // "MSUI"

static DROPPED: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());
static REPAINT: OnceLock<egui::Context> = OnceLock::new();

/// 在目前執行緒找出第一個可見的頂層視窗（eframe 的主視窗建立在 GUI 執行緒上）。
fn main_window() -> Option<HWND> {
    unsafe extern "system" fn pick(hwnd: HWND, lparam: LPARAM) -> BOOL {
        // SAFETY: lparam 指向呼叫端堆疊上的 Option<HWND>，列舉期間有效。
        unsafe {
            if IsWindowVisible(hwnd).as_bool() {
                *(lparam.0 as *mut Option<HWND>) = Some(hwnd);
                return BOOL(0); // 找到了，停止列舉
            }
        }
        BOOL(1)
    }
    let mut found: Option<HWND> = None;
    // SAFETY: 回呼只寫入 found；EnumThreadWindows 同步執行，返回前 found 都有效。
    unsafe {
        let _ = EnumThreadWindows(
            GetCurrentThreadId(),
            Some(pick),
            LPARAM(&mut found as *mut Option<HWND> as isize),
        );
    }
    found
}

unsafe extern "system" fn subclass_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _id: usize,
    _data: usize,
) -> LRESULT {
    if msg == WM_DROPFILES {
        let hdrop = HDROP(wparam.0 as *mut _);
        // SAFETY: WM_DROPFILES 的 wParam 是系統配置的 HDROP，處理完以 DragFinish 釋放。
        unsafe {
            let count = DragQueryFileW(hdrop, u32::MAX, None);
            let mut paths = Vec::new();
            for i in 0..count {
                let len = DragQueryFileW(hdrop, i, None) as usize;
                let mut buf = vec![0u16; len + 1];
                let n = DragQueryFileW(hdrop, i, Some(&mut buf)) as usize;
                paths.push(PathBuf::from(String::from_utf16_lossy(&buf[..n])));
            }
            DragFinish(hdrop);
            if let Ok(mut q) = DROPPED.lock() {
                q.extend(paths);
            }
        }
        if let Some(ctx) = REPAINT.get() {
            ctx.request_repaint();
        }
        return LRESULT(0);
    }
    // SAFETY: 其餘訊息交還原本的視窗程序。
    unsafe { DefSubclassProc(hwnd, msg, wparam, lparam) }
}

/// 在主視窗上啟用 WM_DROPFILES 拖放；找不到視窗或安裝失敗時回傳 false。
pub fn install(ctx: &egui::Context) -> bool {
    let Some(hwnd) = main_window() else {
        return false;
    };
    let _ = REPAINT.set(ctx.clone());
    // SAFETY: hwnd 為本程序在目前執行緒建立的視窗；子類別程序為 'static 函式。
    unsafe {
        for msg in [WM_DROPFILES, WM_COPYDATA, WM_COPYGLOBALDATA] {
            let _ = ChangeWindowMessageFilterEx(hwnd, msg, MSGFLT_ALLOW, None);
        }
        if !SetWindowSubclass(hwnd, Some(subclass_proc), SUBCLASS_ID, 0).as_bool() {
            return false;
        }
        DragAcceptFiles(hwnd, true);
    }
    true
}

/// 取出上次影格之後拖入的檔案。
pub fn take() -> Vec<PathBuf> {
    DROPPED
        .lock()
        .map(|mut q| std::mem::take(&mut *q))
        .unwrap_or_default()
}
