//! 系統資訊：Windows 目錄、原生處理器架構。

use std::path::PathBuf;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::SystemInformation::{
    GetNativeSystemInfo, GetSystemWindowsDirectoryW, PROCESSOR_ARCHITECTURE_AMD64,
    PROCESSOR_ARCHITECTURE_ARM64, PROCESSOR_ARCHITECTURE_INTEL, SYSTEM_INFO,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// 系統的 Windows 資料夾。不讀 `SystemRoot` 環境變數：它可被呼叫端任意設定，
/// 會讓 DCM 基底（wcp.dll）與本機比對讀到假的 WinSxS。
pub fn windows_dir() -> PathBuf {
    let mut buf = [0u16; 260];
    // SAFETY: 緩衝區長度正確；回傳值為寫入的字元數（不含結尾 NUL），失敗或不足時另行處理。
    let n = unsafe { GetSystemWindowsDirectoryW(Some(&mut buf)) } as usize;
    if n == 0 || n >= buf.len() {
        return PathBuf::from(r"C:\Windows");
    }
    PathBuf::from(String::from_utf16_lossy(&buf[..n]))
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
