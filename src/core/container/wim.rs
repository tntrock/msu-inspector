//! WIM 展開：wimgapi.dll（raw-dylib 連結，不需要 Windows SDK）。
//!
//! 以 WIM_MSG_PROCESS 回呼略過不需要的檔案，避免把 24H2 `.msu` 內數 GB 的 PSF 複製到暫存資料夾。

use std::ffi::c_void;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use windows::core::{HSTRING, PCWSTR};

use super::{is_reparse_point, is_within, role_at, Extracted, Item, ItemData, Role};
use crate::core::CoreError;

type Handle = *mut c_void;
type MessageCallback = unsafe extern "system" fn(u32, usize, isize, *mut c_void) -> u32;

#[link(name = "wimgapi", kind = "raw-dylib")]
extern "system" {
    fn WIMCreateFile(
        path: PCWSTR,
        access: u32,
        disposition: u32,
        flags: u32,
        compression: u32,
        result: *mut u32,
    ) -> Handle;
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
const WIM_MSG: u32 = 0x8000 + 0x1476;
const WIM_MSG_PROCESS: u32 = WIM_MSG + 3;
const WIM_MSG_SUCCESS: u32 = 0;
const WIM_MSG_ABORT_IMAGE: u32 = 0xFFFF_FFFF;
/// `WIMRegisterMessageCallback` returns this on failure.
const INVALID_CALLBACK_VALUE: u32 = 0xFFFF_FFFF;

const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_PRIVILEGE_NOT_HELD: u32 = 1314;

struct CallbackCtx<'a> {
    cancel: &'a AtomicBool,
    want: &'a dyn Fn(Role) -> bool,
    skipped: Vec<(String, Role)>,
    out_dir: &'a Path,
    vprefix: &'a str,
}

/// 看起來像「檔名」：有 1-8 字元的英數副檔名，且不全是數字（目錄名稱常帶版本號）。
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

unsafe extern "system" fn on_message(
    msg: u32,
    wparam: usize,
    lparam: isize,
    user: *mut c_void,
) -> u32 {
    if msg != WIM_MSG_PROCESS {
        return WIM_MSG_SUCCESS;
    }
    // SAFETY: `user` was set to `&mut ctx as *mut CallbackCtx as *mut c_void` in `extract`
    // and stays valid for the whole registration/apply span below.
    let ctx = unsafe { &mut *(user as *mut CallbackCtx) };
    if ctx.cancel.load(Ordering::Relaxed) {
        return WIM_MSG_ABORT_IMAGE;
    }
    // SAFETY: wimgapi passes a valid null-terminated UTF-16 string as wParam for
    // WIM_MSG_PROCESS, valid for the duration of this callback invocation.
    let path = unsafe { PCWSTR(wparam as *const u16).to_string() }.unwrap_or_default();
    let full = Path::new(&path);
    let name = full
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if !looks_like_file(&name) {
        return WIM_MSG_SUCCESS; // 目錄或無副檔名的檔案：保留
    }
    let vpath = vpath_of(ctx, full);
    let role = role_at(&vpath);
    if role == Role::Ignore || !(ctx.want)(role) {
        if role != Role::Ignore {
            ctx.skipped.push((vpath, role));
        }
        // SAFETY: lParam points to a BOOL owned by wimgapi for the duration of this
        // callback. Writing 0 (FALSE) tells wimgapi to skip applying this file — this
        // matches Microsoft's own Convert-WindowsImage.ps1 SkipFile() helper, which
        // writes FALSE (0) to lParam to skip a file (TRUE/1 keeps it).
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
            detail: format!(
                "wimgapi error {code}: {}",
                windows::core::Error::from_hresult(windows::core::HRESULT::from_win32(code))
            ),
        },
    }
}

fn last_error() -> u32 {
    // SAFETY: no arguments; reads the calling thread's last-error code.
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
    // SAFETY: all handles opened below are closed before this block ends; `ctx` stays
    // alive (owned by this stack frame) for the whole registration/apply span, and the
    // pointer registered with WIMRegisterMessageCallback is unregistered before `ctx`
    // is dropped.
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
        let mut registered = false;
        let result = (|| {
            if WIMSetTemporaryPath(h, PCWSTR(HSTRING::from(tmp.as_os_str()).as_ptr())) == 0 {
                return Err(map_error(last_error(), vprefix));
            }
            let cb = WIMRegisterMessageCallback(
                h,
                on_message,
                &mut ctx as *mut CallbackCtx as *mut c_void,
            );
            if cb == INVALID_CALLBACK_VALUE {
                return Err(map_error(last_error(), vprefix));
            }
            registered = true;
            let count = WIMGetImageCount(h);
            for index in 1..=count {
                // Create the destination directory before loading the image, so a
                // failure here cannot leak the WIMLoadImage handle.
                let dest = out_dir.join(index.to_string());
                std::fs::create_dir_all(&dest).map_err(|e| CoreError::io(&dest, e))?;
                let img = WIMLoadImage(h, index);
                if img.is_null() {
                    return Err(map_error(last_error(), vprefix));
                }
                let ok = WIMApplyImage(
                    img,
                    PCWSTR(HSTRING::from(dest.as_os_str()).as_ptr()),
                    // 不加 WIM_FLAG_NO_RP_FIX：讓 wimgapi 把絕對連結目標修正到展開資料夾內
                    WIM_FLAG_NO_DIRACL | WIM_FLAG_NO_FILEACL,
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
        if registered {
            WIMUnregisterMessageCallback(h, on_message);
        }
        WIMCloseHandle(h);
        result?;
    }
    let _ = std::fs::remove_dir_all(&tmp);

    let mut out = Extracted {
        items: Vec::new(),
        skipped: ctx.skipped,
    };
    collect_files(out_dir, out_dir, vprefix, want, &mut out.items)?;
    Ok(out)
}

/// 走訪展開結果，把需要的檔案轉成 Item；小檔讀進記憶體後刪除。
///
/// `want` is re-applied here (not just in the `WIM_MSG_PROCESS` callback) so that any
/// unwanted-role file that ends up on disk regardless — e.g. because a future wimgapi
/// quirk applies it despite the callback's skip signal — never becomes an `Item`.
///
/// WIM 可能帶有符號連結／目錄連接（WIMApplyImage 會還原重新剖析點）：一律略過、不跟隨，
/// 並確認每個走訪的資料夾實際位於 `root` 之下，因此只會讀取／刪除暫存資料夾內的檔案。
pub fn collect_files(
    root: &Path,
    dir: &Path,
    vprefix: &str,
    want: &dyn Fn(Role) -> bool,
    items: &mut Vec<Item>,
) -> Result<(), CoreError> {
    if !is_within(dir, root) {
        return Ok(());
    }
    for e in std::fs::read_dir(dir).map_err(|e| CoreError::io(dir, e))? {
        let e = e.map_err(|e| CoreError::io(dir, e))?;
        let path = e.path();
        let meta = std::fs::symlink_metadata(&path).map_err(|e| CoreError::io(&path, e))?;
        if is_reparse_point(&meta) {
            continue;
        }
        if meta.is_dir() {
            collect_files(root, &path, vprefix, want, items)?;
            continue;
        }
        if !meta.is_file() {
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
        let role = role_at(&vpath);
        if role == Role::Ignore || !want(role) {
            continue;
        }
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
    // SAFETY: same as `extract` — handles are closed before returning.
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
