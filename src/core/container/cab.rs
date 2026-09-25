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
    fdintCLOSE_FILE_INFO, fdintCOPY_FILE, fdintNEXT_CABINET, FDICopy, FDICreate, FDIDestroy, ERF,
    FDICREATE_CPU_TYPE, FDINOTIFICATION, FDINOTIFICATIONTYPE,
};
use windows::Win32::System::Memory::{GetProcessHeap, HeapAlloc, HeapFree, HEAP_FLAGS};

use super::{role_of, Extracted, Item, ItemData, Role};
use crate::core::CoreError;

/// FDI 回呼中的「檔案代號」：指向此列舉的 Box 指標。
enum Handle {
    Read(File),
    Memory {
        vpath: String,
        buf: Vec<u8>,
    },
    Disk {
        vpath: String,
        path: PathBuf,
        file: File,
    },
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
    // SAFETY: 回呼只操作本模組建立的 Handle；ctx 在 FDICopy 期間有效，其位址以
    // *const c_void 傳入 pvUser，於各回呼中還原為 &mut Ctx。
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
        .map(|c| {
            if c.is_alphanumeric() || ".-_".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect()
}

// windows 0.62 的 FDINOTIFICATIONTYPE 常數（`fdintCOPY_FILE` 等）沿用 Win32 原始命名，非本專案風格。
#[allow(non_upper_case_globals)]
unsafe extern "system" fn fdi_notify(
    kind: FDINOTIFICATIONTYPE,
    pfdin: *mut FDINOTIFICATION,
) -> isize {
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
