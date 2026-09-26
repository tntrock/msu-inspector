//! CAB 解壓：cabinet.dll 的 FDI。單次循序解壓，於 fdintCOPY_FILE 只挑需要的檔案。
//!
//! FDI 以 ANSI 字串傳遞路徑，但實際開檔由我們的 `fdi_open` 回呼負責；
//! 我們傳入 UTF-8 位元組、在回呼中以 UTF-8 解碼，因此路徑含中文也能開啟。

use std::cell::{Cell, RefCell};
use std::collections::HashSet;
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

use super::{role_at, Extracted, Item, ItemData, Role};
use crate::core::CoreError;

/// 留在記憶體的單一項目上限（位元組）；超過即以 Container 錯誤中止該 CAB。
pub const MAX_MEMORY_ITEM: u64 = 64 * 1024 * 1024;

/// FDI 回呼中的「檔案代號」：指向此列舉的 Box 指標。
///
/// 擁有權規則：代號建立時登記於 `LIVE`，由「先把它從 `LIVE` 移除的一方」釋放。
/// cabinet.dll 在資料損毀等錯誤時，會先以 pfnclose 關閉 fdintCOPY_FILE 的輸出代號，
/// 之後 FDICopy 才回傳 FALSE；因此 `extract` 收尾時只釋放仍登記在案的輸出代號，
/// 絕不重複釋放。
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

thread_local! {
    /// 本執行緒中尚未釋放的代號。FDI 回呼與 FDICopy 在同一執行緒同步執行，
    /// 且 `extract` 不會在回呼中重入，所以用執行緒區域集合追蹤即可。
    static LIVE: RefCell<HashSet<isize>> = RefCell::new(HashSet::new());
    /// 目前開啟、尚未收到 CLOSE_FILE_INFO 的輸出代號（FDICopy 中止時由 `extract` 釋放）。
    static OPEN_OUTPUT: Cell<Option<isize>> = const { Cell::new(None) };
}

/// 把 Handle 放到堆積並登記，回傳代號。
fn register(h: Handle) -> isize {
    let hf = Box::into_raw(Box::new(h)) as isize;
    LIVE.with_borrow_mut(|l| l.insert(hf));
    hf
}

fn is_live(hf: isize) -> bool {
    LIVE.with_borrow(|l| l.contains(&hf))
}

/// 若代號仍登記在案，取回其擁有權並移除登記；已釋放或未知的代號回傳 None。
fn unregister(hf: isize) -> Option<Box<Handle>> {
    if !LIVE.with_borrow_mut(|l| l.remove(&hf)) {
        return None;
    }
    if OPEN_OUTPUT.get() == Some(hf) {
        OPEN_OUTPUT.set(None);
    }
    // SAFETY: hf 由 register 以 Box::into_raw 產生，且剛從 LIVE 移除，
    // 所以這是唯一一次取回擁有權。
    Some(unsafe { Box::from_raw(hf as *mut Handle) })
}

/// 釋放未完成的代號；寫到磁碟的部分輸出檔一併刪除。
fn discard(h: Handle) {
    if let Handle::Disk { path, file, .. } = h {
        drop(file);
        let _ = std::fs::remove_file(path);
    }
}

struct Ctx<'a> {
    vprefix: &'a str,
    out_dir: &'a Path,
    cancel: &'a AtomicBool,
    want: &'a dyn Fn(Role) -> bool,
    out: Extracted,
    counter: usize,
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
    // 相對路徑 `x.cab` 的 parent 為空字串；FDI 需要「目錄 + 檔名」，空目錄改用 `.`
    let dir = match cab.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
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
        error: None,
    };
    let mut erf = ERF::default();
    OPEN_OUTPUT.set(None);
    // SAFETY: 傳給 FDICreate 的回呼都是本模組的 extern "system" 函式，只操作本模組
    // 建立並登記於 LIVE 的 Handle；erf 在 hfdi 存續期間（至 FDIDestroy）有效。
    let hfdi = unsafe {
        FDICreate(
            Some(fdi_alloc),
            Some(fdi_free),
            Some(fdi_open),
            Some(fdi_read),
            Some(fdi_write),
            Some(fdi_close),
            Some(fdi_seek),
            FDICREATE_CPU_TYPE(1), // cpu80386：保護模式
            &mut erf,
        )
    };
    if hfdi.is_null() {
        return Err(container_err("FDICreate failed".into()));
    }
    // SAFETY: name / dir 為以 NUL 結尾的 CString，呼叫期間有效；ctx 在 FDICopy 同步
    // 執行期間有效，其位址以 pvUser 傳入並於 fdi_notify 還原為 &mut Ctx，
    // 此期間本函式不另外存取 ctx。
    let ok = unsafe {
        FDICopy(
            hfdi,
            PCSTR(name.as_ptr().cast()),
            PCSTR(dir.as_ptr().cast()),
            0,
            Some(fdi_notify),
            None,
            Some(&mut ctx as *mut Ctx as *const c_void),
        )
    };
    // SAFETY: hfdi 由上方 FDICreate 成功建立，之後不再使用。
    let _ = unsafe { FDIDestroy(hfdi) };
    // FDI 可能已自行以 pfnclose 關閉輸出代號（此時已不在 LIVE），只釋放仍登記者
    if let Some(h) = OPEN_OUTPUT.take().and_then(unregister) {
        discard(*h);
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
    Ok(ctx.out)
}

unsafe extern "system" fn fdi_alloc(cb: u32) -> *mut c_void {
    // SAFETY: GetProcessHeap / HeapAlloc 沒有前置條件；失敗回傳 null，由 FDI 處理。
    unsafe {
        match GetProcessHeap() {
            Ok(heap) => HeapAlloc(heap, HEAP_FLAGS(0), cb as usize),
            Err(_) => std::ptr::null_mut(),
        }
    }
}

unsafe extern "system" fn fdi_free(pv: *const c_void) {
    // SAFETY: FDI 只把先前由 fdi_alloc（同一個程序堆積）配置的指標交給 pfnfree。
    unsafe {
        if let Ok(heap) = GetProcessHeap() {
            let _ = HeapFree(heap, HEAP_FLAGS(0), Some(pv));
        }
    }
}

unsafe extern "system" fn fdi_open(path: PCSTR, _oflag: i32, _pmode: i32) -> isize {
    // SAFETY: FDI 傳入以 NUL 結尾的路徑（由我們交給 FDICopy 的 dir + name 組成）。
    let path = unsafe { CStr::from_ptr(path.0.cast()) };
    let Ok(path) = path.to_str() else {
        return -1;
    };
    match File::open(path) {
        Ok(f) => register(Handle::Read(f)),
        Err(_) => -1,
    }
}

unsafe extern "system" fn fdi_read(hf: isize, pv: *mut c_void, cb: u32) -> u32 {
    if !is_live(hf) {
        return u32::MAX;
    }
    // SAFETY: hf 仍登記於 LIVE，指向有效的 Handle，且 FDI 不會同時對同一代號做其他操作；
    // pv 為 FDI 提供、至少 cb 位元組的可寫緩衝區。
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
    if !is_live(hf) {
        return u32::MAX;
    }
    // SAFETY: hf 仍登記於 LIVE，指向有效的 Handle；pv 為 FDI 提供、長度 cb 的資料。
    let h = unsafe { &mut *(hf as *mut Handle) };
    let data = unsafe { std::slice::from_raw_parts(pv as *const u8, cb as usize) };
    match h {
        Handle::Memory { buf, .. } => {
            if (buf.len() + data.len()) as u64 > MAX_MEMORY_ITEM {
                return u32::MAX;
            }
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

/// FDI 關閉自己以 pfnopen 開啟的 cabinet；錯誤時也會關閉 fdintCOPY_FILE 的輸出代號
/// （未完成的輸出，部分檔案一併刪除）。未登記的代號視為已釋放，不再處理。
unsafe extern "system" fn fdi_close(hf: isize) -> i32 {
    match unregister(hf) {
        Some(h) => {
            discard(*h);
            0
        }
        None => -1,
    }
}

unsafe extern "system" fn fdi_seek(hf: isize, dist: i32, seektype: i32) -> i32 {
    if !is_live(hf) {
        return -1;
    }
    // SAFETY: hf 仍登記於 LIVE，指向有效的 Handle，且 FDI 不會同時對同一代號做其他操作。
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
    // SAFETY: pfdin 由 FDI 提供、在本次回呼期間有效；n.pv 即 extract 交給 FDICopy 的
    // pvUser（&mut Ctx），FDICopy 執行期間 extract 不會另外存取 ctx。
    let n = unsafe { &mut *pfdin };
    let ctx = unsafe { &mut *(n.pv as *mut Ctx) };
    match kind {
        fdintCOPY_FILE => {
            if ctx.cancel.load(Ordering::Relaxed) {
                return -1;
            }
            // SAFETY: fdintCOPY_FILE 的 psz1 為 CAB 內以 NUL 結尾的檔名。
            let raw = unsafe { CStr::from_ptr(n.psz1.0.cast()) }.to_bytes();
            let inner = String::from_utf8_lossy(raw).replace('\\', "/");
            let base = inner.rsplit('/').next().unwrap_or(&inner).to_string();
            let vpath = format!("{}/{inner}", ctx.vprefix);
            let role = role_at(&inner);
            if role == Role::Ignore {
                return 0;
            }
            if !(ctx.want)(role) {
                ctx.out.skipped.push((vpath, role));
                return 0;
            }
            let size = n.cb.max(0) as u64;
            if !role.to_disk() && size > MAX_MEMORY_ITEM {
                ctx.error = Some(format!(
                    "{vpath}: entry too large ({size} bytes > {MAX_MEMORY_ITEM})"
                ));
                return -1;
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
                    buf: Vec::with_capacity(size.min(MAX_MEMORY_ITEM) as usize),
                }
            };
            let h = register(handle);
            OPEN_OUTPUT.set(Some(h));
            h
        }
        fdintCLOSE_FILE_INFO => {
            // 已被 pfnclose 釋放（或未知）的代號不再處理
            let Some(h) = unregister(n.hf) else {
                return -1;
            };
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
