//! msdelta.dll 的 PA30 差異套用與 DCM manifest 解壓。
//!
//! DLL 以 LoadLibraryExW + GetProcAddress 從 System32 動態載入，不需要 import library。

use std::ffi::c_void;
use std::path::{Path, PathBuf};

use windows::core::{s, HSTRING, PCWSTR};
use windows::Win32::Foundation::{FreeLibrary, HMODULE};
use windows::Win32::System::LibraryLoader::{
    FindResourceW, GetProcAddress, LoadLibraryExW, LoadResource, LockResource, SizeofResource,
    LOAD_LIBRARY_AS_DATAFILE, LOAD_LIBRARY_AS_IMAGE_RESOURCE, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

use super::model::parse_version;
use super::{sys, CoreError};

#[repr(C)]
#[derive(Clone, Copy)]
struct DeltaInput {
    start: *const c_void,
    size: usize,
    editable: i32,
}

impl DeltaInput {
    fn of(buf: &[u8]) -> Self {
        DeltaInput {
            start: if buf.is_empty() {
                std::ptr::null()
            } else {
                buf.as_ptr().cast()
            },
            size: buf.len(),
            editable: 0,
        }
    }
}

#[repr(C)]
struct DeltaOutput {
    start: *mut c_void,
    size: usize,
}

type ApplyDeltaBFn =
    unsafe extern "system" fn(i64, DeltaInput, DeltaInput, *mut DeltaOutput) -> i32;
type DeltaFreeFn = unsafe extern "system" fn(*mut c_void) -> i32;

pub struct DeltaEngine {
    module: HMODULE,
    apply: ApplyDeltaBFn,
    free: DeltaFreeFn,
}

// SAFETY: 只保存函式指標與模組代號；ApplyDeltaB 不依賴呼叫執行緒的狀態。
unsafe impl Send for DeltaEngine {}
unsafe impl Sync for DeltaEngine {}

impl Drop for DeltaEngine {
    fn drop(&mut self) {
        // SAFETY: module 由本結構載入並獨占。
        unsafe {
            let _ = FreeLibrary(self.module);
        }
    }
}

impl DeltaEngine {
    /// 從 System32 載入 msdelta.dll。
    pub fn msdelta() -> Result<Self, CoreError> {
        // SAFETY: 只從 System32 載入；函式指標依 msdelta.h 的原型轉型。
        unsafe {
            let module = LoadLibraryExW(
                &HSTRING::from("msdelta.dll"),
                None,
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
            .map_err(|e| CoreError::Delta(format!("msdelta.dll: {e}")))?;
            match (
                GetProcAddress(module, s!("ApplyDeltaB")),
                GetProcAddress(module, s!("DeltaFree")),
            ) {
                (Some(a), Some(f)) => Ok(DeltaEngine {
                    module,
                    apply: std::mem::transmute::<unsafe extern "system" fn() -> isize, ApplyDeltaBFn>(
                        a,
                    ),
                    free: std::mem::transmute::<unsafe extern "system" fn() -> isize, DeltaFreeFn>(
                        f,
                    ),
                }),
                _ => {
                    let _ = FreeLibrary(module);
                    Err(CoreError::Delta(
                        "msdelta.dll: ApplyDeltaB / DeltaFree not exported".into(),
                    ))
                }
            }
        }
    }

    /// 套用 PA30 差異；`source` 為空代表 null-source（完整壓縮）差異。
    pub fn apply(&self, source: &[u8], delta: &[u8]) -> Result<Vec<u8>, CoreError> {
        let mut out = DeltaOutput {
            start: std::ptr::null_mut(),
            size: 0,
        };
        // SAFETY: 輸入緩衝區在呼叫期間有效；輸出由 DeltaFree 釋放。
        unsafe {
            if (self.apply)(0, DeltaInput::of(source), DeltaInput::of(delta), &mut out) == 0 {
                return Err(CoreError::Delta(format!(
                    "msdelta.dll: ApplyDeltaB failed ({})",
                    windows::core::Error::from_thread()
                )));
            }
            if out.start.is_null() {
                // 成功但輸出為空：無記憶體可釋放。
                return Ok(Vec::new());
            }
            let v = std::slice::from_raw_parts(out.start as *const u8, out.size).to_vec();
            (self.free)(out.start);
            Ok(v)
        }
    }
}

pub const DCM_MAGIC: &[u8; 4] = b"DCM\x01";

pub fn is_dcm(bytes: &[u8]) -> bool {
    bytes.starts_with(DCM_MAGIC)
}

/// DCM manifest 解碼器：持有 wcp.dll 內嵌的基底 manifest。
pub struct DcmDecoder {
    base: Vec<u8>,
}

impl DcmDecoder {
    pub fn with_base(base: Vec<u8>) -> Self {
        DcmDecoder { base }
    }

    /// 從本機最新版 servicing stack 的 wcp.dll 讀取基底。
    pub fn from_system() -> Result<Self, CoreError> {
        let wcp = find_wcp_dll()?;
        Ok(DcmDecoder {
            base: load_base_resource(&wcp)?,
        })
    }

    pub fn base(&self) -> &[u8] {
        &self.base
    }

    pub fn decode(&self, engine: &DeltaEngine, bytes: &[u8]) -> Result<Vec<u8>, CoreError> {
        if !is_dcm(bytes) {
            return Ok(bytes.to_vec());
        }
        if self.base.is_empty() {
            return Err(CoreError::Delta("DCM base manifest unavailable".into()));
        }
        engine.apply(&self.base, &bytes[DCM_MAGIC.len()..])
    }
}

/// `WinSxS\<arch>_microsoft-windows-servicingstack_<token>_<version>_...\wcp.dll` 中版本最新者。
fn find_wcp_dll() -> Result<PathBuf, CoreError> {
    let winsxs = sys::windows_dir().join("WinSxS");
    let prefix = format!("{}_microsoft-windows-servicingstack_", sys::native_arch());
    let entries = std::fs::read_dir(&winsxs).map_err(|e| CoreError::io(&winsxs, e))?;
    let mut best: Option<([u32; 4], PathBuf)> = None;
    for e in entries.filter_map(Result::ok) {
        let name = e.file_name().to_string_lossy().to_ascii_lowercase();
        if !name.starts_with(&prefix) {
            continue;
        }
        let Some(ver) = name.split('_').nth(3).and_then(parse_version) else {
            continue;
        };
        let dll = e.path().join("wcp.dll");
        if dll.is_file() && best.as_ref().is_none_or(|(v, _)| ver > *v) {
            best = Some((ver, dll));
        }
    }
    best.map(|(_, p)| p)
        .ok_or_else(|| CoreError::Delta("servicing stack wcp.dll not found".into()))
}

/// 讀取 wcp.dll 的資源（型別 0x266、ID 1）。
fn load_base_resource(path: &Path) -> Result<Vec<u8>, CoreError> {
    // SAFETY: 以資料檔方式載入，不執行任何程式碼；資源指標在 FreeLibrary 前有效。
    unsafe {
        let module = LoadLibraryExW(
            &HSTRING::from(path.as_os_str()),
            None,
            LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE,
        )
        .map_err(|e| CoreError::Delta(format!("{}: {e}", path.display())))?;
        let result = (|| {
            let res = FindResourceW(Some(module), PCWSTR(1 as _), PCWSTR(0x266 as _));
            if res.is_invalid() {
                return Err(CoreError::Delta(
                    "DCM base resource not found in wcp.dll".into(),
                ));
            }
            let size = SizeofResource(Some(module), res) as usize;
            let handle = LoadResource(Some(module), res)
                .map_err(|e| CoreError::Delta(format!("LoadResource: {e}")))?;
            let ptr = LockResource(handle) as *const u8;
            if ptr.is_null() || size == 0 {
                return Err(CoreError::Delta("DCM base resource is empty".into()));
            }
            Ok(std::slice::from_raw_parts(ptr, size).to_vec())
        })();
        let _ = FreeLibrary(module);
        result
    }
}
