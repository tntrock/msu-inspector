//! 差異引擎：PA30（UpdateCompression.dll / msdelta.dll）、PA19（mspatcha.dll）與 DCM manifest。
//!
//! DLL 一律以 LoadLibraryExW + GetProcAddress 動態載入，不需要 import library。

use std::ffi::c_void;
use std::path::{Path, PathBuf};

use windows::core::{s, HSTRING, PCWSTR};
use windows::Win32::Foundation::{FreeLibrary, FILETIME, HMODULE};
use windows::Win32::System::LibraryLoader::{
    FindResourceW, GetProcAddress, LoadLibraryExW, LoadResource, LockResource, SizeofResource,
    LOAD_LIBRARY_AS_DATAFILE, LOAD_LIBRARY_AS_IMAGE_RESOURCE, LOAD_LIBRARY_SEARCH_SYSTEM32,
    LOAD_WITH_ALTERED_SEARCH_PATH,
};
use windows::Win32::System::Memory::{VirtualFree, MEM_RELEASE};

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
#[allow(clippy::type_complexity)]
type CreateDeltaBFn = unsafe extern "system" fn(
    i64,
    i64,
    i64,
    DeltaInput,
    DeltaInput,
    DeltaInput,
    DeltaInput,
    DeltaInput,
    *const FILETIME,
    u32,
    *mut DeltaOutput,
) -> i32;

const DELTA_FILE_TYPE_RAW: i64 = 1;
const CALG_MD5: u32 = 0x8003;

pub struct DeltaEngine {
    module: HMODULE,
    apply: ApplyDeltaBFn,
    free: DeltaFreeFn,
    create: Option<CreateDeltaBFn>,
    label: String,
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
    /// 載入 System32 內的 `UpdateCompression.dll` 或 `msdelta.dll`。
    pub fn system(dll: &str) -> Result<Self, CoreError> {
        // SAFETY: 只從 System32 載入。
        let module =
            unsafe { LoadLibraryExW(&HSTRING::from(dll), None, LOAD_LIBRARY_SEARCH_SYSTEM32) }
                .map_err(|e| CoreError::Delta(format!("{dll}: {e}")))?;
        Self::from_module(module, format!("system:{dll}"))
    }

    /// 載入指定路徑的 DLL（`.msu` 附帶的 UpdateCompression.dll）。呼叫端必須先驗證簽章。
    pub fn from_path(path: &Path) -> Result<Self, CoreError> {
        // SAFETY: 呼叫端已確認檔案為 Microsoft 簽章。
        let module = unsafe {
            LoadLibraryExW(
                &HSTRING::from(path.as_os_str()),
                None,
                LOAD_WITH_ALTERED_SEARCH_PATH,
            )
        }
        .map_err(|e| CoreError::Delta(format!("{}: {e}", path.display())))?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Self::from_module(module, format!("package:{name}"))
    }

    fn from_module(module: HMODULE, label: String) -> Result<Self, CoreError> {
        // SAFETY: 取得的函式指標依 msdelta.h 的原型轉型。
        unsafe {
            let apply = GetProcAddress(module, s!("ApplyDeltaB"));
            let free = GetProcAddress(module, s!("DeltaFree"));
            let create = GetProcAddress(module, s!("CreateDeltaB"));
            match (apply, free) {
                (Some(a), Some(f)) => Ok(DeltaEngine {
                    module,
                    apply: std::mem::transmute::<unsafe extern "system" fn() -> isize, ApplyDeltaBFn>(
                        a,
                    ),
                    free: std::mem::transmute::<unsafe extern "system" fn() -> isize, DeltaFreeFn>(
                        f,
                    ),
                    create: create.map(|c| {
                        std::mem::transmute::<unsafe extern "system" fn() -> isize, CreateDeltaBFn>(
                            c,
                        )
                    }),
                    label,
                }),
                _ => {
                    let _ = FreeLibrary(module);
                    Err(CoreError::Delta(format!(
                        "{label}: ApplyDeltaB / DeltaFree not exported"
                    )))
                }
            }
        }
    }

    /// 依 spec 的順序：系統 UpdateCompression → 套件附帶（呼叫端已驗證）→ 系統 msdelta。
    pub fn select(package_dll: Option<&Path>) -> Result<Self, CoreError> {
        if let Ok(e) = Self::system("UpdateCompression.dll") {
            return Ok(e);
        }
        if let Some(p) = package_dll {
            if let Ok(e) = Self::from_path(p) {
                return Ok(e);
            }
        }
        Self::system("msdelta.dll")
    }

    pub fn label(&self) -> &str {
        &self.label
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
                    "{}: ApplyDeltaB failed ({})",
                    self.label,
                    windows::core::Error::from_thread()
                )));
            }
            let v = std::slice::from_raw_parts(out.start as *const u8, out.size).to_vec();
            (self.free)(out.start);
            Ok(v)
        }
    }

    /// 產生 PA30 差異（測試用；只有 msdelta.dll 匯出 CreateDeltaB）。
    pub fn create(&self, source: &[u8], target: &[u8]) -> Result<Vec<u8>, CoreError> {
        let create = self.create.ok_or_else(|| {
            CoreError::Delta(format!("{}: CreateDeltaB not exported", self.label))
        })?;
        let empty = DeltaInput::of(&[]);
        let ft = FILETIME::default();
        let mut out = DeltaOutput {
            start: std::ptr::null_mut(),
            size: 0,
        };
        // SAFETY: 同 apply。
        unsafe {
            let ok = create(
                DELTA_FILE_TYPE_RAW,
                0,
                0,
                DeltaInput::of(source),
                DeltaInput::of(target),
                empty,
                empty,
                empty,
                &ft,
                CALG_MD5,
                &mut out,
            );
            if ok == 0 {
                return Err(CoreError::Delta(format!(
                    "CreateDeltaB failed ({})",
                    windows::core::Error::from_thread()
                )));
            }
            let v = std::slice::from_raw_parts(out.start as *const u8, out.size).to_vec();
            (self.free)(out.start);
            Ok(v)
        }
    }
}

type ApplyPatchFn = unsafe extern "system" fn(
    *const u8,
    u32,
    *const u8,
    u32,
    *mut *mut u8,
    u32,
    *mut u32,
    *mut FILETIME,
    u32,
    *const c_void,
    *const c_void,
) -> i32;

/// 還原 PA19（舊版 PSF）null-source 修補：mspatcha.dll 的 ApplyPatchToFileByBuffers。
pub fn apply_pa19(patch: &[u8]) -> Result<Vec<u8>, CoreError> {
    // SAFETY: 從 System32 載入；輸出緩衝區由 mspatcha 以 VirtualAlloc 配置，用 VirtualFree 釋放。
    unsafe {
        let module = LoadLibraryExW(
            &HSTRING::from("mspatcha.dll"),
            None,
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
        .map_err(|e| CoreError::Delta(format!("mspatcha.dll: {e}")))?;
        let result = (|| {
            let f = GetProcAddress(module, s!("ApplyPatchToFileByBuffers"))
                .ok_or_else(|| CoreError::Delta("ApplyPatchToFileByBuffers not exported".into()))?;
            let f = std::mem::transmute::<unsafe extern "system" fn() -> isize, ApplyPatchFn>(f);
            let mut out: *mut u8 = std::ptr::null_mut();
            let mut size = 0u32;
            let mut ft = FILETIME::default();
            let ok = f(
                patch.as_ptr(),
                patch.len() as u32,
                std::ptr::null(),
                0,
                &mut out,
                0,
                &mut size,
                &mut ft,
                0,
                std::ptr::null(),
                std::ptr::null(),
            );
            if ok == 0 || out.is_null() {
                return Err(CoreError::Delta(format!(
                    "PA19 patch failed ({})",
                    windows::core::Error::from_thread()
                )));
            }
            let v = std::slice::from_raw_parts(out, size as usize).to_vec();
            let _ = VirtualFree(out.cast(), 0, MEM_RELEASE);
            Ok(v)
        })();
        let _ = FreeLibrary(module);
        result
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
