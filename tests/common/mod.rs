//! 整合測試共用：以系統 makecab.exe 產生 CAB、讀取 fixture。
#![allow(dead_code)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

pub mod wimbuild;

pub fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

/// 用 makecab 的 DDF 產生 CAB。`files` 的名稱可含 `\` 子目錄（以 DestinationDir 表示）。
/// `dir` 必須是純 ASCII 路徑(makecab 以 ANSI 讀 DDF)。
pub fn make_cab(dir: &Path, cab_name: &str, files: &[(&str, &[u8])], lzx: bool) -> PathBuf {
    let src = dir.join(format!("{cab_name}.src"));
    std::fs::create_dir_all(&src).unwrap();
    let mut ddf = String::from(
        ".OPTION EXPLICIT\n.Set Cabinet=on\n.Set Compress=on\n.Set MaxDiskSize=0\n\
         .Set MaxCabinetSize=0\n.Set FolderSizeThreshold=0\n.Set UniqueFiles=off\n\
         .Set RptFileName=nul\n.Set InfFileName=nul\n",
    );
    writeln!(
        ddf,
        ".Set CompressionType={}",
        if lzx { "LZX" } else { "MSZIP" }
    )
    .unwrap();
    writeln!(ddf, ".Set DiskDirectoryTemplate=\"{}\"", dir.display()).unwrap();
    writeln!(ddf, ".Set CabinetNameTemplate=\"{cab_name}\"").unwrap();
    let mut current_dir = String::new();
    for (i, (name, data)) in files.iter().enumerate() {
        let (sub, base) = name.rsplit_once('\\').unwrap_or(("", name));
        if sub != current_dir {
            writeln!(ddf, ".Set DestinationDir=\"{sub}\"").unwrap();
            current_dir = sub.to_string();
        }
        let p = src.join(format!("f{i}"));
        std::fs::write(&p, data).unwrap();
        writeln!(ddf, "\"{}\" \"{base}\"", p.display()).unwrap();
    }
    let ddf_path = dir.join(format!("{cab_name}.ddf"));
    std::fs::write(&ddf_path, ddf).unwrap();
    let out = Command::new("makecab")
        .arg("/F")
        .arg(&ddf_path)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "makecab failed: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    dir.join(cab_name)
}

/// UTF-16LE（含 BOM），模擬 pkgProperties.txt。
pub fn utf16(text: &str) -> Vec<u8> {
    let mut out = vec![0xFF, 0xFE];
    for u in text.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

/// 以 msdelta.dll 的 CreateDeltaB 產生 PA30 差異（只給測試建立 fixture 用）。
pub fn create_delta(source: &[u8], target: &[u8]) -> Vec<u8> {
    use std::ffi::c_void;
    use windows::core::{s, HSTRING};
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::LibraryLoader::{
        GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Input {
        start: *const c_void,
        size: usize,
        editable: i32,
    }
    #[repr(C)]
    struct Output {
        start: *mut c_void,
        size: usize,
    }
    type CreateFn = unsafe extern "system" fn(
        i64,
        i64,
        i64,
        Input,
        Input,
        Input,
        Input,
        Input,
        *const FILETIME,
        u32,
        *mut Output,
    ) -> i32;
    type FreeFn = unsafe extern "system" fn(*mut c_void) -> i32;
    let input = |b: &[u8]| Input {
        start: if b.is_empty() {
            std::ptr::null()
        } else {
            b.as_ptr().cast()
        },
        size: b.len(),
        editable: 0,
    };
    // SAFETY: 依 msdelta.h 的原型呼叫；輸入在呼叫期間有效，輸出以 DeltaFree 釋放。
    unsafe {
        let m = LoadLibraryExW(
            &HSTRING::from("msdelta.dll"),
            None,
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
        .unwrap();
        let create: CreateFn = std::mem::transmute(GetProcAddress(m, s!("CreateDeltaB")).unwrap());
        let free: FreeFn = std::mem::transmute(GetProcAddress(m, s!("DeltaFree")).unwrap());
        let empty = input(&[]);
        let mut out = Output {
            start: std::ptr::null_mut(),
            size: 0,
        };
        let ok = create(
            1, // DELTA_FILE_TYPE_RAW
            0,
            0,
            input(source),
            input(target),
            empty,
            empty,
            empty,
            &FILETIME::default(),
            0x8003, // CALG_MD5
            &mut out,
        );
        assert!(ok != 0, "CreateDeltaB failed");
        if out.start.is_null() {
            return Vec::new();
        }
        let v = std::slice::from_raw_parts(out.start as *const u8, out.size).to_vec();
        free(out.start);
        v
    }
}
