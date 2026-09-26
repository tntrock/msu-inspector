//! 整合測試共用：以系統 makecab.exe 產生 CAB、讀取 fixture。
#![allow(dead_code)]

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use msu_inspector::core::delta::DeltaEngine;

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

/// 產生 PSF：payload 從 0x10000 開始；`pa30` 為 true 的項目以 PA30 null-source 儲存。
/// `embed` 為 true 時索引放在檔頭（24H2 格式），否則回傳的 XML 需另存為 `*.psf.cix.xml`。
pub fn build_psf(
    dir: &Path,
    file_name: &str,
    entries: &[(&str, &[u8], bool)],
    embed: bool,
) -> (PathBuf, String) {
    let e = DeltaEngine::system("msdelta.dll").unwrap();
    let mut payload = Vec::new();
    let mut files = String::new();
    for (i, (name, data, pa30)) in entries.iter().enumerate() {
        let stored = if *pa30 {
            e.create(b"", data).unwrap()
        } else {
            data.to_vec()
        };
        let offset = 0x10000 + payload.len();
        writeln!(
            files,
            "<File id=\"{i}\" name=\"{name}\" length=\"{}\" time=\"0\" attr=\"128\"><Delta><Source type=\"{}\" offset=\"{offset}\" length=\"{}\"/></Delta></File>",
            data.len(),
            if *pa30 { "PA30" } else { "RAW" },
            stored.len()
        )
        .unwrap();
        payload.extend(stored);
    }
    let xml = format!("<?xml version=\"1.0\"?><Container type=\"PSF\" version=\"2.0\"><Files>{files}</Files></Container>");
    let mut buf = vec![0u8; 0x10000];
    buf[..4].copy_from_slice(b"PSTR");
    if embed {
        let idx = e.create(b"", xml.as_bytes()).unwrap();
        buf[4..8].copy_from_slice(&(idx.len() as u32).to_le_bytes());
        buf[0x80..0x80 + idx.len()].copy_from_slice(&idx);
    }
    buf.extend(payload);
    let path = dir.join(file_name);
    std::fs::File::create(&path)
        .unwrap()
        .write_all(&buf)
        .unwrap();
    (path, xml)
}
