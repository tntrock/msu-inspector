//! 整合測試共用：以系統 makecab.exe 產生 CAB、讀取 fixture。
#![allow(dead_code)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

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
