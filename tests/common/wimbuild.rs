//! 測試用：依 WIM 格式（wimlib 文件）產生單一 image、無壓縮的 WIM。
//! 雜湊只當查表鍵使用，不是真的 SHA-1。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// WIM 中的一個檔案。`reparse` 為 true 時設 FILE_ATTRIBUTE_REPARSE_POINT。
pub struct WimEntry<'a> {
    pub path: &'a str,
    pub data: &'a [u8],
    pub reparse: bool,
}

#[derive(Default)]
struct Dir {
    dirs: BTreeMap<String, Dir>,
    files: Vec<(String, [u8; 20], bool)>,
}

fn align8(v: usize) -> usize {
    (v + 7) & !7
}

fn dentry(name: &str, attrs: u32, subdir: u64, hash: [u8; 20]) -> Vec<u8> {
    let name16: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let len = 102 + name16.len() + if name16.is_empty() { 0 } else { 2 };
    let mut d = Vec::with_capacity(align8(len));
    d.extend((len as u64).to_le_bytes());
    d.extend(attrs.to_le_bytes());
    d.extend((-1i32).to_le_bytes());
    d.extend(subdir.to_le_bytes());
    d.extend([0u8; 40]); // unused ×2、三個時間戳記
    d.extend(hash);
    d.extend([0u8; 12]); // reparse / hard link union
    d.extend(0u16.to_le_bytes()); // num_extra_streams
    d.extend(0u16.to_le_bytes()); // short_name_nbytes
    d.extend((name16.len() as u16).to_le_bytes());
    d.extend(&name16);
    if !name16.is_empty() {
        d.extend([0u8; 2]);
    }
    d.resize(align8(len), 0);
    d
}

/// 寫入此目錄的子項區塊（子目錄的區塊先寫），回傳區塊在 metadata 中的偏移。
fn write_dir(meta: &mut Vec<u8>, node: &Dir) -> u64 {
    let mut child_blocks = BTreeMap::new();
    for (name, sub) in &node.dirs {
        child_blocks.insert(name.clone(), write_dir(meta, sub));
    }
    let start = meta.len() as u64;
    for name in node.dirs.keys() {
        meta.extend(dentry(name, 0x10, child_blocks[name], [0; 20]));
    }
    for (name, hash, reparse) in &node.files {
        let attrs = if *reparse { 0x400 | 0x20 } else { 0x20 };
        meta.extend(dentry(name, attrs, 0, *hash));
    }
    meta.extend(0u64.to_le_bytes()); // 目錄結束標記
    start
}

fn reshdr(size: u64, flags: u8, offset: u64) -> Vec<u8> {
    let mut r = (size | ((flags as u64) << 56)).to_le_bytes().to_vec();
    r.extend(offset.to_le_bytes());
    r.extend(size.to_le_bytes());
    r
}

fn lookup_entry(out: &mut Vec<u8>, res: Vec<u8>, hash: [u8; 20]) {
    out.extend(res);
    out.extend(1u16.to_le_bytes()); // part number
    out.extend(1u32.to_le_bytes()); // ref count
    out.extend(hash);
}

pub fn build_wim(dir: &Path, file_name: &str, entries: &[WimEntry]) -> PathBuf {
    let mut out = vec![0u8; 208];
    let mut root = Dir::default();
    let mut lookup = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        let hash = [(i + 1) as u8; 20];
        let offset = out.len() as u64;
        out.extend(e.data);
        lookup_entry(&mut lookup, reshdr(e.data.len() as u64, 0, offset), hash);
        let mut parts: Vec<&str> = e.path.split(['/', '\\']).collect();
        let name = parts.pop().unwrap().to_string();
        let mut node = &mut root;
        for p in parts {
            node = node.dirs.entry(p.to_string()).or_default();
        }
        node.files.push((name, hash, e.reparse));
    }
    // metadata：安全性區塊（total_length = 8、0 筆）→ root dentry → 各目錄區塊
    let mut meta = Vec::new();
    meta.extend(8u32.to_le_bytes());
    meta.extend(0u32.to_le_bytes());
    let root_at = meta.len();
    meta.extend(dentry("", 0x10, 0, [0; 20]));
    let root_block = write_dir(&mut meta, &root);
    meta[root_at + 16..root_at + 24].copy_from_slice(&root_block.to_le_bytes());
    let meta_off = out.len() as u64;
    out.extend(&meta);
    lookup_entry(
        &mut lookup,
        reshdr(meta.len() as u64, 0x02, meta_off),
        [0xEE; 20],
    );
    let lookup_off = out.len() as u64;
    out.extend(&lookup);

    out[..8].copy_from_slice(b"MSWIM\0\0\0");
    out[8..12].copy_from_slice(&208u32.to_le_bytes());
    out[12..16].copy_from_slice(&0x10d00u32.to_le_bytes());
    out[40..42].copy_from_slice(&1u16.to_le_bytes()); // part number
    out[42..44].copy_from_slice(&1u16.to_le_bytes()); // total parts
    out[44..48].copy_from_slice(&1u32.to_le_bytes()); // image count
    out[48..72].copy_from_slice(&reshdr(lookup.len() as u64, 0, lookup_off));
    let path = dir.join(file_name);
    std::fs::write(&path, out).unwrap();
    path
}
