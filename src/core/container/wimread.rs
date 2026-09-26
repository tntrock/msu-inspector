//! 無壓縮 WIM 的唯讀解析器（純 Rust，不需要系統管理員權限）。
//!
//! 24H2 起的 `.msu` 本身就是無壓縮 WIM；wimgapi 不論整包展開或取出單一檔案都需要還原權限
//! （ERROR_PRIVILEGE_NOT_HELD），所以無壓縮的 WIM 改由這裡直接讀取。格式依 wimlib 的文件：
//! 檔頭（208 位元組）→ lookup table（每筆 50 位元組：資源標頭 + part + refcount + SHA-1）→
//! 每個 image 一份 metadata 資源（安全性區塊 + dentry 樹）。檔案內容以 SHA-1 在 lookup table 查得。
//! 只讀取、不還原任何 reparse point，也不在 out_dir 以外寫入。

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use super::cab::{sanitize, MAX_MEMORY_ITEM};
use super::{role_at, Extracted, Item, ItemData, Role};
use crate::core::CoreError;

const HEADER_SIZE: usize = 208;
const HDR_FLAG_COMPRESSION: u32 = 0x2;
const RES_FLAG_METADATA: u8 = 0x02;
/// 壓縮、分割、solid（packed）資源都不在這個讀取器的範圍內
const RES_FLAG_UNSUPPORTED: u8 = 0x04 | 0x08 | 0x10;
const LOOKUP_ENTRY: usize = 50;
const DENTRY_FIXED: usize = 102;
const ATTR_DIRECTORY: u32 = 0x10;
const ATTR_REPARSE_POINT: u32 = 0x400;
/// metadata / lookup table 大小上限，防止惡意檔頭造成巨量配置
const MAX_TABLE: u64 = 512 * 1024 * 1024;
const MAX_DEPTH: usize = 64;
const MAX_DENTRIES: usize = 4_000_000;

#[derive(Debug, Clone, Copy)]
struct Resource {
    offset: u64,
    size: u64,
    flags: u8,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// 資源標頭（24 位元組）：前 7 位元組為儲存大小、第 8 位元組為旗標，接著偏移與原始大小。
fn resource_at(b: &[u8], at: usize) -> Option<Resource> {
    let packed = u64_at(b, at)?;
    Some(Resource {
        size: packed & 0x00FF_FFFF_FFFF_FFFF,
        flags: (packed >> 56) as u8,
        offset: u64_at(b, at + 8)?,
    })
}

fn align8(v: usize) -> usize {
    (v + 7) & !7
}

/// 檔頭顯示為單一檔案、無壓縮的 WIM 時回傳 true，其餘（含讀取失敗）交給 wimgapi。
pub fn is_uncompressed(path: &Path) -> bool {
    let mut head = [0u8; HEADER_SIZE];
    let ok = File::open(path)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok();
    ok && head.starts_with(b"MSWIM\0\0\0")
        && u32_at(&head, 16).is_some_and(|flags| flags & HDR_FLAG_COMPRESSION == 0)
        && u16_at(&head, 42) == Some(1)
}

struct Reader<'a> {
    file: File,
    file_size: u64,
    vprefix: &'a str,
    out_dir: &'a Path,
    cancel: &'a AtomicBool,
    want: &'a dyn Fn(Role) -> bool,
    lookup: HashMap<[u8; 20], Resource>,
    out: Extracted,
    counter: usize,
    dentries: usize,
}

impl Reader<'_> {
    fn err(&self, detail: impl Into<String>) -> CoreError {
        CoreError::Container {
            path: self.vprefix.to_string(),
            detail: detail.into(),
        }
    }

    fn check_range(&self, res: &Resource, limit: u64) -> Result<(), CoreError> {
        if res.flags & RES_FLAG_UNSUPPORTED != 0 {
            return Err(self.err(format!(
                "unsupported WIM resource flags 0x{:02x}",
                res.flags
            )));
        }
        let end = res.offset.checked_add(res.size);
        if res.size > limit || end.is_none_or(|e| e > self.file_size) {
            return Err(self.err(format!(
                "WIM resource out of range (offset {}, size {}, file {})",
                res.offset, res.size, self.file_size
            )));
        }
        Ok(())
    }

    fn read_resource(&mut self, res: &Resource, limit: u64) -> Result<Vec<u8>, CoreError> {
        self.check_range(res, limit)?;
        let mut buf = vec![0u8; res.size as usize];
        self.file
            .seek(SeekFrom::Start(res.offset))
            .and_then(|_| self.file.read_exact(&mut buf))
            .map_err(|e| self.err(e.to_string()))?;
        Ok(buf)
    }

    /// 走訪一個目錄的子項區塊；`visited` 防止目錄互相參照造成無窮遞迴。
    fn walk(
        &mut self,
        meta: &[u8],
        block: u64,
        rel: &str,
        depth: usize,
        visited: &mut HashSet<u64>,
    ) -> Result<(), CoreError> {
        if depth > MAX_DEPTH || !visited.insert(block) {
            return Ok(());
        }
        let mut at = usize::try_from(block).map_err(|_| self.err("bad directory offset"))?;
        loop {
            let length = u64_at(meta, at).ok_or_else(|| self.err("truncated WIM metadata"))?;
            if length == 0 {
                return Ok(()); // 目錄結束標記
            }
            self.dentries += 1;
            if self.dentries > MAX_DENTRIES {
                return Err(self.err("too many WIM directory entries"));
            }
            let length = usize::try_from(length).map_err(|_| self.err("bad dentry length"))?;
            if length < DENTRY_FIXED || at.checked_add(length).is_none_or(|e| e > meta.len()) {
                return Err(self.err("corrupt WIM directory entry"));
            }
            let d = &meta[at..at + length];
            let attrs = u32_at(d, 8).unwrap_or(0);
            let subdir = u64_at(d, 16).unwrap_or(0);
            let mut hash: [u8; 20] = d[64..84].try_into().unwrap_or([0; 20]);
            let extra_streams = u16_at(d, 96).unwrap_or(0);
            let name_len = u16_at(d, 100).unwrap_or(0) as usize;
            let name_bytes = d
                .get(DENTRY_FIXED..DENTRY_FIXED + name_len)
                .ok_or_else(|| self.err("corrupt WIM file name"))?;
            let units: Vec<u16> = name_bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let name = String::from_utf16_lossy(&units);

            // 額外資料流緊接在 dentry 之後；未命名者即為檔案本體（預設雜湊為 0 時）
            let mut next = align8(at + length);
            for _ in 0..extra_streams {
                let slen = u64_at(meta, next).ok_or_else(|| self.err("truncated WIM stream"))?;
                let slen = usize::try_from(slen).map_err(|_| self.err("bad stream length"))?;
                if slen < 38 || next.checked_add(slen).is_none_or(|e| e > meta.len()) {
                    return Err(self.err("corrupt WIM stream entry"));
                }
                let s_hash: [u8; 20] = meta[next + 16..next + 36].try_into().unwrap_or([0; 20]);
                let s_name_len = u16_at(meta, next + 36).unwrap_or(0);
                if s_name_len == 0 && hash == [0; 20] {
                    hash = s_hash;
                }
                next = align8(next + slen);
            }

            let path = if rel.is_empty() {
                name.clone()
            } else {
                format!("{rel}/{name}")
            };
            if attrs & ATTR_REPARSE_POINT != 0 || name.is_empty() {
                // 不跟隨、不還原 reparse point
            } else if attrs & ATTR_DIRECTORY != 0 {
                if subdir != 0 {
                    self.walk(meta, subdir, &path, depth + 1, visited)?;
                }
            } else {
                self.file_entry(&name, &path, hash)?;
            }
            at = next;
        }
    }

    fn file_entry(&mut self, name: &str, path: &str, hash: [u8; 20]) -> Result<(), CoreError> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err(CoreError::Cancelled);
        }
        let vpath = format!("{}/{path}", self.vprefix);
        let role = role_at(&vpath);
        if role == Role::Ignore {
            return Ok(());
        }
        if !(self.want)(role) {
            self.out.skipped.push((vpath, role));
            return Ok(());
        }
        let res = if hash == [0; 20] {
            Resource {
                offset: 0,
                size: 0,
                flags: 0,
            }
        } else {
            *self
                .lookup
                .get(&hash)
                .ok_or_else(|| self.err(format!("{vpath}: data stream not found")))?
        };
        let data = if role.to_disk() {
            self.check_range(&res, u64::MAX)?;
            self.counter += 1;
            let dest = self
                .out_dir
                .join(format!("{:05}_{}", self.counter, sanitize(name)));
            let mut target = File::create(&dest).map_err(|e| CoreError::io(&dest, e))?;
            self.file
                .seek(SeekFrom::Start(res.offset))
                .map_err(|e| self.err(e.to_string()))?;
            let copied = std::io::copy(&mut (&mut self.file).take(res.size), &mut target)
                .map_err(|e| CoreError::io(&dest, e))?;
            if copied != res.size {
                return Err(self.err(format!("{vpath}: truncated data stream")));
            }
            ItemData::File(dest)
        } else {
            if res.size > MAX_MEMORY_ITEM {
                return Err(self.err(format!(
                    "{vpath}: entry too large ({} bytes > {MAX_MEMORY_ITEM})",
                    res.size
                )));
            }
            ItemData::Bytes(self.read_resource(&res, MAX_MEMORY_ITEM)?)
        };
        self.out.items.push(Item::new(vpath, data));
        Ok(())
    }
}

/// 讀取無壓縮 WIM 的所有 image，只取出 `want` 接受的項目（行為與 wimgapi 路徑相同）。
pub fn extract(
    wim: &Path,
    vprefix: &str,
    out_dir: &Path,
    cancel: &AtomicBool,
    want: &dyn Fn(Role) -> bool,
) -> Result<Extracted, CoreError> {
    let mut file = File::open(wim).map_err(|e| CoreError::io(wim, e))?;
    let file_size = file.metadata().map_err(|e| CoreError::io(wim, e))?.len();
    let mut head = [0u8; HEADER_SIZE];
    file.read_exact(&mut head)
        .map_err(|e| CoreError::io(wim, e))?;
    let mut r = Reader {
        file,
        file_size,
        vprefix,
        out_dir,
        cancel,
        want,
        lookup: HashMap::new(),
        out: Extracted::default(),
        counter: 0,
        dentries: 0,
    };
    if !head.starts_with(b"MSWIM\0\0\0") {
        return Err(r.err("not a WIM file"));
    }
    let table_res = resource_at(&head, 48).ok_or_else(|| r.err("bad WIM header"))?;
    let table = r.read_resource(&table_res, MAX_TABLE)?;
    let mut images = Vec::new();
    for entry in table.as_chunks::<LOOKUP_ENTRY>().0 {
        let Some(res) = resource_at(entry.as_slice(), 0) else {
            continue;
        };
        let hash: [u8; 20] = entry[30..50].try_into().unwrap_or([0; 20]);
        if res.flags & RES_FLAG_METADATA != 0 {
            images.push(res);
        } else {
            r.lookup.insert(hash, res);
        }
    }
    if images.is_empty() {
        return Err(r.err("WIM has no image metadata"));
    }
    for image in images {
        if cancel.load(Ordering::Relaxed) {
            return Err(CoreError::Cancelled);
        }
        let meta = r.read_resource(&image, MAX_TABLE)?;
        // 安全性區塊長度（0 視為 8），之後 8 位元組對齊處為 root dentry
        let security = u32_at(&meta, 0).ok_or_else(|| r.err("truncated WIM metadata"))? as usize;
        let root = align8(security.max(8));
        if root + DENTRY_FIXED > meta.len() {
            return Err(r.err("truncated WIM metadata"));
        }
        let root_block = u64_at(&meta, root + 16).unwrap_or(0);
        if root_block != 0 {
            r.walk(&meta, root_block, "", 0, &mut HashSet::new())?;
        }
    }
    Ok(r.out)
}
