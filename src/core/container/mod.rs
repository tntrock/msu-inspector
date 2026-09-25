//! 容器拆解：CAB / WIM / PSF，輸出 manifest、.mum 等需要的項目。

pub mod cab;

use std::borrow::Cow;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::model::ContainerFormat;
use super::CoreError;

/// 容器中檔案的用途，依檔名判斷。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Manifest,
    Mum,
    PkgProperties,
    PsfIndex,
    NestedCab,
    NestedWim,
    Psf,
    PackageDll,
    Ignore,
}

impl Role {
    /// 可能很大、之後要以檔案開啟的項目寫到暫存資料夾；其餘留在記憶體。
    pub fn to_disk(self) -> bool {
        matches!(
            self,
            Role::NestedCab | Role::NestedWim | Role::Psf | Role::PackageDll
        )
    }
}

pub fn role_of(base_name: &str) -> Role {
    let n = base_name.to_ascii_lowercase();
    if n.ends_with(".manifest") {
        Role::Manifest
    } else if n.ends_with(".mum") {
        Role::Mum
    } else if n.ends_with(".psf.cix.xml") {
        Role::PsfIndex
    } else if n == "pkgproperties.txt"
        || n.ends_with("-pkgproperties.txt")
        || n.ends_with("_pkgproperties.txt")
    {
        Role::PkgProperties
    } else if n.ends_with(".cab") {
        Role::NestedCab
    } else if n.ends_with(".wim") {
        Role::NestedWim
    } else if n.ends_with(".psf") {
        Role::Psf
    } else if n == "updatecompression.dll" {
        Role::PackageDll
    } else {
        Role::Ignore
    }
}

#[derive(Debug)]
pub enum ItemData {
    Bytes(Vec<u8>),
    File(PathBuf),
}

/// 從容器取出的一個檔案。`vpath` 為虛擬路徑（`外層/內層/檔名`，以 `/` 分隔）。
#[derive(Debug)]
pub struct Item {
    pub vpath: String,
    pub name: String,
    pub data: ItemData,
}

impl Item {
    pub fn new(vpath: String, data: ItemData) -> Self {
        let name = vpath.rsplit(['/', '\\']).next().unwrap_or("").to_string();
        Item { vpath, name, data }
    }

    pub fn bytes(&self) -> Result<Cow<'_, [u8]>, CoreError> {
        match &self.data {
            ItemData::Bytes(b) => Ok(Cow::Borrowed(b)),
            ItemData::File(p) => std::fs::read(p)
                .map(Cow::Owned)
                .map_err(|e| CoreError::io(p, e)),
        }
    }

    pub fn path(&self) -> Option<&Path> {
        match &self.data {
            ItemData::File(p) => Some(p),
            ItemData::Bytes(_) => None,
        }
    }
}

/// 單一容器的解壓結果；`skipped` 記錄因 `want` 過濾而略過的非 Ignore 項目。
#[derive(Debug, Default)]
pub struct Extracted {
    pub items: Vec<Item>,
    pub skipped: Vec<(String, Role)>,
}

/// 依檔頭判斷容器格式；`.psf` 沒有可靠的檔頭，以副檔名判斷。
pub fn sniff(path: &Path) -> Result<Option<ContainerFormat>, CoreError> {
    let mut head = [0u8; 8];
    let mut f = std::fs::File::open(path).map_err(|e| CoreError::io(path, e))?;
    let n = f.read(&mut head).map_err(|e| CoreError::io(path, e))?;
    let head = &head[..n];
    if head.starts_with(b"MSCF") {
        return Ok(Some(ContainerFormat::Cab));
    }
    if head.starts_with(b"MSWIM\0\0\0") {
        return Ok(Some(ContainerFormat::Wim));
    }
    let is_psf = path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("psf"));
    Ok(is_psf.then_some(ContainerFormat::Psf))
}
