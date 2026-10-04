//! 容器拆解：CAB / WIM，輸出 manifest、.mum 等需要的項目。
//!
//! PSF（patch storage file）只存放要安裝的檔案本體，不含 manifest（以 5 包真實更新驗證，
//! 含 24H2 LCU），因此不展開。

pub mod cab;
pub mod wim;
pub mod wimread;

use std::borrow::Cow;
use std::collections::{HashSet, VecDeque};
use std::io::Read;
use std::path::{Path, PathBuf};

use super::model::{ContainerFormat, ContainerInfo, Warning, WarningCode};
use super::progress::{Ctx, Progress};
use super::CoreError;

/// 容器中檔案的用途，依檔名判斷。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Manifest,
    Mum,
    PkgProperties,
    NestedCab,
    NestedWim,
    Ignore,
}

impl Role {
    /// 巢狀容器可能很大、之後要以檔案開啟，寫到暫存資料夾；其餘留在記憶體。
    pub fn to_disk(self) -> bool {
        matches!(self, Role::NestedCab | Role::NestedWim)
    }
}

/// WinSxS keyform 資料夾名稱：`arch_名稱_token(16 hex)_版本_語系_雜湊(16 hex)`。
fn is_component_dir(segment: &str) -> bool {
    let parts: Vec<&str> = segment.split('_').collect();
    let n = parts.len();
    let hex16 = |s: &str| s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit());
    n >= 6
        && hex16(parts[n - 4])
        && hex16(parts[n - 1])
        && super::model::parse_version(parts[n - 3]).is_some()
}

/// 依容器內的完整路徑判斷用途。位於元件資料夾中的檔案（例如 Win10 LCU 的 bootos.wim、
/// `f/application.manifest`）都是要安裝到系統的 payload，不是套件容器或元件 manifest，一律略過。
pub fn role_at(inner_path: &str) -> Role {
    let segments: Vec<&str> = inner_path
        .split(['/', '\\'])
        .filter(|s| !s.is_empty())
        .collect();
    let Some((base, dirs)) = segments.split_last() else {
        return Role::Ignore;
    };
    if dirs.iter().any(|d| is_component_dir(d)) {
        Role::Ignore
    } else {
        role_of(base)
    }
}

pub fn role_of(base_name: &str) -> Role {
    let n = base_name.to_ascii_lowercase();
    if n.ends_with(".manifest") {
        Role::Manifest
    } else if n.ends_with(".mum") {
        Role::Mum
    } else if n.contains("pkgproperties") && n.ends_with(".txt") {
        // 例：`…-pkgProperties.txt`、`…-pkgProperties_PSFX.txt`
        Role::PkgProperties
    } else if n.ends_with(".cab") {
        Role::NestedCab
    } else if n.ends_with(".wim") {
        Role::NestedWim
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

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

/// 項目本身是否為重新剖析點（符號連結、目錄連接等）。以 symlink_metadata 取得、不跟隨連結。
pub fn is_reparse_point(meta: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    meta.file_type().is_symlink() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// `path` 解析所有連結後是否仍位於 `root` 之下（兩者都要存在）。
pub fn is_within(path: &Path, root: &Path) -> bool {
    match (std::fs::canonicalize(path), std::fs::canonicalize(root)) {
        (Ok(p), Ok(r)) => p.starts_with(r),
        _ => false,
    }
}

/// 依檔頭判斷容器格式。
pub fn sniff(path: &Path) -> Result<Option<ContainerFormat>, CoreError> {
    let mut head = [0u8; 8];
    let mut f = std::fs::File::open(path).map_err(|e| CoreError::io(path, e))?;
    let n = f.read(&mut head).map_err(|e| CoreError::io(path, e))?;
    let head = &head[..n];
    if head.starts_with(b"MSCF") {
        Ok(Some(ContainerFormat::Cab))
    } else if head.starts_with(b"MSWIM\0\0\0") {
        Ok(Some(ContainerFormat::Wim))
    } else {
        Ok(None)
    }
}

/// 不是安裝內容的巢狀容器：更新掃描中繼資料、安裝工具。
fn skip_reason(lower_name: &str) -> Option<&'static str> {
    if lower_name == "wsusscan.cab" {
        Some("scan metadata")
    } else if lower_name.starts_with("desktopdeployment") {
        Some("installer tooling")
    } else {
        None
    }
}

#[derive(Debug, Default)]
pub struct Collected {
    pub outer: Option<ContainerFormat>,
    pub manifests: Vec<Item>,
    pub mums: Vec<Item>,
    pub pkg_properties: Option<Vec<u8>>,
    pub containers: Vec<ContainerInfo>,
    pub warnings: Vec<Warning>,
    seen: HashSet<String>,
}

impl Collected {
    /// manifest 依檔名、.mum 依完整虛擬路徑（皆不分大小寫）去重：
    /// SSU + LCU 合併套件的每個容器都有自己的 `update.mum`，都要保留給 select_package 挑選。
    fn add_unique(&mut self, item: Item, role: Role) {
        let key = match role {
            Role::Mum => format!("mum:{}", item.vpath.to_ascii_lowercase()),
            _ => item.name.to_ascii_lowercase(),
        };
        if !self.seen.insert(key) {
            return;
        }
        match role {
            Role::Manifest => self.manifests.push(item),
            Role::Mum => self.mums.push(item),
            _ => {}
        }
    }
}

/// 遞迴展開外層容器與所有巢狀 CAB / WIM，收集 manifest、.mum 與 pkgProperties。
pub fn collect(path: &Path, work: &Path, ctx: &Ctx) -> Result<Collected, CoreError> {
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let outer = sniff(path)?.ok_or_else(|| CoreError::UnsupportedFormat(file_name.clone()))?;
    let mut c = Collected {
        outer: Some(outer),
        ..Default::default()
    };
    let cancel = ctx.cancel_flag();
    let mut queue = VecDeque::from([(path.to_path_buf(), file_name, outer)]);
    let mut n = 0usize;
    while let Some((p, vpath, fmt)) = queue.pop_front() {
        ctx.check()?;
        ctx.report(Progress::Unpacking {
            container: vpath.clone(),
        });
        n += 1;
        let out = work.join(format!("c{n:04}"));
        std::fs::create_dir_all(&out).map_err(|e| CoreError::io(&out, e))?;
        let result = match fmt {
            ContainerFormat::Cab => cab::extract(&p, &vpath, &out, &cancel),
            ContainerFormat::Wim => wim::extract(&p, &vpath, &out, &cancel),
        };
        let items = match result {
            Ok(items) => items,
            Err(e @ (CoreError::Cancelled | CoreError::NeedsElevation(_))) => return Err(e),
            Err(e) if n == 1 => return Err(e),
            Err(e) => {
                c.warnings.push(Warning::new(
                    WarningCode::ContainerFailed,
                    &vpath,
                    e.to_string(),
                ));
                c.containers.push(ContainerInfo {
                    path: vpath,
                    format: fmt,
                    skipped: Some(e.to_string()),
                });
                continue;
            }
        };
        c.containers.push(ContainerInfo {
            path: vpath.clone(),
            format: fmt,
            skipped: None,
        });
        for item in items {
            let role = role_at(&item.vpath);
            match role {
                Role::Manifest | Role::Mum => c.add_unique(item, role),
                Role::PkgProperties => {
                    if c.pkg_properties.is_none() {
                        c.pkg_properties = Some(item.bytes()?.into_owned());
                    }
                }
                Role::NestedCab | Role::NestedWim => {
                    let Some(fp) = item.path().map(Path::to_path_buf) else {
                        continue;
                    };
                    let nested = match sniff(&fp)? {
                        Some(f) => f,
                        None if role == Role::NestedCab => ContainerFormat::Cab,
                        None => ContainerFormat::Wim,
                    };
                    if let Some(reason) = skip_reason(&item.name.to_ascii_lowercase()) {
                        if is_within(&fp, work) {
                            let _ = std::fs::remove_file(&fp);
                        }
                        c.containers.push(ContainerInfo {
                            path: item.vpath,
                            format: nested,
                            skipped: Some(reason.into()),
                        });
                        continue;
                    }
                    queue.push_back((fp, item.vpath, nested));
                }
                Role::Ignore => {}
            }
        }
        // 巢狀容器展開後即刪除，節省暫存空間（使用者的原始檔與暫存資料夾外的檔案不動）
        if n > 1 && is_within(&p, work) {
            let _ = std::fs::remove_file(&p);
        }
    }
    Ok(c)
}
