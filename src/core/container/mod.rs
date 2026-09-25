//! 容器拆解：CAB / WIM / PSF，輸出 manifest、.mum 等需要的項目。

pub mod cab;
pub mod psf;
pub mod wim;

use std::borrow::Cow;
use std::collections::{HashSet, VecDeque};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::delta::DeltaEngine;
use super::model::{ContainerFormat, ContainerInfo, Warning, WarningCode};
use super::progress::{Ctx, Progress};
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
    } else if n.contains("pkgproperties") && n.ends_with(".txt") {
        // 例：`…-pkgProperties.txt`、`…-pkgProperties_PSFX.txt`
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

/// 更新掃描用的中繼資料，與安裝動作無關。
const SCAN_METADATA: &str = "wsusscan.cab";
/// 安裝工具（DesktopDeployment*.cab）：只取 UpdateCompression.dll，不收 manifest。
const TOOLING_PREFIX: &str = "desktopdeployment";

#[derive(Debug, Default)]
pub struct Collected {
    pub outer: Option<ContainerFormat>,
    pub manifests: Vec<Item>,
    pub mums: Vec<Item>,
    pub pkg_properties: Option<Vec<u8>>,
    pub psf_indexes: Vec<Item>,
    pub psfs: Vec<Item>,
    pub package_dll: Option<PathBuf>,
    pub containers: Vec<ContainerInfo>,
    pub warnings: Vec<Warning>,
    /// 有 PSF 因過濾而未展開
    pub saw_psf: bool,
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

pub fn collect(path: &Path, work: &Path, ctx: &Ctx) -> Result<Collected, CoreError> {
    let first = collect_pass(path, &work.join("pass1"), ctx, false)?;
    if first.manifests.is_empty() && first.saw_psf {
        let mut second = collect_pass(path, &work.join("pass2"), ctx, true)?;
        second.saw_psf = true;
        return Ok(second);
    }
    Ok(first)
}

fn collect_pass(
    path: &Path,
    work: &Path,
    ctx: &Ctx,
    want_psf: bool,
) -> Result<Collected, CoreError> {
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let outer = match sniff(path)? {
        Some(f @ (ContainerFormat::Cab | ContainerFormat::Wim)) => f,
        _ => return Err(CoreError::UnsupportedFormat(file_name)),
    };
    let mut c = Collected {
        outer: Some(outer),
        ..Default::default()
    };
    let cancel = ctx.cancel_flag();
    let mut queue = VecDeque::from([(path.to_path_buf(), file_name, outer, false)]);
    let mut n = 0usize;
    while let Some((p, vpath, fmt, tooling)) = queue.pop_front() {
        ctx.check()?;
        ctx.report(Progress::Unpacking {
            container: vpath.clone(),
        });
        n += 1;
        let out = work.join(format!("c{n:04}"));
        std::fs::create_dir_all(&out).map_err(|e| CoreError::io(&out, e))?;
        let want = |r: Role| {
            if tooling {
                r == Role::PackageDll
            } else {
                r != Role::Psf || want_psf
            }
        };
        let result = match fmt {
            ContainerFormat::Cab => cab::extract(&p, &vpath, &out, &cancel, &want),
            ContainerFormat::Wim => wim::extract(&p, &vpath, &out, &cancel, &want),
            ContainerFormat::Psf => unreachable!("PSF is resolved separately"),
        };
        let ex = match result {
            Ok(ex) => ex,
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
        if ex.skipped.iter().any(|(_, r)| *r == Role::Psf) {
            c.saw_psf = true;
        }
        for item in ex.items {
            let role = role_of(&item.name);
            match role {
                Role::Manifest | Role::Mum => c.add_unique(item, role),
                Role::PkgProperties => {
                    if c.pkg_properties.is_none() {
                        c.pkg_properties = Some(item.bytes()?.into_owned());
                    }
                }
                Role::PsfIndex => c.psf_indexes.push(item),
                Role::Psf => c.psfs.push(item),
                Role::PackageDll => {
                    if c.package_dll.is_none() {
                        c.package_dll = item.path().map(Path::to_path_buf);
                    }
                }
                Role::NestedCab | Role::NestedWim => {
                    let Some(fp) = item.path().map(Path::to_path_buf) else {
                        continue;
                    };
                    let lname = item.name.to_ascii_lowercase();
                    let nested = match sniff(&fp)? {
                        Some(f @ (ContainerFormat::Cab | ContainerFormat::Wim)) => f,
                        _ if role == Role::NestedCab => ContainerFormat::Cab,
                        _ => ContainerFormat::Wim,
                    };
                    if lname == SCAN_METADATA {
                        if is_within(&fp, work) {
                            let _ = std::fs::remove_file(&fp);
                        }
                        c.containers.push(ContainerInfo {
                            path: item.vpath,
                            format: nested,
                            skipped: Some("scan metadata".into()),
                        });
                        continue;
                    }
                    queue.push_back((fp, item.vpath, nested, lname.starts_with(TOOLING_PREFIX)));
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

/// 從已展開的 PSF 取出 manifest / .mum。索引優先用同名 `*.psf.cix.xml`，
/// 其次 `express.psf.cix.xml`，都沒有時讀檔頭內嵌索引。
pub fn resolve_psfs(c: &mut Collected, engine: &DeltaEngine, ctx: &Ctx) -> Result<(), CoreError> {
    for psf_item in std::mem::take(&mut c.psfs) {
        ctx.check()?;
        let Some(path) = psf_item.path().map(Path::to_path_buf) else {
            continue;
        };
        ctx.report(Progress::Unpacking {
            container: psf_item.vpath.clone(),
        });
        let own_index = format!("{}.cix.xml", psf_item.name.to_ascii_lowercase());
        let sidecar = c
            .psf_indexes
            .iter()
            .find(|i| i.name.to_ascii_lowercase() == own_index)
            .or_else(|| {
                c.psf_indexes
                    .iter()
                    .find(|i| i.name.eq_ignore_ascii_case("express.psf.cix.xml"))
            })
            .map(|i| i.bytes().map(Cow::into_owned))
            .transpose()?;
        let entries = match psf::load_index(&path, sidecar.as_deref(), engine) {
            Ok(e) => e,
            Err(e) => {
                c.warnings.push(Warning::new(
                    WarningCode::PsfFailed,
                    &psf_item.vpath,
                    e.to_string(),
                ));
                c.containers.push(ContainerInfo {
                    path: psf_item.vpath.clone(),
                    format: ContainerFormat::Psf,
                    skipped: Some(e.to_string()),
                });
                continue;
            }
        };
        c.containers.push(ContainerInfo {
            path: psf_item.vpath.clone(),
            format: ContainerFormat::Psf,
            skipped: None,
        });
        let mut file = File::open(&path).map_err(|e| CoreError::io(&path, e))?;
        let total = entries.len();
        for (i, entry) in entries.into_iter().enumerate() {
            if i % 250 == 0 {
                ctx.report(Progress::Decoding { done: i, total });
            }
            ctx.check()?;
            let base = entry
                .name
                .rsplit(['\\', '/'])
                .next()
                .unwrap_or("")
                .to_string();
            let role = role_of(&base);
            if !matches!(role, Role::Manifest | Role::Mum) {
                continue;
            }
            let vpath = format!("{}/{}", psf_item.vpath, entry.name.replace('\\', "/"));
            match psf::read_entry(&mut file, &entry, engine) {
                Ok(bytes) => c.add_unique(Item::new(vpath, ItemData::Bytes(bytes)), role),
                Err(e) => {
                    c.warnings
                        .push(Warning::new(WarningCode::PsfFailed, vpath, e.to_string()))
                }
            }
        }
    }
    Ok(())
}
