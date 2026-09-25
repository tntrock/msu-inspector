//! 本機比對（唯讀）：檔案版本、元件存放區、登錄、服務、排程工作與適用性。

use std::collections::HashMap;
use std::ffi::c_void;
use std::path::{Path, PathBuf};

use windows::core::{w, HSTRING};
use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, VS_FIXEDFILEINFO,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
    KEY_WOW64_32KEY, KEY_WOW64_64KEY, REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ,
    REG_QWORD, REG_SZ, REG_VALUE_TYPE,
};

use super::model::*;
use super::progress::{Ctx, Progress};
use super::{sys, CoreError};

/// 比對結果中保留的字串長度上限（避免 REG_BINARY 塞爆 JSON）。
const MAX_SHOWN: usize = 512;

fn clip(s: &str) -> String {
    if s.len() <= MAX_SHOWN {
        return s.to_string();
    }
    let mut end = MAX_SHOWN;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

fn fmt_version(v: [u32; 4]) -> String {
    format!("{}.{}.{}.{}", v[0], v[1], v[2], v[3])
}

fn status(state: LocalState, current: Option<String>, incoming: Option<String>) -> LocalStatus {
    LocalStatus {
        state,
        current,
        incoming,
    }
}

// ---------------- 環境 ----------------

pub struct LocalEnv {
    pub windows: PathBuf,
    pub arch: String,
    pub build: u32,
    pub ubr: u32,
    pub store: Store,
}

impl LocalEnv {
    pub fn detect() -> Result<Self, CoreError> {
        let windows = sys::windows_dir();
        let cv = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
        let build = read_reg_value(cv, "CurrentBuildNumber", false)
            .and_then(|v| v.render().trim().parse().ok())
            .ok_or_else(|| CoreError::Win32("cannot read CurrentBuildNumber".into()))?;
        let ubr = read_reg_value(cv, "UBR", false)
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        let store = Store::load(&windows)?;
        Ok(LocalEnv {
            windows,
            arch: sys::native_arch().to_string(),
            build,
            ubr,
            store,
        })
    }

    pub fn os_build(&self) -> String {
        format!("{}.{}", self.build, self.ubr)
    }
}

// ---------------- 元件存放區 ----------------

/// `Store::entries` 的鍵：(架構, token, 語系)；值：[(短名稱, 版本)]。
type StoreEntries = HashMap<(String, String, String), Vec<(String, [u32; 4])>>;

/// `WinSxS\Manifests` 的檔名索引：(架構, token, 語系) → [(短名稱, 版本)]。
pub struct Store {
    entries: StoreEntries,
    count: usize,
}

impl Store {
    /// keyform：`arch_短名稱_token_版本_語系_雜湊`；短名稱本身可能含 `_`，所以從兩端切。
    pub fn from_names<'a>(names: impl IntoIterator<Item = &'a str>) -> Self {
        let mut entries: StoreEntries = HashMap::new();
        let mut count = 0;
        for n in names {
            let n = n.to_ascii_lowercase();
            let n = n.strip_suffix(".manifest").unwrap_or(&n);
            let parts: Vec<&str> = n.split('_').collect();
            let len = parts.len();
            if len < 6 {
                continue;
            }
            let Some(ver) = parse_version(parts[len - 3]) else {
                continue;
            };
            let key = (
                parts[0].to_string(),
                parts[len - 4].to_string(),
                parts[len - 2].to_string(),
            );
            entries
                .entry(key)
                .or_default()
                .push((parts[1..len - 4].join("_"), ver));
            count += 1;
        }
        Store { entries, count }
    }

    pub fn load(windows: &Path) -> Result<Self, CoreError> {
        let dir = windows.join("WinSxS").join("Manifests");
        let names: Vec<String> = std::fs::read_dir(&dir)
            .map_err(|e| CoreError::io(&dir, e))?
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        Ok(Store::from_names(names.iter().map(String::as_str)))
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn versions(&self, id: &AssemblyIdentity) -> Vec<[u32; 4]> {
        let lang = if id.language.is_empty() || id.language.eq_ignore_ascii_case("neutral") {
            "none".to_string()
        } else {
            id.language.to_ascii_lowercase()
        };
        let key = (
            id.arch.to_ascii_lowercase(),
            id.public_key_token.to_ascii_lowercase(),
            lang,
        );
        let name = id.name.to_ascii_lowercase();
        self.entries
            .get(&key)
            .map(|list| {
                list.iter()
                    .filter(|(short, _)| keyform_matches(short, &name))
                    .map(|(_, v)| *v)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// 長名稱在 keyform 中會截成 `前綴..後綴`。
pub fn keyform_matches(short: &str, full: &str) -> bool {
    match short.split_once("..") {
        None => short == full,
        Some((pre, suf)) => {
            full.len() >= pre.len() + suf.len() && full.starts_with(pre) && full.ends_with(suf)
        }
    }
}

pub fn compare_component(store: &Store, id: &AssemblyIdentity) -> LocalStatus {
    let versions = store.versions(id);
    let max = versions.iter().max().copied();
    let state = match (parse_version(&id.version), max) {
        (Some(inc), Some(_)) if versions.contains(&inc) => LocalState::InStoreSame,
        (Some(inc), Some(m)) if m < inc => LocalState::InStoreOlder,
        (Some(_), Some(_)) => LocalState::InStoreNewer,
        _ => LocalState::NotInStore,
    };
    status(state, max.map(fmt_version), Some(id.version.clone()))
}

// ---------------- 檔案 ----------------

/// 把 manifest 的 `$(runtime.xxx)` 目的路徑轉成本機路徑；無法對應時回傳 None。
pub fn resolve_path(dest: &str, windows: &Path, wow32: bool) -> Option<PathBuf> {
    let rest = dest.strip_prefix("$(")?;
    let end = rest.find(')')?;
    let var = rest[..end].to_ascii_lowercase();
    let tail = rest[end + 1..].trim_start_matches('\\');
    let win = windows.to_string_lossy();
    let drive = PathBuf::from(format!("{}\\", win.get(..2)?));
    let program_files = if wow32 {
        "Program Files (x86)"
    } else {
        "Program Files"
    };
    let sys32 = windows.join(if wow32 { "SysWOW64" } else { "System32" });
    let base = match var.as_str() {
        "runtime.system32" | "runtime.system" => sys32,
        "runtime.windows" | "runtime.systemroot" => windows.to_path_buf(),
        "runtime.drivers" => windows.join("System32").join("drivers"),
        "runtime.wbem" => sys32.join("wbem"),
        "runtime.fonts" => windows.join("Fonts"),
        "runtime.inf" => windows.join("INF"),
        "runtime.help" => windows.join("Help"),
        "runtime.bootdrive" | "runtime.systemdrive" => drive,
        "runtime.programfiles" => drive.join(program_files),
        "runtime.programfilesx86" => drive.join("Program Files (x86)"),
        "runtime.commonfiles" => drive.join(program_files).join("Common Files"),
        "runtime.programdata" => drive.join("ProgramData"),
        _ => return None,
    };
    Some(if tail.is_empty() {
        base
    } else {
        base.join(tail)
    })
}

pub fn file_version(path: &Path) -> Option<String> {
    let name = HSTRING::from(path.as_os_str());
    // SAFETY: 緩衝區大小由 GetFileVersionInfoSizeW 決定；VerQueryValueW 回傳的指標指向該緩衝區。
    unsafe {
        let size = GetFileVersionInfoSizeW(&name, None);
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        GetFileVersionInfoW(&name, None, size, buf.as_mut_ptr().cast()).ok()?;
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let mut len = 0u32;
        if !VerQueryValueW(buf.as_ptr().cast(), w!("\\"), &mut ptr, &mut len).as_bool()
            || ptr.is_null()
        {
            return None;
        }
        let info = &*(ptr as *const VS_FIXEDFILEINFO);
        Some(format!(
            "{}.{}.{}.{}",
            info.dwFileVersionMS >> 16,
            info.dwFileVersionMS & 0xFFFF,
            info.dwFileVersionLS >> 16,
            info.dwFileVersionLS & 0xFFFF
        ))
    }
}

pub fn compare_versions(current: Option<&str>, incoming: &str) -> LocalState {
    let Some(cur) = current else {
        return LocalState::New;
    };
    match (parse_version(cur), parse_version(incoming)) {
        (Some(c), Some(i)) if c < i => LocalState::Replace,
        (Some(c), Some(i)) if c == i => LocalState::Same,
        (Some(_), Some(_)) => LocalState::Downgrade,
        _ => LocalState::Present,
    }
}

/// 檔案沒有個別版本欄位，`incoming` 用所屬元件版本。
pub fn compare_file(
    f: &FileAction,
    component_version: &str,
    wow32: bool,
    windows: &Path,
) -> LocalStatus {
    let Some(dir) = resolve_path(&f.destination, windows, wow32) else {
        return status(LocalState::UnknownPath, None, None);
    };
    let path = dir.join(&f.name);
    if !path.exists() {
        return status(LocalState::New, None, Some(component_version.to_string()));
    }
    if !f.is_pe {
        return status(LocalState::Present, None, None);
    }
    let current = file_version(&path);
    let state = compare_versions(current.as_deref(), component_version);
    let state = if current.is_none() {
        LocalState::Present
    } else {
        state
    };
    status(state, current, Some(component_version.to_string()))
}

// ---------------- 登錄 ----------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegValue {
    Str(String),
    MultiStr(Vec<String>),
    Dword(u32),
    Qword(u64),
    Binary(Vec<u8>),
    Other(u32, Vec<u8>),
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

impl RegValue {
    /// 與 manifest 相同的表示法：DWORD 為 `0x%08x`、MULTI_SZ 為 `"a","b"`、二進位為大寫十六進位。
    pub fn render(&self) -> String {
        match self {
            RegValue::Str(s) => s.clone(),
            RegValue::MultiStr(v) => v
                .iter()
                .map(|s| format!("\"{s}\""))
                .collect::<Vec<_>>()
                .join(","),
            RegValue::Dword(d) => format!("0x{d:08x}"),
            RegValue::Qword(q) => format!("0x{q:016x}"),
            RegValue::Binary(b) | RegValue::Other(_, b) => hex(b),
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            RegValue::Dword(d) => Some(*d as u64),
            RegValue::Qword(q) => Some(*q),
            _ => None,
        }
    }
}

fn utf16_units(buf: &[u8]) -> Vec<u16> {
    buf.chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect()
}

fn decode_reg(ty: REG_VALUE_TYPE, buf: &[u8]) -> RegValue {
    match ty {
        REG_SZ | REG_EXPAND_SZ => {
            let u = utf16_units(buf);
            let end = u.iter().position(|&c| c == 0).unwrap_or(u.len());
            RegValue::Str(String::from_utf16_lossy(&u[..end]))
        }
        REG_MULTI_SZ => RegValue::MultiStr(
            String::from_utf16_lossy(&utf16_units(buf))
                .split('\0')
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
        ),
        REG_DWORD if buf.len() >= 4 => {
            RegValue::Dword(u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]))
        }
        REG_QWORD if buf.len() >= 8 => {
            RegValue::Qword(u64::from_le_bytes(buf[..8].try_into().unwrap_or_default()))
        }
        REG_BINARY => RegValue::Binary(buf.to_vec()),
        other => RegValue::Other(other.0, buf.to_vec()),
    }
}

/// `HKEY_LOCAL_MACHINE\...` / `HKEY_CLASSES_ROOT\...` → (根機碼, 子機碼)；其他根（例如 HKCU）無法對應。
fn split_root(key: &str) -> Option<(HKEY, String)> {
    let lower = key.to_ascii_lowercase();
    if lower.starts_with("hkey_local_machine\\") {
        Some((
            HKEY_LOCAL_MACHINE,
            key["hkey_local_machine\\".len()..].to_string(),
        ))
    } else if lower.starts_with("hkey_classes_root\\") {
        Some((
            HKEY_LOCAL_MACHINE,
            format!("SOFTWARE\\Classes\\{}", &key["hkey_classes_root\\".len()..]),
        ))
    } else {
        None
    }
}

fn open_key(key_name: &str, wow32: bool) -> Option<HKEY> {
    let (root, sub) = split_root(key_name)?;
    let access = KEY_READ
        | if wow32 {
            KEY_WOW64_32KEY
        } else {
            KEY_WOW64_64KEY
        };
    let mut hkey = HKEY::default();
    // SAFETY: 成功時由呼叫端以 RegCloseKey 關閉。
    let r = unsafe { RegOpenKeyExW(root, &HSTRING::from(sub), Some(0), access, &mut hkey) };
    (r == ERROR_SUCCESS).then_some(hkey)
}

pub fn read_reg_value(key_name: &str, value: &str, wow32: bool) -> Option<RegValue> {
    let hkey = open_key(key_name, wow32)?;
    let name = HSTRING::from(value);
    // SAFETY: 兩段式查詢：先取大小再讀取。
    unsafe {
        let mut ty = REG_VALUE_TYPE::default();
        let mut len = 0u32;
        let mut result = RegQueryValueExW(hkey, &name, None, Some(&mut ty), None, Some(&mut len));
        let mut buf = vec![0u8; len as usize];
        if result == ERROR_SUCCESS {
            result = RegQueryValueExW(
                hkey,
                &name,
                None,
                Some(&mut ty),
                Some(buf.as_mut_ptr()),
                Some(&mut len),
            );
        }
        let _ = RegCloseKey(hkey);
        if result != ERROR_SUCCESS {
            return None;
        }
        buf.truncate(len as usize);
        Some(decode_reg(ty, &buf))
    }
}

fn key_exists(key_name: &str, wow32: bool) -> Option<bool> {
    split_root(key_name)?;
    Some(match open_key(key_name, wow32) {
        Some(h) => {
            // SAFETY: h 由 open_key 開啟。
            unsafe {
                let _ = RegCloseKey(h);
            }
            true
        }
        None => false,
    })
}

fn parse_number(s: &str) -> Option<u64> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

fn parse_multi(s: &str) -> Vec<String> {
    s.split("\",\"")
        .map(|p| p.trim().trim_matches('"').to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

pub fn same_value(value_type: &str, incoming: &str, current: &RegValue) -> bool {
    match value_type.to_ascii_uppercase().as_str() {
        "REG_DWORD" | "REG_QWORD" => {
            parse_number(incoming).is_some_and(|n| current.as_u64() == Some(n))
        }
        "REG_BINARY" => {
            let want: String = incoming
                .chars()
                .filter(char::is_ascii_hexdigit)
                .collect::<String>()
                .to_ascii_uppercase();
            want == current.render()
        }
        "REG_MULTI_SZ" => match current {
            RegValue::MultiStr(v) => parse_multi(incoming) == *v,
            _ => false,
        },
        _ => matches!(current, RegValue::Str(s) if s == incoming),
    }
}

pub fn compare_registry(r: &RegistryAction, wow32: bool) -> LocalStatus {
    let Some(value) = &r.value_name else {
        return match key_exists(&r.key, wow32) {
            None => status(LocalState::UnknownPath, None, None),
            Some(true) => status(LocalState::Same, None, None),
            Some(false) => status(LocalState::New, None, None),
        };
    };
    if split_root(&r.key).is_none() {
        return status(LocalState::UnknownPath, None, None);
    }
    let incoming = r.data.as_deref().map(clip);
    match read_reg_value(&r.key, value, wow32) {
        None => status(LocalState::New, None, incoming),
        Some(cur) => {
            let same = r
                .data
                .as_deref()
                .is_none_or(|d| same_value(r.value_type.as_deref().unwrap_or("REG_SZ"), d, &cur));
            let state = if same {
                LocalState::Same
            } else {
                LocalState::Replace
            };
            status(state, Some(clip(&cur.render())), incoming)
        }
    }
}

// ---------------- 服務與排程工作 ----------------

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceSnapshot {
    pub start: Option<String>,
    pub account: Option<String>,
    pub image: Option<String>,
}

impl ServiceSnapshot {
    fn describe(&self) -> String {
        format!(
            "start={}; account={}; image={}",
            self.start.as_deref().unwrap_or("-"),
            self.account.as_deref().unwrap_or("-"),
            self.image.as_deref().unwrap_or("-")
        )
    }
}

pub fn read_service(name: &str) -> Option<ServiceSnapshot> {
    let key = format!(r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{name}");
    let start = read_reg_value(&key, "Start", false)?.as_u64()?;
    let delayed =
        read_reg_value(&key, "DelayedAutostart", false).and_then(|v| v.as_u64()) == Some(1);
    let start = match (start, delayed) {
        (0, _) => "boot",
        (1, _) => "system",
        (2, true) => "delayedAuto",
        (2, false) => "auto",
        (3, _) => "demand",
        (4, _) => "disabled",
        _ => "unknown",
    };
    Some(ServiceSnapshot {
        start: Some(start.to_string()),
        account: read_reg_value(&key, "ObjectName", false).map(|v| v.render()),
        image: read_reg_value(&key, "ImagePath", false).map(|v| v.render()),
    })
}

fn normalize_image(image: &str, windows: &Path) -> String {
    let mut s = image.trim().trim_matches('"').to_ascii_lowercase();
    let win = format!("{}\\", windows.to_string_lossy().to_ascii_lowercase());
    for prefix in [
        "\\??\\",
        "%systemroot%\\",
        "%windir%\\",
        "\\systemroot\\",
        win.as_str(),
    ] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest.to_string();
        }
    }
    s
}

/// manifest 沒寫的欄位不比對。
pub fn service_matches(
    incoming: &ServiceSnapshot,
    current: &ServiceSnapshot,
    windows: &Path,
) -> bool {
    let eq = |a: &Option<String>, b: &Option<String>| match (a, b) {
        (None, _) => true,
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        (Some(_), None) => false,
    };
    let image_eq = match (&incoming.image, &current.image) {
        (None, _) => true,
        (Some(a), Some(b)) => normalize_image(a, windows) == normalize_image(b, windows),
        (Some(_), None) => false,
    };
    eq(&incoming.start, &current.start) && eq(&incoming.account, &current.account) && image_eq
}

pub fn compare_service(name: &str, incoming: &ServiceSnapshot, windows: &Path) -> LocalStatus {
    match read_service(name) {
        None => status(LocalState::New, None, Some(incoming.describe())),
        Some(cur) => {
            let state = if service_matches(incoming, &cur, windows) {
                LocalState::Same
            } else {
                LocalState::Replace
            };
            status(state, Some(cur.describe()), Some(incoming.describe()))
        }
    }
}

pub fn compare_task(uri: &str, windows: &Path) -> LocalStatus {
    let path = windows
        .join("System32")
        .join("Tasks")
        .join(uri.trim_start_matches('\\'));
    let state = if path.exists() {
        LocalState::Present
    } else {
        LocalState::New
    };
    status(state, None, None)
}

// ---------------- 適用性與整體流程 ----------------

/// 共用同一套服務元件的版本（例如 25H2 的 26200 使用 26100 的累積更新）。
pub fn servicing_base(build: u32) -> u32 {
    match build {
        19041..=19045 => 19041,
        22621 | 22631 => 22621,
        26100 | 26200 => 26100,
        b => b,
    }
}

/// 元件版本 `10.0.<build>.x` 中最常見的 build（忽略 .NET 等非 Windows 版本號）。
pub fn target_build(components: &[Component]) -> Option<u32> {
    let mut counts: HashMap<u32, usize> = HashMap::new();
    for c in components {
        if let Some(v) = parse_version(&c.identity.version) {
            if v[0] == 10 && v[1] == 0 && v[2] >= 10240 {
                *counts.entry(v[2]).or_default() += 1;
            }
        }
    }
    counts
        .into_iter()
        .max_by_key(|&(b, n)| (n, b))
        .map(|(b, _)| b)
}

pub fn applicability(
    report: &AnalysisReport,
    arch: &str,
    build: u32,
) -> (bool, Option<&'static str>) {
    let pkg_arch = report.package.identity.arch.to_ascii_lowercase();
    if !pkg_arch.is_empty() && pkg_arch != "neutral" && pkg_arch != arch {
        return (false, Some("arch_mismatch"));
    }
    if let Some(t) = target_build(&report.components) {
        if servicing_base(t) != servicing_base(build) {
            return (false, Some("build_mismatch"));
        }
    }
    (true, None)
}

fn is_wow(component_arch: &str, native: &str) -> bool {
    let a = component_arch.to_ascii_lowercase();
    (a == "wow64" || a == "x86") && native != "x86"
}

fn compare_action(
    detail: &ActionDetail,
    version: &str,
    wow32: bool,
    env: &LocalEnv,
) -> Option<LocalStatus> {
    match detail {
        ActionDetail::File(f) => Some(compare_file(f, version, wow32, &env.windows)),
        ActionDetail::Registry(r) => Some(compare_registry(r, wow32)),
        ActionDetail::Service(s) => Some(compare_service(
            &s.name,
            &ServiceSnapshot {
                start: s.start.clone(),
                account: s.account.clone(),
                image: s.image_path.clone(),
            },
            &env.windows,
        )),
        ActionDetail::Driver(d) if d.origin == "service" => Some(compare_service(
            &d.name,
            &ServiceSnapshot {
                start: d.start.clone(),
                account: None,
                image: d.image_path.clone(),
            },
            &env.windows,
        )),
        ActionDetail::ScheduledTask(t) => Some(compare_task(&t.uri, &env.windows)),
        _ => None,
    }
}

pub fn compare(report: &mut AnalysisReport, env: &LocalEnv, ctx: &Ctx) -> Result<(), CoreError> {
    let (applicable, reason) = applicability(report, &env.arch, env.build);
    report.mode = Mode::StaticLocal;
    report.local_context = Some(LocalContext {
        os_build: env.os_build(),
        arch: env.arch.clone(),
        applicable,
        not_applicable_reason: reason.map(str::to_string),
    });
    let total = report.components.len();
    for (i, comp) in report.components.iter_mut().enumerate() {
        if i % 100 == 0 {
            ctx.check()?;
            ctx.report(Progress::Comparing { done: i, total });
        }
        comp.local = Some(compare_component(&env.store, &comp.identity));
        let wow32 = is_wow(&comp.identity.arch, &env.arch);
        let version = comp.identity.version.clone();
        for a in &mut comp.actions {
            a.local = compare_action(&a.detail, &version, wow32, env);
        }
    }
    ctx.report(Progress::Comparing { done: total, total });
    Ok(())
}
