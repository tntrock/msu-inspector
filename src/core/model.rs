//! 分析結果的資料模型；JSON 匯出直接序列化這些型別（鍵名一律英文）。

use std::collections::BTreeMap;

use serde::Serialize;

/// manifest / .mum 的 `assemblyIdentity`。
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct AssemblyIdentity {
    pub name: String,
    pub version: String,
    pub arch: String,
    pub language: String,
    pub public_key_token: String,
}

impl AssemblyIdentity {
    /// 顯示與搜尋用：`名稱 版本 (架構, 語系)`。
    pub fn display(&self) -> String {
        format!(
            "{} {} ({}, {})",
            self.name, self.version, self.arch, self.language
        )
    }
}

/// 風險等級；`Ord` 依嚴重程度排序（High 最大）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    #[default]
    Info,
    Low,
    Medium,
    High,
}

impl Risk {
    /// 由高到低，GUI 與摘要依此順序列出。
    pub const ALL: [Risk; 4] = [Risk::High, Risk::Medium, Risk::Low, Risk::Info];

    pub fn code(self) -> &'static str {
        match self {
            Risk::Info => "info",
            Risk::Low => "low",
            Risk::Medium => "medium",
            Risk::High => "high",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    File,
    Registry,
    Directory,
    Service,
    Driver,
    ScheduledTask,
    GenericCommand,
    FirewallRule,
    WmiMof,
    EtwEventlog,
    AdvancedInstaller,
    Setting,
    Unknown,
}

impl ActionKind {
    pub const ALL: [ActionKind; 13] = [
        ActionKind::File,
        ActionKind::Registry,
        ActionKind::Directory,
        ActionKind::Service,
        ActionKind::Driver,
        ActionKind::ScheduledTask,
        ActionKind::GenericCommand,
        ActionKind::FirewallRule,
        ActionKind::WmiMof,
        ActionKind::EtwEventlog,
        ActionKind::AdvancedInstaller,
        ActionKind::Setting,
        ActionKind::Unknown,
    ];

    /// JSON 與 `--kinds` 使用的代碼。
    pub fn code(self) -> &'static str {
        match self {
            ActionKind::File => "file",
            ActionKind::Registry => "registry",
            ActionKind::Directory => "directory",
            ActionKind::Service => "service",
            ActionKind::Driver => "driver",
            ActionKind::ScheduledTask => "scheduled_task",
            ActionKind::GenericCommand => "generic_command",
            ActionKind::FirewallRule => "firewall_rule",
            ActionKind::WmiMof => "wmi_mof",
            ActionKind::EtwEventlog => "etw_eventlog",
            ActionKind::AdvancedInstaller => "advanced_installer",
            ActionKind::Setting => "setting",
            ActionKind::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Option<ActionKind> {
        let s = s.trim();
        ActionKind::ALL
            .into_iter()
            .find(|k| k.code().eq_ignore_ascii_case(s))
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FileAction {
    pub name: String,
    pub destination: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sddl_name: Option<String>,
    pub is_pe: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RegistryAction {
    pub key: String,
    /// `None` 表示只建立機碼；`Some("")` 為預設值。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// `replace` / `append` / `prepend` / `create_key`
    pub operation: String,
    pub owner: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sddl_name: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DirectoryAction {
    pub path: String,
    pub owner: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sddl_name: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ServiceAction {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub required_privileges: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub depend_on: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DriverAction {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_type: Option<String>,
    pub boot_critical: bool,
    /// `service`（來自 serviceData）或 `file`（只有 .sys 檔）
    pub origin: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TaskAction {
    pub uri: String,
    pub exec: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_as: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_level: Option<String>,
    pub triggers: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CommandAction {
    pub executable: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<String>,
    /// `install="false"` 的指令只在移除時執行
    pub runs_on_install: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FirewallAction {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_ports: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_ports: Option<String>,
    /// `element`（`<firewallRule>`）或 `registry`（FirewallRules 登錄值）
    pub origin: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MofAction {
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uninstall_file: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct EtwAction {
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guid: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AdvancedInstallerAction {
    pub element: String,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SettingAction {
    pub element: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct UnknownAction {
    pub element: String,
    pub raw_xml: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ActionDetail {
    File(FileAction),
    Registry(RegistryAction),
    Directory(DirectoryAction),
    Service(ServiceAction),
    Driver(DriverAction),
    ScheduledTask(TaskAction),
    GenericCommand(CommandAction),
    FirewallRule(FirewallAction),
    WmiMof(MofAction),
    EtwEventlog(EtwAction),
    AdvancedInstaller(AdvancedInstallerAction),
    Setting(SettingAction),
    Unknown(UnknownAction),
}

/// 把目錄與名稱接成路徑；目錄已以 `\` 結尾時不重複加。
fn join_path(dir: &str, name: &str) -> String {
    if dir.is_empty() || dir.ends_with('\\') {
        format!("{dir}{name}")
    } else {
        format!("{dir}\\{name}")
    }
}

impl ActionDetail {
    pub fn kind(&self) -> ActionKind {
        match self {
            ActionDetail::File(_) => ActionKind::File,
            ActionDetail::Registry(_) => ActionKind::Registry,
            ActionDetail::Directory(_) => ActionKind::Directory,
            ActionDetail::Service(_) => ActionKind::Service,
            ActionDetail::Driver(_) => ActionKind::Driver,
            ActionDetail::ScheduledTask(_) => ActionKind::ScheduledTask,
            ActionDetail::GenericCommand(_) => ActionKind::GenericCommand,
            ActionDetail::FirewallRule(_) => ActionKind::FirewallRule,
            ActionDetail::WmiMof(_) => ActionKind::WmiMof,
            ActionDetail::EtwEventlog(_) => ActionKind::EtwEventlog,
            ActionDetail::AdvancedInstaller(_) => ActionKind::AdvancedInstaller,
            ActionDetail::Setting(_) => ActionKind::Setting,
            ActionDetail::Unknown(_) => ActionKind::Unknown,
        }
    }

    /// 表格「目標」欄：最能代表此動作的路徑、機碼或名稱。
    pub fn target(&self) -> String {
        match self {
            ActionDetail::File(f) => join_path(&f.destination, &f.name),
            ActionDetail::Registry(r) => match &r.value_name {
                None => r.key.clone(),
                Some(v) if v.is_empty() => format!("{} [(default)]", r.key),
                Some(v) => format!("{} [{v}]", r.key),
            },
            ActionDetail::Directory(d) => d.path.clone(),
            ActionDetail::Service(s) => s.name.clone(),
            ActionDetail::Driver(d) => d.name.clone(),
            ActionDetail::ScheduledTask(t) => t.uri.clone(),
            ActionDetail::GenericCommand(c) => match &c.arguments {
                Some(a) if !a.is_empty() => format!("{} {a}", c.executable),
                _ => c.executable.clone(),
            },
            ActionDetail::FirewallRule(f) => f.name.clone(),
            ActionDetail::WmiMof(m) => m.file.clone(),
            ActionDetail::EtwEventlog(e) => e.provider.clone(),
            ActionDetail::AdvancedInstaller(a) => a.element.clone(),
            ActionDetail::Setting(s) => s.element.clone(),
            ActionDetail::Unknown(u) => u.element.clone(),
        }
    }
}

/// 本機比對狀態。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalState {
    /// 本機不存在，會新增
    New,
    /// 本機存在但內容 / 版本不同，會被取代
    Replace,
    /// 與本機相同
    Same,
    /// 本機版本較新（套件會降版）
    Downgrade,
    /// 本機已存在，但無法比較內容
    Present,
    /// 目標路徑無法對應到本機位置
    UnknownPath,
    InStoreSame,
    InStoreOlder,
    InStoreNewer,
    NotInStore,
}

impl LocalState {
    pub const ALL: [LocalState; 10] = [
        LocalState::New,
        LocalState::Replace,
        LocalState::Same,
        LocalState::Downgrade,
        LocalState::Present,
        LocalState::UnknownPath,
        LocalState::InStoreSame,
        LocalState::InStoreOlder,
        LocalState::InStoreNewer,
        LocalState::NotInStore,
    ];

    pub fn code(self) -> &'static str {
        match self {
            LocalState::New => "new",
            LocalState::Replace => "replace",
            LocalState::Same => "same",
            LocalState::Downgrade => "downgrade",
            LocalState::Present => "present",
            LocalState::UnknownPath => "unknown_path",
            LocalState::InStoreSame => "in_store_same",
            LocalState::InStoreOlder => "in_store_older",
            LocalState::InStoreNewer => "in_store_newer",
            LocalState::NotInStore => "not_in_store",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LocalStatus {
    #[serde(rename = "status")]
    pub state: LocalState,
    #[serde(rename = "from", skip_serializing_if = "Option::is_none")]
    pub current: Option<String>,
    #[serde(rename = "to", skip_serializing_if = "Option::is_none")]
    pub incoming: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Action {
    #[serde(flatten)]
    pub detail: ActionDetail,
    pub risk: Risk,
    /// 命中的風險規則 ID（見 `risk.rs`）
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local: Option<LocalStatus>,
}

impl Action {
    pub fn new(detail: ActionDetail) -> Self {
        Action {
            detail,
            risk: Risk::Info,
            rules: Vec::new(),
            local: None,
        }
    }

    pub fn kind(&self) -> ActionKind {
        self.detail.kind()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Component {
    pub identity: AssemblyIdentity,
    /// manifest 檔名
    pub manifest: String,
    /// `Microsoft.Windows.Categories` 的 typeName（BootCritical、Service…）
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
    pub actions: Vec<Action>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local: Option<LocalStatus>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PackageInfo {
    pub kb: Option<String>,
    pub identity: AssemblyIdentity,
    pub release_type: Option<String>,
    /// `required` / `possible` / `never`
    pub restart: Option<String>,
    pub description: Option<String>,
    pub support_url: Option<String>,
    pub psfx: bool,
    pub applicability: Vec<String>,
    pub properties: BTreeMap<String, String>,
    pub sub_packages: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    Valid,
    Unsigned,
    Invalid,
    #[default]
    Unknown,
}

impl SignatureStatus {
    pub fn code(self) -> &'static str {
        match self {
            SignatureStatus::Valid => "valid",
            SignatureStatus::Unsigned => "unsigned",
            SignatureStatus::Invalid => "invalid",
            SignatureStatus::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SignatureInfo {
    pub status: SignatureStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerFormat {
    Cab,
    Wim,
    Psf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContainerInfo {
    pub path: String,
    pub format: ContainerFormat,
    /// 略過或失敗的原因；正常展開為 None
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SourceInfo {
    pub file: String,
    pub size: u64,
    pub sha256: String,
    /// `msu-cab` / `msu-wim` / `cab`，含 PSF 時加上 `+psf`
    pub format: String,
    pub signature: SignatureInfo,
    pub containers: Vec<ContainerInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta_engine: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub enum Mode {
    #[default]
    #[serde(rename = "static")]
    Static,
    #[serde(rename = "static+local")]
    StaticLocal,
}

impl Mode {
    pub fn code(self) -> &'static str {
        match self {
            Mode::Static => "static",
            Mode::StaticLocal => "static+local",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct LocalContext {
    /// 例如 `26100.4202`
    pub os_build: String,
    pub arch: String,
    pub applicable: bool,
    /// `arch_mismatch` / `build_mismatch`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_applicable_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WarningCode {
    ManifestDecodeFailed,
    ManifestParseFailed,
    MumParseFailed,
    ContainerFailed,
    PsfFailed,
    SignatureNotValid,
    LocalCompareFailed,
    TempCleanupFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Warning {
    pub code: WarningCode,
    pub subject: String,
    pub detail: String,
}

impl Warning {
    pub fn new(code: WarningCode, subject: impl Into<String>, detail: impl Into<String>) -> Self {
        Warning {
            code,
            subject: subject.into(),
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct AnalysisReport {
    pub mode: Mode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_context: Option<LocalContext>,
    pub source: SourceInfo,
    pub package: PackageInfo,
    pub components: Vec<Component>,
    pub warnings: Vec<Warning>,
}

impl AnalysisReport {
    pub fn action_count(&self) -> usize {
        self.components.iter().map(|c| c.actions.len()).sum()
    }
}

/// 解析 `a.b.c.d` 版本字串；缺少的欄位補 0，非數字或超過四段回傳 None。
pub fn parse_version(s: &str) -> Option<[u32; 4]> {
    let mut out = [0u32; 4];
    for (i, part) in s.trim().split('.').enumerate() {
        if i >= 4 {
            return None;
        }
        out[i] = part.parse().ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn action_serializes_flat_with_kind() {
        let a = Action::new(ActionDetail::File(FileAction {
            name: "a.dll".into(),
            destination: "$(runtime.system32)\\".into(),
            is_pe: true,
            ..Default::default()
        }));
        let v = serde_json::to_value(&a).unwrap();
        assert_eq!(v["kind"], "file");
        assert_eq!(v["name"], "a.dll");
        assert_eq!(v["risk"], "info");
        assert!(v.get("rules").is_none());
        assert!(v.get("local").is_none());
        assert!(v.get("source_name").is_none());
    }

    #[test]
    fn local_status_uses_spec_keys() {
        let s = LocalStatus {
            state: LocalState::Replace,
            current: Some("10.0.1".into()),
            incoming: Some("10.0.2".into()),
        };
        assert_eq!(
            serde_json::to_value(&s).unwrap(),
            json!({"status": "replace", "from": "10.0.1", "to": "10.0.2"})
        );
    }

    #[test]
    fn kind_codes_round_trip() {
        for k in ActionKind::ALL {
            assert_eq!(ActionKind::parse(k.code()), Some(k));
            assert_eq!(serde_json::to_value(k).unwrap(), json!(k.code()));
        }
        assert_eq!(ActionKind::parse("nope"), None);
    }

    #[test]
    fn risk_orders_by_severity() {
        assert!(Risk::High > Risk::Medium && Risk::Medium > Risk::Low && Risk::Low > Risk::Info);
        assert_eq!(Risk::ALL[0], Risk::High);
    }

    #[test]
    fn mode_serializes_like_spec() {
        assert_eq!(
            serde_json::to_value(Mode::StaticLocal).unwrap(),
            json!("static+local")
        );
        assert_eq!(Mode::Static.code(), "static");
    }

    #[test]
    fn parses_versions() {
        assert_eq!(parse_version("10.0.26100.1742"), Some([10, 0, 26100, 1742]));
        assert_eq!(parse_version("6.1"), Some([6, 1, 0, 0]));
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("1.2.3.4.5"), None);
        assert_eq!(parse_version("a.b"), None);
    }

    #[test]
    fn targets_are_readable() {
        let reg = ActionDetail::Registry(RegistryAction {
            key: "HKEY_LOCAL_MACHINE\\SOFTWARE\\X".into(),
            value_name: Some(String::new()),
            ..Default::default()
        });
        assert_eq!(reg.target(), "HKEY_LOCAL_MACHINE\\SOFTWARE\\X [(default)]");
        let file = ActionDetail::File(FileAction {
            name: "a.dll".into(),
            destination: "$(runtime.system32)".into(),
            ..Default::default()
        });
        assert_eq!(file.target(), "$(runtime.system32)\\a.dll");
    }
}
