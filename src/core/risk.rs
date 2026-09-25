//! 風險規則：每條規則有 ID、等級與中英文理由；命中的 ID 記在 `Action.rules`。

use super::model::*;
use crate::i18n::Lang;

pub struct Rule {
    pub id: &'static str,
    pub level: Risk,
    pub zh: &'static str,
    pub en: &'static str,
}

impl Rule {
    pub fn reason(&self, lang: Lang) -> &'static str {
        match lang {
            Lang::ZhTw => self.zh,
            Lang::En => self.en,
        }
    }
}

macro_rules! rule {
    ($id:literal, $level:ident, $zh:literal, $en:literal) => {
        Rule {
            id: $id,
            level: Risk::$level,
            zh: $zh,
            en: $en,
        }
    };
}

pub const RULES: &[Rule] = &[
    rule!(
        "DRV_BOOT_START",
        High,
        "在開機或系統啟動階段載入的驅動程式",
        "Driver loaded at boot or system start"
    ),
    rule!(
        "DRV_BOOT_CRITICAL",
        High,
        "列為 BootCritical 的驅動程式，失敗可能導致無法開機",
        "BootCritical driver; a failure can prevent booting"
    ),
    rule!(
        "CMD_GENERIC",
        High,
        "安裝時執行外部程式（genericCommand）",
        "Runs an external program during installation (genericCommand)"
    ),
    rule!(
        "AI_BOOT",
        High,
        "更新開機管理程式、開機檔案或 Secure Boot 設定",
        "Updates the boot manager, boot files or Secure Boot configuration"
    ),
    rule!(
        "REG_AUTOSTART",
        High,
        "寫入自動啟動或登入流程相關的登錄位置",
        "Writes an autostart or logon-related registry location"
    ),
    rule!(
        "REG_SECURITY",
        High,
        "修改 LSA、驗證或認證提供者等安全性設定",
        "Changes LSA, authentication or credential provider settings"
    ),
    rule!(
        "FW_INBOUND_ALLOW",
        High,
        "允許輸入連線的防火牆規則",
        "Firewall rule that allows inbound traffic"
    ),
    rule!(
        "SVC_NEW",
        High,
        "本機尚未存在的新服務",
        "New service that does not exist on this machine"
    ),
    rule!(
        "SVC_CHANGED",
        High,
        "變更現有服務的啟動類型、帳戶或映像路徑",
        "Changes an existing service's start type, account or image path"
    ),
    rule!(
        "TASK_NEW",
        High,
        "本機尚未存在的新排程工作",
        "New scheduled task that does not exist on this machine"
    ),
    rule!(
        "AI_CUSTOM",
        Medium,
        "安裝時由進階安裝程式執行自訂動作",
        "An advanced installer runs custom actions during installation"
    ),
    rule!("FW_RULE", Medium, "防火牆規則", "Firewall rule"),
    rule!(
        "TASK_DEFINED",
        Medium,
        "定義排程工作",
        "Defines a scheduled task"
    ),
    rule!(
        "WMI_MOF",
        Medium,
        "編譯並註冊 WMI MOF",
        "Compiles and registers a WMI MOF"
    ),
    rule!(
        "COM_REGISTRATION",
        Medium,
        "註冊 COM 伺服器",
        "Registers a COM server"
    ),
    rule!(
        "PE_SYSTEM",
        Medium,
        "替換 System32 或驅動程式資料夾中的可執行檔",
        "Replaces an executable in System32 or the drivers folder"
    ),
    rule!(
        "DRV_FILE",
        Medium,
        "安裝驅動程式檔案（.sys）",
        "Installs a driver file (.sys)"
    ),
    rule!(
        "UNKNOWN_ELEMENT",
        Medium,
        "未辨識的 manifest 元素，需要人工檢視",
        "Unrecognized manifest element; review manually"
    ),
    rule!(
        "SVC_DEFINED",
        Low,
        "定義服務設定",
        "Defines service configuration"
    ),
    rule!(
        "UNCHANGED_COMPONENT",
        Info,
        "本機元件存放區已有相同版本，此動作不會改變系統",
        "The same component version is already in the local store; no change"
    ),
];

pub fn rule(id: &str) -> Option<&'static Rule> {
    RULES.iter().find(|r| r.id == id)
}

/// 沒有命中任何規則時的預設等級。
pub fn base_level(kind: ActionKind) -> Risk {
    match kind {
        ActionKind::EtwEventlog | ActionKind::Setting => Risk::Info,
        _ => Risk::Low,
    }
}

const AUTOSTART_KEYS: &[&str] = &[
    "\\currentversion\\run",
    "\\currentversion\\runonce",
    "\\currentversion\\winlogon",
    "\\image file execution options",
    "\\session manager\\knowndlls",
    "\\explorer\\shellserviceobjectdelayload",
    "\\active setup\\installed components",
    "\\appcertdlls",
];
const SESSION_MANAGER_VALUES: &[&str] =
    &["bootexecute", "setupexecute", "pendingfilerenameoperations"];
const APPINIT_VALUES: &[&str] = &["appinit_dlls", "loadappinit_dlls"];
const SECURITY_KEYS: &[&str] = &[
    "\\control\\lsa",
    "\\authentication\\credential providers",
    "\\authentication\\credential provider filters",
    "\\control\\securityproviders",
    "\\credentialsdelegation",
    "\\control\\cryptography\\configuration",
];
const BOOT_INSTALLERS: &[&str] = &["bfsvc", "secureboot", "fveupdateai"];

fn registry_rules(r: &RegistryAction, out: &mut Vec<&'static str>) {
    let key = r.key.to_ascii_lowercase();
    let value = r.value_name.as_deref().unwrap_or("").to_ascii_lowercase();
    let autostart = AUTOSTART_KEYS.iter().any(|k| key.contains(k))
        || (key.ends_with("\\control\\session manager")
            && SESSION_MANAGER_VALUES.contains(&value.as_str()))
        || (key.ends_with("\\windows nt\\currentversion\\windows")
            && APPINIT_VALUES.contains(&value.as_str()));
    if autostart {
        out.push("REG_AUTOSTART");
    }
    if SECURITY_KEYS.iter().any(|k| key.contains(k)) {
        out.push("REG_SECURITY");
    }
    if key.contains("\\clsid\\{")
        && (key.ends_with("\\inprocserver32") || key.ends_with("\\localserver32"))
    {
        out.push("COM_REGISTRATION");
    }
}

fn local_state(action: &Action) -> Option<LocalState> {
    action.local.as_ref().map(|l| l.state)
}

pub fn evaluate(comp: &Component, action: &Action) -> Vec<&'static str> {
    if comp
        .local
        .as_ref()
        .is_some_and(|l| l.state == LocalState::InStoreSame)
    {
        return vec!["UNCHANGED_COMPONENT"];
    }
    let mut out = Vec::new();
    match &action.detail {
        ActionDetail::Driver(d) => {
            if d.start
                .as_deref()
                .is_some_and(|s| s.eq_ignore_ascii_case("boot") || s.eq_ignore_ascii_case("system"))
            {
                out.push("DRV_BOOT_START");
            }
            if d.boot_critical {
                out.push("DRV_BOOT_CRITICAL");
            }
            if d.origin == "file" {
                out.push("DRV_FILE");
            }
        }
        ActionDetail::GenericCommand(c) if c.runs_on_install => out.push("CMD_GENERIC"),
        ActionDetail::AdvancedInstaller(a) => {
            if BOOT_INSTALLERS.contains(&a.element.to_ascii_lowercase().as_str()) {
                out.push("AI_BOOT");
            } else {
                out.push("AI_CUSTOM");
            }
        }
        ActionDetail::Registry(r) => registry_rules(r, &mut out),
        ActionDetail::FirewallRule(f) => {
            let inbound = f
                .direction
                .as_deref()
                .is_some_and(|d| d.eq_ignore_ascii_case("in"));
            let allow = f
                .action
                .as_deref()
                .is_some_and(|a| a.eq_ignore_ascii_case("allow"));
            out.push(if inbound && allow {
                "FW_INBOUND_ALLOW"
            } else {
                "FW_RULE"
            });
        }
        ActionDetail::Service(_) => out.push(match local_state(action) {
            Some(LocalState::New) => "SVC_NEW",
            Some(LocalState::Replace) => "SVC_CHANGED",
            _ => "SVC_DEFINED",
        }),
        ActionDetail::ScheduledTask(_) => out.push(match local_state(action) {
            Some(LocalState::New) => "TASK_NEW",
            _ => "TASK_DEFINED",
        }),
        ActionDetail::WmiMof(_) => out.push("WMI_MOF"),
        ActionDetail::File(f) => {
            let dest = f.destination.to_ascii_lowercase();
            if f.is_pe
                && (dest.contains("$(runtime.system32)")
                    || dest.contains("$(runtime.drivers)")
                    || dest.contains("\\system32\\"))
            {
                out.push("PE_SYSTEM");
            }
        }
        ActionDetail::Unknown(_) => out.push("UNKNOWN_ELEMENT"),
        _ => {}
    }
    out
}

pub fn apply(report: &mut AnalysisReport) {
    for comp in &mut report.components {
        let hits: Vec<Vec<&'static str>> = comp.actions.iter().map(|a| evaluate(comp, a)).collect();
        for (action, rules) in comp.actions.iter_mut().zip(hits) {
            let unchanged = rules == ["UNCHANGED_COMPONENT"];
            let from_rules = rules
                .iter()
                .filter_map(|id| rule(id))
                .map(|r| r.level)
                .max();
            action.risk = if unchanged {
                Risk::Info
            } else {
                from_rules
                    .unwrap_or(Risk::Info)
                    .max(base_level(action.kind()))
            };
            action.rules = rules;
        }
    }
}
