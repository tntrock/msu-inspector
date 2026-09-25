//! 元件 manifest → `Component`。
//!
//! 頂層元素的分類依據本機 WinSxS 19,173 個 manifest 的統計（見 spec 第 11 節）。

use roxmltree::Node;

use super::{attr, child, elements, identity_of, is_el, parse_doc};
use crate::core::model::*;
use crate::core::CoreError;

/// 不視為「動作」的結構性元素。
const STRUCTURAL: &[&str] = &[
    "assemblyIdentity",
    "dependency",
    "trustInfo",
    "localization",
    "deployment",
    "migration",
    "rescache",
    "languagePack",
    "imaging",
    "feature",
    "categoryDefinitions",
    "satelliteCategory",
    "languageCategory",
    "containsSettings",
    "compatibility",
    "noInheritable",
    "mvid",
    "application",
];

const PE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "sys", "efi", "ocx", "cpl", "scr", "drv", "com",
];

/// 安裝時會執行自訂程式碼、但名稱不以 `AI` 結尾的進階安裝程式元素。
const ADVANCED_INSTALLERS: &[&str] = &[
    "bfsvc",
    "SecureBoot",
    "appxRegistration",
    "networkComponents",
    "unattendActions",
    "sppInstaller",
    "WinsockNameSpaceOnlineInstall",
    "WinsockAppPermittedLspCategories",
    "WinsockTransportOnlineInstall",
    "MsmqWorkgroupOnlineInstall",
    "MsmqHttpOnlineInstall",
    "MsmqAdIntegrationOnlineInstall",
    "pbr",
    "msdtc",
];

const DRIVER_SERVICE_TYPES: &[&str] = &["kernelDriver", "fileSystemDriver", "recognizerDriver"];

/// `unknown` 動作保留的原始 XML 上限（字元邊界內截斷）。
const RAW_XML_LIMIT: usize = 4096;

pub fn is_pe_name(name: &str) -> bool {
    name.rsplit_once('.')
        .is_some_and(|(_, ext)| PE_EXTENSIONS.iter().any(|e| e.eq_ignore_ascii_case(ext)))
}

pub fn parse_component(manifest_name: &str, xml: &str) -> Result<Component, CoreError> {
    let xml = xml.trim_start_matches('\u{feff}');
    let doc = parse_doc(xml)?;
    let root = doc.root_element();
    if !is_el(root, "assembly") {
        return Err(CoreError::Xml(format!(
            "{manifest_name}: root element is <{}>, expected <assembly>",
            root.tag_name().name()
        )));
    }
    let mut comp = Component {
        identity: child(root, "assemblyIdentity")
            .map(identity_of)
            .unwrap_or_default(),
        manifest: manifest_name.to_string(),
        ..Default::default()
    };
    for node in root.children().filter(Node::is_element) {
        let name = node.tag_name().name();
        match name {
            n if STRUCTURAL.contains(&n) => {}
            "file" => comp
                .actions
                .push(Action::new(ActionDetail::File(parse_file(node)))),
            "registryKeys" => parse_registry_keys(node, &mut comp.actions),
            "directories" => parse_directories(node, &mut comp.actions),
            "memberships" => parse_memberships(node, &mut comp),
            "taskScheduler" => parse_tasks(node, &mut comp.actions),
            "genericCommands" => parse_generic_commands(node, &mut comp.actions),
            "firewallRule" => {
                comp.actions
                    .push(Action::new(ActionDetail::FirewallRule(firewall_element(
                        node,
                    ))))
            }
            "mof" => comp
                .actions
                .push(Action::new(ActionDetail::WmiMof(MofAction {
                    file: attr(node, "name").unwrap_or_default(),
                    uninstall_file: attr(node, "uninstallmof"),
                }))),
            "instrumentation" => {
                for p in node.descendants().filter(|n| is_el(*n, "provider")) {
                    comp.actions
                        .push(Action::new(ActionDetail::EtwEventlog(EtwAction {
                            provider: attr(p, "name").unwrap_or_default(),
                            guid: attr(p, "guid"),
                        })));
                }
            }
            "configuration" => {
                comp.actions
                    .push(Action::new(ActionDetail::Setting(SettingAction {
                        element: name.to_string(),
                    })))
            }
            n if n.ends_with("AI") || ADVANCED_INSTALLERS.contains(&n) => {
                comp.actions
                    .push(Action::new(ActionDetail::AdvancedInstaller(
                        advanced_installer(node),
                    )))
            }
            _ => comp.actions.push(unknown(xml, node)),
        }
    }
    finalize_drivers(&mut comp);
    Ok(comp)
}

fn sddl_name(n: Node) -> Option<String> {
    child(n, "securityDescriptor").and_then(|s| attr(s, "name"))
}

fn is_true(v: Option<String>) -> bool {
    v.is_some_and(|v| v.eq_ignore_ascii_case("true"))
}

fn parse_file(node: Node) -> FileAction {
    let name = attr(node, "name").unwrap_or_default();
    let hash = node.descendants().find(|n| is_el(*n, "hash"));
    let hash_alg = hash
        .and_then(|h| h.descendants().find(|n| is_el(*n, "DigestMethod")))
        .and_then(|m| attr(m, "Algorithm"))
        .map(|a| a.rsplit('#').next().unwrap_or("").to_string());
    let hash_value = hash
        .and_then(|h| h.descendants().find(|n| is_el(*n, "DigestValue")))
        .and_then(|v| v.text())
        .map(|t| t.trim().to_string());
    FileAction {
        is_pe: is_pe_name(&name),
        destination: attr(node, "destinationPath").unwrap_or_default(),
        source_name: attr(node, "sourceName"),
        hash_alg,
        hash: hash_value,
        sddl_name: sddl_name(node),
        name,
    }
}

fn parse_registry_keys(node: Node, out: &mut Vec<Action>) {
    for key in elements(node, "registryKey") {
        let key_name = attr(key, "keyName").unwrap_or_default();
        let owner = is_true(attr(key, "owner"));
        let sddl = sddl_name(key);
        let values: Vec<Node> = elements(key, "registryValue").collect();
        if values.is_empty() {
            out.push(Action::new(ActionDetail::Registry(RegistryAction {
                key: key_name.clone(),
                operation: "create_key".into(),
                owner,
                sddl_name: sddl.clone(),
                ..Default::default()
            })));
        }
        for v in values {
            let reg = RegistryAction {
                key: key_name.clone(),
                value_name: Some(attr(v, "name").unwrap_or_default()),
                value_type: attr(v, "valueType"),
                data: attr(v, "value"),
                operation: attr(v, "operationHint").unwrap_or_else(|| "replace".into()),
                owner,
                sddl_name: sddl.clone(),
            };
            if let Some(fw) = firewall_from_registry(&reg) {
                out.push(Action::new(ActionDetail::FirewallRule(fw)));
            }
            out.push(Action::new(ActionDetail::Registry(reg)));
        }
    }
}

fn parse_directories(node: Node, out: &mut Vec<Action>) {
    for d in elements(node, "directory") {
        out.push(Action::new(ActionDetail::Directory(DirectoryAction {
            path: attr(d, "destinationPath").unwrap_or_default(),
            owner: is_true(attr(d, "owner")),
            sddl_name: sddl_name(d),
        })));
    }
}

fn split_list(v: Option<String>) -> Vec<String> {
    v.map(|s| {
        s.split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect()
    })
    .unwrap_or_default()
}

fn text_of(n: Option<Node>) -> Option<String> {
    n.and_then(|n| n.text()).map(|t| t.trim().to_string())
}

fn parse_memberships(node: Node, comp: &mut Component) {
    for cm in elements(node, "categoryMembership") {
        if let Some(t) = child(cm, "id").and_then(|id| attr(id, "typeName")) {
            if !comp.categories.contains(&t) {
                comp.categories.push(t);
            }
        }
        for inst in elements(cm, "categoryInstance") {
            for sd in elements(inst, "serviceData") {
                comp.actions.push(service_or_driver(sd));
            }
        }
    }
}

fn service_or_driver(sd: Node) -> Action {
    let service_type = attr(sd, "type");
    let name = attr(sd, "name").unwrap_or_default();
    let is_driver = service_type.as_deref().is_some_and(|t| {
        DRIVER_SERVICE_TYPES
            .iter()
            .any(|d| d.eq_ignore_ascii_case(t))
    });
    if is_driver {
        Action::new(ActionDetail::Driver(DriverAction {
            name,
            image_path: attr(sd, "imagePath"),
            start: attr(sd, "start"),
            service_type,
            boot_critical: false,
            origin: "service".into(),
        }))
    } else {
        Action::new(ActionDetail::Service(ServiceAction {
            name,
            display_name: attr(sd, "displayName"),
            image_path: attr(sd, "imagePath"),
            start: attr(sd, "start"),
            service_type,
            account: attr(sd, "objectName"),
            required_privileges: split_list(attr(sd, "requiredPrivileges")),
            group: attr(sd, "group"),
            depend_on: split_list(attr(sd, "dependOnService")),
        }))
    }
}

/// 設定 BootCritical 旗標；沒有對應 serviceData 的 .sys 檔補一筆 `origin = file` 的驅動。
fn finalize_drivers(comp: &mut Component) {
    let boot_critical = comp.categories.iter().any(|c| c == "BootCritical");
    let mut service_images: Vec<String> = Vec::new();
    for a in &mut comp.actions {
        if let ActionDetail::Driver(d) = &mut a.detail {
            d.boot_critical = boot_critical;
            if let Some(p) = &d.image_path {
                service_images.push(p.to_ascii_lowercase());
            }
        }
    }
    let mut extra = Vec::new();
    for a in &comp.actions {
        let ActionDetail::File(f) = &a.detail else {
            continue;
        };
        let lower = f.name.to_ascii_lowercase();
        if !lower.ends_with(".sys") || service_images.iter().any(|p| p.ends_with(&lower)) {
            continue;
        }
        extra.push(Action::new(ActionDetail::Driver(DriverAction {
            name: f.name[..f.name.len() - 4].to_string(),
            image_path: Some(ActionDetail::File(f.clone()).target()),
            start: None,
            service_type: None,
            boot_critical,
            origin: "file".into(),
        })));
    }
    comp.actions.extend(extra);
}

fn parse_tasks(node: Node, out: &mut Vec<Action>) {
    for task in elements(node, "Task") {
        let uri = text_of(child(task, "RegistrationInfo").and_then(|r| child(r, "URI")))
            .unwrap_or_default();
        let principal = child(task, "Principals").and_then(|p| child(p, "Principal"));
        let run_as =
            text_of(principal.and_then(|p| child(p, "UserId").or_else(|| child(p, "GroupId"))));
        let run_level = text_of(principal.and_then(|p| child(p, "RunLevel")));
        let mut exec = Vec::new();
        if let Some(actions) = child(task, "Actions") {
            for a in actions.children().filter(Node::is_element) {
                match a.tag_name().name() {
                    "Exec" => {
                        let cmd = text_of(child(a, "Command")).unwrap_or_default();
                        match text_of(child(a, "Arguments")) {
                            Some(args) if !args.is_empty() => exec.push(format!("{cmd} {args}")),
                            _ => exec.push(cmd),
                        }
                    }
                    "ComHandler" => exec.push(format!(
                        "COM {}",
                        text_of(child(a, "ClassId")).unwrap_or_default()
                    )),
                    other => exec.push(other.to_string()),
                }
            }
        }
        let triggers = child(task, "Triggers")
            .map(|t| {
                t.children()
                    .filter(Node::is_element)
                    .map(|n| n.tag_name().name().to_string())
                    .collect()
            })
            .unwrap_or_default();
        out.push(Action::new(ActionDetail::ScheduledTask(TaskAction {
            uri,
            exec,
            run_as,
            run_level,
            triggers,
        })));
    }
}

fn parse_generic_commands(node: Node, out: &mut Vec<Action>) {
    for g in elements(node, "genericCommand") {
        out.push(Action::new(ActionDetail::GenericCommand(CommandAction {
            executable: attr(g, "executableName")
                .or_else(|| attr(g, "executable"))
                .unwrap_or_default(),
            arguments: attr(g, "arguments"),
            runs_on_install: !attr(g, "install").is_some_and(|v| v.eq_ignore_ascii_case("false")),
        })));
    }
}

fn firewall_element(n: Node) -> FirewallAction {
    FirewallAction {
        name: attr(n, "internalName")
            .or_else(|| attr(n, "Name"))
            .unwrap_or_default(),
        direction: attr(n, "Dir"),
        action: attr(n, "Action"),
        program: attr(n, "Binary"),
        protocol: attr(n, "Protocol"),
        local_ports: attr(n, "LPort"),
        remote_ports: attr(n, "RPort"),
        origin: "element".into(),
    }
}

/// `...\FirewallPolicy\FirewallRules` 或 `RestrictedServices` 下、以 `v2.` 開頭的值即為防火牆規則。
fn firewall_from_registry(r: &RegistryAction) -> Option<FirewallAction> {
    let key = r.key.to_ascii_lowercase();
    if !(key.contains("\\firewallpolicy\\firewallrules")
        || key.contains("\\firewallpolicy\\restrictedservices"))
    {
        return None;
    }
    let data = r.data.as_deref()?;
    if !data.get(..3)?.eq_ignore_ascii_case("v2.") {
        return None;
    }
    let mut fields = std::collections::BTreeMap::new();
    for part in data.split('|').skip(1) {
        if let Some((k, v)) = part.split_once('=') {
            fields
                .entry(k.to_ascii_lowercase())
                .or_insert_with(|| v.to_string());
        }
    }
    Some(FirewallAction {
        name: fields
            .get("name")
            .cloned()
            .or_else(|| r.value_name.clone())
            .unwrap_or_default(),
        direction: fields.get("dir").cloned(),
        action: fields.get("action").cloned(),
        program: fields.get("app").cloned(),
        protocol: fields.get("protocol").cloned(),
        local_ports: fields.get("lport").cloned(),
        remote_ports: fields.get("rport").cloned(),
        origin: "registry".into(),
    })
}

fn advanced_installer(n: Node) -> AdvancedInstallerAction {
    let mut attributes: std::collections::BTreeMap<String, String> = n
        .attributes()
        .map(|a| (a.name().to_string(), a.value().to_string()))
        .collect();
    let children: Vec<&str> = n
        .children()
        .filter(Node::is_element)
        .map(|c| c.tag_name().name())
        .collect();
    if !children.is_empty() {
        attributes.insert("children".into(), children.join(","));
    }
    AdvancedInstallerAction {
        element: n.tag_name().name().to_string(),
        attributes,
    }
}

/// 未辨識的元素：保留原始 XML 片段（最多 RAW_XML_LIMIT 位元組）。
fn unknown(xml: &str, node: Node) -> Action {
    let raw = &xml[node.range()];
    let raw_xml = if raw.len() > RAW_XML_LIMIT {
        let mut end = RAW_XML_LIMIT;
        while !raw.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}…", &raw[..end])
    } else {
        raw.to_string()
    };
    Action::new(ActionDetail::Unknown(UnknownAction {
        element: node.tag_name().name().to_string(),
        raw_xml,
    }))
}
