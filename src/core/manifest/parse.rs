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
            _ => comp.actions.push(unknown(xml, node)),
        }
    }
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
