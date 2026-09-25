//! `.mum`（套件 manifest）與 `*-pkgProperties.txt` 解析。

use std::collections::BTreeMap;

use super::{attr, child, decode_text, elements, identity_of, is_el, parse_doc};
use crate::core::model::{AssemblyIdentity, PackageInfo};
use crate::core::CoreError;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MumInfo {
    pub file_name: String,
    pub identity: AssemblyIdentity,
    pub identifier: Option<String>,
    pub release_type: Option<String>,
    pub restart: Option<String>,
    pub description: Option<String>,
    pub support_url: Option<String>,
    /// `customInformation PackageFormat="PSFX"`
    pub psfx: bool,
    pub parents: Vec<AssemblyIdentity>,
    pub sub_packages: Vec<AssemblyIdentity>,
    pub components: Vec<AssemblyIdentity>,
}

pub fn parse_mum(file_name: &str, xml: &str) -> Result<MumInfo, CoreError> {
    let doc = parse_doc(xml)?;
    let root = doc.root_element();
    if !is_el(root, "assembly") {
        return Err(CoreError::Xml(format!("{file_name}: not an <assembly>")));
    }
    let mut m = MumInfo {
        file_name: file_name.to_string(),
        identity: child(root, "assemblyIdentity")
            .map(identity_of)
            .unwrap_or_default(),
        description: attr(root, "description"),
        support_url: attr(root, "supportInformation"),
        ..Default::default()
    };
    let Some(pkg) = child(root, "package") else {
        return Ok(m);
    };
    m.identifier = attr(pkg, "identifier");
    m.release_type = attr(pkg, "releaseType");
    m.restart = attr(pkg, "restart");
    m.psfx = pkg.children().any(|n| {
        is_el(n, "customInformation")
            && n.attribute("PackageFormat")
                .is_some_and(|f| f.eq_ignore_ascii_case("PSFX"))
    });
    if let Some(parent) = child(pkg, "parent") {
        m.parents = elements(parent, "assemblyIdentity")
            .map(identity_of)
            .collect();
    }
    for update in elements(pkg, "update") {
        for c in elements(update, "component") {
            if let Some(id) = child(c, "assemblyIdentity") {
                m.components.push(identity_of(id));
            }
        }
        for p in elements(update, "package") {
            if let Some(id) = child(p, "assemblyIdentity") {
                m.sub_packages.push(identity_of(id));
            }
        }
    }
    Ok(m)
}

/// 每行 `Key="Value"`；檔案通常為 UTF-16LE。
pub fn parse_pkg_properties(bytes: &[u8]) -> BTreeMap<String, String> {
    let text = decode_text(bytes).unwrap_or_default();
    text.lines()
        .filter_map(|line| {
            let (k, v) = line.trim().split_once('=')?;
            Some((k.trim().to_string(), v.trim().trim_matches('"').to_string()))
        })
        .filter(|(k, _)| !k.is_empty())
        .collect()
}

/// 從檔名取出 `KBnnnnnn`（`kb` 後至少 5 位數字）。
pub fn kb_from_file_name(name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut i = 0;
    while let Some(pos) = lower[i..].find("kb") {
        let start = i + pos + 2;
        let digits: String = bytes[start..]
            .iter()
            .take_while(|b| b.is_ascii_digit())
            .map(|b| *b as char)
            .collect();
        if digits.len() >= 5 {
            return Some(format!("KB{digits}"));
        }
        i = start;
    }
    None
}

fn eq_kb(a: Option<&str>, b: Option<&str>) -> bool {
    matches!((a, b), (Some(a), Some(b)) if a.eq_ignore_ascii_case(b))
}

/// 選出頂層套件：`update.mum` → `Package_for_*` 且 identifier 與 KB 相符 →
/// identifier 相符 → 參照最多子套件 / 元件者。
pub fn select_package(
    mums: &[MumInfo],
    kb_hint: Option<&str>,
    properties: BTreeMap<String, String>,
) -> PackageInfo {
    let top = mums
        .iter()
        .find(|m| m.file_name.eq_ignore_ascii_case("update.mum"))
        .or_else(|| {
            mums.iter().find(|m| {
                m.identity
                    .name
                    .to_ascii_lowercase()
                    .starts_with("package_for_")
                    && eq_kb(m.identifier.as_deref(), kb_hint)
            })
        })
        .or_else(|| {
            mums.iter()
                .find(|m| eq_kb(m.identifier.as_deref(), kb_hint))
        })
        .or_else(|| {
            mums.iter()
                .max_by_key(|m| m.sub_packages.len() + m.components.len())
        });

    let kb_from_props = properties
        .get("KB Article Number")
        .map(|n| format!("KB{}", n.trim()));
    let mut applicability: Vec<String> = properties
        .get("ApplicabilityInfo")
        .cloned()
        .into_iter()
        .collect();

    let Some(top) = top else {
        return PackageInfo {
            kb: kb_hint.map(str::to_string).or(kb_from_props),
            applicability,
            properties,
            ..Default::default()
        };
    };
    for p in &top.parents {
        if !applicability.contains(&p.name) {
            applicability.push(p.name.clone());
        }
    }
    let kb = top
        .identifier
        .clone()
        .filter(|i| i.to_ascii_uppercase().starts_with("KB"))
        .or_else(|| kb_hint.map(str::to_string))
        .or(kb_from_props);
    PackageInfo {
        kb,
        identity: top.identity.clone(),
        release_type: top.release_type.clone(),
        restart: top.restart.clone(),
        description: top.description.clone(),
        support_url: top.support_url.clone(),
        psfx: top.psfx,
        applicability,
        properties,
        sub_packages: top.sub_packages.len(),
    }
}
