use std::collections::BTreeMap;

use msu_inspector::core::manifest::package::*;

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

#[test]
fn parses_mum_with_bom() {
    let xml = format!("\u{feff}{}", fixture("rollup.mum"));
    let m = parse_mum(
        "Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.9457.1.0.mum",
        &xml,
    )
    .unwrap();
    assert_eq!(m.identity.name, "Package_for_RollupFix");
    assert_eq!(m.identifier.as_deref(), Some("KB5129195"));
    assert_eq!(m.release_type.as_deref(), Some("Security Update"));
    assert_eq!(m.restart.as_deref(), Some("possible"));
    assert_eq!(m.description.as_deref(), Some("Fix for KB5129195"));
    assert_eq!(
        m.support_url.as_deref(),
        Some("https://support.microsoft.com/help/5129195")
    );
    assert!(m.psfx);
    assert_eq!(m.parents.len(), 2);
    assert_eq!(m.sub_packages.len(), 2);
    assert!(m.components.is_empty());
}

#[test]
fn parses_component_lists() {
    let m = parse_mum("Package_1_for_KB5129195.mum", &fixture("sub.mum")).unwrap();
    assert_eq!(m.components.len(), 1);
    assert_eq!(
        m.components[0].name,
        "WindowsSearchEngineSKU-Group-Deployment"
    );
    assert!(!m.psfx);
}

#[test]
fn parses_utf16_pkg_properties() {
    let text = "ApplicabilityInfo=\"Windows 11.0 Client SKUs\"\r\nKB Article Number=\"5129195\"\r\nProcessor Architecture=\"amd64\"\r\n";
    let mut bytes = vec![0xFF, 0xFE];
    for u in text.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    let p = parse_pkg_properties(&bytes);
    assert_eq!(
        p.get("ApplicabilityInfo").map(String::as_str),
        Some("Windows 11.0 Client SKUs")
    );
    assert_eq!(
        p.get("KB Article Number").map(String::as_str),
        Some("5129195")
    );
    assert_eq!(p.len(), 3);
}

#[test]
fn extracts_kb_from_file_names() {
    assert_eq!(
        kb_from_file_name("windows11.0-kb5043080-x64_abc.msu").as_deref(),
        Some("KB5043080")
    );
    assert_eq!(
        kb_from_file_name("Windows10.0-KB890830-x64.cab").as_deref(),
        Some("KB890830")
    );
    assert_eq!(kb_from_file_name("update.msu"), None);
    assert_eq!(kb_from_file_name("kbd.msu"), None);
}

#[test]
fn selects_top_level_package() {
    let rollup = parse_mum("Package_for_RollupFix.mum", &fixture("rollup.mum")).unwrap();
    let sub = parse_mum("Package_1_for_KB5129195.mum", &fixture("sub.mum")).unwrap();
    let mut props = BTreeMap::new();
    props.insert(
        "ApplicabilityInfo".to_string(),
        "Windows 11.0 Client SKUs".to_string(),
    );
    let p = select_package(&[sub.clone(), rollup.clone()], Some("KB5129195"), props);
    assert_eq!(p.identity.name, "Package_for_RollupFix");
    assert_eq!(p.kb.as_deref(), Some("KB5129195"));
    assert_eq!(p.sub_packages, 2);
    assert!(p.psfx);
    assert_eq!(
        p.applicability,
        vec![
            "Windows 11.0 Client SKUs".to_string(),
            "Microsoft-Windows-CoreEdition".to_string(),
            "Microsoft-Windows-ProfessionalEdition".to_string()
        ]
    );

    // update.mum 優先
    let mut update = sub.clone();
    update.file_name = "update.mum".into();
    let p = select_package(&[rollup, update], None, BTreeMap::new());
    assert_eq!(p.identity.name, "Package_1_for_KB5129195");

    // 沒有任何 .mum：只帶 KB 提示
    let p = select_package(&[], Some("KB1"), BTreeMap::new());
    assert_eq!(p.kb.as_deref(), Some("KB1"));
}
