use msu_inspector::core::manifest::parse::{is_pe_name, parse_component};
use msu_inspector::core::model::*;

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn of_kind(c: &Component, k: ActionKind) -> Vec<&ActionDetail> {
    c.actions
        .iter()
        .filter(|a| a.kind() == k)
        .map(|a| &a.detail)
        .collect()
}

#[test]
fn parses_identity() {
    let c = parse_component("basic.manifest", &fixture("basic.manifest")).unwrap();
    assert_eq!(c.manifest, "basic.manifest");
    assert_eq!(c.identity.name, "Microsoft-Windows-AppReadiness-Service");
    assert_eq!(c.identity.version, "10.0.26100.1591");
    assert_eq!(c.identity.arch, "amd64");
    assert_eq!(c.identity.language, "neutral");
    assert_eq!(c.identity.public_key_token, "31bf3856ad364e35");
}

#[test]
fn parses_files_with_hash() {
    let c = parse_component("basic.manifest", &fixture("basic.manifest")).unwrap();
    let files = of_kind(&c, ActionKind::File);
    assert_eq!(files.len(), 2);
    let ActionDetail::File(f) = files[0] else {
        panic!()
    };
    assert_eq!(f.name, "AppReadiness.dll");
    assert_eq!(f.destination, "$(runtime.system32)\\");
    assert_eq!(f.source_name.as_deref(), Some("AppReadiness.dll"));
    assert_eq!(f.hash_alg.as_deref(), Some("sha256"));
    assert_eq!(f.hash.as_deref(), Some("q83vEjRWeJA="));
    assert_eq!(f.sddl_name.as_deref(), Some("WRP_FILE_DEFAULT_SDDL"));
    assert!(f.is_pe);
    let ActionDetail::File(txt) = files[1] else {
        panic!()
    };
    assert!(!txt.is_pe);
    assert_eq!(txt.hash, None);
}

#[test]
fn parses_registry_values_and_empty_keys() {
    let c = parse_component("basic.manifest", &fixture("basic.manifest")).unwrap();
    let regs: Vec<&RegistryAction> = of_kind(&c, ActionKind::Registry)
        .into_iter()
        .map(|d| match d {
            ActionDetail::Registry(r) => r,
            _ => unreachable!(),
        })
        .collect();
    assert_eq!(regs.len(), 3);
    assert_eq!(regs[0].value_name.as_deref(), Some("NotifyObject"));
    assert_eq!(regs[0].value_type.as_deref(), Some("REG_SZ"));
    assert_eq!(regs[0].operation, "replace");
    assert_eq!(
        regs[0].sddl_name.as_deref(),
        Some("AppReadiness_Registry_SDDL")
    );
    assert_eq!(regs[1].value_name.as_deref(), Some(""));
    assert_eq!(regs[1].data.as_deref(), Some("AppReadiness & more"));
    assert_eq!(regs[1].operation, "append");
    assert_eq!(regs[2].value_name, None);
    assert_eq!(regs[2].operation, "create_key");
    assert!(regs[2].owner);
}

#[test]
fn parses_directories() {
    let c = parse_component("basic.manifest", &fixture("basic.manifest")).unwrap();
    let dirs = of_kind(&c, ActionKind::Directory);
    let ActionDetail::Directory(d) = dirs[0] else {
        panic!()
    };
    assert_eq!(d.path, "$(runtime.windows)\\AppReadiness\\");
    assert!(d.owner);
    assert_eq!(d.sddl_name.as_deref(), Some("AppReadiness_File_SDDL"));
}

#[test]
fn keeps_unknown_elements_and_skips_structural_ones() {
    let c = parse_component("basic.manifest", &fixture("basic.manifest")).unwrap();
    let unknown = of_kind(&c, ActionKind::Unknown);
    assert_eq!(unknown.len(), 1, "only <fooBar> is unknown");
    let ActionDetail::Unknown(u) = unknown[0] else {
        panic!()
    };
    assert_eq!(u.element, "fooBar");
    assert!(u.raw_xml.starts_with("<fooBar mode=\"strange\">"));
    assert!(u.raw_xml.ends_with("</fooBar>"));
}

#[test]
fn accepts_bom_and_rejects_non_assembly() {
    let xml = format!("\u{feff}{}", fixture("basic.manifest"));
    assert!(parse_component("x", &xml).is_ok());
    assert!(parse_component("x", "<notAssembly/>").is_err());
    assert!(parse_component("x", "<assembly").is_err());
}

#[test]
fn detects_pe_names() {
    for n in ["a.dll", "b.EXE", "c.sys", "bootmgfw.efi", "d.ocx", "e.cpl"] {
        assert!(is_pe_name(n), "{n}");
    }
    for n in ["a.txt", "b.mui.bak", "noext", "x.xml"] {
        assert!(!is_pe_name(n), "{n}");
    }
}
