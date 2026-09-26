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

fn actions() -> Component {
    parse_component("actions.manifest", &fixture("actions.manifest")).unwrap()
}

#[test]
fn counts_every_kind() {
    let c = actions();
    let count = |k| c.actions.iter().filter(|a| a.kind() == k).count();
    assert_eq!(count(ActionKind::File), 3);
    assert_eq!(
        count(ActionKind::Driver),
        2,
        "acpiex (service) + helper.sys (file)"
    );
    assert_eq!(count(ActionKind::Service), 1);
    assert_eq!(count(ActionKind::ScheduledTask), 1);
    assert_eq!(count(ActionKind::GenericCommand), 2);
    assert_eq!(
        count(ActionKind::FirewallRule),
        2,
        "element + registry value"
    );
    assert_eq!(count(ActionKind::Registry), 1);
    assert_eq!(count(ActionKind::WmiMof), 1);
    assert_eq!(count(ActionKind::EtwEventlog), 1);
    assert_eq!(count(ActionKind::AdvancedInstaller), 3);
    assert_eq!(count(ActionKind::Setting), 1);
    assert_eq!(count(ActionKind::Unknown), 0);
    assert_eq!(
        c.categories,
        vec!["BootCritical".to_string(), "Service".to_string()]
    );
}

#[test]
fn parses_services_and_drivers() {
    let c = actions();
    let svc = c.actions.iter().find_map(|a| match &a.detail {
        ActionDetail::Service(s) => Some(s),
        _ => None,
    });
    let svc = svc.unwrap();
    assert_eq!(svc.name, "AppReadiness");
    assert_eq!(svc.start.as_deref(), Some("demand"));
    assert_eq!(svc.account.as_deref(), Some("LocalSystem"));
    assert_eq!(
        svc.required_privileges,
        vec!["SeImpersonatePrivilege", "SeTcbPrivilege"]
    );
    assert_eq!(svc.depend_on, vec!["RpcSs"]);

    let drivers: Vec<&DriverAction> = c
        .actions
        .iter()
        .filter_map(|a| match &a.detail {
            ActionDetail::Driver(d) => Some(d),
            _ => None,
        })
        .collect();
    let acpi = drivers.iter().find(|d| d.name == "acpiex").unwrap();
    assert_eq!(acpi.origin, "service");
    assert_eq!(acpi.start.as_deref(), Some("boot"));
    assert!(acpi.boot_critical);
    let helper = drivers.iter().find(|d| d.name == "helper").unwrap();
    assert_eq!(helper.origin, "file");
    assert_eq!(
        helper.image_path.as_deref(),
        Some("$(runtime.drivers)\\helper.sys")
    );
    assert!(helper.boot_critical);
}

#[test]
fn parses_tasks_and_commands() {
    let c = actions();
    let task = c.actions.iter().find_map(|a| match &a.detail {
        ActionDetail::ScheduledTask(t) => Some(t),
        _ => None,
    });
    let task = task.unwrap();
    assert_eq!(
        task.uri,
        "\\Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser"
    );
    assert_eq!(task.run_as.as_deref(), Some("S-1-5-18"));
    assert_eq!(task.run_level.as_deref(), Some("HighestAvailable"));
    assert_eq!(task.triggers, vec!["TimeTrigger", "BootTrigger"]);
    assert_eq!(
        task.exec,
        vec![
            "%windir%\\system32\\compattelrunner.exe -m:appraiser.dll".to_string(),
            "COM {01575CFE-9A55-4003-A5E1-F38D1EBDCBE1}".to_string()
        ]
    );

    let cmds: Vec<&CommandAction> = c
        .actions
        .iter()
        .filter_map(|a| match &a.detail {
            ActionDetail::GenericCommand(g) => Some(g),
            _ => None,
        })
        .collect();
    assert_eq!(
        cmds[0].executable,
        "$(runtime.system32)\\inetsrv\\iissetup.exe"
    );
    assert_eq!(cmds[0].arguments.as_deref(), Some("/install ASPNET"));
    assert!(cmds[0].runs_on_install);
    assert!(!cmds[1].runs_on_install);
}

#[test]
fn parses_firewall_rules_from_both_sources() {
    let c = actions();
    let fws: Vec<&FirewallAction> = c
        .actions
        .iter()
        .filter_map(|a| match &a.detail {
            ActionDetail::FirewallRule(f) => Some(f),
            _ => None,
        })
        .collect();
    let el = fws.iter().find(|f| f.origin == "element").unwrap();
    assert_eq!(
        el.name,
        "Microsoft-Windows-DeviceManagement-CertificateInstall-TCP-Out"
    );
    assert_eq!(el.direction.as_deref(), Some("Out"));
    assert_eq!(el.action.as_deref(), Some("Allow"));
    assert_eq!(el.local_ports.as_deref(), Some("49152-65535"));
    let reg = fws.iter().find(|f| f.origin == "registry").unwrap();
    assert_eq!(reg.name, "Block inbound traffic to dmcertinst.exe");
    assert_eq!(reg.direction.as_deref(), Some("in"));
    assert_eq!(reg.action.as_deref(), Some("Block"));
    assert_eq!(
        reg.program.as_deref(),
        Some("%SystemRoot%\\System32\\dmcertinst.exe")
    );
}

#[test]
fn parses_mof_etw_advanced_installers() {
    let c = actions();
    let mof = c.actions.iter().find_map(|a| match &a.detail {
        ActionDetail::WmiMof(m) => Some(m),
        _ => None,
    });
    assert_eq!(
        mof.unwrap().uninstall_file.as_deref(),
        Some("$(runtime.wbem)\\Remove.Microsoft.AppV.AppvClientWmi.mof")
    );
    let etw = c.actions.iter().find_map(|a| match &a.detail {
        ActionDetail::EtwEventlog(e) => Some(e),
        _ => None,
    });
    assert_eq!(
        etw.unwrap().provider,
        "Microsoft-Windows-AppModel-MessagingDataModel"
    );
    let ais: Vec<&AdvancedInstallerAction> = c
        .actions
        .iter()
        .filter_map(|a| match &a.detail {
            ActionDetail::AdvancedInstaller(x) => Some(x),
            _ => None,
        })
        .collect();
    let names: Vec<&str> = ais.iter().map(|a| a.element.as_str()).collect();
    assert_eq!(names, vec!["fveUpdateAI", "bfsvc", "networkComponents"]);
    assert_eq!(
        ais[0].attributes.get("fveCommand").map(String::as_str),
        Some("bootmgr")
    );
    assert_eq!(
        ais[2].attributes.get("children").map(String::as_str),
        Some("filterDriver")
    );
}
