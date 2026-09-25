use msu_inspector::core::model::*;
use msu_inspector::core::risk::{self, apply, evaluate, RULES};
use msu_inspector::i18n::Lang;

fn comp(actions: Vec<ActionDetail>) -> Component {
    Component {
        identity: AssemblyIdentity {
            name: "c".into(),
            version: "10.0.26100.1".into(),
            ..Default::default()
        },
        actions: actions.into_iter().map(Action::new).collect(),
        ..Default::default()
    }
}

fn reg(key: &str, value: &str) -> ActionDetail {
    ActionDetail::Registry(RegistryAction {
        key: key.into(),
        value_name: Some(value.into()),
        operation: "replace".into(),
        ..Default::default()
    })
}

fn rules_of(detail: ActionDetail) -> Vec<&'static str> {
    let c = comp(vec![detail]);
    evaluate(&c, &c.actions[0])
}

#[test]
fn every_rule_has_both_reasons_and_unique_id() {
    let mut ids: Vec<&str> = RULES.iter().map(|r| r.id).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), RULES.len());
    for r in RULES {
        assert!(!r.zh.is_empty() && !r.en.is_empty(), "{}", r.id);
        assert_eq!(risk::rule(r.id).unwrap().reason(Lang::En), r.en);
    }
}

#[test]
fn flags_boot_drivers() {
    let d = ActionDetail::Driver(DriverAction {
        name: "acpiex".into(),
        start: Some("boot".into()),
        boot_critical: true,
        origin: "service".into(),
        ..Default::default()
    });
    assert_eq!(rules_of(d), vec!["DRV_BOOT_START", "DRV_BOOT_CRITICAL"]);
    let f = ActionDetail::Driver(DriverAction {
        name: "x".into(),
        origin: "file".into(),
        ..Default::default()
    });
    assert_eq!(rules_of(f), vec!["DRV_FILE"]);
}

#[test]
fn flags_registry_locations() {
    assert_eq!(
        rules_of(reg(
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "x"
        )),
        vec!["REG_AUTOSTART"]
    );
    assert_eq!(
        rules_of(reg(
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager",
            "BootExecute"
        )),
        vec!["REG_AUTOSTART"]
    );
    assert!(rules_of(reg(
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager",
        "Other"
    ))
    .is_empty());
    assert_eq!(
        rules_of(reg(
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
            "Security Packages"
        )),
        vec!["REG_SECURITY"]
    );
    assert_eq!(
        rules_of(reg(
            "HKEY_CLASSES_ROOT\\CLSID\\{11111111-2222-3333-4444-555555555555}\\InprocServer32",
            ""
        )),
        vec!["COM_REGISTRATION"]
    );
    assert!(rules_of(reg("HKEY_LOCAL_MACHINE\\SOFTWARE\\Contoso", "x")).is_empty());
}

#[test]
fn flags_commands_firewall_and_installers() {
    let cmd = |install| {
        ActionDetail::GenericCommand(CommandAction {
            executable: "x.exe".into(),
            arguments: None,
            runs_on_install: install,
        })
    };
    assert_eq!(rules_of(cmd(true)), vec!["CMD_GENERIC"]);
    assert!(rules_of(cmd(false)).is_empty());
    let fw = |dir: &str, act: &str| {
        ActionDetail::FirewallRule(FirewallAction {
            name: "r".into(),
            direction: Some(dir.into()),
            action: Some(act.into()),
            origin: "element".into(),
            ..Default::default()
        })
    };
    assert_eq!(rules_of(fw("In", "Allow")), vec!["FW_INBOUND_ALLOW"]);
    assert_eq!(rules_of(fw("Out", "Allow")), vec!["FW_RULE"]);
    let ai = |e: &str| {
        ActionDetail::AdvancedInstaller(AdvancedInstallerAction {
            element: e.into(),
            attributes: Default::default(),
        })
    };
    assert_eq!(rules_of(ai("bfsvc")), vec!["AI_BOOT"]);
    assert_eq!(rules_of(ai("HTTPAI")), vec!["AI_CUSTOM"]);
}

#[test]
fn service_and_task_rules_depend_on_local_state() {
    let mut c = comp(vec![ActionDetail::Service(ServiceAction {
        name: "s".into(),
        ..Default::default()
    })]);
    assert_eq!(evaluate(&c, &c.actions[0]), vec!["SVC_DEFINED"]);
    c.actions[0].local = Some(LocalStatus {
        state: LocalState::New,
        current: None,
        incoming: None,
    });
    assert_eq!(evaluate(&c, &c.actions[0]), vec!["SVC_NEW"]);
    c.actions[0].local = Some(LocalStatus {
        state: LocalState::Replace,
        current: None,
        incoming: None,
    });
    assert_eq!(evaluate(&c, &c.actions[0]), vec!["SVC_CHANGED"]);

    let mut t = comp(vec![ActionDetail::ScheduledTask(TaskAction::default())]);
    assert_eq!(evaluate(&t, &t.actions[0]), vec!["TASK_DEFINED"]);
    t.actions[0].local = Some(LocalStatus {
        state: LocalState::New,
        current: None,
        incoming: None,
    });
    assert_eq!(evaluate(&t, &t.actions[0]), vec!["TASK_NEW"]);
}

#[test]
fn apply_sets_levels_and_unchanged_components_become_info() {
    let pe = ActionDetail::File(FileAction {
        name: "k.dll".into(),
        destination: "$(runtime.system32)\\".into(),
        is_pe: true,
        ..Default::default()
    });
    let txt = ActionDetail::File(FileAction {
        name: "a.txt".into(),
        destination: "$(runtime.windows)\\".into(),
        ..Default::default()
    });
    let etw = ActionDetail::EtwEventlog(EtwAction {
        provider: "p".into(),
        guid: None,
    });
    let mut report = AnalysisReport {
        components: vec![comp(vec![pe.clone(), txt, etw]), comp(vec![pe])],
        ..Default::default()
    };
    report.components[1].local = Some(LocalStatus {
        state: LocalState::InStoreSame,
        current: Some("10.0.26100.1".into()),
        incoming: Some("10.0.26100.1".into()),
    });
    apply(&mut report);
    let a = &report.components[0].actions;
    assert_eq!(
        (a[0].risk, a[0].rules.clone()),
        (Risk::Medium, vec!["PE_SYSTEM"])
    );
    assert_eq!((a[1].risk, a[1].rules.is_empty()), (Risk::Low, true));
    assert_eq!(a[2].risk, Risk::Info);
    let b = &report.components[1].actions[0];
    assert_eq!(
        (b.risk, b.rules.clone()),
        (Risk::Info, vec!["UNCHANGED_COMPONENT"])
    );
}
