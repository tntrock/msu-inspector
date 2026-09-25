use std::path::PathBuf;

use msu_inspector::core::local::*;
use msu_inspector::core::model::*;
use msu_inspector::core::sys;

fn win() -> PathBuf {
    PathBuf::from(r"C:\Windows")
}

#[test]
fn resolves_runtime_variables() {
    assert_eq!(
        resolve_path("$(runtime.system32)\\", &win(), false),
        Some(PathBuf::from(r"C:\Windows\System32"))
    );
    assert_eq!(
        resolve_path("$(runtime.system32)\\", &win(), true),
        Some(PathBuf::from(r"C:\Windows\SysWOW64"))
    );
    assert_eq!(
        resolve_path("$(runtime.drivers)\\x", &win(), false),
        Some(PathBuf::from(r"C:\Windows\System32\drivers\x"))
    );
    assert_eq!(
        resolve_path("$(runtime.programFiles)\\A", &win(), true),
        Some(PathBuf::from(r"C:\Program Files (x86)\A"))
    );
    assert_eq!(resolve_path("$(runtime.nope)\\x", &win(), false), None);
    assert_eq!(resolve_path("relative\\x", &win(), false), None);
}

#[test]
fn compares_versions() {
    assert_eq!(compare_versions(None, "10.0.1.2"), LocalState::New);
    assert_eq!(
        compare_versions(Some("10.0.1.1"), "10.0.1.2"),
        LocalState::Replace
    );
    assert_eq!(
        compare_versions(Some("10.0.1.2"), "10.0.1.2"),
        LocalState::Same
    );
    assert_eq!(
        compare_versions(Some("10.0.1.3"), "10.0.1.2"),
        LocalState::Downgrade
    );
    assert_eq!(compare_versions(Some("?"), "10.0.1.2"), LocalState::Present);
}

#[test]
fn matches_truncated_keyform_names() {
    let full = "microsoft-windows-3daudio-hrtfdata-deployment";
    assert!(keyform_matches(
        "microsoft-windows-3..hrtfdata-deployment",
        full
    ));
    assert!(keyform_matches(full, full));
    assert!(!keyform_matches(
        "microsoft-windows-4..hrtfdata-deployment",
        full
    ));
    assert!(!keyform_matches("microsoft-windows-3daudio", full));
}

#[test]
fn store_lookup_by_identity() {
    let store = Store::from_names([
        "amd64_microsoft-windows-3..hrtfdata-deployment_31bf3856ad364e35_10.0.26100.1_none_22f425f17c681669.manifest",
        "amd64_microsoft-windows-3..hrtfdata-deployment_31bf3856ad364e35_10.0.26100.9_none_aaaaaaaaaaaaaaaa.manifest",
        "wow64_microsoft-windows-3..hrtfdata-deployment_31bf3856ad364e35_10.0.26100.9_none_bbbbbbbbbbbbbbbb.manifest",
        "garbage.manifest",
    ]);
    assert_eq!(store.len(), 3);
    let id = AssemblyIdentity {
        name: "Microsoft-Windows-3DAudio-HrtfData-Deployment".into(),
        version: "10.0.26100.9".into(),
        arch: "amd64".into(),
        language: "neutral".into(),
        public_key_token: "31bf3856ad364e35".into(),
    };
    let mut v = store.versions(&id);
    v.sort();
    assert_eq!(v, vec![[10, 0, 26100, 1], [10, 0, 26100, 9]]);
    assert_eq!(
        compare_component(&store, &id).state,
        LocalState::InStoreSame
    );
    let newer = AssemblyIdentity {
        version: "10.0.26100.20".into(),
        ..id.clone()
    };
    let s = compare_component(&store, &newer);
    assert_eq!(
        (s.state, s.current.as_deref()),
        (LocalState::InStoreOlder, Some("10.0.26100.9"))
    );
    let older = AssemblyIdentity {
        version: "10.0.26100.5".into(),
        ..id.clone()
    };
    assert_eq!(
        compare_component(&store, &older).state,
        LocalState::InStoreNewer
    );
    let other = AssemblyIdentity {
        name: "other".into(),
        ..id
    };
    assert_eq!(
        compare_component(&store, &other).state,
        LocalState::NotInStore
    );
}

#[test]
fn applicability_rules() {
    assert_eq!(servicing_base(26200), 26100);
    assert_eq!(servicing_base(22631), 22621);
    assert_eq!(servicing_base(19045), 19041);
    let comp = |v: &str| Component {
        identity: AssemblyIdentity {
            version: v.into(),
            ..Default::default()
        },
        ..Default::default()
    };
    let comps = vec![
        comp("10.0.26100.100"),
        comp("10.0.26100.101"),
        comp("10.0.22621.5"),
        comp("4.0.15920.1"),
    ];
    assert_eq!(target_build(&comps), Some(26100));
    let mut report = AnalysisReport {
        components: comps,
        ..Default::default()
    };
    report.package.identity.arch = "amd64".into();
    assert_eq!(applicability(&report, "amd64", 26200), (true, None));
    assert_eq!(
        applicability(&report, "arm64", 26100),
        (false, Some("arch_mismatch"))
    );
    assert_eq!(
        applicability(&report, "amd64", 22631),
        (false, Some("build_mismatch"))
    );
}

#[test]
fn compares_registry_values_by_type() {
    assert!(same_value("REG_DWORD", "0x00000001", &RegValue::Dword(1)));
    assert!(same_value("REG_DWORD", "1", &RegValue::Dword(1)));
    assert!(!same_value("REG_DWORD", "0x2", &RegValue::Dword(1)));
    assert!(same_value(
        "REG_BINARY",
        "01 0A ff",
        &RegValue::Binary(vec![1, 10, 255])
    ));
    assert!(same_value(
        "REG_MULTI_SZ",
        "\"a\",\"b\"",
        &RegValue::MultiStr(vec!["a".into(), "b".into()])
    ));
    assert!(same_value("REG_SZ", "x", &RegValue::Str("x".into())));
    assert!(!same_value("REG_SZ", "x", &RegValue::Str("X".into())));
    assert_eq!(RegValue::Dword(10).render(), "0x0000000a");
    assert_eq!(
        RegValue::MultiStr(vec!["a".into(), "b".into()]).render(),
        "\"a\",\"b\""
    );
}

#[test]
fn compares_services() {
    let w = win();
    let cur = ServiceSnapshot {
        start: Some("auto".into()),
        account: Some("LocalSystem".into()),
        image: Some(r"%SystemRoot%\System32\svchost.exe -k netsvcs -p".into()),
    };
    let same = ServiceSnapshot {
        start: Some("Auto".into()),
        account: Some("localsystem".into()),
        image: Some(r"C:\Windows\System32\svchost.exe -k netsvcs -p".into()),
    };
    assert!(service_matches(&same, &cur, &w));
    let partial = ServiceSnapshot {
        start: Some("auto".into()),
        account: None,
        image: None,
    };
    assert!(
        service_matches(&partial, &cur, &w),
        "fields missing in the manifest are not compared"
    );
    let changed = ServiceSnapshot {
        start: Some("demand".into()),
        ..same
    };
    assert!(!service_matches(&changed, &cur, &w));
}

// ---- 以下讀取本機實際狀態（唯讀）----

#[test]
fn detects_local_environment() {
    let env = LocalEnv::detect().unwrap();
    assert!(env.build >= 10240);
    assert_eq!(env.arch, sys::native_arch());
    assert!(env.store.len() > 1000);
    assert!(env.os_build().starts_with(&env.build.to_string()));
}

#[test]
fn reads_local_file_and_registry() {
    let kernel32 = sys::windows_dir().join("System32").join("kernel32.dll");
    let v = file_version(&kernel32).expect("kernel32 version");
    let f = FileAction {
        name: "kernel32.dll".into(),
        destination: "$(runtime.system32)\\".into(),
        is_pe: true,
        ..Default::default()
    };
    assert_eq!(
        compare_file(&f, &v, false, &sys::windows_dir()).state,
        LocalState::Same
    );
    let missing = FileAction {
        name: "no-such-file.dll".into(),
        ..f
    };
    assert_eq!(
        compare_file(&missing, &v, false, &sys::windows_dir()).state,
        LocalState::New
    );

    let key = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    assert!(read_reg_value(key, "CurrentBuildNumber", false).is_some());
    let r = RegistryAction {
        key: key.into(),
        value_name: Some("MsuInspectorNoSuchValue".into()),
        value_type: Some("REG_SZ".into()),
        data: Some("x".into()),
        operation: "replace".into(),
        ..Default::default()
    };
    assert_eq!(compare_registry(&r, false).state, LocalState::New);
    let key_only = RegistryAction {
        value_name: None,
        ..r.clone()
    };
    assert_eq!(compare_registry(&key_only, false).state, LocalState::Same);
    let hkcu = RegistryAction {
        key: r"HKEY_CURRENT_USER\Software".into(),
        ..r
    };
    assert_eq!(
        compare_registry(&hkcu, false).state,
        LocalState::UnknownPath
    );
}

#[test]
fn reads_services_and_tasks() {
    assert!(read_service("EventLog").is_some());
    let s = compare_service(
        "msu-inspector-no-such-service",
        &ServiceSnapshot::default(),
        &sys::windows_dir(),
    );
    assert_eq!(s.state, LocalState::New);
    assert_eq!(
        compare_task(r"\Microsoft\Windows\NoSuchTask-msu", &sys::windows_dir()).state,
        LocalState::New
    );
}

#[test]
fn first_store_entry_is_same() {
    let env = LocalEnv::detect().unwrap();
    let name = std::fs::read_dir(env.windows.join("WinSxS").join("Manifests"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .find(|n| n.starts_with(&format!("{}_microsoft-windows-", env.arch)) && !n.contains(".."))
        .unwrap();
    let parts: Vec<&str> = name.trim_end_matches(".manifest").split('_').collect();
    let n = parts.len();
    let id = AssemblyIdentity {
        name: parts[1..n - 4].join("_"),
        version: parts[n - 3].into(),
        arch: parts[0].into(),
        language: if parts[n - 2] == "none" {
            "neutral".into()
        } else {
            parts[n - 2].into()
        },
        public_key_token: parts[n - 4].into(),
    };
    assert_eq!(
        compare_component(&env.store, &id).state,
        LocalState::InStoreSame
    );
}
