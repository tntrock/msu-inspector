mod common;

use msu_inspector::core::analyze::{analyze, format_label, AnalyzeOptions};
use msu_inspector::core::delta::{DcmDecoder, DeltaEngine};
use msu_inspector::core::model::*;
use msu_inspector::core::progress::Ctx;
use msu_inspector::core::CoreError;

/// 建立一個模擬 LCU 的 .msu：外層 CAB → 內層 LZX CAB（rollup.mum + 純文字 manifest + DCM manifest + 壞掉的 manifest）。
fn build_msu(dir: &std::path::Path) -> std::path::PathBuf {
    let dcm = DcmDecoder::from_system().unwrap();
    let mut basic_dcm = b"DCM\x01".to_vec();
    basic_dcm.extend(
        DeltaEngine::system("msdelta.dll")
            .unwrap()
            .create(dcm.base(), common::fixture("basic.manifest").as_bytes())
            .unwrap(),
    );
    let inner = common::make_cab(
        dir,
        "Windows11.0-KB5129195-x64.cab",
        &[
            (
                "Package_for_RollupFix~31bf3856ad364e35~amd64~~26100.9457.1.0.mum",
                common::fixture("rollup.mum").as_bytes(),
            ),
            (
                "amd64_test-actions_31bf3856ad364e35_10.0.26100.1742_none_0.manifest",
                common::fixture("actions.manifest").as_bytes(),
            ),
            (
                "amd64_appreadiness_31bf3856ad364e35_10.0.26100.1591_none_0.manifest",
                &basic_dcm,
            ),
            ("broken.manifest", b"<assembly"),
        ],
        true,
    );
    let props = common::utf16("KB Article Number=\"5129195\"\r\n");
    common::make_cab(
        dir,
        "Windows11.0-KB5129195-x64.msu",
        &[
            (
                "Windows11.0-KB5129195-x64.cab",
                &std::fs::read(inner).unwrap(),
            ),
            ("Windows11.0-KB5129195-x64-pkgProperties.txt", &props),
        ],
        false,
    )
}

#[test]
fn analyzes_synthetic_msu() {
    let t = tempfile::tempdir().unwrap();
    let msu = build_msu(t.path());
    let temp_root = t.path().join("temp");
    std::fs::create_dir_all(&temp_root).unwrap();
    let opts = AnalyzeOptions {
        compare_local: false,
        temp_root: Some(temp_root.clone()),
    };
    let r = analyze(&msu, &opts, &Ctx::silent()).unwrap();

    assert_eq!(r.mode, Mode::Static);
    assert!(r.local_context.is_none());
    assert_eq!(r.package.kb.as_deref(), Some("KB5129195"));
    assert_eq!(r.package.identity.name, "Package_for_RollupFix");
    assert_eq!(r.source.file, "Windows11.0-KB5129195-x64.msu");
    assert_eq!(r.source.format, "msu-cab");
    assert_eq!(r.source.sha256.len(), 64);
    assert_eq!(r.source.signature.status, SignatureStatus::Unsigned);

    let names: Vec<&str> = r
        .components
        .iter()
        .map(|c| c.identity.name.as_str())
        .collect();
    assert_eq!(
        names,
        vec!["Microsoft-Windows-AppReadiness-Service", "Test-Actions"]
    );
    let codes: Vec<WarningCode> = r.warnings.iter().map(|w| w.code).collect();
    assert!(codes.contains(&WarningCode::SignatureNotValid));
    assert!(codes.contains(&WarningCode::ManifestParseFailed));

    let high: Vec<&Action> = r
        .components
        .iter()
        .flat_map(|c| &c.actions)
        .filter(|a| a.risk == Risk::High)
        .collect();
    assert!(high.iter().any(|a| a.rules.contains(&"DRV_BOOT_START")));
    assert!(high.iter().any(|a| a.rules.contains(&"CMD_GENERIC")));

    assert_eq!(
        std::fs::read_dir(&temp_root).unwrap().count(),
        0,
        "temp dir must be removed"
    );
}

#[test]
fn cancel_removes_temp_dir() {
    let t = tempfile::tempdir().unwrap();
    let msu = build_msu(t.path());
    let temp_root = t.path().join("temp");
    std::fs::create_dir_all(&temp_root).unwrap();
    let ctx = Ctx::silent();
    ctx.cancel_flag()
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let opts = AnalyzeOptions {
        compare_local: false,
        temp_root: Some(temp_root.clone()),
    };
    assert!(matches!(
        analyze(&msu, &opts, &ctx),
        Err(CoreError::Cancelled)
    ));
    assert_eq!(std::fs::read_dir(&temp_root).unwrap().count(), 0);
}

#[test]
fn compares_with_local_machine_when_requested() {
    let t = tempfile::tempdir().unwrap();
    let msu = build_msu(t.path());
    let opts = AnalyzeOptions {
        compare_local: true,
        temp_root: None,
    };
    let r = analyze(&msu, &opts, &Ctx::silent()).unwrap();
    if r.warnings
        .iter()
        .any(|w| w.code == WarningCode::LocalCompareFailed)
    {
        eprintln!(
            "local compare unavailable on this machine: {:?}",
            r.warnings
        );
        return;
    }
    assert_eq!(r.mode, Mode::StaticLocal);
    let ctx = r.local_context.as_ref().unwrap();
    assert!(!ctx.os_build.is_empty());
    assert!(r.components.iter().all(|c| c.local.is_some()));
}

#[test]
fn rejects_missing_and_non_update_files() {
    let t = tempfile::tempdir().unwrap();
    let p = t.path().join("notes.txt");
    std::fs::write(&p, b"hello").unwrap();
    assert!(matches!(
        analyze(&p, &AnalyzeOptions::default(), &Ctx::silent()),
        Err(CoreError::UnsupportedFormat(_))
    ));
    let missing = t.path().join("missing.msu");
    assert!(matches!(
        analyze(&missing, &AnalyzeOptions::default(), &Ctx::silent()),
        Err(CoreError::Io { .. })
    ));
}

#[test]
fn labels_formats() {
    assert_eq!(
        format_label(Some(ContainerFormat::Cab), "a.msu", false),
        "msu-cab"
    );
    assert_eq!(
        format_label(Some(ContainerFormat::Wim), "a.MSU", true),
        "msu-wim+psf"
    );
    assert_eq!(
        format_label(Some(ContainerFormat::Cab), "a.cab", false),
        "cab"
    );
}
