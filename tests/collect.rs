mod common;

use msu_inspector::core::container::collect;
use msu_inspector::core::model::{ContainerFormat, WarningCode};
use msu_inspector::core::progress::Ctx;
use msu_inspector::core::CoreError;

const PKG_PROPS: &str =
    "ApplicabilityInfo=\"Windows 10.0 Client SKUs\"\r\nKB Article Number=\"5099999\"\r\n";

fn names(items: &[msu_inspector::core::container::Item]) -> Vec<String> {
    let mut v: Vec<String> = items.iter().map(|i| i.name.clone()).collect();
    v.sort();
    v
}

#[test]
fn collects_nested_msu_layout() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    let inner = common::make_cab(
        d,
        "inner.cab",
        &[
            ("update.mum", b"<assembly/>"),
            ("a.manifest", b"<assembly/>"),
            ("b.manifest", b"<assembly/>"),
            ("amd64_c\\c.manifest", b"<assembly/>"),
            ("payload.dll", b"MZ"),
        ],
        true,
    );
    let wsus = common::make_cab(
        d,
        "WSUSSCAN.cab",
        &[("scan.manifest", b"<assembly/>")],
        false,
    );
    let props = common::utf16(PKG_PROPS);
    let msu = common::make_cab(
        d,
        "Windows10.0-KB5099999-x64.msu",
        &[
            (
                "Windows10.0-KB5099999-x64.cab",
                &std::fs::read(&inner).unwrap(),
            ),
            ("WSUSSCAN.cab", &std::fs::read(&wsus).unwrap()),
            ("Windows10.0-KB5099999-x64-pkgProperties.txt", &props),
        ],
        false,
    );
    let work = d.join("work");
    let c = collect(&msu, &work, &Ctx::silent()).unwrap();
    assert_eq!(c.outer, Some(ContainerFormat::Cab));
    assert_eq!(
        names(&c.manifests),
        vec!["a.manifest", "b.manifest", "c.manifest"]
    );
    assert_eq!(names(&c.mums), vec!["update.mum"]);
    assert_eq!(c.pkg_properties.as_deref(), Some(props.as_slice()));
    let wsus_info = c
        .containers
        .iter()
        .find(|i| i.path.ends_with("WSUSSCAN.cab"))
        .unwrap();
    assert!(wsus_info.skipped.is_some());
    assert_eq!(
        c.containers.iter().filter(|i| i.skipped.is_none()).count(),
        2
    );
    assert!(c.warnings.is_empty());
}

#[test]
fn desktop_deployment_tooling_is_skipped() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    let dd = common::make_cab(
        d,
        "DesktopDeployment.cab",
        &[
            ("UpdateCompression.dll", b"MZ-fake"),
            ("tool.manifest", b"<assembly/>"),
        ],
        false,
    );
    let inner = common::make_cab(d, "kb.cab", &[("a.manifest", b"<assembly/>")], false);
    let msu = common::make_cab(
        d,
        "x.msu",
        &[
            ("DesktopDeployment.cab", &std::fs::read(&dd).unwrap()),
            ("kb.cab", &std::fs::read(&inner).unwrap()),
        ],
        false,
    );
    let c = collect(&msu, &d.join("work"), &Ctx::silent()).unwrap();
    assert_eq!(names(&c.manifests), vec!["a.manifest"]);
    let dd = c
        .containers
        .iter()
        .find(|i| i.path.ends_with("DesktopDeployment.cab"))
        .unwrap();
    assert_eq!(dd.skipped.as_deref(), Some("installer tooling"));
}

#[test]
fn dedupes_manifests_across_containers() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    let a = common::make_cab(d, "a.cab", &[("same.manifest", b"<assembly/>")], false);
    let b = common::make_cab(d, "b.cab", &[("SAME.manifest", b"<assembly/>")], false);
    let msu = common::make_cab(
        d,
        "x.msu",
        &[
            ("a.cab", &std::fs::read(&a).unwrap()),
            ("b.cab", &std::fs::read(&b).unwrap()),
        ],
        false,
    );
    let c = collect(&msu, &d.join("work"), &Ctx::silent()).unwrap();
    assert_eq!(c.manifests.len(), 1);
}

#[test]
fn corrupt_nested_container_becomes_warning() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    let good = common::make_cab(d, "good.cab", &[("a.manifest", b"<assembly/>")], false);
    let msu = common::make_cab(
        d,
        "x.msu",
        &[
            ("good.cab", &std::fs::read(&good).unwrap()),
            ("bad.cab", b"MSCF truncated"),
        ],
        false,
    );
    let c = collect(&msu, &d.join("work"), &Ctx::silent()).unwrap();
    assert_eq!(c.manifests.len(), 1);
    assert_eq!(c.warnings.len(), 1);
    assert_eq!(c.warnings[0].code, WarningCode::ContainerFailed);
}

#[test]
fn rejects_non_update_files() {
    let t = tempfile::tempdir().unwrap();
    for (name, bytes) in [
        ("x.exe", b"MZ\x90\x00 not an update".as_slice()),
        ("empty.msu", b"".as_slice()),
        ("x.zip", b"PK\x03\x04".as_slice()),
        ("lonely.psf", b"PSTR".as_slice()),
    ] {
        let p = t.path().join(name);
        std::fs::write(&p, bytes).unwrap();
        let r = collect(&p, &t.path().join("work"), &Ctx::silent());
        assert!(
            matches!(r, Err(CoreError::UnsupportedFormat(_))),
            "{name}: {r:?}"
        );
    }
}

#[test]
fn cancel_stops_collection() {
    let t = tempfile::tempdir().unwrap();
    let msu = common::make_cab(t.path(), "x.msu", &[("a.manifest", b"<assembly/>")], false);
    let ctx = Ctx::silent();
    ctx.cancel_flag()
        .store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(matches!(
        collect(&msu, &t.path().join("work"), &ctx),
        Err(CoreError::Cancelled)
    ));
}

#[test]
fn keeps_update_mum_from_every_container() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    let ssu = common::make_cab(
        d,
        "SSU-26100.1-x64.cab",
        &[("update.mum", b"<assembly/>")],
        false,
    );
    let lcu = common::make_cab(
        d,
        "Windows11.0-KB5099999-x64.cab",
        &[
            ("update.mum", b"<assembly/>"),
            ("a.manifest", b"<assembly/>"),
        ],
        false,
    );
    let msu = common::make_cab(
        d,
        "Windows11.0-KB5099999-x64.msu",
        &[
            ("SSU-26100.1-x64.cab", &std::fs::read(&ssu).unwrap()),
            (
                "Windows11.0-KB5099999-x64.cab",
                &std::fs::read(&lcu).unwrap(),
            ),
        ],
        false,
    );
    let c = collect(&msu, &d.join("work"), &Ctx::silent()).unwrap();
    let mut vpaths: Vec<&str> = c.mums.iter().map(|m| m.vpath.as_str()).collect();
    vpaths.sort();
    assert_eq!(
        vpaths,
        vec![
            "Windows11.0-KB5099999-x64.msu/SSU-26100.1-x64.cab/update.mum",
            "Windows11.0-KB5099999-x64.msu/Windows11.0-KB5099999-x64.cab/update.mum",
        ]
    );
}

#[test]
fn payload_containers_inside_component_folders_are_not_unpacked() {
    // Win10 / Server LCU 的元件資料夾內含 bootos.wim 等「要安裝的檔案」，不是套件容器
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    let comp =
        "amd64_microsoft-windows-ptp-bootos_31bf3856ad364e35_10.0.19041.7725_none_4a9456e64d9847d8";
    let inner = common::make_cab(
        d,
        "kb.cab",
        &[
            ("update.mum", b"<assembly/>"),
            ("a.manifest", b"<assembly/>"),
            (&format!("{comp}\\bootos.wim"), b"MSWIM\0\0\0garbage"),
            (&format!("{comp}\\inner.cab"), b"MSCF truncated"),
        ],
        false,
    );
    let msu = common::make_cab(
        d,
        "x.msu",
        &[("kb.cab", &std::fs::read(&inner).unwrap())],
        false,
    );
    let c = collect(&msu, &d.join("work"), &Ctx::silent()).unwrap();
    assert_eq!(names(&c.manifests), vec!["a.manifest"]);
    assert!(c.warnings.is_empty(), "{:?}", c.warnings);
    assert!(
        !c.containers
            .iter()
            .any(|i| i.path.contains("bootos.wim") || i.path.ends_with("inner.cab")),
        "{:?}",
        c.containers
    );
}
