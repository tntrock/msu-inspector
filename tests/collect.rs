mod common;

use msu_inspector::core::container::{collect, resolve_psfs};
use msu_inspector::core::delta::DeltaEngine;
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
fn desktop_deployment_only_provides_update_compression() {
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
    let dll = c.package_dll.expect("UpdateCompression.dll path");
    assert_eq!(std::fs::read(dll).unwrap(), b"MZ-fake");
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
fn resolves_manifests_from_psf_with_sidecar_index() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    let (psf, xml) = common::build_psf(
        d,
        "Windows10.0-KB5099999-x64.psf",
        &[
            (
                "amd64_x_10.0.1.1_none_abc\\a.manifest",
                b"<assembly id=\"a\"/>",
                true,
            ),
            ("amd64_x_10.0.1.1_none_abc\\f\\x.dll", b"MZ", false),
        ],
        false,
    );
    let inner = common::make_cab(
        d,
        "Windows10.0-KB5099999-x64.cab",
        &[
            ("update.mum", b"<assembly/>"),
            ("express.psf.cix.xml", xml.as_bytes()),
        ],
        false,
    );
    let msu = common::make_cab(
        d,
        "x.msu",
        &[
            (
                "Windows10.0-KB5099999-x64.cab",
                &std::fs::read(&inner).unwrap(),
            ),
            (
                "Windows10.0-KB5099999-x64.psf",
                &std::fs::read(&psf).unwrap(),
            ),
        ],
        false,
    );
    let mut c = collect(&msu, &d.join("work"), &Ctx::silent()).unwrap();
    assert!(c.saw_psf);
    assert_eq!(
        c.psfs.len(),
        1,
        "second pass extracts the PSF because no manifest was found"
    );
    resolve_psfs(&mut c, &DeltaEngine::select(None).unwrap(), &Ctx::silent()).unwrap();
    assert_eq!(names(&c.manifests), vec!["a.manifest"]);
    assert_eq!(&*c.manifests[0].bytes().unwrap(), b"<assembly id=\"a\"/>");
    assert!(c
        .containers
        .iter()
        .any(|i| i.format == ContainerFormat::Psf));
}

#[test]
fn skips_psf_when_manifests_already_found() {
    let t = tempfile::tempdir().unwrap();
    let d = t.path();
    let (psf, _) = common::build_psf(d, "kb.psf", &[("a.manifest", b"<assembly/>", false)], true);
    let inner = common::make_cab(d, "kb.cab", &[("b.manifest", b"<assembly/>")], false);
    let msu = common::make_cab(
        d,
        "x.msu",
        &[
            ("kb.cab", &std::fs::read(&inner).unwrap()),
            ("kb.psf", &std::fs::read(&psf).unwrap()),
        ],
        false,
    );
    let c = collect(&msu, &d.join("work"), &Ctx::silent()).unwrap();
    assert!(c.saw_psf);
    assert!(c.psfs.is_empty());
    assert_eq!(names(&c.manifests), vec!["b.manifest"]);
}
